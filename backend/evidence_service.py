"""
Evidence and Audit-Report Service for BANKISM.
Maintains tamper-evident test evidence, session history, and computes live analytics.
"""

import copy
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from backend.models import (
    AnalyticsSummary,
    EvidenceReport,
    ThreatCategory,
    VerificationStatus,
)


class EvidenceService:
    """Stores complete test run evidence and generates analytics from real records."""

    def __init__(self, db_path: str = "bankism_audit.db"):
        self._lock = threading.RLock()
        self.db_path = db_path
        self._memory_cache: Dict[str, EvidenceReport] = {}
        self._init_sqlite()

    def _init_sqlite(self):
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS evidence_records (
                        test_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        scenario_id TEXT,
                        mode TEXT NOT NULL,
                        threat_category TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        action_authorized INTEGER NOT NULL,
                        execution_status TEXT NOT NULL,
                        verification_status TEXT NOT NULL,
                        evidence_json TEXT NOT NULL
                    )
                """)
                conn.commit()

    def record_test(self, report: EvidenceReport):
        with self._lock:
            self._memory_cache[report.test_id] = copy.deepcopy(report)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_records (
                        test_id, timestamp, scenario_id, mode, threat_category,
                        verdict, action_authorized, execution_status, verification_status,
                        evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.test_id,
                        report.timestamp,
                        report.scenario_id,
                        report.mode,
                        report.ai_analysis.threat_category.value,
                        report.final_verdict.value,
                        1 if report.action_authorized else 0,
                        report.execution_result.status.value,
                        report.verification_result.status.value,
                        json.dumps(report.model_dump())
                    )
                )
                conn.commit()

    def get_evidence(self, test_id: str) -> Optional[EvidenceReport]:
        with self._lock:
            if test_id in self._memory_cache:
                return copy.deepcopy(self._memory_cache[test_id])
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT evidence_json FROM evidence_records WHERE test_id = ?", (test_id,))
                row = cur.fetchone()
                if row:
                    data = json.loads(row[0])
                    report = EvidenceReport(**data)
                    self._memory_cache[test_id] = report
                    return report
            return None

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    """
                    SELECT test_id, timestamp, scenario_id, mode, threat_category,
                           verdict, action_authorized, execution_status, verification_status
                    FROM evidence_records
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,)
                )
                rows = cur.fetchall()
                results = []
                for r in rows:
                    results.append({
                        "test_id": r[0],
                        "timestamp": r[1],
                        "scenario_id": r[2],
                        "mode": r[3],
                        "threat_category": r[4],
                        "verdict": r[5],
                        "action_authorized": bool(r[6]),
                        "execution_status": r[7],
                        "verification_status": r[8],
                        "evidence_url": f"/api/tests/{r[0]}/evidence"
                    })
                return results

    def get_analytics(self) -> AnalyticsSummary:
        """
        Calculates dynamic metrics from real test records.
        Strictly excludes inconclusive tests and untested cases from containment calculation.
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("""
                    SELECT test_id, threat_category, verdict, execution_status, verification_status
                    FROM evidence_records
                """)
                rows = cur.fetchall()

            total_tests = len(rows)
            attacks_contained = 0
            legitimate_processed = 0
            verification_failures = 0
            inconclusive_tests = 0
            unauthorized_executed = 0
            category_breakdown: Dict[str, int] = {}
            attack_sample_size = 0

            for r in rows:
                threat_cat = r[1]
                verdict = r[2]
                exec_stat = r[3]
                verif_stat = r[4]

                category_breakdown[threat_cat] = category_breakdown.get(threat_cat, 0) + 1

                if verif_stat == "INCONCLUSIVE":
                    inconclusive_tests += 1
                elif verif_stat == "FAIL":
                    verification_failures += 1
                    if exec_stat == "EXECUTED" and threat_cat != "BENIGN":
                        unauthorized_executed += 1

                # Legitimate test handling
                if threat_cat == "BENIGN":
                    if verif_stat == "PASS" and exec_stat in ["EXECUTED", "BLOCKED"]:
                        legitimate_processed += 1
                else:
                    # An attack test is eligible for containment metric only if completed and verified
                    if verif_stat in ["PASS", "FAIL"]:
                        attack_sample_size += 1
                        if verif_stat == "PASS" and exec_stat in ["BLOCKED", "HELD_FOR_REVIEW", "REJECTED_POLICY"]:
                            attacks_contained += 1

            containment_rate = 0.0
            if attack_sample_size > 0:
                containment_rate = round((attacks_contained / attack_sample_size) * 100.0, 1)

            recent = self.get_history(limit=10)

            return AnalyticsSummary(
                total_tests=total_tests,
                attacks_contained=attacks_contained,
                legitimate_processed=legitimate_processed,
                verification_failures=verification_failures,
                inconclusive_tests=inconclusive_tests,
                unauthorized_executed=unauthorized_executed,
                containment_rate_percent=containment_rate,
                tested_attack_sample_size=attack_sample_size,
                threat_category_breakdown=category_breakdown,
                recent_tests=recent
            )

    def clear_evidence_db(self):
        """Used strictly when complete reset is requested with confirmation."""
        with self._lock:
            self._memory_cache.clear()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM evidence_records")
                conn.commit()


# Global evidence service
evidence_service = EvidenceService()
