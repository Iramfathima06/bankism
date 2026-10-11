"""
Complete End-to-End Security Pipeline for BANKISM:
Attack -> Analyze -> Defend -> Control Execution -> Verify Outcome -> Generate Evidence.
Runs each request through the 9 live visualization stages.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from backend.evidence_service import evidence_service, EvidenceService
from backend.execution_gate import execution_gate, TransactionExecutionGate
from backend.mock_bank import mock_bank, MockBankService
from backend.models import (
    ActionType,
    AIThreatAnalysis,
    CheckStatus,
    Decision,
    EvidenceReport,
    ExecutionResult,
    ExecutionStatus,
    NormalizedInput,
    PipelineStage,
    RiskLevel,
    SecurityChecks,
    StageStatus,
    TestRequest,
    ThreatCategory,
    VerdictResponse,
    VerificationResult,
    VerificationStatus,
)
from backend.policy_engine import policy_engine, DeterministicPolicyEngine, PolicyEvaluationResult
from backend.scenario_library import scenario_library
from backend.threat_analyzer import threat_analyzer, ThreatAnalyzer, InputNormalizer


class SecurityPipeline:
    """Coordinates the Bankism firewall, execution gate, mock bank, verifier, and audit log."""

    def __init__(
        self,
        bank: MockBankService = mock_bank,
        analyzer: ThreatAnalyzer = threat_analyzer,
        policy: DeterministicPolicyEngine = policy_engine,
        gate: TransactionExecutionGate = execution_gate,
        evidence: EvidenceService = evidence_service
    ):
        self.bank = bank
        self.analyzer = analyzer
        self.policy = policy
        self.gate = gate
        self.evidence = evidence

    def run_test(self, request: TestRequest) -> VerdictResponse:
        test_id = f"TEST-{uuid.uuid4().hex[:10].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        stages: List[PipelineStage] = []

        scenario_def = scenario_library.get_by_id(request.scenario_id) if request.scenario_id else None

        # Pre-test snapshot
        pre_snapshot = self.bank.take_snapshot()

        # STAGE 1: Request Received
        s1_start = time.perf_counter()
        stages.append(PipelineStage(
            stage_id="stage-1-reception",
            name="Request Received & Tagged",
            status=StageStatus.PASSED,
            duration_ms=round((time.perf_counter() - s1_start) * 1000, 2),
            details={
                "test_id": test_id,
                "timestamp": now_iso,
                "mode": "CURATED" if scenario_def else "CUSTOM",
                "request_length": len(request.request_text)
            }
        ))

        # STAGE 2: Input Validation & Normalization
        s2_start = time.perf_counter()
        normalized = InputNormalizer.normalize_and_inspect(request.request_text)
        s2_status = StageStatus.PASSED
        if normalized.detected_encodings or normalized.contains_homoglyphs:
            s2_status = StageStatus.PASSED  # Normalization passed but flagged findings

        stages.append(PipelineStage(
            stage_id="stage-2-input-validation",
            name="Input Validation & Normalization",
            status=s2_status,
            duration_ms=round((time.perf_counter() - s2_start) * 1000, 2),
            details={
                "detected_encodings": normalized.detected_encodings,
                "contains_homoglyphs": normalized.contains_homoglyphs,
                "extracted_amount": normalized.extracted_amount,
                "extracted_beneficiary": normalized.extracted_beneficiary,
                "extracted_account": normalized.extracted_account,
                "extracted_memo": normalized.extracted_memo
            }
        ))

        # STAGE 3: AI Threat Analysis
        s3_start = time.perf_counter()
        ai_analysis = self.analyzer.analyze(
            normalized=normalized,
            simulate_failure=request.simulate_llm_failure
        )
        s3_status = StageStatus.PASSED
        if ai_analysis.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            s3_status = StageStatus.FAILED
        elif ai_analysis.risk_level == RiskLevel.MEDIUM or ai_analysis.is_ambiguous:
            s3_status = StageStatus.PASSED

        stages.append(PipelineStage(
            stage_id="stage-3-threat-analysis",
            name="AI Threat Analysis",
            status=s3_status,
            duration_ms=round((time.perf_counter() - s3_start) * 1000, 2),
            details={
                "analyzer_mode": ai_analysis.analyzer_mode,
                "intent": ai_analysis.intent.value,
                "threat_category": ai_analysis.threat_category.value,
                "risk_level": ai_analysis.risk_level.value,
                "confidence": ai_analysis.confidence,
                "detected_patterns": ai_analysis.detected_patterns,
                "is_ambiguous": ai_analysis.is_ambiguous
            }
        ))

        # STAGE 4 & 5: Authentication, Authorization & Deterministic Policy Validation
        s4_start = time.perf_counter()
        policy_res = self.policy.evaluate(
            request=request,
            normalized=normalized,
            threat_analysis=ai_analysis
        )

        auth_passed = (
            policy_res.security_checks.authentication == CheckStatus.PASS and
            policy_res.security_checks.authorization == CheckStatus.PASS
        )
        stages.append(PipelineStage(
            stage_id="stage-4-auth-authz",
            name="Identity & Authorization Gate",
            status=StageStatus.PASSED if auth_passed else StageStatus.FAILED,
            duration_ms=round((time.perf_counter() - s4_start) * 1000, 2),
            details={
                "authentication": policy_res.security_checks.authentication.value,
                "authorization": policy_res.security_checks.authorization.value,
                "authenticated_customer": request.authenticated_customer_id,
                "source_account": request.source_account_id
            }
        ))

        s5_start = time.perf_counter()
        tx_policy_passed = (
            policy_res.security_checks.transaction_limit in [CheckStatus.PASS, CheckStatus.NOT_APPLICABLE] and
            policy_res.security_checks.cumulative_limit in [CheckStatus.PASS, CheckStatus.NOT_APPLICABLE] and
            policy_res.security_checks.idempotency in [CheckStatus.PASS, CheckStatus.NOT_APPLICABLE]
        )
        stages.append(PipelineStage(
            stage_id="stage-5-tx-policy",
            name="Deterministic Transaction Policy",
            status=StageStatus.PASSED if tx_policy_passed else StageStatus.FAILED,
            duration_ms=round((time.perf_counter() - s5_start) * 1000, 2),
            details={
                "transaction_limit": policy_res.security_checks.transaction_limit.value,
                "cumulative_limit": policy_res.security_checks.cumulative_limit.value,
                "idempotency": policy_res.security_checks.idempotency.value
            }
        ))

        # STAGE 6: Security Decision
        s6_start = time.perf_counter()
        stages.append(PipelineStage(
            stage_id="stage-6-decision",
            name="Firewall Verdict Synthesizer",
            status=StageStatus.PASSED if policy_res.decision == Decision.APPROVE else (
                StageStatus.FAILED if policy_res.decision == Decision.BLOCK else StageStatus.INCONCLUSIVE
            ),
            duration_ms=round((time.perf_counter() - s6_start) * 1000, 2),
            details={
                "decision": policy_res.decision.value,
                "action_authorized": policy_res.action_authorized,
                "rationale": policy_res.rationale
            }
        ))

        # STAGE 7: Execution Gate
        s7_start = time.perf_counter()
        exec_result, mock_bank_called = self.gate.process_execution(
            request=request,
            policy_result=policy_res,
            test_id=test_id
        )
        stages.append(PipelineStage(
            stage_id="stage-7-execution-gate",
            name="Transaction Execution Gate",
            status=StageStatus.PASSED if exec_result.executed else StageStatus.SKIPPED,
            duration_ms=round((time.perf_counter() - s7_start) * 1000, 2),
            details={
                "status": exec_result.status.value,
                "executed": exec_result.executed,
                "mock_bank_called": mock_bank_called,
                "transaction_id": exec_result.transaction_id,
                "message": exec_result.message
            }
        ))

        # Post-test snapshot
        post_snapshot = self.bank.take_snapshot()

        # Determine expected outcome for independent verifier
        if scenario_def:
            expected_outcome = scenario_def.expected_outcome
        else:
            # Custom attack test expected outcome deduction:
            if not request.is_authenticated:
                expected_outcome = "AUTH_BLOCKED"
            elif policy_res.decision == Decision.BLOCK:
                expected_outcome = "NO_TRANSFER"
            elif policy_res.decision == Decision.REVIEW:
                expected_outcome = "HELD_FOR_REVIEW"
            elif ai_analysis.intent == ActionType.BALANCE_INQUIRY and policy_res.action_authorized:
                expected_outcome = "READ_ONLY_AUTHORIZED"
            elif policy_res.action_authorized and exec_result.executed:
                expected_outcome = "TRANSFER_EXECUTED"
            else:
                expected_outcome = "NO_TRANSFER"

        # STAGE 8: Independent Verification Engine
        s8_start = time.perf_counter()
        requested_amt = request.amount or normalized.extracted_amount
        src_acc = request.source_account_id or "ACC_ALICE_101"
        dst_acc = request.destination_account_id or policy_res.details.get("destination_account_id")

        from backend.verification_engine import verification_engine
        verification_res = verification_engine.verify(
            test_id=test_id,
            expected_outcome=expected_outcome,
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
            policy_result=policy_res,
            execution_result=exec_result,
            requested_amount=requested_amt,
            source_account_id=src_acc,
            destination_account_id=dst_acc
        )
        stages.append(PipelineStage(
            stage_id="stage-8-verification",
            name="Independent State Verifier",
            status=StageStatus.PASSED if verification_res.status == VerificationStatus.PASS else (
                StageStatus.FAILED if verification_res.status == VerificationStatus.FAIL else StageStatus.INCONCLUSIVE
            ),
            duration_ms=round((time.perf_counter() - s8_start) * 1000, 2),
            details={
                "status": verification_res.status.value,
                "expected": verification_res.expected_outcome,
                "observed": verification_res.observed_outcome,
                "rationale": verification_res.rationale
            }
        ))

        # STAGE 9: Evidence Report Generation
        s9_start = time.perf_counter()
        created_ledger_entries = [e.model_dump() for e in self.bank.get_ledger_for_test(test_id)]

        evidence_report = EvidenceReport(
            test_id=test_id,
            timestamp=now_iso,
            scenario_id=request.scenario_id,
            mode="CURATED" if scenario_def else "CUSTOM",
            original_request=request.request_text,
            notes=request.notes,
            normalized_input=normalized,
            ai_analysis=ai_analysis,
            deterministic_policy_checks={
                "checks": policy_res.security_checks.model_dump(),
                "details": policy_res.details
            },
            final_verdict=policy_res.decision,
            action_authorized=policy_res.action_authorized,
            execution_result=exec_result,
            mock_bank_called=mock_bank_called,
            pre_test_balances=pre_snapshot.accounts,
            post_test_balances=post_snapshot.accounts,
            ledger_entries_created=created_ledger_entries,
            verification_result=verification_res,
            security_guarantee_notes=(
                "Bankism security policy operates independently of LLM classification. "
                "The mock banking ledger and balance states are independently audited."
            )
        )
        self.evidence.record_test(evidence_report)

        stages.append(PipelineStage(
            stage_id="stage-9-evidence",
            name="Audit Evidence Persisted",
            status=StageStatus.PASSED,
            duration_ms=round((time.perf_counter() - s9_start) * 1000, 2),
            details={"evidence_url": f"/api/tests/{test_id}/evidence"}
        ))

        # Calculate snapshot diff
        snapshot_diff = {
            "pre_balances": pre_snapshot.accounts,
            "post_balances": post_snapshot.accounts,
            "deltas": {
                k: round(post_snapshot.accounts[k] - pre_snapshot.accounts[k], 2)
                for k in pre_snapshot.accounts
            }
        }

        # Build final standardized verdict response (matching Section 16 format)
        return VerdictResponse(
            test_id=test_id,
            timestamp=now_iso,
            scenario_id=request.scenario_id,
            decision=policy_res.decision,
            risk_level=ai_analysis.risk_level,
            threat_category=ai_analysis.threat_category,
            rationale=policy_res.rationale,
            detected_patterns=policy_res.detected_patterns,
            action=ai_analysis.intent,
            security_checks=policy_res.security_checks,
            action_authorized=policy_res.action_authorized,
            execution=exec_result,
            verification=verification_res,
            evidence_url=f"/api/tests/{test_id}/evidence",
            stages=stages,
            account_snapshot_diff=snapshot_diff
        )


pipeline = SecurityPipeline()
