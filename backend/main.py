"""
Main FastAPI application for BANKISM AI Banking Security Firewall & Live Attack Lab.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.evidence_service import evidence_service
from backend.mock_bank import mock_bank
from backend.models import (
    AnalyticsSummary,
    EvidenceReport,
    TestRequest,
    VerdictResponse,
)
from backend.pipeline import pipeline
from backend.scenario_library import scenario_library, ScenarioDefinition
from backend.threat_analyzer import threat_analyzer

app = FastAPI(
    title="BANKISM — AI Banking Security Firewall",
    description="Deterministic security firewall, live attack lab, and independent verification engine for banking AI.",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ResetSandboxRequest(BaseModel):
    confirm: bool = True
    clear_ledger: bool = True
    clear_evidence: bool = False


# Health & Configuration Status
@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    has_gemini = bool(threat_analyzer.gemini_api_key)
    has_openai = bool(threat_analyzer.openai_api_key)
    mode = "LLM_ASSISTED" if (has_gemini or has_openai) else "RULE_BASED_FALLBACK"

    return {
        "status": "HEALTHY",
        "service": "BANKISM AI Banking Security Firewall",
        "version": "2.0.0",
        "operating_mode": mode,
        "llm_providers": {
            "gemini_configured": has_gemini,
            "openai_configured": has_openai,
        },
        "sandbox_environment": "SIMULATED_FINANCIAL_ENVIRONMENT",
        "independent_verifier_active": True,
        "policy_engine_active": True,
        "ledger_entries_count": len(mock_bank.ledger),
    }


# Scenario Library
@app.get("/api/scenarios", response_model=List[ScenarioDefinition])
def get_scenarios():
    return scenario_library.get_all()


# Execute Test (Curated or Custom)
@app.post("/api/tests", response_model=VerdictResponse)
def execute_test(request: TestRequest):
    try:
        # If scenario_id is provided, merge with defaults if missing
        if request.scenario_id:
            scenario = scenario_library.get_by_id(request.scenario_id)
            if scenario:
                default_req = scenario.default_test_request
                if not request.request_text:
                    request.request_text = default_req.request_text
                if request.amount is None and default_req.amount is not None:
                    request.amount = default_req.amount
                if request.destination_account_id is None and default_req.destination_account_id is not None:
                    request.destination_account_id = default_req.destination_account_id
                if request.memo is None and default_req.memo is not None:
                    request.memo = default_req.memo
                if request.idempotency_key is None and default_req.idempotency_key is not None:
                    request.idempotency_key = default_req.idempotency_key
                if default_req.simulate_llm_failure:
                    request.simulate_llm_failure = True
                if not default_req.is_authenticated:
                    request.is_authenticated = False
                if default_req.source_account_id:
                    request.source_account_id = default_req.source_account_id

        # Scenario 6: Cumulative limit circumvention helper:
        # If scenario-6 is run, seed 2 prior transfers today so the cumulative calculation is tested
        if request.scenario_id == "scenario-6":
            curr_transferred = mock_bank.get_daily_cumulative_transferred("ACC_ALICE_101")
            if curr_transferred < 8000.0:
                # Pre-populate two valid transfers of ₹4,000 each in the ledger
                mock_bank.execute_transfer(
                    source_account_id="ACC_ALICE_101",
                    destination_account_id="ACC_BOB_201",
                    amount=4000.0,
                    test_id="SETUP-SCENARIO-6A",
                    memo="Prior transaction 1 today",
                    policy_decision="APPROVE"
                )
                mock_bank.execute_transfer(
                    source_account_id="ACC_ALICE_101",
                    destination_account_id="ACC_BOB_201",
                    amount=4000.0,
                    test_id="SETUP-SCENARIO-6B",
                    memo="Prior transaction 2 today",
                    policy_decision="APPROVE"
                )

        # Scenario 13: Duplicate transaction helper:
        # Pre-seed one transaction with the key so the second one triggers duplicate rejection
        if request.scenario_id == "scenario-13":
            if not mock_bank.check_idempotency("IDEMP-TEST-REPLAY-001"):
                mock_bank.execute_transfer(
                    source_account_id="ACC_ALICE_101",
                    destination_account_id="ACC_BOB_201",
                    amount=1000.0,
                    test_id="SETUP-SCENARIO-13",
                    idempotency_key="IDEMP-TEST-REPLAY-001",
                    memo="First original transaction",
                    policy_decision="APPROVE"
                )

        verdict = pipeline.run_test(request)
        return verdict
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution failure: {str(e)}")


# Get Test State / Evidence by ID
@app.get("/api/tests/{test_id}/evidence", response_model=EvidenceReport)
def get_test_evidence(test_id: str):
    report = evidence_service.get_evidence(test_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Evidence report for test {test_id} not found.")
    return report


# History & Analytics
@app.get("/api/history")
def get_test_history(limit: int = Query(default=100, ge=1, le=500)):
    return evidence_service.get_history(limit=limit)


@app.get("/api/analytics", response_model=AnalyticsSummary)
def get_analytics():
    return evidence_service.get_analytics()


# Mock Banking Ledger & Accounts
@app.get("/api/mock-bank/accounts")
def get_mock_accounts():
    return [acc.model_dump() for acc in mock_bank.get_all_accounts()]


@app.get("/api/mock-bank/transactions")
def get_mock_transactions(limit: int = Query(default=50, ge=1, le=200)):
    return [entry.model_dump() for entry in mock_bank.get_ledger(limit=limit)]


@app.post("/api/mock-bank/reset")
def reset_sandbox(req: ResetSandboxRequest):
    if not req.confirm:
        raise HTTPException(
            status_code=400,
            detail="Sandbox reset requires explicit confirmation (confirm=true)."
        )
    reset_info = mock_bank.reset_sandbox(clear_ledger=req.clear_ledger)
    if req.clear_evidence:
        evidence_service.clear_evidence_db()
        reset_info["evidence_cleared"] = True
    else:
        reset_info["evidence_cleared"] = False
        reset_info["note"] = "Audit test evidence history was preserved."
    return reset_info


# Mount static frontend
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/")
    def serve_frontend():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"message": "BANKISM API running. Frontend index.html not found."}
