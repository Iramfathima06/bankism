"""
Data models and schemas for BANKISM AI Banking Security Firewall.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class Decision(str, Enum):
    APPROVE = "APPROVE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    BENIGN = "BENIGN"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    UNAUTHORIZED_TRANSFER = "UNAUTHORIZED_TRANSFER"
    LIMIT_VIOLATION = "LIMIT_VIOLATION"
    CUMULATIVE_LIMIT_VIOLATION = "CUMULATIVE_LIMIT_VIOLATION"
    MALICIOUS_MEMO = "MALICIOUS_MEMO"
    SENSITIVE_INFO_EXTRACTION = "SENSITIVE_INFO_EXTRACTION"
    AMBIGUOUS_REQUEST = "AMBIGUOUS_REQUEST"
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"
    OBFUSCATED_INSTRUCTION = "OBFUSCATED_INSTRUCTION"
    MODEL_FAILURE = "MODEL_FAILURE"
    DUPLICATE_TRANSACTION = "DUPLICATE_TRANSACTION"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    UNKNOWN = "UNKNOWN"


class ActionType(str, Enum):
    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    TRANSFER_MONEY = "TRANSFER_MONEY"
    VIEW_TRANSACTIONS = "VIEW_TRANSACTIONS"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    UNKNOWN = "UNKNOWN"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExecutionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    HELD_FOR_REVIEW = "HELD_FOR_REVIEW"
    REJECTED_POLICY = "REJECTED_POLICY"
    FAILED = "FAILED"


class VerificationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PipelineStage(BaseModel):
    stage_id: str
    name: str
    status: StageStatus = StageStatus.PENDING
    duration_ms: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityChecks(BaseModel):
    input_validation: CheckStatus = CheckStatus.NOT_APPLICABLE
    threat_analysis: CheckStatus = CheckStatus.NOT_APPLICABLE
    authentication: CheckStatus = CheckStatus.NOT_APPLICABLE
    authorization: CheckStatus = CheckStatus.NOT_APPLICABLE
    transaction_limit: CheckStatus = CheckStatus.NOT_APPLICABLE
    cumulative_limit: CheckStatus = CheckStatus.NOT_APPLICABLE
    idempotency: CheckStatus = CheckStatus.NOT_APPLICABLE


class ExecutionResult(BaseModel):
    status: ExecutionStatus
    executed: bool
    transaction_id: Optional[str] = None
    failure_reason: Optional[str] = None
    message: Optional[str] = None


class VerificationResult(BaseModel):
    status: VerificationStatus
    expected_outcome: str
    observed_outcome: str
    rationale: str
    evidence_proof: Dict[str, Any] = Field(default_factory=dict)


class NormalizedInput(BaseModel):
    original_text: str
    cleaned_text: str
    detected_encodings: List[str] = Field(default_factory=list)
    contains_homoglyphs: bool = False
    extracted_amount: Optional[float] = None
    extracted_beneficiary: Optional[str] = None
    extracted_memo: Optional[str] = None
    extracted_account: Optional[str] = None


class AIThreatAnalysis(BaseModel):
    analyzer_mode: str  # "LLM_ASSISTED" or "RULE_BASED_FALLBACK"
    intent: ActionType
    threat_category: ThreatCategory
    risk_level: RiskLevel
    confidence: float
    detected_patterns: List[str] = Field(default_factory=list)
    rationale: str
    is_ambiguous: bool = False
    missing_fields: List[str] = Field(default_factory=list)
    raw_model_response: Optional[Dict[str, Any]] = None


class BankAccount(BaseModel):
    account_id: str
    customer_id: str
    customer_name: str
    account_type: str
    balance: float
    currency: str = "INR"
    is_active: bool = True
    daily_limit: float = 10000.0
    per_tx_limit: float = 10000.0
    saved_beneficiaries: List[str] = Field(default_factory=list)


class LedgerEntry(BaseModel):
    transaction_id: str
    test_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    source_account_id: str
    destination_account_id: str
    amount: float
    currency: str = "INR"
    memo: Optional[str] = None
    timestamp: str
    status: str
    policy_decision: Optional[str] = None


class BankSnapshot(BaseModel):
    timestamp: str
    accounts: Dict[str, float]  # account_id -> balance
    total_ledger_entries: int
    last_transaction_id: Optional[str] = None


class TestRequest(BaseModel):
    scenario_id: Optional[str] = None
    request_text: str
    notes: Optional[str] = None
    authenticated_customer_id: Optional[str] = "cust_alice_001"
    is_authenticated: bool = True
    source_account_id: Optional[str] = "ACC_ALICE_101"
    destination_account_id: Optional[str] = None
    amount: Optional[float] = None
    memo: Optional[str] = None
    idempotency_key: Optional[str] = None
    simulate_llm_failure: bool = False
    simulate_unauthorized_bypass: bool = False  # For verifier breach testing


class VerdictResponse(BaseModel):
    test_id: str
    timestamp: str
    scenario_id: Optional[str] = None
    decision: Decision
    risk_level: RiskLevel
    threat_category: ThreatCategory
    rationale: str
    detected_patterns: List[str]
    action: ActionType
    security_checks: SecurityChecks
    action_authorized: bool
    execution: ExecutionResult
    verification: VerificationResult
    evidence_url: str
    stages: List[PipelineStage] = Field(default_factory=list)
    account_snapshot_diff: Optional[Dict[str, Any]] = None


class EvidenceReport(BaseModel):
    test_id: str
    timestamp: str
    scenario_id: Optional[str] = None
    mode: str  # "CURATED" or "CUSTOM"
    original_request: str
    notes: Optional[str] = None
    normalized_input: NormalizedInput
    ai_analysis: AIThreatAnalysis
    deterministic_policy_checks: Dict[str, Any]
    final_verdict: Decision
    action_authorized: bool
    execution_result: ExecutionResult
    mock_bank_called: bool
    pre_test_balances: Dict[str, float]
    post_test_balances: Dict[str, float]
    ledger_entries_created: List[Dict[str, Any]]
    verification_result: VerificationResult
    security_guarantee_notes: str


class AnalyticsSummary(BaseModel):
    total_tests: int
    attacks_contained: int
    legitimate_processed: int
    verification_failures: int
    inconclusive_tests: int
    unauthorized_executed: int
    containment_rate_percent: float
    tested_attack_sample_size: int
    threat_category_breakdown: Dict[str, int]
    recent_tests: List[Dict[str, Any]]
