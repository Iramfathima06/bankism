"""
Deterministic Banking Security Policy Engine for BANKISM.
Operates strictly in trusted backend code.
Evaluates:
- Authentication (session / bearer validity)
- Authorization (account ownership and permission mapping)
- Transaction bounds and validation
- Hard per-transaction limits
- Daily cumulative limits calculated from trusted ledger records
- Risk-based decisioning (APPROVE / REVIEW / BLOCK)
"""

from typing import Dict, List, Optional, Tuple, Any

from backend.mock_bank import MockBankService, mock_bank
from backend.models import (
    ActionType,
    AIThreatAnalysis,
    CheckStatus,
    Decision,
    NormalizedInput,
    RiskLevel,
    SecurityChecks,
    TestRequest,
    ThreatCategory,
)


class PolicyEvaluationResult:
    def __init__(
        self,
        decision: Decision,
        action_authorized: bool,
        security_checks: SecurityChecks,
        rationale: str,
        detected_patterns: List[str],
        details: Dict[str, Any]
    ):
        self.decision = decision
        self.action_authorized = action_authorized
        self.security_checks = security_checks
        self.rationale = rationale
        self.detected_patterns = detected_patterns
        self.details = details


class DeterministicPolicyEngine:
    """Enforces non-negotiable banking security rules independently of the LLM."""

    def __init__(self, bank_service: MockBankService = mock_bank):
        self.bank = bank_service

    def evaluate(
        self,
        request: TestRequest,
        normalized: NormalizedInput,
        threat_analysis: AIThreatAnalysis
    ) -> PolicyEvaluationResult:
        security_checks = SecurityChecks()
        patterns: List[str] = list(threat_analysis.detected_patterns)
        details: Dict[str, Any] = {}

        # 1. Input Validation Check
        if threat_analysis.threat_category == ThreatCategory.OBFUSCATED_INSTRUCTION:
            security_checks.input_validation = CheckStatus.FAIL
        else:
            security_checks.input_validation = CheckStatus.PASS

        # 2. Threat Analysis Check
        if threat_analysis.threat_category in [
            ThreatCategory.PROMPT_INJECTION,
            ThreatCategory.MALICIOUS_MEMO,
            ThreatCategory.SENSITIVE_INFO_EXTRACTION,
        ]:
            security_checks.threat_analysis = CheckStatus.FAIL
        elif threat_analysis.threat_category in [
            ThreatCategory.AMBIGUOUS_REQUEST,
            ThreatCategory.OBFUSCATED_INSTRUCTION
        ]:
            security_checks.threat_analysis = CheckStatus.REVIEW
        else:
            security_checks.threat_analysis = CheckStatus.PASS

        # 3. Authentication Check
        if not request.is_authenticated:
            security_checks.authentication = CheckStatus.FAIL
            patterns.append("Unauthenticated request; missing valid identity credential.")
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Request lacks mandatory authentication. Banking operations require authenticated sessions.",
                detected_patterns=patterns,
                details={"authentication": "Missing or invalid session credentials"}
            )
        else:
            security_checks.authentication = CheckStatus.PASS

        # Resolve effective customer and source account
        cust_id = request.authenticated_customer_id or "cust_alice_001"
        source_acc_id = request.source_account_id or "ACC_ALICE_101"

        # Check if request text explicitly mentions another customer's account (e.g. ACC_VIKRAM_999)
        # or unauthorized phrase like "from another customer's account"
        requested_source = source_acc_id
        if normalized.extracted_account and normalized.extracted_account != source_acc_id:
            # User is attempting to specify an account outside their authenticated session
            requested_source = normalized.extracted_account

        # 4. Authorization Check
        owned_accounts = self.bank.get_customer_accounts(cust_id)
        owned_account_ids = [acc.account_id for acc in owned_accounts]

        # Handle sensitive info extraction or accessing other customers
        if threat_analysis.threat_category == ThreatCategory.SENSITIVE_INFO_EXTRACTION:
            security_checks.authorization = CheckStatus.FAIL
            patterns.append("Requester not authorized to view external customer data or credentials.")
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Requester is not authorized to access confidential customer data, credentials, or global ledger.",
                detected_patterns=patterns,
                details={"authorization": "Unauthorized customer information access"}
            )

        # Check source account ownership
        if requested_source not in owned_account_ids:
            security_checks.authorization = CheckStatus.FAIL
            patterns.append(f"Account {requested_source} is not owned by authenticated customer {cust_id}.")
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Requester attempted to access or transfer funds from an account they do not own.",
                detected_patterns=patterns,
                details={"authorization": f"Account {requested_source} not owned by {cust_id}"}
            )
        else:
            security_checks.authorization = CheckStatus.PASS

        # If Prompt Injection was detected:
        if threat_analysis.threat_category == ThreatCategory.PROMPT_INJECTION:
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Direct prompt injection or security policy override detected. Action blocked.",
                detected_patterns=patterns,
                details={"policy": "Prompt injection detected; zero execution permitted."}
            )

        # If Malicious Memo was detected:
        if threat_analysis.threat_category == ThreatCategory.MALICIOUS_MEMO:
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Payment memo contains untrusted instructions or exfiltration attempts. Operation blocked.",
                detected_patterns=patterns,
                details={"policy": "Malicious memo detected."}
            )

        # 5. Intent-specific policy enforcement
        # Case A: Balance Inquiry
        if threat_analysis.intent == ActionType.BALANCE_INQUIRY:
            security_checks.transaction_limit = CheckStatus.NOT_APPLICABLE
            security_checks.cumulative_limit = CheckStatus.NOT_APPLICABLE
            security_checks.idempotency = CheckStatus.NOT_APPLICABLE

            return PolicyEvaluationResult(
                decision=Decision.APPROVE,
                action_authorized=True,
                security_checks=security_checks,
                rationale="Authorized balance inquiry passed all authentication and ownership checks.",
                detected_patterns=patterns,
                details={"action": "BALANCE_INQUIRY", "account_id": source_acc_id}
            )

        # Case B: Ambiguous Transfer Request
        if threat_analysis.threat_category == ThreatCategory.AMBIGUOUS_REQUEST or threat_analysis.is_ambiguous:
            return PolicyEvaluationResult(
                decision=Decision.REVIEW,
                action_authorized=False,
                security_checks=security_checks,
                rationale="Request is ambiguous or missing required parameters (beneficiary or amount). Execution held for review.",
                detected_patterns=patterns,
                details={"missing_fields": threat_analysis.missing_fields}
            )

        # Case C: Transfer Money
        if threat_analysis.intent == ActionType.TRANSFER_MONEY:
            source_acc = self.bank.get_account(source_acc_id)
            if not source_acc:
                security_checks.authorization = CheckStatus.FAIL
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale=f"Source account {source_acc_id} does not exist.",
                    detected_patterns=patterns,
                    details={"error": "Invalid source account"}
                )

            # Resolve amount
            amount = request.amount or normalized.extracted_amount or 0.0
            if amount <= 0.0:
                security_checks.transaction_limit = CheckStatus.FAIL
                return PolicyEvaluationResult(
                    decision=Decision.REVIEW,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale="Invalid or non-positive transfer amount. Requires valid positive currency amount.",
                    detected_patterns=patterns,
                    details={"amount": amount}
                )

            # Resolve destination beneficiary
            dest_acc_id = request.destination_account_id
            if not dest_acc_id:
                if normalized.extracted_beneficiary:
                    b_str = normalized.extracted_beneficiary.upper()
                    if b_str in ["BOB", "ACC_BOB_201", "SAVED_BENEFICIARY"]:
                        dest_acc_id = "ACC_BOB_201"
                    elif b_str in self.bank.accounts:
                        dest_acc_id = b_str

            if not dest_acc_id:
                # Default to saved beneficiary if mentioned
                if "saved beneficiary" in normalized.cleaned_text.lower() and source_acc.saved_beneficiaries:
                    dest_acc_id = source_acc.saved_beneficiaries[0]
                else:
                    return PolicyEvaluationResult(
                        decision=Decision.REVIEW,
                        action_authorized=False,
                        security_checks=security_checks,
                        rationale="Unspecified or unresolvable destination beneficiary.",
                        detected_patterns=patterns,
                        details={"error": "Beneficiary missing"}
                    )

            # Check if destination exists
            dest_acc = self.bank.get_account(dest_acc_id)
            if not dest_acc:
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale=f"Destination account {dest_acc_id} does not exist in banking registry.",
                    detected_patterns=patterns,
                    details={"error": "Unknown beneficiary"}
                )

            # 6. Check Idempotency Key
            if request.idempotency_key:
                existing_tx = self.bank.check_idempotency(request.idempotency_key)
                if existing_tx:
                    security_checks.idempotency = CheckStatus.FAIL
                    patterns.append(f"Duplicate transaction request detected (Key: {request.idempotency_key}).")
                    return PolicyEvaluationResult(
                        decision=Decision.BLOCK,
                        action_authorized=False,
                        security_checks=security_checks,
                        rationale=f"Transaction with idempotency key '{request.idempotency_key}' already processed. Duplicate execution blocked.",
                        detected_patterns=patterns,
                        details={"duplicate_transaction_id": existing_tx.transaction_id}
                    )
                else:
                    security_checks.idempotency = CheckStatus.PASS
            else:
                security_checks.idempotency = CheckStatus.NOT_APPLICABLE

            # 7. Check Per-Transaction Limit (e.g. ₹10,000)
            if amount > source_acc.per_tx_limit:
                security_checks.transaction_limit = CheckStatus.FAIL
                patterns.append(f"Amount ₹{amount:.2f} exceeds per-transaction limit of ₹{source_acc.per_tx_limit:.2f}.")
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale=f"Per-transaction limit violation: Requested ₹{amount:.2f} exceeds maximum threshold ₹{source_acc.per_tx_limit:.2f}. Deterministic policy blocks execution.",
                    detected_patterns=patterns,
                    details={
                        "per_tx_limit": source_acc.per_tx_limit,
                        "requested_amount": amount,
                        "limit_type": "PER_TRANSACTION"
                    }
                )
            else:
                security_checks.transaction_limit = CheckStatus.PASS

            # 8. Check Daily Cumulative Limit from Trusted Ledger Records
            daily_transferred = self.bank.get_daily_cumulative_transferred(source_acc_id)
            if daily_transferred + amount > source_acc.daily_limit:
                security_checks.cumulative_limit = CheckStatus.FAIL
                patterns.append(
                    f"Cumulative daily total ₹{(daily_transferred + amount):.2f} exceeds daily limit ₹{source_acc.daily_limit:.2f}."
                )
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale=f"Daily cumulative limit exceeded: Prior transfers today ₹{daily_transferred:.2f} + current ₹{amount:.2f} exceeds daily limit ₹{source_acc.daily_limit:.2f}. Prevents splitting circumvention.",
                    detected_patterns=patterns,
                    details={
                        "prior_daily_transferred": daily_transferred,
                        "daily_limit": source_acc.daily_limit,
                        "requested_amount": amount
                    }
                )
            else:
                security_checks.cumulative_limit = CheckStatus.PASS

            # 9. Sufficient Funds Check
            if source_acc.balance < amount:
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    action_authorized=False,
                    security_checks=security_checks,
                    rationale=f"Insufficient funds: Available balance ₹{source_acc.balance:.2f} is less than requested ₹{amount:.2f}.",
                    detected_patterns=patterns,
                    details={"available_balance": source_acc.balance, "requested_amount": amount}
                )

            # All checks pass!
            return PolicyEvaluationResult(
                decision=Decision.APPROVE,
                action_authorized=True,
                security_checks=security_checks,
                rationale="All deterministic banking policies, identity verification, and limit checks satisfied.",
                detected_patterns=patterns,
                details={
                    "source_account_id": source_acc_id,
                    "destination_account_id": dest_acc_id,
                    "amount": amount,
                    "currency": "INR"
                }
            )

        # Default for unknown action
        return PolicyEvaluationResult(
            decision=Decision.REVIEW,
            action_authorized=False,
            security_checks=security_checks,
            rationale="Unrecognized banking action. Execution held pending review.",
            detected_patterns=patterns,
            details={"intent": threat_analysis.intent}
        )


# Global deterministic policy engine
policy_engine = DeterministicPolicyEngine()
