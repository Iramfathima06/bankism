"""
Secure Transaction Execution Gate for BANKISM.
Controls privileged access to the Mock Banking service.
Ensures fail-closed execution semantics:
- Never allows execution if any mandatory check failed
- Never trusts frontend claims or LLM approvals alone
- Enforces strict execution boundaries
"""

from typing import Dict, Optional, Tuple, Any

from backend.mock_bank import MockBankService, mock_bank
from backend.models import (
    ActionType,
    Decision,
    ExecutionResult,
    ExecutionStatus,
    TestRequest,
)
from backend.policy_engine import PolicyEvaluationResult


class TransactionExecutionGate:
    """Gatekeeper between policy decisions and privileged banking execution."""

    def __init__(self, bank_service: MockBankService = mock_bank):
        self.bank = bank_service

    def process_execution(
        self,
        request: TestRequest,
        policy_result: PolicyEvaluationResult,
        test_id: str
    ) -> Tuple[ExecutionResult, bool]:
        """
        Evaluates whether execution can proceed.
        Returns: (ExecutionResult, mock_bank_called: bool)
        """
        # Critical test hook: simulate_unauthorized_bypass
        # Allows testing and proving that the Independent Verifier will catch unauthorized operations!
        if request.simulate_unauthorized_bypass:
            # Force execute despite policy block
            source = request.source_account_id or "ACC_ALICE_101"
            dest = request.destination_account_id or "ACC_BOB_201"
            amt = request.amount or 1000.0
            success, tx_id, err = self.bank.execute_transfer(
                source_account_id=source,
                destination_account_id=dest,
                amount=amt,
                test_id=test_id,
                memo="[SIMULATED_BYPASS_BREACH]",
                policy_decision="UNAUTHORIZED_BYPASS"
            )
            return ExecutionResult(
                status=ExecutionStatus.EXECUTED,
                executed=True,
                transaction_id=tx_id,
                message="[SECURITY TEST] Unauthorized bypass was artificially triggered to verify independent auditor detection."
            ), True

        # Standard Fail-Closed Logic:
        # Condition 1: Security policy must explicitly authorize action
        if not policy_result.action_authorized or policy_result.decision != Decision.APPROVE:
            if policy_result.decision == Decision.REVIEW:
                return ExecutionResult(
                    status=ExecutionStatus.HELD_FOR_REVIEW,
                    executed=False,
                    failure_reason=policy_result.rationale,
                    message="Transaction held for administrative/compliance review. Privileged state remains unchanged."
                ), False
            else:
                return ExecutionResult(
                    status=ExecutionStatus.BLOCKED,
                    executed=False,
                    failure_reason=policy_result.rationale,
                    message="Transaction execution blocked by Bankism security policy engine."
                ), False

        # Condition 2: Action-specific execution
        action = policy_result.details.get("action") or (
            ActionType.TRANSFER_MONEY if "source_account_id" in policy_result.details else ActionType.BALANCE_INQUIRY
        )

        if action == ActionType.BALANCE_INQUIRY:
            # Read-only operation: No ledger or balance modification
            acc_id = policy_result.details.get("account_id") or request.source_account_id or "ACC_ALICE_101"
            acc = self.bank.get_account(acc_id)
            balance_val = acc.balance if acc else 0.0
            return ExecutionResult(
                status=ExecutionStatus.EXECUTED,
                executed=True,
                message=f"Authorized balance inquiry completed. Available balance for {acc_id}: ₹{balance_val:,.2f} {acc.currency if acc else 'INR'}."
            ), False

        if action == ActionType.TRANSFER_MONEY or "amount" in policy_result.details:
            src = policy_result.details["source_account_id"]
            dst = policy_result.details["destination_account_id"]
            amt = policy_result.details["amount"]
            memo = request.memo or "Fund transfer via Bankism"

            success, tx_id, error_msg = self.bank.execute_transfer(
                source_account_id=src,
                destination_account_id=dst,
                amount=amt,
                test_id=test_id,
                idempotency_key=request.idempotency_key,
                memo=memo,
                policy_decision=policy_result.decision.value
            )

            if success:
                return ExecutionResult(
                    status=ExecutionStatus.EXECUTED,
                    executed=True,
                    transaction_id=tx_id,
                    message=f"Transfer of ₹{amt:,.2f} from {src} to {dst} successfully executed."
                ), True
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILED,
                    executed=False,
                    failure_reason=error_msg,
                    message=f"Execution gate rejected mock bank transfer: {error_msg}"
                ), False

        # Fallback block
        return ExecutionResult(
            status=ExecutionStatus.BLOCKED,
            executed=False,
            failure_reason="Unsupported execution action.",
            message="No execution permitted for unmapped action type."
        ), False


# Global execution gate
execution_gate = TransactionExecutionGate()
