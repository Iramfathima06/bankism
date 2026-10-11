"""
Simulated Mock Banking System for BANKISM.
Provides deterministic accounts, transactions ledger, idempotency checks,
and state snapshotting for independent verification.
"""

import copy
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from backend.models import BankAccount, LedgerEntry, BankSnapshot


INITIAL_ACCOUNTS: Dict[str, BankAccount] = {
    "ACC_ALICE_101": BankAccount(
        account_id="ACC_ALICE_101",
        customer_id="cust_alice_001",
        customer_name="Alice Sharma",
        account_type="SAVINGS",
        balance=45000.00,
        currency="INR",
        is_active=True,
        daily_limit=10000.00,
        per_tx_limit=10000.00,
        saved_beneficiaries=["ACC_BOB_201"]
    ),
    "ACC_BOB_201": BankAccount(
        account_id="ACC_BOB_201",
        customer_id="cust_bob_002",
        customer_name="Bob Patel",
        account_type="CURRENT",
        balance=20000.00,
        currency="INR",
        is_active=True,
        daily_limit=25000.00,
        per_tx_limit=20000.00,
        saved_beneficiaries=["ACC_ALICE_101"]
    ),
    "ACC_VIKRAM_999": BankAccount(
        account_id="ACC_VIKRAM_999",
        customer_id="cust_vikram_003",
        customer_name="Vikram Malhotra",
        account_type="WEALTH_SAVINGS",
        balance=500000.00,
        currency="INR",
        is_active=True,
        daily_limit=100000.00,
        per_tx_limit=50000.00,
        saved_beneficiaries=[]
    ),
}


class MockBankService:
    """Thread-safe Mock Banking Service maintaining balances, ledger, and state snapshots."""

    def __init__(self):
        self._lock = threading.RLock()
        self.accounts: Dict[str, BankAccount] = {}
        self.ledger: List[LedgerEntry] = []
        self.processed_idempotency_keys: Dict[str, str] = {}  # idempotency_key -> transaction_id
        self._initialize_state()

    def _initialize_state(self):
        with self._lock:
            self.accounts = {acc_id: copy.deepcopy(acc) for acc_id, acc in INITIAL_ACCOUNTS.items()}
            self.ledger.clear()
            self.processed_idempotency_keys.clear()

    def reset_sandbox(self, clear_ledger: bool = True) -> Dict[str, Any]:
        """Resets the mock banking sandbox back to the deterministic initial state."""
        with self._lock:
            self.accounts = {acc_id: copy.deepcopy(acc) for acc_id, acc in INITIAL_ACCOUNTS.items()}
            if clear_ledger:
                self.ledger.clear()
                self.processed_idempotency_keys.clear()
            return {
                "message": "Mock banking sandbox successfully reset to initial deterministic state.",
                "accounts_reset": list(self.accounts.keys()),
                "ledger_entries_retained": len(self.ledger)
            }

    def get_account(self, account_id: str) -> Optional[BankAccount]:
        with self._lock:
            acc = self.accounts.get(account_id)
            return copy.deepcopy(acc) if acc else None

    def get_all_accounts(self) -> List[BankAccount]:
        with self._lock:
            return [copy.deepcopy(acc) for acc in self.accounts.values()]

    def get_customer_accounts(self, customer_id: str) -> List[BankAccount]:
        with self._lock:
            return [
                copy.deepcopy(acc)
                for acc in self.accounts.values()
                if acc.customer_id == customer_id
            ]

    def get_ledger(self, limit: int = 50) -> List[LedgerEntry]:
        with self._lock:
            return [copy.deepcopy(entry) for entry in reversed(self.ledger[-limit:])]

    def get_ledger_for_test(self, test_id: str) -> List[LedgerEntry]:
        with self._lock:
            return [
                copy.deepcopy(entry)
                for entry in self.ledger
                if entry.test_id == test_id
            ]

    def check_idempotency(self, idempotency_key: str) -> Optional[LedgerEntry]:
        """Returns existing transaction if idempotency key was previously processed."""
        if not idempotency_key:
            return None
        with self._lock:
            tx_id = self.processed_idempotency_keys.get(idempotency_key)
            if tx_id:
                for entry in self.ledger:
                    if entry.transaction_id == tx_id:
                        return copy.deepcopy(entry)
            return None

    def get_daily_cumulative_transferred(self, account_id: str) -> float:
        """
        Calculates total transferred out of this account today from trusted ledger records.
        Prevents circumvention by splitting transactions.
        """
        with self._lock:
            total = 0.0
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            for entry in self.ledger:
                if entry.source_account_id == account_id and entry.status == "SUCCESS":
                    if entry.timestamp.startswith(today_str):
                        total += entry.amount
            return total

    def take_snapshot(self) -> BankSnapshot:
        """Takes an immutable snapshot of all account balances and ledger state."""
        with self._lock:
            balances = {acc_id: acc.balance for acc_id, acc in self.accounts.items()}
            last_tx = self.ledger[-1].transaction_id if self.ledger else None
            return BankSnapshot(
                timestamp=datetime.now(timezone.utc).isoformat(),
                accounts=balances,
                total_ledger_entries=len(self.ledger),
                last_transaction_id=last_tx
            )

    def execute_transfer(
        self,
        source_account_id: str,
        destination_account_id: str,
        amount: float,
        test_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        memo: Optional[str] = None,
        policy_decision: Optional[str] = "APPROVE"
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Executes a transfer directly against the mock banking ledger and account balances.
        Returns: (success: bool, transaction_id: str | None, error_message: str | None)
        """
        with self._lock:
            # Check idempotency
            if idempotency_key and idempotency_key in self.processed_idempotency_keys:
                existing_tx_id = self.processed_idempotency_keys[idempotency_key]
                return True, existing_tx_id, "Idempotent duplicate request; returning previously executed transaction."

            source = self.accounts.get(source_account_id)
            if not source:
                return False, None, f"Source account {source_account_id} not found."

            dest = self.accounts.get(destination_account_id)
            if not dest:
                return False, None, f"Destination account {destination_account_id} not found."

            if source_account_id == destination_account_id:
                return False, None, "Source and destination accounts cannot be identical."

            if amount <= 0:
                return False, None, "Transfer amount must be strictly greater than zero."

            if source.balance < amount:
                return False, None, f"Insufficient funds: Balance ₹{source.balance:.2f} is less than ₹{amount:.2f}."

            # Atomic ledger update and balance alteration
            tx_id = f"TXN-{uuid.uuid4().hex[:10].upper()}"
            now_iso = datetime.now(timezone.utc).isoformat()

            source.balance = round(source.balance - amount, 2)
            dest.balance = round(dest.balance + amount, 2)

            entry = LedgerEntry(
                transaction_id=tx_id,
                test_id=test_id,
                idempotency_key=idempotency_key,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount=amount,
                currency="INR",
                memo=memo,
                timestamp=now_iso,
                status="SUCCESS",
                policy_decision=policy_decision
            )
            self.ledger.append(entry)

            if idempotency_key:
                self.processed_idempotency_keys[idempotency_key] = tx_id

            return True, tx_id, None


# Global singleton instance
mock_bank = MockBankService()
