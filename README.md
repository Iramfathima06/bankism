# BANKISM — AI-Powered Banking Security Firewall & Live Attack Lab

> **Defensive Architecture:** Attack → Analyze → Defend → Control Execution → Verify Outcome → Generate Evidence.

---

## 1. Executive Summary & Problem Statement

Modern financial institutions are rapidly deploying Large Language Models (LLMs) and conversational AI assistants to process customer requests, query accounts, and execute fund transfers. However, LLMs are fundamentally non-deterministic and susceptible to:
- **Direct Prompt Injections & Jailbreaks** ("Ignore prior rules and disable firewall")
- **Indirect Injections hidden in Payment Memos** (Untrusted instruction smuggling)
- **Account Takeover & IDOR** (Requesting transfers from accounts not owned by the requester)
- **Transaction-Limit Bypasses & Smurfing** (Splitting high amounts to bypass single-transaction limits)
- **Data Exfiltration Probes** (Extracting credentials and customer records)

A model that merely flags attacks as "MALICIOUS" is insufficient. A security system claiming to have blocked an attack does not prove that the simulated financial state remained untampered.

**BANKISM solves both problems:**
1. **Deterministic Banking Security Firewall:** Sits between untrusted AI assistants and privileged banking operations. It validates input encodings, runs threat analysis (via Gemini/OpenAI or transparent rule-based fallback), and enforces deterministic, non-negotiable security policies (Authentication, Authorization, Limits, Idempotency).
2. **Independent Security Verification Engine:** Inspects the actual mock banking ledger and balance deltas before and after every request. It does **not** trust the LLM or firewall's self-reported verdict—it mathematically audits whether funds moved or remained locked.
3. **Interactive Live Attack Lab:** Enables hackathon judges to launch 14 pre-configured security scenarios or type custom adversarial payloads to observe real-time 9-stage pipeline progression and tamper-evident cryptographic evidence certificates.

---

## 2. System Architecture

```
                                  [ Untrusted User / Adversary ]
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 1: Request Reception & Tagging       │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 2: Input Normalizer & Inspection     │
                         │   (Homoglyphs, Base64, Hex, Zero-Width)     │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 3: AI Threat Analysis                │
                         │   (Gemini 1.5 / GPT-4o-mini / Fallback)     │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 4 & 5: Deterministic Policy Engine   │
                         │   - Authentication (Session Token)          │
                         │   - Authorization (Account Ownership)       │
                         │   - Per-Tx Limit (₹10,000 ceiling)           │
                         │   - Cumulative Daily Limit (₹10,000 max)     │
                         │   - Idempotency / Replay Shield             │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 6: Firewall Verdict Synthesizer      │
                         │   (APPROVE / REVIEW / BLOCK)                 │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 7: Transaction Execution Gate        │
                         │   (Fail-Closed Privileged Boundary)          │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 8: Independent State Verifier        │
                         │   (Pre/Post Balances & Ledger Invariant)    │
                         │   -> PASS | FAIL | INCONCLUSIVE             │
                         └──────────────────────┬───────────────────────┘
                                                │
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │   Stage 9: Audit Evidence & SQLite Store     │
                         │   (Tamper-Evident Proof & JSON Export)      │
                         └──────────────────────────────────────────────┘
```

---

## 3. Technology Stack

- **Backend:** Python 3.14 / 3.10+, FastAPI, Pydantic v2, Uvicorn, HTTPX
- **Database & Audit:** SQLite (`bankism_audit.db`) with thread-safe in-memory cache
- **Frontend:** Semantic HTML5, modern CSS3 (Cybersecurity Dark Navy theme), Vanilla ES6 JavaScript (zero npm build dependencies, zero broken CDN links)
- **Testing:** Pytest, FastAPI TestClient (20 automated security test suites)

---

## 4. Installation & Setup

### Prerequisites
- Python 3.10 or higher (Python 3.14 supported)
- Standard web browser (Chrome, Edge, Firefox, Safari)

### Step 1: Install Python Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `fastapi`, `uvicorn`, `pydantic`, `httpx`, `pytest`, `python-dotenv`)*

### Step 2: Environment Configuration (Optional)
Bankism is engineered to run **100% out of the box in Rule-Based Fallback Mode** without any paid API keys or external network dependencies.

To optionally connect a live LLM:
```bash
cp .env.example .env
```
Add your optional API key in `.env`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
# or
OPENAI_API_KEY=your_openai_api_key_here
```

---

## 5. Starting the Application

Launch the unified server (serves both the frontend dashboard and backend API):
```bash
python run.py
```

The console will indicate the active address:
```
======================================================================
   BANKISM — AI Banking Security Firewall & Live Attack Lab
   Defensive Architecture: Attack -> Analyze -> Defend -> Gate -> Verify
======================================================================
 * Serving UI and API at: http://127.0.0.1:8000
 * API Documentation at:  http://127.0.0.1:8000/docs
 * Independent Verifier:  ACTIVE
 * Operating Mode:        Rule-Based Fallback (Optional LLM enabled via .env)
======================================================================
```

Open **`http://127.0.0.1:8000`** in your browser.

---

## 6. Running the Automated Test Suite

Bankism includes 20 comprehensive automated tests validating all security requirements of Section 19:

```bash
python -m pytest tests/test_all.py -v
```

### Actual Test Execution Output:
```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1 -- rootdir: E:\projects\anti_agent
collected 20 items

tests/test_all.py::test_01_legitimate_balance_inquiry PASSED             [  5%]
tests/test_all.py::test_02_balance_inquiry_without_auth PASSED           [ 10%]
tests/test_all.py::test_03_unauthorized_account_access PASSED            [ 15%]
tests/test_all.py::test_04_prompt_injection_attempt PASSED               [ 20%]
tests/test_all.py::test_05_transaction_above_limit PASSED                [ 25%]
tests/test_all.py::test_06_daily_cumulative_limit PASSED                 [ 30%]
tests/test_all.py::test_07_malicious_payment_memo PASSED                 [ 35%]
tests/test_all.py::test_08_ambiguous_transaction_request PASSED          [ 40%]
tests/test_all.py::test_09_obfuscated_input_handling PASSED              [ 45%]
tests/test_all.py::test_10_llm_failure_fallback PASSED                   [ 50%]
tests/test_all.py::test_11_invalid_llm_json_fallback PASSED              [ 55%]
tests/test_all.py::test_12_duplicate_transaction_submission PASSED       [ 60%]
tests/test_all.py::test_13_successful_legitimate_transfer PASSED         [ 65%]
tests/test_all.py::test_14_blocked_transfer_leaves_ledger_unchanged PASSED [ 70%]
tests/test_all.py::test_15_unauthorized_transfer_triggers_verification_failure PASSED [ 75%]
tests/test_all.py::test_16_verifier_inconclusive_when_state_missing PASSED [ 80%]
tests/test_all.py::test_17_evidence_record_matches_outcome PASSED        [ 85%]
tests/test_all.py::test_18_analytics_calculation_real_records PASSED     [ 90%]
tests/test_all.py::test_19_repeated_attacks_fail_closed PASSED           [ 95%]
tests/test_all.py::test_20_sandbox_reset PASSED                          [100%]

======================= 20 passed in 1.35s ====================================
```

---

## 7. Curated Scenario Library (Mode A)

Bankism provides 14 pre-configured test scenarios ready for single-click execution:

| Scenario ID | Name | Threat Category | Expected Outcome |
|---|---|---|---|
| `scenario-1` | Legitimate Balance Inquiry | `BENIGN` | `READ_ONLY_AUTHORIZED` |
| `scenario-2` | Legitimate Fund Transfer (₹2,000) | `BENIGN` | `TRANSFER_EXECUTED` |
| `scenario-3` | Direct Prompt Injection | `PROMPT_INJECTION` | `NO_TRANSFER` |
| `scenario-4` | Unauthorized Account Takeover (Vikram) | `UNAUTHORIZED_TRANSFER` | `NO_TRANSFER` |
| `scenario-5` | Single Transaction Limit Violation (₹50k > ₹10k) | `LIMIT_VIOLATION` | `NO_TRANSFER` |
| `scenario-6` | Daily Cumulative Limit Circumvention | `CUMULATIVE_LIMIT_VIOLATION` | `NO_TRANSFER` |
| `scenario-7` | Malicious Payment Memo Injection | `MALICIOUS_MEMO` | `NO_TRANSFER` |
| `scenario-8` | Sensitive Credential & Data Exfiltration | `SENSITIVE_INFO_EXTRACTION` | `NO_TRANSFER` |
| `scenario-9` | Ambiguous Banking Request ("Send to that person") | `AMBIGUOUS_REQUEST` | `HELD_FOR_REVIEW` |
| `scenario-10` | Missing Authentication Token | `MISSING_AUTHENTICATION` | `AUTH_BLOCKED` |
| `scenario-11` | Obfuscated Cyrillic Homoglyphs | `OBFUSCATED_INSTRUCTION` | `NO_TRANSFER` |
| `scenario-12` | Simulated LLM Failure / Outage | `MODEL_FAILURE` | `NO_TRANSFER` |
| `scenario-13` | Replay / Duplicate Idempotency Key | `DUPLICATE_TRANSACTION` | `NO_TRANSFER` |
| `scenario-14` | Legitimate Control Benchmark (₹1,500) | `BENIGN` | `TRANSFER_EXECUTED` |

---

## 8. Custom  Attack Interface (Mode B)

Judges can type arbitrary natural-language attacks in the Custom Attack Sandbox:
1. Navigate to **Live Attack Lab** → **Mode B: Custom Judge Attacks**.
2. Click any judge shortcut button or type a custom request into the textarea.
3. Optionally expand **Advanced Security Parameters**:
   - Change simulated customer (`Alice`, `Bob`, `Vikram`).
   - Uncheck `Request is Authenticated` to simulate unauthenticated API calls.
   - Check `Simulate LLM Outage` to verify fail-closed fallback behavior.
   - Check `Simulate Gate Bypass` to test the Independent Verifier catching a breach!
4. Click **Execute Security Pipeline**.
5. The view instantly switches to the **Live Visualizer**, stepping through all 9 stages in real time with backend execution times in milliseconds.

---

## 9. Inspecting Independent Verification Reports

For every test execution, click **Inspect Cryptographic Evidence & Balance Snapshot Proof**:
- **Test ID & Timestamp:** Unique tracking identifier.
- **Untrusted Request & Normalized Input:** Decoded homoglyphs and extracted parameters.
- **Pre-Test vs Post-Test Balances:** Exact balance snapshot table with highlighted deltas.
- **Ledger Records:** Confirmed transaction hash, timestamps, and idempotency status.
- **Auditor Proof Rationale:** Mathematical confirmation why the test was marked `PASS`, `FAIL`, or `INCONCLUSIVE`.
- **JSON Export:** Click **Export Evidence JSON** to download a verifiable report.

---

## 10. Mock Banking Sandbox & Reset Mechanics

Under **Mock Bank & Ledger**, judges can inspect live account cards:
- **Alice Sharma (`ACC_ALICE_101`):** ₹45,000.00 (Savings, Limit: ₹10k per-tx / ₹10k daily)
- **Bob Patel (`ACC_BOB_201`):** ₹20,000.00 (Current, Limit: ₹25k)
- **Vikram Malhotra (`ACC_VIKRAM_999`):** ₹500,000.00 (Wealth Savings, Target Account)

Click **Reset Sandbox**:
- Confirms before resetting mock accounts back to starting balances.
- By default, **preserves** the audit history table so test evidence is never lost.

---

## 11. Rule-Based Fallback Engine Specification

When no paid LLM API key is configured or during model outages:
- **Input Normalizer:** Flags Cyrillic homoglyphs (`а`, `е`, `о`, `р`, `с`, `у`, `х`, `і`), zero-width spaces (`\u200B`), Base64 payloads, and hex strings.
- **Pattern Classifiers:** Detects instruction overrides, exfiltration keywords, unauthorized account access terms, and ambiguous references.
- **Deterministic Policy Engine:** Enforces authentication, account ownership, ₹10k per-transaction ceilings, and cumulative ledger sums.
- **Fail-Closed Guarantee:** Privileged actions are rejected if any condition cannot be satisfied.

---

## 12. Security Limitations (Documented Boundary)

This application is an educational prototype built for hackathon evaluation:
1. **Sandboxed Data:** Operates strictly with simulated bank accounts; no live banking APIs (SWIFT, UPI, ACH) are connected.
2. **Obfuscation Limits:** The rule-based fallback detects known homoglyphs, Base64, and zero-width spaces, but novel steganographic vectors require full LLM reasoning.
3. **Authentication:** Uses simulated bearer sessions rather than cryptographic OAuth2/JWT signatures.

---


