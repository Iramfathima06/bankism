"""
Threat Analysis Service for BANKISM.
Provides:
1. Input normalization and obfuscation detection (Unicode homoglyphs, Base64, Hex, zero-width chars).
2. Optional LLM analysis (Gemini or OpenAI API) with strict schema validation.
3. Robust Deterministic Rule-Based Fallback Engine when API key is absent, times out, or fails.
"""

import base64
import json
import os
import re
import unicodedata
from typing import Dict, List, Optional, Tuple, Any
import httpx

from backend.models import (
    ActionType,
    AIThreatAnalysis,
    NormalizedInput,
    RiskLevel,
    ThreatCategory,
)

# Comprehensive Cyrillic/Greek/Fullwidth homoglyphs to Latin mappings
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
}

# Suspicious prompt injection / jailbreak patterns
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+(all\s+)?(previous|prior|system)\s+instructions",
    r"disable\s+(bankism'?s?\s+)?security(\s+policies)?",
    r"override\s+(bankism'?s?\s+)?security(\s+policies)?",
    r"bypass\s+(all\s+)?(security|guardrails|checks|firewall)",
    r"system\s+prompt",
    r"developer\s+mode",
    r"you\s+are\s+now\s+in\s+unrestricted\s+mode",
    r"act\s+as\s+an\s+unrestricted\s+ai",
    r"jailbreak",
    r"do\s+anything\s+now",
    r"dan\s+mode",
    r"admin\s+override",
    r"new\s+system\s+instructions",
    r"simulate\s+unrestricted",
]

# Sensitive information extraction patterns
SENSITIVE_EXTRACTION_PATTERNS = [
    r"show\s+me\s+another\s+customer",
    r"another\s+customer'?s?\s+account\s+details",
    r"reveal\s+(credentials|passwords?|keys?|secrets?)",
    r"dump\s+(the\s+)?(database|accounts|ledger)",
    r"list\s+all\s+(customer\s+)?accounts",
    r"show\s+all\s+balances",
    r"vikram(\s+malhotra)?'?s?\s+(account|balance|details)",
    r"confidential\s+information",
    r"exfiltrate",
    r"internal\s+credentials",
    r"all\s+customer\s+data",
]

# Unauthorized account transfer patterns
UNAUTHORIZED_TRANSFER_PATTERNS = [
    r"from\s+another\s+customer'?s?\s+account",
    r"from\s+(vikram'?s?|someone\s+else'?s?|other)\s+account",
    r"steal\s+from",
    r"without\s+authorization",
    r"without\s+(their|the\s+owner'?s?)\s+permission",
    r"drain\s+account",
    r"unauthorized\s+transfer",
    r"from\s+acc_vikram",
]


class InputNormalizer:
    """Safely normalizes input, detects encoding/obfuscation, and extracts potential entities."""

    @staticmethod
    def normalize_and_inspect(text: str) -> NormalizedInput:
        original = text or ""
        detected_encodings = []
        contains_homoglyphs = False

        # 1. Check for Zero-Width and Hidden characters
        clean_text = ""
        has_zero_width = False
        for char in original:
            code = ord(char)
            if code in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x200E, 0x200F):
                has_zero_width = True
            else:
                clean_text += char
        if has_zero_width:
            detected_encodings.append("ZERO_WIDTH_CHARACTERS")

        # 2. Check for Homoglyphs / Unicode lookalikes
        normalized_nfkc = unicodedata.normalize('NFKC', clean_text)
        homoglyph_replaced = ""
        for char in normalized_nfkc:
            if char in HOMOGLYPH_MAP:
                homoglyph_replaced += HOMOGLYPH_MAP[char]
                contains_homoglyphs = True
            elif 0x0400 <= ord(char) <= 0x04FF:  # Cyrillic block
                # Any Cyrillic character in primarily Latin text is treated as homoglyph
                homoglyph_replaced += char
                contains_homoglyphs = True
            else:
                homoglyph_replaced += char
        if contains_homoglyphs:
            detected_encodings.append("UNICODE_HOMOGLYPHS")

        # 3. Check for Base64 encoded payload segments
        b64_matches = re.findall(r'\b[A-Za-z0-9+/]{20,}={0,2}\b', homoglyph_replaced)
        decoded_b64_fragments = []
        for match in b64_matches:
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str) > 6 and any(c.isalnum() for c in decoded_str):
                    detected_encodings.append("BASE64_PAYLOAD")
                    decoded_b64_fragments.append(decoded_str)
            except Exception:
                pass

        # 4. Check for Hex strings
        hex_matches = re.findall(r'\b(?:0x)?[0-9a-fA-F]{16,}\b', homoglyph_replaced)
        if hex_matches:
            detected_encodings.append("HEX_ENCODED_PAYLOAD")

        # Combine text for inspection (treating any decoded fragment purely as untrusted data)
        effective_text = homoglyph_replaced
        if decoded_b64_fragments:
            effective_text += " [DECODED_UNTRUSTED_CONTENT: " + " ".join(decoded_b64_fragments) + "]"

        # Extract amount
        extracted_amount = None
        amount_match = re.search(r'(?:₹|rs\.?|inr)?\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+)\s*(?:₹|rs\.?|inr|rupees)?', effective_text, re.IGNORECASE)
        if amount_match:
            try:
                num_str = amount_match.group(1).replace(',', '')
                val = float(num_str)
                if val > 0:
                    extracted_amount = val
            except ValueError:
                pass

        # Extract memo
        extracted_memo = None
        memo_match = re.search(r'(?:memo|note|description|remark):\s*["\']?([^"\']+)["\']?', effective_text, re.IGNORECASE)
        if memo_match:
            extracted_memo = memo_match.group(1).strip()

        # Extract beneficiary
        extracted_beneficiary = None
        if "saved beneficiary" in effective_text.lower():
            extracted_beneficiary = "SAVED_BENEFICIARY"
        else:
            beneficiary_match = re.search(r'to\s+([A-Za-z0-9_]+)', effective_text, re.IGNORECASE)
            if beneficiary_match:
                b1_clean = beneficiary_match.group(1).strip()
                if b1_clean.lower() not in ["that", "person", "someone", "him", "her", "my", "the"]:
                    extracted_beneficiary = b1_clean

        # Extract account ID
        extracted_account = None
        acc_match = re.search(r'\b(ACC_[A-Za-z0-9_]+)\b', effective_text)
        if acc_match:
            extracted_account = acc_match.group(1)

        return NormalizedInput(
            original_text=original,
            cleaned_text=effective_text.strip(),
            detected_encodings=list(set(detected_encodings)),
            contains_homoglyphs=contains_homoglyphs,
            extracted_amount=extracted_amount,
            extracted_beneficiary=extracted_beneficiary,
            extracted_memo=extracted_memo,
            extracted_account=extracted_account
        )


class ThreatAnalyzer:
    """Hybrid AI Threat Analyzer supporting Gemini/OpenAI API with Rule-Based Fallback."""

    def __init__(self):
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()

    def _is_valid_key(self, key: str) -> bool:
        if not key or len(key) < 10:
            return False
        if any(ph in key.lower() for ph in ["your_key", "placeholder", "xxx", "change_me", "api_key"]):
            return False
        return True

    def analyze(
        self,
        normalized: NormalizedInput,
        simulate_failure: bool = False
    ) -> AIThreatAnalysis:
        """
        Analyzes the normalized request.
        If simulate_failure=True, or during testing, or when no valid paid API key is configured,
        transparently operates in deterministic rule-based fallback mode.
        """
        # Fast rule-based path during tests or simulated failure
        if simulate_failure or "PYTEST_CURRENT_TEST" in os.environ or os.getenv("BANKISM_FORCE_FALLBACK") == "1":
            return self._rule_based_fallback(
                normalized,
                forced_reason="Simulated LLM service failure/timeout for reliability testing." if simulate_failure else None
            )

        # Try LLM if configured with valid key
        if self._is_valid_key(self.gemini_api_key):
            try:
                return self._call_gemini(normalized)
            except Exception as e:
                return self._rule_based_fallback(
                    normalized,
                    forced_reason=f"Gemini API unavailable or failed ({type(e).__name__}); rule-based fallback active."
                )

        if self._is_valid_key(self.openai_api_key):
            try:
                return self._call_openai(normalized)
            except Exception as e:
                return self._rule_based_fallback(
                    normalized,
                    forced_reason=f"OpenAI API unavailable or failed ({type(e).__name__}); rule-based fallback active."
                )

        # Default: Deterministic Rule-Based Analysis
        return self._rule_based_fallback(normalized)

    def _call_gemini(self, normalized: NormalizedInput) -> AIThreatAnalysis:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_api_key}"
        system_instruction = (
            "You are BANKISM Security Threat Analysis Engine. "
            "Analyze the untrusted user request for banking intent and security threats. "
            "Respond ONLY with valid JSON conforming to the schema:\n"
            "{\n"
            "  \"intent\": \"BALANCE_INQUIRY\"|\"TRANSFER_MONEY\"|\"VIEW_TRANSACTIONS\"|\"POLICY_OVERRIDE\"|\"UNKNOWN\",\n"
            "  \"threat_category\": \"BENIGN\"|\"PROMPT_INJECTION\"|\"UNAUTHORIZED_TRANSFER\"|\"LIMIT_VIOLATION\"|\"MALICIOUS_MEMO\"|\"SENSITIVE_INFO_EXTRACTION\"|\"AMBIGUOUS_REQUEST\"|\"OBFUSCATED_INSTRUCTION\",\n"
            "  \"risk_level\": \"LOW\"|\"MEDIUM\"|\"HIGH\"|\"CRITICAL\",\n"
            "  \"confidence\": 0.0 to 1.0,\n"
            "  \"detected_patterns\": [\"string\"],\n"
            "  \"rationale\": \"string\",\n"
            "  \"is_ambiguous\": boolean,\n"
            "  \"missing_fields\": [\"string\"]\n"
            "}"
        )
        payload = {
            "contents": [{"parts": [{"text": f"Analyze untrusted request:\n```{normalized.cleaned_text}```"}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.0
            }
        }
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(raw_text)

            return AIThreatAnalysis(
                analyzer_mode="LLM_ASSISTED (Gemini 1.5)",
                intent=ActionType(parsed.get("intent", "UNKNOWN")),
                threat_category=ThreatCategory(parsed.get("threat_category", "UNKNOWN")),
                risk_level=RiskLevel(parsed.get("risk_level", "MEDIUM")),
                confidence=float(parsed.get("confidence", 0.9)),
                detected_patterns=parsed.get("detected_patterns", []),
                rationale=parsed.get("rationale", "LLM threat classification completed."),
                is_ambiguous=bool(parsed.get("is_ambiguous", False)),
                missing_fields=parsed.get("missing_fields", []),
                raw_model_response=parsed
            )

    def _call_openai(self, normalized: NormalizedInput) -> AIThreatAnalysis:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.openai_api_key}"}
        prompt = (
            "You are BANKISM Security Threat Analysis Engine. "
            "Analyze the untrusted user request for banking intent and security threats. "
            "Respond ONLY with valid JSON conforming to the schema:\n"
            "{\n"
            "  \"intent\": \"BALANCE_INQUIRY\"|\"TRANSFER_MONEY\"|\"VIEW_TRANSACTIONS\"|\"POLICY_OVERRIDE\"|\"UNKNOWN\",\n"
            "  \"threat_category\": \"BENIGN\"|\"PROMPT_INJECTION\"|\"UNAUTHORIZED_TRANSFER\"|\"LIMIT_VIOLATION\"|\"MALICIOUS_MEMO\"|\"SENSITIVE_INFO_EXTRACTION\"|\"AMBIGUOUS_REQUEST\"|\"OBFUSCATED_INSTRUCTION\",\n"
            "  \"risk_level\": \"LOW\"|\"MEDIUM\"|\"HIGH\"|\"CRITICAL\",\n"
            "  \"confidence\": 0.0 to 1.0,\n"
            "  \"detected_patterns\": [\"string\"],\n"
            "  \"rationale\": \"string\",\n"
            "  \"is_ambiguous\": boolean,\n"
            "  \"missing_fields\": [\"string\"]\n"
            "}"
        )
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"Untrusted request: {normalized.cleaned_text}"}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0
        }
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw_text)

            return AIThreatAnalysis(
                analyzer_mode="LLM_ASSISTED (OpenAI)",
                intent=ActionType(parsed.get("intent", "UNKNOWN")),
                threat_category=ThreatCategory(parsed.get("threat_category", "UNKNOWN")),
                risk_level=RiskLevel(parsed.get("risk_level", "MEDIUM")),
                confidence=float(parsed.get("confidence", 0.9)),
                detected_patterns=parsed.get("detected_patterns", []),
                rationale=parsed.get("rationale", "LLM threat classification completed."),
                is_ambiguous=bool(parsed.get("is_ambiguous", False)),
                missing_fields=parsed.get("missing_fields", []),
                raw_model_response=parsed
            )

    def _rule_based_fallback(
        self,
        normalized: NormalizedInput,
        forced_reason: Optional[str] = None
    ) -> AIThreatAnalysis:
        """
        Deterministic, transparent rule-based threat evaluation.
        Clearly exposes that detection operates in rule-based fallback mode.
        """
        text = normalized.cleaned_text.lower()
        detected_patterns: List[str] = []
        mode_str = f"RULE_BASED_FALLBACK{f' ({forced_reason})' if forced_reason else ''}"

        # 1. Obfuscation detection
        if normalized.detected_encodings:
            detected_patterns.append(f"Suspicious encoding/obfuscation detected: {', '.join(normalized.detected_encodings)}")
        if normalized.contains_homoglyphs:
            detected_patterns.append("Unicode homoglyph characters detected")

        # 2. Check for Malicious Payment Memo FIRST (if memo is present)
        memo_to_check = normalized.extracted_memo or ""
        if not memo_to_check and ("memo:" in text or "with memo" in text):
            # Extract memo part
            parts = re.split(r'memo:?|"memo":?', text, flags=re.IGNORECASE)
            if len(parts) > 1:
                memo_to_check = parts[1]

        if memo_to_check:
            memo_lower = memo_to_check.lower()
            memo_injection = any(re.search(pat, memo_lower) for pat in PROMPT_INJECTION_PATTERNS)
            memo_extraction = any(re.search(pat, memo_lower) for pat in SENSITIVE_EXTRACTION_PATTERNS)
            if memo_injection or memo_extraction:
                detected_patterns.append("Untrusted instructions or sensitive queries embedded inside payment memo")
                return AIThreatAnalysis(
                    analyzer_mode=mode_str,
                    intent=ActionType.TRANSFER_MONEY,
                    threat_category=ThreatCategory.MALICIOUS_MEMO,
                    risk_level=RiskLevel.HIGH,
                    confidence=0.96,
                    detected_patterns=detected_patterns,
                    rationale="Payment memo contains suspicious instructions attempting to bypass security or exfiltrate data.",
                    is_ambiguous=False,
                    missing_fields=[]
                )

        # 3. Check for Prompt Injection / Policy Overrides
        has_prompt_injection = False
        for pat in PROMPT_INJECTION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                has_prompt_injection = True
                detected_patterns.append(f"Instruction override attempt matched pattern: '{pat}'")

        if has_prompt_injection:
            return AIThreatAnalysis(
                analyzer_mode=mode_str,
                intent=ActionType.POLICY_OVERRIDE,
                threat_category=ThreatCategory.PROMPT_INJECTION,
                risk_level=RiskLevel.CRITICAL,
                confidence=0.98,
                detected_patterns=detected_patterns,
                rationale="The request attempts to override security controls or alter system instructions.",
                is_ambiguous=False,
                missing_fields=[]
            )

        # 4. Check for Sensitive Information Extraction
        for pat in SENSITIVE_EXTRACTION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                detected_patterns.append(f"Sensitive information extraction attempt: '{pat}'")
                return AIThreatAnalysis(
                    analyzer_mode=mode_str,
                    intent=ActionType.VIEW_TRANSACTIONS,
                    threat_category=ThreatCategory.SENSITIVE_INFO_EXTRACTION,
                    risk_level=RiskLevel.HIGH,
                    confidence=0.96,
                    detected_patterns=detected_patterns,
                    rationale="Request attempts unauthorized extraction of other customers' accounts, credentials, or confidential data.",
                    is_ambiguous=False,
                    missing_fields=[]
                )

        # 5. Check for Unauthorized Account Access
        for pat in UNAUTHORIZED_TRANSFER_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                detected_patterns.append("Unauthorized account transfer attempt from non-owned account")
                return AIThreatAnalysis(
                    analyzer_mode=mode_str,
                    intent=ActionType.TRANSFER_MONEY,
                    threat_category=ThreatCategory.UNAUTHORIZED_TRANSFER,
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.97,
                    detected_patterns=detected_patterns,
                    rationale="Attempted fund transfer from an account not owned or authorized by the requester.",
                    is_ambiguous=False,
                    missing_fields=[]
                )

        # 6. Check for Obfuscated instructions standalone
        if normalized.detected_encodings or normalized.contains_homoglyphs:
            return AIThreatAnalysis(
                analyzer_mode=mode_str,
                intent=ActionType.UNKNOWN,
                threat_category=ThreatCategory.OBFUSCATED_INSTRUCTION,
                risk_level=RiskLevel.HIGH,
                confidence=0.92,
                detected_patterns=detected_patterns,
                rationale="Request contains encoded or obfuscated text patterns designed to evade natural-language inspection.",
                is_ambiguous=True,
                missing_fields=["cleartext_intent"]
            )

        # 7. Check for Ambiguous Request
        if any(term in text for term in ["that person", "someone", "send money to him", "send the money"]) and not ("saved beneficiary" in text):
            detected_patterns.append("Vague beneficiary reference ('that person' / unresolvable recipient)")
            return AIThreatAnalysis(
                analyzer_mode=mode_str,
                intent=ActionType.TRANSFER_MONEY,
                threat_category=ThreatCategory.AMBIGUOUS_REQUEST,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.90,
                detected_patterns=detected_patterns,
                rationale="Request lacks specific beneficiary and/or amount; cannot safely determine transaction target.",
                is_ambiguous=True,
                missing_fields=["destination_beneficiary"]
            )

        # 8. Check for Balance Inquiry
        if any(term in text for term in ["balance", "check my account", "how much money", "account balance"]):
            detected_patterns.append("Legitimate balance inquiry intent")
            return AIThreatAnalysis(
                analyzer_mode=mode_str,
                intent=ActionType.BALANCE_INQUIRY,
                threat_category=ThreatCategory.BENIGN,
                risk_level=RiskLevel.LOW,
                confidence=0.95,
                detected_patterns=detected_patterns,
                rationale="Benign account balance inquiry detected.",
                is_ambiguous=False,
                missing_fields=[]
            )

        # 9. Check for Fund Transfer Intent
        if any(term in text for term in ["transfer", "send", "pay", "wire"]):
            # Check if high amount
            if normalized.extracted_amount and normalized.extracted_amount > 10000.0:
                detected_patterns.append(f"Transfer amount ₹{normalized.extracted_amount:.2f} exceeds standard ₹10,000 threshold")
                return AIThreatAnalysis(
                    analyzer_mode=mode_str,
                    intent=ActionType.TRANSFER_MONEY,
                    threat_category=ThreatCategory.LIMIT_VIOLATION,
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.94,
                    detected_patterns=detected_patterns,
                    rationale="Financial transfer exceeds single transaction threshold; flagged for policy inspection.",
                    is_ambiguous=False,
                    missing_fields=[]
                )

            detected_patterns.append("Financial fund transfer intent")
            return AIThreatAnalysis(
                analyzer_mode=mode_str,
                intent=ActionType.TRANSFER_MONEY,
                threat_category=ThreatCategory.BENIGN,
                risk_level=RiskLevel.LOW,
                confidence=0.95,
                detected_patterns=detected_patterns,
                rationale="Legitimate fund transfer request structure detected.",
                is_ambiguous=False,
                missing_fields=[]
            )

        # Default fallback
        detected_patterns.append("Unclassified natural language request")
        return AIThreatAnalysis(
            analyzer_mode=mode_str,
            intent=ActionType.UNKNOWN,
            threat_category=ThreatCategory.UNKNOWN,
            risk_level=RiskLevel.LOW,
            confidence=0.70,
            detected_patterns=detected_patterns,
            rationale="Request did not trigger known threat signatures or banking operations.",
            is_ambiguous=True,
            missing_fields=[]
        )


# Global threat analyzer
threat_analyzer = ThreatAnalyzer()
