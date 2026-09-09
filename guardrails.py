"""Financial LLM Guardrails: PII Redaction & Hallucination Filter."""
import re

class BankingGuardrails:
    PII_PATTERNS = {
        "AADHAAR": r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b",
        "PAN_CARD": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b"
    }

    @classmethod
    def redact_pii(cls, text: str) -> str:
        """Replaces sensitive banking PII with synthetic compliance tokens."""
        redacted = text
        for pii_type, pattern in cls.PII_PATTERNS.items():
            redacted = re.sub(pattern, f"[{pii_type}_REDACTED]", redacted)
        return redacted

    @classmethod
    def validate_covenant_bounds(cls, output: str, max_ltv: float = 80.0) -> bool:
        """Validates that LLM output does not contradict banking regulatory boundaries."""
        ltv_match = re.search(r"LTV\s*(?:limit|cap)?\s*(?:of|is)?\s*(\d+(?:\.\d+)?)%", output, re.I)
        if ltv_match:
            val = float(ltv_match.group(1))
            return val <= max_ltv
        return True

if __name__ == "__main__":
    sample = "Customer PAN is ABCDE1234F with Aadhaar 1234 5678 9012 requesting LTV of 75%."
    print("Cleaned:", BankingGuardrails.redact_pii(sample))
