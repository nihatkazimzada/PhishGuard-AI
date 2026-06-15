import os
import json
import re
import logging
from typing import Any, Dict

from openai import OpenAI

logger = logging.getLogger("phishguard.ai")

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "minimax-m3")

client = OpenAI(base_url=OPENAI_BASE_URL, api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


SYSTEM_PROMPT = (
    "You are a cybersecurity expert specializing in phishing email detection. "
    "Analyze the provided email and return ONLY a valid JSON object with this exact structure:\n"
    "{\n"
    '  "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING",\n'
    '  "risk_score": <integer 0-100>,\n'
    '  "confidence": <integer 0-100>,\n'
    '  "summary": "<2-3 sentence plain English explanation>",\n'
    '  "indicators": {\n'
    '    "urgency_language": <boolean>,\n'
    '    "suspicious_links": <boolean>,\n'
    '    "impersonation_attempt": <boolean>,\n'
    '    "grammar_errors": <boolean>,\n'
    '    "unusual_sender_patterns": <boolean>,\n'
    '    "credential_request": <boolean>,\n'
    '    "financial_pressure": <boolean>\n'
    "  },\n"
    '  "recommendation": "<one clear action the user should take>",\n'
    '  "technical_details": "<optional deeper analysis for security professionals>"\n'
    "}\n"
    "Return ONLY the JSON. No markdown, no explanation outside the JSON."
)

DEFAULT_INDICATORS = {
    "urgency_language": False,
    "suspicious_links": False,
    "impersonation_attempt": False,
    "grammar_errors": False,
    "unusual_sender_patterns": False,
    "credential_request": False,
    "financial_pressure": False,
}

ERROR_RESULT: Dict[str, Any] = {
    "verdict": "SUSPICIOUS",
    "risk_score": 0,
    "confidence": 0,
    "summary": "Analysis service temporarily unavailable. Please try again in a moment.",
    "indicators": DEFAULT_INDICATORS.copy(),
    "recommendation": "Retry the scan, or manually verify the email with your IT/security team.",
    "technical_details": "The AI backend did not return a valid response.",
    "error": True,
}


def _coerce_indicators(raw: Any) -> Dict[str, bool]:
    coerced = DEFAULT_INDICATORS.copy()
    if not isinstance(raw, dict):
        return coerced
    for key in coerced:
        if key in raw:
            value = raw[key]
            if isinstance(value, bool):
                coerced[key] = value
            elif isinstance(value, str):
                coerced[key] = value.strip().lower() in ("true", "1", "yes", "y")
            else:
                coerced[key] = bool(value)
    return coerced


def _coerce_score(value: Any) -> int:
    try:
        score = int(float(value))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))


def _extract_json_object(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, count=1).strip()
        if text.endswith("```"):
            text = text[: -3].strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


def _fallback_heuristic(subject: str, body: str) -> Dict[str, Any]:
    text = f"{subject or ''}\n{body or ''}".lower()
    indicators = {
        "urgency_language": any(
            w in text
            for w in [
                "urgent", "immediately", "act now", "within 24 hours",
                "final notice", "expires today", "right away", "asap",
            ]
        ),
        "suspicious_links": any(
            w in text for w in ["http://", "bit.ly", "tinyurl", "click here", "verify here"]
        ),
        "impersonation_attempt": any(
            w in text
            for w in [
                "paypal", "amazon support", "apple id", "microsoft support",
                "irs", "bank of", "chase support", "fedex", "dhl",
            ]
        )
        and any(w in text for w in ["verify", "confirm", "suspend", "locked", "unusual activity"]),
        "grammar_errors": False,
        "unusual_sender_patterns": any(
            w in text for w in ["noreply@", "support@", "secure-", "-verify", "no-reply"]
        ),
        "credential_request": any(
            w in text
            for w in [
                "password", "login", "sign in", "verify your account",
                "confirm your identity", "social security",
            ]
        ),
        "financial_pressure": any(
            w in text
            for w in [
                "wire transfer", "gift card", "bitcoin", "invoice attached",
                "payment overdue", "tax", "refund",
            ]
        ),
    }

    score = sum(10 for v in indicators.values() if v) * 2 + (10 if len(body) < 80 else 0)
    score = max(0, min(100, score))
    if score >= 70:
        verdict = "PHISHING"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": 55,
        "summary": (
            "AI model was unavailable, so a local heuristic was used. "
            "Results should be treated as a preliminary check only."
        ),
        "indicators": indicators,
        "recommendation": "Verify the sender and any links before taking action.",
        "technical_details": "Fallback heuristic used because the AI provider was unreachable.",
        "fallback": True,
    }


def _normalize(result: Dict[str, Any]) -> Dict[str, Any]:
    verdict = str(result.get("verdict", "SUSPICIOUS")).upper()
    if verdict not in ("SAFE", "SUSPICIOUS", "PHISHING"):
        verdict = "SUSPICIOUS"

    return {
        "verdict": verdict,
        "risk_score": _coerce_score(result.get("risk_score", 0)),
        "confidence": _coerce_score(result.get("confidence", 0)),
        "summary": str(result.get("summary", "")).strip()
        or "No summary was provided by the analyzer.",
        "indicators": _coerce_indicators(result.get("indicators")),
        "recommendation": str(result.get("recommendation", "")).strip()
        or "Exercise caution and verify before acting on this email.",
        "technical_details": str(result.get("technical_details", "")).strip(),
    }


def analyze_email(subject: str, body: str) -> Dict[str, Any]:
    subject = (subject or "").strip()
    body = (body or "").strip()

    if not body:
        return {
            "verdict": "SUSPICIOUS",
            "risk_score": 0,
            "confidence": 0,
            "summary": "Cannot analyze an empty email body.",
            "indicators": DEFAULT_INDICATORS.copy(),
            "recommendation": "Paste the full email body before running a scan.",
            "technical_details": "Empty body submitted.",
            "error": True,
        }

    if client is None:
        logger.warning("OPENAI_API_KEY not configured; using heuristic fallback.")
        return _fallback_heuristic(subject, body)

    user_prompt = (
        f"Subject: {subject or '(none provided)'}\n\n"
        f"Body:\n{body[:6000]}"
    )

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=800,
        )
    except Exception as exc:
        logger.exception("AI provider call failed: %s", exc)
        return _fallback_heuristic(subject, body)

    try:
        raw_text = response.choices[0].message.content or ""
        json_text = _extract_json_object(raw_text)
        parsed = json.loads(json_text)
        return _normalize(parsed)
    except Exception as exc:
        logger.exception("Failed to parse AI response: %s", exc)
        return ERROR_RESULT.copy()
