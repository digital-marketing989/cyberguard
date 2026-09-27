"""
OpenRouter LLM Explainer
Calls the OpenRouter API (OpenAI-compatible) to generate a human-readable
threat explanation from extracted indicators.

Design principle: indicators are passed as structured input;
the LLM is instructed to ONLY explain the provided indicators —
it must not invent new ones.
"""
from __future__ import annotations
import logging
from typing import List, Optional
from openai import AsyncOpenAI
from app.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are CyberGuard's AI threat analyst. Your role is to produce a concise, \
professional, human-readable explanation of a detected cyber threat for a security analyst dashboard.

RULES:
1. Explain ONLY the indicators provided in the user message. Do NOT invent or assume additional indicators.
2. Be specific — reference the actual indicator values.
3. Keep your explanation to 2-4 sentences.
4. Begin with the risk level, e.g. "High Risk: ..."
5. Use plain English — avoid jargon overload, but maintain professional tone.
6. End with one sentence summarising the recommended action category (block/quarantine/investigate/monitor).
"""


async def generate_explanation(
    threat_type: str,
    risk_level: str,
    risk_score: float,
    indicators: List[str],
    extra_context: Optional[str] = None,
) -> str:
    """
    Ask the OpenRouter LLM to explain the threat.

    Falls back to a template-based explanation if the API key is missing
    or the call fails (so the demo works offline too).
    """
    if not settings.OPENROUTER_API_KEY or settings.OPENROUTER_API_KEY == "your_openrouter_api_key_here":
        return _template_explanation(threat_type, risk_level, risk_score, indicators)

    indicators_text = "\n".join(f"- {ind}" for ind in indicators) if indicators else "- No specific indicators detected"
    user_message = (
        f"Threat type: {threat_type}\n"
        f"Risk level: {risk_level} (score: {risk_score}/100)\n"
        f"Detected indicators:\n{indicators_text}"
    )
    if extra_context:
        user_message += f"\nAdditional context: {extra_context}"

    try:
        client = AsyncOpenAI(
            api_key=settings.OPENROUTER_API_KEY,
            base_url=settings.OPENROUTER_BASE_URL,
        )
        response = await client.chat.completions.create(
            model=settings.LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            max_tokens=300,
            temperature=0.3,
            timeout=settings.LLM_TIMEOUT,
        )
        explanation = response.choices[0].message.content.strip()
        return explanation
    except Exception as exc:
        logger.warning("OpenRouter API call failed: %s — using template fallback", exc)
        return _template_explanation(threat_type, risk_level, risk_score, indicators)


def _template_explanation(
    threat_type: str,
    risk_level: str,
    risk_score: float,
    indicators: List[str],
) -> str:
    """Rule-based fallback explanation when LLM is unavailable."""
    if not indicators:
        return (
            f"{risk_level} Risk: A {threat_type} event was detected with a score of {risk_score}/100. "
            "No specific indicators were extracted. Manual review is recommended."
        )
    indicator_summary = "; ".join(indicators[:4])
    if len(indicators) > 4:
        indicator_summary += f"; and {len(indicators) - 4} more indicator(s)"
    action = _default_action(risk_level)
    return (
        f"{risk_level} Risk: The analysis flagged this {threat_type} event "
        f"with a confidence-weighted score of {risk_score}/100. "
        f"Key indicators include: {indicator_summary}. "
        f"Recommended immediate action: {action}."
    )


def _default_action(risk_level: str) -> str:
    mapping = {
        "Safe":     "no action required, continue monitoring",
        "Low":      "log and monitor for follow-up activity",
        "Medium":   "investigate and warn affected users",
        "High":     "quarantine / block and notify security team",
        "Critical": "immediate escalation, block all access, notify SOC",
    }
    return mapping.get(risk_level, "review and investigate")
