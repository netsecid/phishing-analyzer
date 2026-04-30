import base64
import json
import os

import anthropic

_SYSTEM_PROMPT = """\
You are a phishing analysis expert. You analyze webpage screenshots and metadata \
to determine if a site is a phishing attempt.

Analyze for:
- Brand impersonation (fake logos, spoofed UI elements)
- Suspicious or lookalike domains
- Urgency/fear tactics
- Credential harvesting forms
- Visual quality and consistency issues
- Misleading content or misdirection

Return ONLY a valid JSON object — no markdown, no preamble, no explanation."""


def analyze_with_claude(case: dict, screenshot_path: str) -> dict:
    """Return an AI phishing assessment for the given case and screenshot."""
    _FALLBACK = {
        "verdict": "inconclusive",
        "confidence": 0,
        "brand_impersonated": None,
        "risk_indicators": [],
        "summary": "AI analysis was not available.",
        "recommended_action": "monitor",
    }

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _FALLBACK

    try:
        with open(screenshot_path, "rb") as fh:
            image_b64 = base64.standard_b64encode(fh.read()).decode()
    except OSError:
        return _FALLBACK

    metadata = (
        f"Final URL: {case.get('final_url') or 'unknown'}\n"
        f"Page title: {case.get('title') or 'unknown'}\n"
        f"HTTP status: {case.get('status_code') or 'unknown'}\n"
        f"Response headers:\n{json.dumps(case.get('raw_headers') or {}, indent=2)}"
    )

    user_prompt = (
        "Analyze the screenshot and metadata below for phishing indicators.\n\n"
        f"{metadata}\n\n"
        "Return ONLY a JSON object with exactly these fields:\n"
        '  "verdict": "phishing" | "suspicious" | "legitimate" | "inconclusive"\n'
        '  "confidence": integer 0-100\n'
        '  "brand_impersonated": string or null (e.g. "Rakuten", "Apple")\n'
        '  "risk_indicators": array of strings describing suspicious elements\n'
        '  "summary": 2-3 sentence human-readable assessment\n'
        '  "recommended_action": "takedown" | "monitor" | "dismiss"\n'
    )

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": image_b64,
                            },
                        },
                        {"type": "text", "text": user_prompt},
                    ],
                }
            ],
        )

        raw = next(
            (block.text for block in response.content if block.type == "text"), ""
        ).strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        result = json.loads(raw)

        required_keys = {
            "verdict",
            "confidence",
            "brand_impersonated",
            "risk_indicators",
            "summary",
            "recommended_action",
        }
        if not required_keys.issubset(result):
            return _FALLBACK

        return result

    except Exception:
        return _FALLBACK
