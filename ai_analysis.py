import base64
import json
import os
from typing import Optional

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

_FALLBACK = {
    "verdict": "inconclusive",
    "confidence": 0,
    "brand_impersonated": None,
    "risk_indicators": [],
    "summary": "AI analysis was not available.",
    "recommended_action": "monitor",
}


def _build_intel_summary(intel: dict) -> Optional[str]:
    if not intel:
        return None
    lines = []

    gsb = intel.get("gsb") or {}
    if gsb.get("is_listed") and not gsb.get("error"):
        lines.append(f"- Google Safe Browsing: MATCH — {', '.join(gsb.get('threat_types', []))}")

    pt = intel.get("phishtank") or {}
    if pt.get("verified") and not pt.get("error"):
        lines.append(f"- PhishTank: community-verified phishing (ID: {pt.get('phish_id')})")

    vt_outer = intel.get("virustotal") or {}
    vt = vt_outer.get("data") or {}
    if vt and not vt.get("not_found") and not vt_outer.get("error"):
        lines.append(
            f"- VirusTotal: {vt.get('malicious', 0)} malicious, "
            f"{vt.get('suspicious', 0)} suspicious detections"
        )

    otx = intel.get("otx") or {}
    if not otx.get("error") and otx.get("domain_pulses", 0) > 0:
        lines.append(f"- OTX AlienVault: {otx['domain_pulses']} threat pulse(s)")

    abuse = intel.get("abuseipdb") or {}
    if not abuse.get("error") and abuse.get("abuse_score") is not None:
        lines.append(f"- AbuseIPDB: hosting IP abuse score {abuse['abuse_score']}/100")

    urlscan = intel.get("urlscan") or {}
    if not urlscan.get("error") and urlscan.get("total", 0) > 0:
        lines.append(f"- URLScan.io: {urlscan['total']} prior scans on record")

    crtsh = intel.get("crtsh") or {}
    if not crtsh.get("error") and crtsh.get("earliest_cert_date"):
        wildcard_note = " (wildcard cert detected)" if crtsh.get("wildcard_certs") else ""
        lines.append(
            f"- crt.sh: domain first seen {crtsh['earliest_cert_date']}, "
            f"{crtsh['cert_count']} total certs{wildcard_note}"
        )

    urlhaus = intel.get("urlhaus") or {}
    if not urlhaus.get("error") and (urlhaus.get("url_listed") or urlhaus.get("host_listed")):
        lines.append(f"- URLhaus: infrastructure listed as malware distribution ({urlhaus.get('threat', '')})")

    if not lines:
        return None
    return "Threat Intelligence Context (external sources):\n" + "\n".join(lines)

# ── Provider config ───────────────────────────────────────────────────────────
# MODEL_PROVIDER: "anthropic" | "bedrock" | "openai" | "openrouter"
# MODEL_NAME:     e.g. "claude-opus-4-7", "anthropic.claude-opus-4-5-20241022-v1:0",
#                 "gpt-4o", "google/gemini-pro-vision", "meta-llama/llama-3.2-90b-vision-instruct"
# See README.md → "Model Configuration" for full details.
_PROVIDER = os.getenv("MODEL_PROVIDER", "anthropic").lower()
_MODEL = os.getenv("MODEL_NAME", "claude-opus-4-7")


def _build_user_prompt(case: dict, intel_summary: Optional[str] = None) -> str:
    metadata = (
        f"Final URL: {case.get('final_url') or 'unknown'}\n"
        f"Page title: {case.get('title') or 'unknown'}\n"
        f"HTTP status: {case.get('status_code') or 'unknown'}\n"
        f"Response headers:\n{json.dumps(case.get('raw_headers') or {}, indent=2)}"
    )
    body_snippet = (case.get("response_body") or "")[:3000]
    if body_snippet:
        metadata += f"\n\nResponse body (first 3000 chars):\n{body_snippet}"

    prompt = (
        "Analyze the screenshot and metadata below for phishing indicators.\n\n"
        f"{metadata}\n\n"
    )
    if intel_summary:
        prompt += f"{intel_summary}\n\n"
    prompt += (
        "Return ONLY a JSON object with exactly these fields:\n"
        '  "verdict": "phishing" | "suspicious" | "legitimate" | "inconclusive"\n'
        '  "confidence": integer 0-100\n'
        '  "brand_impersonated": string or null (e.g. "Rakuten", "Apple")\n'
        '  "risk_indicators": array of strings describing suspicious elements\n'
        '  "summary": 2-3 sentence human-readable assessment\n'
        '  "recommended_action": "takedown" | "monitor" | "dismiss"\n'
    )
    return prompt


def _parse_response(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    result = json.loads(raw)
    required = {"verdict", "confidence", "brand_impersonated", "risk_indicators", "summary", "recommended_action"}
    if not required.issubset(result):
        return _FALLBACK
    return result


def _analyze_anthropic(case: dict, image_b64: Optional[str], intel_summary: Optional[str] = None) -> dict:
    import anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _FALLBACK
    client = anthropic.Anthropic(api_key=api_key)
    content = []
    if image_b64:
        content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image_b64}})
    content.append({"type": "text", "text": _build_user_prompt(case, intel_summary)})
    response = client.messages.create(
        model=_MODEL,
        max_tokens=1024,
        system=[{"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": content}],
    )
    raw = next((b.text for b in response.content if b.type == "text"), "")
    return _parse_response(raw)


def _analyze_bedrock(case: dict, image_b64: Optional[str], intel_summary: Optional[str] = None) -> dict:
    import anthropic
    region = os.getenv("AWS_BEDROCK_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    client = anthropic.AnthropicBedrock(aws_region=region)
    content = []
    if image_b64:
        content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image_b64}})
    content.append({"type": "text", "text": _build_user_prompt(case, intel_summary)})
    response = client.messages.create(
        model=_MODEL,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
    )
    raw = next((b.text for b in response.content if b.type == "text"), "")
    return _parse_response(raw)


def _analyze_openai(case: dict, image_b64: Optional[str], intel_summary: Optional[str] = None) -> dict:
    import openai
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return _FALLBACK
    client = openai.OpenAI(api_key=api_key)
    content = []
    if image_b64:
        content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}})
    content.append({"type": "text", "text": _build_user_prompt(case, intel_summary)})
    response = client.chat.completions.create(
        model=_MODEL,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": content},
        ],
    )
    raw = response.choices[0].message.content or ""
    return _parse_response(raw)


def _analyze_openrouter(case: dict, image_b64: Optional[str], intel_summary: Optional[str] = None) -> dict:
    import openai
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return _FALLBACK
    client = openai.OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        default_headers={
            "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "https://github.com/netsecid/phishing-analyzer"),
            "X-Title": os.getenv("OPENROUTER_SITE_NAME", "Phishing Analyzer"),
        },
    )
    content = []
    if image_b64:
        content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}})
    content.append({"type": "text", "text": _build_user_prompt(case, intel_summary)})
    response = client.chat.completions.create(
        model=_MODEL,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": content},
        ],
    )
    raw = response.choices[0].message.content or ""
    return _parse_response(raw)


def analyze_with_claude(case: dict, screenshot_path: str, intel: Optional[dict] = None) -> dict:
    """Return an AI phishing assessment. Provider selected via MODEL_PROVIDER env var."""
    intel_summary = _build_intel_summary(intel) if intel else None

    image_b64: Optional[str] = None
    try:
        with open(screenshot_path, "rb") as fh:
            image_b64 = base64.standard_b64encode(fh.read()).decode()
    except OSError:
        pass  # no screenshot — continue in text-only mode if intel is available

    if image_b64 is None and intel_summary is None:
        return _FALLBACK

    try:
        if _PROVIDER == "bedrock":
            return _analyze_bedrock(case, image_b64, intel_summary)
        elif _PROVIDER == "openai":
            return _analyze_openai(case, image_b64, intel_summary)
        elif _PROVIDER == "openrouter":
            return _analyze_openrouter(case, image_b64, intel_summary)
        else:
            return _analyze_anthropic(case, image_b64, intel_summary)
    except Exception:
        return _FALLBACK
