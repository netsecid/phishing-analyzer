import socket
from urllib.parse import urlparse

import requests

_ASN_ABUSE = {
    "cloudflare": "abuse@cloudflare.com",
    "amazon": "abuse@amazonaws.com",
    "aws": "abuse@amazonaws.com",
    "google": "network-abuse@google.com",
    "fastly": "abuse@fastly.com",
    "digitalocean": "abuse@digitalocean.com",
}


def _extract_domain(url: str) -> str:
    netloc = urlparse(url).netloc
    return netloc.split(":")[0] if netloc else ""


def _rdap_lookup(domain: str) -> dict:
    result = {
        "registrar_name": None,
        "registrar_abuse_email": None,
        "registration_date": None,
        "expiry_date": None,
        "nameservers": [],
    }
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return result

    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            result["registration_date"] = date
        elif action == "expiration":
            result["expiry_date"] = date

    result["nameservers"] = [
        ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")
    ]

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1:
            for field in vcard[1]:
                if field[0] == "fn" and not result["registrar_name"]:
                    result["registrar_name"] = field[3]
                elif field[0] == "email" and not result["registrar_abuse_email"]:
                    result["registrar_abuse_email"] = field[3]
        # Prefer explicit abuse sub-entity email
        for sub in entity.get("entities", []):
            if "abuse" in sub.get("roles", []):
                sub_vcard = sub.get("vcardArray", [])
                if len(sub_vcard) > 1:
                    for field in sub_vcard[1]:
                        if field[0] == "email":
                            result["registrar_abuse_email"] = field[3]
                            break

    return result


def _ip_lookup(domain: str) -> dict:
    result = {"ip": None, "org": None, "country": None, "abuse_email": None}
    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception:
        return result

    try:
        r = requests.get(f"https://ipinfo.io/{result['ip']}/json", timeout=10)
        r.raise_for_status()
        data = r.json()
        result["org"] = data.get("org")
        result["country"] = data.get("country")
    except Exception:
        pass

    org_lower = (result["org"] or "").lower()
    for key, email in _ASN_ABUSE.items():
        if key in org_lower:
            result["abuse_email"] = email
            break

    if not result["abuse_email"]:
        result["abuse_email"] = f"abuse@{domain}"

    return result


def _build_email(domain, brand, url, timestamp, summary, indicators, verdict):
    brand_str = brand or "[Unknown Brand]"
    subject = f"Phishing Site Report - {brand_str} - {domain}"
    indicators_text = "\n".join(f"  - {i}" for i in (indicators or [])) or "  - No specific indicators recorded"

    body = f"""To Whom It May Concern,

This is to report a phishing website that is actively impersonating {brand_str} and poses an immediate risk to internet users.

PHISHING SITE DETAILS
---------------------
URL: {url}
Domain: {domain}
Detection Time: {timestamp or '[Unknown]'}
Verdict: {(verdict or 'phishing').upper()}
Brand Impersonated: {brand_str}

ANALYSIS SUMMARY
----------------
{summary or '[No summary available]'}

RISK INDICATORS
---------------
{indicators_text}

ACTION REQUESTED
----------------
We respectfully request the immediate suspension or takedown of the above domain/URL \
to protect users from credential theft and financial harm. We are prepared to provide \
screenshots, network captures, or any additional evidence upon request.

Thank you for your prompt attention to this matter.

[Your Name] | [Your Organization]"""

    return subject, body


def generate_takedown_report(case: dict, ai_result: dict) -> dict:
    url = case.get("final_url") or case.get("url") or ""
    domain = _extract_domain(url)

    rdap = _rdap_lookup(domain) if domain else {}
    ip_info = _ip_lookup(domain) if domain else {}

    subject, body = _build_email(
        domain=domain or "[Unknown]",
        brand=ai_result.get("brand_impersonated"),
        url=url,
        timestamp=case.get("timestamp"),
        summary=ai_result.get("summary"),
        indicators=ai_result.get("risk_indicators") or [],
        verdict=ai_result.get("verdict"),
    )

    return {
        "domain": domain or "[Unknown]",
        "ip_address": ip_info.get("ip") or "[Unknown]",
        "registrar_name": rdap.get("registrar_name") or "[Unknown]",
        "registrar_abuse_email": rdap.get("registrar_abuse_email") or "[Unknown]",
        "hosting_org": ip_info.get("org") or "[Unknown]",
        "hosting_country": ip_info.get("country") or "[Unknown]",
        "hosting_abuse_email": ip_info.get("abuse_email") or "[Unknown]",
        "rdap_registration_date": rdap.get("registration_date") or "[Unknown]",
        "rdap_expiry_date": rdap.get("expiry_date") or "[Unknown]",
        "nameservers": rdap.get("nameservers") or [],
        "email_subject": subject,
        "email_body": body,
    }
