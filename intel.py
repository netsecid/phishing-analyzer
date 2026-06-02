"""
intel.py — External threat intelligence lookups.

Supported sources: URLScan.io, VirusTotal, Shodan, Censys.
API keys are read from environment variables (see README → External Intelligence).
"""

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

_TIMEOUT = 10


def _extract_domain(url: str) -> str:
    netloc = urlparse(url).netloc
    return netloc.split(":")[0] if netloc else ""


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ── URLScan.io ────────────────────────────────────────────────────────────────

def query_urlscan(url: str) -> dict:
    api_key = os.getenv("URLSCAN_API_KEY", "")
    domain = _extract_domain(url)
    result = {"available": bool(domain), "configured": bool(api_key), "results": [], "error": None}
    if not domain:
        result["error"] = "Could not extract domain"
        return result
    try:
        headers = {"API-Key": api_key} if api_key else {}
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 10},
            headers=headers,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        for item in data.get("results", []):
            page = item.get("page", {})
            result["results"].append({
                "scan_id": item.get("_id"),
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "server": page.get("server"),
                "timestamp": item.get("task", {}).get("time"),
                "screenshot": item.get("screenshot"),
                "verdicts": item.get("verdicts", {}).get("overall", {}),
            })
        result["total"] = data.get("total", 0)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── VirusTotal ────────────────────────────────────────────────────────────────

def query_virustotal(url: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    result = {"available": bool(url), "configured": bool(api_key), "error": None, "data": None}
    if not api_key:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        return result
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result["data"] = {"not_found": True}
            return result
        r.raise_for_status()
        d = r.json().get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["data"] = {
            "url": attrs.get("url"),
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "times_submitted": attrs.get("times_submitted"),
            "reputation": attrs.get("reputation"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "categories": attrs.get("categories", {}),
            "threat_names": list({
                v.get("result") for v in attrs.get("last_analysis_results", {}).values()
                if v.get("category") in ("malicious", "suspicious") and v.get("result")
            }),
        }
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Shodan ────────────────────────────────────────────────────────────────────

def query_shodan(ip: str | None) -> dict:
    api_key = os.getenv("SHODAN_API_KEY", "")
    result = {"available": bool(ip), "configured": bool(api_key), "error": None, "data": None}
    if not ip:
        result["error"] = "No IP address provided"
        return result
    if not api_key:
        result["error"] = "SHODAN_API_KEY not configured"
        return result
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result["data"] = {"not_found": True}
            return result
        r.raise_for_status()
        d = r.json()
        result["data"] = {
            "ip": d.get("ip_str"),
            "org": d.get("org"),
            "isp": d.get("isp"),
            "asn": d.get("asn"),
            "country": d.get("country_name"),
            "city": d.get("city"),
            "hostnames": d.get("hostnames", []),
            "domains": d.get("domains", []),
            "ports": d.get("ports", []),
            "tags": d.get("tags", []),
            "vulns": list(d.get("vulns", {}).keys()),
            "last_update": d.get("last_update"),
            "services": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": (s.get("data") or "")[:200],
                }
                for s in d.get("data", [])[:10]
            ],
        }
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Censys ────────────────────────────────────────────────────────────────────

def query_censys(ip: str | None) -> dict:
    api_id = os.getenv("CENSYS_API_ID", "")
    api_secret = os.getenv("CENSYS_API_SECRET", "")
    result = {"available": bool(ip), "configured": bool(api_id and api_secret), "error": None, "data": None}
    if not ip:
        result["error"] = "No IP address provided"
        return result
    if not (api_id and api_secret):
        result["error"] = "CENSYS_API_ID / CENSYS_API_SECRET not configured"
        return result
    try:
        r = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(api_id, api_secret),
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result["data"] = {"not_found": True}
            return result
        r.raise_for_status()
        d = r.json().get("result", {})
        services = []
        for svc in d.get("services", [])[:10]:
            services.append({
                "port": svc.get("port"),
                "transport": svc.get("transport_protocol"),
                "service_name": svc.get("service_name"),
                "product": svc.get("software", [{}])[0].get("product") if svc.get("software") else None,
            })
        result["data"] = {
            "ip": d.get("ip"),
            "asn": d.get("autonomous_system", {}).get("asn"),
            "asn_name": d.get("autonomous_system", {}).get("name"),
            "country": d.get("location", {}).get("country"),
            "city": d.get("location", {}).get("city"),
            "labels": d.get("labels", []),
            "last_updated": d.get("last_updated_at"),
            "services": services,
        }
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Google Safe Browsing ─────────────────────────────────────────────────────

def query_google_safe_browsing(url: str) -> dict:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    result = {
        "available": bool(url),
        "configured": bool(api_key),
        "threat_types": [],
        "is_listed": False,
        "error": None,
    }
    if not api_key:
        result["error"] = "GOOGLE_SAFE_BROWSING_API_KEY not configured"
        return result
    try:
        payload = {
            "client": {"clientId": "phishing-analyzer", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        matches = r.json().get("matches", [])
        result["threat_types"] = list({m.get("threatType") for m in matches if m.get("threatType")})
        result["is_listed"] = bool(matches)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── OTX (AlienVault) ──────────────────────────────────────────────────────────

def query_otx(url: str) -> dict:
    api_key = os.getenv("OTX_API_KEY", "")
    domain = _extract_domain(url)
    result = {
        "available": bool(domain),
        "configured": bool(api_key),
        "domain_pulses": 0,
        "reputation": 0,
        "tags": [],
        "malware_families": [],
        "error": None,
    }
    if not api_key:
        result["error"] = "OTX_API_KEY not configured"
        return result
    if not domain:
        result["error"] = "Could not extract domain"
        return result
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        result["domain_pulses"] = pulse_info.get("count", 0)
        result["reputation"] = data.get("reputation", 0)
        pulses = pulse_info.get("pulses", [])
        result["tags"] = list({
            tag for p in pulses for tag in p.get("tags", [])
        })[:20]
        result["malware_families"] = list({
            mf.get("display_name", "")
            for p in pulses
            for mf in p.get("malware_families", [])
            if mf.get("display_name")
        })[:10]
    except Exception as e:
        result["error"] = str(e)
    return result


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def query_abuseipdb(ip: str | None) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    result = {
        "available": bool(ip),
        "configured": bool(api_key),
        "abuse_score": None,
        "total_reports": 0,
        "isp": None,
        "usage_type": None,
        "country": None,
        "is_whitelisted": False,
        "error": None,
    }
    if not ip:
        result["error"] = "No IP address provided"
        return result
    if not api_key:
        result["error"] = "ABUSEIPDB_API_KEY not configured"
        return result
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        result["abuse_score"] = d.get("abuseConfidenceScore")
        result["total_reports"] = d.get("totalReports", 0)
        result["isp"] = d.get("isp")
        result["usage_type"] = d.get("usageType")
        result["country"] = d.get("countryCode")
        result["is_whitelisted"] = d.get("isWhitelisted", False)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── crt.sh (Certificate Transparency) ─────────────────────────────────────────

def query_crtsh(domain: str) -> dict:
    result = {
        "available": bool(domain),
        "cert_count": 0,
        "earliest_cert_date": None,
        "latest_cert_date": None,
        "wildcard_certs": False,
        "error": None,
    }
    if not domain:
        result["error"] = "No domain provided"
        return result
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        certs = r.json()[:500]
        if not certs:
            return result
        result["cert_count"] = len(certs)
        dates = [c.get("not_before", "") for c in certs if c.get("not_before")]
        if dates:
            result["earliest_cert_date"] = min(dates)[:10]
            result["latest_cert_date"] = max(dates)[:10]
        result["wildcard_certs"] = any(
            "*" in (c.get("common_name") or "") or "*" in (c.get("name_value") or "")
            for c in certs
        )
    except Exception as e:
        result["error"] = str(e)
    return result


# ── URLhaus ───────────────────────────────────────────────────────────────────

def query_urlhaus(url: str, domain: str) -> dict:
    result = {
        "available": bool(url or domain),
        "url_listed": False,
        "host_listed": False,
        "threat": None,
        "tags": [],
        "error": None,
    }
    try:
        if url:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") == "is_listed":
                result["url_listed"] = True
                result["threat"] = d.get("threat")
                result["tags"] = d.get("tags") or []
        if domain:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") == "is_listed":
                result["host_listed"] = True
                if not result["threat"] and d.get("urls"):
                    result["threat"] = d["urls"][0].get("threat")
    except Exception as e:
        result["error"] = str(e)
    return result


# ── PhishTank ─────────────────────────────────────────────────────────────────

def query_phishtank(url: str) -> dict:
    api_key = os.getenv("PHISHTANK_API_KEY", "")
    result = {
        "available": bool(url),
        "configured": True,
        "in_database": False,
        "verified": False,
        "valid": False,
        "verified_at": None,
        "phish_id": None,
        "error": None,
    }
    try:
        data = {"url": url, "format": "json"}
        if api_key:
            data["app_key"] = api_key
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=data,
            headers={"User-Agent": "phishing-analyzer/1.0"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json().get("results", {})
        result["in_database"] = d.get("in_database", False)
        result["verified"] = d.get("verified", False)
        result["valid"] = d.get("valid", False)
        result["verified_at"] = d.get("verified_at")
        result["phish_id"] = d.get("phish_id")
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Hunt/Pivot suggestions ────────────────────────────────────────────────────

def generate_pivot_suggestions(case: dict, ai_result: dict, intel: dict) -> list[dict]:
    """Rule-based pivot/hunting suggestions based on case context."""
    suggestions = []
    domain = _extract_domain(case.get("final_url") or case.get("url") or "")
    ip = None
    td = case.get("takedown_data") or {}
    if td:
        ip = td.get("ip_address")
    if not ip and intel:
        ip = (intel.get("shodan") or {}).get("data", {}) or {}
        ip = ip.get("ip") if isinstance(ip, dict) else None

    brand = ai_result.get("brand_impersonated")
    verdict = ai_result.get("verdict")
    indicators = ai_result.get("risk_indicators") or []
    registrar = td.get("registrar_name", "")
    hosting_org = td.get("hosting_org", "")
    reg_date = td.get("rdap_registration_date", "")
    nameservers = td.get("nameservers") or []

    if ip:
        suggestions.append({
            "category": "IP Pivot",
            "title": f"Find all domains hosted on {ip}",
            "description": "Phishing kits are often deployed across multiple domains on the same server.",
            "queries": [
                f"https://search.censys.io/hosts/{ip}",
                f"https://www.shodan.io/host/{ip}",
                f"https://urlscan.io/search/#ip%3A{ip}",
                f"https://www.virustotal.com/gui/ip-address/{ip}",
            ],
        })

    if domain:
        parts = domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain
        suggestions.append({
            "category": "Domain Pivot",
            "title": f"Search for lookalike domains of {base_domain}",
            "description": "Attackers register multiple typosquatted variants of the same domain.",
            "queries": [
                f"https://dnstwist.it/?q={base_domain}",
                f"https://urlscan.io/search/#domain%3A{base_domain}",
                f"https://crt.sh/?q=%25{base_domain}",
            ],
        })

        suggestions.append({
            "category": "Certificate Transparency",
            "title": f"Check SSL certificate history for {domain}",
            "description": "CT logs reveal when and how SSL certs were issued — useful for tracking kit deployment timelines.",
            "queries": [
                f"https://crt.sh/?q={domain}",
                f"https://transparencyreport.google.com/https/certificates?cert_search_auth=&cert_search_cert=&cert_search=include_subdomains%3Dtrue%26domain%3D{domain}",
            ],
        })

    if brand:
        suggestions.append({
            "category": "Brand Hunting",
            "title": f"Hunt for other phishing pages impersonating {brand}",
            "description": f"Find active campaigns targeting {brand} across scanning platforms.",
            "queries": [
                f"https://urlscan.io/search/#page.title%3A{brand}",
                f"https://www.virustotal.com/gui/search/{brand}%20phishing",
                f"https://phishtank.org/phish_search.php?valid=y&active=y&Search=Search&brand={brand}",
            ],
        })

    if nameservers:
        ns_root = nameservers[0].split(".")[-2] + "." + nameservers[0].split(".")[-1] if nameservers else ""
        if ns_root:
            suggestions.append({
                "category": "Nameserver Pivot",
                "title": f"Find domains using nameserver {nameservers[0]}",
                "description": "Bulk-registered phishing domains often share the same nameservers.",
                "queries": [
                    f"https://www.virustotal.com/gui/domain/{nameservers[0]}",
                    f"https://securitytrails.com/list/ns/{nameservers[0]}",
                ],
            })

    if registrar and registrar not in ("[Unknown]", ""):
        suggestions.append({
            "category": "Registrar Pivot",
            "title": f"Investigate abuse patterns at {registrar}",
            "description": "Some registrars are abused repeatedly. Searching by registrar can surface related campaigns.",
            "queries": [
                f"https://urlscan.io/search/#page.domain%3A*%20AND%20task.tags%3Aphishing",
            ],
        })

    if reg_date and reg_date not in ("[Unknown]", ""):
        suggestions.append({
            "category": "Temporal Pivot",
            "title": "Find domains registered around the same time",
            "description": "Phishing kits are often deployed in bulk. Co-registered domains on the same day/week are likely part of the same campaign.",
            "queries": [
                f"https://securitytrails.com/list/registered/{reg_date[:10].replace('-', '')}",
            ],
        })

    if hosting_org and hosting_org not in ("[Unknown]", ""):
        suggestions.append({
            "category": "ASN Pivot",
            "title": f"Explore other phishing on {hosting_org} infrastructure",
            "description": "Attackers often stick to the same hosting provider for a campaign.",
            "queries": [
                f"https://www.shodan.io/search?query=org%3A\"{hosting_org}\"",
                f"https://urlscan.io/search/#page.asn%3A*",
            ],
        })

    suggestions.append({
        "category": "OSINT",
        "title": "Full passive DNS & WHOIS history",
        "description": "Historical DNS resolution data can reveal past IPs, related domains, and infrastructure changes.",
        "queries": [
            f"https://securitytrails.com/domain/{domain}/history/a" if domain else "https://securitytrails.com",
            f"https://whoisfreaks.com/lookup/{domain}" if domain else "https://whoisfreaks.com",
            f"https://www.threatcrowd.org/domain.php?domain={domain}" if domain else "https://www.threatcrowd.org",
        ],
    })

    return suggestions


# ── Main gather function ──────────────────────────────────────────────────────

def gather_intel(case: dict, ai_result: dict) -> dict:
    url = case.get("final_url") or case.get("url") or ""
    domain = _extract_domain(url)
    ip = _resolve_ip(domain) if domain else None

    _tasks = {
        "urlscan":    lambda: query_urlscan(url),
        "virustotal": lambda: query_virustotal(url),
        "shodan":     lambda: query_shodan(ip),
        "censys":     lambda: query_censys(ip),
        "gsb":        lambda: query_google_safe_browsing(url),
        "otx":        lambda: query_otx(url),
        "abuseipdb":  lambda: query_abuseipdb(ip),
        "crtsh":      lambda: query_crtsh(domain),
        "urlhaus":    lambda: query_urlhaus(url, domain),
        "phishtank":  lambda: query_phishtank(url),
    }

    results: dict = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fn): name for name, fn in _tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)}

    results["resolved_ip"] = ip
    results["pivot_suggestions"] = generate_pivot_suggestions(case, ai_result, results)
    return results
