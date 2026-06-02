# Design: Async Analysis Pipeline + Enriched Threat Intel

**Date:** 2026-06-02  
**Status:** Approved for implementation

---

## 1. Goals

1. Eliminate the 90 s hard timeout that causes analysis failures on slow-loading phishing pages.
2. Show threat intel results to the analyst while the browser capture is still running.
3. Run all intel sources in parallel instead of sequentially.
4. Add six new free intel sources: Google Safe Browsing lookup, OTX AlienVault, AbuseIPDB, crt.sh, URLhaus, PhishTank.
5. Feed a compact intel summary into the AI prompt so confidence scores reflect external threat signals.
6. Degrade gracefully when individual intel sources fail.

---

## 2. New Analysis Flow

### Before (single blocking HTTP response)

```
POST /api/analyze  ←  client blocks for entire duration
  subprocess analyze.py          30 s nav + screenshot
  database.insert_case()
  ai_analysis.analyze_with_claude()
  takedown.generate_takedown_report()
  intel_module.gather_intel()    URLScan→VT→Shodan→Censys sequential
→ response (90 s timeout hard limit)
```

### After (non-blocking, polling)

```
POST /api/analyze
  database.insert_case_pending(url)   ← stub record, status=running
→ {case_id: 123, status: "running"}   ← returns immediately

asyncio background task _run_analysis(case_id, url):
  ┌──────────────────────────┐   ┌─────────────────────────────────────┐
  │  Browser subprocess      │   │  Intel gather (10 sources parallel) │
  │  analyze.py              │   │  ThreadPoolExecutor(max_workers=10)  │
  │  nav timeout:   120 s    │   │  GSB, OTX, AbuseIPDB,               │
  │  proc timeout:  300 s    │   │  URLScan, VT, Shodan, Censys,        │
  └──────────┬───────────────┘   │  crt.sh, URLhaus, PhishTank          │
             │                   └──────────────┬──────────────────────┘
             │                                  │ update_case_intel() called
             │                                  │ immediately when intel done
             │                                  │ (independent of browser task)
             │                                  │ → visible on next poll
             └──────────────┬────────────────────┘
                            │ both tasks complete (or browser timed out)
                            ▼
                  AI analysis
                  analyze_with_claude(case, screenshot_path, intel=intel_result)
                  screenshot (if available) + intel key signals in prompt
                            │
                     if phishing / suspicious
                            ▼
                    Takedown report
                            │
                            ▼
                  Regenerate pivot suggestions
                  generate_pivot_suggestions(updated_case, analysis, intel)
                  update_case_intel() with final pivot suggestions
                            │
                            ▼
                     status = complete

GET /api/cases/123  (frontend polls every 2.5 s)
  Derived progress from existing fields:
    intel_data NOT NULL  → intel stage done
    ai_verdict  NOT NULL → AI stage done
    status = complete    → all done, stop polling
```

---

## 3. Database Changes

### New column

```sql
ALTER TABLE cases ADD COLUMN status TEXT DEFAULT 'running';
```

Added to `_migrate_db()` in `database.py`.

### New function: `insert_case_pending(url, timestamp) → int`

Inserts a stub record with only `url`, `timestamp`, and `status='running'`. Returns `case_id`. All other fields remain NULL until filled by the background task.

### New function: `update_case_browser_results(case_id, data) → None`

Called by the background task after `analyze.py` subprocess completes. Updates: `title`, `final_url`, `status_code`, `screenshot_path`, `raw_headers`, `response_body`.

### New function: `update_case_status(case_id, status, error=None) → None`

Sets `status` column. Used to mark `complete` or `failed`, and to store the browser timeout error string.

### Existing `update_case_ai_analysis()`, `update_case_takedown()`, `update_case_intel()` are unchanged.

---

## 4. Timeout Changes

| File | Setting | Before | After |
|---|---|---|---|
| `analyze.py:69` | Playwright `page.goto` timeout | 30 000 ms | 120 000 ms |
| `main.py` | subprocess `timeout` | 90 s | 300 s |

### Browser timeout path

When the subprocess hits the 300 s limit, `subprocess.TimeoutExpired` is caught inside the background task. The case record is updated with `error="browser timeout"`. Analysis continues:

- AI runs in text-only mode (`analyze_with_claude` already returns `_FALLBACK` when the screenshot file is missing — no code change needed there).
- Intel results are still stored and displayed normally.
- `status` is set to `complete` (not `failed`) so the analyst can still see intel and the partial verdict.

---

## 5. Intel Sources — Full Set

### Existing sources (unchanged API, now run in parallel)

| Source | Key env var | What it provides |
|---|---|---|
| URLScan.io | `URLSCAN_API_KEY` (optional) | Prior scans, overall verdict, screenshot history |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Multi-engine scan stats, threat names |
| Shodan | `SHODAN_API_KEY` | Open ports, banners, vuln tags, org |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Host services, ASN, labels |

### New sources

#### 5a. Google Safe Browsing Lookup

- **Env var:** `GOOGLE_SAFE_BROWSING_API_KEY` (free, no billing required)
- **Endpoint:** `POST https://safebrowsing.googleapis.com/v4/threatMatches:find`
- **Threat types checked:** `MALWARE`, `SOCIAL_ENGINEERING` (phishing), `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`
- **Returns:** list of matched threat types, or empty list (clean)
- **Key signal for AI:** any match → high-confidence indicator

```python
def query_google_safe_browsing(url: str) -> dict:
    # result shape: {configured, threat_types: [], error}
```

#### 5b. OTX AlienVault

- **Env var:** `OTX_API_KEY` (free registration at otx.alienvault.com)
- **Endpoints:**
  - `GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general`
  - `GET https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general`
- **Returns:** pulse count (community threat reports), reputation score, malware families, tags
- **Key signal for AI:** pulse_count > 0 indicates known threat actor activity

```python
def query_otx(url: str) -> dict:
    # result shape: {configured, domain_pulses, url_pulses, reputation, tags, error}
```

#### 5c. AbuseIPDB

- **Env var:** `ABUSEIPDB_API_KEY` (free tier: 1 000 checks/day)
- **Endpoint:** `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
- **Returns:** abuse confidence score (0–100), total reports, ISP, usage type, country
- **Key signal for AI:** score ≥ 50 on hosting IP is a strong infrastructure indicator

```python
def query_abuseipdb(ip: str | None) -> dict:
    # result shape: {configured, abuse_score, total_reports, isp, usage_type, error}
```

#### 5d. crt.sh (Certificate Transparency)

- **Env var:** none required
- **Endpoint:** `GET https://crt.sh/?q={domain}&output=json`
- **Returns:** list of SSL certificates with issued date, issuer, subject
- **Derived signals:**
  - `cert_count` — total certs issued (many = domain has history; 1–2 new = newly stood up)
  - `earliest_cert_date` — domain age via CT (more reliable than WHOIS for phishing kits)
  - `wildcard_certs` — boolean; wildcard certs suggest bulk/automated deployment
- **No key, no rate limit for moderate use**

```python
def query_crtsh(domain: str) -> dict:
    # result shape: {cert_count, earliest_cert_date, latest_cert_date, wildcard_certs, error}
```

#### 5e. URLhaus (Abuse.ch)

- **Env var:** none required
- **Endpoints:**
  - `POST https://urlhaus-api.abuse.ch/v1/url/` — check if URL is in malware distribution DB
  - `POST https://urlhaus-api.abuse.ch/v1/host/` — check domain/IP
- **Returns:** query status (`is_listed` boolean), threat type, tags, associated payloads
- **Note:** URLhaus is primarily malware distribution, not phishing — but hosting infrastructure overlaps heavily with phishing kits

```python
def query_urlhaus(url: str, domain: str) -> dict:
    # result shape: {url_listed, host_listed, threat, tags, error}
```

#### 5f. PhishTank

- **Env var:** `PHISHTANK_API_KEY` (optional; increases rate limit)
- **Endpoint:** `POST https://checkurl.phishtank.com/checkurl/` with `url` + `format=json`
- **Returns:** `in_database` boolean, `verified` boolean, `verified_at` timestamp, `valid` (community-confirmed phishing)
- **Key signal for AI:** `valid=true` = community-verified phishing page

```python
def query_phishtank(url: str) -> dict:
    # result shape: {configured, in_database, verified, verified_at, phish_id, error}
```

### Parallelization inside `gather_intel()`

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def gather_intel(case: dict, ai_result: dict) -> dict:
    url = case.get("final_url") or case.get("url") or ""
    domain = _extract_domain(url)
    ip = _resolve_ip(domain) if domain else None

    tasks = {
        "urlscan":  lambda: query_urlscan(url),
        "virustotal": lambda: query_virustotal(url),
        "shodan":   lambda: query_shodan(ip),
        "censys":   lambda: query_censys(ip),
        "gsb":      lambda: query_google_safe_browsing(url),
        "otx":      lambda: query_otx(url),
        "abuseipdb": lambda: query_abuseipdb(ip),
        "crtsh":    lambda: query_crtsh(domain),
        "urlhaus":  lambda: query_urlhaus(url, domain),
        "phishtank": lambda: query_phishtank(url),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)}  # fallback, never propagates

    results["resolved_ip"] = ip
    results["pivot_suggestions"] = generate_pivot_suggestions(case, ai_result, results)
    return results
```

---

## 6. AI Prompt Enrichment

`analyze_with_claude(case, screenshot_path, intel=None)` gains a third optional parameter.

Internally it calls `_build_intel_summary(intel)` to produce a compact string, then passes it to `_build_user_prompt(case, intel_summary=None)`, which gains an optional `intel_summary` parameter.

### Intel summary builder (new helper in `ai_analysis.py`)

```python
def _build_intel_summary(intel: dict) -> str | None:
    lines = []

    gsb = intel.get("gsb", {})
    if gsb and not gsb.get("error") and gsb.get("threat_types"):
        lines.append(f"- Google Safe Browsing: MATCH — {', '.join(gsb['threat_types'])}")

    pt = intel.get("phishtank", {})
    if pt and not pt.get("error") and pt.get("verified"):
        lines.append(f"- PhishTank: community-verified phishing (ID: {pt.get('phish_id')})")

    vt = intel.get("virustotal", {}).get("data") or {}
    if vt and not intel.get("virustotal", {}).get("error"):
        lines.append(
            f"- VirusTotal: {vt.get('malicious', 0)} malicious, "
            f"{vt.get('suspicious', 0)} suspicious detections"
        )

    otx = intel.get("otx", {})
    if otx and not otx.get("error") and otx.get("domain_pulses", 0) > 0:
        lines.append(f"- OTX AlienVault: {otx['domain_pulses']} threat pulse(s)")

    abuse = intel.get("abuseipdb", {})
    if abuse and not abuse.get("error") and abuse.get("abuse_score") is not None:
        lines.append(f"- AbuseIPDB: hosting IP score {abuse['abuse_score']}/100")

    urlscan = intel.get("urlscan", {})
    if urlscan and not urlscan.get("error"):
        lines.append(
            f"- URLScan: {urlscan.get('total', 0)} prior scans, "
            f"resolved IP: {intel.get('resolved_ip', 'unknown')}"
        )

    crtsh = intel.get("crtsh", {})
    if crtsh and not crtsh.get("error") and crtsh.get("earliest_cert_date"):
        lines.append(
            f"- crt.sh: earliest cert {crtsh['earliest_cert_date']}, "
            f"{crtsh['cert_count']} total certs"
            + (" (wildcard cert detected)" if crtsh.get("wildcard_certs") else "")
        )

    urlhaus = intel.get("urlhaus", {})
    if urlhaus and not urlhaus.get("error") and urlhaus.get("url_listed"):
        lines.append(f"- URLhaus: URL listed as malware distribution ({urlhaus.get('threat', '')})")

    if not lines:
        return None
    return "Threat Intelligence Context (external sources):\n" + "\n".join(lines)
```

The summary is appended after the metadata block in the user prompt, before the response format instructions.

---

## 7. Configuration

### `.env` additions

```dotenv
# New intel sources (all free tiers)
GOOGLE_SAFE_BROWSING_API_KEY=...   # console.developers.google.com → Safe Browsing API
OTX_API_KEY=...                    # otx.alienvault.com → API key in profile settings
ABUSEIPDB_API_KEY=...              # abuseipdb.com → API tab in account settings
PHISHTANK_API_KEY=...              # phishtank.com/api_register.php (optional, increases limit)

# crt.sh and URLhaus require no credentials
```

### `CLAUDE.md` additions

The module responsibility description for `intel.py` should be updated to list all ten sources.

The `.env` example block should include the four new optional keys with comments.

---

## 8. Frontend Changes (`static/index.html`)

### Submit flow

```
1. User clicks Analyze
2. POST /api/analyze → {case_id, status: "running"}
3. Show "Analysis in progress" panel with stage indicators:
     [ ] Threat Intel   (fills first, ~10 s)
     [ ] Browser Capture (fills second, 30–120 s)
     [ ] AI Analysis    (fills third, after browser done)
4. Start polling GET /api/cases/{case_id} every 2.5 s
5. On each poll response:
     - if intel_data populated → check [✓] Threat Intel, populate Intel tab
     - if ai_verdict populated → check [✓] AI Analysis, show verdict banner
     - if status=complete      → check [✓] all stages, stop polling
     - if status=failed        → show error, stop polling
```

### Intel tab — new source cards

Ten source cards total (existing four + six new). Each card follows the existing pattern: source name, status badge (configured / not configured / error), and result data. New cards:

- **Google Safe Browsing** — threat type badges (SOCIAL_ENGINEERING, MALWARE, etc.) or "Clean"
- **OTX AlienVault** — pulse count, reputation score, threat tags
- **AbuseIPDB** — abuse score gauge, total report count, ISP
- **crt.sh** — cert count, earliest issued date, wildcard flag
- **URLhaus** — listed/not listed badge, threat type
- **PhishTank** — verified phishing badge with verification date, or "Not in database"

### Progress stage indicator

Minimal addition above the results area. Three rows with checkboxes/spinners:

```
[✓] Threat Intel      — 9 sources, 2 errors       (intel_data NOT NULL)
[⟳] Browser Capture   — capturing screenshot...    (screenshot_path NULL)
[ ] AI Analysis       — waiting for browser         (ai_verdict NULL)
```

---

## 9. Error Handling Summary

| Scenario | Behavior |
|---|---|
| 1–2 intel sources fail | Other sources proceed normally; errored sources show error card in UI; error sources omitted from AI summary |
| All intel sources fail | Intel tab shows all error cards; AI runs with no intel context (current behavior) |
| Browser times out (300 s) | Error stored in case; AI runs text-only (no screenshot); intel still shown; status=complete |
| Browser errors mid-capture | Same as timeout; partial screenshot attempted before giving up |
| AI call fails | Falls back to `inconclusive` verdict (existing `_FALLBACK`); takedown skipped |
| Individual ThreadPoolExecutor worker crashes | `future.result()` exception caught per-future; fallback dict `{"error": str(e)}` substituted |

---

## 10. Files Changed

| File | Change |
|---|---|
| `database.py` | Add `status` column migration; add `insert_case_pending()`, `update_case_browser_results()`, `update_case_status()` |
| `main.py` | `POST /api/analyze` returns immediately; add `_run_analysis()` background task; timeout 90→300 s |
| `analyze.py` | Playwright nav timeout 30 000→120 000 ms |
| `intel.py` | Add 6 new `query_*` functions; convert `gather_intel()` to `ThreadPoolExecutor` |
| `ai_analysis.py` | Add `_build_intel_summary()`; update `_build_user_prompt()` to accept + embed intel context |
| `static/index.html` | Polling submit flow; progress stage indicator; 6 new intel source cards |
| `CLAUDE.md` | Update `intel.py` module description; update `.env` example block |
| `.env.example` / `README.md` | Document 4 new optional env vars |
