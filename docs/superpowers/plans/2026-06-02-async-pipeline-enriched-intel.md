# Async Pipeline + Enriched Threat Intel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the analysis timeout to 300 s, run browser capture and threat intel in parallel so intel results appear while the browser is still loading, add six new free intel sources, and feed a compact intel summary into the AI prompt.

**Architecture:** `POST /api/analyze` returns `{case_id, status: "running"}` immediately after creating a stub DB record, then an asyncio background task runs browser capture and all 10 intel sources in parallel, writes each result to the DB as it finishes, then runs AI analysis (with intel context in the prompt), and finally marks the case complete. The frontend polls `GET /api/cases/{id}` every 2.5 s and progressively populates tabs as data arrives.

**Tech Stack:** FastAPI, asyncio, SQLite (via sqlite3), Playwright (subprocess), ThreadPoolExecutor for intel parallelism, vanilla JS (no build step), Python 3.11+.

**Spec:** `docs/superpowers/specs/2026-06-02-async-pipeline-enriched-intel-design.md`

---

## File map

| File | What changes |
|---|---|
| `database.py` | Add `status` column migration; add `insert_case_pending()`, `update_case_browser_results()`, `update_case_status()` |
| `analyze.py` | Playwright nav timeout 30 000 ms → 120 000 ms |
| `intel.py` | Add 6 new `query_*` functions; convert `gather_intel()` to `ThreadPoolExecutor` |
| `ai_analysis.py` | Add `_build_intel_summary()`; `_build_user_prompt()` accepts `intel_summary`; `analyze_with_claude()` gets `intel=None` param and handles missing screenshot |
| `main.py` | `POST /api/analyze` returns immediately; add `_run_analysis()` background task; remove old `_run()` blocking pattern |
| `static/index.html` | Polling submit flow; progress stage indicator; 6 new intel source cards in `renderIntel()` |
| `CLAUDE.md` | Update `.env` example block and `intel.py` module description |
| `README.md` | Document 4 new optional env vars |

---

## Task 1 — database.py: add `status` column and three new functions

**Files:**
- Modify: `database.py`

- [ ] **Step 1: Add `status` to the migration list and back-fill existing rows**

  Open `database.py`. In `_migrate_db()`, append `("status", "TEXT DEFAULT 'complete'")` to `new_columns` and add an explicit back-fill `UPDATE` call after the loop so pre-existing rows are never NULL:

  ```python
  def _migrate_db():
      new_columns = [
          ("ai_verdict", "TEXT"),
          ("ai_confidence", "INTEGER"),
          ("ai_brand_impersonated", "TEXT"),
          ("ai_risk_indicators", "TEXT"),
          ("ai_summary", "TEXT"),
          ("ai_recommended_action", "TEXT"),
          ("takedown_data", "TEXT"),
          ("response_body", "TEXT"),
          ("intel_data", "TEXT"),
          ("status", "TEXT DEFAULT 'complete'"),   # ← new
      ]
      with _conn() as conn:
          for col, col_type in new_columns:
              try:
                  conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {col_type}")
              except Exception:
                  pass
          # back-fill any rows that pre-date this column
          try:
              conn.execute("UPDATE cases SET status = 'complete' WHERE status IS NULL")
          except Exception:
              pass
  ```

- [ ] **Step 2: Add `insert_case_pending()`**

  Add this function directly after `insert_case()`:

  ```python
  def insert_case_pending(*, url: str, timestamp: str) -> int:
      with _conn() as conn:
          cur = conn.execute(
              "INSERT INTO cases (url, timestamp, status) VALUES (?, ?, 'running')",
              (url, timestamp),
          )
          return cur.lastrowid
  ```

- [ ] **Step 3: Add `update_case_browser_results()`**

  Add after `insert_case_pending()`:

  ```python
  def update_case_browser_results(case_id: int, data: dict):
      with _conn() as conn:
          conn.execute(
              """UPDATE cases SET
                 title = ?, final_url = ?, status_code = ?,
                 screenshot_path = ?, raw_headers = ?, response_body = ?
                 WHERE id = ?""",
              (
                  data.get("title"),
                  data.get("final_url"),
                  data.get("status"),        # analyze.py uses key "status" for HTTP status code
                  data.get("screenshot"),
                  json.dumps(data.get("headers", {})),
                  data.get("body"),
                  case_id,
              ),
          )
  ```

- [ ] **Step 4: Add `update_case_status()`**

  Add after `update_case_browser_results()`:

  ```python
  def update_case_status(case_id: int, status: str):
      with _conn() as conn:
          conn.execute(
              "UPDATE cases SET status = ? WHERE id = ?",
              (status, case_id),
          )
  ```

- [ ] **Step 5: Verify the migration runs cleanly**

  Delete `cases.db` if one exists from development, start the app briefly, then inspect the schema:

  ```bash
  rm -f cases.db
  python -c "import database; database.init_db(); print('OK')"
  sqlite3 cases.db ".schema cases"
  ```

  Expected output includes: `status TEXT DEFAULT 'complete'`

- [ ] **Step 6: Commit**

  ```bash
  git add database.py
  git commit -m "feat(db): add status column and pending/browser/status update functions"
  ```

---

## Task 2 — analyze.py: extend Playwright navigation timeout

**Files:**
- Modify: `analyze.py:69`

- [ ] **Step 1: Change the nav timeout**

  In `analyze.py`, line 69, change `timeout=30_000` to `timeout=120_000`:

  ```python
  nav_response = page.goto(url, timeout=120_000, wait_until="networkidle")
  ```

- [ ] **Step 2: Verify the change**

  ```bash
  grep "timeout=" analyze.py
  ```

  Expected: `timeout=120_000`

- [ ] **Step 3: Commit**

  ```bash
  git add analyze.py
  git commit -m "feat(analyzer): extend Playwright nav timeout from 30s to 120s"
  ```

---

## Task 3 — intel.py: add 6 new query functions

**Files:**
- Modify: `intel.py`

Add all six functions after the existing `query_censys()` function and before `generate_pivot_suggestions()`.

- [ ] **Step 1: Add `query_google_safe_browsing()`**

  ```python
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
  ```

- [ ] **Step 2: Add `query_otx()`**

  ```python
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
  ```

- [ ] **Step 3: Add `query_abuseipdb()`**

  ```python
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
  ```

- [ ] **Step 4: Add `query_crtsh()`**

  ```python
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
          certs = r.json()[:500]   # cap at 500 to avoid huge responses for popular domains
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
  ```

- [ ] **Step 5: Add `query_urlhaus()`**

  ```python
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
  ```

- [ ] **Step 6: Add `query_phishtank()`**

  ```python
  def query_phishtank(url: str) -> dict:
      api_key = os.getenv("PHISHTANK_API_KEY", "")
      result = {
          "available": bool(url),
          "configured": True,          # works without a key (rate-limited)
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
  ```

- [ ] **Step 7: Verify the new functions are importable**

  ```bash
  python -c "
  from intel import (query_google_safe_browsing, query_otx, query_abuseipdb,
                     query_crtsh, query_urlhaus, query_phishtank)
  print('All 6 functions import OK')
  # Quick smoke test — crtsh requires no key
  r = query_crtsh('example.com')
  print('crtsh cert_count:', r.get('cert_count'), 'error:', r.get('error'))
  "
  ```

  Expected: prints cert count > 0 and error: None.

- [ ] **Step 8: Commit**

  ```bash
  git add intel.py
  git commit -m "feat(intel): add 6 new free threat intel sources (GSB, OTX, AbuseIPDB, crt.sh, URLhaus, PhishTank)"
  ```

---

## Task 4 — intel.py: parallelize `gather_intel()` and update pivot suggestions pass

**Files:**
- Modify: `intel.py`

- [ ] **Step 1: Add `ThreadPoolExecutor` import at the top of `intel.py`**

  Replace the existing imports block. `concurrent.futures` is stdlib — no new dependency:

  ```python
  import os
  import socket
  from concurrent.futures import ThreadPoolExecutor, as_completed
  from urllib.parse import urlparse

  import requests
  ```

- [ ] **Step 2: Replace the body of `gather_intel()`**

  The existing `gather_intel` runs URLScan → VT → Shodan → Censys sequentially. Replace its entire body with the parallel version that also includes all 10 sources. The function signature is unchanged: `gather_intel(case: dict, ai_result: dict) -> dict`.

  ```python
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
  ```

- [ ] **Step 3: Verify parallelism is working — should be much faster than before**

  ```bash
  time python -c "
  import intel
  case = {'url': 'https://example.com', 'final_url': 'https://example.com'}
  result = intel.gather_intel(case, {})
  sources = [k for k in result if k not in ('resolved_ip', 'pivot_suggestions')]
  print('Sources:', sources)
  for s in sources:
      err = result[s].get('error') if isinstance(result[s], dict) else None
      print(f'  {s}: error={err}')
  "
  ```

  Expected: runs in ~10 s total (not 40 s+), all 10 sources present in output.

- [ ] **Step 4: Commit**

  ```bash
  git add intel.py
  git commit -m "feat(intel): parallelize all 10 intel sources with ThreadPoolExecutor"
  ```

---

## Task 5 — ai_analysis.py: intel enrichment

**Files:**
- Modify: `ai_analysis.py`

- [ ] **Step 1: Add `_build_intel_summary()` helper**

  Add this function after `_FALLBACK` and before the provider config block:

  ```python
  def _build_intel_summary(intel: dict) -> str | None:
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
  ```

- [ ] **Step 2: Update `_build_user_prompt()` to accept and embed `intel_summary`**

  Replace the existing `_build_user_prompt` function:

  ```python
  def _build_user_prompt(case: dict, intel_summary: str | None = None) -> str:
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
  ```

- [ ] **Step 3: Update all four `_analyze_*` functions to accept and pass `intel_summary`, and handle `image_b64=None` for text-only mode**

  Replace all four `_analyze_*` functions with these updated versions:

  ```python
  def _analyze_anthropic(case: dict, image_b64: str | None, intel_summary: str | None = None) -> dict:
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


  def _analyze_bedrock(case: dict, image_b64: str | None, intel_summary: str | None = None) -> dict:
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


  def _analyze_openai(case: dict, image_b64: str | None, intel_summary: str | None = None) -> dict:
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


  def _analyze_openrouter(case: dict, image_b64: str | None, intel_summary: str | None = None) -> dict:
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
  ```

- [ ] **Step 4: Update `analyze_with_claude()` to accept `intel` and handle missing screenshot**

  Replace the existing `analyze_with_claude` function:

  ```python
  def analyze_with_claude(case: dict, screenshot_path: str, intel: dict | None = None) -> dict:
      """Return an AI phishing assessment. Provider selected via MODEL_PROVIDER env var."""
      intel_summary = _build_intel_summary(intel) if intel else None

      image_b64: str | None = None
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
  ```

- [ ] **Step 5: Verify the module imports and the summary builder works**

  ```bash
  python -c "
  import ai_analysis
  # Test summary builder with mock intel
  mock_intel = {
      'gsb': {'is_listed': True, 'threat_types': ['SOCIAL_ENGINEERING'], 'error': None},
      'virustotal': {'data': {'malicious': 5, 'suspicious': 2, 'not_found': False}, 'error': None},
      'phishtank': {'verified': False, 'error': None},
      'otx': {'domain_pulses': 3, 'error': None},
      'abuseipdb': {'abuse_score': 75, 'error': None},
      'urlscan': {'total': 8, 'error': None},
      'crtsh': {'earliest_cert_date': '2026-01-15', 'cert_count': 2, 'wildcard_certs': False, 'error': None},
      'urlhaus': {'url_listed': False, 'host_listed': False, 'error': None},
  }
  summary = ai_analysis._build_intel_summary(mock_intel)
  print(summary)
  print()
  print('analyze_with_claude signature OK:', ai_analysis.analyze_with_claude.__code__.co_varnames[:3])
  "
  ```

  Expected: prints a multi-line intel summary with GSB match, VT detections, OTX pulses, AbuseIPDB score, and crt.sh info.

- [ ] **Step 6: Commit**

  ```bash
  git add ai_analysis.py
  git commit -m "feat(ai): add intel context to AI prompt and support text-only mode when screenshot missing"
  ```

---

## Task 6 — main.py: non-blocking POST + background pipeline task

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add `datetime` import and background task set at the top of `main.py`**

  The file already imports `asyncio`, `json`, `os`, `subprocess`, `sys`. Add `datetime` to the stdlib imports and add the task reference set after the app is created:

  ```python
  import asyncio
  import json
  import os
  import subprocess
  import sys
  from datetime import datetime, timezone
  from pathlib import Path
  ```

  After `app = FastAPI(title="Phishing Analyzer")` and `database.init_db()`, add:

  ```python
  _background_tasks: set[asyncio.Task] = set()
  ```

- [ ] **Step 2: Replace the `analyze` endpoint and add `_run_analysis()`**

  Remove the entire existing `analyze` endpoint (lines 118–173) and the nested `_run()` function inside it. Replace with:

  ```python
  @app.post("/api/analyze", dependencies=[Depends(_require_auth)])
  async def analyze(req: AnalyzeRequest):
      url = req.url.strip()
      if not url.startswith(("http://", "https://")):
          raise HTTPException(status_code=422, detail="URL must start with http:// or https://")

      timestamp = datetime.now(timezone.utc).isoformat()
      case_id = database.insert_case_pending(url=url, timestamp=timestamp)

      task = asyncio.create_task(_run_analysis(case_id, url))
      _background_tasks.add(task)
      task.add_done_callback(_background_tasks.discard)

      return {"case_id": case_id, "status": "running"}


  async def _run_analysis(case_id: int, url: str) -> None:
      """Background pipeline: browser + intel in parallel, then AI, then takedown."""
      try:
          stub_case = database.get_case(case_id)

          async def _do_browser() -> dict | None:
              def _run():
                  return subprocess.run(
                      [sys.executable, str(BASE_DIR / "analyze.py"), url, "--json"],
                      capture_output=True,
                      text=True,
                      timeout=300,
                  )
              try:
                  proc = await asyncio.to_thread(_run)
                  data = json.loads(proc.stdout)
                  database.update_case_browser_results(case_id, data)
                  return data
              except subprocess.TimeoutExpired:
                  return None
              except (json.JSONDecodeError, Exception):
                  return None

          async def _do_intel() -> dict:
              intel = await asyncio.to_thread(intel_module.gather_intel, stub_case, {})
              database.update_case_intel(case_id, intel)
              return intel

          # Run browser capture and intel in parallel; each writes to DB independently
          browser_result, intel_result = await asyncio.gather(
              _do_browser(),
              _do_intel(),
              return_exceptions=True,
          )

          if isinstance(browser_result, Exception):
              browser_result = None
          if isinstance(intel_result, Exception):
              intel_result = {}

          # Fetch the case after browser fields have been written
          case = database.get_case(case_id)
          screenshot_path = (browser_result or {}).get("screenshot") or ""

          # AI analysis — uses screenshot (if captured) + intel context
          analysis = await asyncio.to_thread(
              ai_analysis.analyze_with_claude, case, screenshot_path, intel_result or {}
          )
          database.update_case_ai_analysis(case_id, analysis)

          # Takedown report for phishing/suspicious verdicts
          if analysis.get("verdict") in ("phishing", "suspicious"):
              td = await asyncio.to_thread(takedown.generate_takedown_report, case, analysis)
              database.update_case_takedown(case_id, td)

          # Regenerate pivot suggestions with full verdict + takedown context
          try:
              if intel_result:
                  final_case = database.get_case(case_id)
                  updated_intel = dict(intel_result)
                  updated_intel["pivot_suggestions"] = intel_module.generate_pivot_suggestions(
                      final_case, analysis, updated_intel
                  )
                  database.update_case_intel(case_id, updated_intel)
          except Exception:
              pass

          database.update_case_status(case_id, "complete")

      except Exception:
          try:
              database.update_case_status(case_id, "failed")
          except Exception:
              pass
  ```

- [ ] **Step 3: Start the server and verify `POST /api/analyze` returns immediately**

  ```bash
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
  ```

  In another terminal (replace `<session_cookie>` with a real cookie after logging in via the browser):

  ```bash
  # First log in via browser at http://localhost:8000/login, copy the session cookie value, then:
  curl -s -X POST http://localhost:8000/api/analyze \
    -H "Content-Type: application/json" \
    -H "Cookie: session=<session_cookie>" \
    -d '{"url": "https://example.com"}' | python3 -m json.tool
  ```

  Expected: response arrives in < 1 s, looks like:
  ```json
  {"case_id": 1, "status": "running"}
  ```

- [ ] **Step 4: Verify polling shows progressive updates**

  While the previous curl is still "running" (wait 5 s), poll the case:

  ```bash
  curl -s http://localhost:8000/api/cases/1 \
    -H "Cookie: session=<session_cookie>" | python3 -m json.tool
  ```

  After ~10 s, `intel_data` should be non-null. After ~60 s, `ai_verdict` should be set and `status` should be `"complete"`.

- [ ] **Step 5: Commit**

  ```bash
  git add main.py
  git commit -m "feat(api): non-blocking analyze endpoint with parallel browser+intel background task"
  ```

---

## Task 7 — static/index.html: polling UI, progress indicator, 6 new intel cards

**Files:**
- Modify: `static/index.html`

### 7a — Replace `startScan()` with polling flow

- [ ] **Step 1: Replace the `startScan()` function**

  Find the `startScan()` function (starts at `async function startScan()` around line 756) and replace it entirely with:

  ```js
  async function startScan() {
    const input = document.getElementById('urlInput');
    let url = input.value.trim();
    if (!url) { toast('Enter a URL to analyze', 'info'); return; }
    if (!url.startsWith('http')) url = 'https://' + url;

    const btn = document.getElementById('scanBtn');
    const statusEl = document.getElementById('scanStatus');
    const progressBar = document.getElementById('progressBar');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing…';
    progressBar.style.display = 'block';

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const { case_id } = await res.json();
      input.value = '';
      document.getElementById('dupWarning').classList.remove('visible');
      showStageProgress(statusEl);
      await pollUntilComplete(case_id, statusEl);
    } catch (e) {
      toast(`Scan failed: ${e.message}`, 'error');
      statusEl.textContent = `Error: ${e.message}`;
      statusEl.classList.add('visible');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>🔍</span> Analyze';
      progressBar.style.display = 'none';
      setTimeout(() => {
        statusEl.classList.remove('visible');
        statusEl.innerHTML = '';
      }, 4000);
    }
  }

  function showStageProgress(statusEl) {
    statusEl.innerHTML = `
      <div id="stageList" style="display:flex;flex-direction:column;gap:0.3rem;margin-top:0.2rem">
        <div id="stage-intel" class="stage-row">
          <span class="spinner" style="width:10px;height:10px;border-width:1.5px"></span>
          <span>Querying 10 threat intel sources…</span>
        </div>
        <div id="stage-browser" class="stage-row" style="opacity:0.5">
          <span class="spinner" style="width:10px;height:10px;border-width:1.5px"></span>
          <span>Capturing mobile screenshot…</span>
        </div>
        <div id="stage-ai" class="stage-row" style="opacity:0.5">
          <span class="spinner" style="width:10px;height:10px;border-width:1.5px"></span>
          <span>AI analysis pending…</span>
        </div>
      </div>`;
    statusEl.classList.add('visible');
  }

  function markStageDone(stageId, label) {
    const el = document.getElementById(stageId);
    if (el) {
      el.style.opacity = '1';
      el.innerHTML = `<span style="color:var(--green);font-weight:600">✓</span> <span>${label}</span>`;
    }
  }

  async function pollUntilComplete(case_id, statusEl) {
    let intelShown = false;
    let aiShown = false;

    return new Promise((resolve) => {
      const interval = setInterval(async () => {
        try {
          const c = await fetch(`/api/cases/${case_id}`).then(r => r.json());

          if (c.intel_data && !intelShown) {
            intelShown = true;
            markStageDone('stage-intel', '10 intel sources queried');
            const intelStage = document.getElementById('stage-browser');
            if (intelStage) intelStage.style.opacity = '1';
          }

          if (c.ai_verdict && !aiShown) {
            aiShown = true;
            markStageDone('stage-browser', 'Screenshot captured');
            markStageDone('stage-ai', `AI verdict: ${c.ai_verdict}`);
          }

          if (c.status === 'complete' || c.status === 'failed') {
            clearInterval(interval);
            if (c.status === 'failed') {
              toast('Analysis failed — partial results may be available', 'error');
            } else {
              toast(
                `Analysis complete: ${c.ai_verdict || 'inconclusive'}`,
                c.ai_verdict === 'phishing' ? 'error' : c.ai_verdict === 'legitimate' ? 'success' : 'info'
              );
            }
            showDetail(c);
            loadStats();
            loadCases();
            resolve();
          }
        } catch (e) {
          // network hiccup — keep polling
        }
      }, 2500);
    });
  }
  ```

- [ ] **Step 2: Add `.stage-row` CSS to the `<style>` block**

  Find the `.spinner` CSS rule (around line 437) and add after it:

  ```css
  .stage-row {
    display: flex; align-items: center; gap: 0.4rem;
    font-size: 0.78rem; color: var(--muted);
  }
  .stage-row span:first-child { flex-shrink: 0; }
  ```

### 7b — Add 6 new intel source cards to `renderIntel()`

- [ ] **Step 3: Add the 6 new source blocks inside `renderIntel()`**

  Find the end of `renderIntel()` where `el.innerHTML = html;` is called (around line 960). Add the 6 new blocks before that line:

  ```js
  // Google Safe Browsing
  html += renderIntelSource('Google Safe Browsing', '🛡', intel.gsb, (d) => {
    if (d.error && !d.configured) return `<div class="intel-not-configured">GOOGLE_SAFE_BROWSING_API_KEY not configured.</div>`;
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    if (d.is_listed) {
      return `<div class="intel-key-val"><span class="intel-key">Status</span><span class="intel-val"><span class="badge phishing dot">LISTED</span></span></div>` +
        `<div class="intel-key-val"><span class="intel-key">Threat types</span><span class="intel-val">${(d.threat_types||[]).map(t => `<span class="tag" style="color:var(--red)">${esc(t)}</span>`).join(' ')}</span></div>`;
    }
    return `<div class="intel-key-val"><span class="intel-key">Status</span><span class="intel-val"><span class="badge legitimate dot">Clean</span></span></div>`;
  });

  // OTX AlienVault
  html += renderIntelSource('OTX AlienVault', '👁', intel.otx, (d) => {
    if (!d.configured) return `<div class="intel-not-configured">OTX_API_KEY not configured.</div>`;
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    return `
      <div class="intel-key-val"><span class="intel-key">Threat pulses</span><span class="intel-val" style="color:${d.domain_pulses>0?'var(--red)':'var(--green)'}">${d.domain_pulses}</span></div>
      <div class="intel-key-val"><span class="intel-key">Reputation</span><span class="intel-val">${d.reputation}</span></div>
      ${d.tags && d.tags.length ? `<div class="intel-key-val"><span class="intel-key">Tags</span><span class="intel-val">${d.tags.slice(0,8).map(t=>`<span class="tag">${esc(t)}</span>`).join(' ')}</span></div>` : ''}
      ${d.malware_families && d.malware_families.length ? `<div class="intel-key-val"><span class="intel-key">Malware</span><span class="intel-val">${d.malware_families.map(f=>`<span class="tag" style="color:var(--red)">${esc(f)}</span>`).join(' ')}</span></div>` : ''}
    `;
  });

  // AbuseIPDB
  html += renderIntelSource('AbuseIPDB', '🚨', intel.abuseipdb, (d) => {
    if (!d.configured) return `<div class="intel-not-configured">ABUSEIPDB_API_KEY not configured.</div>`;
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    const score = d.abuse_score ?? 0;
    const scoreColor = score >= 50 ? 'var(--red)' : score >= 20 ? 'var(--orange)' : 'var(--green)';
    return `
      <div class="intel-key-val"><span class="intel-key">Abuse score</span><span class="intel-val" style="font-weight:700;color:${scoreColor}">${score}/100</span></div>
      <div class="intel-key-val"><span class="intel-key">Reports</span><span class="intel-val">${d.total_reports}</span></div>
      ${d.isp ? `<div class="intel-key-val"><span class="intel-key">ISP</span><span class="intel-val">${esc(d.isp)}</span></div>` : ''}
      ${d.usage_type ? `<div class="intel-key-val"><span class="intel-key">Usage type</span><span class="intel-val">${esc(d.usage_type)}</span></div>` : ''}
      ${d.country ? `<div class="intel-key-val"><span class="intel-key">Country</span><span class="intel-val">${esc(d.country)}</span></div>` : ''}
    `;
  });

  // crt.sh
  html += renderIntelSource('crt.sh (Cert Transparency)', '📜', intel.crtsh, (d) => {
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    if (!d.cert_count) return `<div class="intel-not-configured">No certificates found.</div>`;
    return `
      <div class="intel-key-val"><span class="intel-key">Total certs</span><span class="intel-val">${d.cert_count}</span></div>
      ${d.earliest_cert_date ? `<div class="intel-key-val"><span class="intel-key">First seen</span><span class="intel-val">${esc(d.earliest_cert_date)}</span></div>` : ''}
      ${d.latest_cert_date ? `<div class="intel-key-val"><span class="intel-key">Latest cert</span><span class="intel-val">${esc(d.latest_cert_date)}</span></div>` : ''}
      ${d.wildcard_certs ? `<div class="intel-key-val"><span class="intel-key">Wildcard</span><span class="intel-val"><span class="badge suspicious dot">Detected</span></span></div>` : ''}
    `;
  });

  // URLhaus
  html += renderIntelSource('URLhaus (Abuse.ch)', '☣', intel.urlhaus, (d) => {
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    if (!d.url_listed && !d.host_listed) return `<div class="intel-key-val"><span class="intel-key">Status</span><span class="intel-val"><span class="badge legitimate dot">Not listed</span></span></div>`;
    return `
      ${d.url_listed ? `<div class="intel-key-val"><span class="intel-key">URL</span><span class="intel-val"><span class="badge phishing dot">Listed</span></span></div>` : ''}
      ${d.host_listed ? `<div class="intel-key-val"><span class="intel-key">Host</span><span class="intel-val"><span class="badge phishing dot">Listed</span></span></div>` : ''}
      ${d.threat ? `<div class="intel-key-val"><span class="intel-key">Threat type</span><span class="intel-val">${esc(d.threat)}</span></div>` : ''}
      ${d.tags && d.tags.length ? `<div class="intel-key-val"><span class="intel-key">Tags</span><span class="intel-val">${d.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join(' ')}</span></div>` : ''}
    `;
  });

  // PhishTank
  html += renderIntelSource('PhishTank', '🪝', intel.phishtank, (d) => {
    if (d.error) return `<div class="intel-error">Error: ${esc(d.error)}</div>`;
    if (!d.in_database) return `<div class="intel-key-val"><span class="intel-key">Status</span><span class="intel-val"><span class="badge legitimate dot">Not in database</span></span></div>`;
    return `
      <div class="intel-key-val"><span class="intel-key">Status</span><span class="intel-val"><span class="badge ${d.verified ? 'phishing' : 'suspicious'} dot">${d.verified ? 'Verified phishing' : 'In database (unverified)'}</span></span></div>
      ${d.phish_id ? `<div class="intel-key-val"><span class="intel-key">PhishTank ID</span><span class="intel-val mono">${esc(d.phish_id)}</span></div>` : ''}
      ${d.verified_at ? `<div class="intel-key-val"><span class="intel-key">Verified at</span><span class="intel-val">${esc(String(d.verified_at).slice(0,10))}</span></div>` : ''}
    `;
  });
  ```

- [ ] **Step 4: Update the `renderIntelSource()` function to handle sources without a `configured` field**

  The new sources (crtsh, urlhaus) don't use a `configured` flag. Update the badge logic:

  ```js
  function renderIntelSource(title, icon, data, contentFn) {
    if (!data) return `<div class="intel-source"><div class="intel-source-header"><div class="intel-source-title">${icon} ${title}</div><span class="badge">N/A</span></div></div>`;
    const hasConfigured = 'configured' in data;
    const badge = hasConfigured
      ? (data.configured ? '<span class="badge legitimate dot">Active</span>' : '<span class="badge inconclusive">Not configured</span>')
      : (data.error ? '<span class="badge inconclusive">Error</span>' : '<span class="badge legitimate dot">Active</span>');
    return `
      <div class="intel-source">
        <div class="intel-source-header">
          <div class="intel-source-title">${icon} ${title}</div>
          ${badge}
        </div>
        <div class="intel-source-body">${contentFn(data)}</div>
      </div>`;
  }
  ```

- [ ] **Step 5: Open the app in a browser and submit a test URL**

  ```bash
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
  ```

  Open `http://localhost:8000`, log in, submit `https://example.com`. Verify:
  - The Analyze button returns immediately (no long wait)
  - Three stage rows appear (Intel, Browser, AI)
  - Intel stage gets a green checkmark first (~10 s)
  - Browser stage gets a checkmark after screenshot completes (~30–60 s)
  - AI stage gets a checkmark and the detail view opens (~5 s after browser)
  - Intel tab shows 10 source cards (4 existing + 6 new)

- [ ] **Step 6: Commit**

  ```bash
  git add static/index.html
  git commit -m "feat(ui): polling submit flow, progress stages, 6 new intel source cards"
  ```

---

## Task 8 — CLAUDE.md and README.md: document new env vars and updated module descriptions

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update the `.env` example block in `CLAUDE.md`**

  Find the `.env` example block and add the four new optional keys:

  ```dotenv
  # Optional: external intel APIs
  # URLSCAN_API_KEY=...
  # VIRUSTOTAL_API_KEY=...
  # SHODAN_API_KEY=...
  # CENSYS_API_ID=...
  # CENSYS_API_SECRET=...
  # GOOGLE_SAFE_BROWSING_API_KEY=...  # console.cloud.google.com → Safe Browsing API (free)
  # OTX_API_KEY=...                   # otx.alienvault.com → API key in profile (free)
  # ABUSEIPDB_API_KEY=...             # abuseipdb.com → API tab in account (free, 1k/day)
  # PHISHTANK_API_KEY=...             # phishtank.com/api_register.php (optional, rate-limit increase)
  ```

- [ ] **Step 2: Update `intel.py` module description in `CLAUDE.md`**

  Find the bullet for `intel.py` under "Module Responsibilities" and expand it:

  ```
  - **`intel.py`** — External threat intelligence aggregator. `gather_intel()` resolves the
    domain IP then fans out to **ten sources in parallel** using `ThreadPoolExecutor`:
    URLScan.io, VirusTotal, Shodan, Censys (all existing), plus Google Safe Browsing lookup,
    OTX AlienVault, AbuseIPDB, crt.sh (certificate transparency), URLhaus, and PhishTank.
    Sources with no API key configured return a structured error dict and do not block others.
    Also generates `pivot_suggestions`. Called in the background pipeline before AI analysis;
    results written to DB independently of browser capture.
  ```

- [ ] **Step 3: Update README.md — add a new "External Intelligence" section entry for the new sources**

  Find the External Intelligence section (or equivalent) in `README.md` and add the four new env vars with free-tier notes:

  ```markdown
  | `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | Google Safe Browsing phishing/malware lookup. Free. [Get key](https://console.cloud.google.com/) → Safe Browsing API. |
  | `OTX_API_KEY` | Optional | AlienVault OTX domain/IP threat pulses. Free. [Register at otx.alienvault.com](https://otx.alienvault.com). |
  | `ABUSEIPDB_API_KEY` | Optional | IP abuse confidence score. Free tier: 1 000 checks/day. [abuseipdb.com](https://www.abuseipdb.com). |
  | `PHISHTANK_API_KEY` | Optional | PhishTank community phishing DB. Works without key (rate-limited). [Register](https://phishtank.com/api_register.php). |
  ```

  Also note that `crt.sh` and `URLhaus` require no credentials.

- [ ] **Step 4: Commit**

  ```bash
  git add CLAUDE.md README.md
  git commit -m "docs: document 6 new intel sources and updated pipeline architecture"
  ```

---

## Self-review checklist

- [x] **Spec coverage**: All 10 sections of the spec have corresponding tasks.
  - Timeout changes → Task 2 (analyze.py) + Task 6 (main.py 300 s wrapper)
  - Parallel browser+intel → Task 6 (`asyncio.gather(_do_browser(), _do_intel())`)
  - Intel writes independently → Task 6 (`_do_intel()` calls `update_case_intel()` internally)
  - 10 intel sources parallel → Task 4 (`ThreadPoolExecutor`)
  - 6 new query functions → Task 3
  - AI intel enrichment → Task 5 (`_build_intel_summary`, `analyze_with_claude(intel=)`)
  - DB status column → Task 1
  - Polling frontend → Task 7a
  - Progress indicator → Task 7a (`showStageProgress`, `markStageDone`)
  - New intel cards → Task 7b
  - Pivot suggestions regeneration → Task 6 (after AI+takedown)
  - Error handling (partial intel) → Task 4 (per-future try/except), Task 6 (`return_exceptions=True`)
  - Browser timeout → Task 6 (`TimeoutExpired` caught, returns `None`, AI proceeds text-only)
  - Unhandled pipeline crash → Task 6 (outer `try/except` marks status=`failed`)
  - CLAUDE.md/README → Task 8

- [x] **Placeholder scan**: No TBD, no "add error handling", no "similar to above" — all steps contain complete code.

- [x] **Type consistency**:
  - `insert_case_pending(*, url, timestamp)` defined in Task 1, called in Task 6 ✓
  - `update_case_browser_results(case_id, data)` defined in Task 1, called in Task 6 ✓
  - `update_case_status(case_id, status)` defined in Task 1, called in Task 6 ✓
  - `analyze_with_claude(case, screenshot_path, intel=None)` defined in Task 5, called in Task 6 ✓
  - `gather_intel(case, ai_result)` signature unchanged, called in Task 6 ✓
  - `generate_pivot_suggestions(case, ai_result, intel)` signature unchanged, called in Task 6 ✓
  - `intel.gsb`, `intel.otx`, etc. keys set in Task 4 `gather_intel()`, consumed in Task 7b ✓
