import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel

import ai_analysis
import database
import takedown

BASE_DIR = Path(__file__).parent

for _var in ("ANTHROPIC_API_KEY", "APP_PASSWORD", "SECRET_KEY"):
    if not os.environ.get(_var):
        print(f"ERROR: {_var} environment variable is not set.", file=sys.stderr)
        sys.exit(1)

APP_PASSWORD = os.environ["APP_PASSWORD"]
_signer = URLSafeTimedSerializer(os.environ["SECRET_KEY"])
_SESSION_COOKIE = "session"
_SESSION_MAX_AGE = 8 * 3600

app = FastAPI(title="Phishing Analyzer")
database.init_db()


def _make_session_token() -> str:
    return _signer.dumps("authenticated")


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    try:
        _signer.loads(token, max_age=_SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def _require_auth(request: Request):
    if not _valid_session(request.cookies.get(_SESSION_COOKIE)):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Auth routes ──────────────────────────────────────────────────────────────

@app.get("/login")
def login_page(request: Request):
    if _valid_session(request.cookies.get(_SESSION_COOKIE)):
        return RedirectResponse("/", status_code=302)
    return FileResponse(BASE_DIR / "static" / "login.html")


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    if form.get("password", "") != APP_PASSWORD:
        return RedirectResponse("/login?error=1", status_code=302)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        _SESSION_COOKIE,
        _make_session_token(),
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(_SESSION_COOKIE)
    return response


# ── Protected page ───────────────────────────────────────────────────────────

@app.get("/")
def index(request: Request):
    if not _valid_session(request.cookies.get(_SESSION_COOKIE)):
        return RedirectResponse("/login", status_code=302)
    return FileResponse(BASE_DIR / "static" / "index.html")


# ── API routes (return 401 JSON when unauthenticated) ────────────────────────

class AnalyzeRequest(BaseModel):
    url: str


def _screenshot_url(path: str | None) -> str | None:
    if not path:
        return None
    return f"/screenshots/{Path(path).name}"


def _enrich(case: dict) -> dict:
    case["screenshot_url"] = _screenshot_url(case.get("screenshot_path"))
    return case


@app.post("/api/analyze", dependencies=[Depends(_require_auth)])
async def analyze(req: AnalyzeRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")

    def _run():
        return subprocess.run(
            [sys.executable, str(BASE_DIR / "analyze.py"), url, "--json"],
            capture_output=True,
            text=True,
            timeout=90,
        )

    try:
        proc = await asyncio.to_thread(_run)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Analysis timed out after 90 s")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"analyze.py produced no JSON. stderr: {proc.stderr[:500]}",
        )

    case_id = database.insert_case(
        url=data.get("url_input", url),
        timestamp=data.get("timestamp", ""),
        title=data.get("title"),
        final_url=data.get("final_url"),
        status_code=data.get("status"),
        screenshot_path=data.get("screenshot"),
        raw_headers=json.dumps(data.get("headers", {})),
    )

    case = database.get_case(case_id)
    screenshot_path = data.get("screenshot") or ""
    analysis = await asyncio.to_thread(ai_analysis.analyze_with_claude, case, screenshot_path)
    database.update_case_ai_analysis(case_id, analysis)

    if analysis.get("verdict") in ("phishing", "suspicious"):
        td = await asyncio.to_thread(takedown.generate_takedown_report, case, analysis)
        database.update_case_takedown(case_id, td)

    return _enrich(database.get_case(case_id))


@app.get("/api/cases", dependencies=[Depends(_require_auth)])
def list_cases():
    return [_enrich(c) for c in database.get_all_cases()]


@app.get("/api/cases/{case_id}", dependencies=[Depends(_require_auth)])
def get_case(case_id: int):
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return _enrich(case)


@app.post("/api/cases/{case_id}/takedown", dependencies=[Depends(_require_auth)])
async def regenerate_takedown(case_id: int):
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ai_result = {
        "verdict": case.get("ai_verdict"),
        "brand_impersonated": case.get("ai_brand_impersonated"),
        "risk_indicators": case.get("ai_risk_indicators") or [],
        "summary": case.get("ai_summary"),
    }
    td = await asyncio.to_thread(takedown.generate_takedown_report, case, ai_result)
    database.update_case_takedown(case_id, td)
    return td


# Static mounts must come after route definitions
app.mount(
    "/screenshots",
    StaticFiles(directory=str(BASE_DIR / "screenshots")),
    name="screenshots",
)
app.mount(
    "/",
    StaticFiles(directory=str(BASE_DIR / "static"), html=True),
    name="static",
)
