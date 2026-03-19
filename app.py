import os
import io
import shutil
import tempfile
import asyncio
import logging
import zipfile
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

from analyzer import clone_repo, analyze_repo
from llm_review import get_llm_review
from gumroad_auth import verify_license
from fix_generator import generate_fixes
from vibecheck_md import generate_vibecheck_md
from db import save_audit, get_audit

import json

# Max LOC for fix pack generation
FIX_PACK_MAX_LOC = 50000

# Gumroad purchase URLs
GUMROAD_REPORT_URL = os.getenv("GUMROAD_REPORT_URL", "https://trevorgd6.gumroad.com/l/qvbyo")
GUMROAD_FIXPACK_URL = os.getenv("GUMROAD_FIXPACK_URL", "https://trevorgd6.gumroad.com/l/atwzm")

app = FastAPI(title="Vibe Audit")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


def _issue_count(llm_review: dict) -> int:
    """Count total actionable issues from the LLM review."""
    if not llm_review or llm_review.get("error"):
        return 0
    return (
        len(llm_review.get("priority_fixes", []))
        + len(llm_review.get("security_concerns", []))
        + len(llm_review.get("code_smells", []))
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/audit", response_class=HTMLResponse)
async def run_audit(request: Request, repo_url: str = Form(...), license_key: str = Form("")):
    # Determine tier: no key = free, valid key = report
    tier = "free"
    valid_key = ""
    if license_key.strip():
        auth = await verify_license(license_key)
        if not auth["success"]:
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "error": auth.get("error", "Invalid license key"), "repo_url": repo_url},
            )
        tier = "report"
        valid_key = license_key.strip()

    # Normalize repo URL
    repo_url = repo_url.strip()
    if not any(host in repo_url for host in ["github.com", "gitlab.com", "bitbucket.org"]):
        if "/" in repo_url and len(repo_url.split("/")) == 2:
            repo_url = f"https://github.com/{repo_url}"
        else:
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "error": "Enter a valid GitHub URL or owner/repo", "repo_url": repo_url},
            )

    tmp_dir = tempfile.mkdtemp(prefix="vibe_audit_")
    try:
        # Clone
        try:
            repo_path = await asyncio.to_thread(clone_repo, repo_url, tmp_dir)
        except ValueError as e:
            return templates.TemplateResponse(
                "index.html", {"request": request, "error": str(e), "repo_url": repo_url}
            )

        # Analyze
        audit_result = await asyncio.to_thread(analyze_repo, repo_path, repo_url)

        # LLM review
        try:
            llm_result = await asyncio.to_thread(get_llm_review, audit_result)
            audit_result.llm_review = llm_result
            if "architecture_score" in llm_result:
                audit_result.section_scores["architecture"] = min(15, max(0, llm_result["architecture_score"]))
                audit_result.score = sum(audit_result.section_scores.values())
                if audit_result.score >= 90:
                    audit_result.grade = "A"
                elif audit_result.score >= 75:
                    audit_result.grade = "B"
                elif audit_result.score >= 60:
                    audit_result.grade = "C"
                elif audit_result.score >= 40:
                    audit_result.grade = "D"
                else:
                    audit_result.grade = "F"
        except Exception as e:
            logging.error("LLM review failed: %s", e)
            audit_result.llm_review = {"error": str(e), "overall_assessment": "LLM review unavailable."}

        # Save
        audit_id = save_audit(license_key, "", repo_url, audit_result)

        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "audit": audit_result.to_dict(),
                "llm": audit_result.llm_review or {},
                "audit_id": audit_id,
                "tier": tier,
                "license_key": valid_key,
                "issue_count": _issue_count(audit_result.llm_review),
                "fix_eligible": audit_result.total_loc <= FIX_PACK_MAX_LOC,
                "total_loc": audit_result.total_loc,
                "gumroad_report_url": GUMROAD_REPORT_URL,
                "gumroad_fixpack_url": GUMROAD_FIXPACK_URL,
            },
        )

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/report/{audit_id}", response_class=HTMLResponse)
async def view_report(request: Request, audit_id: str):
    audit = get_audit(audit_id)
    if not audit:
        return templates.TemplateResponse("index.html", {"request": request, "error": "Report not found."})

    report = json.loads(audit["report_json"])
    llm = report.get("llm_review") or {}

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "audit": report,
            "llm": llm,
            "audit_id": audit_id,
            "tier": "free",
            "issue_count": _issue_count(llm),
            "fix_eligible": report.get("total_loc", 0) <= FIX_PACK_MAX_LOC,
            "total_loc": report.get("total_loc", 0),
            "gumroad_report_url": GUMROAD_REPORT_URL,
            "gumroad_fixpack_url": GUMROAD_FIXPACK_URL,
        },
    )


@app.post("/unlock/{audit_id}", response_class=HTMLResponse)
async def unlock_report(request: Request, audit_id: str, license_key: str = Form("")):
    """Unlock the full report with a license key."""
    auth = await verify_license(license_key)
    if not auth["success"]:
        audit = get_audit(audit_id)
        if not audit:
            return templates.TemplateResponse("index.html", {"request": request, "error": "Report not found."})
        report = json.loads(audit["report_json"])
        llm = report.get("llm_review") or {}
        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "audit": report,
                "llm": llm,
                "audit_id": audit_id,
                "tier": "free",
                "unlock_error": auth.get("error", "Invalid license key"),
                "issue_count": _issue_count(llm),
                "fix_eligible": report.get("total_loc", 0) <= FIX_PACK_MAX_LOC,
                "total_loc": report.get("total_loc", 0),
                "gumroad_report_url": GUMROAD_REPORT_URL,
                "gumroad_fixpack_url": GUMROAD_FIXPACK_URL,
            },
        )

    audit = get_audit(audit_id)
    if not audit:
        return templates.TemplateResponse("index.html", {"request": request, "error": "Report not found."})

    report = json.loads(audit["report_json"])
    llm = report.get("llm_review") or {}

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "audit": report,
            "llm": llm,
            "audit_id": audit_id,
            "tier": "report",
            "license_key": license_key.strip(),
            "issue_count": _issue_count(llm),
            "fix_eligible": report.get("total_loc", 0) <= FIX_PACK_MAX_LOC,
            "total_loc": report.get("total_loc", 0),
            "gumroad_report_url": GUMROAD_REPORT_URL,
            "gumroad_fixpack_url": GUMROAD_FIXPACK_URL,
        },
    )


@app.get("/vibecheck/{audit_id}")
async def download_vibecheck(request: Request, audit_id: str, key: str = ""):
    """Download VIBECHECK.md — an AI-assistant-ready fix instructions file."""
    auth = await verify_license(key)
    if not auth["success"]:
        return HTMLResponse("Unauthorized — valid Full Report license key required.", status_code=401)

    audit = get_audit(audit_id)
    if not audit:
        return HTMLResponse("Not found", status_code=404)

    report = json.loads(audit["report_json"])
    llm = report.get("llm_review") or {}

    md_content = generate_vibecheck_md(report, llm)
    repo_name = audit.get("repo_name", "project")

    return StreamingResponse(
        io.BytesIO(md_content.encode()),
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=VIBECHECK-{repo_name}.md"},
    )


@app.post("/fixes/{audit_id}", response_class=HTMLResponse)
async def get_fixes(request: Request, audit_id: str, license_key: str = Form("")):
    """Generate and display corrected code files (Fix Pack tier)."""
    auth = await verify_license(license_key)
    if not auth["success"]:
        return templates.TemplateResponse(
            "fixes.html",
            {"request": request, "error": auth.get("error", "Invalid license key"), "audit_id": audit_id},
        )

    audit = get_audit(audit_id)
    if not audit:
        return templates.TemplateResponse(
            "fixes.html",
            {"request": request, "error": "Audit report not found.", "audit_id": audit_id},
        )

    report = json.loads(audit["report_json"])
    llm_review = report.get("llm_review") or {}
    source_files = json.loads(audit.get("source_files") or "{}")

    if not source_files:
        return templates.TemplateResponse(
            "fixes.html",
            {"request": request, "error": "Source files not available for this audit.", "audit_id": audit_id},
        )

    # Check LOC limit
    total_loc = report.get("total_loc", 0)
    if total_loc > FIX_PACK_MAX_LOC:
        return templates.TemplateResponse(
            "fixes.html",
            {
                "request": request,
                "error": f"This repo has {total_loc:,} lines of code, which exceeds the {FIX_PACK_MAX_LOC:,} LOC limit for automated fixes. Contact us for enterprise audits.",
                "audit_id": audit_id,
            },
        )

    if not llm_review or llm_review.get("error"):
        return templates.TemplateResponse(
            "fixes.html",
            {"request": request, "error": "No review data available to generate fixes.", "audit_id": audit_id},
        )

    # Generate fixes
    fix_result = await asyncio.to_thread(generate_fixes, source_files, llm_review, report)

    if fix_result.get("error"):
        return templates.TemplateResponse(
            "fixes.html",
            {"request": request, "error": fix_result["error"], "audit_id": audit_id},
        )

    return templates.TemplateResponse(
        "fixes.html",
        {
            "request": request,
            "audit_id": audit_id,
            "repo_name": audit.get("repo_name", ""),
            "fixes": fix_result.get("fixes", []),
            "fix_count": len(fix_result.get("fixes", [])),
        },
    )


@app.get("/download/{audit_id}")
async def download_fixes(request: Request, audit_id: str, key: str = ""):
    """Download corrected files as a zip."""
    auth = await verify_license(key)
    if not auth["success"]:
        return HTMLResponse("Unauthorized", status_code=401)

    audit = get_audit(audit_id)
    if not audit:
        return HTMLResponse("Not found", status_code=404)

    report = json.loads(audit["report_json"])
    llm_review = report.get("llm_review") or {}
    source_files = json.loads(audit.get("source_files") or "{}")

    if not source_files or not llm_review:
        return HTMLResponse("No data available", status_code=400)

    fix_result = await asyncio.to_thread(generate_fixes, source_files, llm_review, report)

    if fix_result.get("error") or not fix_result.get("fixes"):
        return HTMLResponse("Fix generation failed", status_code=500)

    buf = io.BytesIO()
    repo_name = audit.get("repo_name", "fixes")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fix in fix_result["fixes"]:
            filepath = fix.get("file", "unknown")
            corrected = fix.get("corrected_code", "")
            if corrected:
                zf.writestr(f"{repo_name}-fixes/{filepath}", corrected)
            if fix.get("diff"):
                zf.writestr(f"{repo_name}-fixes/{filepath}.diff", fix["diff"])

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={repo_name}-fixes.zip"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8888")),
        reload=os.getenv("DEV_MODE", "").lower() == "true",
    )
