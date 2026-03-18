import os
import json
import difflib
import logging
from openai import OpenAI

log = logging.getLogger(__name__)

FIX_PROMPT = """You are a senior software engineer. You've just completed a code audit and found issues.
Now generate the CORRECTED versions of the files listed below.

## Issues Found
{issues_summary}

## Original Source Files
{file_contents}

---

For each file that needs changes, return a JSON object with this exact structure:
{{
  "fixes": [
    {{
      "file": "path/to/file.py",
      "description": "What was fixed and why (1-2 sentences)",
      "severity": "critical|high|medium|low",
      "corrected_code": "the entire corrected file content"
    }}
  ]
}}

Rules:
- Only include files that actually need changes — don't return files that are fine
- The corrected_code must be the COMPLETE file content — but if the file is over 200 lines, include only the first 20 lines, then "# ... unchanged ...", then the changed section with 5 lines of context above and below, then "# ... unchanged ..." and the last 10 lines. This keeps output manageable.
- Preserve the original style, indentation, and structure
- Only fix actual issues — don't refactor or "improve" things that aren't broken
- If a file has multiple issues, fix them all in one corrected version
- For secrets: replace with environment variable references (os.getenv / process.env)
- For missing validation: add minimal, targeted input validation
- For missing error handling: add try/except or try/catch only where failures would crash
- Limit to the 5 most impactful fixes maximum
- Return ONLY valid JSON, no markdown fences"""


def generate_fixes(source_files: dict, llm_review: dict, audit_data: dict) -> dict:
    """Generate corrected code files based on the audit review."""
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        return {"error": "No API key configured"}

    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key)
    model = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4.5")

    # Build issues summary from the LLM review
    issues = []
    for item in llm_review.get("security_concerns", []):
        issues.append(f"[SECURITY/{item.get('severity','medium')}] {item.get('issue','')} — Fix: {item.get('fix','')}")
    for item in llm_review.get("code_smells", []):
        issues.append(f"[CODE SMELL/{item.get('severity','medium')}] {item.get('file','')}: {item.get('issue','')}")
    for item in llm_review.get("priority_fixes", []):
        issues.append(f"[FIX/{item.get('severity','medium')}] {item.get('title','')}: {item.get('description','')}")
    for item in llm_review.get("architecture_concerns", []):
        issues.append(f"[ARCHITECTURE] {item}")

    if not issues:
        return {"fixes": [], "message": "No issues to fix — your code is clean!"}

    issues_summary = "\n".join(f"- {i}" for i in issues)

    # Build file contents (limit to files mentioned in issues + key files)
    mentioned_files = set()
    for item in llm_review.get("code_smells", []):
        f = item.get("file", "")
        if f:
            mentioned_files.add(f)

    # Include mentioned files + entry points
    files_to_send = {}
    total_chars = 0
    MAX_TOTAL = 60000

    # Priority: files mentioned in issues
    for path, content in source_files.items():
        if total_chars >= MAX_TOTAL:
            break
        if any(path.endswith(m) or m in path for m in mentioned_files):
            files_to_send[path] = content
            total_chars += len(content)

    # Fill with remaining key files
    for path, content in source_files.items():
        if total_chars >= MAX_TOTAL:
            break
        if path not in files_to_send:
            files_to_send[path] = content
            total_chars += len(content)

    file_sections = []
    for path, content in files_to_send.items():
        file_sections.append(f"--- {path} ---\n{content}")
    file_contents = "\n\n".join(file_sections)

    prompt = FIX_PROMPT.format(
        issues_summary=issues_summary,
        file_contents=file_contents,
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=16000,
        )

        text = response.choices[0].message.content.strip()

        # Extract JSON
        if text.startswith("```"):
            lines = text.split("\n")
            start = 1
            end = len(lines)
            for i in range(len(lines) - 1, 0, -1):
                if lines[i].strip() == "```":
                    end = i
                    break
            text = "\n".join(lines[start:end])
            if text.startswith("json"):
                text = text[4:].strip()

        result = json.loads(text)

        # Generate diffs
        for fix in result.get("fixes", []):
            filepath = fix.get("file", "")
            corrected = fix.get("corrected_code", "")
            original = source_files.get(filepath, "")

            if original and corrected:
                diff = difflib.unified_diff(
                    original.splitlines(keepends=True),
                    corrected.splitlines(keepends=True),
                    fromfile=f"a/{filepath}",
                    tofile=f"b/{filepath}",
                    lineterm="",
                )
                fix["diff"] = "\n".join(diff)
                fix["original_lines"] = len(original.splitlines())
                fix["corrected_lines"] = len(corrected.splitlines())
            else:
                fix["diff"] = ""

        return result

    except json.JSONDecodeError as e:
        log.error("Fix generator returned invalid JSON: %s", e)
        return {"error": f"Failed to parse fix response: {e}"}
    except Exception as e:
        log.error("Fix generation failed: %s", e)
        return {"error": str(e)}


def generate_preview_fix(source_files: dict, llm_review: dict) -> dict:
    """Generate a single fix preview (free teaser)."""
    # Pick the highest-severity fix that references a specific file
    best_fix = None
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for smell in llm_review.get("code_smells", []):
        if smell.get("file") and smell["file"] in source_files:
            if best_fix is None or severity_order.get(smell.get("severity", "low"), 3) < severity_order.get(best_fix.get("severity", "low"), 3):
                best_fix = smell

    if not best_fix:
        # Fall back to first priority fix
        fixes = llm_review.get("priority_fixes", [])
        if fixes:
            return {
                "title": fixes[0].get("title", ""),
                "description": fixes[0].get("description", ""),
                "severity": fixes[0].get("severity", "medium"),
                "preview_only": True,
            }
        return None

    # Generate a quick fix for just this one file
    filepath = best_fix["file"]
    original = source_files.get(filepath, "")
    if not original:
        return {
            "title": best_fix.get("issue", ""),
            "severity": best_fix.get("severity", "medium"),
            "file": filepath,
            "preview_only": True,
        }

    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        return None

    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key)
    model = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4.5")

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{
                "role": "user",
                "content": f"""Fix this one issue in the file below and return ONLY the corrected file content. No explanation, no markdown fences, just the code.

Issue: {best_fix.get('issue', '')}
Severity: {best_fix.get('severity', 'medium')}

--- {filepath} ---
{original[:6000]}"""
            }],
            temperature=0.2,
            max_tokens=4000,
        )

        corrected = response.choices[0].message.content.strip()
        # Strip markdown fences if present
        if corrected.startswith("```"):
            lines = corrected.split("\n")
            corrected = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        diff_lines = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            corrected.splitlines(keepends=True),
            fromfile=f"a/{filepath}",
            tofile=f"b/{filepath}",
            lineterm="",
        ))

        return {
            "file": filepath,
            "issue": best_fix.get("issue", ""),
            "severity": best_fix.get("severity", "medium"),
            "diff": "\n".join(diff_lines),
            "preview_only": True,
        }

    except Exception as e:
        log.error("Preview fix generation failed: %s", e)
        return None
