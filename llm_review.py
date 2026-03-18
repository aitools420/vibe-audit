import os
import json
import logging
from openai import OpenAI

log = logging.getLogger(__name__)

REVIEW_PROMPT = """You are a senior software engineer conducting a professional code audit for a non-technical founder who built their project using AI coding tools ("vibe coding"). Be honest, specific, and constructive.

## Repository Info
- **Name:** {repo_name}
- **Primary Language:** {primary_language}
- **Total Files:** {total_files} | **Total LOC:** {total_loc}
- **Languages:** {languages}
- **Has Tests:** {has_tests} ({test_file_count} test files)
- **Has CI:** {has_ci} | **Has Linting:** {has_linting}
- **Dependencies:** {dep_count} ({dep_files})
- **Secrets Found:** {secrets_count}

## File Tree
```
{file_tree}
```

## Source Files
{file_contents}

---

Analyze this codebase and return a JSON object with EXACTLY these keys:

{{
  "architecture_summary": "2-3 sentence plain-English overview of how this app is structured",
  "architecture_concerns": ["list of specific architectural problems — reference file names"],
  "code_smells": [
    {{"file": "path/to/file.py", "issue": "what's wrong", "severity": "critical|high|medium|low"}}
  ],
  "security_concerns": [
    {{"issue": "what's dangerous", "severity": "critical|high|medium|low", "fix": "how to fix it in one sentence"}}
  ],
  "priority_fixes": [
    {{"title": "short name", "description": "what to do and why it matters", "effort": "1h|4h|1d|1w", "severity": "critical|high|medium|low", "file": "path/to/file", "fix_snippet": "a short before/after code snippet showing the minimal fix (3-8 lines max, use comments like # Before: and # After: to separate)"}}
  ],
  "positive_notes": ["genuinely good things about this codebase"],
  "overall_assessment": "2 paragraph honest assessment written for someone who doesn't code. Explain what shape their project is in and whether it's ready for production. Be direct.",
  "architecture_score": <integer 0-15>
}}

Rules:
- Reference actual file names and patterns from the code
- Don't pad with generic advice — be specific to THIS repo
- Order priority_fixes by severity (critical first)
- architecture_score: 13-15 = solid, 9-12 = decent, 5-8 = needs work, 0-4 = serious issues
- Return ONLY valid JSON, no markdown fences"""


def get_llm_review(audit_result) -> dict:
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        return {"error": "No API key configured", "overall_assessment": "LLM review unavailable — no API key."}

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    model = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4.5")

    # Build file contents section
    file_sections = []
    for path, content in audit_result.key_file_contents.items():
        file_sections.append(f"--- {path} ---\n{content}")
    file_contents = "\n\n".join(file_sections)

    prompt = REVIEW_PROMPT.format(
        repo_name=audit_result.repo_name,
        primary_language=audit_result.primary_language,
        total_files=audit_result.total_files,
        total_loc=audit_result.total_loc,
        languages=json.dumps(audit_result.languages),
        has_tests=audit_result.has_tests,
        test_file_count=audit_result.test_file_count,
        has_ci=audit_result.has_ci,
        has_linting=audit_result.has_linting,
        dep_count=audit_result.dependency_count,
        dep_files=", ".join(audit_result.dep_files_found) or "none",
        secrets_count=len(audit_result.secrets_found),
        file_tree=audit_result.file_tree,
        file_contents=file_contents,
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=4000,
        )

        text = response.choices[0].message.content.strip()

        # Extract JSON from possible markdown fence
        if text.startswith("```"):
            lines = text.split("\n")
            start = 1 if lines[0].startswith("```") else 0
            end = len(lines)
            for i in range(len(lines) - 1, 0, -1):
                if lines[i].strip() == "```":
                    end = i
                    break
            text = "\n".join(lines[start:end])
            if text.startswith("json"):
                text = text[4:].strip()

        return json.loads(text)

    except json.JSONDecodeError as e:
        log.error("LLM returned invalid JSON: %s", e)
        return {
            "error": f"Failed to parse LLM response: {e}",
            "overall_assessment": "The AI review ran but returned an unparseable response. The static analysis above is still valid.",
            "architecture_score": 10,
        }
    except Exception as e:
        log.error("LLM review failed: %s", e)
        return {
            "error": str(e),
            "overall_assessment": "LLM review unavailable due to an error. The static analysis above is still valid.",
            "architecture_score": 10,
        }
