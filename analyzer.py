import os
import re
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".java": "Java", ".kt": "Kotlin", ".swift": "Swift", ".cs": "C#",
    ".cpp": "C++", ".c": "C", ".h": "C/C++", ".php": "PHP",
    ".vue": "Vue", ".svelte": "Svelte",
}

CODE_EXTENSIONS = set(LANG_MAP.keys())

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}", "API Key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*[\"']?[^\s\"']{8,}", "Password/Secret"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Stripe Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer Token"),
    (r"xox[bpras]-[a-zA-Z0-9\-]{10,}", "Slack Token"),
]

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".turbo", ".vercel",
}

SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi",
    ".zip", ".tar", ".gz", ".bz2", ".rar",
    ".lock", ".sum",
    ".map", ".min.js", ".min.css",
}


@dataclass
class SecretFinding:
    file: str
    line_num: int
    pattern_type: str
    snippet: str


@dataclass
class AuditResult:
    repo_url: str
    repo_name: str

    # Structure
    total_files: int = 0
    total_loc: int = 0
    languages: dict = field(default_factory=dict)
    primary_language: str = ""
    file_tree: str = ""

    # Security
    secrets_found: list = field(default_factory=list)
    env_committed: bool = False
    gitignore_exists: bool = False
    gitignore_issues: list = field(default_factory=list)

    # Dependencies
    dep_files_found: list = field(default_factory=list)
    dependency_count: int = 0
    dependencies: list = field(default_factory=list)
    pinned_deps: int = 0
    unpinned_deps: int = 0

    # Code Quality
    has_tests: bool = False
    test_file_count: int = 0
    has_readme: bool = False
    has_ci: bool = False
    has_linting: bool = False
    has_dockerfile: bool = False
    has_license: bool = False
    avg_file_loc: float = 0
    largest_files: list = field(default_factory=list)

    # Key files for LLM review
    key_file_contents: dict = field(default_factory=dict)

    # LLM Review (filled later)
    llm_review: Optional[dict] = None

    # Score
    score: int = 0
    grade: str = ""
    section_scores: dict = field(default_factory=dict)

    def to_dict(self):
        d = {}
        for k, v in self.__dict__.items():
            if k == "key_file_contents":
                continue
            if isinstance(v, list) and v and hasattr(v[0], "__dict__"):
                d[k] = [vars(x) for x in v]
            else:
                d[k] = v
        return d


def clone_repo(repo_url: str, tmp_dir: str) -> str:
    url = repo_url.strip().rstrip("/")
    if not url.startswith("http"):
        url = f"https://github.com/{url}"
    if not url.endswith(".git"):
        url = url + ".git"

    repo_name = url.split("/")[-1].replace(".git", "")
    clone_path = os.path.join(tmp_dir, repo_name)

    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", url, clone_path],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        msg = result.stderr.strip()
        if "not found" in msg.lower() or "404" in msg:
            raise ValueError("Repository not found. Check the URL and make sure it's public.")
        raise ValueError(f"Failed to clone repository: {msg[:200]}")

    return clone_path


def analyze_repo(repo_path: str, repo_url: str) -> AuditResult:
    result = AuditResult(repo_url=repo_url, repo_name=os.path.basename(repo_path))
    repo_root = Path(repo_path)

    all_files = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            fpath = Path(root) / f
            ext = fpath.suffix.lower()
            if ext in SKIP_EXTENSIONS:
                continue
            rel = str(fpath.relative_to(repo_root))
            all_files.append((rel, fpath, ext))

    result.total_files = len(all_files)

    # Language breakdown
    lang_counter = Counter()
    file_locs = []

    for rel, fpath, ext in all_files:
        lang = LANG_MAP.get(ext)
        if lang:
            lang_counter[lang] += 1
        try:
            content = fpath.read_text(errors="ignore")
            loc = len(content.splitlines())
            result.total_loc += loc
            if ext in CODE_EXTENSIONS:
                file_locs.append((rel, loc))
        except Exception:
            continue

    result.languages = dict(lang_counter.most_common(10))
    if lang_counter:
        result.primary_language = lang_counter.most_common(1)[0][0]

    if file_locs:
        result.avg_file_loc = round(sum(loc for _, loc in file_locs) / len(file_locs), 1)
        result.largest_files = [(f, loc) for f, loc in sorted(file_locs, key=lambda x: -x[1])[:10]]

    # File tree
    tree_lines = []
    _build_tree(repo_root, repo_root, tree_lines, max_depth=3, current_depth=0)
    result.file_tree = "\n".join(tree_lines[:100])

    # Scans
    _scan_secrets(repo_root, all_files, result)
    _check_project_files(repo_root, result)
    _parse_dependencies(repo_root, result)
    _collect_key_files(repo_root, all_files, result)
    _calculate_score(result)

    return result


def _build_tree(root, current, lines, max_depth, current_depth, prefix=""):
    if current_depth > max_depth:
        return
    try:
        entries = sorted(current.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
    except PermissionError:
        return

    visible = [
        e for e in entries
        if (e.is_dir() and e.name not in SKIP_DIRS and not e.name.startswith("."))
        or (e.is_file() and e.suffix.lower() not in SKIP_EXTENSIONS)
    ]

    for i, entry in enumerate(visible):
        if len(lines) >= 100:
            return
        is_last = i == len(visible) - 1
        connector = "└── " if is_last else "├── "
        if entry.is_dir():
            lines.append(f"{prefix}{connector}{entry.name}/")
            ext_prefix = "    " if is_last else "│   "
            _build_tree(root, entry, lines, max_depth, current_depth + 1, prefix + ext_prefix)
        else:
            lines.append(f"{prefix}{connector}{entry.name}")


def _scan_secrets(repo_root, all_files, result):
    result.env_committed = (repo_root / ".env").exists()

    gitignore = repo_root / ".gitignore"
    result.gitignore_exists = gitignore.exists()
    if result.gitignore_exists:
        gi = gitignore.read_text(errors="ignore")
        if ".env" not in gi:
            result.gitignore_issues.append(".env not in .gitignore")
        if "node_modules" not in gi and (repo_root / "package.json").exists():
            result.gitignore_issues.append("node_modules not in .gitignore")

    scan_exts = SKIP_EXTENSIONS | {".svg", ".lock", ".sum", ".map"}
    for rel, fpath, ext in all_files:
        if ext in scan_exts:
            continue
        try:
            content = fpath.read_text(errors="ignore")
            for line_num, line in enumerate(content.splitlines(), 1):
                if len(line) > 1000:
                    continue
                for pattern, ptype in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        snippet = line.strip()[:80]
                        snippet = re.sub(r"[a-zA-Z0-9_\-]{12,}", "***REDACTED***", snippet)
                        result.secrets_found.append(
                            SecretFinding(file=rel, line_num=line_num, pattern_type=ptype, snippet=snippet)
                        )
                        break
        except Exception:
            continue


def _check_project_files(repo_root, result):
    # Tests
    test_dirs = ["test", "tests", "spec", "specs", "__tests__"]
    for d in test_dirs:
        td = repo_root / d
        if td.is_dir():
            result.has_tests = True
            result.test_file_count = sum(1 for _ in td.rglob("*") if _.is_file())
            break

    if not result.has_tests:
        patterns = ["test_*.py", "*_test.py", "*.test.js", "*.test.ts", "*.test.tsx", "*.spec.js", "*.spec.ts"]
        test_files = []
        for p in patterns:
            test_files.extend(repo_root.rglob(p))
        if test_files:
            result.has_tests = True
            result.test_file_count = len(test_files)

    result.has_readme = any((repo_root / f).exists() for f in ["README.md", "README.rst", "README.txt", "README"])
    result.has_ci = any([
        (repo_root / ".github" / "workflows").is_dir(),
        (repo_root / ".gitlab-ci.yml").exists(),
        (repo_root / ".circleci").is_dir(),
        (repo_root / "Jenkinsfile").exists(),
        (repo_root / ".travis.yml").exists(),
    ])
    result.has_linting = any([
        (repo_root / f).exists()
        for f in [
            ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml", "eslint.config.js", "eslint.config.mjs",
            ".flake8", ".pylintrc", "ruff.toml",
            ".prettierrc", ".prettierrc.json", "biome.json",
        ]
    ])
    # Also check pyproject.toml for ruff/black/flake8 config
    if not result.has_linting:
        pyproject = repo_root / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text(errors="ignore")
            if any(tool in content for tool in ["[tool.ruff]", "[tool.black]", "[tool.flake8]", "[tool.pylint]"]):
                result.has_linting = True

    result.has_dockerfile = (repo_root / "Dockerfile").exists() or (repo_root / "docker-compose.yml").exists() or (repo_root / "docker-compose.yaml").exists()
    result.has_license = any((repo_root / f).exists() for f in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"])


def _parse_dependencies(repo_root, result):
    # Python
    for req_name in ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]:
        req_file = repo_root / req_name
        if req_file.exists():
            result.dep_files_found.append(req_name)
            for line in req_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    result.dependencies.append(line.split("#")[0].strip())
                    if "==" in line:
                        result.pinned_deps += 1
                    else:
                        result.unpinned_deps += 1

    if (repo_root / "pyproject.toml").exists():
        result.dep_files_found.append("pyproject.toml")

    # Node
    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        result.dep_files_found.append("package.json")
        try:
            pkg = json.loads(pkg_json.read_text(errors="ignore"))
            for section in ["dependencies", "devDependencies"]:
                for name, ver in pkg.get(section, {}).items():
                    result.dependencies.append(f"{name}@{ver}")
                    if ver.startswith("^") or ver.startswith("~") or ver == "*":
                        result.unpinned_deps += 1
                    else:
                        result.pinned_deps += 1
        except Exception:
            pass

    # Go / Rust
    for dep_file in ["go.mod", "Cargo.toml", "Gemfile", "build.gradle", "pom.xml"]:
        if (repo_root / dep_file).exists():
            result.dep_files_found.append(dep_file)

    result.dependency_count = len(result.dependencies)


def _collect_key_files(repo_root, all_files, result):
    MAX_FILE_SIZE = 8000
    MAX_TOTAL = 50000

    priority_names = [
        "main.py", "app.py", "index.py", "server.py", "manage.py", "wsgi.py", "asgi.py",
        "index.js", "index.ts", "app.js", "app.ts", "server.js", "server.ts",
        "main.go", "main.rs", "lib.rs",
        "package.json", "pyproject.toml", "Cargo.toml",
        "Dockerfile", "docker-compose.yml",
    ]

    collected = {}
    total_chars = 0

    for pname in priority_names:
        if total_chars >= MAX_TOTAL:
            break
        for rel, fpath, ext in all_files:
            if os.path.basename(rel) == pname:
                try:
                    content = fpath.read_text(errors="ignore")[:MAX_FILE_SIZE]
                    collected[rel] = content
                    total_chars += len(content)
                except Exception:
                    pass
                break

    # Fill with largest code files
    sorted_by_size = sorted(
        [(rel, fpath, ext) for rel, fpath, ext in all_files if ext in CODE_EXTENSIONS and rel not in collected],
        key=lambda x: x[1].stat().st_size if x[1].exists() else 0,
        reverse=True,
    )

    for rel, fpath, ext in sorted_by_size[:15]:
        if total_chars >= MAX_TOTAL:
            break
        try:
            content = fpath.read_text(errors="ignore")[:MAX_FILE_SIZE]
            collected[rel] = content
            total_chars += len(content)
        except Exception:
            continue

    result.key_file_contents = collected


def _calculate_score(result):
    scores = {}

    # Security (30 pts)
    sec = 30
    sec -= min(20, len(result.secrets_found) * 5)
    if result.env_committed:
        sec -= 10
    if not result.gitignore_exists:
        sec -= 5
    if result.gitignore_issues:
        sec -= len(result.gitignore_issues) * 2
    scores["security"] = max(0, sec)

    # Dependencies (15 pts)
    dep = 15
    if not result.dep_files_found:
        dep -= 5
    total = max(1, result.dependency_count)
    if result.dependency_count > 0 and result.unpinned_deps / total > 0.5:
        dep -= 5
    if result.dependency_count > 80:
        dep -= 3
    scores["dependencies"] = max(0, dep)

    # Code Quality (25 pts)
    cq = 25
    if not result.has_tests:
        cq -= 10
    if not result.has_readme:
        cq -= 3
    if not result.has_linting:
        cq -= 5
    if not result.has_ci:
        cq -= 4
    if result.avg_file_loc > 500:
        cq -= 3
    scores["code_quality"] = max(0, cq)

    # Structure (15 pts)
    struct = 15
    if result.total_files < 3:
        struct -= 5
    if not result.primary_language:
        struct -= 3
    if not result.has_dockerfile:
        struct -= 2
    if not result.has_license:
        struct -= 2
    scores["structure"] = max(0, struct)

    # Architecture (15 pts) — adjusted by LLM later
    scores["architecture"] = 15

    result.section_scores = scores
    result.score = sum(scores.values())

    if result.score >= 90:
        result.grade = "A"
    elif result.score >= 75:
        result.grade = "B"
    elif result.score >= 60:
        result.grade = "C"
    elif result.score >= 40:
        result.grade = "D"
    else:
        result.grade = "F"
