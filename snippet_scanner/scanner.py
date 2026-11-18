"""Scan engine: runs line rules, multi-line rules and file-level checks."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

from bs4 import BeautifulSoup

from .models import CATEGORIES, SEVERITY_ORDER, Finding, Rule
from .rules import RULES

# Guard rails so a single request cannot burn unbounded CPU.
MAX_CONTENT_CHARS = 1_000_000
MAX_LINE_CHARS = 4_000  # minified bundles have enormous lines; cap regex input
MAX_FINDINGS_PER_RULE = 25
SNIPPET_CHARS = 140


class ContentTooLargeError(ValueError):
    """Raised when the submitted content exceeds ``MAX_CONTENT_CHARS``."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _snippet(line: str) -> str:
    line = line.strip()
    return line if len(line) <= SNIPPET_CHARS else line[: SNIPPET_CHARS - 1] + "…"


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def _finding_from_rule(rule: Rule, line_number: Optional[int], snippet: Optional[str]) -> Finding:
    return Finding(
        rule_id=rule.id,
        issue=rule.title,
        severity=rule.effective_severity,
        description=rule.description,
        suggestion=rule.suggestion,
        owasp_category=rule.owasp_category,
        line_number=line_number,
        snippet=snippet,
    )


def _make(category: str, rule_id: str, title: str, description: str, suggestion: str,
          line: Optional[int], severity: Optional[str] = None, snippet: Optional[str] = None) -> Finding:
    name, default_sev = CATEGORIES[category]
    return Finding(rule_id, title, severity or default_sev, description, suggestion, name, line, snippet)


# --------------------------------------------------------------------------
# Rule runners
# --------------------------------------------------------------------------
def _run_line_rules(lines: List[str], rules: Iterable[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    counts: Dict[str, int] = {}
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        line = raw[:MAX_LINE_CHARS]
        for rule in rules:
            if counts.get(rule.id, 0) >= MAX_FINDINGS_PER_RULE:
                continue
            if any(p.search(line) for p in rule.patterns):
                counts[rule.id] = counts.get(rule.id, 0) + 1
                findings.append(_finding_from_rule(rule, number, _snippet(raw)))
    return findings


def _run_multiline_rules(content: str, rules: Iterable[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        reported = 0
        for pattern in rule.patterns:
            for match in pattern.finditer(content):
                if reported >= MAX_FINDINGS_PER_RULE:
                    break
                reported += 1
                line_no = _line_of(content, match.start())
                first_line = match.group(0).splitlines()[0] if match.group(0) else ""
                findings.append(_finding_from_rule(rule, line_no, _snippet(first_line)))
    return findings


# --------------------------------------------------------------------------
# A06 - Vulnerable and outdated components
# --------------------------------------------------------------------------
def _parse_version(text: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)[:4])


def _lt(version: str, minimum: str) -> bool:
    a, b = _parse_version(version), _parse_version(minimum)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


# (library, first non-vulnerable version, note). ``None`` means every version
# of that major line is considered end-of-life.
_JS_LIBS = {
    "jquery": ("3.5.0", "XSS in `htmlPrefilter` (CVE-2020-11022/11023)"),
    "bootstrap": ("3.4.1", "XSS in tooltip/popover data attributes (CVE-2019-8331)"),
    "lodash": ("4.17.21", "prototype pollution and command injection (CVE-2020-8203, CVE-2021-23337)"),
    "moment": ("2.29.4", "ReDoS and path traversal (CVE-2022-24785, CVE-2022-31129)"),
    "angular": ("2.0.0", "AngularJS 1.x is end-of-life and has unpatched sandbox escapes"),
    "angularjs": ("2.0.0", "AngularJS 1.x is end-of-life and has unpatched sandbox escapes"),
}

_PY_PACKAGES = {
    "requests": ("2.31.0", "Proxy-Authorization header leak (CVE-2023-32681)"),
    "pyyaml": ("5.4", "arbitrary code execution via full_load (CVE-2020-14343)"),
    "django": ("4.2", "versions before 4.2 are end-of-life and have unpatched CVEs"),
    "flask": ("2.2.5", "session cookie disclosure behind caching proxies (CVE-2023-30861)"),
    "jinja2": ("3.1.3", "XSS via the xmlattr filter (CVE-2024-22195)"),
    "urllib3": ("1.26.18", "request body leak on redirect (CVE-2023-43804)"),
    "pillow": ("10.0.1", "libwebp heap overflow (CVE-2023-4863)"),
    "werkzeug": ("2.3.8", "multipart DoS and debugger issues (CVE-2023-46136)"),
}

_NPM_PACKAGES = {
    "lodash": ("4.17.21", "prototype pollution (CVE-2020-8203)"),
    "minimist": ("1.2.6", "prototype pollution (CVE-2021-44906)"),
    "axios": ("1.6.0", "CSRF token leak (CVE-2023-45857)"),
    "express": ("4.17.3", "vulnerable `qs` dependency (CVE-2022-24999)"),
    "jquery": ("3.5.0", "XSS (CVE-2020-11022)"),
    "moment": ("2.29.4", "ReDoS (CVE-2022-31129)"),
    "node-fetch": ("2.6.7", "credential leak on redirect (CVE-2022-0235)"),
    "jsonwebtoken": ("9.0.0", "signature validation bypasses (CVE-2022-23529)"),
}

_MAVEN_ARTIFACTS = {
    "log4j-core": ("2.17.1", "Log4Shell remote code execution (CVE-2021-44228 and follow-ups)"),
    "snakeyaml": ("2.0", "arbitrary code execution on untrusted YAML (CVE-2022-1471)"),
    "commons-text": ("1.10.0", "Text4Shell remote code execution (CVE-2022-42889)"),
    "jackson-databind": ("2.13.4.2", "deserialization DoS/RCE gadgets (CVE-2022-42003)"),
}


def _outdated(rule_id: str, title: str, name: str, version: str, minimum: str, note: str,
              line: Optional[int], snippet: Optional[str] = None) -> Finding:
    return _make(
        "A06", rule_id, title,
        f"{name} {version} is below {minimum}, which fixes a known issue: {note}.",
        f"Upgrade {name} to {minimum} or newer, and run an SCA tool (npm audit, pip-audit, "
        "OWASP Dependency-Check, Dependabot) in CI.",
        line, snippet=snippet,
    )


def _looks_like_html(content: str) -> bool:
    return bool(re.search(r"<\s*(?:script|link|html|head|body|meta)\b", content, re.IGNORECASE))


def _js_lib_from_url(src: str) -> Optional[Tuple[str, str]]:
    """Extract (library, version) from a script URL, e.g. ``jquery-3.3.1.min.js``
    or ``.../jquery/3.3.1/jquery.min.js`` or ``jquery@3.3.1``."""
    path = src.lower().split("?")[0]
    for lib in sorted(_JS_LIBS, key=len, reverse=True):
        for pattern in (
            rf"{lib}[-.@](\d+(?:\.\d+){{1,3}})",
            rf"/{lib}/(\d+(?:\.\d+){{1,3}})/",
        ):
            m = re.search(pattern, path)
            if m:
                return lib, m.group(1)
    return None


def check_html_components(content: str) -> List[Finding]:
    """A06 (outdated JS includes) and A08 (insecure / unverified third-party scripts)."""
    if not _looks_like_html(content):
        return []
    findings: List[Finding] = []
    soup = BeautifulSoup(content, "html.parser")

    seen_libs = set()
    for tag in soup.find_all(["script", "link"]):
        attr = "src" if tag.name == "script" else "href"
        url = tag.get(attr)
        if not url:
            continue
        if tag.name == "link" and "stylesheet" not in (tag.get("rel") or []):
            continue
        line = getattr(tag, "sourceline", None)
        snippet = _snippet(str(tag)[:200])
        lowered = url.strip().lower()

        if tag.name == "script":
            found = _js_lib_from_url(url)
            if found and found not in seen_libs:
                lib, version = found
                minimum, note = _JS_LIBS[lib]
                if _lt(version, minimum):
                    seen_libs.add(found)
                    findings.append(_outdated(
                        "A06-OUTDATED-JS-LIB", f"Outdated {lib} ({version})", lib, version, minimum, note, line, snippet))

        if lowered.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1)", lowered):
            findings.append(_make(
                "A08", "A08-HTTP-RESOURCE", "Resource loaded over plain HTTP",
                "A script or stylesheet is fetched over HTTP, so it can be modified in transit "
                "(man-in-the-middle) to inject malicious code.",
                "Load every external resource over HTTPS.", line, snippet=snippet))
        elif (lowered.startswith("https://") or lowered.startswith("//")) and not tag.get("integrity"):
            findings.append(_make(
                "A08", "A08-NO-SRI", "Third-party resource without Subresource Integrity",
                "An external script or stylesheet is loaded without an `integrity` hash. If the host is "
                "compromised the file can be swapped for a malicious one without detection.",
                'Add `integrity="sha384-..." crossorigin="anonymous"` (or self-host the file).',
                line, severity="Medium", snippet=snippet))
    return findings


_PY_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*(\d+(?:\.\d+)*)", re.MULTILINE)
_NPM_DEP = re.compile(r"\"([@\w./\-]+)\"\s*:\s*\"[\^~>=<\s]*(\d+(?:\.\d+){0,2})[^\"]*\"")
_MVN_DEP = re.compile(
    r"<artifactId>\s*([\w.\-]+)\s*</artifactId>\s*<version>\s*(\d+(?:\.\d+)*)\s*</version>", re.IGNORECASE)


def check_dependency_manifest(content: str) -> List[Finding]:
    """A06 for pasted ``requirements.txt`` / ``package.json`` / ``pom.xml`` content."""
    findings: List[Finding] = []

    for m in _PY_REQ.finditer(content):
        name, version = m.group(1).lower().replace("_", "-"), m.group(2)
        entry = _PY_PACKAGES.get(name)
        if entry and _lt(version, entry[0]):
            findings.append(_outdated(
                "A06-OUTDATED-PY-PACKAGE", f"Outdated Python package: {name} {version}",
                name, version, entry[0], entry[1], _line_of(content, m.start()), _snippet(m.group(0))))

    if '"dependencies"' in content or '"devDependencies"' in content:
        for m in _NPM_DEP.finditer(content):
            name, version = m.group(1).lower(), m.group(2)
            entry = _NPM_PACKAGES.get(name)
            if entry and _lt(version, entry[0]):
                findings.append(_outdated(
                    "A06-OUTDATED-NPM-PACKAGE", f"Outdated npm package: {name} {version}",
                    name, version, entry[0], entry[1], _line_of(content, m.start()), _snippet(m.group(0))))

    for m in _MVN_DEP.finditer(content):
        name, version = m.group(1).lower(), m.group(2)
        entry = _MAVEN_ARTIFACTS.get(name)
        if entry and _lt(version, entry[0]):
            findings.append(_outdated(
                "A06-OUTDATED-JAVA-LIB", f"Outdated Java library: {name} {version}",
                name, version, entry[0], entry[1], _line_of(content, m.start()), _snippet(m.group(0))))
    return findings


# --------------------------------------------------------------------------
# A09 - missing security logging (file-level)
# --------------------------------------------------------------------------
_SENSITIVE_OP = re.compile(
    r"\b(?:def|function|func|void|public\s+\w+)\s+"
    r"(?:login|log_in|authenticate|register|signup|change_?password|reset_?password|delete_?user|"
    r"update_?user_?role|grant_?permission)\w*\s*\(", re.IGNORECASE)
_LOGGING = re.compile(
    r"\b(?:logger|logging|syslog|audit\w*|error_log|log\.(?:info|warn|warning|error|debug)|"
    r"console\.(?:log|warn|error)|Log\.[diwe]|print|puts|fmt\.Print\w*|System\.out\.print\w*)\b", re.IGNORECASE)


def check_missing_logging(content: str) -> List[Finding]:
    m = _SENSITIVE_OP.search(content)
    if m and not _LOGGING.search(content):
        return [_make(
            "A09", "A09-NO-SECURITY-LOGGING", "No security logging around sensitive operations",
            f"A sensitive operation (`{m.group(0).strip()}`) is defined but the code contains no logging at all. "
            "Without logs, failed logins, privilege changes and abuse go unnoticed.",
            "Log security events (logins and failures, access-control denials, account and role changes) with "
            "enough context, ship them to central monitoring, and alert on anomalies.",
            _line_of(content, m.start()), snippet=_snippet(m.group(0)))]
    return []


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------
# Metadata for the checks implemented as code rather than as a ``Rule``;
# surfaced by the ``/rules`` endpoint so the catalogue is complete.
FILE_CHECKS = [
    {"id": "A06-OUTDATED-JS-LIB", "title": "Outdated JavaScript library in a <script> tag", "severity": "Medium", "owasp_category": CATEGORIES["A06"][0]},
    {"id": "A06-OUTDATED-PY-PACKAGE", "title": "Outdated Python package (requirements.txt)", "severity": "Medium", "owasp_category": CATEGORIES["A06"][0]},
    {"id": "A06-OUTDATED-NPM-PACKAGE", "title": "Outdated npm package (package.json)", "severity": "Medium", "owasp_category": CATEGORIES["A06"][0]},
    {"id": "A06-OUTDATED-JAVA-LIB", "title": "Outdated Java library (pom.xml)", "severity": "Medium", "owasp_category": CATEGORIES["A06"][0]},
    {"id": "A08-HTTP-RESOURCE", "title": "Resource loaded over plain HTTP", "severity": "High", "owasp_category": CATEGORIES["A08"][0]},
    {"id": "A08-NO-SRI", "title": "Third-party resource without Subresource Integrity", "severity": "Medium", "owasp_category": CATEGORIES["A08"][0]},
    {"id": "A09-NO-SECURITY-LOGGING", "title": "No security logging around sensitive operations", "severity": "Low", "owasp_category": CATEGORIES["A09"][0]},
]

_LINE_RULES = tuple(r for r in RULES if not r.multiline)
_MULTILINE_RULES = tuple(r for r in RULES if r.multiline)


def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.line_number, f.issue)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_content(content: str) -> List[dict]:
    """Scan ``content`` and return findings as JSON-serialisable dicts,
    ordered by severity then line number."""
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    if len(content) > MAX_CONTENT_CHARS:
        raise ContentTooLargeError(f"Content exceeds the {MAX_CONTENT_CHARS:,} character limit.")

    findings: List[Finding] = []
    findings += _run_line_rules(content.splitlines(), _LINE_RULES)
    findings += _run_multiline_rules(content, _MULTILINE_RULES)
    findings += check_html_components(content)
    findings += check_dependency_manifest(content)
    findings += check_missing_logging(content)

    ordered = sorted(
        _dedupe(findings),
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line_number or 0, f.rule_id),
    )
    return [f.to_dict() for f in ordered]


def summarize(results: List[dict]) -> Dict[str, int]:
    """Count findings per severity."""
    summary = {"total": len(results), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        key = r["severity"].lower()
        summary[key] = summary.get(key, 0) + 1
    return summary
