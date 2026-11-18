# Snippet Scanner

[![CI](https://github.com/shankumar7/Snippet-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/shankumar7/Snippet-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-2021-red)

**Snippet Scanner** is a small web app that checks code snippets, dependency manifests and live web pages
against the [OWASP Top 10 (2021)](https://owasp.org/Top10/). Paste code (or a URL), press **Scan**, and get a list of
findings, each with a severity, the matching line, an explanation of the risk and a suggested fix.

🌐 **Live demo:** <https://snippet-scanner.pages.dev>

> **What it is, honestly:** a fast, transparent, *pattern-based* scanner (regular expressions plus HTML parsing).
> It is great for quick feedback while you code and for learning what risky code looks like. It is **not** a
> full static-analysis (SAST) engine: it does no data-flow analysis, so it will produce some false positives and
> false negatives. Treat it as a first pass, not a security audit.

---

## Table of contents

1. [Features](#features)
2. [Quick start](#quick-start)
3. [How it works](#how-it-works)
4. [Project structure](#project-structure)
5. [API reference](#api-reference)
6. [Configuration](#configuration)
7. [What gets detected](#what-gets-detected)
8. [Security design of the scanner itself](#security-design-of-the-scanner-itself)
9. [Adding a rule](#adding-a-rule)
10. [Testing](#testing)
11. [Deployment](#deployment)
12. [Limitations](#limitations)
13. [Team & license](#team--license)

---

## Features

- **Scan a code snippet** in PHP, JavaScript, Python, Java, C#, HTML and more.
- **Scan a URL**: the server downloads the page (safely, see [security design](#security-design-of-the-scanner-itself)) and scans its HTML and inline scripts.
- **Scan dependency manifests**: paste `requirements.txt`, `package.json` or `pom.xml` to find known-vulnerable versions.
- **All ten OWASP categories (A01–A10)** are covered by 40+ rules.
- **Actionable results**: severity, OWASP category, line number, the offending line, risk explanation and fix advice, sorted most severe first.
- **One command to run**: the Flask app serves both the API and the web UI.
- **Tested**: 98 automated tests covering rules, API behaviour and the SSRF-safe fetcher, run in CI on Python 3.10–3.13.

## Quick start

Requirements: **Python 3.10+** (Node.js is only needed if you want to rebuild the stylesheet).

```bash
git clone https://github.com/shankumar7/Snippet-scanner.git
cd Snippet-scanner
```

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

```bash
pip install -r requirements.txt
```

```bash
python app.py
```

Open <http://127.0.0.1:5050>. That's it: the backend serves the UI too.

Quick API check from another terminal:

```bash
curl -s -X POST http://127.0.0.1:5050/scan \
  -H 'Content-Type: application/json' \
  -d '{"code_snippet": "password = \"hunter2hunter2\"\nos.system(\"ping \" + host)"}'
```

> **URL scanning on localhost:** by design the scanner refuses to fetch private/loopback addresses, so you
> can't scan `http://localhost:8000` out of the box. For local development only, start the server with
> `ALLOW_PRIVATE_URLS=true python app.py`.

## How it works

```
 Browser (index.html)
        │  POST /scan  {"code_snippet": "..."}  or  {"url": "https://..."}
        ▼
 ┌─────────────────────────── Flask app (snippet_scanner/api.py) ───────────────────────────┐
 │  validate JSON ──► url?  ──► fetcher.fetch_url()  (SSRF-safe download, size/time limits) │
 │                      │                                                                    │
 │                      ▼                                                                    │
 │            scanner.scan_content(text)                                                     │
 │              1. line rules        every rule's regexes run on every line                  │
 │              2. multi-line rules  regexes run on the whole document                       │
 │              3. HTML checks       parse <script>/<link>: outdated libs, HTTP, missing SRI │
 │              4. manifest checks   requirements.txt / package.json / pom.xml versions      │
 │              5. file-level checks e.g. sensitive operations with no logging at all        │
 │              6. de-duplicate, sort by severity then line number                           │
 └──────────────────────────────────────────┬───────────────────────────────────────────────┘
                                            ▼
              JSON: { status, summary, counts, vulnerabilities: [ {rule_id, issue, severity,
                      description, suggestion, owasp_category, line_number, snippet}, ... ] }
                                            ▼
              Browser renders summary cards + one card per finding (all values HTML-escaped)
```

### The design in one paragraph

Detection logic is **data, not code**. Each check is a `Rule` (in `snippet_scanner/rules.py`): an id, an OWASP
category, one or more regular expressions, and the text shown to the user. The engine
(`snippet_scanner/scanner.py`) is generic: it loops over lines, applies the rules, and post-processes the results.
Checks that need real parsing (HTML tags, version comparison) are small functions in the engine. The URL fetcher
is isolated in its own module because it is the one part that touches the network. The Flask layer
(`snippet_scanner/api.py`) is thin: validate input, call the scanner, shape the JSON.

### Severity model

Every OWASP category has a default severity (A01/A02/A03/A07/A08/A10 → *High*, A04/A05/A06 → *Medium*,
A09 → *Low*). A rule can override it where the real-world impact differs; for example "plain-HTTP URL" and
"potential IDOR" are *Medium* even though their categories default to *High*.

### Precision over recall

Rules deliberately look for specific risky constructs rather than keywords. For example, SQL injection requires a
SQL statement **and** string concatenation/interpolation; `json.loads`, `confirmPassword`, `obj.old` or an
`xmlns="http://www.w3.org/..."` namespace are *not* flagged. Each rule reports at most 25 findings so one noisy
pattern can't bury everything else.

## Project structure

```
Snippet-scanner/
├── app.py                    # Entry point: `python app.py` (dev) / `gunicorn app:app` (prod)
├── snippet_scanner/          # The backend package
│   ├── api.py                #   Flask app factory, routes (/scan, /rules, /health), error handling
│   ├── scanner.py            #   Scan engine + HTML / dependency / logging checks
│   ├── rules.py              #   Declarative OWASP rule catalogue (add new checks here)
│   ├── models.py             #   Rule / Finding dataclasses, OWASP categories & severities
│   └── fetcher.py            #   SSRF-safe URL downloader
├── index.html                # Single-page UI (vanilla JS), served at `/` and by static hosts
├── tailwind.css              # Precompiled stylesheet (generated, committed)
├── tailwind.input.css        # Tailwind entry file used to build tailwind.css
├── tests/                    # pytest suite: rules, API, fetcher
├── .github/workflows/ci.yml  # Runs the tests on Python 3.10–3.13
├── render.yaml               # Render.com deployment blueprint
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # + pytest
├── package.json              # Only used to rebuild the CSS (`npm run build:css`)
├── tailwind.config.js
└── LICENSE                   # MIT
```

## API reference

### `POST /scan`

Request body (JSON): provide **one** of

| Field          | Type   | Description                                                      |
| -------------- | ------ | ---------------------------------------------------------------- |
| `code_snippet` | string | Source code or manifest text to scan (max 1,000,000 characters). |
| `url`          | string | A public `http://` / `https://` page to download and scan.       |

Successful response (`200`):

```json
{
  "status": "success",
  "summary": "2 potential vulnerability(s) detected.",
  "counts": { "total": 2, "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0 },
  "vulnerabilities": [
    {
      "rule_id": "A02-HARDCODED-SECRET",
      "issue": "Hardcoded secret or credential",
      "severity": "High",
      "description": "A password, API key, token or similar secret is assigned a literal value in source. ...",
      "suggestion": "Load secrets from environment variables or a secrets manager, ...",
      "owasp_category": "A02:2021 - Cryptographic Failures",
      "line_number": 1,
      "snippet": "password = \"hunter2hunter2\""
    }
  ]
}
```

Errors always have the shape `{"status": "error", "message": "...", "vulnerabilities": []}`:

| Status | Meaning                                                                                  |
| ------ | ---------------------------------------------------------------------------------------- |
| `400`  | Malformed JSON, missing/empty input, or a URL that is not allowed (bad scheme, private address, …) |
| `413`  | Request body or snippet too large                                                        |
| `502`  | The remote URL could not be fetched (DNS failure, timeout, HTTP error, too large, …)     |
| `500`  | Unexpected server error (details are logged server-side, never returned)                 |

### `GET /rules`

Lists every check (`id`, `title`, `severity`, `owasp_category`).

### `GET /health`

Returns `{"status": "ok", "version": "..."}`; used as the deployment health check.

## Configuration

All settings are optional environment variables.

| Variable             | Default     | Purpose                                                                              |
| -------------------- | ----------- | ------------------------------------------------------------------------------------ |
| `PORT`               | `5050`      | Port for `python app.py` (gunicorn/Render set their own).                            |
| `HOST`               | `127.0.0.1` | Bind address for `python app.py`.                                                    |
| `CORS_ORIGINS`       | `*`         | Comma-separated list of origins allowed to call the API from a browser.              |
| `ALLOW_PRIVATE_URLS` | `false`     | Allow URL scans of private/loopback addresses. **Local development only.**           |
| `SERVE_FRONTEND`     | `true`      | Serve `index.html` at `/`. Set `false` for an API-only deployment.                    |

**Pointing the frontend at a different backend.** The page picks its API automatically (same origin when served by
Flask, `http://127.0.0.1:5050` when opened from a file, the hosted API otherwise). To override, define
`window.SNIPPET_SCANNER_API = "https://your-api.example.com"` in a script tag before the main script in `index.html`.

## What gets detected

| OWASP 2021 category                          | Examples of what the rules look for                                                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **A01** Broken Access Control                | Roles stored in `localStorage`/cookies, UI-only role checks, sequential IDs (IDOR), open redirects                                   |
| **A02** Cryptographic Failures               | Hardcoded secrets & private keys, AWS/GitHub/Stripe key formats, MD5/SHA-1, DES/RC4/ECB, disabled TLS verification, `http://` URLs   |
| **A03** Injection                            | SQL built with concatenation / f-strings, OS command injection, `eval`, DOM XSS (`innerHTML`, `document.write`), SSTI, PHP file include, format strings |
| **A04** Insecure Design                      | "TODO: add auth/validation" comments, bypass comments, exposed internal/debug API paths                                              |
| **A05** Security Misconfiguration            | Debug mode on, default credentials/secret keys, wildcard CORS / `ALLOWED_HOSTS`, leftover `phpinfo`/stack traces                     |
| **A06** Vulnerable & Outdated Components     | Old jQuery/Bootstrap/Lodash/Moment/AngularJS in `<script>` tags; vulnerable pins in `requirements.txt`, `package.json`, `pom.xml`    |
| **A07** Identification & Auth Failures       | Hardcoded weak passwords, short password policy, session cookies without `Secure`/`SameSite`, unverified or `none`-algorithm JWTs     |
| **A08** Software & Data Integrity Failures   | `pickle`/`unserialize`/`yaml.load`/`ObjectInputStream`, scripts over HTTP, third-party scripts without SRI, `curl \| sh`             |
| **A09** Logging & Monitoring Failures        | Swallowed exceptions, secrets written to logs, sensitive operations (login, delete user…) with no logging in the code at all          |
| **A10** SSRF                                 | HTTP client calls fed from request parameters or from a variable named like a URL                                                    |

The full, live list is available at `GET /rules`. The A06 version data is a small, hand-picked subset of
well-known advisories, intended as an illustration, not a replacement for tools such as `pip-audit`, `npm audit`
or Dependabot.

## Security design of the scanner itself

A tool that fetches user-supplied URLs is itself an SSRF target, so `snippet_scanner/fetcher.py` is deliberately strict:

- Only `http`/`https`, only ports 80/443, no `user:pass@` in URLs.
- The hostname is resolved and **every** address must be public. Loopback, private (RFC 1918), link-local
  (including the `169.254.169.254` cloud-metadata address), multicast, reserved and IPv4-mapped-IPv6 addresses are rejected.
- Redirects are followed manually (max 3) and **each hop is re-validated**, so a public site can't bounce the scanner into your network.
- The connection is **pinned to the address that was validated** (TLS still verifies the certificate against the
  original hostname and sends it as SNI), which defeats DNS-rebinding between "check" and "use".
- Responses are capped at 1 MB and the whole fetch at 20 s.

Other protections: request bodies are capped at 2 MB, scanned text at 1,000,000 characters, very long lines
(minified bundles) are truncated before regex matching, every rule has a result cap, server errors never leak
stack traces, and the frontend HTML-escapes everything it renders (findings can echo scanned code).

The API is stateless, stores nothing and has no authentication. If you expose it publicly, put it behind a
rate-limiting proxy (Render, Cloudflare and nginx all offer this).

## Adding a rule

Append a `Rule` to `RULES` in `snippet_scanner/rules.py`:

```python
Rule(
    id="A05-EXAMPLE",
    category="A05",                       # A01 ... A10
    title="Short name shown in the UI",
    description="Why this is risky.",
    suggestion="How to fix it.",
    patterns=_re(r"\bdangerous_call\s*\(", flags=_I),
    severity="Medium",                    # optional; defaults to the category's severity
),
```

Then add one vulnerable and one safe example to `tests/test_scanner.py` (see the `VULNERABLE` / `SAFE` lists) and
run the tests. Rules are matched per line; set `multiline=True` for a pattern that must span lines.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite (98 tests) covers each rule with vulnerable *and* safe samples, the API's success and error paths, and
the fetcher against a real local HTTP/HTTPS server (private-address blocking, redirect re-validation, DNS-rebinding
pinning, TLS hostname verification, size and time limits).

To rebuild the stylesheet after changing the HTML's Tailwind classes:

```bash
npm install
npm run build:css
```

## Deployment

**Backend (Render):** `render.yaml` is a ready-made blueprint. It installs `requirements.txt`, starts
`gunicorn app:app`, and uses `/health` as the health check. Create a new *Blueprint* service from this repository.
Any host that can run `gunicorn app:app --bind 0.0.0.0:$PORT` works the same way.

**Frontend (static hosting):** the UI is just `index.html` + `tailwind.css` at the repository root, so Cloudflare
Pages, GitHub Pages or Netlify can serve the repo as-is (no build command, root as the output directory). It calls
the hosted API by default; see [Configuration](#configuration) to point it elsewhere. You can also skip separate
hosting entirely, since the backend serves the UI at `/`.

## Limitations

- Regex heuristics cannot follow data flow: `eval(x)` is flagged even if `x` is a constant, and a vulnerability
  split across several statements may be missed.
- A06 knows only a small set of libraries and versions.
- URL scans analyse the HTML the server returns; they do not execute JavaScript or crawl other pages.
- The A09 "no logging" check is intentionally coarse (it only looks at whether *any* logging exists in the text).

## Team & license

Built as part of **Hack 4 Mini 2.O 2025**, organized by CMR Technical Campus (CMRCTC), Telangana.

- **Pitta Shankumar**: project lead
- Jessani Radhika
- Rani Vamshika
- Kurva Aishwarya

Released under the [MIT License](LICENSE). Copyright © 2025 Shankumar Pitta.
