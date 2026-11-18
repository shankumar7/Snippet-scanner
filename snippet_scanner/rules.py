"""Detection rules, grouped by OWASP Top 10 (2021) category.

Every rule is plain data: a regex (or several) plus the message shown to the
user. Adding a new check means appending a ``Rule`` to ``RULES``; the engine in
``scanner.py`` needs no changes.

These are heuristics, not a full static analyser. They are tuned to prefer
precise patterns (e.g. "SQL keyword + string concatenation") over loose ones
(e.g. "the word `login` appears"), but false positives and negatives remain
possible.
"""

from __future__ import annotations

import re
from typing import List

from .models import Rule

_I = re.IGNORECASE


def _re(*patterns: str, flags: int = 0) -> tuple:
    return tuple(re.compile(p, flags) for p in patterns)


# Sources of attacker-controlled data across common languages / frameworks.
_USER_INPUT = (
    r"(?:request\.(?:args|form|values|json|data|GET|POST|query_params|params|body)"
    r"|req\.(?:query|body|params)"
    r"|\$_(?:GET|POST|REQUEST|COOKIE)"
    r"|getParameter\s*\(|input\s*\(|sys\.argv|window\.location|location\.(?:hash|search))"
)

# Function calls that perform an outbound HTTP request.
_HTTP_CALLS = (
    r"(?:requests\.(?:get|post|put|patch|delete|head|request)"
    r"|urllib\.request\.urlopen|urlopen|httpx\.(?:get|post|request)"
    r"|axios(?:\.(?:get|post|request))?|fetch|http\.get|https\.get"
    r"|curl_init|file_get_contents|fopen|fsockopen"
    r"|WebClient\.DownloadString|HttpClient\.GetAsync|new\s+URL)"
)

RULES: List[Rule] = [
    # ------------------------------------------------------------------ A01
    Rule(
        id="A01-CLIENT-ROLE-STORAGE",
        category="A01",
        title="Role or permission stored client-side",
        description=(
            "Roles or permissions are kept in browser storage or a cookie. "
            "The user controls these values, so any access decision based on "
            "them can be bypassed."
        ),
        suggestion=(
            "Keep roles and permissions in the server-side session or a signed "
            "token, and enforce authorization on the server for every request."
        ),
        patterns=_re(
            r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"]"
            r"(?:role|roles|is_?admin|isAdmin|permissions?|user_?role)['\"]",
            r"document\.cookie\s*=\s*['\"`]\s*(?:role|is_?admin|isAdmin|permissions?)\s*=",
            flags=_I,
        ),
    ),
    Rule(
        id="A01-CLIENT-SIDE-CHECK",
        category="A01",
        title="Access control enforced only in the UI",
        description=(
            "A role check appears to hide or disable UI elements. This is "
            "presentation only: the underlying endpoint or data is still "
            "reachable by anyone who calls it directly."
        ),
        suggestion=(
            "Treat client-side checks as cosmetic. Authorize every sensitive "
            "action and data access on the server."
        ),
        patterns=_re(
            r"\bif\s*\(\s*[\w.]*(?:role|isAdmin|is_admin)[\w.]*\s*(?:===?|!==?)\s*['\"]\w+['\"]\s*\)"
            r"[^}]{0,200}?(?:style\.display\s*=\s*['\"]none['\"]|\.hidden\s*=\s*true"
            r"|\.disabled\s*=\s*true|classList\.(?:add|remove)\s*\(\s*['\"]hidden['\"])",
            flags=_I | re.DOTALL,
        ),
        multiline=True,
    ),
    Rule(
        id="A01-IDOR",
        category="A01",
        title="Potential insecure direct object reference (IDOR)",
        severity="Medium",
        description=(
            "A sequential numeric identifier is used to reference a resource "
            "(e.g. `user_id=123`, `/orders/42`). If the server does not verify "
            "that the caller owns that resource, changing the number exposes "
            "other users' data."
        ),
        suggestion=(
            "Check on the server that the authenticated user may access the "
            "specific resource. Prefer unguessable identifiers (UUIDs) as "
            "defense in depth."
        ),
        patterns=_re(
            r"\b(?:user_?id|account_?id|doc(?:ument)?_?id|file_?id|order_?id|invoice_?id)\s*=\s*['\"]?\d+\b",
            r"/(?:users?|accounts?|orders?|documents?|invoices?)/\d+\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A01-OPEN-REDIRECT",
        category="A01",
        title="Open redirect",
        severity="Medium",
        description=(
            "A redirect target is taken directly from user input. Attackers "
            "can use this to send victims from your trusted domain to a "
            "malicious site."
        ),
        suggestion=(
            "Redirect only to relative paths or to an allow-list of known "
            "hosts; never to a raw user-supplied URL."
        ),
        patterns=_re(
            r"\b(?:redirect|sendRedirect|res\.redirect|header\s*\(\s*['\"]Location:)[^\n]*" + _USER_INPUT,
            flags=_I,
        ),
    ),
    # ------------------------------------------------------------------ A02
    Rule(
        id="A02-HARDCODED-SECRET",
        category="A02",
        title="Hardcoded secret or credential",
        description=(
            "A password, API key, token or similar secret is assigned a "
            "literal value in source. Anyone with access to the code (or its "
            "version history) gets the secret."
        ),
        suggestion=(
            "Load secrets from environment variables or a secrets manager, "
            "rotate anything already committed, and keep secrets out of "
            "version control."
        ),
        patterns=_re(
            r"\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|"
            r"(?:access|auth|bearer|refresh)[_-]?token|token|passwd|password|pwd|"
            r"private[_-]?key|aws[_-]?secret[_-]?access[_-]?key|db[_-]?password)"
            r"['\"]?\s*[:=]\s*['\"][^'\"\s$]{4,}['\"]",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
            r"\bsk_live_[0-9A-Za-z]{16,}\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A02-CLIENT-SECRET-STORAGE",
        category="A02",
        title="Sensitive value kept in browser storage",
        description=(
            "Tokens, passwords or keys are written to `localStorage`, "
            "`sessionStorage` or a script-readable cookie, where any XSS "
            "payload can read them."
        ),
        suggestion=(
            "Store session tokens in `HttpOnly; Secure; SameSite` cookies set "
            "by the server. Never store passwords or long-lived secrets in the "
            "browser."
        ),
        patterns=_re(
            r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"](?:api[_-]?key|secret|token|access_?token|password|auth)['\"]",
            r"document\.cookie\s*=\s*['\"`][^'\"`;]*(?:token|password|secret)\s*=",
            flags=_I,
        ),
    ),
    Rule(
        id="A02-WEAK-HASH",
        category="A02",
        title="Weak hash algorithm (MD5 / SHA-1)",
        description=(
            "MD5 and SHA-1 are broken for security purposes (collisions are "
            "practical, and both are far too fast for password hashing)."
        ),
        suggestion=(
            "Use SHA-256 or stronger for integrity, and a dedicated password "
            "hash such as Argon2id, bcrypt or scrypt for passwords."
        ),
        patterns=_re(
            r"hashlib\.(?:md5|sha1)\b",
            r"createHash\s*\(\s*['\"](?:md5|sha-?1)['\"]",
            r"MessageDigest\.getInstance\s*\(\s*['\"](?:md5|sha-?1)['\"]",
            r"\b(?:md5|sha1)\s*\(",
            r"\bMD5\.Create\s*\(|\bSHA1(?:CryptoServiceProvider|Managed)?\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A02-WEAK-CIPHER",
        category="A02",
        title="Weak or unsafe cipher / mode",
        description=(
            "DES, 3DES, RC4, Blowfish and ECB mode are obsolete or leak "
            "plaintext structure."
        ),
        suggestion=(
            "Use AES-256-GCM or ChaCha20-Poly1305 through a vetted library, "
            "with a unique nonce per message."
        ),
        patterns=_re(
            r"\b(?:RC4|3DES|DESede)\b",
            r"\bDES\b(?!\w)",
            r"\bBlowfish\b",
            r"\bMODE_ECB\b|AES/ECB|/ECB/",
        ),
    ),
    Rule(
        id="A02-TLS-VERIFY-OFF",
        category="A02",
        title="TLS certificate verification disabled",
        description=(
            "Certificate validation is turned off, so the connection can be "
            "intercepted by anyone on the network path."
        ),
        suggestion=(
            "Leave certificate verification on. If you use a private CA, "
            "point the client at the CA bundle instead of disabling checks."
        ),
        patterns=_re(
            r"\bverify\s*=\s*False\b",
            r"rejectUnauthorized\s*:\s*false",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
            r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)",
            r"InsecureSkipVerify\s*:\s*true",
            r"\bcurl\b[^\n|]*\s(?:-k|--insecure)\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A02-PLAIN-HTTP",
        category="A02",
        title="Insecure plain-HTTP URL",
        severity="Medium",
        description=(
            "A URL uses `http://` rather than `https://`, so traffic is sent "
            "unencrypted and can be read or modified in transit."
        ),
        suggestion="Use HTTPS for every external endpoint.",
        patterns=_re(
            r"\bhttp://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|"
            r"schemas\.|java\.sun\.com|xmlns|example\.(?:com|org|net)|\$\{|\{)[\w.-]+",
            flags=_I,
        ),
    ),
    # ------------------------------------------------------------------ A03
    Rule(
        id="A03-SQL-INJECTION",
        category="A03",
        title="Possible SQL injection (string-built query)",
        description=(
            "A SQL statement is built by concatenating or interpolating "
            "variables into the query string. If any value is user-controlled "
            "an attacker can change the query."
        ),
        suggestion=(
            "Use parameterized queries / prepared statements (e.g. "
            "`cursor.execute(sql, params)`) or an ORM. Never splice input "
            "into SQL text."
        ),
        patterns=_re(
            # "SELECT ..." + var   |  "..." % var  |  "...".format(  |  ${var}
            r"['\"`]\s*(?:SELECT\b[^'\"`]*\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^'\"`]*"
            r"(?:['\"`]\s*(?:\+|%\s*[\w(])|['\"`]\s*\.\s*\$|\$\{|['\"`]\s*\.format\s*\()",
            # concatenation that *starts* with a variable-bearing literal end:  "... WHERE id=" + id
            r"\b(?:SELECT\b.+\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^\n]*['\"]\s*\+\s*[\w(]",
            # f-strings / interpolated SQL
            r"\bf['\"]\s*(?:SELECT\b.*?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^\n]*\{\w",
            r"\b(?:mysql_query|mysqli_query|pg_query)\s*\([^)\n]*\$\w+",
            flags=_I,
        ),
    ),
    Rule(
        id="A03-COMMAND-INJECTION",
        category="A03",
        title="Possible OS command injection",
        description=(
            "A shell command is built from variables, or run through a shell. "
            "User-controlled input could append extra commands."
        ),
        suggestion=(
            "Avoid the shell. Pass arguments as a list (e.g. "
            "`subprocess.run([...], shell=False)`), validate input against an "
            "allow-list, and prefer library APIs over shelling out."
        ),
        patterns=_re(
            r"\b(?:os\.system|os\.popen|commands\.getoutput|shell_exec|passthru|popen|proc_open"
            r"|child_process\.exec(?:Sync)?|Runtime\.getRuntime\(\)\.exec)\s*\([^)\n]*"
            r"(?:\+|\$\w+|\$\{|%\s*[\w(]|\.format\s*\(|\bf['\"])",
            r"\b(?:system|exec)\s*\([^)\n]*(?:\$_(?:GET|POST|REQUEST)|\$\w+)",
            r"\bsubprocess\.\w+\s*\([^)\n]*shell\s*=\s*True",
            flags=_I,
        ),
    ),
    Rule(
        id="A03-CODE-EVAL",
        category="A03",
        title="Dynamic code evaluation",
        description=(
            "`eval`, `new Function` or string-based timers execute text as "
            "code. If any part of that text is influenced by a user, it is "
            "code injection."
        ),
        suggestion=(
            "Remove dynamic evaluation. Parse data with `JSON.parse` / "
            "`ast.literal_eval`, and pass real functions to timers."
        ),
        patterns=_re(
            r"(?<![\w.])eval\s*\(\s*(?!['\"]\s*\))\S",
            r"\bnew\s+Function\s*\(",
            r"\b(?:setTimeout|setInterval)\s*\(\s*['\"`]",
        ),
    ),
    Rule(
        id="A03-DOM-XSS",
        category="A03",
        title="Possible DOM-based cross-site scripting (XSS)",
        description=(
            "Non-constant data is written into the page as HTML "
            "(`innerHTML`, `document.write`, `insertAdjacentHTML`, jQuery "
            "`.html()`). Unsanitized user data here becomes executable script."
        ),
        suggestion=(
            "Use `textContent`/`innerText` for text. If HTML is required, "
            "sanitize it (e.g. DOMPurify) and deploy a strict "
            "Content-Security-Policy."
        ),
        patterns=_re(
            r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?!(?:'[^'+]*'|\"[^\"+]*\")\s*;?\s*$)\S",
            r"\bdocument\.write(?:ln)?\s*\(\s*(?!['\"][^'\"+]*['\"]\s*\))",
            r"\binsertAdjacentHTML\s*\(",
            r"\bdangerouslySetInnerHTML\b",
            r"\$\([^)]*\)\.(?:html|append|prepend)\s*\(\s*(?!['\"][^'\"+]*['\"]\s*\))[^)\s]",
        ),
    ),
    Rule(
        id="A03-JS-URL",
        category="A03",
        title="`javascript:` URL",
        description=(
            "A `javascript:` URL in an attribute runs script when activated "
            "and is a common XSS vector."
        ),
        suggestion="Use real event listeners and validate any user-supplied URL scheme.",
        patterns=_re(
            r"\b(?:href|src|action|formaction)\s*=\s*['\"]?\s*javascript:",
            flags=_I,
        ),
    ),
    Rule(
        id="A03-SERVER-XSS-SSTI",
        category="A03",
        title="Unescaped output / template injection",
        description=(
            "Output escaping is bypassed (`|safe`, `Markup()`, `echo $_GET`), "
            "or a template is built from a string, which can lead to XSS or "
            "server-side template injection."
        ),
        suggestion=(
            "Rely on the template engine's auto-escaping, avoid "
            "`render_template_string` with dynamic input, and encode output "
            "by context."
        ),
        patterns=_re(
            r"\brender_template_string\s*\([^)\n]*(?:\+|%\s*[\w(]|\.format\s*\(|\bf['\"])",
            r"\b(?:echo|print)\b[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
            r"\{\{[^}]*\|\s*safe\s*\}\}|\bMarkup\s*\(\s*(?!['\"])",
            flags=_I,
        ),
    ),
    Rule(
        id="A03-PHP-INCLUDE",
        category="A03",
        title="File inclusion from user input",
        description=(
            "`include`/`require` receives user-controlled data, which allows "
            "local or remote file inclusion."
        ),
        suggestion="Map user choices to a fixed allow-list of files; never include a raw path.",
        patterns=_re(
            r"\b(?:include|require)(?:_once)?\b[^\n;]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A03-FORMAT-STRING",
        category="A03",
        title="Format string vulnerability",
        description=(
            "A variable is used as the format string of `printf`-style "
            "functions, so `%n`/`%s` in the data can read or write memory."
        ),
        suggestion='Always use a constant format string: `printf("%s", value)`.',
        patterns=_re(r"\b(?:printf|fprintf|sprintf|syslog)\s*\(\s*(?:[\w>.\-]+\s*,\s*)?[A-Za-z_]\w*\s*\)"),
    ),
    # ------------------------------------------------------------------ A04
    Rule(
        id="A04-SECURITY-TODO",
        category="A04",
        title="Unfinished security control",
        description=(
            "A comment indicates that authentication, validation or "
            "sanitization still has to be added, or is intentionally skipped."
        ),
        suggestion=(
            "Implement the missing control before release and track security "
            "TODOs as blocking issues."
        ),
        patterns=_re(
            r"(?://|#|/\*|<!--)\s*(?:TODO|FIXME|XXX|HACK)\b[^\n]*\b(?:auth\w*|validat\w*|sanitiz\w*|csrf|security|permission\w*)",
            r"(?://|#|/\*)\s*(?:bypass|disable|skip)\w*\s+(?:security|auth\w*|validation|csrf)",
            flags=_I,
        ),
    ),
    Rule(
        id="A04-INTERNAL-API",
        category="A04",
        title="Internal/admin endpoint referenced",
        severity="Low",
        description=(
            "A path that looks like an internal or debug API is referenced. "
            "Internal endpoints must never be reachable without strong access "
            "control."
        ),
        suggestion="Do not expose internal endpoints publicly; require authentication and network-level restrictions.",
        patterns=_re(r"/api/(?:v\d+/)?(?:internal|debug|private)\b", flags=_I),
    ),
    # ------------------------------------------------------------------ A05
    Rule(
        id="A05-DEBUG-ENABLED",
        category="A05",
        title="Debug mode enabled",
        description=(
            "Debug mode exposes stack traces, internal paths and sometimes an "
            "interactive console to attackers."
        ),
        suggestion="Disable debug features in production and read the setting from the environment.",
        patterns=_re(
            r"\bapp\.run\s*\([^)\n]*debug\s*=\s*True",
            r"^\s*DEBUG\s*=\s*True\b",
            r"\bdisplay_errors\s*=\s*(?:on|1|true)\b",
            r"\bexpose_php\s*=\s*on\b",
            r"\bFLASK_DEBUG\s*=\s*(?:1|true)\b",
            flags=_I,
        ),
    ),
    Rule(
        id="A05-VERBOSE-ERRORS",
        category="A05",
        title="Stack trace / debug output left in code",
        severity="Low",
        description="Stack traces and debug dumps can leak internals when shown to users.",
        suggestion="Log details server-side and return a generic error message to clients.",
        patterns=_re(
            r"\.printStackTrace\s*\(",
            r"\b(?:phpinfo\s*\(|var_dump\s*\(|print_r\s*\()",
            r"\btraceback\.print_exc\s*\(",
        ),
    ),
    Rule(
        id="A05-DEFAULT-CREDS",
        category="A05",
        title="Default or placeholder credentials",
        severity="High",
        description="Default credentials or placeholder secret keys are trivially guessed.",
        suggestion="Generate unique credentials per environment and fail startup if defaults are used.",
        patterns=_re(
            r"\b(?:user(?:name)?|admin|login)\s*[:=]\s*['\"]admin['\"][^\n]*\b(?:password|pass|pwd)\s*[:=]\s*['\"](?:admin|password|1234\d*|root)['\"]",
            r"\b(?:secret_?key|SECRET_KEY)\s*=\s*['\"](?:your[_-]?secret[_-]?key[_-]?here|changeme|secret|dev|development)['\"]",
            flags=_I,
        ),
    ),
    Rule(
        id="A05-PERMISSIVE-CORS",
        category="A05",
        title="Wildcard CORS / host allow-list",
        severity="Medium",
        description=(
            "Allowing every origin (or every host) removes a browser security "
            "boundary and can expose authenticated APIs to other sites."
        ),
        suggestion="Allow only the specific origins/hosts you control.",
        patterns=_re(
            r"Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]?\*",
            r"\ballow_origins\s*=\s*\[\s*['\"]\*['\"]",
            r"\bALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]",
            flags=_I,
        ),
    ),
    # ------------------------------------------------------------------ A07
    Rule(
        id="A07-WEAK-PASSWORD",
        category="A07",
        title="Hardcoded weak password",
        description="A trivially guessable password is hardcoded.",
        suggestion=(
            "Never hardcode passwords. Enforce server-side password policy "
            "and consider MFA and account lockout."
        ),
        patterns=_re(
            r"\b(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"](?:123456\d*|password\d*|admin\d*|test\d*|qwerty\d*|letmein|welcome\d*|root)['\"]",
            flags=_I,
        ),
    ),
    Rule(
        id="A07-SHORT-PASSWORD-POLICY",
        category="A07",
        title="Weak password length policy",
        severity="Medium",
        description="Password length is validated against a threshold below 8 characters.",
        suggestion="Require at least 8-12 characters (preferably longer passphrases) and enforce it server-side.",
        patterns=_re(r"\bpassword\w*\.length\s*(?:<|<=)\s*[1-7]\b|\bmin_?length\s*[:=]\s*[1-7]\b[^\n]*password", flags=_I),
    ),
    Rule(
        id="A07-COOKIE-FLAGS",
        category="A07",
        title="Session cookie without Secure / SameSite",
        severity="Medium",
        description=(
            "A session or auth cookie is set without `Secure` and `SameSite` "
            "(and, if set from JS, cannot be `HttpOnly`), exposing it to "
            "interception, XSS and CSRF."
        ),
        suggestion="Set cookies on the server with `HttpOnly; Secure; SameSite=Lax` (or `Strict`).",
        patterns=_re(
            r"^(?!.*\bsecure\b)(?!.*\bsamesite\b).*document\.cookie\s*=.*(?:session|token|auth|sid)",
            r"\bset_cookie\s*\((?![^)\n]*httponly)(?![^)\n]*secure)[^)\n]*(?:session|token|auth|sid)",
            flags=_I,
        ),
    ),
    Rule(
        id="A07-JWT-UNVERIFIED",
        category="A07",
        title="JWT signature not verified",
        description=(
            "A JWT is decoded without verifying its signature or accepts the "
            "`none` algorithm, allowing forged tokens."
        ),
        suggestion="Always verify the signature with a fixed, explicit algorithm list.",
        patterns=_re(
            r"\bjwt\.decode\s*\([^)\n]*(?:verify\s*=\s*False|verify_signature['\"]?\s*:\s*False)",
            r"\balgorithms?\s*[:=]\s*\[?\s*['\"]none['\"]",
            r"\bignoreExpiration\s*:\s*true",
            flags=_I,
        ),
    ),
    # ------------------------------------------------------------------ A08
    Rule(
        id="A08-UNSAFE-DESERIALIZATION",
        category="A08",
        title="Unsafe deserialization",
        description=(
            "Deserializers that can instantiate arbitrary objects "
            "(`pickle`, `unserialize`, `ObjectInputStream`, `yaml.load` "
            "without `SafeLoader`) allow remote code execution on untrusted "
            "input."
        ),
        suggestion=(
            "Never deserialize untrusted data with these APIs. Use JSON with "
            "schema validation, `yaml.safe_load`, or sign and verify payloads."
        ),
        patterns=_re(
            r"\b(?:pickle|cPickle|dill|marshal|shelve)\.loads?\s*\(",
            r"\bunserialize\s*\(",
            r"\bObjectInputStream\b",
            r"\byaml\.load\s*\((?![^)\n]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)",
            r"\bnode-serialize\b|\bunserialize\s*\(\s*req\.",
        ),
    ),
    Rule(
        id="A08-PIPE-TO-SHELL",
        category="A08",
        title="Remote script piped into a shell",
        severity="Medium",
        description="Downloading and executing a script in one step runs unverified code.",
        suggestion="Download, verify a checksum or signature, review, then execute.",
        patterns=_re(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", flags=_I),
    ),
    # ------------------------------------------------------------------ A09
    Rule(
        id="A09-SWALLOWED-ERROR",
        category="A09",
        title="Error silently swallowed",
        description="Exceptions are caught and ignored, so failures (and attacks) leave no trace.",
        suggestion="Log the error with context, then handle or re-raise it.",
        patterns=_re(
            r"\bexcept\b[^\n:]*:\s*pass\b",
            r"\bcatch\s*\([^)]*\)\s*\{\s*\}",
            flags=_I,
        ),
    ),
    Rule(
        id="A09-SECRET-IN-LOG",
        category="A09",
        title="Sensitive value written to logs",
        severity="Medium",
        description="Passwords, tokens or keys appear to be logged, exposing them to anyone with log access.",
        suggestion="Never log secrets; mask or omit sensitive fields.",
        patterns=_re(
            r"\b(?:log|logger|logging|console)\.\w+\s*\([^)\n]*(?:password|passwd|secret|api_?key|token)\b",
            r"\bprint\s*\(\s*f?['\"][^'\"\n]*(?:password|secret|token)[^'\"\n]*\{",
            flags=_I,
        ),
    ),
    # ------------------------------------------------------------------ A10
    Rule(
        id="A10-SSRF-USER-INPUT",
        category="A10",
        title="Server-side request built from user input",
        description=(
            "An outbound HTTP request uses data taken directly from the "
            "request. An attacker can make your server call internal services "
            "or cloud metadata endpoints."
        ),
        suggestion=(
            "Validate URLs against an allow-list of hosts and schemes, "
            "resolve and reject private/loopback/link-local addresses, and "
            "do not follow redirects blindly."
        ),
        patterns=_re(
            r"\b" + _HTTP_CALLS + r"\s*\([^)\n]*" + _USER_INPUT,
            flags=_I,
        ),
    ),
    Rule(
        id="A10-SSRF-URL-VARIABLE",
        category="A10",
        title="Server-side request to a variable URL",
        severity="Medium",
        description=(
            "An outbound HTTP request targets a variable named like a URL. If "
            "its value is user-influenced and unvalidated, this is SSRF."
        ),
        suggestion=(
            "Confirm where the URL comes from. If it is user-supplied, "
            "validate it against an allow-list and block internal addresses."
        ),
        patterns=_re(
            r"\b" + _HTTP_CALLS + r"\s*\(\s*(?:url|uri|target_?url|user_?url|link|endpoint|address)\b",
            flags=_I,
        ),
    ),
]
