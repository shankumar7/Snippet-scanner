"""Rule-level tests: each vulnerable sample must be flagged, each safe one must not."""

import pytest

from snippet_scanner import scan_content
from snippet_scanner.scanner import ContentTooLargeError, MAX_CONTENT_CHARS


def rule_ids(code):
    return {r["rule_id"] for r in scan_content(code)}


VULNERABLE = [
    ("A01-CLIENT-ROLE-STORAGE", "localStorage.setItem('role', 'admin');"),
    ("A01-IDOR", "fetch('/api/orders/42')"),
    ("A01-OPEN-REDIRECT", "return redirect(request.args['next'])"),
    ("A02-HARDCODED-SECRET", 'api_key = "sk-abcdef123456"'),
    ("A02-HARDCODED-SECRET", "key = 'AKIAABCDEFGHIJKLMNOP'"),
    ("A02-CLIENT-SECRET-STORAGE", "localStorage.setItem('token', t)"),
    ("A02-WEAK-HASH", "h = hashlib.md5(data).hexdigest()"),
    ("A02-WEAK-CIPHER", 'Cipher.getInstance("DES/ECB/PKCS5Padding")'),
    ("A02-TLS-VERIFY-OFF", "requests.get(u, verify=False)"),
    ("A02-PLAIN-HTTP", 'const api = "http://api.example-bank.io/v1";'),
    ("A03-SQL-INJECTION", 'query = "SELECT * FROM users WHERE id=" + user_id'),
    ("A03-SQL-INJECTION", 'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")'),
    ("A03-SQL-INJECTION", 'cur.execute("SELECT * FROM t WHERE a=\'%s\'" % a)'),
    ("A03-COMMAND-INJECTION", 'os.system("ping " + host)'),
    ("A03-COMMAND-INJECTION", "subprocess.run(cmd, shell=True)"),
    ("A03-CODE-EVAL", "result = eval(user_input)"),
    ("A03-DOM-XSS", "div.innerHTML = location.hash;"),
    ("A03-DOM-XSS", "document.write(name)"),
    ("A03-JS-URL", '<a href="javascript:alert(1)">x</a>'),
    ("A03-SERVER-XSS-SSTI", 'render_template_string("Hi " + name)'),
    ("A03-SERVER-XSS-SSTI", "echo $_GET['q'];"),
    ("A03-PHP-INCLUDE", "include($_GET['page']);"),
    ("A03-FORMAT-STRING", "printf(user_input);"),
    ("A04-SECURITY-TODO", "// TODO: add authentication here"),
    ("A05-DEBUG-ENABLED", "app.run(debug=True)"),
    ("A05-VERBOSE-ERRORS", "e.printStackTrace();"),
    ("A05-DEFAULT-CREDS", 'SECRET_KEY = "changeme"'),
    ("A05-PERMISSIVE-CORS", "Access-Control-Allow-Origin: *"),
    ("A07-WEAK-PASSWORD", 'password = "123456"'),
    ("A07-SHORT-PASSWORD-POLICY", "if (password.length < 6) { fail(); }"),
    ("A07-COOKIE-FLAGS", "document.cookie = 'session=' + id;"),
    ("A07-JWT-UNVERIFIED", "jwt.decode(token, verify=False)"),
    ("A08-UNSAFE-DESERIALIZATION", "obj = pickle.loads(blob)"),
    ("A08-UNSAFE-DESERIALIZATION", "cfg = yaml.load(text)"),
    ("A08-PIPE-TO-SHELL", "curl -s https://x.sh | sudo bash"),
    ("A09-SWALLOWED-ERROR", "except Exception: pass"),
    ("A09-SECRET-IN-LOG", 'logger.info("password=%s", password)'),
    ("A10-SSRF-USER-INPUT", "requests.get(request.args['url'])"),
    ("A10-SSRF-URL-VARIABLE", "resp = requests.get(url)"),
]


@pytest.mark.parametrize("expected,code", VULNERABLE)
def test_vulnerable_code_is_flagged(expected, code):
    assert expected in rule_ids(code)


SAFE = [
    "data = json.loads(payload)",  # was flagged as insecure deserialization
    "confirmPassword = form.confirm",  # was flagged as weak password
    "obj.old = 1\nobj.temp = 2\nobj.test = 3",  # was flagged as backup files
    '<svg xmlns="http://www.w3.org/2000/svg"></svg>',  # namespace URI, not insecure traffic
    'cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))',  # parameterized
    "subprocess.run(['ls', '-l'], shell=False)",
    "el.textContent = userInput;",
    "el.innerHTML = '<b>static</b>';",
    "yaml.load(text, Loader=yaml.SafeLoader)",
    "password = os.environ['DB_PASSWORD']",
    "hashlib.sha256(data)",
    "fetch('https://api.github.com/repos')",
    "x = 1 + 2",
    "",
]


@pytest.mark.parametrize("code", SAFE)
def test_safe_code_is_not_flagged(code):
    assert scan_content(code) == [], scan_content(code)


def test_line_numbers_and_snippets():
    results = scan_content("a = 1\nb = 2\npassword = 'supersecret1'\n")
    assert len(results) == 1
    assert results[0]["line_number"] == 3
    assert "password" in results[0]["snippet"]


def test_results_sorted_by_severity():
    code = "except Exception: pass\npassword = 'supersecret1'\nfetch('/api/orders/1')"
    sev = [r["severity"] for r in scan_content(code)]
    order = {"High": 0, "Medium": 1, "Low": 2}
    assert sev == sorted(sev, key=order.get)


def test_result_shape():
    r = scan_content("app.run(debug=True)")[0]
    for key in ("rule_id", "issue", "severity", "description", "suggestion", "owasp_category", "line_number"):
        assert key in r


# ------------------------------------------------------------------ A06 / A08
def test_outdated_jquery_script_tag():
    html = '<script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-x"></script>'
    ids = rule_ids(html)
    assert "A06-OUTDATED-JS-LIB" in ids
    assert "A08-NO-SRI" not in ids  # integrity attribute present


def test_modern_jquery_not_flagged():
    html = '<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-x"></script>'
    assert "A06-OUTDATED-JS-LIB" not in rule_ids(html)


def test_cdn_script_without_sri_and_http_script():
    ids = rule_ids('<script src="https://cdn.example.net/lib.js"></script>\n<script src="http://evil.test/a.js"></script>')
    assert {"A08-NO-SRI", "A08-HTTP-RESOURCE"} <= ids


def test_multiline_script_tag_is_parsed():
    html = '<script\n  src="https://cdn.jsdelivr.net/npm/x.js"\n  defer></script>'
    results = [r for r in scan_content(html) if r["rule_id"] == "A08-NO-SRI"]
    assert results and results[0]["line_number"] == 1


def test_requirements_txt_outdated():
    assert "A06-OUTDATED-PY-PACKAGE" in rule_ids("flask==2.0.1\nrequests==2.31.0\n")
    assert "A06-OUTDATED-PY-PACKAGE" not in rule_ids("flask==3.1.1\nrequests==2.32.3\n")


def test_package_json_outdated():
    assert "A06-OUTDATED-NPM-PACKAGE" in rule_ids('{"dependencies": {"lodash": "^4.17.4"}}')


def test_pom_outdated_log4j():
    pom = "<artifactId>log4j-core</artifactId><version>2.14.1</version>"
    assert "A06-OUTDATED-JAVA-LIB" in rule_ids(pom)


# ------------------------------------------------------------------ A09
def test_missing_logging_flagged_only_when_no_logging():
    assert "A09-NO-SECURITY-LOGGING" in rule_ids("def login(user, pw):\n    return check(user, pw)\n")
    assert "A09-NO-SECURITY-LOGGING" not in rule_ids(
        "def login(user, pw):\n    logger.info('login attempt')\n    return check(user, pw)\n")


# ------------------------------------------------------------------ limits
def test_oversized_content_rejected():
    with pytest.raises(ContentTooLargeError):
        scan_content("a" * (MAX_CONTENT_CHARS + 1))


def test_pathological_input_is_fast():
    import time
    nasty = ("SELECT " + "a" * 3500 + " FROM " + '"' * 400 + " ") * 200
    start = time.time()
    scan_content(nasty)
    assert time.time() - start < 10


def test_non_string_rejected():
    with pytest.raises(TypeError):
        scan_content(None)  # type: ignore[arg-type]
