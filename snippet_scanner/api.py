"""Flask application: JSON API plus (optionally) the static frontend."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from . import __version__
from .fetcher import FetchError, UnsafeURLError, fetch_url
from .rules import RULES
from .scanner import FILE_CHECKS, ContentTooLargeError, scan_content, summarize

log = logging.getLogger("snippet_scanner")

FRONTEND_DIR = Path(__file__).resolve().parent.parent  # repo root: index.html + tailwind.css


def _env_flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _error(message: str, status: int):
    return jsonify({"status": "error", "message": message, "error": message, "vulnerabilities": []}), status


def create_app(config: Optional[dict] = None) -> Flask:
    """Application factory.

    Environment variables (all optional):

    ``CORS_ORIGINS``         comma-separated allowed origins (default ``*``)
    ``ALLOW_PRIVATE_URLS``   set to ``true`` to let the URL scanner reach
                             private/loopback addresses (local dev only!)
    ``SERVE_FRONTEND``       serve ``index.html`` at ``/`` (default ``true``)
    """
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        ALLOW_PRIVATE_URLS=_env_flag("ALLOW_PRIVATE_URLS", False),
        SERVE_FRONTEND=_env_flag("SERVE_FRONTEND", True),
        JSON_SORT_KEYS=False,
    )
    if config:
        app.config.update(config)

    origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]
    CORS(app, resources={r"/*": {"origins": origins or "*"}})

    # ---------------------------------------------------------------- routes
    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "version": __version__})

    @app.get("/rules")
    def rules():
        catalogue = [
            {"id": r.id, "title": r.title, "severity": r.effective_severity, "owasp_category": r.owasp_category}
            for r in RULES
        ] + FILE_CHECKS
        return jsonify({"count": len(catalogue), "rules": catalogue})

    @app.post("/scan")
    def scan():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return _error('Invalid JSON payload. Send an object with "code_snippet" or "url".', 400)

        code, url = data.get("code_snippet"), data.get("url")
        if isinstance(code, str) and code.strip():
            content = code
        elif isinstance(url, str) and url.strip():
            try:
                content = fetch_url(url, allow_private=app.config["ALLOW_PRIVATE_URLS"])
            except UnsafeURLError as exc:
                return _error(str(exc), 400)
            except FetchError as exc:
                return _error(str(exc), 502)
        else:
            return _error('Missing "code_snippet" or "url" in the request payload.', 400)

        try:
            results = scan_content(content)
        except ContentTooLargeError as exc:
            return _error(str(exc), 413)

        counts = summarize(results)
        return jsonify({
            "status": "success",
            "summary": f"{counts['total']} potential vulnerability(s) detected.",
            "counts": counts,
            "vulnerabilities": results,
        })

    # -------------------------------------------------------------- frontend
    if app.config["SERVE_FRONTEND"] and FRONTEND_DIR.is_dir():
        @app.get("/")
        def index():
            return send_from_directory(FRONTEND_DIR, "index.html")

        @app.get("/tailwind.css")
        def stylesheet():
            return send_from_directory(FRONTEND_DIR, "tailwind.css")

    # ---------------------------------------------------------------- errors
    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        if exc.code == 413:
            return _error("Request body is too large (limit 2 MB).", 413)
        return _error(exc.description or exc.name, exc.code or 500)

    @app.errorhandler(Exception)
    def unexpected(exc: Exception):
        log.exception("Unhandled error while processing %s", request.path)
        return _error("Internal server error.", 500)

    return app
