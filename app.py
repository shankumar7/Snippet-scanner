"""Entry point.

    python app.py                      # development server on http://127.0.0.1:5050
    gunicorn app:app                   # production (see Procfile / render.yaml)
"""

import os

from snippet_scanner.api import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5050")),
        debug=False,
    )
