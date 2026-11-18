import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from snippet_scanner.api import create_app  # noqa: E402


@pytest.fixture()
def client():
    app = create_app({"TESTING": True})
    return app.test_client()
