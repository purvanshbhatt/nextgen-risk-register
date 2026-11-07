"""Test configuration.

backend.db resolves the database location from NGRR_DATA_DIR / NGRR_DB_PATH at
import time, so the environment must be set before any backend module loads.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="ngrr-test-"))
os.environ["NGRR_DATA_DIR"] = str(_TMP)
os.environ["NGRR_DB_PATH"] = str(_TMP / "register.db")

import pytest  # noqa: E402

from backend import seed as seeder  # noqa: E402


@pytest.fixture(scope="session")
def seeded_db():
    """Fresh demo dataset for the whole test session."""
    seeder.reset()
    seeder.seed()
    return os.environ["NGRR_DB_PATH"]


@pytest.fixture(scope="session")
def client(seeded_db):
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as c:
        yield c
