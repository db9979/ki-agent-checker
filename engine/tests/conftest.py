import pytest
from fastapi.testclient import TestClient

from kac_engine.api import create_app
from kac_engine.keystore import SecretStore

TOKEN = "test-token"


@pytest.fixture
def client():
    app = create_app(token=TOKEN, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {TOKEN}"
        yield c
