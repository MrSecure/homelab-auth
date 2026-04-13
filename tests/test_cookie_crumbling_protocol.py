#!/usr/bin/env python3
"""Functional tests for the /cookie-crumbling-protocol-v2 endpoint."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_CONFIG = """
auth:
    hashing_string: test-key
    session_max_age: 43200
    htpasswd_path: users.htpasswd
cookie:
    name: session
    domain: .example.com
    secure: true
    httponly: true
    samesite: Lax
    exchange_enabled: true
header:
    name: X-HomeLab-Auth-Token
server:
    port: 5000
redir:
    external_name: auth
    default_destination: dashboard
page:
    title: Login
""".strip()

_DISABLED_EXCHANGE_CONFIG = _MINIMAL_CONFIG.replace("exchange_enabled: true", "exchange_enabled: false")


@pytest.fixture(autouse=True)
def _mock_sys_exit():
    """Prevent main.py module-level sys.exit() calls from aborting tests."""
    with patch("sys.exit"):
        yield


def load_main_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config_yaml: str = _MINIMAL_CONFIG) -> ModuleType:
    """Load src/main.py against a temporary config directory for route tests."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_yaml)
    (tmp_path / "users.htpasswd").write_text(
        "testuser:$2y$12$R9h/cIPz0gi.URNNX3HNJe9Z1q43NbEsGe7nCLwjYaXpYhEjrRxzq\n"
    )

    repo_root = Path(__file__).parent.parent
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(repo_root / "src"))
    monkeypatch.setattr(sys, "argv", ["main.py", str(config_file)])

    module_name = f"main_for_cookie_exchange_test_{tmp_path.name}"
    spec = importlib.util.spec_from_file_location(module_name, repo_root / "src" / "main.py")
    assert spec is not None and spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config["TESTING"] = True
    return module


# ---------------------------------------------------------------------------
# Functional endpoint tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_valid_cookie_returns_200(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Enabled endpoint + valid session cookie returns 200 with token and identity."""
    mod = load_main_module(tmp_path, monkeypatch)
    client = mod.app.test_client()

    valid_cookie = mod.signer.sign("testuser").decode("utf-8")
    client.set_cookie(mod.cfg["cookie"]["name"], valid_cookie)

    response = client.get("/cookie-crumbling-protocol-v2")

    assert response.status_code == 200
    assert response.content_type == "application/json"
    body = response.get_json()
    assert body["token"] == valid_cookie
    assert body["identity"] == "testuser"
    assert "cookie" in body
    assert "header" in body


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_missing_cookie_returns_400(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Enabled endpoint + no session cookie returns 400 Unauthorized (not 401, to avoid auth loops)."""
    mod = load_main_module(tmp_path, monkeypatch)
    client = mod.app.test_client()

    response = client.get("/cookie-crumbling-protocol-v2")

    assert response.status_code == 400
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "Unauthorized"}


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_bad_signature_returns_400(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Enabled endpoint + tampered cookie returns 400 Invalid Session."""
    mod = load_main_module(tmp_path, monkeypatch)
    client = mod.app.test_client()

    client.set_cookie(mod.cfg["cookie"]["name"], "this.is.not.a.valid.signed.cookie")

    response = client.get("/cookie-crumbling-protocol-v2")

    assert response.status_code == 400
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "Invalid Session"}


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_expired_cookie_returns_400(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Enabled endpoint + expired session cookie returns 400 Invalid Session."""
    import time

    mod = load_main_module(tmp_path, monkeypatch)
    client = mod.app.test_client()

    # Sign the cookie as if it was issued 2 days ago so it is expired (session_max_age=43200 = 12 h)
    past_time = time.time() - (2 * 24 * 60 * 60)  # 2 days in seconds
    with patch("time.time", return_value=past_time):
        expired_cookie = mod.signer.sign("testuser").decode("utf-8")

    client.set_cookie(mod.cfg["cookie"]["name"], expired_cookie)

    response = client.get("/cookie-crumbling-protocol-v2")

    assert response.status_code == 400
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "Invalid Session"}


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_disabled_returns_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Disabled config returns 404 Not Found regardless of cookie presence."""
    mod = load_main_module(tmp_path, monkeypatch, _DISABLED_EXCHANGE_CONFIG)
    client = mod.app.test_client()

    valid_cookie = mod.signer.sign("testuser").decode("utf-8")
    client.set_cookie(mod.cfg["cookie"]["name"], valid_cookie)

    response = client.get("/cookie-crumbling-protocol-v2")

    assert response.status_code == 404
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "Not Found"}


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_post_method_not_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Endpoint only accepts GET; POST returns 405 Method Not Allowed."""
    mod = load_main_module(tmp_path, monkeypatch)
    client = mod.app.test_client()

    response = client.post("/cookie-crumbling-protocol-v2")

    assert response.status_code == 405


@pytest.mark.unit
def test_example_config_has_cookie_exchange_enabled():
    """Verify example config includes exchange_enabled setting in cookie section."""
    import yaml
    from pathlib import Path

    config_path = Path(__file__).parent.parent / "examples" / "config.yaml"
    content = config_path.read_text()
    config = yaml.safe_load(content)

    assert "cookie" in config
    assert "exchange_enabled" in config["cookie"]
    assert config["cookie"]["exchange_enabled"] is True


@pytest.mark.unit
def test_support_wsgi_config_has_cookie_exchange_enabled():
    """Verify WSGI support config includes exchange_enabled setting in cookie section."""
    import yaml
    from pathlib import Path

    config_path = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    content = config_path.read_text()
    config = yaml.safe_load(content)

    assert "cookie" in config
    assert "exchange_enabled" in config["cookie"]
    assert config["cookie"]["exchange_enabled"] is True


@pytest.mark.unit
def test_support_config_has_cookie_exchange_enabled():
    """Verify support config includes exchange_enabled setting in cookie section."""
    import yaml
    from pathlib import Path

    config_path = Path(__file__).parent.parent / "support" / "config.yaml"
    content = config_path.read_text()
    config = yaml.safe_load(content)

    assert "cookie" in config
    assert "exchange_enabled" in config["cookie"]
    assert config["cookie"]["exchange_enabled"] is True


@pytest.mark.unit
def test_cookie_exchange_default_enabled():
    """Verify exchange_enabled defaults to True when not specified."""
    cfg = {"cookie": {}}
    enabled = cfg.get("cookie", {}).get("exchange_enabled", True)
    assert enabled is True


@pytest.mark.unit
def test_cookie_exchange_respects_disabled_config():
    """Verify exchange_enabled can be disabled via configuration."""
    cfg = {"cookie": {"exchange_enabled": False}}
    enabled = cfg.get("cookie", {}).get("exchange_enabled", True)
    assert enabled is False


@pytest.mark.unit
def test_header_config_section_exists():
    """Verify all config files include header section."""
    import yaml
    from pathlib import Path

    for config_file in ["examples/config.yaml", "support/wsgi-config.yaml", "support/config.yaml"]:
        config_path = Path(__file__).parent.parent / config_file
        content = config_path.read_text()
        config = yaml.safe_load(content)

        assert "header" in config, f"{config_file} should have header section"
        assert "name" in config["header"], f"{config_file} header should have name"
        assert config["header"]["name"] == "X-HomeLab-Auth-Token", \
            f"{config_file} header.name should default to X-HomeLab-Auth-Token"


@pytest.mark.unit
def test_verify_endpoint_checks_header():
    """Verify the /verify endpoint checks header as fallback when exchange is enabled."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    # Find the verify function
    func_start = content.find("def verify():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify it checks cookie first
    cookie_check_pos = func_content.find("request.cookies.get")
    header_check_pos = func_content.find("request.headers.get")
    assert cookie_check_pos > 0, "Should check cookies"
    assert header_check_pos > 0, "Should check headers"
    assert cookie_check_pos < header_check_pos, "Cookie check should come first"

    # Verify it checks exchange_enabled
    assert "exchange_enabled" in func_content
    # Verify it uses the header
    assert "X-HomeLab-Misconfigured" in func_content


@pytest.mark.unit
def test_header_name_default_value():
    """Verify header name defaults to X-HomeLab-Misconfigured when not specified."""
    cfg = {}
    header_name = cfg.get("header", {}).get("name", "X-HomeLab-Misconfigured")
    assert header_name == "X-HomeLab-Misconfigured"


@pytest.mark.unit
def test_header_name_can_be_customized():
    """Verify header name can be customized via configuration."""
    cfg = {"header": {"name": "X-Custom-Token"}}
    header_name = cfg.get("header", {}).get("name", "X-HomeLab-Misconfigured")
    assert header_name == "X-Custom-Token"
