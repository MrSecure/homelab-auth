#!/usr/bin/env python3
"""Tests for the /validate ForwardAuth endpoint behavior."""

import importlib.util
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest


def _load_main_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Load src/main.py with an isolated temp config and cwd."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "auth:",
                "  hashing_string: test-key",
                "  session_max_age: 43200",
                "  htpasswd_path: users.htpasswd",
                "  failed_response_code: 497",
                "cookie:",
                "  name: pecan_sandy",
                "  domain: null",
                "  secure: true",
                "  httponly: true",
                "  samesite: Lax",
                "  allowed_hosts:",
                "    - labs.home.arpa",
                "    - sslip.io",
                "server:",
                "  host: 0.0.0.0",
                "  port: 55000",
                "redir:",
                "  external_name: auth",
                "  default_destination: dashboard",
                "page:",
                "  title: Home Lab Access",
            ]
        )
    )
    htpasswd_file = tmp_path / "users.htpasswd"
    htpasswd_file.write_text(
        "testuser:$2y$12$R9h/cIPz0gi.URNNX3HNJe9Z1q43NbEsGe7nCLwjYaXpYhEjrRxzq\n"
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "config.yaml"])

    main_path = Path(__file__).parent.parent / "src" / "main.py"
    module_name = f"main_validate_test_{id(tmp_path)}"
    spec = importlib.util.spec_from_file_location(module_name, main_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.unit
def test_validate_returns_ok_for_authenticated_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return 200 OK when a valid session cookie is present."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    signed_cookie = main.cookie_signer.sign("testuser").decode("utf-8")
    client.set_cookie(
        main.cfg["cookie"]["name"],
        signed_cookie,
        domain="localhost",
    )
    response = client.get("/validate")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "OK"


@pytest.mark.unit
def test_validate_redirects_sslip_host_for_unauthenticated_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return 307 redirect with auth-<ip>.sslip.io hostname for unauthenticated request."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    response = client.get(
        "/validate",
        headers={
            "X-Forwarded-Host": "web-10-9-8-177.sslip.io",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Uri": "/",
        },
    )

    assert response.status_code == 307
    assert response.location is not None
    parsed_location = urlparse(response.location)
    assert parsed_location.scheme == "https"
    assert parsed_location.netloc == "auth-10-9-8-177.sslip.io"
    query_params = parse_qs(parsed_location.query)
    assert query_params["rd"] == ["https://web-10-9-8-177.sslip.io/"]


@pytest.mark.unit
def test_validate_redirects_labs_host_for_unauthenticated_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return 307 redirect with auth.labs.home.arpa hostname for unauthenticated request."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    response = client.get(
        "/validate",
        headers={
            "X-Forwarded-Host": "web.labs.home.arpa",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Uri": "/",
        },
    )

    assert response.status_code == 307
    assert response.location is not None
    parsed_location = urlparse(response.location)
    assert parsed_location.scheme == "https"
    assert parsed_location.netloc == "auth.labs.home.arpa"
    query_params = parse_qs(parsed_location.query)
    assert query_params["rd"] == ["https://web.labs.home.arpa/"]


@pytest.mark.unit
def test_validate_returns_configured_failure_code_on_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return configured failed_response_code when validate raises unexpectedly."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    def _raise_runtime_error(_: str | None) -> bool:
        raise RuntimeError("simulated verification failure")

    monkeypatch.setattr(main, "is_authenticated", _raise_runtime_error)
    response = client.get("/validate")

    assert response.status_code == 497
    assert response.get_data(as_text=True) == "Unauthorized"


@pytest.mark.unit
def test_verify_returns_ok_for_authenticated_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return 200 OK on /verify when a valid session cookie is present."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    signed_cookie = main.cookie_signer.sign("testuser").decode("utf-8")
    client.set_cookie(
        main.cfg["cookie"]["name"],
        signed_cookie,
        domain="localhost",
    )
    response = client.get("/verify")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "OK"


@pytest.mark.unit
def test_verify_returns_configured_failure_code_for_unauthenticated_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return configured failed_response_code on /verify when unauthenticated."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    response = client.get(
        "/verify",
        headers={
            "X-Forwarded-Host": "web.labs.home.arpa",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Uri": "/",
        },
    )

    assert response.status_code == 497
    assert response.get_data(as_text=True) == "Unauthorized"


@pytest.mark.unit
def test_verify_returns_configured_failure_code_on_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Return configured failed_response_code on /verify when it raises unexpectedly."""
    main = _load_main_module(tmp_path, monkeypatch)
    app = main.app
    client = app.test_client()

    def _raise_runtime_error(_: str | None) -> bool:
        raise RuntimeError("simulated verification failure")

    monkeypatch.setattr(main, "is_authenticated", _raise_runtime_error)
    response = client.get("/verify")

    assert response.status_code == 497
    assert response.get_data(as_text=True) == "Unauthorized"
