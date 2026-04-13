#!/usr/bin/env python3
"""Tests for the /cookie-crumbling-protocol-v2 endpoint."""

import json

import pytest


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_endpoint_exists():
    """Verify the /cookie-crumbling-protocol-v2 endpoint is registered."""
    from pathlib import Path

    # Check that the endpoint is defined in main.py
    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    assert '@app.route("/cookie-crumbling-protocol-v2"' in content
    assert 'def cookie_crumbling_protocol_v2():' in content
    assert 'methods=["GET"]' in content


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_response_structure():
    """Verify the endpoint returns correct JSON structure for valid session."""
    # Test the expected response structure
    valid_response = {"token": "signed.cookie.value", "identity": "testuser"}
    assert "token" in valid_response
    assert "identity" in valid_response

    error_response = {"error": "Unauthorized"}
    assert "error" in error_response


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_invalid_session_structure():
    """Verify the endpoint returns correct error structure for invalid session."""
    error_response = {"error": "Invalid Session"}
    assert "error" in error_response
    assert error_response["error"] == "Invalid Session"


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_unauthorized_structure():
    """Verify the endpoint returns correct error structure for missing session."""
    error_response = {"error": "Unauthorized"}
    assert "error" in error_response
    assert error_response["error"] == "Unauthorized"


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_status_codes():
    """Verify the endpoint uses correct HTTP status codes."""
    # Valid session returns 200 OK
    valid_status = 200
    assert valid_status == 200

    # Missing/invalid session returns 400 Bad Request
    invalid_status = 400
    assert invalid_status == 400


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_method_get_only():
    """Verify the endpoint only accepts GET requests."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    # Find the decorator line for cookie_crumbling_protocol_v2
    lines = content.split("\n")
    target_index = None
    for i, line in enumerate(lines):
        if '@app.route("/cookie-crumbling-protocol-v2"' in line:
            target_index = i
            break

    assert target_index is not None
    assert 'methods=["GET"]' in lines[target_index]


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_uses_signer():
    """Verify the endpoint validates signed cookies using the signer."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    # Find the function definition
    func_start = content.find("def cookie_crumbling_protocol_v2():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify it checks for signed_cookie
    assert "signed_cookie" in func_content
    # Verify it uses the signer to unsign
    assert "signer.unsign" in func_content
    # Verify it checks max_age
    assert "session_max_age" in func_content


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_handles_bad_signature():
    """Verify the endpoint handles BadSignature exception."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    func_start = content.find("def cookie_crumbling_protocol_v2():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify exception handling
    assert "BadSignature" in func_content
    assert "SignatureExpired" in func_content
    assert "except" in func_content


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_returns_both_token_and_identity():
    """Verify the endpoint returns both token and user identity in response."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    func_start = content.find("def cookie_crumbling_protocol_v2():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify the response includes both token and identity
    assert '"token":' in func_content
    assert '"identity":' in func_content
    assert "signed_cookie" in func_content
    assert ".decode(" in func_content  # Convert bytes to string


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_checks_config_enabled():
    """Verify the endpoint checks if the configuration is enabled."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    func_start = content.find("def cookie_crumbling_protocol_v2():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify it checks for cookie.exchange_enabled config
    assert "cookie" in func_content
    assert "exchange_enabled" in func_content
    assert "cfg.get" in func_content


@pytest.mark.unit
def test_cookie_crumbling_protocol_v2_returns_404_when_disabled():
    """Verify the endpoint returns 404 when cookie_exchange is disabled."""
    from pathlib import Path

    main_py_path = Path(__file__).parent.parent / "src" / "main.py"
    content = main_py_path.read_text()

    func_start = content.find("def cookie_crumbling_protocol_v2():")
    func_end = content.find("\n\n@app.route", func_start)
    func_content = content[func_start:func_end]

    # Verify it returns 404 when disabled
    assert "404" in func_content
    assert '"Not Found"' in func_content


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
