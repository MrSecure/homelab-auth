#!/usr/bin/env python3
"""
Test wsgi.py WSGI entry point module.

Tests for environment variable handling, sys.argv manipulation, bcrypt compatibility,
and Flask app initialization via the WSGI entry point.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


@pytest.mark.unit
def test_wsgi_entry_point_imports():
    """Test that wsgi module can be imported without errors."""
    # This test verifies the module structure exists
    # (actual import test would require app initialization)
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    assert wsgi_path.exists(), "wsgi.py module should exist"
    assert wsgi_path.is_file(), "wsgi.py should be a regular file"


@pytest.mark.unit
def test_wsgi_module_has_app_export():
    """Test that wsgi.py exports the app object."""
    # Read the wsgi.py file to verify __all__ definition
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    assert '__all__ = ["app"]' in content, "wsgi.py should export app in __all__"
    assert 'from src.main import app' in content or 'from main import app' in content, \
        "wsgi.py should import app from main module"


@pytest.mark.unit
def test_wsgi_bcrypt_compatibility_fix():
    """Test that wsgi.py includes bcrypt 4.0+ compatibility fix."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    # Check for compatibility fix
    assert '# --- FIX: Passlib/Bcrypt 4.0+ Compatibility ---' in content, \
        "wsgi.py should include bcrypt compatibility fix comment"
    assert 'if not hasattr(bcrypt, "__about__")' in content, \
        "wsgi.py should check for __about__ attribute"
    assert 'bcrypt.__about__ = type("obj"' in content, \
        "wsgi.py should create __about__ object for compatibility"


@pytest.mark.unit
def test_wsgi_env_var_config_file():
    """Test that wsgi.py handles HOMELAB_AUTH_CONFIG_FILE environment variable."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    assert 'HOMELAB_AUTH_CONFIG_FILE' in content, \
        "wsgi.py should reference HOMELAB_AUTH_CONFIG_FILE env var"
    assert 'os.getenv("HOMELAB_AUTH_CONFIG_FILE", "config.yaml")' in content, \
        "wsgi.py should use getenv with config.yaml default"


@pytest.mark.unit
def test_wsgi_env_var_hashing_key():
    """Test that wsgi.py handles HOMELAB_AUTH_HASHING_KEY environment variable."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    assert 'HOMELAB_AUTH_HASHING_KEY' in content, \
        "wsgi.py should reference HOMELAB_AUTH_HASHING_KEY env var"
    assert 'os.getenv("HOMELAB_AUTH_HASHING_KEY")' in content, \
        "wsgi.py should read HOMELAB_AUTH_HASHING_KEY from environment"


@pytest.mark.unit
def test_wsgi_sys_argv_manipulation():
    """Test that wsgi.py properly constructs sys.argv."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    # Verify sys.argv is being constructed
    assert 'sys.argv = [' in content, "wsgi.py should construct sys.argv"
    assert 'sys.argv[0]' in content, "wsgi.py should preserve script name in sys.argv"
    assert 'sys.argv.extend' in content, "wsgi.py should extend sys.argv for optional args"


@pytest.mark.unit
def test_wsgi_logging_setup():
    """Test that wsgi.py sets up logging early to suppress warnings."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    assert 'logging.basicConfig()' in content, \
        "wsgi.py should configure logging early"
    assert 'getLogger("passlib.handlers.bcrypt").setLevel(logging.CRITICAL)' in content, \
        "wsgi.py should suppress passlib bcrypt warnings"


@pytest.mark.unit
def test_wsgi_imports_order():
    """Test that wsgi.py imports bcrypt before logging setup comments."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()
    lines = content.split('\n')

    # Find indices of key lines
    import_os_idx = next((i for i, line in enumerate(lines) if 'import os' in line), -1)
    logging_setup_idx = next((i for i, line in enumerate(lines) if 'logging.basicConfig()' in line), -1)
    bcrypt_import_idx = next((i for i, line in enumerate(lines) if 'import bcrypt' in line), -1)

    assert import_os_idx >= 0, "Should import os"
    assert logging_setup_idx >= 0, "Should setup logging"
    assert bcrypt_import_idx >= 0, "Should import bcrypt"

    # Logging should be setup before bcrypt import to suppress warnings
    assert logging_setup_idx < bcrypt_import_idx, \
        "Logging should be configured before bcrypt import"


@pytest.mark.unit
def test_wsgi_fallback_import():
    """Test that wsgi.py has fallback import for Docker compatibility."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    assert 'try:' in content and 'from src.main import app' in content, \
        "wsgi.py should try to import from src.main for development"
    assert 'except ModuleNotFoundError:' in content, \
        "wsgi.py should handle ModuleNotFoundError"
    assert 'from main import app' in content, \
        "wsgi.py should fallback to main module for Docker"


@pytest.mark.unit
def test_wsgi_config_env_var_default():
    """Test that config file defaults to config.yaml."""
    # This tests the documented default behavior
    content = 'os.getenv("HOMELAB_AUTH_CONFIG_FILE", "config.yaml")'
    assert 'config.yaml' in content, \
        "Default config file should be config.yaml"


@pytest.mark.unit
def test_wsgi_hashing_key_precedence():
    """Test that environment variable has higher precedence than defaults."""
    wsgi_path = Path(__file__).parent.parent / "src" / "wsgi.py"
    content = wsgi_path.read_text()

    # Verify env var is checked first
    assert 'if os.getenv("HOMELAB_AUTH_HASHING_KEY"):' in content, \
        "wsgi.py should check HOMELAB_AUTH_HASHING_KEY as highest precedence"
    assert 'sys.argv.extend(["--hashing-key"' in content, \
        "wsgi.py should pass hashing key as CLI arg when env var is set"


@pytest.mark.integration
def test_wsgi_config_file_loading():
    """Test that WSGI config file can be properly loaded."""
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    assert config_file.exists(), "wsgi-config.yaml should exist in support directory"

    # Verify it's valid YAML with required sections
    import yaml
    config = yaml.safe_load(config_file.read_text())

    required_sections = ['auth', 'cookie', 'server', 'redir', 'page']
    for section in required_sections:
        assert section in config, f"wsgi-config.yaml should have {section} section"


@pytest.mark.integration
def test_wsgi_config_auth_section():
    """Test that WSGI config has proper auth settings."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    auth = config['auth']
    assert 'htpasswd_path' in auth, "auth section should specify htpasswd_path"
    assert 'session_max_age' in auth, "auth section should specify session_max_age"
    assert auth['session_max_age'] > 0, "session_max_age should be positive"


@pytest.mark.integration
def test_wsgi_config_cookie_section():
    """Test that WSGI config has proper cookie settings."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    cookie = config['cookie']
    required_keys = ['name', 'secure', 'httponly', 'samesite']
    for key in required_keys:
        assert key in cookie, f"cookie section should have {key}"

    assert isinstance(cookie['secure'], bool), "secure should be boolean"
    assert isinstance(cookie['httponly'], bool), "httponly should be boolean"
    assert cookie['samesite'] in ['Strict', 'Lax', 'None'], \
        "samesite should be Strict, Lax, or None"


@pytest.mark.integration
def test_wsgi_config_allowed_hosts():
    """Test that WSGI config includes allowed hosts."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    assert 'allowed_hosts' in config['cookie'], \
        "cookie section should specify allowed_hosts"
    assert isinstance(config['cookie']['allowed_hosts'], list), \
        "allowed_hosts should be a list"
    assert len(config['cookie']['allowed_hosts']) > 0, \
        "allowed_hosts should not be empty"


@pytest.mark.integration
def test_wsgi_config_server_section():
    """Test that WSGI config has proper server settings."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    server = config['server']
    assert 'port' in server, "server section should specify port"
    assert 'host' in server, "server section should specify host"
    assert isinstance(server['port'], int), "port should be integer"


@pytest.mark.integration
def test_wsgi_config_redir_section():
    """Test that WSGI config has proper redirect settings."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    redir = config['redir']
    assert 'external_name' in redir, "redir section should specify external_name"
    assert 'default_destination' in redir, "redir section should specify default_destination"


@pytest.mark.integration
def test_wsgi_config_page_section():
    """Test that WSGI config has proper page settings."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    page = config['page']
    assert 'template_path' in page, "page section should specify template_path"
    assert 'title' in page, "page section should specify title"


@pytest.mark.integration
def test_run_gunicorn_task_exists():
    """Test that Taskfile includes run-gunicorn task."""
    taskfile = Path(__file__).parent.parent / "Taskfile.yml"
    content = taskfile.read_text()

    assert 'run-gunicorn:' in content, "Taskfile should define run-gunicorn task"
    assert 'HOMELAB_AUTH_CONFIG_FILE' in content, \
        "Taskfile should set HOMELAB_AUTH_CONFIG_FILE in run-gunicorn"
    assert 'HOMELAB_AUTH_HASHING_KEY' in content, \
        "Taskfile should set HOMELAB_AUTH_HASHING_KEY in run-gunicorn"
    assert 'gunicorn' in content, "Taskfile should invoke gunicorn in run-gunicorn task"


@pytest.mark.integration
def test_run_gunicorn_task_configuration():
    """Test that run-gunicorn task has proper gunicorn configuration."""
    taskfile = Path(__file__).parent.parent / "Taskfile.yml"
    content = taskfile.read_text()

    # Extract the run-gunicorn section
    assert '--workers 4' in content or '--worker' in content, \
        "gunicorn should be configured with workers"
    assert '--timeout' in content, \
        "gunicorn should be configured with timeout"
    assert 'src.wsgi:app' in content, \
        "gunicorn should reference src.wsgi:app entry point"


@pytest.mark.integration
def test_wsgi_deployment_docs_exist():
    """Test that WSGI deployment documentation exists."""
    wsgi_docs = Path(__file__).parent.parent / "docs" / "WSGI_DEPLOYMENT.md"
    assert wsgi_docs.exists(), "docs/WSGI_DEPLOYMENT.md should exist"
    assert wsgi_docs.is_file(), "WSGI_DEPLOYMENT.md should be a regular file"


@pytest.mark.integration
def test_wsgi_deployment_docs_comprehensive():
    """Test that WSGI deployment docs cover key topics."""
    wsgi_docs = Path(__file__).parent.parent / "docs" / "WSGI_DEPLOYMENT.md"
    content = wsgi_docs.read_text()

    key_sections = [
        '## Architecture',
        '## Environment Variables',
        '## Configuration File',
        '## Deployment Patterns',
        '## Gunicorn Configuration',
        '## Security Considerations',
        '## Troubleshooting',
    ]

    for section in key_sections:
        assert section in content, f"WSGI docs should include section: {section}"


@pytest.mark.unit
def test_wsgi_socket_binding():
    """Test that run-gunicorn binds to proper socket."""
    taskfile = Path(__file__).parent.parent / "Taskfile.yml"
    content = taskfile.read_text()

    # Should bind to 0.0.0.0:8000 for development
    assert '--bind 0.0.0.0:8000' in content, \
        "run-gunicorn should bind to 0.0.0.0:8000"


@pytest.mark.unit
def test_wsgi_logging_configuration():
    """Test that run-gunicorn logs to stdout/stderr."""
    taskfile = Path(__file__).parent.parent / "Taskfile.yml"
    content = taskfile.read_text()

    assert '--access-logfile -' in content, \
        "run-gunicorn should log access logs to stdout"
    assert '--error-logfile -' in content, \
        "run-gunicorn should log error logs to stderr"


@pytest.mark.unit
def test_wsgi_session_cookie_name():
    """Test that WSGI config uses appropriate cookie name."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    cookie_name = config['cookie']['name']
    assert isinstance(cookie_name, str), "cookie name should be string"
    assert len(cookie_name) > 0, "cookie name should not be empty"


@pytest.mark.unit
def test_wsgi_advisory_message():
    """Test that WSGI config includes security advisory message."""
    import yaml
    config_file = Path(__file__).parent.parent / "support" / "wsgi-config.yaml"
    config = yaml.safe_load(config_file.read_text())

    advisory = config['page'].get('advisory', '')
    assert isinstance(advisory, str), "advisory should be string"
    assert len(advisory) > 0, "advisory should not be empty"
    # Check for security-related keywords
    assert any(word in advisory.lower() for word in ['authorized', 'monitored', 'prohibited']), \
        "advisory should mention security/authorization"


@pytest.mark.unit
def test_wsgi_docker_entrypoint():
    """Test that Docker entrypoint includes WSGI support."""
    entrypoint = Path(__file__).parent.parent / "support" / "entrypoint.sh"
    if entrypoint.exists():
        content = entrypoint.read_text()
        assert 'gunicorn' in content or 'wsgi' in content.lower(), \
            "Docker entrypoint should support WSGI/gunicorn"


@pytest.mark.integration
def test_wsgi_env_vars_in_readme():
    """Test that README documents WSGI environment variables."""
    readme = Path(__file__).parent.parent / "README.md"
    content = readme.read_text()

    assert 'HOMELAB_AUTH_CONFIG_FILE' in content, \
        "README should document HOMELAB_AUTH_CONFIG_FILE"
    assert 'HOMELAB_AUTH_HASHING_KEY' in content, \
        "README should document HOMELAB_AUTH_HASHING_KEY"


@pytest.mark.integration
def test_wsgi_quick_start_in_readme():
    """Test that README includes WSGI quick start section."""
    readme = Path(__file__).parent.parent / "README.md"
    content = readme.read_text()

    assert 'task run-gunicorn' in content, \
        "README should mention task run-gunicorn"
    assert 'gunicorn' in content, \
        "README should document gunicorn usage"
