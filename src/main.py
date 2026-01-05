#!/usr/bin/env python3
"""
homelab-auth script entrypoint
"""

import sys
import json
import yaml
import bcrypt
import hashlib
from pathlib import Path
from flask import Flask, request, make_response, redirect, render_template_string
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from passlib.apache import HtpasswdFile
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from urllib.parse import urlparse
import logging

# --- FIX: Passlib/Bcrypt 4.0+ Compatibility ---
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("obj", (object,), {"__version__": bcrypt.__version__})

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16KB max request body
logger = logging.getLogger(__name__)


def validate_file_path(file_path: str, file_type: str = "file") -> Path:
    """
    Validate that a file path is safe and exists.

    Args:
        file_path: Path to validate
        file_type: Description of file type for error messages

    Returns:
        Resolved Path object

    Raises:
        ValueError: If path is invalid, outside current directory, or does not exist
    """
    try:
        path = Path(file_path).resolve()
        cwd = Path.cwd().resolve()

        # Ensure path is within current working directory (prevent directory traversal)
        if not str(path).startswith(str(cwd)):
            raise ValueError(f"{file_type} path traversal detected: {file_path}")

        # Check if file exists
        if not path.exists():
            raise ValueError(f"{file_type} does not exist: {file_path}")

        # Check if it's a file, not a directory
        if not path.is_file():
            raise ValueError(f"{file_type} is not a regular file: {file_path}")

        # Check file permissions (readable)
        if not path.stat().st_mode & 0o400:
            raise ValueError(f"{file_type} is not readable: {file_path}")

        logger.info("Validated %s path: %s", file_type, path)
        return path

    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to validate {file_type} path '{file_path}': {e}")


def load_config(config_file: str = "config.yaml") -> dict:
    """
    Load and validate configuration file.

    Args:
        config_file: Path to configuration file

    Returns:
        Parsed YAML configuration dictionary

    Raises:
        SystemExit: If config file is invalid or cannot be loaded
    """
    try:
        config_path = validate_file_path(config_file, "config")
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except ValueError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error("Invalid YAML in config file: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to load config file: %s", e)
        sys.exit(1)


def validate_and_init_hashing_string(cfg: dict) -> str:
    """
    Validate auth.hashing_string is configured.
    Returns the hashing string to use.
    Falls back to SHA1 hash of config if not explicitly configured.

    Args:
        cfg: Configuration dictionary

    Returns:
        The hashing string to use for signing
    """
    hashing_string = cfg.get("auth", {}).get("hashing_string")

    if not hashing_string:
        # Fallback to SHA1 hash of config data as a system property
        cfg_str = json.dumps(cfg, sort_keys=True)
        hashing_string = hashlib.sha1(cfg_str.encode()).hexdigest()
        logger.warning(
            "auth.hashing_string is not configured. "
            "Using SHA1 hash of config as fallback."
        )

    return hashing_string


def load_htpasswd_file(htpasswd_path: str) -> HtpasswdFile:
    """
    Load and validate htpasswd file.

    Args:
        htpasswd_path: Path to htpasswd file

    Returns:
        HtpasswdFile object

    Raises:
        SystemExit: If htpasswd file is invalid or cannot be loaded
    """
    try:
        path = validate_file_path(htpasswd_path, "htpasswd")
        return HtpasswdFile(str(path))
    except ValueError as e:
        logger.error("Htpasswd configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to load htpasswd file: %s", e)
        sys.exit(1)


cfg = load_config()
hashing_string = validate_and_init_hashing_string(cfg)

# Log only the hash and length of the hashing_string for audit purposes,
# never log the actual value to prevent exposure in DEBUG logs or exception tracebacks
_key_hash = hashlib.sha256(hashing_string.encode()).hexdigest()[:16]
_key_len = len(hashing_string)
logger.debug(
    "Session signing key initialized (length=%d, hash=%s)", _key_len, _key_hash
)

# Create signer immediately and clear the key material from module scope
# to prevent accidental exposure in exception tracebacks or log statements
signer = TimestampSigner(hashing_string)
del hashing_string  # Explicitly remove the cryptographic material from module scope

users = load_htpasswd_file(cfg["auth"]["htpasswd_path"])


def get_cookie_subdomain():
    """
    Extract subdomain from a hostname.
    Validates X-Forwarded-Host against allowed_hosts whitelist.
    Returns: '.sub.domain.tld' or None
    """
    conf_domain = cfg.get("cookie", {}).get("domain")
    if conf_domain:
        return conf_domain

    allowed_hosts = cfg.get("cookie", {}).get("allowed_hosts", [])
    hostname = request.headers.get("X-Forwarded-Host", request.host).lower()

    # If whitelist exists, validate the hostname
    if allowed_hosts:
        # Check if hostname matches or is a subdomain of allowed hosts
        is_allowed = False
        for allowed in allowed_hosts:
            if hostname == allowed.lower() or hostname.endswith("." + allowed.lower()):
                is_allowed = True
                break

        if not is_allowed:
            # Fallback to request.host if X-Forwarded-Host does not match
            hostname = request.host.lower()

    parts = hostname.split(".")
    if len(parts) < 2:
        return None

    # Extract base domain (everything except first subdomain)
    domain = ".".join(parts[1:])
    return f".{domain}"


def is_safe_redirect(target_url):
    """
    Validate that the redirect URL's domain is within the cookie domain.
    Returns True if safe, False otherwise.
    """
    if target_url.startswith("/"):
        return True  # Relative URLs are safe

    try:
        parsed = urlparse(target_url)
        target_host = parsed.netloc.lower()
        cookie_domain = get_cookie_subdomain()

        if not cookie_domain:
            return False

        # Remove leading dot from cookie domain for comparison
        cookie_domain_clean = cookie_domain.lstrip(".")

        # Check if target host is the cookie domain or a subdomain of it
        if target_host == cookie_domain_clean or target_host.endswith(cookie_domain):
            return True

        return False
    except Exception:
        logger.warning("Detected unsafe redirect URL: %s", target_url)
        return False


def render_login_template(title: str, feedback: str = None) -> str:
    """
    Render the login page template.

    Attempts to load and render a Jinja2 template from the configured
    page.template_path. If the template path is not configured or the file
    cannot be loaded, falls back to the built-in LOGIN_FORM template.

    Args:
        title: Page title to pass to the template
        feedback: Optional error or feedback message to display

    Returns:
        Rendered HTML string
    """
    template_path = cfg.get("page", {}).get("template_path")
    advisory = cfg.get("page", {}).get("advisory")

    if template_path:
        try:
            # Validate the template path for security
            path = validate_file_path(template_path, "template")
            template_dir = str(path.parent)
            template_name = path.name

            # Create Jinja2 environment and load template
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template(template_name)
            logger.info("Loaded login template from: %s", path)
            return template.render(title=title, advisory=advisory, feedback=feedback)

        except ValueError as e:
            logger.warning(
                "Template validation failed: %s. Using fallback template.", e
            )
        except TemplateNotFound as e:
            logger.warning("Template not found: %s. Using fallback template.", e)
        except Exception as e:
            logger.warning(
                "Failed to load template from %s: %s. Using fallback template.",
                template_path,
                e,
            )

    # Fallback to built-in template
    logger.debug("Using built-in LOGIN_FORM template")
    return render_template_string(
        LOGIN_FORM, title=title, advisory=advisory, feedback=feedback
    )


# HTML Template (Keep same as previous response)
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head><title>{{ title | escape }}</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px;">
    <div style="border: 1px solid #ccc; padding: 20px; border-radius: 8px; max-width: 400px;">
        <h2>{{ title | escape }}</h2>
        <form method="post">
            <input type="text" name="user" placeholder="Username" required><br><br>
            <input type="password" name="pw" placeholder="Password" required><br><br>
            <button type="submit" style="width: 100%;">Login</button>
        </form>
        {% if feedback %}
        <div style="margin-top: 20px; padding: 15px; background-color: #ffcccc; border-left: 4px solid #cc0000; border-radius: 4px; color: #990000;">
            <p style="margin: 8px 0 0 0; font-size: 14px;">{{ feedback | escape }}</p>
        </div>
        {% endif %}
        {% if advisory %}
        <div style="margin-top: 20px; padding: 15px; background-color: #f0f8ff; border-left: 4px solid #0066cc; border-radius: 4px; color: #333;">
            <p style="margin: 8px 0 0 0; font-size: 14px;">{{ advisory | escape }}</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def redir():
    domain = get_cookie_subdomain()
    target_url = request.args.get(
        "rd", f"https://{cfg['redir']['default_destination']}{domain}"
    )

    # Validate redirect URL is within allowed domain
    if not is_safe_redirect(target_url):
        target_url = f"https://{cfg['redir']['default_destination']}{domain}"

    login_url = f"https://{cfg['redir']['external_name']}{domain}"
    return redirect(f"{login_url}/login?rd={target_url}", code=307)


@app.route("/login", methods=["GET", "POST"])
def login():
    domain = get_cookie_subdomain()
    target_url = request.args.get(
        "rd", f"https://{cfg['redir']['default_destination']}{domain}"
    )

    # Validate redirect URL is within allowed domain
    if not is_safe_redirect(target_url):
        target_url = f"https://{cfg['redir']['default_destination']}{domain}"

    # --- Check for already logged-in user (valid session cookie) ---
    signed_cookie = request.cookies.get(cfg["cookie"]["name"])
    if signed_cookie:
        try:
            username = signer.unsign(
                signed_cookie, max_age=cfg["auth"]["session_max_age"]
            )
            # If valid session, redirect immediately
            return redirect(target_url)
        except (BadSignature, SignatureExpired):
            pass  # Continue to login form

    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("pw", "")

        # Validate inputs are present and within reasonable limits
        if not username or not password:
            logger.warning(
                "Login attempt with missing credentials from %s", request.remote_addr
            )
            return render_login_template(
                cfg["page"]["title"], feedback="Invalid Credentials."
            ), 401

        # Prevent oversized input attacks
        if len(username) > 255 or len(password) > 4096:
            logger.warning(
                "Login attempt with oversized input from %s", request.remote_addr
            )
            return render_login_template(
                cfg["page"]["title"], feedback="Invalid Credentials."
            ), 401

        if users.check_password(username, password):
            logger.info(
                "Successful login for user: %s from %s", username, request.remote_addr
            )
            signed_val = signer.sign(username).decode("utf-8")

            resp = make_response(redirect(target_url))
            resp.set_cookie(
                key=cfg["cookie"]["name"],
                value=signed_val,
                domain=domain,
                max_age=cfg["auth"]["session_max_age"],
                httponly=cfg["cookie"]["httponly"],
                secure=cfg["cookie"]["secure"],
                samesite=cfg["cookie"]["samesite"],
            )
            return resp

        logger.warning(
            "Failed login attempt for user: %s from %s", username, request.remote_addr
        )
        return render_login_template(
            cfg["page"]["title"], feedback="Invalid Credentials."
        ), 401

    return render_login_template(cfg["page"]["title"])


@app.route("/verify", methods=["GET"])
def verify():
    signed_cookie = request.cookies.get(cfg["cookie"]["name"])
    if not signed_cookie:
        return "Unauthorized", 401

    try:
        signer.unsign(signed_cookie, max_age=cfg["auth"]["session_max_age"])
        return "OK", 200
    except (BadSignature, SignatureExpired):
        return "Invalid Session", 401


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Logout endpoint that invalidates the session cookie."""
    domain = get_cookie_subdomain()
    target_url = request.args.get(
        "rd", f"https://{cfg['redir']['default_destination']}{domain}"
    )

    # Validate redirect URL is within allowed domain
    if not is_safe_redirect(target_url):
        target_url = f"https://{cfg['redir']['default_destination']}{domain}"

    logger.info("User logout from %s", request.remote_addr)

    resp = make_response(redirect(target_url))
    resp.set_cookie(
        key=cfg["cookie"]["name"],
        value="logged-out",
        domain=domain,
        max_age=0,
        httponly=cfg["cookie"]["httponly"],
        secure=cfg["cookie"]["secure"],
        samesite=cfg["cookie"]["samesite"],
    )
    return resp


@app.errorhandler(400)
def handle_bad_request(error):
    """Handle malformed requests gracefully."""
    logger.warning("Bad request received: %s", error)
    return "Bad Request", 400


@app.errorhandler(408)
def handle_request_timeout(error):
    """Handle request timeout."""
    logger.warning("Request timeout: %s", error)
    return "Request Timeout", 408


@app.errorhandler(413)
def handle_payload_too_large(error):
    """Handle oversized request body."""
    logger.warning("Payload too large: %s", error)
    return "Payload Too Large", 413


@app.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors gracefully."""
    logger.error("Internal server error: %s", error)
    return "Internal Server Error", 500


@app.route("/healthz", methods=["GET"])
def healthz():
    """Service health check endpoint for Docker and Traefik."""
    return {"status": "healthy"}, 200


@app.route("/done", methods=["GET"])
def done():
    """Successful login landing page."""
    return render_template_string(
        "<h1>Login Successful</h1><p>You can now close this window.</p>"
    )


if __name__ == "__main__":
    app.run(host=cfg["server"]["host"], port=cfg["server"]["port"])
