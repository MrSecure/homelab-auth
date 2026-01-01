#!/usr/bin/env python3
"""
homelab-auth script entrypoint
"""

import secrets
import sys
import yaml
import bcrypt
from pathlib import Path
from flask import Flask, request, make_response, redirect, render_template_string
from passlib.apache import HtpasswdFile
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from urllib.parse import urlparse
import logging

# --- FIX: Passlib/Bcrypt 4.0+ Compatibility ---
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("obj", (object,), {"__version__": bcrypt.__version__})

app = Flask(__name__)
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
    Validate auth.hashing_string. If null/empty, generate a random one.
    Returns the hashing string to use.
    """
    hashing_string = cfg.get("auth", {}).get("hashing_string")

    if not hashing_string:
        # Generate a cryptographically secure random string
        hashing_string = secrets.token_urlsafe(32)
        logger.warning(
            "Generated random hashing_string at startup. Set auth.hashing_string in config.yaml for persistent sessions."
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
signer = TimestampSigner(hashing_string)
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


# HTML Template (Keep same as previous response)
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head><title>{{ title | escape }}</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px;">
    <div style="border: 1px solid #ccc; padding: 20px; border-radius: 8px;">
        <h2>{{ title | escape }}</h2>
        <form method="post">
            <input type="text" name="user" placeholder="Username" required><br><br>
            <input type="password" name="pw" placeholder="Password" required><br><br>
            <button type="submit" style="width: 100%;">Login</button>
        </form>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def redir():
    target_url = request.args.get("rd", "/done")

    # Validate redirect URL is within allowed domain
    if not is_safe_redirect(target_url):
        target_url = "/done"

    login_url = f"https://{cfg['redir']['external_name']}{cfg['cookie']['domain']}"
    return redirect(f"{login_url}/login?rd={target_url}", code=307)


@app.route("/login", methods=["GET", "POST"])
def login():
    target_url = request.args.get(
        "rd", f"https://{cfg['redir']['default_destination']}{cfg['cookie']['domain']}"
    )

    # Validate redirect URL is within allowed domain
    if not is_safe_redirect(target_url):
        target_url = (
            f"https://{cfg['redir']['default_destination']}{cfg['cookie']['domain']}"
        )

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
            return "Invalid Credentials", 401

        # Prevent oversized input attacks
        if len(username) > 255 or len(password) > 4096:
            logger.warning(
                "Login attempt with oversized input from %s", request.remote_addr
            )
            return "Invalid Credentials", 401

        if users.check_password(username, password):
            logger.info(
                "Successful login for user: %s from %s", username, request.remote_addr
            )
            signed_val = signer.sign(username).decode("utf-8")
            domain = get_cookie_subdomain()

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
        return "Invalid Credentials", 401

    return render_template_string(LOGIN_FORM, title=cfg["page"]["title"])


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
