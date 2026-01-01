#!/usr/bin/env python3
"""
homelab-auth script entrypoint
"""

import yaml
import bcrypt
from flask import Flask, request, make_response, redirect, render_template_string
from passlib.apache import HtpasswdFile
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired

# --- FIX: Passlib/Bcrypt 4.0+ Compatibility ---
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("obj", (object,), {"__version__": bcrypt.__version__})

app = Flask(__name__)


def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


cfg = load_config()
signer = TimestampSigner(cfg["auth"]["hashing_string"])
users = HtpasswdFile(cfg["auth"]["htpasswd_path"])


def get_cookie_subdomain():
    """
    Extract subdomain from a hostname.
    Example: 'workbook.abce1234.sec540.cloud'
    Returns: '.abce1234.sec540.cloud'
    """

    conf_domain = cfg.get("cookie", {}).get("domain")
    if conf_domain:
        return conf_domain

    hostname = request.headers.get("X-Forwarded-Host", request.host)
    parts = hostname.split(".")

    conf_domain = cfg.get("cookie", {}).get("domain")
    if conf_domain:
        return conf_domain

    if len(parts) < 2:
        return None

    domain = ".".join(parts[1:])

    return f".{domain}"


# HTML Template (Keep same as previous response)
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head><title>{{ title }}</title></head>
<body style="font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px;">
    <div style="border: 1px solid #ccc; padding: 20px; border-radius: 8px;">
        <h2>{{ title }}</h2>
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
    login_url = f"https://{cfg['redir']['external_name']}{cfg['cookie']['domain']}"
    return redirect(f"{login_url}/login?rd={target_url}", code=307)


@app.route("/login", methods=["GET", "POST"])
def login():
    target_url = request.args.get(
        "rd", f"https://{cfg['redir']['default_destination']}{cfg['cookie']['domain']}"
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
        username = request.form.get("user")
        password = request.form.get("pw")

        if users.check_password(username, password):
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
