# Security Review: homelab-auth Authentication Flow

**Date**: January 1, 2026 (Updated)
**Scope**: Authentication flow security analysis
**Status**: Review completed with one critical fix applied

---

## Executive Summary

The homelab-auth application implements a simple OIDC-like authentication service using Flask with session token signing via `itsdangerous`. Overall, the security posture is **reasonably good** with some areas for improvement. The code demonstrates awareness of common security concerns. A critical fix has been applied to prevent cryptographic key exposure in logs.

**Latest Update**: The cryptographic material (`hashing_string`) is now immediately deleted from module scope after use, preventing accidental exposure in DEBUG logs or exception tracebacks.

---

## Critical Issues (Resolved)

### 1. **Cryptographic Key Material Exposed in Logs and Version Control** ✅ FIXED

**Location**: [src/main.py](src/main.py#L145-L152)

**Issue**: The `hashing_string` (used as the signing key for session tokens) was remaining in module scope after initialization.

**Previous Risk**:
- Exception tracebacks could expose the key if an error occurred after initialization
- Module-level variables can be inspected in DEBUG scenarios
- Risk of accidental logging of key material

**Fix Applied**:
```python
# Log only the hash and length of the hashing_string for audit purposes,
# never log the actual value to prevent exposure in DEBUG logs or exception tracebacks
_key_hash = hashlib.sha256(hashing_string.encode()).hexdigest()[:16]
_key_len = len(hashing_string)
logger.debug("Session signing key initialized (length=%d, hash=%s)", _key_len, _key_hash)

# Create signer immediately and clear the key material from module scope
# to prevent accidental exposure in exception tracebacks or log statements
signer = TimestampSigner(hashing_string)
del hashing_string  # Explicitly remove the cryptographic material from module scope
```

**Benefits**:
- ✅ Key material is removed from module scope immediately after use
- ✅ Only hash and length are logged for audit purposes
- ✅ Prevents accidental exposure in exception tracebacks
- ✅ No impact on functionality - signer is already initialized
- ✅ Minimal performance overhead

**Additional Recommendations**:
- Ensure config.yaml is not world-readable (600 permissions recommended)
- Consider key rotation for long-lived deployments (enterprise feature)

---

### 2. **Missing CSRF Protection on Login Form** 🔴 HIGH

**Location**: [src/main.py](src/main.py#L246-L290)

**Issue**: The login form submission has no CSRF token protection.

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    # ...
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("pw", "")
        # No CSRF token validation
```

**Risks**:
- Attacker can trick authenticated users into submitting login forms to attacker-controlled endpoints
- Cross-site request forgery attacks are possible
- Users on multiple tabs could unknowingly submit credentials

**Recommendations**:
- Implement CSRF protection using `flask-wtf` or `itsdangerous` for token generation
- Add CSRF token to login form
- Validate CSRF token on POST

**Example Fix**:
```python
# Add to imports
import secrets

# Generate token per-request
@app.route("/login", methods=["GET", "POST"])
def login():
    csrf_token = request.args.get("csrf") or secrets.token_urlsafe(32)

    if request.method == "POST":
        provided_token = request.form.get("csrf_token", "")
        if not provided_token or provided_token != session.get("csrf_token"):
            logger.warning("CSRF token validation failed from %s", request.remote_addr)
            return "Invalid Request", 403
```

---

## High-Severity Issues

### 3. **Insufficient Rate Limiting on Login Endpoint** 🟡 MEDIUM-HIGH

**Location**: [src/main.py](src/main.py#L246-L290)

**Issue**: No rate limiting on login attempts. An attacker can brute-force credentials.

```python
if users.check_password(username, password):
    # No rate limiting, retry limit, or account lockout
    logger.info("Successful login for user: %s from %s", username, request.remote_addr)
```

**Risks**:
- Credential stuffing / brute force attacks
- Denial of service on login endpoint
- No protection for weak passwords

**Recommendations**:
- Implement rate limiting per IP address (e.g., Flask-Limiter)
- Implement account lockout after N failed attempts
- Add exponential backoff
- Consider implementing CAPTCHA after multiple failures

**Example Fix**:
```bash
# Add to dependencies
pip add flask-limiter redis
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # 5 login attempts per minute per IP
def login():
    # ...
```

---

### 4. **Timing Attack Vulnerability in Password Comparison** 🟡 MEDIUM

**Location**: [src/main.py](src/main.py#L276)

**Issue**: `passlib`'s `check_password()` should be timing-safe, but this depends on passlib version.

```python
if users.check_password(username, password):
```

**Risks**:
- Timing differences in password comparison could leak information about valid usernames
- Attacker can potentially deduce valid usernames through timing analysis

**Current Status**: ✅ **PASSLIB LIKELY SAFE**
- `passlib` >= 1.7.4 implements constant-time comparison
- bcrypt comparison is timing-safe by design

**Recommendations**:
- Verify passlib version is recent (✅ already using 1.7.4+)
- Keep passlib updated
- Consider always adding a fixed delay to login responses

---

### 5. **Default Redirect Allows Open Redirect on Configuration Error** 🟡 MEDIUM

**Location**: [src/main.py](src/main.py#L225-L240)

**Issue**: If `cookie.domain` validation fails, the redirect defaults to a potentially unsafe destination.

```python
if not is_safe_redirect(target_url):
    target_url = (
        f"https://{cfg['redir']['default_destination']}{cfg['cookie']['domain']}"
    )
    # If cookie.domain is misconfigured, this could redirect anywhere
```

**Risks**:
- Misconfiguration could lead to open redirect vulnerability
- If config parsing fails, default values might be unsafe

**Recommendations**:
- Validate all redirect URLs more strictly
- Add strict domain whitelist enforcement
- Log all redirect attempts (especially rejected ones)

---

## Medium-Severity Issues

### 6. **Session Token Validation Missing Hostname Binding** 🟡 MEDIUM

**Location**: [src/main.py](src/main.py#L303-313)

**Issue**: Session tokens are not bound to the hostname/browser. A token could be used across different hosts.

```python
@app.route("/verify", methods=["GET"])
def verify():
    signed_cookie = request.cookies.get(cfg["cookie"]["name"])
    if not signed_cookie:
        return "Unauthorized", 401

    try:
        signer.unsign(signed_cookie, max_age=cfg["auth"]["session_max_age"])
        return "OK", 200
```

**Risks**:
- If token is intercepted/stolen, it can be used from any location
- No protection against token theft via network sniffing (though HTTPS helps)
- No IP binding or browser fingerprinting

**Recommendations**:
- Include request metadata in signed data (IP, User-Agent hash)
- Validate request metadata matches on unsign
- Add optional IP binding in configuration

**Example Enhancement**:
```python
def get_request_hash():
    """Generate hash of request characteristics for token binding."""
    import hashlib
    data = f"{request.remote_addr}:{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]

@app.route("/login", methods=["GET", "POST"])
def login():
    # ...
    if users.check_password(username, password):
        req_hash = get_request_hash()
        signed_val = signer.sign(f"{username}:{req_hash}").decode("utf-8")

@app.route("/verify", methods=["GET"])
def verify():
    try:
        data = signer.unsign(signed_cookie, max_age=max_age)
        username, req_hash = data.split(":")
        current_hash = get_request_hash()
        if req_hash != current_hash:
            return "Session invalid for this location", 401
        return "OK", 200
```

---

### 7. **X-Forwarded-Host Header Injection Risk** 🟡 MEDIUM

**Location**: [src/main.py](src/main.py#L155-176)

**Issue**: The code trusts `X-Forwarded-Host` header without strict validation. If proxy is misconfigured, attacker could inject malicious hosts.

```python
def get_cookie_subdomain():
    allowed_hosts = cfg.get("cookie", {}).get("allowed_hosts", [])
    hostname = request.headers.get("X-Forwarded-Host", request.host).lower()

    if allowed_hosts:
        is_allowed = False
        for allowed in allowed_hosts:
            if hostname == allowed.lower() or hostname.endswith("." + allowed.lower()):
                is_allowed = True
                break
```

**Current Status**: ✅ **MOSTLY SAFE**
- Whitelist validation is present
- Fallback to `request.host` on invalid header
- Case-insensitive comparison is good

**Recommendations**:
- Add validation that X-Forwarded-Host header only comes from trusted proxies
- Consider adding `X-Forwarded-Proto` validation
- Log suspicious X-Forwarded-Host values
- Reject headers with invalid characters

**Example Enhancement**:
```python
TRUSTED_PROXIES = {"10.0.0.1", "10.0.0.2"}  # Add this to config

def get_cookie_subdomain():
    # Only trust X-Forwarded-Host from known proxies
    if request.remote_addr not in TRUSTED_PROXIES:
        hostname = request.host.lower()
    else:
        hostname = request.headers.get("X-Forwarded-Host", request.host).lower()
```

---

### 8. **Missing Security Headers** 🟡 MEDIUM

**Location**: [src/main.py](src/main.py) - Login template

**Issue**: Response headers lack security headers that prevent common attacks.

```python
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head><title>{{ title | escape }}</title></head>
```

**Missing Headers**:
- `Content-Security-Policy` (CSP) - prevents XSS
- `X-Content-Type-Options: nosniff` - prevents MIME type sniffing
- `X-Frame-Options: DENY` - prevents clickjacking
- `X-XSS-Protection: 1; mode=block` - legacy XSS protection
- `Strict-Transport-Security` (HSTS) - enforces HTTPS

**Recommendations**:
```python
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

## Low-Severity Issues

### 9. **Verbose Error Messages May Leak Information** 🟢 LOW

**Location**: [src/main.py](src/main.py#L269-280)

**Issue**: Login endpoint returns same error message for all failures, which is good. However, logging includes the username.

```python
logger.warning(
    "Failed login attempt for user: %s from %s", username, request.remote_addr
)
```

**Risks**:
- Username enumeration through logs
- Logs could be exposed in monitoring systems

**Recommendations**:
- Log failed attempts with IP and hash of username, not the plaintext username
- Implement log rotation and restricted access to logs

```python
import hashlib
username_hash = hashlib.sha256(username.encode()).hexdigest()[:8]
logger.warning(
    "Failed login attempt (user: %s) from %s", username_hash, request.remote_addr
)
```

---

### 10. **Missing Logout Endpoint** 🟢 LOW

**Location**: [src/main.py](src/main.py) - No logout route

**Issue**: There is no way to explicitly invalidate a session token.

**Risks**:
- Users cannot manually log out
- Tokens must expire naturally (12 hours by default)
- Compromised tokens remain valid until expiration

**Recommendations**:
```python
@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Invalidate user session."""
    resp = make_response(redirect("/login"))
    resp.set_cookie(
        key=cfg["cookie"]["name"],
        value="",
        max_age=0,  # Immediately expire the cookie
        httponly=cfg["cookie"]["httponly"],
        secure=cfg["cookie"]["secure"],
        samesite=cfg["cookie"]["samesite"],
    )
    logger.info("User logged out from %s", request.remote_addr)
    return resp
```

---

### 11. **File Path Validation Logic Could Be Stricter** 🟢 LOW

**Location**: [src/main.py](src/main.py#L25-60)

**Issue**: Directory traversal protection is good, but path validation is only checked at startup.

```python
if not str(path).startswith(str(cwd)):
    raise ValueError(f"{file_type} path traversal detected: {file_path}")
```

**Current Status**: ✅ **SAFE**
- Logic is correct and prevents directory traversal
- Resolves symlinks appropriately
- Checked at module load time

**Recommendations**:
- Consider re-validating paths if they come from user input in future features
- Add logging of loaded file paths for audit purposes

---

### 12. **Session Max Age Default is 12 Hours** 🟢 LOW

**Location**: [support/config.yaml](support/config.yaml#L7)

**Issue**: Default session timeout is relatively long (12 hours).

```yaml
session_max_age: 43200  # 12 hours in seconds
```

**Risks**:
- Long window for token compromise/replay
- For high-security applications, this may be excessive

**Recommendations**:
- Consider reducing to 4-6 hours for security-sensitive environments
- Add configuration option for different timeout levels
- Log session expirations

---

## Best Practices: ✅ Observed

The following security best practices are **correctly implemented**:

1. ✅ **Password verification uses passlib** - Strong cryptographic hashing (bcrypt)
2. ✅ **Input validation on credentials** - Length limits prevent oversized inputs
3. ✅ **Secure cookie flags** - `HttpOnly`, `Secure`, `SameSite=Lax` configured
4. ✅ **Session token signing** - Uses `itsdangerous.TimestampSigner`
5. ✅ **Timestamp validation** - Max age is enforced on tokens
6. ✅ **Redirect validation** - Basic domain-based validation on redirect URLs
7. ✅ **Logging of security events** - Failed/successful logins are logged
8. ✅ **File path validation** - Directory traversal protection in place
9. ✅ **YAML parsing** - Uses `safe_load()` instead of unsafe `load()`
10. ✅ **No hardcoded secrets** - Uses config file and environment variables
11. ✅ **Cryptographic material protection** - Key material deleted from module scope after use

---

## Configuration Security

### Configuration File Protection

The `config.yaml` file should have restricted permissions:

```bash
# Recommended file permissions
chmod 600 /app/config.yaml
chown app:app /app/config.yaml

# Or in Dockerfile:
RUN chmod 600 /app/config.yaml && \
    chown app:app /app/config.yaml
```

---

## Testing Recommendations

Add security-focused tests:

```python
# tests/test_security.py

@pytest.mark.unit
def test_csrf_token_required_on_login():
    """Login POST must require valid CSRF token."""
    # Test that POST without CSRF token returns 403

@pytest.mark.unit
def test_rate_limiting_on_login():
    """Verify rate limiting protects against brute force."""
    # Test that 6 login attempts in 1 minute are blocked

@pytest.mark.unit
def test_timing_attack_mitigation():
    """Login failures should take consistent time."""
    # Test that invalid user vs wrong password take ~same time

@pytest.mark.unit
def test_session_token_not_in_logs():
    """Session tokens must not appear in logs."""
    # Verify logs don't contain token values

@pytest.mark.unit
def test_xss_prevention_in_template():
    """Template must escape user-controlled values."""
    # Test with username="<script>alert(1)</script>"
```

---

## Deployment Security Checklist

- [ ] Run container as non-root user
- [ ] Set `config.yaml` permissions to 600
- [ ] Use `Secure` flag for cookies in production (HTTPS only)
- [ ] Implement rate limiting at reverse proxy or application level
- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Use strong `hashing_string` (current 32 bytes is good)
- [ ] Set up log aggregation and monitoring
- [ ] Regular security updates for dependencies
- [ ] Restrict network access to auth service
- [ ] Monitor failed login attempts for attacks

---

## Dependencies Security

**Current** [pyproject.toml](pyproject.toml):
```toml
dependencies = [
    "Flask>=3.0.0",
    "PyYAML>=6.0.1",
    "passlib>=1.7.4",
    "bcrypt==3.2.2",
    "itsdangerous>=2.1.0",
    "gunicorn>=21.2.0"
]
```

**Recommendations**:
- ✅ `bcrypt==3.2.2` - Pinned version is good (prevents breaking changes)
- ✅ `passlib>=1.7.4` - Modern version with timing-safe comparison
- ✅ `itsdangerous>=2.1.0` - Recent version with security fixes
- ⚠️ `Flask>=3.0.0` - Should consider pin to `>=3.0,<4.0` to prevent major version surprises
- ⚠️ Implement automated dependency scanning (Dependabot, Renovate) - ✅ Already configured

---

## Summary of Issues by Severity

| Severity | Count | Issues |
|----------|-------|--------|
| 🔴 HIGH | 1 | CSRF protection *(Key exposure ✅ FIXED)* |
| 🟡 MEDIUM | 5 | Rate limiting, Timing attacks, Redirects, Session binding, X-Forwarded-Host, Security headers |
| 🟢 LOW | 5 | Error messages, Logout endpoint, Path validation, Session timeout, Dependency versions |

---

## Priority Remediation Plan

**Phase 1 (Immediate - Critical)** ✅ *1/2 Complete*:
1. ✅ **COMPLETED**: Remove cryptographic material from module scope after use
2. ⏳ **IN PROGRESS**: Implement CSRF protection on login form
3. ⏳ **TODO**: Add rate limiting to prevent brute force attacks

**Phase 2 (High - Before Production)**:
4. Add security headers (CSP, X-Frame-Options, etc.)
5. Implement session token binding to request context
6. Add logout endpoint

**Phase 3 (Medium - Hardening)**:
7. Add suspicious header logging
8. Improve error message logging (hash usernames)
9. Add security-focused tests

**Phase 4 (Low - Long-term)**:
10. Implement key rotation mechanism
11. Add advanced rate limiting and account lockout
12. Implement IP binding for tokens

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

---

**Reviewed by**: GitHub Copilot
**Review Date**: January 1, 2026
