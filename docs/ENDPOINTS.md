# API Endpoints

## GET `/verify`

Validates an existing session for forward-auth and API checks.

- Checks the configured session cookie first.
- If cookie exchange is enabled, checks the configured auth header as a fallback.
- Does not redirect to login; returns status directly so reverse proxies can decide the next step.

**Responses:**

- `200 OK` with body `OK` when the token is valid.
- `401 Unauthorized` with body `Invalid Session` when a token is present but invalid or expired.
- `401 Unauthorized` with body `Unauthorized` when no token is provided.

## GET `/`

Entry route that normalizes the destination and forwards the user to the login page.

- Accepts optional query parameter `rd` (return destination).
- Validates `rd` against allowed redirect domain rules.
- Falls back to configured default destination when `rd` is missing or unsafe.
- Returns an HTTP `307` redirect to `/login?rd=<destination>` on the external auth host.

## GET `/login`

Renders the login form.

- Validates and normalizes `rd` the same way as `/`.
- If a valid session cookie already exists, immediately redirects to `rd`.
- If cookie exchange is enabled and a valid auth header is present, immediately redirects to `rd`.
- Otherwise renders the login page with a CSRF token tied to the client address.

**Responses:**

- `200 OK` with HTML login form.
- `302 Found` redirect to `rd` when user is already authenticated.

## POST `/login`

Processes submitted credentials and creates a session.

- Requires a valid CSRF token.
- Rejects missing or oversized username/password inputs.
- Verifies credentials against the configured htpasswd user store.
- On success, sets the signed session cookie with configured security flags and redirects to `rd`.

**Responses:**

- `302 Found` redirect to `rd` with session cookie on successful authentication.
- `400 Bad Request` when CSRF validation fails.
- `401 Unauthorized` when credentials are invalid or required fields are missing.

## GET `/done`

Simple local success page used by some auth flows after login.

- Returns a minimal HTML message indicating login succeeded.

**Responses:**

- `200 OK` with HTML body.

## GET `/cookie-crumbling-protocol-v2`

Exchanges a valid session cookie for structured identity data.

- Intended for integrations that need token/identity/header metadata from the authenticated session.
- Returns `400` for missing/invalid session cookies to avoid proxy auth loops.
- Can be disabled via configuration.

**Response (success - HTTP 200):**

```json
{
  "token": "signed.cookie.value",
  "identity": "username",
  "cookie": "session_cookie_name",
  "header": "X-Configured-Auth-Header"
}
```

**Response (missing cookie - HTTP 400):**

```json
{
  "error": "Unauthorized"
}
```

**Response (invalid session - HTTP 400):**

```json
{
  "error": "Invalid Session"
}
```

**Response (disabled - HTTP 404):**

```json
{
  "error": "Not Found"
}
```

**Configuration:**

By default, this endpoint is enabled. To disable it, set `exchange_enabled` to `false` in the `cookie` section of your configuration file:

```yaml
cookie:
  name: session
  secure: true
  httponly: true
  samesite: Lax
  domain: .example.com
  exchange_enabled: false  # Set to true (default) to enable
```

When disabled, requests to the endpoint receive a `404` response.

## GET/POST `/logout`

Logs the user out by invalidating the browser session cookie.

- Sets the session cookie to a placeholder value with `max_age=0` to expire it.
- Preserves configured cookie security flags (`Secure`, `HttpOnly`, `SameSite`, and domain).
- Returns the login page with a "Logged out." feedback message.

**Responses:**

- `200 OK` with HTML login page and expired session cookie.

## GET `/healthz`

Lightweight service health endpoint for container and load balancer probes.

- Does not require authentication.
- Returns static JSON status.

**Response (success - HTTP 200):**

```json
{
  "status": "healthy"
}
```
