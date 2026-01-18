# WSGI Deployment Guide

This guide explains how to deploy Home Lab Auth using a WSGI server like gunicorn for production environments.

## Overview

Since release 0.9.2, Home Lab Auth includes native WSGI support through:

- **[src/wsgi.py](../src/wsgi.py)** — WSGI application entry point for gunicorn
- **[support/wsgi-config.yaml](../support/wsgi-config.yaml)** — Example WSGI configuration file
- **[support/entrypoint.sh](../support/entrypoint.sh)** — Docker entrypoint script with gunicorn integration
- **Dockerfile** — Multi-stage build optimized for WSGI deployment

## Architecture

### WSGI Entry Point

The `src/wsgi.py` module serves as the application entry point for WSGI servers. It:

1. **Manages environment variables** — Reads configuration from environment variables instead of CLI arguments
2. **Handles bcrypt compatibility** — Applies a compatibility fix for bcrypt/passlib 4.0+ versions
3. **Flexible imports** — Supports both local development (`src.main`) and Docker deployments (`main`)
4. **Exports the Flask app** — Provides the `app` object that gunicorn calls

### Configuration Flow

```
Environment Variables
        ↓
  src/wsgi.py
        ↓
  Initialize sys.argv
        ↓
  Import src/main.py
        ↓
  Parse config file
        ↓
  Flask app ready for WSGI
```

## Environment Variables

The WSGI module accepts the following environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOMELAB_AUTH_CONFIG_FILE` | `config.yaml` | Path to the configuration YAML file |
| `HOMELAB_AUTH_HASHING_KEY` | *(auto-generated)* | Session signing key (highest precedence) |

### Session Hashing Key Precedence

The application supports three methods for providing the hashing key (in order of precedence):

1. **Environment Variable** (for WSGI deployment) — `HOMELAB_AUTH_HASHING_KEY`
2. **CLI Argument** (for direct Python execution) — `--hashing-key`
3. **Auto-generated Fallback** — SHA1 hash of the config file (development only)

## Configuration File

A WSGI configuration file must include all required sections. See [support/wsgi-config.yaml](../support/wsgi-config.yaml) for a complete example:

```yaml
auth:
  htpasswd_path: /path/to/users.htpasswd
  session_max_age: 43200  # 12 hours in seconds

cookie:
  name: pecan_sandy
  secure: true            # HTTPS only
  httponly: true          # No JavaScript access
  samesite: Lax           # CSRF protection
  domain: null            # Implicit from request
  allowed_hosts:
    - dev.home.arpa
    - labs.home.arpa

server:
  port: 55000
  host: 0.0.0.0

redir:
  external_name: auth
  default_destination: dashboard

page:
  template_path: login_template.html.j2
  title: Home Lab Access
  advisory: |
    This system is for authorized users only. All activities are monitored and recorded.
    Unauthorized access is prohibited and may be subject to criminal prosecution.
```

### Configuration Sections

**`auth`** — Authentication settings
- `htpasswd_path` — Path to htpasswd file (required)
- `session_max_age` — Session timeout in seconds (default: 43200 = 12 hours)

**`cookie`** — Session cookie settings
- `name` — Cookie name (default: `pecan_sandy`)
- `secure` — HTTPS only (should be `true` in production)
- `httponly` — Disable JavaScript access (default: `true`)
- `samesite` — CSRF protection (`Strict`, `Lax`, or `None`)
- `domain` — Cookie domain (e.g., `.example.com` or `null` for implicit)
- `allowed_hosts` — List of allowed hostnames

**`server`** — Server binding
- `host` — Bind address (default: `0.0.0.0`)
- `port` — Port number (default: 55000)

**`redir`** — Redirect settings
- `external_name` — External service name for redirects (e.g., `auth`)
- `default_destination` — Default redirect target

**`page`** — UI settings
- `template_path` — Path to Jinja2 login template
- `title` — Page title
- `advisory` — Security advisory text

## Deployment Patterns

### Local Development with Task Runner

Run using the built-in task runner:

```bash
task run-gunicorn
```

Equivalent to:

```bash
HOMELAB_AUTH_CONFIG_FILE=support/wsgi-config.yaml \
  HOMELAB_AUTH_HASHING_KEY="homelab-auth-dev-key" \
  gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 \
    --access-logfile - --error-logfile - src.wsgi:app
```

### Direct Gunicorn Execution

```bash
HOMELAB_AUTH_CONFIG_FILE=/path/to/config.yaml \
  HOMELAB_AUTH_HASHING_KEY="your-stable-production-key" \
  gunicorn \
    --workers 4 \
    --worker-class sync \
    --bind 0.0.0.0:55000 \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --graceful-timeout 10 \
    --access-logfile - \
    --error-logfile - \
    src.wsgi:app
```

### Docker Container Deployment

The Docker image includes an optimized entrypoint that automatically runs gunicorn:

```bash
docker run \
  -e HOMELAB_AUTH_CONFIG_FILE=/config/wsgi-config.yaml \
  -e HOMELAB_AUTH_HASHING_KEY="your-production-key" \
  -v /path/to/config:/config \
  -p 55000:55000 \
  MrSecure/homelab-auth:latest
```

The container runs with production-recommended settings:
- 4 gunicorn workers by default
- 30-second timeouts for long-running requests
- Connection pooling via `--keep-alive`
- Periodic worker recycling via `--max-requests`
- Graceful shutdown with 10-second timeout
- Logs streamed to stdout/stderr for container orchestration

### Docker Compose Example

```yaml
version: '3.8'

services:
  homelab-auth:
    image: MrSecure/homelab-auth:latest
    environment:
      HOMELAB_AUTH_CONFIG_FILE: /config/wsgi-config.yaml
      HOMELAB_AUTH_HASHING_KEY: "${AUTH_KEY}"
    ports:
      - "55000:55000"
    volumes:
      - ./config:/config
      - ./users.htpasswd:/app/users.htpasswd:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:55000/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

## Gunicorn Configuration

### Worker Classes

For Home Lab Auth, use the **sync** worker class (default):

```bash
gunicorn --worker-class sync src.wsgi:app
```

The sync worker is appropriate because:
- Authentication requests are I/O bound (htpasswd lookups)
- Session management is lightweight
- No async/await code in the application

### Worker Count

Recommended settings:
- **Development**: 2-4 workers
- **Production**: `2 × CPU_cores + 1` workers

```bash
gunicorn --workers 4 src.wsgi:app  # For 2-core system
```

### Timeout Settings

```bash
gunicorn \
  --timeout 30 \         # Request timeout (seconds)
  --keep-alive 5 \       # Keep-alive timeout (seconds)
  --graceful-timeout 10  # Graceful shutdown timeout (seconds)
  src.wsgi:app
```

### Worker Recycling

Prevent memory leaks by recycling workers periodically:

```bash
gunicorn \
  --max-requests 1000 \           # Requests before worker recycling
  --max-requests-jitter 100 \     # Random offset (0-100 requests)
  src.wsgi:app
```

## Reverse Proxy Setup

### Traefik (Recommended)

```yaml
# traefik-middleware.yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: auth-headers
spec:
  headers:
    customRequestHeaders:
      X-Forwarded-Proto: https
      X-Forwarded-Host: auth.example.com

---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: homelab-auth
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`auth.example.com`)
      kind: Rule
      services:
        - name: homelab-auth
          port: 55000
      middlewares:
        - name: auth-headers
  tls:
    certResolver: letsencrypt
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://homelab-auth:55000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
        proxy_connect_timeout 10s;
    }
}
```

## Health Checks

### Kubernetes Liveness/Readiness

```yaml
livenessProbe:
  httpGet:
    path: /
    port: 55000
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /
    port: 55000
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

### Docker Healthcheck

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:55000/ || exit 1
```

## Logging

### Access Logs

Enable access logs to stdout for container orchestration:

```bash
gunicorn \
  --access-logfile - \
  --error-logfile - \
  src.wsgi:app
```

Example access log format:
```
127.0.0.1 - - [17/Jan/2026 20:30:45] "POST /login HTTP/1.1" 302 209
127.0.0.1 - - [17/Jan/2026 20:30:46] "GET /done HTTP/1.1" 200 1234
```

### Structured Logging

For better log parsing in container orchestration systems:

```bash
gunicorn \
  --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s' \
  --error-logfile - \
  src.wsgi:app
```

## Security Considerations

### Session Hashing Key

**CRITICAL**: Use a strong, stable production hashing key:

```bash
# Generate a secure key
openssl rand -hex 32
# Output: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z

# Use in environment
export HOMELAB_AUTH_HASHING_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
gunicorn src.wsgi:app
```

**Never use auto-generated keys in production** — they differ on each deployment, invalidating existing sessions.

### HTTPS/TLS

Always use HTTPS in production. Configure gunicorn behind a reverse proxy with proper TLS:

```bash
# Recommend using a reverse proxy (nginx, Traefik, etc.) for TLS
# instead of gunicorn directly
gunicorn \
  --bind 127.0.0.1:55000 \  # Bind to localhost only
  src.wsgi:app
```

### Cookie Security

Ensure cookies are properly secured in production:

```yaml
# wsgi-config.yaml
cookie:
  secure: true              # HTTPS only
  httponly: true            # No JavaScript access
  samesite: Strict          # Strict CSRF protection (or Lax if needed)
  domain: .example.com      # Explicit domain
```

### Htpasswd File Permissions

```bash
# Restrict htpasswd file to read-only
chmod 400 /path/to/users.htpasswd
chown root:app /path/to/users.htpasswd

# In Docker
COPY --chown=root:app ./users.htpasswd /app/users.htpasswd
RUN chmod 400 /app/users.htpasswd
```

## Troubleshooting

### Module Import Errors

If you see `ModuleNotFoundError: No module named 'src.main'`:

1. Verify the working directory is the project root
2. Check Python path includes the project directory
3. Ensure `src/main.py` exists and is readable

```bash
# Check working directory
pwd

# Check Python path
python -c "import sys; print(sys.path)"

# Verify module can be imported
python -c "from src.main import app; print(app)"
```

### Bcrypt/Passlib Warnings

The WSGI module automatically handles bcrypt 4.0+ compatibility. If you see warnings:

1. Ensure you're using the WSGI entry point (`src.wsgi:app`)
2. Check bcrypt/passlib versions
3. Review the compatibility fix in `src/wsgi.py`

```bash
# Check installed versions
pip show bcrypt passlib
```

### Configuration File Not Found

If you see `FileNotFoundError` for the config file:

1. Verify the `HOMELAB_AUTH_CONFIG_FILE` environment variable
2. Check file paths are absolute or relative to working directory
3. Ensure file permissions allow reading

```bash
# Set absolute path
export HOMELAB_AUTH_CONFIG_FILE=/etc/homelab-auth/config.yaml
export HOMELAB_AUTH_HASHING_KEY="your-key"
gunicorn src.wsgi:app

# Or use relative path from project root
export HOMELAB_AUTH_CONFIG_FILE=support/wsgi-config.yaml
gunicorn src.wsgi:app
```

### Session Issues

If sessions aren't persisting across gunicorn restarts:

1. Verify `HOMELAB_AUTH_HASHING_KEY` is the same across deployments
2. Check cookie domain and secure flags match your environment
3. Ensure all gunicorn workers use the same hashing key

```bash
# Use consistent key across all deployments
export HOMELAB_AUTH_HASHING_KEY="$(cat /etc/homelab-auth/key.txt)"
gunicorn --workers 4 src.wsgi:app
```

## See Also

- [README.md](../README.md) — Project overview and quick start
- [docs/SECURITY_REVIEW.md](./SECURITY_REVIEW.md) — Security considerations
- [docs/RUNTIME_ERROR_PREVENTION.md](./RUNTIME_ERROR_PREVENTION.md) — Troubleshooting runtime issues
- [support/entrypoint.sh](../support/entrypoint.sh) — Docker entrypoint script
- [Dockerfile](../Dockerfile) — Production Docker build
