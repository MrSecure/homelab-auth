# WSGI Quick Reference

## Running Locally

```bash
# Development mode (Flask development server)
task run

# Production-like mode (gunicorn)
task run-gunicorn
```

## Environment Variables

```bash
# Configuration file location (default: config.yaml)
export HOMELAB_AUTH_CONFIG_FILE="/path/to/config.yaml"

# Session signing key (required for production)
export HOMELAB_AUTH_HASHING_KEY="your-stable-secret-key"

# Both together
export HOMELAB_AUTH_CONFIG_FILE="/path/to/config.yaml"
export HOMELAB_AUTH_HASHING_KEY="your-key"
gunicorn --workers 4 --bind 0.0.0.0:55000 src.wsgi:app
```

## Docker Deployment

```bash
# Build
docker build -t homelab-auth .

# Run
docker run \
  -e HOMELAB_AUTH_CONFIG_FILE=/config/wsgi-config.yaml \
  -e HOMELAB_AUTH_HASHING_KEY="your-key" \
  -v /path/to/config:/config \
  -p 55000:55000 \
  homelab-auth
```

## Docker Compose

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
```

## Gunicorn Worker Configuration

```bash
# For 2-core system
gunicorn --workers 5 src.wsgi:app  # 2*2+1

# For 4-core system
gunicorn --workers 9 src.wsgi:app  # 2*4+1
```

## Configuration File Sections

| Section | Key | Purpose |
| ------- | --- | ------- |
| `auth` | `htpasswd_path` | Path to htpasswd file |
| `auth` | `session_max_age` | Session timeout (seconds) |
| `cookie` | `name` | Cookie name |
| `cookie` | `secure` | HTTPS only (true/false) |
| `cookie` | `httponly` | No JS access (true/false) |
| `cookie` | `samesite` | CSRF protection (Strict/Lax/None) |
| `server` | `host` | Bind address |
| `server` | `port` | Port number |
| `redir` | `external_name` | Service name for redirects |
| `redir` | `default_destination` | Default redirect target |
| `page` | `title` | Login page title |
| `page` | `advisory` | Security warning text |

## Security Checklist

- [ ] Use stable hashing key in production
- [ ] Set `cookie.secure: true` for HTTPS-only
- [ ] Set `cookie.httponly: true` to prevent JS access
- [ ] Set `cookie.samesite: Lax` or `Strict` for CSRF protection
- [ ] Restrict htpasswd file permissions: `chmod 400`
- [ ] Use HTTPS/TLS via reverse proxy
- [ ] Keep dependencies updated
- [ ] Monitor application logs
- [ ] Use production-grade gunicorn settings

## Troubleshooting

### ModuleNotFoundError: No module named 'src.main'

- Ensure working directory is project root
- Check Python path includes project directory
- Use `python -c "from src.main import app"` to verify

### Bcrypt/passlib warnings

- Already handled by wsgi.py automatically
- Check you're using WSGI entry point (src.wsgi:app)

### FileNotFoundError for config file

- Verify `HOMELAB_AUTH_CONFIG_FILE` is set correctly
- Use absolute paths if possible
- Check file permissions

### Sessions invalid after restart

- Ensure `HOMELAB_AUTH_HASHING_KEY` is identical across restarts
- Don't rely on auto-generated keys in production

## See Also

- [docs/WSGI_DEPLOYMENT.md](docs/WSGI_DEPLOYMENT.md) — Comprehensive guide
- [README.md](README.md) — Project overview
- [support/wsgi-config.yaml](support/wsgi-config.yaml) — Example config
- [WSGI_CHANGES.md](WSGI_CHANGES.md) — Change summary
