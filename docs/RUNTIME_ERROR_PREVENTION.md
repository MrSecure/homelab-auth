# Runtime Error Prevention Guide

## Issue Addressed
The error `[ERROR] Error handling request (no URI read)` occurs when gunicorn workers encounter malformed or incomplete HTTP requests, typically due to:
- Clients sending incomplete/malformed requests
- Proxy connection resets
- Worker timeouts on slow connections
- Missing request size limits

## Solutions Implemented

### 1. Flask Configuration (src/main.py)
- **MAX_CONTENT_LENGTH = 16KB**: Prevents oversized request attacks and memory issues
- **JSON_SORT_KEYS**: Consistent JSON output

### 2. Flask Error Handlers
Added graceful error handlers for common HTTP errors:
- **400 Bad Request**: Handles malformed request data
- **408 Request Timeout**: Handles slow/stalled requests
- **413 Payload Too Large**: Handles requests exceeding max size
- **500 Internal Server Error**: Graceful error recovery

### 3. Gunicorn Configuration (support/entrypoint.sh)
Enhanced worker configuration for production stability:

| Setting | Value | Purpose |
|---------|-------|---------|
| `--timeout` | 30 | Worker timeout (kills hung workers) |
| `--keep-alive` | 5 | HTTP keep-alive timeout |
| `--max-requests` | 1000 | Restart workers after N requests (memory leak prevention) |
| `--max-requests-jitter` | 100 | Randomize restart to avoid thundering herd |
| `--graceful-timeout` | 10 | Grace period for graceful shutdown |
| `--error-logfile -` | stdout | Log errors to container logs |
| `--access-logfile -` | stdout | Log access to container logs |
| `--worker-class` | sync | Use sync worker (stable for auth service) |

## How This Prevents Errors

### WSGI Entrypoint (src/wsgi.py)

`src/wsgi.py` provides a production-ready WSGI entrypoint intended for use with servers like `gunicorn`.

- It initializes logging early and applies a compatibility shim for newer `bcrypt`/`passlib` versions so worker startup does not raise import-time warnings or errors.
- For initialization it sets `sys.argv` to a controlled value using the `HOMELAB_AUTH_CONFIG_FILE` environment variable (defaults to `config.yaml`) and will append a `--hashing-key` argument when `HOMELAB_AUTH_HASHING_KEY` is set. This lets the same configuration-loading code in `src/main.py` run in both CLI and WSGI contexts without parsing unexpected arguments.
- Exported symbol: `app` (the Flask application) — WSGI servers should point to `src.wsgi:app` (or `wsgi:app` when running inside the container image).

Deployment notes:
- Ensure the configured config file path is readable by the WSGI process.
- Prefer setting `HOMELAB_AUTH_HASHING_KEY` in production to avoid the config-based SHA1 fallback, which will change if the config file contents change and can invalidate sessions.
- The container `support/entrypoint.sh` demonstrates a recommended `gunicorn` invocation that uses `wsgi:app`.

1. **Timeout Protection**: Worker timeouts prevent hung connections from accumulating
2. **Request Size Limits**: Prevents memory exhaustion from oversized payloads
3. **Graceful Degradation**: Error handlers return proper HTTP status codes instead of crashes
4. **Worker Recycling**: Periodic worker restarts clean up memory leaks
5. **Proper Logging**: All errors logged to container stdout for debugging

## Testing

To verify the fixes work:

```bash
# Test malformed request
curl -v --http1.0 "http://localhost:55000/login" -H "Content-Length: invalid"

# Test oversized payload (should be rejected)
python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:55000/login', data=b'x'*20000)"

# Test normal operation
curl -v "http://localhost:55000/healthz"
```

## Monitoring

Watch for these log patterns to catch issues early:
- `Bad request received`: Malformed client requests
- `Request timeout`: Slow/stalled client connections
- `Payload too large`: Oversized requests
- `Worker timeout`: Check if legitimate requests are being killed (increase timeout if needed)

## Configuration Tuning

If you experience issues, consider adjusting:
- **`--timeout`**: Increase if legitimate requests timeout (reduce for faster error detection)
- **`--workers`**: Increase for higher concurrency, decrease for lower memory usage
- **`MAX_CONTENT_LENGTH`**: Increase if valid requests are being rejected
