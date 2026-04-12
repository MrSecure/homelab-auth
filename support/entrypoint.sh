#!/bin/bash
# Entrypoint script for homelab-auth container
#
# The application supports multiple methods for providing the hashing key:
# 1. CLI argument: --hashing-key "your-key"
# 2. Environment variable: HOMELAB_AUTH_HASHING_KEY
# 3. Fallback: SHA1 hash of config file

set -euo pipefail

ARGUMENTS=${1:-NONE}
CONFIG_FILE="${CONFIG_FILE:-/app/config.yaml}"
SERVICE_PORT="${SERVICE_PORT:-55000}"
PYTHON="${PYTHON:-python3}"

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found at $CONFIG_FILE" >&2
    exit 1
fi

# Log the startup configuration
echo "Starting homelab-auth"
echo "  Config file: $CONFIG_FILE"
echo "  Service port: $SERVICE_PORT"

if [[ -n "${HOMELAB_AUTH_HASHING_KEY:-}" ]]; then
    echo "  Hashing key: provided via HOMELAB_AUTH_HASHING_KEY environment variable"
else
    echo "  Hashing key: will use SHA1 hash of config file as fallback"
fi

if [[ "--check-config" == "${ARGUMENTS}" ]]; then
    echo "Performing configuration check..."
    # Run the application with a special argument to validate the config and exit
    _confg_args="--check-config --print-config"
else
    _confg_args=""
fi
# Start gunicorn with proper timeout and error handling configuration
# shellcheck disable=SC2086
exec gunicorn \
    --workers 4 \
    --worker-class sync \
    --bind "0.0.0.0:${SERVICE_PORT}" \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --control-socket /app/.gunicorn/gunicorn.sock \
    --graceful-timeout 10 \
    --error-logfile - \
    --access-logfile - \
    $_confg_args wsgi:app
