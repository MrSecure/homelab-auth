#!/bin/bash
# Entrypoint script for homelab-auth container
# Initializes hashing_string in config.yaml if not already set

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/app/config.yaml}"
PYTHON="${PYTHON:-python3}"

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found at $CONFIG_FILE" >&2
    exit 1
fi

# Use Python to check and update the config file
$PYTHON << PYTHON_SCRIPT
import secrets
import yaml
from pathlib import Path

config_file = Path("$CONFIG_FILE")

# Load the config
with open(config_file, 'r') as f:
    config = yaml.safe_load(f) or {}

# Initialize auth section if missing
if 'auth' not in config:
    config['auth'] = {}

# Check if hashing_string is already set
hashing_string = config['auth'].get('hashing_string')

if not hashing_string:
    # Generate a new random hashing string
    hashing_string = secrets.token_urlsafe(32)
    config['auth']['hashing_string'] = hashing_string

    # Try to write the updated config back to file
    try:
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        print(f"Generated and persisted hashing_string in {config_file}")
    except IOError as e:
        # Fail gracefully - the application will use the SHA1 hash of config as fallback
        print(f"Warning: Could not write hashing_string to {config_file}: {e}")
        print("The application will use a fallback hashing_string based on config data")
else:
    print("Using existing hashing_string from config file")

PYTHON_SCRIPT

# Exit if Python script failed
# shellcheck disable=SC2181
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to process config file" >&2
    exit 1
fi

# Start gunicorn with proper timeout and error handling configuration
exec gunicorn \
    --workers 4 \
    --worker-class sync \
    --bind "0.0.0.0:${SERVICE_PORT:-55000}" \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --graceful-timeout 10 \
    --error-logfile - \
    --access-logfile - \
    main:app
