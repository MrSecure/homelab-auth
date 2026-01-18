#!/usr/bin/env python3
"""
WSGI entry point for gunicorn.

This module initializes the Flask app with environment variables instead of CLI arguments.
"""

import os
import sys
import logging

# Setup logging early to suppress passlib warnings
logging.basicConfig()
logging.getLogger("passlib.handlers.bcrypt").setLevel(logging.CRITICAL)

import bcrypt

# --- FIX: Passlib/Bcrypt 4.0+ Compatibility ---
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("obj", (object,), {"__version__": bcrypt.__version__})

# Import the initialization code from main
# We need to set up sys.argv to avoid argparse errors
sys.argv = [
    sys.argv[0],
    os.getenv("HOMELAB_AUTH_CONFIG_FILE", "config.yaml"),
]

# Set the hashing key if provided via environment variable
if os.getenv("HOMELAB_AUTH_HASHING_KEY"):
    sys.argv.extend(["--hashing-key", os.getenv("HOMELAB_AUTH_HASHING_KEY")])

# Now import main which will parse our controlled argv
# Try to import from src.main first (local development), fall back to main (Docker)
try:
    from src.main import app
except ModuleNotFoundError:
    from main import app

# Export the app for gunicorn
__all__ = ["app"]
