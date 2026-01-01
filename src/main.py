#!/usr/bin/env python3
"""
homelab-auth script entrypoint
"""

from homelab_auth import config


def main():
    """Main entry point for the application."""
    log = config.setup_logging()
    log.debug("Logging initialized with level: %s", log.level)

    raise NotImplementedError()


if __name__ == "__main__":
    main()
