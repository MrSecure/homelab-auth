#!/usr/bin/env python3
"""
Test package metadata and imports
"""

import pytest

from homelab_auth import (
    __maintainer__,
    __project_name__,
    __version__,
)


@pytest.mark.unit
def test_package_metadata():
    """Test that package metadata is accessible."""

    assert __maintainer__ == "MrSecure"
    assert __project_name__ == "homelab_auth"
    assert __version__ is not None
    assert isinstance(__version__, str)
