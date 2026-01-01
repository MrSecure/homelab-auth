#!/usr/bin/env python3
"""
Test homelab_auth/config.py
"""

import argparse
import logging
from unittest.mock import patch

import pytest

from homelab_auth import config


@pytest.mark.unit
def test_create_arg_parser():
    """Test create_arg_parser creates a valid ArgumentParser."""
    parser = config.create_arg_parser()
    assert isinstance(parser, argparse.ArgumentParser)


@pytest.mark.unit
def test_create_arg_parser_version():
    """Test that --version flag works."""
    parser = config.create_arg_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])
    assert exc_info.value.code == 0


@pytest.mark.unit
def test_create_arg_parser_debug():
    """Test that --debug flag sets log level to DEBUG."""
    parser = config.create_arg_parser()
    args = parser.parse_args(["--debug"])
    assert args.loglevel == logging.DEBUG


@pytest.mark.unit
def test_create_arg_parser_verbose():
    """Test that --verbose flag sets log level to INFO."""
    parser = config.create_arg_parser()
    args = parser.parse_args(["--verbose"])
    assert args.loglevel == logging.INFO


@pytest.mark.unit
def test_create_arg_parser_default_loglevel():
    """Test that default log level is WARNING when no flag is provided."""
    parser = config.create_arg_parser()
    args = parser.parse_args([])
    assert args.loglevel == logging.WARNING


@pytest.mark.unit
def test_create_arg_parser_mutually_exclusive():
    """Test that --debug and --verbose are mutually exclusive."""
    parser = config.create_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--debug", "--verbose"])


@pytest.mark.unit
def test_get_args_config(mocker):
    """Test get_args_config returns a dictionary."""
    mocker.patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(loglevel=logging.WARNING),
        autospec=True,
    )

    result = config.get_args_config()
    assert isinstance(result, dict)
    assert "loglevel" in result
    assert result["loglevel"] == logging.WARNING


@pytest.mark.unit
def test_get_args_config_with_debug(mocker):
    """Test get_args_config with debug flag."""
    mocker.patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(loglevel=logging.DEBUG),
        autospec=True,
    )

    result = config.get_args_config()
    assert result["loglevel"] == logging.DEBUG


@pytest.mark.unit
def test_setup_logging(mocker):
    """Test setup_logging returns a Logger instance."""
    mocker.patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(loglevel=logging.WARNING),
        autospec=True,
    )

    logger = config.setup_logging()
    assert isinstance(logger, logging.Logger)
    assert logger.name == "homelab_auth"


@pytest.mark.unit
def test_setup_logging_sets_correct_level(mocker):
    """Test setup_logging sets the correct logging level."""
    mocker.patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(loglevel=logging.DEBUG),
        autospec=True,
    )

    logger = config.setup_logging()
    # The root logger's effective level should reflect the configuration
    assert logging.getLogger().level == logging.DEBUG


@pytest.mark.unit
def test_setup_logging_format():
    """Test that setup_logging configures the correct log format."""
    with patch("logging.basicConfig") as mock_basic_config:
        with patch(
            "argparse.ArgumentParser.parse_args",
            return_value=argparse.Namespace(loglevel=logging.WARNING),
        ):
            config.setup_logging()
            mock_basic_config.assert_called_once()
            call_kwargs = mock_basic_config.call_args[1]
            assert "format" in call_kwargs
            # Check that the format string contains expected JSON keys
            format_str = call_kwargs["format"]
            assert "timestamp" in format_str
            assert "namespace" in format_str
            assert "loglevel" in format_str
            assert "message" in format_str
