# SPDX-License-Identifier: Apache-2.0
"""Backward-compatibility re-export.  Use ``kerbwolf.cli.extract`` instead."""

from kerbwolf.cli.extract import _build_parser, _output_results, main

__all__ = ["_build_parser", "_output_results", "main"]
