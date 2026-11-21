# SPDX-License-Identifier: Apache-2.0
"""Backward-compatibility re-export.  Use ``kerbwolf.attacks.extract`` instead."""

from kerbwolf.attacks.extract import _captured_to_result, extract_from_pcap

__all__ = ["_captured_to_result", "extract_from_pcap"]
