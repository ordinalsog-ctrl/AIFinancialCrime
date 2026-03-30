#!/usr/bin/env python3
"""Thin wrapper for the active report generator module."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.investigation.generate_case_report import cli


if __name__ == "__main__":
    raise SystemExit(cli())
