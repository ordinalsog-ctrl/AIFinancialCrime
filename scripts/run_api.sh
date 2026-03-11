#!/usr/bin/env bash
set -euo pipefail

pwd
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"
uvicorn afci.api.main:app --reload --port 8080
