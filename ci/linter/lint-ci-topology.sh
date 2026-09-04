#!/usr/bin/env bash
# Protect the measured four-lane workflow topology.
set -euo pipefail
exec python3 ci/linter/ci_topology.py
