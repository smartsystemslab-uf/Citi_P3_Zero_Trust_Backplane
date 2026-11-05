#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/zt-pdp" >&2
  exit 2
fi

PDP_ROOT="$1"
python -m pip install -e '.[test,fastapi]'
python -m pip install -e "$PDP_ROOT"
python pep_placement_engine.py generate examples/citi_project_baseline.yaml --output generated --pdp-root "$PDP_ROOT"
PDP_ROOT="$PDP_ROOT" pytest -q
echo "PEP generator generation and PDP integration tests passed."
