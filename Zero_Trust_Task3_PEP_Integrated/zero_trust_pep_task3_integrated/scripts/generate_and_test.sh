#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/zero_trust_pdp_task4_secure" >&2
  exit 2
fi

TASK4_ROOT="$1"
python -m pip install -e '.[test,fastapi]'
python -m pip install -e "$TASK4_ROOT"
python pep_placement_engine.py generate examples/citi_project_baseline.yaml --output generated --task4-root "$TASK4_ROOT"
TASK4_ROOT="$TASK4_ROOT" pytest -q
echo "Task 3 generation and Task 4 integration tests passed."
