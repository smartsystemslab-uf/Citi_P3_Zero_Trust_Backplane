param(
    [Parameter(Mandatory=$true)]
    [string]$Task4Root
)

$ErrorActionPreference = "Stop"

python -m pip install -e ".[test,fastapi]"
python -m pip install -e $Task4Root
python .\pep_placement_engine.py generate .\examples\citi_project_baseline.yaml --output .\generated --task4-root $Task4Root
$env:TASK4_ROOT = $Task4Root
pytest -q
Write-Host "Task 3 generation and Task 4 integration tests passed."
