param(
    [Parameter(Mandatory=$true)]
    [string]$PdpRoot
)

$ErrorActionPreference = "Stop"

python -m pip install -e ".[test,fastapi]"
python -m pip install -e $PdpRoot
python .\pep_placement_engine.py generate .\examples\citi_project_baseline.yaml --output .\generated --pdp-root $PdpRoot
$env:PDP_ROOT = $PdpRoot
pytest -q
Write-Host "PEP generator generation and PDP integration tests passed."
