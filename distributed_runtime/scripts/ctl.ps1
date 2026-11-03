# PowerShell entry point: .\distributed_runtime\scripts\ctl.ps1 <command> [options]
#   .\distributed_runtime\scripts\ctl.ps1 build
#   .\distributed_runtime\scripts\ctl.ps1 prepare
#   .\distributed_runtime\scripts\ctl.ps1 start
#   .\distributed_runtime\scripts\ctl.ps1 run read --count 3
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path (Split-Path -Parent $root) ".venv\Scripts\python.exe"
$env:PYTHONDONTWRITEBYTECODE = "1"
& $py (Join-Path $PSScriptRoot "ctl.py") @args
exit $LASTEXITCODE
