# PowerShell entry point of the distributed runtime (same commands as ctl.py, see its help):
#   .\distributed_runtime\scripts\ctl.ps1 build --project examples\helpdesk_mas\zt_adk.playback.yaml
#   .\distributed_runtime\scripts\ctl.ps1 prepare
#   .\distributed_runtime\scripts\ctl.ps1 start
#   .\distributed_runtime\scripts\ctl.ps1 run -m "Look up user alice" --role employee
#   .\distributed_runtime\scripts\ctl.ps1 approvals list
#   .\distributed_runtime\scripts\ctl.ps1 verify
#   .\distributed_runtime\scripts\ctl.ps1 stop
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path (Split-Path -Parent $root) ".venv\Scripts\python.exe"
$env:PYTHONDONTWRITEBYTECODE = "1"
& $py (Join-Path $PSScriptRoot "ctl.py") @args
exit $LASTEXITCODE
