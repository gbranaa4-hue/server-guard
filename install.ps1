<#
One-command setup for a new machine: venv, dependencies, first-run
baseline steps, and (optionally) the Startup-folder persistence shortcut
described in ROADMAP.md #1/#4.

Deliberately does NOT register a Windows Scheduled Task -- that's been
tried and hit a real, reproduced Access Denied on a standard (non-admin)
account; see README's "Reliability" section and ROADMAP.md #1. This
script uses the same Startup-folder fallback that's already proven to
work, offered as an explicit opt-in prompt rather than silently modifying
login behavior.

Usage:
    powershell -ExecutionPolicy Bypass -File install.ps1
#>

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot

Write-Host "== server-guard setup ==" -ForegroundColor Cyan

# 1. Virtual environment
$venvPath = Join-Path $repoRoot ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "Creating virtual environment..."
    python -m venv $venvPath
} else {
    Write-Host "Virtual environment already exists, skipping creation."
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPythonw = Join-Path $venvPath "Scripts\pythonw.exe"

# 2. Dependencies
Write-Host "Installing dependencies..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $repoRoot "requirements.txt")

# 3. First-run baseline steps (see README's Usage section -- these are
#    real, required one-time steps, not optional polish: guard.py won't
#    have sensible unexpected-port/workload thresholds without them).
Write-Host ""
Write-Host "Dependencies installed. Two first-run steps remain (not run" -ForegroundColor Yellow
Write-Host "automatically -- each takes real wall-clock time):" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1) Record this host's expected listening ports:"
Write-Host "       $venvPython guard.py --learn-baseline --max-ticks 1"
Write-Host ""
Write-Host "  2) Measure real workload thresholds (takes ~5 minutes):"
Write-Host "       $venvPython baseline_measure.py --duration 300"
Write-Host ""
Write-Host "  3) Copy config/alerting.example.json to config/alerting.json"
Write-Host "     and fill in a real webhook (ntfy.sh needs zero signup)."
Write-Host ""

# 4. Optional: Startup-folder persistence (explicit opt-in, not silent)
$answer = Read-Host "Install a Startup-folder shortcut so supervisor.py runs at login? [y/N]"
if ($answer -eq "y" -or $answer -eq "Y") {
    $startup = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startup "ServerGuardSupervisor.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $venvPythonw
    $Shortcut.Arguments = "supervisor.py -- --interval 5 --retention-days 30"
    $Shortcut.WorkingDirectory = $repoRoot
    $Shortcut.Description = "Auto-starts server-guard's supervisor (crash/hang recovery for guard.py) at login"
    $Shortcut.Save()
    Write-Host "Startup shortcut installed at: $shortcutPath" -ForegroundColor Green
    Write-Host "Takes effect on next login. Delete the shortcut to undo." -ForegroundColor Green
} else {
    Write-Host "Skipped. Run supervisor.py manually, or re-run this script later to add it."
}

Write-Host ""
Write-Host "Setup complete. Once the first-run steps above are done, start continuous monitoring with:" -ForegroundColor Cyan
Write-Host "  $venvPython supervisor.py -- --interval 5 --retention-days 30"
