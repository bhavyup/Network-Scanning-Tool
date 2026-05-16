param(
    [switch]$InstallDev,
    [string]$VenvName = ".venv",
    [switch]$ForceRecreate
)

$ErrorActionPreference = "Stop"

function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py"
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }

    throw "Python was not found in PATH. Install Python 3.10+ and retry."
}

if ($ForceRecreate -and (Test-Path $VenvName)) {
    Write-Host "Removing existing virtual environment at $VenvName"
    Remove-Item $VenvName -Recurse -Force
}

$pythonCmd = Get-PythonCommand

if (-not (Test-Path $VenvName)) {
    Write-Host "Creating virtual environment at $VenvName"
    if ($pythonCmd -eq "py") {
        & py -3 -m venv $VenvName
    }
    else {
        & python -m venv $VenvName
    }
}

$venvPython = Join-Path $VenvName "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "Virtual environment python executable not found at $venvPython"
}

Write-Host "Upgrading pip"
& $venvPython -m pip install --upgrade pip

Write-Host "Installing runtime dependencies"
& $venvPython -m pip install -r requirements.txt

if ($InstallDev) {
    Write-Host "Installing development dependencies"
    & $venvPython -m pip install -r requirements-dev.txt
}

Write-Host "Bootstrap complete."
Write-Host "Activate with: .\$VenvName\Scripts\Activate.ps1"
