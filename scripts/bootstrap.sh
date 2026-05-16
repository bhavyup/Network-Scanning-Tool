#!/usr/bin/env bash
set -euo pipefail

VENV_NAME=".venv"
INSTALL_DEV=0
FORCE_RECREATE=0

usage() {
  echo "Usage: bash scripts/bootstrap.sh [--dev] [--venv <name>] [--recreate]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)
      INSTALL_DEV=1
      shift
      ;;
    --venv)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      VENV_NAME="$2"
      shift 2
      ;;
    --recreate)
      FORCE_RECREATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Python was not found in PATH. Install Python 3.10+ and retry."
  exit 1
fi

if [[ $FORCE_RECREATE -eq 1 && -d "$VENV_NAME" ]]; then
  echo "Removing existing virtual environment at $VENV_NAME"
  rm -rf "$VENV_NAME"
fi

if [[ ! -d "$VENV_NAME" ]]; then
  echo "Creating virtual environment at $VENV_NAME"
  "$PYTHON_BIN" -m venv "$VENV_NAME"
fi

if [[ -f "$VENV_NAME/bin/python" ]]; then
  VENV_PY="$VENV_NAME/bin/python"
elif [[ -f "$VENV_NAME/Scripts/python.exe" ]]; then
  VENV_PY="$VENV_NAME/Scripts/python.exe"
else
  echo "Virtual environment python executable not found."
  exit 1
fi

echo "Upgrading pip"
"$VENV_PY" -m pip install --upgrade pip

echo "Installing runtime dependencies"
"$VENV_PY" -m pip install -r requirements.txt

if [[ $INSTALL_DEV -eq 1 ]]; then
  echo "Installing development dependencies"
  "$VENV_PY" -m pip install -r requirements-dev.txt
fi

echo "Bootstrap complete."
echo "Activate with: source $VENV_NAME/bin/activate"
