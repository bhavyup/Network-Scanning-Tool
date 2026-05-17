# Contributing

Thanks for taking the time to contribute. This project focuses on practical scanning workflows, so changes should stay clear, safe, and easy to run.

## Quick Start

1. Fork the repo and create a feature branch.
2. Set up a virtual environment.
3. Install dependencies.

Windows:

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Linux/macOS:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Testing

Run tests with:

```
python -m pytest -q
```

Run tests with coverage (CI target is 90%+):

```
python -m pytest -q --cov=src --cov-report=term-missing --cov-fail-under=90
```

Run type checks:

```
python -m mypy src
```

Notes:
- Tests are deterministic and do not require network access.
- Live scans and ARP/raw-socket modes still require admin/root privileges.
- Use safe, authorized targets when running scans manually.

## What To Include In A PR

- What changed and why.
- How you tested it (commands and environment).
- Any docs or README updates that should ship with the change.

## Style Expectations

- Keep changes focused and avoid drive-by refactors.
- Prefer clear naming and consistent scan result formatting.
- Add or update tests when behavior changes.

## Security And Safety

Please do not post sensitive target details or private network data in public issues or PRs.
