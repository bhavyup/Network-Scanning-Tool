# Development Guide

This guide provides information for developers who want to contribute to the Network Scanner project.

## Development Environment Setup

### Prerequisites

-   Python 3.10 or higher
-   Virtual environment (recommended)
-   Code editor/IDE
-   Network testing environment

### Setup Steps

1. **Create and populate local environment**

    Option A (recommended): bootstrap script

    ```powershell
    ./scripts/bootstrap.ps1 -InstallDev
    ```

    Option B (manual)

    ```bash
    python -m venv .venv
    # Linux/macOS
    source .venv/bin/activate
    # Windows PowerShell
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    ```

2. **Verify CLI is available**

    ```bash
    python src/main.py --help
    ```

## Project Structure

```
network-scanner/
├── src/
│   ├── main.py         # Command-line interface
│   ├── scanner.py      # Core scanning functionality
│   ├── tui.py          # Curses-based TUI
│   └── __init__.py
├── tests/              # Test files
├── docs/              # Documentation
├── scripts/            # Bootstrap helpers
├── requirements.txt    # Production dependencies
└── requirements-dev.txt # Development dependencies
```

## Coding Standards

### Python Style Guide

-   Follow PEP 8 guidelines
-   Use type hints
-   Document all functions and classes
-   Keep functions focused and small

### Code Organization

-   Separate concerns
-   Use meaningful names
-   Keep related code together
-   Follow the single responsibility principle

### Documentation

-   Use docstrings for all functions and classes
-   Keep comments clear and concise
-   Update documentation with code changes
-   Include examples where helpful

## Testing

### Running Tests

```bash
python -m pytest tests/
```

### Test Structure

```
tests/
├── test_scanner.py
└── test_integration.py
```

### Test Caveat

Current tests run against live network behavior and can vary by:

- network reachability
- local firewall rules
- user privileges
- host services currently running

### Writing Tests

1. **Unit Tests**

    - Test individual functions
    - Mock external dependencies
    - Cover edge cases

2. **Integration Tests**
    - Test component interactions
    - Verify end-to-end functionality
    - Test with real network conditions

## Development Workflow

### 1. Feature Development

1. Create feature branch
    ```bash
    git checkout -b feature/new-feature
    ```
2. Implement changes
3. Write tests
4. Update documentation
5. Submit pull request

### 2. Bug Fixes

1. Create bug fix branch
    ```bash
    git checkout -b fix/bug-description
    ```
2. Fix the issue
3. Add regression tests
4. Update documentation
5. Submit pull request

### 3. Code Review

1. Submit pull request
2. Address review comments
3. Update code as needed
4. Get approval
5. Merge changes

## Network Testing

### Test Environment

-   Use isolated network
-   Set up test targets
-   Configure test firewalls
-   Monitor network traffic

### Testing Tools

-   Wireshark for packet analysis
-   Network emulators
-   Virtual machines
-   Test automation tools

## Performance Considerations

### Optimization Tips

1. **Network Operations**

    - Use appropriate timeouts
    - Implement rate limiting
    - Handle errors gracefully
    - Optimize packet handling

2. **System Resources**
    - Manage memory usage
    - Handle file descriptors
    - Clean up resources
    - Monitor system load

### Profiling

1. **CPU Profiling**

    ```bash
    python -m cProfile src/main.py
    ```

2. **Memory Profiling**
    ```bash
    python -m memory_profiler src/main.py
    ```

## Lint and Type Checks

```bash
flake8 src tests
pylint src
mypy src
black --check src tests
```

## Security Considerations

### Code Security

1. **Input Validation**

    - Validate all inputs
    - Sanitize user data
    - Handle edge cases
    - Prevent injection attacks

2. **Error Handling**
    - Don't expose sensitive information
    - Log appropriately
    - Handle exceptions securely
    - Clean up resources

### Network Security

1. **Packet Handling**

    - Validate packet contents
    - Handle malformed packets
    - Implement rate limiting
    - Monitor for abuse

2. **Access Control**
    - Check permissions
    - Validate targets
    - Implement logging
    - Follow security guidelines

## Release Process

### Versioning

-   Follow semantic versioning
-   Update version numbers
-   Tag releases
-   Update changelog

### Release Steps

1. Update version
2. Run tests
3. Update documentation
4. Create release notes
5. Tag release
6. Build distribution
7. Publish release

## Contributing Guidelines

### Pull Requests

1. Fork the repository
2. Create feature branch
3. Make changes
4. Run tests
5. Update documentation
6. Submit pull request

### Code Review

1. Review checklist
2. Style guidelines
3. Test coverage
4. Documentation
5. Security considerations

### Issue Reporting

1. Check existing issues
2. Create new issue
3. Provide details
4. Include reproduction steps
5. Add system information