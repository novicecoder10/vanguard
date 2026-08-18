# Contributing to Vanguard EDR

Thank you for your interest in contributing to Vanguard EDR! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem**
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include screenshots and animated GIFs if possible**
- **Include your environment details (OS, Python version, etc.)**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior and the expected improved behavior**
- **Explain why this enhancement would be useful**

### Pull Requests

- Follow the Python style guide (PEP 8)
- Include appropriate test cases
- Update documentation if applicable
- Provide a clear description of what you changed and why
- Reference any related issues

## Development Setup

### Prerequisites
- Python 3.9+
- Git
- pip

### Setting Up Development Environment

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/vanguard.git
   cd vanguard
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -e ".[dev,frida]"
   ```

5. Make your changes and test them:
   ```bash
   pytest  # Run tests
   black .  # Format code
   flake8  # Lint code
   mypy .  # Type check (optional)
   ```

## Code Style

### Python Style
- Follow PEP 8
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Use type hints where appropriate

### Formatting
```bash
# Format code with black
black vanguard_agent/ vanguard_server/

# Check style with flake8
flake8 vanguard_agent/ vanguard_server/

# Check types with mypy
mypy vanguard_agent/ vanguard_server/
```

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Consider starting commit messages with:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `style:` for code style changes
  - `refactor:` for code refactoring
  - `test:` for adding tests
  - `chore:` for maintenance tasks

Example:
```
feat(sysmon): Add real-time process correlation

Implement process correlation logic in SysmonMonitor to detect
parent-child relationships and identify suspicious process chains.

Fixes #123
```

## Testing

### Running Tests
```bash
pytest -v
```

### Writing Tests
- Place test files in appropriate test directories
- Use descriptive test names
- Test both success and failure cases
- Include docstrings explaining what is tested

## Documentation

- Keep README.md updated
- Update relevant documentation in `docs/` folder
- Include docstrings for all public functions
- Keep CHANGELOG.md up to date

## Pull Request Process

1. Update the README.md with details of any interface changes
2. Update the CHANGELOG.md with notes on your changes
3. Ensure all tests pass locally
4. Ensure code follows the style guidelines
5. Include a clear description of your changes

## Additional Notes

### Important Files
- `setup.py` - Package configuration
- `CHANGELOG.md` - Version history and roadmap
- `PACKAGES.md` - Dependency information
- `WINDOWS_FIX_LOG.md` - Technical fix documentation

### Areas for Contribution

#### High Priority
- [ ] Additional behavioral signatures (see THREAT_SIGNATURES in ml_analyzer.py)
- [ ] Performance optimizations
- [ ] Test coverage improvements
- [ ] Documentation enhancements

#### Medium Priority
- [ ] UI/UX improvements
- [ ] Cross-platform support improvements
- [ ] Database scalability (ClickHouse migration)
- [ ] Additional detection methods

#### Future
- [ ] Web-based management console
- [ ] Cloud platform integrations
- [ ] Advanced ML models
- [ ] RBAC implementation

## Questions?

Feel free to open an issue with the `question` label or start a discussion.

## License

By contributing to Vanguard EDR, you agree that your contributions will be licensed under its MIT License.

## Recognition

Contributors will be recognized in the CHANGELOG.md and README.md acknowledgements section.

---

Thank you for contributing to Vanguard EDR! 🎉
