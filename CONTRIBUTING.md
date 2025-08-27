# Contributing to Git Security Scanner

Thank you for your interest in contributing to Git Security Scanner! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use issue templates when available
3. Provide clear descriptions with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (OS, versions)
   - Error messages and logs

### Suggesting Features

1. Open a discussion or issue
2. Describe the use case
3. Explain expected benefits
4. Consider implementation approach

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Open a pull request

## Development Setup

### Prerequisites

- Docker Desktop
- Git
- GitHub account
- GitHub Personal Access Token (for testing)

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/cloudon-one/git-security-scanner-public.git
cd git-security-scanner-public
```

2. Build the Docker image:
```bash
docker build -t git-security-scanner:dev .
```

3. Test local scanning:
```bash
# Create test directory
mkdir -p test-repo
echo "test content" > test-repo/test.txt

# Run scan
docker run --rm \
  -v $(pwd)/test-repo:/scan_target:ro \
  -v $(pwd)/reports:/reports \
  security-scanner:dev all
```

4. Test GitHub repository scanning:
```bash
docker run --rm \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e GITHUB_OWNER=owner \
  -e GITHUB_REPO=repo \
  -v $(pwd)/reports:/reports \
  security-scanner:dev all
```

## Testing

### Integration Testing

Test the complete workflow:

```bash
# Test with a sample repository
docker run --rm \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e GITHUB_OWNER=cloudon-one \
  -e GITHUB_REPO=test-repo \
  -v $(pwd)/reports:/reports \
  security-scanner:dev all

# Verify reports
ls -la reports/json/final-security-report.json
ls -la reports/html/final-security-report.html
```

### GitHub Action Testing

1. Create test workflow in your fork:
```yaml
# .github/workflows/test.yml
name: Test Scanner
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          fail_on_critical: false
```

2. Push changes and monitor Actions tab

## Code Standards

### Python (git-audit-script.py)

- Follow PEP 8 style guide
- Handle exceptions gracefully
- Add logging for debugging
- Validate all inputs
- Use type hints where appropriate

### Shell Scripts (run_scans.sh)

- Use bash strict mode (`set -euo pipefail`)
- Add error handling
- Comment complex logic
- Validate environment variables
- Use quotes for variables

### Dockerfile

- Use specific tool versions
- Minimize image layers
- Run as non-root user (scanner:1000)
- Clean up temporary files
- Use multi-stage builds

### Configuration (gitleaks.toml)

- Document custom rules
- Test rule changes thoroughly
- Maintain allowlists carefully
- Consider false positive impacts

## Pull Request Guidelines

### PR Checklist

- [ ] Code follows project standards
- [ ] Tests pass successfully
- [ ] Documentation updated if needed
- [ ] No security vulnerabilities introduced
- [ ] Backward compatibility maintained
- [ ] Examples updated if applicable

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security fix

## Testing
- [ ] Tested locally with Docker
- [ ] Tested as GitHub Action
- [ ] Verified report generation

## Screenshots (if applicable)
Add screenshots of report outputs or UI changes
```

## Security Considerations

When contributing:
- Never commit secrets or credentials
- Test security rules thoroughly
- Consider performance impacts
- Document security implications
- Follow secure coding practices
- Review dependencies for vulnerabilities

## Version Management

Follow semantic versioning:
- **Major (X.0.0)**: Breaking changes
- **Minor (0.X.0)**: New features, backward compatible
- **Patch (0.0.X)**: Bug fixes, security patches

### Release Process

1. Update version in `action.yml`
2. Create release notes
3. Tag the release:
```bash
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1
```

4. Build and push Docker image:
```bash
docker build -t ghcr.io/cloudon-one/git-security-scanner:v1.1.1 .
docker push ghcr.io/cloudon-one/git-security-scanner:v1.1.1
```

## Project Structure

```
public-repo/
├── action.yml           # GitHub Action definition
├── Dockerfile          # Container specification
├── git-audit-script.py # Main orchestration
├── run_scans.sh       # Shell wrapper
├── gitleaks.toml      # Secret detection config
├── README.md          # User documentation
├── CONTRIBUTING.md    # This file
└── LICENSE           # MIT license
```

## Tool Versions

Current versions used:
- Gitleaks: v8.28.0
- Trivy: v0.65.0
- Python: 3.11
- Alpine: 3.19

## Getting Help

- Open an issue for bugs
- Start a discussion for questions
- Review existing documentation
- Check closed issues/PRs

## Recognition

Contributors are recognized in:
- Release notes
- GitHub contributors graph
- Project documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make security scanning better for everyone!