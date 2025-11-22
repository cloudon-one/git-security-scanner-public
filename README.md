# Git Security Scanner - GitHub Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Git%20Security%20Scanner-blue?logo=github)](https://github.com/marketplace/actions/git-security-scanner)
[![Release](https://img.shields.io/badge/Release-v2.0.0-green)](https://github.com/cloudon-one/git-security-scanner-public/releases/tag/v2.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue?logo=docker)](https://ghcr.io/cloudon-one/security-scanner)

**Comprehensive security scanning for GitHub repositories** - Detect secrets, vulnerabilities, and misconfigurations in your CI/CD pipeline.

## Features

- **Secret Detection** - Find API keys, passwords, and tokens using Gitleaks
- **Vulnerability Scanning** - Identify CVEs and security issues with Trivy
- **Misconfiguration Detection** - Catch IaC security problems
- **Multiple Report Formats** - JSON, HTML, and SARIF for GitHub Security tab
- **PR Integration** - Automatic security comments on pull requests
- **Quality Gates** - Fail builds on critical security issues

## Quick Start

Add to your workflow (`.github/workflows/security.yml`):

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        uses: cloudon-one/git-security-scanner@v2
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_critical: true
```

## Configuration

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github_token` | No | `${{ github.token }}` | GitHub token for API access |
| `fail_on_critical` | No | `true` | Fail build if critical issues found |
| `scan_type` | No | `all` | Scan type: `all`, `gitleaks`, or `trivy` |
| `repository_path` | No | `.` | Path to repository to scan |
| `upload_sarif` | No | `true` | Upload SARIF to GitHub Security tab |
| `create_pr_comment` | No | `true` | Create PR comments with results |
| `scanner_version` | No | `latest` | Docker image version to use |

### Outputs

| Output | Description |
|--------|-------------|
| `risk_level` | Overall risk: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `critical_count` | Number of critical issues |
| `high_count` | Number of high severity issues |
| `medium_count` | Number of medium severity issues |
| `low_count` | Number of low severity issues |
| `secrets_found` | Number of secrets detected |
| `vulnerabilities_found` | Number of vulnerabilities found |
| `misconfigurations_found` | Number of misconfigurations detected |
| `report_url` | Link to detailed security report |

## Usage Examples

### Basic Security Check

```yaml
- uses: cloudon-one/git-security-scanner@v2
  with:
    fail_on_critical: true
    create_pr_comment: true
```

### Advanced Configuration

```yaml
- uses: cloudon-one/git-security-scanner@v2
  id: security
  with:
    scan_type: all
    fail_on_critical: false
    repository_path: ./src
    
- name: Process Results
  run: |
    echo "Risk Level: ${{ steps.security.outputs.risk_level }}"
    echo "Secrets: ${{ steps.security.outputs.secrets_found }}"
    echo "Vulnerabilities: ${{ steps.security.outputs.vulnerabilities_found }}"
```

### Scheduled Security Audits

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 1'  # Mondays at 2 AM

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cloudon-one/git-security-scanner@v2
        with:
          fail_on_critical: false
```

## Building from Source

### Prerequisites

- Docker
- GitHub Token (for GitHub API access)

### Build Docker Image

```bash
docker build -t git-security-scanner .
```

### Run Local Scan

```bash
# Scan current directory
docker run --rm \
  -v $(pwd):/scan_target:ro \
  -v $(pwd)/reports:/reports \
  security-scanner all

# Scan specific repository
docker run --rm \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e GITHUB_OWNER=owner \
  -e GITHUB_REPO=repo \
  -v $(pwd)/reports:/reports \
  security-scanner all
```

## Architecture

The scanner consists of:

- `action.yml` - GitHub Action definition
- `Dockerfile` - Container with security tools
- `git-audit-script.py` - Main orchestration script
- `run_scans.sh` - Shell wrapper for execution
- `gitleaks.toml` - Secret detection configuration

## Security Tools

- **[Gitleaks](https://github.com/gitleaks/gitleaks)** v8.28.0 - Secret detection
- **[Trivy](https://github.com/aquasecurity/trivy)** v0.65.0 - Vulnerability scanning

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Support

- **Issues**: [Report bugs](https://github.com/cloudon-one/git-security-scanner/issues)
- **Discussions**: [Ask questions](https://github.com/cloudon-one/git-security-scanner/discussions)

## License

MIT License - see [LICENSE](LICENSE) file.

---

Made by [CloudOn One](https://github.com/cloudon-one)
