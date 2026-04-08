# Git Security Scanner - GitHub Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Git%20Security%20Scanner-blue?logo=github)](https://github.com/marketplace/actions/git-security-scanner)
[![Release](https://img.shields.io/github/v/release/cloudon-one/git-security-scanner-public)](https://github.com/cloudon-one/git-security-scanner-public/releases/tag/v2.1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue?logo=docker)](https://github.com/cloudon-one/git-security-scanner-public/pkgs/container/git-security-scanner)

**Comprehensive security scanning for GitHub repositories** - Detect secrets, vulnerabilities, and misconfigurations in your CI/CD pipeline.

## Features

- **Secret Detection** - Find API keys, passwords, and tokens using Gitleaks
- **Vulnerability Scanning** - Identify CVEs and security issues with Trivy
- **OSV Scanning** - Detect known vulnerabilities in open-source dependencies
- **Misconfiguration Detection** - Catch IaC and Kubernetes security problems
- **Multiple Report Formats** - JSON, HTML, and SARIF for GitHub Security tab
- **PR Integration** - Automatic security comments on pull requests
- **Quality Gates** - Fail builds on critical security issues
- **Multi-Architecture** - Supports both AMD64 and ARM64 runners

## Quick Start

Add to your workflow (`.github/workflows/security.yml`):

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write
  packages: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Security Scan
        uses: cloudon-one/git-security-scanner-public@v2.1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_critical: true
          scan_type: all
          create_pr_comment: true

      - name: Upload scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results-${{ github.run_number }}
          path: /tmp/security-scan-results/
          retention-days: 30
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
| `scanner_version` | No | `main` | Docker image tag to use |

### Outputs

| Output | Description |
|--------|-------------|
| `risk_level` | Overall risk: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
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
- uses: cloudon-one/git-security-scanner-public@v2.1
  with:
    fail_on_critical: true
    create_pr_comment: true
```

### Advanced Configuration with Result Processing

```yaml
- uses: cloudon-one/git-security-scanner-public@v2.1
  id: security
  with:
    scan_type: all
    fail_on_critical: false
    repository_path: ./src

- name: Process Results
  if: always()
  run: |
    echo "Risk Level: ${{ steps.security.outputs.risk_level }}"
    echo "Secrets: ${{ steps.security.outputs.secrets_found }}"
    echo "Vulnerabilities: ${{ steps.security.outputs.vulnerabilities_found }}"
    echo "Misconfigurations: ${{ steps.security.outputs.misconfigurations_found }}"
```

### Scheduled Weekly Security Audit

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 1'  # Mondays at 2 AM
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  packages: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: cloudon-one/git-security-scanner-public@v2.1
        with:
          fail_on_critical: false
```

### Gitleaks-Only Scan (Secrets Detection)

```yaml
- uses: cloudon-one/git-security-scanner-public@v2.1
  with:
    scan_type: gitleaks
    fail_on_critical: true
```

### Trivy-Only Scan (Vulnerabilities and Misconfigurations)

```yaml
- uses: cloudon-one/git-security-scanner-public@v2.1
  with:
    scan_type: trivy
    fail_on_critical: false
```

## Building from Source

### Prerequisites

- Docker with BuildKit support
- GitHub Token (for GHCR access)

### Build Docker Image

```bash
docker build --platform linux/amd64 -t git-security-scanner .
```

### Run Local Scan

```bash
# Scan current directory
docker run --rm \
  -v $(pwd):/scan_target:ro \
  -v $(pwd)/reports:/reports \
  git-security-scanner all

# Scan with specific scan type
docker run --rm \
  -v $(pwd):/scan_target:ro \
  -v $(pwd)/reports:/reports \
  git-security-scanner gitleaks
```

## Architecture

```
git-security-scanner-public/
├── action.yml              # GitHub Action composite definition
├── Dockerfile              # Multi-stage container build (Alpine 3.23)
├── git-audit-script.py     # Main Python orchestration script
├── run_scans.sh            # Shell entrypoint wrapper
├── gitleaks.toml           # Secret detection rules configuration
├── Makefile                # Build automation
└── .github/workflows/
    ├── build-scanner-image.yml      # Docker image CI/CD
    └── repository-security-scan.yml # Self-scan workflow
```

## Security Tools (v2.1)

| Tool | Version | Purpose |
|------|---------|---------|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | v8.30.1 | Secret detection in git history and code |
| [Trivy](https://github.com/aquasecurity/trivy) | v0.69.3 | Vulnerability and misconfiguration scanning |
| [OSV-Scanner](https://github.com/google/osv-scanner) | v2.2.1 | Open-source dependency vulnerability detection |
| [Helm](https://helm.sh/) | v3.20.1 | Kubernetes manifest template rendering |

**Base Image**: Alpine Linux 3.23 with Python 3.12

## Changelog

### v2.1 (2026-04-08)

- Updated Gitleaks v8.28.0 → v8.30.1
- Updated Trivy v0.65.0 → v0.69.3
- Added OSV-Scanner v2.2.1 for dependency vulnerability detection
- Updated Helm v3.18.6 → v3.20.1
- Updated Alpine Linux 3.19 → 3.23
- Added SHA256 checksum verification for all security tool downloads (AMD64 + ARM64)
- Fixed JSON report metric extraction paths
- Removed debug print statements from production code
- Improved Docker image pull reliability for cross-repo GHCR access
- Multi-architecture support (AMD64 and ARM64)

### v2 (2025-11-22)

- Added multi-architecture Docker builds
- Added Makefile and Dockerfile checksum verification
- Added unit tests
- Refactored main Python script

### v1.1.1 (2025-08-27)

- Initial public release with Gitleaks and Trivy integration

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Support

- **Issues**: [Report bugs](https://github.com/cloudon-one/git-security-scanner-public/issues)
- **Discussions**: [Ask questions](https://github.com/cloudon-one/git-security-scanner-public/discussions)

## License

MIT License - see [LICENSE](LICENSE) file.

---

Made by [CloudOn One](https://github.com/cloudon-one)
