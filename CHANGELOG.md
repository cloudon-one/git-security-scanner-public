# Changelog

All notable changes to Git Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2025-08-27

### 🚀 First Stable Release

We're excited to announce the first stable release of Git Security Scanner - a comprehensive security scanning GitHub Action that helps protect your repositories from secrets, vulnerabilities, and misconfigurations.

### ✨ Key Features

- **🔍 Multi-Tool Security Scanning**
  - **Gitleaks v8.28.0** for secret detection (API keys, passwords, tokens)
  - **Trivy v0.65.0** for vulnerability and misconfiguration scanning
  - Comprehensive coverage of code, dependencies, and IaC files

- **📊 Rich Reporting**
  - Multiple output formats: JSON, HTML, and SARIF
  - Automatic upload to GitHub Security tab
  - Detailed metrics and risk assessment

- **🔄 Seamless CI/CD Integration**
  - Zero-configuration setup with sensible defaults
  - Automatic PR comments with security summaries
  - Configurable quality gates to fail builds on critical issues

- **📈 Actionable Outputs**
  - Risk level assessment (CRITICAL, HIGH, MEDIUM, LOW)
  - Categorized issue counts by severity
  - Direct links to detailed security reports

### 🎯 What This Release Includes

- Initial GitHub Action implementation with composite steps
- Docker-based scanning engine with Gitleaks and Trivy
- Automated security report generation in multiple formats
- GitHub Security tab integration via SARIF upload
- Pull request comment automation
- Configurable build failure on critical issues
- Comprehensive output variables for workflow integration

### ⚙️ Configuration Options

- `github_token`: GitHub token for API access (default: `${{ github.token }}`)
- `fail_on_critical`: Fail build on critical issues (default: `true`)
- `scan_type`: Type of scan - `all`, `gitleaks`, or `trivy` (default: `all`)
- `repository_path`: Path to scan (default: `.`)
- `upload_sarif`: Upload SARIF to GitHub Security tab (default: `true`)
- `create_pr_comment`: Create PR comments (default: `true`)
- `scanner_version`: Scanner image version (default: `latest`)

### 🏗️ Infrastructure

- Containerized scanning using GitHub Container Registry (`ghcr.io`)
- Automatic image selection with fallback mechanisms
- Support for branch-specific and PR-specific container images
- Optimized for GitHub Actions runners

### 📝 Technical Details

- **Base Image**: Alpine Linux with Python 3.12
- **Security Tools**: Gitleaks v8.28.0, Trivy v0.65.0
- **Report Formats**: JSON, HTML, SARIF
- **Container Registry**: `ghcr.io/cloudon-one/git-security-scanner`

### 🙏 Acknowledgments

Built with industry-leading open source security tools:

- [Gitleaks](https://github.com/gitleaks/gitleaks) for secret detection
- [Trivy](https://github.com/aquasecurity/trivy) for vulnerability scanning

---

[1.1.1]: https://github.com/cloudon-one/git-security-scanner-public/releases/tag/v1.1.1