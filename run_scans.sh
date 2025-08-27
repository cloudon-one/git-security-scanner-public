#!/bin/bash
set -euo pipefail

# Smart defaults with CI/CD detection
detect_ci_environment() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "github"
    elif [[ -n "${GITLAB_CI:-}" ]]; then
        echo "gitlab"
    elif [[ -n "${JENKINS_URL:-}" ]]; then
        echo "jenkins"
    elif [[ -n "${CI:-}" ]]; then
        echo "generic"
    else
        echo "local"
    fi
}

# Auto-detect repository structure and set defaults
CI_PLATFORM=$(detect_ci_environment)

# Intelligent path detection
if [[ -d "/scan_target" ]]; then
    DEFAULT_REPO_PATH="/scan_target"
    DEFAULT_REPORTS_DIR="/scan_target/scan_reports"
elif [[ -d "/scan" ]]; then
    DEFAULT_REPO_PATH="/scan"
    DEFAULT_REPORTS_DIR="/reports"
else
    DEFAULT_REPO_PATH="/scan"
    DEFAULT_REPORTS_DIR="/reports"
fi

# Configuration with smart defaults
REPO_PATH="${REPO_PATH:-$DEFAULT_REPO_PATH}"
REPORTS_DIR="${REPORTS_DIR:-$DEFAULT_REPORTS_DIR}"
GITHUB_OWNER="${GITHUB_OWNER:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_ORG="${GITHUB_ORG:-}"
SCAN_ALL_REPOS_MODE="${SCAN_ALL_REPOS_MODE:-false}"
SCAN_ORG_REPOS_MODE="${SCAN_ORG_REPOS_MODE:-false}"
MAX_REPOS="${MAX_REPOS:-50}"
GITLEAKS_CONFIG_PATH="${GITLEAKS_CONFIG_PATH:-/app/gitleaks.toml}"
PYTHON_SCRIPT_PATH="${PYTHON_SCRIPT_PATH:-/app/git-audit-script.py}"

# CI-specific defaults
SCAN_TYPE="${SCAN_TYPE:-${DEFAULT_SCAN_TYPE:-comprehensive}}"
OUTPUT_FORMATS="${OUTPUT_FORMATS:-${DEFAULT_OUTPUT_FORMATS:-json,html}}"
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-${DEFAULT_FAIL_ON_CRITICAL:-true}}"

ensure_dir_exists() {
    mkdir -p "$1" 2>/dev/null || true
}

# GCS authentication removed - using CI/CD pipeline artifacts instead

display_config() {
    echo "🚀 Security Scanner Starting..."
    echo "=== Scanner Configuration ==="
    echo "- Date: $(date)"
    echo "- CI Platform: ${CI_PLATFORM}"
    echo "- Scan Type: ${SCAN_TYPE}"
    echo "- Repository Path: ${REPO_PATH}"
    echo "- Reports Directory: ${REPORTS_DIR}"
    echo ""
    echo "=== Tool Versions ==="
    echo "- Gitleaks: $(gitleaks version 2>&1 | head -n 1 | sed 's/.*v//' || echo 'Not found')"
    echo "- Trivy: $(trivy --version 2>&1 | head -n 1 || echo 'Not found')"
    echo "- Python3: $(python3 --version || echo 'Not found')"
    
    if [[ -n "$GITHUB_OWNER" ]]; then
        echo ""
        echo "=== GitHub Configuration ==="
        echo "- Owner: ${GITHUB_OWNER}"
        if [[ -n "$GITHUB_REPO" ]]; then
            echo "- Repository: ${GITHUB_REPO}"
        fi
    fi
    if [[ -n "$GITHUB_ORG" ]]; then
        echo "- Organization: ${GITHUB_ORG}"
    fi
    echo "=============================================="
}

display_help() {
    echo ""
    echo "🛡️ Security Scanner - Help"
    echo ""
    echo "USAGE:"
    echo "    docker run --rm ghcr.io/cloudon-one/security-scanner:latest [COMMAND] [OPTIONS]"
    echo ""
    echo "COMMANDS:"
    echo "    all         Run comprehensive scan (Gitleaks + Trivy) [default]"
    echo "    gitleaks    Run only Gitleaks secret detection"
    echo "    trivy       Run only Trivy vulnerability/misconfiguration scan"
    echo "    help        Show this help message"
    echo ""
    echo "SCANNING MODES:"
    echo "    Local Repository Scan:"
    echo "      docker run --rm -v /path/to/repo:/scan_target ghcr.io/cloudon-one/security-scanner:latest"
    echo ""
    echo "    GitHub Repository Scan:"
    echo "      docker run --rm -e GITHUB_TOKEN=xyz -e GITHUB_OWNER=user -e GITHUB_REPO=repo ghcr.io/cloudon-one/security-scanner:latest"
    echo ""
    echo "    Organization Scan:"
    echo "      docker run --rm -e GITHUB_TOKEN=xyz -e GITHUB_ORG=myorg -e SCAN_ORG_REPOS_MODE=true ghcr.io/cloudon-one/security-scanner:latest"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "    GITHUB_TOKEN        GitHub personal access token"
    echo "    GITHUB_OWNER        GitHub username or organization"
    echo "    GITHUB_REPO         Repository name (for single repo scans)"
    echo "    GITHUB_ORG          Organization name (for org scans)"  
    echo "    SCAN_ORG_REPOS_MODE Set to 'true' for organization scans"
    echo "    REPO_PATH           Path to scan (default: /scan)"
    echo "    REPORTS_DIR         Output directory (default: /reports)"
    echo "    FAIL_ON_CRITICAL    Exit with error on critical findings (default: true)"
    echo ""
    echo "EXAMPLES:"
    echo "    # Scan local repository"
    echo "    docker run --rm -v \$(pwd):/scan_target ghcr.io/cloudon-one/security-scanner:latest"
    echo ""
    echo "    # Scan specific GitHub repository"  
    echo "    docker run --rm -e GITHUB_TOKEN=token -e GITHUB_OWNER=user -e GITHUB_REPO=myrepo ghcr.io/cloudon-one/security-scanner:latest"
    echo ""
    echo "    # Run only secret detection"
    echo "    docker run --rm -v \$(pwd):/scan_target ghcr.io/cloudon-one/security-scanner:latest gitleaks"
    echo ""
}

scan_gitleaks_local() {
    local target_path="$1" 
    local output_dir="$2"  
    local report_file="${output_dir}/gitleaks-report.json" 
    local sarif_file="${output_dir}/gitleaks.sarif"
    ensure_dir_exists "${output_dir}"

    echo "--- Running Gitleaks on local path: ${target_path} ---"
    echo "- Using Gitleaks config: ${GITLEAKS_CONFIG_PATH}"
    rm -f "${report_file}" "${sarif_file}"

    if [[ -d "${target_path}/.git" ]]; then
        echo "- Git repository detected, scanning with git history"
        # Generate JSON report
        gitleaks detect \
            --source="${target_path}" \
            --config="${GITLEAKS_CONFIG_PATH}" \
            --report-path="${report_file}" \
            --report-format="json" \
            --exit-code 0 2>/dev/null || true
        # Generate SARIF report
        gitleaks detect \
            --source="${target_path}" \
            --config="${GITLEAKS_CONFIG_PATH}" \
            --report-path="${sarif_file}" \
            --report-format="sarif" \
            --exit-code 0 2>/dev/null || true
    else
        echo "- No git repository detected, scanning filesystem only"
        # Generate JSON report
        gitleaks detect \
            --source="${target_path}" \
            --config="${GITLEAKS_CONFIG_PATH}" \
            --no-git \
            --report-path="${report_file}" \
            --report-format="json" \
            --exit-code 0 2>/dev/null || true
        # Generate SARIF report
        gitleaks detect \
            --source="${target_path}" \
            --config="${GITLEAKS_CONFIG_PATH}" \
            --no-git \
            --report-path="${sarif_file}" \
            --report-format="sarif" \
            --exit-code 0 2>/dev/null || true
    fi

    if [[ -f "${report_file}" ]]; then
        local findings_count
        findings_count=$(jq 'if type == "array" then length else (.findings // []) | length end' "${report_file}" 2>/dev/null || echo "0")
        echo "- Gitleaks scan complete. Found ${findings_count} potential issues."
    else
        echo "- Gitleaks report was not generated, creating empty report."
        echo '[]' > "${report_file}" 
    fi
}

scan_trivy_fs_local() {
    local target_path="$1" 
    local output_dir="$2"  
    local report_file="${output_dir}/trivy-fs-report.json" 
    local sarif_file="${output_dir}/trivy.sarif"
    ensure_dir_exists "${output_dir}"

    echo "--- Running Trivy Filesystem Scan on local path: ${target_path} ---"
    if [[ ! -d "${target_path}" && ! -f "${target_path}" ]]; then 
        echo "- Target path does not exist: ${target_path}"
        echo '{"Results":[]}' > "${report_file}"
        return 1
    fi

    rm -f "${report_file}" "${sarif_file}"

    # Generate JSON report
    trivy fs \
        --scanners vuln,misconfig \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --format json \
        --output "${report_file}" \
        --exit-code 0 \
        "${target_path}" || true
    
    # Generate SARIF report
    trivy fs \
        --scanners vuln,misconfig \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --format sarif \
        --output "${sarif_file}" \
        --exit-code 0 \
        "${target_path}" || true

    if [[ -f "${report_file}" ]]; then
        local report_size
        report_size=$(stat -c%s "${report_file}" 2>/dev/null || wc -c < "${report_file}" | xargs echo 2>/dev/null || echo "0") 
        if [[ "${report_size}" -eq 0 ]]; then
            echo "- Trivy report file is empty, creating default structure."
            echo '{"Results":[]}' > "${report_file}"
        elif ! jq empty "${report_file}" &>/dev/null; then 
            echo "- Trivy report contains invalid JSON, creating empty report."
            echo '{"Results":[]}' > "${report_file}"
        else
            local vuln_count
            vuln_count=$(jq '[.Results[]? | select(.Vulnerabilities != null) | .Vulnerabilities[]] | length' "${report_file}" 2>/dev/null || echo "0")
            echo "- Trivy scan complete. Found ${vuln_count} vulnerabilities."
        fi
    else
        echo "- Trivy report was not generated, creating empty report."
        echo '{"Results":[]}' > "${report_file}"
    fi
    return 0 
}


main() {
    if [ -f /opt/venv/bin/activate ]; then
        source /opt/venv/bin/activate
    fi

    display_config
    ensure_dir_exists "${REPORTS_DIR}" 

    local action="${1:-all}"
    shift || true 
    local is_local_path_scan=true
    if [[ "$SCAN_ALL_REPOS_MODE" == "true" || "$SCAN_ORG_REPOS_MODE" == "true" || (-n "$GITHUB_REPO" && -n "$GITHUB_OWNER") ]]; then
        is_local_path_scan=false
    fi

    if [[ "$action" == "gitleaks" || "$action" == "trivy" || ("$action" == "all" && "$is_local_path_scan" == "true") ]]; then
        if [[ ! -d "${REPO_PATH}" ]]; then
            echo "ERROR: Scan target directory '${REPO_PATH}' not found."
            echo "Please mount your repository to /scan_target or ensure REPO_PATH is correctly set."
            exit 1
        fi
    fi

    case "$action" in
        help|--help|-h)
            display_help
            exit 0
            ;;
        gitleaks)
            scan_gitleaks_local "${REPO_PATH}" "${REPORTS_DIR}"
            ;;
        trivy)
            scan_trivy_fs_local "${REPO_PATH}" "${REPORTS_DIR}"
            ;;
        all)
        if [[ "$is_local_path_scan" == "true" ]]; then
            echo "🔍 Running comprehensive security scan..."
            scan_gitleaks_local "${REPO_PATH}" "${REPORTS_DIR}"
            scan_trivy_fs_local "${REPO_PATH}" "${REPORTS_DIR}"
            
            echo "📊 Generating consolidated report..."
            python3 "${PYTHON_SCRIPT_PATH}" \
                --reports-dir "${REPORTS_DIR}" \
                --repo-path "${REPO_PATH}" \
                --action generate-summary "$@"
            
            # Automatic CI/CD quality gate checking
            if [[ "$FAIL_ON_CRITICAL" == "true" ]] && [[ -f "${REPORTS_DIR}/json/final-security-report.json" ]]; then
                echo "🛡️  Running security quality gates..."
                RISK_LEVEL=$(jq -r '.metadata.risk_level // "UNKNOWN"' "${REPORTS_DIR}/json/final-security-report.json" 2>/dev/null || echo "UNKNOWN")
                CRITICAL_ISSUES=$(jq -r '.metadata.critical_issues // 0' "${REPORTS_DIR}/json/final-security-report.json" 2>/dev/null || echo "0")
                SECRETS_FOUND=$(jq -r '.executive_summary.quick_stats.gitleaks.secrets_found // 0' "${REPORTS_DIR}/json/final-security-report.json" 2>/dev/null || echo "0")
                
                echo "📋 Security Results Summary:"
                echo "  - Risk Level: ${RISK_LEVEL}"
                echo "  - Critical Issues: ${CRITICAL_ISSUES}"  
                echo "  - Secrets Found: ${SECRETS_FOUND}"
                echo "  - CI Platform: ${CI_PLATFORM}"
                
                if [[ "$RISK_LEVEL" == "CRITICAL" ]] || [[ "$CRITICAL_ISSUES" -gt 0 ]] || [[ "$SECRETS_FOUND" -gt 0 ]]; then
                    echo ""
                    echo "🚨 CRITICAL SECURITY ISSUES DETECTED 🚨"
                    echo "Quality gate failed due to critical security findings."
                    echo "Please address these issues before proceeding."
                    exit 1
                else
                    echo "✅ Security quality gates passed - no critical issues found"
                fi
            fi
        else
                if [[ "$SCAN_ORG_REPOS_MODE" == "true" ]]; then
                    python3 "${PYTHON_SCRIPT_PATH}" --reports-dir "${REPORTS_DIR}" --action scan-org "$@"
                elif [[ "$SCAN_ALL_REPOS_MODE" == "true" ]]; then
                    python3 "${PYTHON_SCRIPT_PATH}" --reports-dir "${REPORTS_DIR}" --action scan-user "$@"
                elif [[ -n "$GITHUB_REPO" && -n "$GITHUB_OWNER" ]]; then
                    python3 "${PYTHON_SCRIPT_PATH}" --reports-dir "${REPORTS_DIR}" --action scan-single-repo "$@"
                else
                    echo "ERROR: Misconfigured 'all' action: No local path scan, and no GitHub multi-repo mode detected."
                    exit 1
                fi
            fi
            ;;
        scan-project|scan-user|scan-single-repo)
            python3 "${PYTHON_SCRIPT_PATH}" --reports-dir "${REPORTS_DIR}" --action "${action}" "$@"
            ;;
        generate-summary)
            python3 "${PYTHON_SCRIPT_PATH}" --reports-dir "${REPORTS_DIR}" --action "${action}" "$@"
            ;;
        *)
            if command -v "$action" >/dev/null 2>&1; then
                exec "$action" "$@"
            fi
            exit 1
            ;;
    esac

    echo "--- All operations complete. Reports in ${REPORTS_DIR} ---"
}

main "$@"