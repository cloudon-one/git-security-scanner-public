#!/usr/bin/env python3
"""
GitHub Security Scanner

This script handles repository scanning and report processing
for comprehensive security analysis using Gitleaks and Trivy.
"""

import argparse
import json
import os
import sys
import tempfile
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import html
import requests

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_REPO = os.environ.get("GITHUB_REPO")
GITHUB_ORG = os.environ.get("GITHUB_ORG")
SCAN_ALL_REPOS = os.environ.get("SCAN_ALL_REPOS", "false").lower() == "true"
SCAN_ORG_REPOS = os.environ.get("SCAN_ORG_REPOS", "false").lower() == "true"
MAX_REPOS = int(os.environ.get("MAX_REPOS", "50"))
GITHUB_API_BASE_URL = "https://api.github.com"
REPO_PATH_FROM_ARGS = None


class CleanFormatter(logging.Formatter):
    """Custom formatter to remove redundant prefixes and clean up output"""

    def format(self, record):
        if record.levelno == logging.INFO:
            return record.getMessage()
        elif record.levelno == logging.WARNING:
            return f"WARNING: {record.getMessage()}"
        elif record.levelno == logging.ERROR:
            return f"ERROR: {record.getMessage()}"
        else:
            return super().format(record)


logging.basicConfig(
    level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler()]
)
for handler in logging.root.handlers:
    handler.setFormatter(CleanFormatter())

logger = logging.getLogger(__name__)


def get_current_utc_time() -> datetime:
    return datetime.now(timezone.utc)


def safe_remove_if_exists(path_to_remove: str) -> None:
    try:
        if os.path.isfile(path_to_remove):
            os.remove(path_to_remove)
            logger.debug(f"Removed existing file: {path_to_remove}")
        elif os.path.isdir(path_to_remove):
            import shutil

            shutil.rmtree(path_to_remove)
            logger.debug(f"Removed existing directory: {path_to_remove}")
    except Exception as e:
        logger.warning(f"Could not remove {path_to_remove}: {e}")


def get_github_auth() -> Optional[str]:
    if not GITHUB_TOKEN:
        logger.warning(
            "GITHUB_TOKEN environment variable is not set. GitHub API calls will fail."
        )
        return None
    return GITHUB_TOKEN


def make_github_request(endpoint: str, params: Optional[Dict] = None) -> Dict:
    url = f"{GITHUB_API_BASE_URL}/{endpoint}"
    token = get_github_auth()
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    headers["Accept"] = "application/vnd.github.v3+json"

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "unknown"
        logger.error(
            f"HTTP Error making GitHub request to {url}: {e} (Status Code: {status_code})"
        )
        if e.response is not None and e.response.content:
            logger.error(
                f"Response content: {e.response.content.decode('utf-8', errors='ignore')}"
            )
        return {}
    except requests.exceptions.RequestException as e:
        logger.error(f"Request Error making GitHub request to {url}: {e}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"JSON Decode Error from GitHub request to {url}: {e}")
        return {}


def get_paginated_results(
    endpoint: str, params: Optional[Dict] = None, max_pages: int = 100
) -> List[Dict]:
    """Get paginated results from GitHub API"""
    token = get_github_auth()
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    headers["Accept"] = "application/vnd.github.v3+json"

    all_results = []
    page = 1
    next_url: Optional[str] = f"{GITHUB_API_BASE_URL}/{endpoint}"

    while next_url and page <= max_pages:
        try:
            if params is None:
                params = {}
            params["page"] = page
            params["per_page"] = 100

            response = requests.get(
                next_url, headers=headers, params=params, timeout=30
            )
            response.raise_for_status()

            results = response.json()
            if isinstance(results, list):
                all_results.extend(results)
            else:
                all_results.append(results)
            if "next" in response.links:
                next_url = response.links["next"]["url"]
                page += 1
            else:
                next_url = None

        except Exception as e:
            logger.error(f"Error fetching page {page} from {endpoint}: {e}")
            break

    return all_results


def get_organization_repositories(org: str) -> List[Dict]:
    """Get all repositories in a GitHub organization"""
    return get_paginated_results(f"orgs/{org}/repos")


def get_user_repositories(owner: str) -> List[Dict]:
    """Get all repositories for a GitHub user"""
    return get_paginated_results(f"users/{owner}/repos")


def run_scan_command(scan_type: str, repo_path: str, output_path: str) -> int:
    """Run a specific security scan command"""
    ensure_dir_exists(output_path)

    if scan_type == "gitleaks":
        return run_gitleaks_scan(repo_path, output_path)
    elif scan_type == "trivy-fs":
        return run_trivy_fs_scan(repo_path, output_path)
    elif scan_type == "trivy-config":
        return run_trivy_config_scan(repo_path, output_path)
    else:
        logger.error(f"Unknown scan type: {scan_type}")
        return 1


def run_gitleaks_scan(repo_path: str, output_path: str) -> int:
    """Run Gitleaks secret detection scan"""
    report_file = os.path.join(output_path, "gitleaks-report.json")
    config_path = "/app/gitleaks.toml"

    logger.info(f"Running Gitleaks scan on: {repo_path}")
    logger.info(f"Using config: {config_path}")

    safe_remove_if_exists(report_file)

    cmd = [
        "gitleaks",
        "detect",
        "--source",
        repo_path,
        "--config",
        config_path,
        "--report-path",
        report_file,
        "--report-format",
        "json",
        "--exit-code",
        "0",
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, dict) and "findings" in data:
                        findings_count = len(data["findings"])
                    elif isinstance(data, list):
                        findings_count = len(data)
                    else:
                        findings_count = 0
                    logger.info(
                        f"Gitleaks scan complete. Found {findings_count} potential issues."
                    )
                except json.JSONDecodeError:
                    logger.warning("Gitleaks report is not valid JSON")
        else:
            logger.info("Gitleaks scan complete. No issues found.")
            # Create empty report
            with open(report_file, "w") as f:
                json.dump([], f)

        return 0
    except subprocess.TimeoutExpired:
        logger.error("Gitleaks scan timed out")
        return 1
    except subprocess.CalledProcessError as e:
        logger.error(f"Gitleaks scan failed: {e}")
        return e.returncode
    except Exception as e:
        logger.error(f"Unexpected error during Gitleaks scan: {e}")
        return 1


def run_trivy_fs_scan(repo_path: str, output_path: str) -> int:
    """Run Trivy filesystem vulnerability scan"""
    report_file = os.path.join(output_path, "trivy-fs-report.json")

    logger.info(f"Running Trivy filesystem scan on: {repo_path}")

    safe_remove_if_exists(report_file)

    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--output",
        report_file,
        "--severity",
        "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        repo_path,
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                try:
                    data = json.load(f)
                    if "Results" in data:
                        total_vulns = sum(
                            len(result.get("Vulnerabilities", []))
                            for result in data["Results"]
                        )
                        logger.info(
                            f"Trivy filesystem scan complete. Found {total_vulns} vulnerabilities."
                        )
                    else:
                        logger.info(
                            "Trivy filesystem scan complete. No vulnerabilities found."
                        )
                except json.JSONDecodeError:
                    logger.warning("Trivy filesystem report is not valid JSON")
        else:
            logger.info("Trivy filesystem scan complete. No vulnerabilities found.")
            with open(report_file, "w") as f:
                json.dump({"Results": []}, f)

        return 0
    except subprocess.TimeoutExpired:
        logger.error("Trivy filesystem scan timed out")
        return 1
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy filesystem scan failed: {e}")
        return e.returncode
    except Exception as e:
        logger.error(f"Unexpected error during Trivy filesystem scan: {e}")
        return 1


def run_trivy_config_scan(repo_path: str, output_path: str) -> int:
    """Run Trivy configuration scan"""
    report_file = os.path.join(output_path, "trivy-config-report.json")

    logger.info(f"Running Trivy configuration scan on: {repo_path}")

    safe_remove_if_exists(report_file)

    cmd = [
        "trivy",
        "config",
        "--format",
        "json",
        "--output",
        report_file,
        "--severity",
        "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        repo_path,
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if os.path.exists(report_file):
            with open(report_file, "r") as f:
                try:
                    data = json.load(f)
                    if "Results" in data:
                        total_misconfigs = sum(
                            len(result.get("Misconfigurations", []))
                            for result in data["Results"]
                        )
                        logger.info(
                            f"Trivy configuration scan complete. Found {total_misconfigs} misconfigurations."
                        )
                    else:
                        logger.info(
                            "Trivy configuration scan complete. No misconfigurations found."
                        )
                except json.JSONDecodeError:
                    logger.warning("Trivy configuration report is not valid JSON")
        else:
            logger.info(
                "Trivy configuration scan complete. No misconfigurations found."
            )
            with open(report_file, "w") as f:
                json.dump({"Results": []}, f)

        return 0
    except subprocess.TimeoutExpired:
        logger.error("Trivy configuration scan timed out")
        return 1
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy configuration scan failed: {e}")
        return e.returncode
    except Exception as e:
        logger.error(f"Unexpected error during Trivy configuration scan: {e}")
        return 1


def ensure_dir_exists(path: str) -> None:
    """Ensure directory exists"""
    os.makedirs(path, exist_ok=True)


def generate_dynamic_recommendations(detailed_reports: Dict) -> Dict:
    """Generate dynamic security recommendations based on scan results"""
    recommendations = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    # Gitleaks recommendations
    if "gitleaks" in detailed_reports:
        gitleaks_data = detailed_reports["gitleaks"]
        if isinstance(gitleaks_data, list) and len(gitleaks_data) > 0:
            recommendations["critical"].append(
                "🔴 CRITICAL: Secrets detected in repository. Immediately rotate all exposed credentials and review access controls."
            )
            recommendations["high"].append(
                "🔴 HIGH: Implement secret scanning in CI/CD pipeline to prevent future secret commits."
            )
            recommendations["medium"].append(
                "🟡 MEDIUM: Review and update .gitignore to exclude sensitive files."
            )

    # Trivy vulnerability recommendations
    if "trivy-fs" in detailed_reports:
        trivy_data = detailed_reports["trivy-fs"]
        if isinstance(trivy_data, dict) and "Results" in trivy_data:
            critical_vulns = 0
            high_vulns = 0
            for result in trivy_data["Results"]:
                for vuln in result.get("Vulnerabilities", []):
                    if vuln.get("Severity") == "CRITICAL":
                        critical_vulns += 1
                    elif vuln.get("Severity") == "HIGH":
                        high_vulns += 1

            if critical_vulns > 0:
                recommendations["critical"].append(
                    f"🔴 CRITICAL: {critical_vulns} critical vulnerabilities detected. Update dependencies immediately."
                )
            if high_vulns > 0:
                recommendations["high"].append(
                    f"🔴 HIGH: {high_vulns} high severity vulnerabilities detected. Plan updates within 30 days."
                )

    if "trivy-config" in detailed_reports:
        trivy_config_data = detailed_reports["trivy-config"]
        if isinstance(trivy_config_data, dict) and "Results" in trivy_config_data:
            misconfigs = sum(
                len(result.get("Misconfigurations", []))
                for result in trivy_config_data["Results"]
            )
            if misconfigs > 0:
                recommendations["high"].append(
                    f"🔴 HIGH: {misconfigs} security misconfigurations detected. Review and fix configuration issues."
                )

    if not any(recommendations.values()):
        recommendations["info"].append(
            "✅ No security issues detected. Continue monitoring and maintain security best practices."
        )

    return recommendations


def generate_combined_report(
    owner: str,
    repo_slug: str,
    scan_results_summary: Dict,
    detailed_reports_data: Optional[Dict] = None,
    branch: str = None,
) -> Dict:
    """Generate a comprehensive security report combining all scan results"""
    current_time_obj = get_current_utc_time()
    current_date = current_time_obj.strftime("%Y-%m-%d")
    current_time = current_time_obj.strftime("%H:%M:%S UTC")

    # Get actual metadata from environment or use provided values
    actual_owner = os.environ.get("GITHUB_OWNER")
    actual_repo_slug = os.environ.get("GITHUB_REPO")
    actual_branch = (
        branch
        or os.environ.get("GITHUB_REF_NAME")
        or os.environ.get("GIT_BRANCH")
        or os.environ.get("BRANCH_NAME")
    )
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")

    if not actual_owner:
        actual_owner = owner or "unknown-owner"
    if not actual_repo_slug:
        actual_repo_slug = repo_slug or "unknown-repo"
    if actual_owner == "local_scan" or actual_repo_slug == "scan_target":
        actual_owner = "local-scan"
        actual_repo_slug = "local-repository"
    if repo_full_name and "/" in repo_full_name:
        parts = repo_full_name.split("/")
        if len(parts) >= 2:
            if actual_owner in ["unknown-owner", "local-scan"]:
                actual_owner = parts[0]
            if actual_repo_slug in ["unknown-repo", "local-repository"]:
                actual_repo_slug = parts[1]

    logger.info(
        f"Report metadata - Owner: {actual_owner}, Repo: {actual_repo_slug}, Branch: {actual_branch}"
    )

    gitleaks_findings = scan_results_summary.get("gitleaks", {}).get(
        "findings_count", 0
    )
    trivy_vulnerabilities = scan_results_summary.get("trivy-fs", {}).get(
        "vulnerabilities_count", 0
    )
    trivy_misconfigurations = scan_results_summary.get("trivy-fs", {}).get(
        "misconfigurations_count", 0
    )
    total_issues = gitleaks_findings + trivy_vulnerabilities + trivy_misconfigurations

    secret_risk = "CRITICAL" if gitleaks_findings > 0 else "LOW"
    vuln_risk = (
        "CRITICAL"
        if trivy_vulnerabilities > 10
        else "HIGH"
        if trivy_vulnerabilities > 5
        else "MEDIUM"
        if trivy_vulnerabilities > 0
        else "LOW"
    )
    config_risk = (
        "HIGH"
        if trivy_misconfigurations > 5
        else "MEDIUM"
        if trivy_misconfigurations > 0
        else "LOW"
    )
    overall_risk = (
        "CRITICAL"
        if gitleaks_findings > 0 or total_issues > 25
        else "HIGH"
        if total_issues > 15
        else "MEDIUM"
        if total_issues > 8
        else "LOW"
        if total_issues > 0
        else "INFO"
    )
    combined_report = {
        "metadata": {
            "scan_date": current_date,
            "scan_time": current_time,
            "owner": actual_owner,
            "repository": actual_repo_slug,
            "branch": actual_branch,
            "full_name": repo_full_name or f"{actual_owner}/{actual_repo_slug}",
            "scan_tools": ["gitleaks", "trivy-fs"],
        },
        "executive_summary": {
            "total_issues": total_issues,
            "risk_level": overall_risk,
            "secret_exposure_risk": secret_risk,
            "vulnerability_risk": vuln_risk,
            "configuration_risk": config_risk,
            "gitleaks_secrets_found": gitleaks_findings,
            "trivy_vulnerabilities_found": trivy_vulnerabilities,
            "trivy_misconfigurations_found": trivy_misconfigurations,
            "quick_stats": {
                "gitleaks": {"secrets_found": gitleaks_findings},
                "trivy": {
                    "vulnerabilities_found": trivy_vulnerabilities,
                    "misconfigurations_found": trivy_misconfigurations,
                },
            },
        },
        "detailed_results": detailed_reports_data,
        "recommendations": generate_dynamic_recommendations(
            detailed_reports_data or {}
        ),
        "scan_details": {
            "gitleaks": {"findings": gitleaks_findings, "risk_level": secret_risk},
            "trivy_vulnerabilities": {
                "findings": trivy_vulnerabilities,
                "risk_level": vuln_risk,
            },
            "trivy_misconfigurations": {
                "findings": trivy_misconfigurations,
                "risk_level": config_risk,
            },
        },
    }

    if total_issues > 0:
        combined_report["executive_summary"]["description"] = (
            f"Security scan completed for {actual_owner}/{actual_repo_slug}. Total issues found: {total_issues}. Overall risk level: {overall_risk}."
        )
    else:
        combined_report["executive_summary"]["description"] = (
            f"Security scan completed for {actual_owner}/{actual_repo_slug}. No issues found by automated scanners. Overall risk level: INFO."
        )
    return combined_report


def get_report_css() -> str:
    """Return the CSS styles for the HTML report"""
    return """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header .subtitle { margin-top: 10px; opacity: 0.9; font-size: 1.1em; }
        .content { padding: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .meta-item { background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }
        .meta-item strong { display: block; color: #495057; margin-bottom: 5px; }
        .risk-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 0.9em; text-transform: uppercase; }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #fd7e14; color: white; }
        .risk-medium { background: #ffc107; color: #212529; }
        .risk-low { background: #28a745; color: white; }
        .risk-info { background: #17a2b8; color: white; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); cursor: pointer; transition: all 0.3s ease; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .stat-card.clickable { border-color: #667eea; }
        .stat-number { font-size: 2em; font-weight: bold; color: #495057; }
        .stat-number.critical { color: #dc3545; }
        .stat-number.high { color: #fd7e14; }
        .stat-number.medium { color: #ffc107; }
        .stat-number.low { color: #28a745; }
        .stat-number.zero { color: #6c757d; }
        .stat-label { color: #6c757d; margin-top: 5px; }
        .recommendations { margin-top: 20px; }
        .rec-category { margin-bottom: 20px; }
        .rec-category h3 { margin-bottom: 10px; color: #495057; }
        .rec-item { background: #f8f9fa; padding: 15px; margin-bottom: 10px; border-radius: 6px; border-left: 4px solid #667eea; }
        .rec-critical { border-left-color: #dc3545; }
        .rec-high { border-left-color: #fd7e14; }
        .rec-medium { border-left-color: #ffc107; }
        .rec-low { border-left-color: #28a745; }
        .rec-info { border-left-color: #17a2b8; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; border-top: 1px solid #dee2e6; }
        .findings-section { margin-top: 30px; }
        .findings-tool { margin-bottom: 25px; }
        .findings-tool h3 { background: #e9ecef; padding: 10px 15px; margin: 0 0 15px 0; border-left: 4px solid #667eea; }
        .finding-item { background: white; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 15px; padding: 15px; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { font-weight: bold; color: #495057; flex-grow: 1; }
        .finding-severity { font-size: 0.85em; padding: 3px 8px; border-radius: 12px; font-weight: bold; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #212529; }
        .severity-low { background: #28a745; color: white; }
        .severity-unknown { background: #6c757d; color: white; }
        .finding-details { margin-top: 10px; }
        .finding-detail-row { margin-bottom: 8px; }
        .finding-label { font-weight: bold; color: #495057; display: inline-block; min-width: 80px; }
        .finding-value { color: #6c757d; }
        .code-snippet { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 0.9em; margin: 8px 0; overflow-x: auto; }
        .remediation-box { background: #e7f3ff; border: 1px solid #bee5eb; border-radius: 6px; padding: 15px; margin-top: 10px; }
        .remediation-title { font-weight: bold; color: #0c5460; margin-bottom: 8px; }
        .remediation-text { color: #0c5460; line-height: 1.5; }
    """


def convert_json_to_html(report_data: Dict[str, Any]) -> str:
    """Convert the JSON report to a formatted HTML report"""

    def esc(text: Any) -> str:
        return html.escape(str(text))

    meta = report_data.get("metadata", {})
    exec_summary = report_data.get("executive_summary", {})
    recommendations = report_data.get("recommendations", {})
    scan_details = report_data.get("scan_details", {})
    detailed_results = report_data.get("detailed_results", {})

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {esc(meta.get("owner", "N/A"))}/{esc(meta.get("repository", "N/A"))}</title>
    <style>
        {get_report_css()}
    </style>
    <script>
        function scrollToSection(sectionId) {{
            const element = document.getElementById(sectionId);
            if (element) {{
                element.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                element.style.backgroundColor = '#fff3cd';
                setTimeout(() => element.style.backgroundColor = '', 2000);
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Report</h1>
            <div class="subtitle">{esc(meta.get("owner", "N/A"))}/{esc(meta.get("repository", "N/A"))}</div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="meta-grid">
                    <div class="meta-item">
                        <strong>Repository</strong>
                        {esc(meta.get("owner", "N/A"))}/{esc(meta.get("repository", "N/A"))}
                    </div>
                    <div class="meta-item">
                        <strong>Branch</strong>
                        {esc(meta.get("branch", "N/A"))}
                    </div>
                    <div class="meta-item">
                        <strong>Scan Date</strong>
                        {esc(meta.get("scan_date", "N/A"))}
                    </div>
                    <div class="meta-item">
                        <strong>Scan Time</strong>
                        {esc(meta.get("scan_time", "N/A"))}
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card clickable" onclick="scrollToSection('detailed-findings')">
                        <div class="stat-number {("critical" if exec_summary.get("total_issues", 0) > 20 else "high" if exec_summary.get("total_issues", 0) > 10 else "medium" if exec_summary.get("total_issues", 0) > 0 else "zero")}">{exec_summary.get("total_issues", 0)}</div>
                        <div class="stat-label">Total Issues</div>
                    </div>
                    <div class="stat-card clickable" onclick="scrollToSection('gitleaks-findings')">
                        <div class="stat-number {("critical" if exec_summary.get("gitleaks_secrets_found", 0) > 0 else "zero")}">{exec_summary.get("gitleaks_secrets_found", 0)}</div>
                        <div class="stat-label">Secrets Found</div>
                    </div>
                    <div class="stat-card clickable" onclick="scrollToSection('trivy-vulnerabilities')">
                        <div class="stat-number {("critical" if exec_summary.get("trivy_vulnerabilities_found", 0) > 10 else "high" if exec_summary.get("trivy_vulnerabilities_found", 0) > 5 else "medium" if exec_summary.get("trivy_vulnerabilities_found", 0) > 0 else "zero")}">{exec_summary.get("trivy_vulnerabilities_found", 0)}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    <div class="stat-card clickable" onclick="scrollToSection('trivy-misconfigurations')">
                        <div class="stat-number {("high" if exec_summary.get("trivy_misconfigurations_found", 0) > 5 else "medium" if exec_summary.get("trivy_misconfigurations_found", 0) > 0 else "zero")}">{exec_summary.get("trivy_misconfigurations_found", 0)}</div>
                        <div class="stat-label">Misconfigurations</div>
                    </div>
                </div>
                
                <div style="text-align: center; margin: 20px 0;">
                    <span class="risk-badge risk-{exec_summary.get("risk_level", "info").lower()}">
                        Overall Risk: {esc(exec_summary.get("risk_level", "INFO"))}
                    </span>
                </div>
                
                <p style="color: #495057; line-height: 1.6; margin: 20px 0;">
                    {esc(exec_summary.get("description", "No description available."))}
                </p>
            </div>
            
            <div class="section">
                <h2>🔍 Scan Details</h2>
                <div class="stats-grid">
                    <div class="stat-card clickable" onclick="scrollToSection('gitleaks-findings')">
                        <div class="stat-number {("critical" if scan_details.get("gitleaks", {}).get("findings", 0) > 0 else "zero")}">{scan_details.get("gitleaks", {}).get("findings", 0)}</div>
                        <div class="stat-label">Gitleaks Findings</div>
                        <div class="risk-badge risk-{scan_details.get("gitleaks", {}).get("risk_level", "info").lower()}" style="margin-top: 10px;">
                            {esc(scan_details.get("gitleaks", {}).get("risk_level", "INFO"))}
                        </div>
                    </div>
                    <div class="stat-card clickable" onclick="scrollToSection('trivy-vulnerabilities')">
                        <div class="stat-number {("critical" if scan_details.get("trivy_vulnerabilities", {}).get("findings", 0) > 10 else "high" if scan_details.get("trivy_vulnerabilities", {}).get("findings", 0) > 5 else "medium" if scan_details.get("trivy_vulnerabilities", {}).get("findings", 0) > 0 else "zero")}">{scan_details.get("trivy_vulnerabilities", {}).get("findings", 0)}</div>
                        <div class="stat-label">Trivy Vulnerabilities</div>
                        <div class="risk-badge risk-{scan_details.get("trivy_vulnerabilities", {}).get("risk_level", "info").lower()}" style="margin-top: 10px;">
                            {esc(scan_details.get("trivy_vulnerabilities", {}).get("risk_level", "INFO"))}
                        </div>
                    </div>
                    <div class="stat-card clickable" onclick="scrollToSection('trivy-misconfigurations')">
                        <div class="stat-number {("high" if scan_details.get("trivy_misconfigurations", {}).get("findings", 0) > 5 else "medium" if scan_details.get("trivy_misconfigurations", {}).get("findings", 0) > 0 else "zero")}">{scan_details.get("trivy_misconfigurations", {}).get("findings", 0)}</div>
                        <div class="stat-label">Trivy Misconfigurations</div>
                        <div class="risk-badge risk-{scan_details.get("trivy_misconfigurations", {}).get("risk_level", "info").lower()}" style="margin-top: 10px;">
                            {esc(scan_details.get("trivy_misconfigurations", {}).get("risk_level", "INFO"))}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>💡 Recommendations</h2>
                <div class="recommendations">
    """

    # Add recommendations by priority
    for priority in ["critical", "high", "medium", "low", "info"]:
        recs = recommendations.get(priority, [])
        if recs:
            html_content += f"""
                    <div class="rec-category">
                        <h3>{priority.title()} Priority</h3>
            """
            for rec in recs:
                html_content += f"""
                        <div class="rec-item rec-{priority}">{esc(rec)}</div>
                """
            html_content += """
                    </div>
            """

    html_content += """
                </div>
            </div>
            
            <div class="section" id="detailed-findings">
                <h2>🔍 Detailed Findings</h2>
                <div class="findings-section">
    """
    gitleaks_data = detailed_results.get("gitleaks", {})
    if gitleaks_data and (isinstance(gitleaks_data, list) and len(gitleaks_data) > 0):
        html_content += """
                    <div class="findings-tool" id="gitleaks-findings">
                        <h3>🔐 Gitleaks - Secret Detection</h3>
        """
        for finding in gitleaks_data:
            if isinstance(finding, dict):
                description = finding.get("Description", "Secret detected")
                file_path = finding.get("File", "Unknown file")
                line_number = finding.get("StartLine", "Unknown line")
                rule_id = finding.get("RuleID", "Unknown rule")
                secret = finding.get("Secret", "")
                masked_secret = (
                    secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
                    if len(secret) > 8
                    else "*" * len(secret)
                )

                html_content += f"""
                        <div class="finding-item">
                            <div class="finding-header">
                                <div class="finding-title">{esc(description)}</div>
                                <div class="finding-severity severity-critical">CRITICAL</div>
                            </div>
                            <div class="finding-details">
                                <div class="finding-detail-row">
                                    <span class="finding-label">File:</span>
                                    <span class="finding-value">{esc(file_path)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Line:</span>
                                    <span class="finding-value">{esc(str(line_number))}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Rule:</span>
                                    <span class="finding-value">{esc(rule_id)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Secret:</span>
                                    <span class="finding-value code-snippet">{esc(masked_secret)}</span>
                                </div>
                            </div>
                            <div class="remediation-box">
                                <div class="remediation-title">🛠️ Remediation</div>
                                <div class="remediation-text">
                                    1. Immediately rotate the exposed credential<br>
                                    2. Remove the secret from git history using tools like git-filter-repo<br>
                                    3. Store secrets in environment variables or secure vaults<br>
                                    4. Add .gitignore rules to prevent future secret commits<br>
                                    5. Implement pre-commit hooks for secret scanning
                                </div>
                            </div>
                        </div>
                """
        html_content += """
                    </div>
        """
    trivy_fs_data = detailed_results.get("trivy-fs", {})
    if (
        trivy_fs_data
        and isinstance(trivy_fs_data, dict)
        and trivy_fs_data.get("Results")
    ):
        html_content += """
                    <div class="findings-tool" id="trivy-vulnerabilities">
                        <h3>🐛 Trivy - Vulnerability Scan</h3>
        """
        for result in trivy_fs_data.get("Results", []):
            if isinstance(result, dict) and result.get("Vulnerabilities"):
                target = result.get("Target", "Unknown target")
                for vuln in result.get("Vulnerabilities", []):
                    if isinstance(vuln, dict):
                        vuln_id = vuln.get("VulnerabilityID", "Unknown ID")
                        pkg_name = vuln.get("PkgName", "Unknown package")
                        installed_version = vuln.get(
                            "InstalledVersion", "Unknown version"
                        )
                        fixed_version = vuln.get("FixedVersion", "No fix available")
                        severity = vuln.get("Severity", "UNKNOWN")
                        title = vuln.get("Title", "Unknown vulnerability")
                        description = vuln.get(
                            "Description", "No description available"
                        )

                        html_content += f"""
                        <div class="finding-item">
                            <div class="finding-header">
                                <div class="finding-title">{esc(vuln_id)}: {esc(title)}</div>
                                <div class="finding-severity severity-{severity.lower()}">{esc(severity)}</div>
                            </div>
                            <div class="finding-details">
                                <div class="finding-detail-row">
                                    <span class="finding-label">Package:</span>
                                    <span class="finding-value">{esc(pkg_name)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Version:</span>
                                    <span class="finding-value">{esc(installed_version)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Fixed In:</span>
                                    <span class="finding-value">{esc(fixed_version)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Target:</span>
                                    <span class="finding-value">{esc(target)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Description:</span>
                                    <div class="finding-value">{esc(description[:200])}{"..." if len(description) > 200 else ""}</div>
                                </div>
                            </div>
                            <div class="remediation-box">
                                <div class="remediation-title">🛠️ Remediation</div>
                                <div class="remediation-text">
                                    {"Update package to version " + esc(fixed_version) + " or later" if fixed_version != "No fix available" else "No fix currently available - monitor for updates"}
                                </div>
                            </div>
                        </div>
                        """
        html_content += """
                    </div>
        """
    trivy_fs_data = detailed_results.get("trivy-fs", {})
    if (
        trivy_fs_data
        and isinstance(trivy_fs_data, dict)
        and trivy_fs_data.get("Results")
    ):
        html_content += """
                    <div class="findings-tool" id="trivy-misconfigurations">
                        <h3>⚙️ Trivy - Misconfigurations</h3>
        """
        for result in trivy_fs_data.get("Results", []):
            if isinstance(result, dict) and result.get("Misconfigurations"):
                target = result.get("Target", "Unknown target")
                for misconfig in result.get("Misconfigurations", []):
                    if isinstance(misconfig, dict):
                        check_id = misconfig.get("ID", "Unknown ID")
                        title = misconfig.get("Title", "Unknown misconfiguration")
                        description = misconfig.get(
                            "Description", "No description available"
                        )
                        severity = misconfig.get("Severity", "UNKNOWN")
                        message = misconfig.get("Message", "No message available")
                        resolution = misconfig.get(
                            "Resolution", "No resolution provided"
                        )
                        print(
                            f"🔧 PROCESSING {check_id}: Original resolution: '{resolution}'"
                        )
                        if "infrastructure-as-code" in resolution.lower():
                            print(f"🚨 FOUND GENERIC TEXT IN RESOLUTION: {resolution}")
                        else:
                            print(f"✅ RESOLUTION IS CLEAN: {resolution}")

                        html_content += f"""
                        <div class="finding-item">
                            <div class="finding-header">
                                <div class="finding-title">{esc(check_id)}: {esc(title)}</div>
                                <div class="finding-severity severity-{severity.lower()}">{esc(severity)}</div>
                            </div>
                            <div class="finding-details">
                                <div class="finding-detail-row">
                                    <span class="finding-label">Target:</span>
                                    <span class="finding-value">{esc(target)}</span>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Message:</span>
                                    <div class="finding-value">{esc(message)}</div>
                                </div>
                                <div class="finding-detail-row">
                                    <span class="finding-label">Description:</span>
                                    <div class="finding-value">{esc(description[:200])}{"..." if len(description) > 200 else ""}</div>
                                </div>
                            </div>
                            <div class="remediation-box">
                                <div class="remediation-title">🛠️ Remediation</div>
                                <div class="remediation-text">
                                    {esc(resolution) if resolution != "No resolution provided" else "Review configuration settings and apply security best practices"}
                                </div>
                            </div>
                        </div>
                        """
        html_content += """
                    </div>
        """
    if not any(
        [
            gitleaks_data
            and (isinstance(gitleaks_data, list) and len(gitleaks_data) > 0),
            trivy_fs_data
            and isinstance(trivy_fs_data, dict)
            and trivy_fs_data.get("Results"),
        ]
    ):
        html_content += """
                    <div style="text-align: center; padding: 40px; color: #6c757d;">
                        <h3>✅ No Security Issues Found</h3>
                        <p>All automated security scans completed without finding any issues.</p>
                    </div>
        """
    print("🕒 FOOTER PROCESSING:")
    print(f"   - meta keys: {list(meta.keys())}")
    print(f"   - scan_date: '{meta.get('scan_date', 'N/A')}'")
    print(f"   - scan_time: '{meta.get('scan_time', 'N/A')}'")
    footer_date = esc(meta.get("scan_date", "N/A"))
    footer_time = esc(meta.get("scan_time", "N/A"))
    print(f"   - footer_date: '{footer_date}'")
    print(f"   - footer_time: '{footer_time}'")
    footer_html = f"""
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by GitHub Security Scanner | {footer_date} {footer_time}</p>
        </div>
    </div>
</body>
</html>
    """
    html_content += footer_html

    return html_content


def convert_consolidated_report_to_html(consolidated_report: Dict) -> str:
    """Convert consolidated organization report to HTML"""

    def esc(text: Any) -> str:
        return html.escape(str(text))

    meta = consolidated_report.get("metadata", {})
    exec_summary = consolidated_report.get("executive_summary", {})
    recommendations = consolidated_report.get("recommendations", {})
    top_repos = consolidated_report.get("top_repositories", {})
    all_repos = consolidated_report.get("all_repositories", [])

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organization Security Report - {esc(meta.get("organization", "N/A"))}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.8em; font-weight: 300; }}
        .header .subtitle {{ margin-top: 10px; opacity: 0.9; font-size: 1.2em; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .meta-item {{ background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .meta-item strong {{ display: block; color: #495057; margin-bottom: 5px; }}
        .risk-badge {{ display: inline-block; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 1em; text-transform: uppercase; }}
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; color: #212529; }}
        .risk-low {{ background: #28a745; color: white; }}
        .risk-info {{ background: #17a2b8; color: white; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 25px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; color: #495057; }}
        .stat-number.critical {{ color: #dc3545; }}
        .stat-number.high {{ color: #fd7e14; }}
        .stat-number.medium {{ color: #ffc107; }}
        .stat-number.low {{ color: #28a745; }}
        .stat-number.zero {{ color: #6c757d; }}
        .stat-label {{ color: #6c757d; margin-top: 8px; font-weight: 500; }}
        .recommendations {{ margin-top: 20px; }}
        .rec-category {{ margin-bottom: 25px; }}
        .rec-category h3 {{ margin-bottom: 15px; color: #495057; }}
        .rec-item {{ background: #f8f9fa; padding: 18px; margin-bottom: 12px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .rec-critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .rec-high {{ border-left-color: #fd7e14; background: #fff8f0; }}
        .rec-medium {{ border-left-color: #ffc107; background: #fffbf0; }}
        .rec-low {{ border-left-color: #28a745; background: #f0fff4; }}
        .rec-info {{ border-left-color: #17a2b8; background: #f0fdff; }}
        .repo-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .repo-table th, .repo-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        .repo-table th {{ background: #f8f9fa; font-weight: 600; color: #495057; }}
        .repo-table tbody tr:hover {{ background: #f8f9fa; }}
        .repo-name {{ font-weight: bold; color: #495057; }}
        .repo-link {{ color: #667eea; text-decoration: none; margin-right: 10px; }}
        .repo-link:hover {{ text-decoration: underline; }}
        .top-repos {{ margin-bottom: 30px; }}
        .top-repos h3 {{ color: #495057; margin-bottom: 15px; border-left: 4px solid #667eea; padding-left: 15px; }}
        .repo-card {{ background: white; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; margin-bottom: 10px; }}
        .repo-card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .repo-card-title {{ font-weight: bold; color: #495057; }}
        .repo-card-links {{ margin-top: 10px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; border-top: 1px solid #dee2e6; }}
        .tabs {{ display: flex; border-bottom: 1px solid #dee2e6; margin-bottom: 20px; }}
        .tab {{ padding: 10px 20px; cursor: pointer; border-bottom: 3px solid transparent; }}
        .tab.active {{ border-bottom-color: #667eea; color: #667eea; font-weight: 600; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
    <script>
        function showTab(tabName) {{
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            document.querySelector(`[onclick="showTab('${{tabName}}')"]`).classList.add('active');
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Organization Security Report</h1>
            <div class="subtitle">{esc(meta.get("organization", "N/A"))}</div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="meta-grid">
                    <div class="meta-item">
                        <strong>Organization</strong>
                        {esc(meta.get("organization", "N/A"))}
                    </div>
                    <div class="meta-item">
                        <strong>Repositories Scanned</strong>
                        {exec_summary.get("total_repositories_scanned", 0)}
                    </div>
                    <div class="meta-item">
                        <strong>Scan Date</strong>
                        {esc(meta.get("scan_date", "N/A"))}
                    </div>
                    <div class="meta-item">
                        <strong>Scan Time</strong>
                        {esc(meta.get("scan_time", "N/A"))}
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number {("critical" if exec_summary.get("total_issues_across_org", 0) > 100 else "high" if exec_summary.get("total_issues_across_org", 0) > 50 else "medium" if exec_summary.get("total_issues_across_org", 0) > 0 else "zero")}">{exec_summary.get("total_issues_across_org", 0)}</div>
                        <div class="stat-label">Total Issues</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number {("critical" if exec_summary.get("total_secrets_found", 0) > 0 else "zero")}">{exec_summary.get("total_secrets_found", 0)}</div>
                        <div class="stat-label">Secrets Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number {("critical" if exec_summary.get("total_vulnerabilities_found", 0) > 50 else "high" if exec_summary.get("total_vulnerabilities_found", 0) > 20 else "medium" if exec_summary.get("total_vulnerabilities_found", 0) > 0 else "zero")}">{exec_summary.get("total_vulnerabilities_found", 0)}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number {("high" if exec_summary.get("total_misconfigurations_found", 0) > 20 else "medium" if exec_summary.get("total_misconfigurations_found", 0) > 0 else "zero")}">{exec_summary.get("total_misconfigurations_found", 0)}</div>
                        <div class="stat-label">Misconfigurations</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number critical">{exec_summary.get("critical_repos", 0)}</div>
                        <div class="stat-label">Critical Risk Repos</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number high">{exec_summary.get("high_risk_repos", 0)}</div>
                        <div class="stat-label">High Risk Repos</div>
                    </div>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <span class="risk-badge risk-{exec_summary.get("organization_risk_level", "info").lower()}">
                        Organization Risk: {esc(exec_summary.get("organization_risk_level", "INFO"))}
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>💡 Recommendations</h2>
                <div class="recommendations">
    """
    for priority in ["critical", "high", "medium", "low", "info"]:
        recs = recommendations.get(priority, [])
        if recs:
            html_content += f"""
                    <div class="rec-category">
                        <h3>{priority.title()} Priority</h3>
            """
            for rec in recs:
                html_content += f"""
                        <div class="rec-item rec-{priority}">{esc(rec)}</div>
                """
            html_content += """
                    </div>
            """

    html_content += """
                </div>
            </div>
            
            <div class="section">
                <h2>🏆 Top Repositories</h2>
                <div class="tabs">
                    <div class="tab active" onclick="showTab('tab-risk')">By Overall Risk</div>
                    <div class="tab" onclick="showTab('tab-secrets')">By Secrets</div>
                    <div class="tab" onclick="showTab('tab-vulns')">By Vulnerabilities</div>
                    <div class="tab" onclick="showTab('tab-configs')">By Misconfigurations</div>
                </div>
                
                <div id="tab-risk" class="tab-content active">
    """
    for repo in top_repos.get("by_overall_risk", [])[:10]:
        html_content += f"""
                    <div class="repo-card">
                        <div class="repo-card-header">
                            <div class="repo-card-title">{esc(repo["repository"])}</div>
                            <div class="risk-badge risk-{repo["risk_level"].lower()}">{esc(repo["risk_level"])}</div>
                        </div>
                        <div>Total Issues: {repo["total_issues"]} | Secrets: {repo["secrets_found"]} | Vulnerabilities: {repo["vulnerabilities_found"]} | Misconfigurations: {repo["misconfigurations_found"]}</div>
                        <div class="repo-card-links">
                            <a href="{repo["html_report_url"]}" target="_blank" class="repo-link">📄 HTML Report</a>
                            <a href="{repo["json_report_url"]}" target="_blank" class="repo-link">📋 JSON Data</a>
                        </div>
                    </div>
        """

    html_content += """
                </div>
                
                <div id="tab-secrets" class="tab-content">
    """

    # Top repositories by secrets
    secrets_repos = top_repos.get("by_secrets", [])
    if secrets_repos:
        for repo in secrets_repos[:10]:
            html_content += f"""
                    <div class="repo-card">
                        <div class="repo-card-header">
                            <div class="repo-card-title">{esc(repo["repository"])}</div>
                            <div class="risk-badge risk-critical">SECRETS: {repo["secrets_found"]}</div>
                        </div>
                        <div>Total Issues: {repo["total_issues"]} | Risk Level: {repo["risk_level"]}</div>
                        <div class="repo-card-links">
                            <a href="{repo["html_report_url"]}" target="_blank" class="repo-link">📄 HTML Report</a>
                            <a href="{repo["json_report_url"]}" target="_blank" class="repo-link">📋 JSON Data</a>
                        </div>
                    </div>
            """
    else:
        html_content += """
                    <div style="text-align: center; padding: 40px; color: #6c757d;">
                        <h3>✅ No Secrets Found</h3>
                        <p>No exposed secrets detected in any repository.</p>
                    </div>
        """

    html_content += """
                </div>
                
                <div id="tab-vulns" class="tab-content">
    """

    # Top repositories by vulnerabilities
    vuln_repos = top_repos.get("by_vulnerabilities", [])
    if vuln_repos:
        for repo in vuln_repos[:10]:
            html_content += f"""
                    <div class="repo-card">
                        <div class="repo-card-header">
                            <div class="repo-card-title">{esc(repo["repository"])}</div>
                            <div class="risk-badge risk-{repo["risk_level"].lower()}">VULNS: {repo["vulnerabilities_found"]}</div>
                        </div>
                        <div>Total Issues: {repo["total_issues"]} | Risk Level: {repo["risk_level"]}</div>
                        <div class="repo-card-links">
                            <a href="{repo["html_report_url"]}" target="_blank" class="repo-link">📄 HTML Report</a>
                            <a href="{repo["json_report_url"]}" target="_blank" class="repo-link">📋 JSON Data</a>
                        </div>
                    </div>
            """
    else:
        html_content += """
                    <div style="text-align: center; padding: 40px; color: #6c757d;">
                        <h3>✅ No Vulnerabilities Found</h3>
                        <p>No vulnerabilities detected in any repository.</p>
                    </div>
        """

    html_content += """
                </div>
                
                <div id="tab-configs" class="tab-content">
    """

    # Top repositories by misconfigurations
    config_repos = top_repos.get("by_misconfigurations", [])
    if config_repos:
        for repo in config_repos[:10]:
            html_content += f"""
                    <div class="repo-card">
                        <div class="repo-card-header">
                            <div class="repo-card-title">{esc(repo["repository"])}</div>
                            <div class="risk-badge risk-{repo["risk_level"].lower()}">CONFIGS: {repo["misconfigurations_found"]}</div>
                        </div>
                        <div>Total Issues: {repo["total_issues"]} | Risk Level: {repo["risk_level"]}</div>
                        <div class="repo-card-links">
                            <a href="{repo["html_report_url"]}" target="_blank" class="repo-link">📄 HTML Report</a>
                            <a href="{repo["json_report_url"]}" target="_blank" class="repo-link">📋 JSON Data</a>
                        </div>
                    </div>
            """
    else:
        html_content += """
                    <div style="text-align: center; padding: 40px; color: #6c757d;">
                        <h3>✅ No Misconfigurations Found</h3>
                        <p>No configuration issues detected in any repository.</p>
                    </div>
        """

    html_content += """
                </div>
            </div>
            
            <div class="section">
                <h2>📋 All Repositories</h2>
                <table class="repo-table">
                    <thead>
                        <tr>
                            <th>Repository</th>
                            <th>Risk Level</th>
                            <th>Total Issues</th>
                            <th>Secrets</th>
                            <th>Vulnerabilities</th>
                            <th>Misconfigurations</th>
                            <th>Reports</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    # All repositories table
    for repo in all_repos:
        html_content += f"""
                        <tr>
                            <td class="repo-name">{esc(repo["repository"])}</td>
                            <td><span class="risk-badge risk-{repo["risk_level"].lower()}">{esc(repo["risk_level"])}</span></td>
                            <td>{repo["total_issues"]}</td>
                            <td>{repo["secrets_found"]}</td>
                            <td>{repo["vulnerabilities_found"]}</td>
                            <td>{repo["misconfigurations_found"]}</td>
                            <td>
                                <a href="{repo["html_report_url"]}" target="_blank" class="repo-link">HTML</a>
                                <a href="{repo["json_report_url"]}" target="_blank" class="repo-link">JSON</a>
                            </td>
                        </tr>
        """

    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by GitHub Security Scanner | {esc(meta.get("scan_date", "N/A"))} {esc(meta.get("scan_time", "N/A"))}</p>
        </div>
    </div>
</body>
</html>
    """

    return html_content


def send_org_slack_notification(
    org: str, consolidated_report: Dict, report_path: str
) -> bool:
    """Send Slack notification with organization scan results"""
    slack_token = os.environ.get("SLACK_BOT_TOKEN")
    slack_channel = os.environ.get("SLACK_CHANNEL", "#security-alerts")

    if not slack_token:
        logger.info("SLACK_BOT_TOKEN not configured, skipping Slack notification")
        return False

    try:
        exec_summary = consolidated_report.get("executive_summary", {})
        meta = consolidated_report.get("metadata", {})
        top_repos = consolidated_report.get("top_repositories", {}).get(
            "by_overall_risk", []
        )

        total_issues = exec_summary.get("total_issues_across_org", 0)
        risk_level = exec_summary.get("organization_risk_level", "INFO")
        secrets_found = exec_summary.get("total_secrets_found", 0)
        vulnerabilities_found = exec_summary.get("total_vulnerabilities_found", 0)
        misconfigs_found = exec_summary.get("total_misconfigurations_found", 0)
        repos_scanned = exec_summary.get("total_repositories_scanned", 0)

        # Risk level emoji mapping
        risk_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "ℹ️",
        }

        # Build message
        message_blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🏢 Organization Security Scan Complete: {org}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Organization:* {org}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Repositories Scanned:* {repos_scanned}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Level:* {risk_emoji.get(risk_level, 'ℹ️')} {risk_level}",
                    },
                    {"type": "mrkdwn", "text": f"*Total Issues:* {total_issues}"},
                ],
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Secrets Found:* {secrets_found}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Vulnerabilities:* {vulnerabilities_found}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Misconfigurations:* {misconfigs_found}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Scan Date:* {meta.get('scan_date', 'N/A')}",
                    },
                ],
            },
        ]

        # Add top repositories if any have issues
        if top_repos and any(repo["total_issues"] > 0 for repo in top_repos[:5]):
            top_repos_text = "\\n".join(
                [
                    f"• *{repo['repository']}*: {repo['total_issues']} issues ({repo['risk_level']})"
                    for repo in top_repos[:5]
                    if repo["total_issues"] > 0
                ]
            )

            message_blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*🏆 Top Repositories with Issues:*\\n{top_repos_text}",
                    },
                }
            )

        # Add recommendations for critical/high issues
        recommendations = consolidated_report.get("recommendations", {})
        critical_recs = recommendations.get("critical", [])
        high_recs = recommendations.get("high", [])

        if critical_recs or high_recs:
            rec_text = ""
            if critical_recs:
                rec_text += "\\n".join([f"• {rec}" for rec in critical_recs[:3]])
            if high_recs and len(rec_text) < 1000:  # Slack message limit
                if rec_text:
                    rec_text += "\\n"
                rec_text += "\\n".join([f"• {rec}" for rec in high_recs[:2]])

            if rec_text:
                message_blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*🎯 Key Recommendations:*\\n{rec_text[:1500]}",
                        },
                    }
                )

        # Report will be available as pipeline artifact

        # Send to Slack
        payload = {
            "channel": slack_channel,
            "blocks": message_blocks,
            "username": "Security Scanner Bot",
            "icon_emoji": ":shield:",
        }

        headers = {
            "Authorization": f"Bearer {slack_token}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            json=payload,
            headers=headers,
            timeout=30,
        )

        if response.status_code == 200 and response.json().get("ok"):
            logger.info(
                f"Slack notification sent successfully for organization '{org}'"
            )
            return True
        else:
            logger.error(f"Failed to send Slack notification: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")
        return False


# Slack notification functionality removed


def scan_single_repository(
    owner: str, repo_slug: str, repo_path_base: str, reports_dir_base: str
) -> Dict:
    """
    Scans a single repository and generates comprehensive reports.

    Args:
        owner: GitHub owner (user or organization)
        repo_slug: Repository name/slug
        repo_path_base: Base path for repository (used if no remote clone)
        reports_dir_base: Base directory for storing reports

    Returns:
        Dict containing scan results and metadata
    """
    print(f"🎯 FUNCTION ENTRY: scan_single_repository({owner}, {repo_slug})")
    logger.info(f"Starting scan for repository: {owner}/{repo_slug}")

    current_time_obj = get_current_utc_time()

    final_reports_repo_dir = os.path.join(reports_dir_base, owner, repo_slug)
    repo_scan_temp_output_dir = os.path.join(final_reports_repo_dir, "temp_scan_output")

    safe_remove_if_exists(repo_scan_temp_output_dir)
    os.makedirs(repo_scan_temp_output_dir, exist_ok=True)

    json_dir = os.path.join(final_reports_repo_dir, "json")
    html_dir = os.path.join(final_reports_repo_dir, "html")
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    scan_target_path = ""
    temp_clone_dir_obj = None
    token = get_github_auth()
    if token and ((GITHUB_OWNER and GITHUB_REPO) or (owner and repo_slug)):
        temp_clone_dir_obj = tempfile.TemporaryDirectory(prefix=f"scan_{repo_slug}_")
        scan_target_path = temp_clone_dir_obj.name
        logger.info(
            f"Cloning repository {owner}/{repo_slug} into temporary directory {scan_target_path}..."
        )
        try:
            clone_url = f"https://{token}@github.com/{owner}/{repo_slug}.git"
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, scan_target_path],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            logger.info(
                f"Repository {owner}/{repo_slug} cloned successfully to {scan_target_path}"
            )
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to clone repository {owner}/{repo_slug}: {e}")
            stderr_output = getattr(e, "stderr", None)
            if stderr_output:
                logger.error(f"Clone stderr: {stderr_output}")
            if temp_clone_dir_obj:
                temp_clone_dir_obj.cleanup()
            if REPO_PATH_FROM_ARGS and os.path.isdir(REPO_PATH_FROM_ARGS):
                logger.warning(
                    f"Clone failed. Falling back to local path provided: {REPO_PATH_FROM_ARGS} for {owner}/{repo_slug}"
                )
                scan_target_path = REPO_PATH_FROM_ARGS
            else:
                safe_remove_if_exists(repo_scan_temp_output_dir)
                return {
                    "error": f"Failed to clone repository {owner}/{repo_slug} and no valid local fallback: {str(e)}",
                    "results": {},
                }
    else:
        logger.info(
            f"No GitHub credentials for remote clone, or local scan mode. Assuming local scan for {owner}/{repo_slug} at path: {repo_path_base}"
        )
        if not os.path.isdir(repo_path_base):
            logger.error(
                f"Local repository path {repo_path_base} does not exist or is not a directory."
            )
            safe_remove_if_exists(repo_scan_temp_output_dir)
            return {
                "error": f"Local repository path {repo_path_base} not found.",
                "results": {},
            }
        scan_target_path = repo_path_base

    # Run security scans
    scan_results_summary: Dict[str, Dict[str, Any]] = {}
    detailed_reports_data: Dict[str, Any] = {}

    for tool_name in ["gitleaks", "trivy-fs", "trivy-config"]:
        logger.info(
            f"--- Starting {tool_name} scan for {owner}/{repo_slug} on path {scan_target_path} ---"
        )
        run_scan_command(tool_name, scan_target_path, repo_scan_temp_output_dir)

        # Determine report file name based on tool
        if tool_name == "trivy-fs":
            report_file_name = "trivy-fs-report.json"
        elif tool_name == "trivy-config":
            report_file_name = "trivy-config-report.json"
        else:
            report_file_name = f"{tool_name}-report.json"

        individual_report_path = os.path.join(
            repo_scan_temp_output_dir, report_file_name
        )
        current_tool_findings_data: Any = None
        count = 0
        misconfig_count_trivy = 0

        if (
            os.path.exists(individual_report_path)
            and os.path.isfile(individual_report_path)
            and os.path.getsize(individual_report_path) > 0
        ):
            try:
                with open(individual_report_path, "r", encoding="utf-8") as f:
                    current_tool_findings_data = json.load(f)
                detailed_reports_data[tool_name] = current_tool_findings_data

                if tool_name == "gitleaks":
                    count = (
                        len(current_tool_findings_data)
                        if isinstance(current_tool_findings_data, list)
                        else 0
                    )
                    scan_results_summary[tool_name] = {
                        "findings_count": count,
                        "report_file": report_file_name,
                    }
                elif tool_name == "trivy-fs":
                    vuln_count_trivy = 0
                    if (
                        isinstance(current_tool_findings_data, dict)
                        and "Results" in current_tool_findings_data
                    ):
                        for result in current_tool_findings_data.get("Results", []):
                            if isinstance(result, dict):
                                vulnerabilities = result.get("Vulnerabilities", [])
                                if vulnerabilities and isinstance(
                                    vulnerabilities, list
                                ):
                                    vuln_count_trivy += len(vulnerabilities)
                    count = vuln_count_trivy
                    scan_results_summary[tool_name] = {
                        "vulnerabilities_count": vuln_count_trivy,
                        "report_file": report_file_name,
                    }
                elif tool_name == "trivy-config":
                    misconfig_count_trivy = 0
                    if (
                        isinstance(current_tool_findings_data, dict)
                        and "Results" in current_tool_findings_data
                    ):
                        for result in current_tool_findings_data.get("Results", []):
                            if isinstance(result, dict):
                                misconfigurations = result.get("Misconfigurations", [])
                                if misconfigurations and isinstance(
                                    misconfigurations, list
                                ):
                                    misconfig_count_trivy += len(misconfigurations)
                    count = misconfig_count_trivy
                    scan_results_summary[tool_name] = {
                        "misconfigurations_count": misconfig_count_trivy,
                        "report_file": report_file_name,
                    }

                logger.info(
                    f"{tool_name} scan for {owner}/{repo_slug} processed successfully: {count} main issues found"
                    + (
                        f", {misconfig_count_trivy} misconfigs"
                        if tool_name == "trivy-config" and misconfig_count_trivy > 0
                        else ""
                    )
                )
            except json.JSONDecodeError as e:
                logger.error(
                    f"Error decoding JSON from {tool_name} report {individual_report_path} for {owner}/{repo_slug}: {e}"
                )
                detailed_reports_data[tool_name] = (
                    [] if tool_name == "gitleaks" else {"Results": []}
                )
                scan_results_summary[tool_name] = {
                    "error": "JSON decode error",
                    "findings_count": 0,
                    "vulnerabilities_count": 0,
                    "misconfigurations_count": 0,
                }
            except Exception as e:
                logger.error(
                    f"Error processing {tool_name} report {individual_report_path} for {owner}/{repo_slug}: {e}"
                )
                detailed_reports_data[tool_name] = (
                    [] if tool_name == "gitleaks" else {"Results": []}
                )
                scan_results_summary[tool_name] = {
                    "error": str(e),
                    "findings_count": 0,
                    "vulnerabilities_count": 0,
                    "misconfigurations_count": 0,
                }
        else:
            logger.warning(
                f"{tool_name} report {individual_report_path} still not found or empty after scan command for {owner}/{repo_slug}."
            )
            if tool_name == "gitleaks":
                detailed_reports_data[tool_name] = []
            elif tool_name in ["trivy-fs", "trivy-config"]:
                detailed_reports_data[tool_name] = {"Results": []}
            scan_results_summary[tool_name] = {
                "error": "Report not found or empty post-scan",
                "findings_count": 0,
                "vulnerabilities_count": 0,
                "misconfigurations_count": 0,
            }

    # Cleanup temporary directories
    if temp_clone_dir_obj:
        logger.debug(f"Cleaning up temporary clone directory: {scan_target_path}")
        temp_clone_dir_obj.cleanup()
    logger.debug(
        f"Cleaning up temporary scan output directory: {repo_scan_temp_output_dir}"
    )
    safe_remove_if_exists(repo_scan_temp_output_dir)

    # Generate summary with GitHub Actions metadata
    current_time_obj = get_current_utc_time()

    # Calculate severity breakdown for GitHub Actions
    gitleaks_findings = scan_results_summary.get("gitleaks", {}).get(
        "findings_count", 0
    )
    trivy_vulnerabilities = scan_results_summary.get("trivy-fs", {}).get(
        "vulnerabilities_count", 0
    )
    trivy_misconfigurations = scan_results_summary.get("trivy-fs", {}).get(
        "misconfigurations_count", 0
    )
    total_issues = gitleaks_findings + trivy_vulnerabilities + trivy_misconfigurations

    # Determine risk level
    overall_risk = (
        "CRITICAL"
        if gitleaks_findings > 0 or total_issues > 25
        else "HIGH"
        if total_issues > 15
        else "MEDIUM"
        if total_issues > 8
        else "LOW"
        if total_issues > 0
        else "INFO"
    )

    # GitHub Actions expects severity breakdown
    critical_issues = gitleaks_findings  # Secrets are critical
    high_issues = min(trivy_vulnerabilities, 10) + (
        trivy_misconfigurations if trivy_misconfigurations > 5 else 0
    )
    medium_issues = max(0, trivy_vulnerabilities - 10) + (
        trivy_misconfigurations
        if trivy_misconfigurations <= 5 and trivy_misconfigurations > 0
        else 0
    )
    low_issues = 0  # We don't track low severity separately

    repo_level_summary_for_aggregation = {
        "scan_date": current_time_obj.strftime("%Y-%m-%d"),
        "scan_time": current_time_obj.strftime("%H:%M:%S UTC"),
        "github": {"owner": owner, "repository": repo_slug},
        "results": scan_results_summary,
        "metadata": {
            "risk_level": overall_risk,
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "high_issues": high_issues,
            "medium_issues": medium_issues,
            "low_issues": low_issues,
            "gitleaks_secrets": gitleaks_findings,
            "trivy_vulnerabilities": trivy_vulnerabilities,
            "trivy_misconfigurations": trivy_misconfigurations,
        },
    }

    summary_file_path = os.path.join(final_reports_repo_dir, "summary.json")
    safe_remove_if_exists(summary_file_path)
    with open(summary_file_path, "w", encoding="utf-8") as f:
        json.dump(repo_level_summary_for_aggregation, f, indent=2)

    # Generate combined report (branch detection handled in generate_combined_report)
    final_combined_report_data = generate_combined_report(
        owner, repo_slug, scan_results_summary, detailed_reports_data
    )

    # Save combined report as JSON
    combined_report_json_path = os.path.join(json_dir, "final-security-report.json")
    safe_remove_if_exists(combined_report_json_path)
    with open(combined_report_json_path, "w", encoding="utf-8") as f:
        json.dump(final_combined_report_data, f, indent=2)

    # Generate and save HTML report
    print("🔥 ABOUT TO CALL convert_json_to_html function")
    html_content = convert_json_to_html(final_combined_report_data)
    print(f"🔥 HTML CONTENT LENGTH: {len(html_content)} characters")
    print(
        f"🔥 HTML CONTENT CONTAINS 'infrastructure-as-code': {'infrastructure-as-code' in html_content}"
    )
    print(f"🔥 HTML CONTENT FOOTER EXCERPT: {html_content[-200:]}")
    combined_report_html_path = os.path.join(html_dir, "final-security-report.html")
    safe_remove_if_exists(combined_report_html_path)
    with open(combined_report_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"🔥 HTML REPORT WRITTEN TO: {combined_report_html_path}")

    # Reports are saved locally and will be uploaded as CI/CD pipeline artifacts

    logger.info(
        f"Scan completed for {owner}/{repo_slug}. Reports saved to {final_reports_repo_dir}"
    )
    return {
        "success": True,
        "results": scan_results_summary,
        "combined_report": final_combined_report_data,
    }


def generate_consolidated_org_report(
    org: str,
    aggregated_repo_summaries: List[Dict],
    overall_totals: Dict,
    reports_dir_base: str,
) -> Dict:
    """Generate consolidated organization-wide report with top repositories and links"""
    current_time_obj = get_current_utc_time()
    current_date = current_time_obj.strftime("%Y-%m-%d")
    current_time = current_time_obj.strftime("%H:%M:%S UTC")

    # Calculate top repositories by various metrics
    repo_rankings = []
    for repo_data in aggregated_repo_summaries:
        if "combined_report" in repo_data:
            exec_summary = repo_data["combined_report"].get("executive_summary", {})
            repo_name = (
                repo_data["combined_report"]
                .get("metadata", {})
                .get("repository", "unknown")
            )

            total_issues = exec_summary.get("total_issues", 0)
            risk_level = exec_summary.get("risk_level", "INFO")
            secrets_found = exec_summary.get("gitleaks_secrets_found", 0)
            vulnerabilities_found = exec_summary.get("trivy_vulnerabilities_found", 0)
            misconfigs_found = exec_summary.get("trivy_misconfigurations_found", 0)

            # Generate local report URLs (will be available as pipeline artifacts)
            html_url = f"scan_reports/{org}/{repo_name}/html/final-security-report.html"
            json_url = f"scan_reports/{org}/{repo_name}/json/final-security-report.json"

            repo_rankings.append(
                {
                    "repository": repo_name,
                    "total_issues": total_issues,
                    "risk_level": risk_level,
                    "secrets_found": secrets_found,
                    "vulnerabilities_found": vulnerabilities_found,
                    "misconfigurations_found": misconfigs_found,
                    "html_report_url": html_url,
                    "json_report_url": json_url,
                    "risk_score": get_risk_score(
                        risk_level, total_issues, secrets_found
                    ),
                }
            )

    # Sort repositories by different criteria
    top_by_risk = sorted(
        repo_rankings, key=lambda x: (-x["risk_score"], -x["total_issues"])
    )[:10]
    top_by_secrets = sorted(repo_rankings, key=lambda x: -x["secrets_found"])[:10]
    top_by_vulnerabilities = sorted(
        repo_rankings, key=lambda x: -x["vulnerabilities_found"]
    )[:10]
    top_by_misconfigs = sorted(
        repo_rankings, key=lambda x: -x["misconfigurations_found"]
    )[:10]

    # Calculate overall risk level
    total_org_issues = (
        overall_totals["gitleaks_findings"]
        + overall_totals["trivy_vulnerabilities"]
        + overall_totals["trivy_misconfigurations"]
    )
    org_risk_level = (
        "CRITICAL"
        if overall_totals["gitleaks_findings"] > 0 or total_org_issues > 100
        else "HIGH"
        if total_org_issues > 50
        else "MEDIUM"
        if total_org_issues > 0
        else "LOW"
    )

    # Build consolidated report
    consolidated_report = {
        "metadata": {
            "scan_date": current_date,
            "scan_time": current_time,
            "organization": org,
            "total_repositories": len(repo_rankings),
            "scan_tools": ["gitleaks", "trivy-fs"],
        },
        "executive_summary": {
            "organization_risk_level": org_risk_level,
            "total_repositories_scanned": len(repo_rankings),
            "total_issues_across_org": total_org_issues,
            "total_secrets_found": overall_totals["gitleaks_findings"],
            "total_vulnerabilities_found": overall_totals["trivy_vulnerabilities"],
            "total_misconfigurations_found": overall_totals["trivy_misconfigurations"],
            "critical_repos": len(
                [r for r in repo_rankings if r["risk_level"] == "CRITICAL"]
            ),
            "high_risk_repos": len(
                [r for r in repo_rankings if r["risk_level"] == "HIGH"]
            ),
            "medium_risk_repos": len(
                [r for r in repo_rankings if r["risk_level"] == "MEDIUM"]
            ),
            "low_risk_repos": len(
                [r for r in repo_rankings if r["risk_level"] == "LOW"]
            ),
        },
        "top_repositories": {
            "by_overall_risk": top_by_risk,
            "by_secrets": [r for r in top_by_secrets if r["secrets_found"] > 0],
            "by_vulnerabilities": [
                r for r in top_by_vulnerabilities if r["vulnerabilities_found"] > 0
            ],
            "by_misconfigurations": [
                r for r in top_by_misconfigs if r["misconfigurations_found"] > 0
            ],
        },
        "recommendations": generate_org_recommendations(overall_totals, repo_rankings),
        "all_repositories": sorted(repo_rankings, key=lambda x: x["repository"]),
    }

    return consolidated_report


def get_risk_score(risk_level: str, total_issues: int, secrets_found: int) -> int:
    """Calculate numerical risk score for ranking"""
    base_score = {"CRITICAL": 1000, "HIGH": 100, "MEDIUM": 10, "LOW": 1, "INFO": 0}.get(
        risk_level, 0
    )
    return base_score + total_issues + (secrets_found * 50)  # Secrets weighted heavily


def generate_org_recommendations(
    overall_totals: Dict, repo_rankings: List[Dict]
) -> Dict:
    """Generate organization-wide recommendations"""
    recommendations = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    # Critical recommendations
    if overall_totals["gitleaks_findings"] > 0:
        critical_repos = [r for r in repo_rankings if r["secrets_found"] > 0]
        recommendations["critical"].append(
            f"🔴 CRITICAL: {len(critical_repos)} repositories have exposed secrets. "
            f"Immediate action required across organization."
        )

    if overall_totals["trivy_vulnerabilities"] > 200:
        recommendations["critical"].append(
            f"🔴 CRITICAL: {overall_totals['trivy_vulnerabilities']} vulnerabilities found across organization. "
            f"Implement organization-wide vulnerability management program."
        )

    # High priority recommendations
    vuln_repos = [r for r in repo_rankings if r["vulnerabilities_found"] > 0]
    if len(vuln_repos) > len(repo_rankings) * 0.5:
        recommendations["high"].append(
            f"🔴 HIGH: {len(vuln_repos)} repositories ({len(vuln_repos) / len(repo_rankings) * 100:.0f}%) have vulnerabilities. "
            f"Organization-wide dependency management needed."
        )

    config_repos = [r for r in repo_rankings if r["misconfigurations_found"] > 0]
    if len(config_repos) > 0:
        recommendations["high"].append(
            f"🔴 HIGH: {len(config_repos)} repositories have misconfigurations. "
            f"Standardize security configurations across organization."
        )

    # Medium priority recommendations
    if len([r for r in repo_rankings if r["risk_level"] in ["CRITICAL", "HIGH"]]) > 5:
        recommendations["medium"].append(
            "🟡 MEDIUM: Multiple high-risk repositories detected. Prioritize security reviews for top repositories."
        )

    # Info recommendations
    if not any(recommendations.values()):
        recommendations["info"].append(
            "✅ Organization security posture is good. Continue monitoring and maintain security best practices."
        )
    else:
        recommendations["info"].append(
            f"📊 Organization scan complete: {len(repo_rankings)} repositories analyzed. "
            f"Focus on top {min(10, len([r for r in repo_rankings if r['total_issues'] > 0]))} repositories with issues."
        )

    return recommendations


def scan_organization_repositories(
    org: str, repo_path_base_for_local: str, reports_dir_base: str
) -> Dict:
    """Scan all repositories in a GitHub organization"""
    if not org:
        logger.error("Organization must be specified for organization scanning.")
        return {"error": "Organization must be specified"}

    logger.info(f"Scanning repositories in organization '{org}'")
    repos = get_organization_repositories(org)

    if not repos:
        logger.warning(f"No repositories found in organization '{org}'.")
        return {"error": f"No repositories found for organization {org}"}

    org_summary_dir = os.path.join(reports_dir_base, org)
    os.makedirs(org_summary_dir, exist_ok=True)

    repos_to_scan = repos[:MAX_REPOS] if len(repos) > MAX_REPOS else repos
    logger.info(
        f"Found {len(repos)} repositories in organization, will scan up to {len(repos_to_scan)} (MAX_REPOS={MAX_REPOS})"
    )

    aggregated_repo_summaries = []
    overall_totals = {
        "gitleaks_findings": 0,
        "trivy_vulnerabilities": 0,
        "trivy_misconfigurations": 0,
    }

    for i, repo in enumerate(repos_to_scan):
        repo_slug = repo.get("name", "unknown")
        logger.info(
            f"--- Starting scan for org repo {i + 1}/{len(repos_to_scan)}: {org}/{repo_slug} ---"
        )
        repo_summary_data = scan_single_repository(
            org, repo_slug, repo_path_base_for_local, reports_dir_base
        )

        if "success" in repo_summary_data and repo_summary_data["success"]:
            aggregated_repo_summaries.append(repo_summary_data)

            # Aggregate totals
            results = repo_summary_data.get("results", {})
            overall_totals["gitleaks_findings"] += results.get("gitleaks", {}).get(
                "findings_count", 0
            )
            overall_totals["trivy_vulnerabilities"] += results.get("trivy-fs", {}).get(
                "vulnerabilities_count", 0
            )
            overall_totals["trivy_misconfigurations"] += results.get(
                "trivy-config", {}
            ).get("misconfigurations_count", 0)

    # Generate organization summary
    current_time_obj = get_current_utc_time()
    current_date_str = current_time_obj.strftime("%Y-%m-%d")

    org_overall_summary_data = {
        "scan_date": current_date_str,
        "scan_time": current_time_obj.strftime("%H:%M:%S UTC"),
        "github_scope": {"organization": org},
        "total_repositories_in_org": len(repos),
        "repositories_scanned": len(aggregated_repo_summaries),
        "overall_totals": overall_totals,
        "repository_summaries": aggregated_repo_summaries,
    }

    org_summary_file_path = os.path.join(
        org_summary_dir, "organization-scan-summary.json"
    )
    safe_remove_if_exists(org_summary_file_path)
    with open(org_summary_file_path, "w", encoding="utf-8") as f:
        json.dump(org_overall_summary_data, f, indent=2)

    # Generate consolidated report
    logger.info(f"Generating consolidated organization report for '{org}'...")
    consolidated_report = generate_consolidated_org_report(
        org, aggregated_repo_summaries, overall_totals, reports_dir_base
    )

    # Save consolidated report as JSON
    consolidated_json_path = os.path.join(
        org_summary_dir, "consolidated-security-report.json"
    )
    safe_remove_if_exists(consolidated_json_path)
    with open(consolidated_json_path, "w", encoding="utf-8") as f:
        json.dump(consolidated_report, f, indent=2)

    # Generate HTML consolidated report
    html_content = convert_consolidated_report_to_html(consolidated_report)
    consolidated_html_path = os.path.join(
        org_summary_dir, "consolidated-security-report.html"
    )
    safe_remove_if_exists(consolidated_html_path)
    with open(consolidated_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Consolidated reports are saved locally and will be uploaded as CI/CD pipeline artifacts

    logger.info(
        f"Organization scan for '{org}' completed. Aggregated summary at {org_summary_file_path}"
    )
    logger.info(f"Consolidated report generated: {consolidated_html_path}")

    total_org_issues = (
        overall_totals["gitleaks_findings"]
        + overall_totals["trivy_vulnerabilities"]
        + overall_totals["trivy_misconfigurations"]
    )

    # Send Slack notification
    send_org_slack_notification(org, consolidated_report, consolidated_html_path)

    return {
        "success": True,
        "organization": org,
        "repositories_scanned": len(aggregated_repo_summaries),
        "total_issues": total_org_issues,
        "consolidated_report_path": consolidated_html_path,
    }


def scan_user_repositories(
    owner: str, repo_path_base_for_local: str, reports_dir_base: str
) -> Dict:
    """Scan all repositories for a GitHub user"""
    if not owner:
        logger.error("Owner must be specified for user repository scanning.")
        return {"error": "Owner must be specified"}

    logger.info(f"Scanning repositories for user '{owner}'")
    repos = get_user_repositories(owner)

    if not repos:
        logger.warning(f"No repositories found for user '{owner}'.")
        return {"error": f"No repositories found for user {owner}"}

    user_summary_dir = os.path.join(reports_dir_base, owner)
    os.makedirs(user_summary_dir, exist_ok=True)

    repos_to_scan = repos[:MAX_REPOS] if len(repos) > MAX_REPOS else repos
    logger.info(
        f"Found {len(repos)} repositories for user, will scan up to {len(repos_to_scan)} (MAX_REPOS={MAX_REPOS})"
    )

    aggregated_repo_summaries = []
    overall_totals = {
        "gitleaks_findings": 0,
        "trivy_vulnerabilities": 0,
        "trivy_misconfigurations": 0,
    }

    for i, repo in enumerate(repos_to_scan):
        repo_slug = repo.get("name", "unknown")
        logger.info(
            f"--- Starting scan for user repo {i + 1}/{len(repos_to_scan)}: {owner}/{repo_slug} ---"
        )
        repo_summary_data = scan_single_repository(
            owner, repo_slug, repo_path_base_for_local, reports_dir_base
        )

        if "success" in repo_summary_data and repo_summary_data["success"]:
            aggregated_repo_summaries.append(repo_summary_data)

            # Aggregate totals
            results = repo_summary_data.get("results", {})
            overall_totals["gitleaks_findings"] += results.get("gitleaks", {}).get(
                "findings_count", 0
            )
            overall_totals["trivy_vulnerabilities"] += results.get("trivy-fs", {}).get(
                "vulnerabilities_count", 0
            )
            overall_totals["trivy_misconfigurations"] += results.get(
                "trivy-config", {}
            ).get("misconfigurations_count", 0)

    # Generate user summary
    current_time_obj = get_current_utc_time()
    current_date_str = current_time_obj.strftime("%Y-%m-%d")

    user_overall_summary_data = {
        "scan_date": current_date_str,
        "scan_time": current_time_obj.strftime("%H:%M:%S UTC"),
        "github_scope": {"owner": owner},
        "total_repositories_for_user": len(repos),
        "repositories_scanned": len(aggregated_repo_summaries),
        "overall_totals": overall_totals,
        "repository_summaries": aggregated_repo_summaries,
    }

    user_summary_file_path = os.path.join(user_summary_dir, "user-scan-summary.json")
    safe_remove_if_exists(user_summary_file_path)
    with open(user_summary_file_path, "w", encoding="utf-8") as f:
        json.dump(user_overall_summary_data, f, indent=2)

    logger.info(
        f"User scan for '{owner}' completed. Aggregated summary at {user_summary_file_path}"
    )

    total_user_issues = (
        overall_totals["gitleaks_findings"]
        + overall_totals["trivy_vulnerabilities"]
        + overall_totals["trivy_misconfigurations"]
    )

    return {
        "success": True,
        "owner": owner,
        "repositories_scanned": len(aggregated_repo_summaries),
        "total_issues": total_user_issues,
    }


def process_scan_reports(
    gitleaks_report_path: str = None,
    trivy_report_path: str = None,
    osv_report_path: str = None,
) -> Dict:
    """Process individual scan report files and return a consolidated summary"""
    scan_results_summary = {}
    detailed_reports_data = {}

    # Process Gitleaks report
    if gitleaks_report_path and os.path.exists(gitleaks_report_path):
        try:
            with open(gitleaks_report_path, "r", encoding="utf-8") as f:
                gitleaks_data = json.load(f)
            detailed_reports_data["gitleaks"] = gitleaks_data
            count = len(gitleaks_data) if isinstance(gitleaks_data, list) else 0
            scan_results_summary["gitleaks"] = {
                "findings_count": count,
                "report_file": "gitleaks-report.json",
            }
            logger.info(f"Processed Gitleaks report: {count} findings found")
        except Exception as e:
            logger.error(f"Error processing Gitleaks report: {e}")
            detailed_reports_data["gitleaks"] = []
            scan_results_summary["gitleaks"] = {"findings_count": 0, "error": str(e)}

    # Process Trivy report
    if trivy_report_path and os.path.exists(trivy_report_path):
        try:
            with open(trivy_report_path, "r", encoding="utf-8") as f:
                trivy_data = json.load(f)
            detailed_reports_data["trivy-fs"] = trivy_data

            vuln_count = 0
            misconfig_count = 0
            if isinstance(trivy_data, dict) and "Results" in trivy_data:
                for result in trivy_data.get("Results", []):
                    if isinstance(result, dict):
                        vulnerabilities = result.get("Vulnerabilities", [])
                        if vulnerabilities and isinstance(vulnerabilities, list):
                            vuln_count += len(vulnerabilities)

                        misconfigurations = result.get("Misconfigurations", [])
                        if misconfigurations and isinstance(misconfigurations, list):
                            misconfig_count += len(misconfigurations)

            scan_results_summary["trivy-fs"] = {
                "vulnerabilities_count": vuln_count,
                "misconfigurations_count": misconfig_count,
                "report_file": "trivy-fs-report.json",
            }
            logger.info(
                f"Processed Trivy report: {vuln_count} vulnerabilities and {misconfig_count} misconfigurations found"
            )
        except Exception as e:
            logger.error(f"Error processing Trivy report: {e}")
            detailed_reports_data["trivy-fs"] = {"Results": []}
            scan_results_summary["trivy-fs"] = {
                "vulnerabilities_count": 0,
                "misconfigurations_count": 0,
                "error": str(e),
            }
    return {
        "scan_results_summary": scan_results_summary,
        "detailed_reports_data": detailed_reports_data,
    }


def save_final_reports(
    combined_report: Dict, reports_output_dir_base: str, owner: str, repo_name: str
):
    """Save the final combined report in JSON and HTML formats"""
    # Create necessary directories
    json_dir = os.path.join(reports_output_dir_base, "json")
    html_dir = os.path.join(reports_output_dir_base, "html")
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)

    # Save combined report as JSON
    combined_report_json_path = os.path.join(json_dir, "final-security-report.json")
    safe_remove_if_exists(combined_report_json_path)
    with open(combined_report_json_path, "w", encoding="utf-8") as f:
        json.dump(combined_report, f, indent=2)
    logger.info(f"JSON report saved: {combined_report_json_path}")

    # Save combined report as HTML
    combined_report_html_path = os.path.join(html_dir, "final-security-report.html")
    safe_remove_if_exists(combined_report_html_path)
    html_content = convert_json_to_html(combined_report)
    with open(combined_report_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"HTML report saved: {combined_report_html_path}")


def detect_repository_info(repo_path: str) -> tuple:
    """Detect repository owner, name, and branch from various sources"""
    import subprocess

    # Try to get from environment variables first (GitHub Actions, etc.)
    github_repository = os.environ.get("GITHUB_REPOSITORY")  # format: owner/repo
    github_ref = os.environ.get("GITHUB_REF")  # format: refs/heads/branch-name
    github_head_ref = os.environ.get("GITHUB_HEAD_REF")  # PR branch name

    owner = None
    repo_name = None
    branch = None

    # Parse GitHub environment variables
    if github_repository and "/" in github_repository:
        parts = github_repository.split("/")
        owner = parts[0]
        repo_name = parts[1]
        logger.info(f"Detected repository from GITHUB_REPOSITORY: {owner}/{repo_name}")

    # Parse branch from GitHub environment
    if github_head_ref:
        branch = github_head_ref
        logger.info(f"Detected branch from GITHUB_HEAD_REF: {branch}")
    elif github_ref and github_ref.startswith("refs/heads/"):
        branch = github_ref.replace("refs/heads/", "")
        logger.info(f"Detected branch from GITHUB_REF: {branch}")

    # Fallback to git commands if environment variables are not available
    if not owner or not repo_name or not branch:
        try:
            # Change to repository directory if it exists
            original_cwd = os.getcwd()
            if os.path.isdir(repo_path) and os.path.exists(
                os.path.join(repo_path, ".git")
            ):
                os.chdir(repo_path)
                logger.info(f"Changed to repository directory: {repo_path}")

                # Get remote origin URL
                if not owner or not repo_name:
                    try:
                        remote_url = (
                            subprocess.check_output(
                                ["git", "remote", "get-url", "origin"],
                                stderr=subprocess.DEVNULL,
                                timeout=10,
                            )
                            .decode("utf-8")
                            .strip()
                        )

                        # Parse different URL formats
                        if "github.com" in remote_url:
                            if remote_url.startswith("https://github.com/"):
                                # https://github.com/owner/repo.git
                                path = remote_url.replace(
                                    "https://github.com/", ""
                                ).replace(".git", "")
                            elif remote_url.startswith("git@github.com:"):
                                # git@github.com:owner/repo.git
                                path = remote_url.replace(
                                    "git@github.com:", ""
                                ).replace(".git", "")
                            else:
                                path = None

                            if path and "/" in path:
                                parts = path.split("/")
                                if not owner:
                                    owner = parts[0]
                                if not repo_name:
                                    repo_name = parts[1]
                                logger.info(
                                    f"Detected repository from git remote: {owner}/{repo_name}"
                                )
                    except subprocess.SubprocessError as e:
                        logger.debug(f"Could not get git remote: {e}")

                # Get current branch
                if not branch:
                    try:
                        branch = (
                            subprocess.check_output(
                                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                stderr=subprocess.DEVNULL,
                                timeout=10,
                            )
                            .decode("utf-8")
                            .strip()
                        )
                        if branch != "HEAD":
                            logger.info(f"Detected branch from git: {branch}")
                        else:
                            # In detached HEAD state, try to get branch from reflog or describe
                            try:
                                branch = (
                                    subprocess.check_output(
                                        [
                                            "git",
                                            "describe",
                                            "--contains",
                                            "--all",
                                            "HEAD",
                                        ],
                                        stderr=subprocess.DEVNULL,
                                        timeout=10,
                                    )
                                    .decode("utf-8")
                                    .strip()
                                )
                                if branch.startswith("heads/"):
                                    branch = branch.replace("heads/", "")
                                logger.info(
                                    f"Detected branch from git describe: {branch}"
                                )
                            except subprocess.SubprocessError:
                                branch = None
                    except subprocess.SubprocessError as e:
                        logger.debug(f"Could not get git branch: {e}")

                # Restore original directory
                os.chdir(original_cwd)

        except Exception as e:
            logger.debug(f"Error detecting repository info: {e}")
            # Restore directory in case of error
            try:
                os.chdir(original_cwd)
            except Exception:
                pass

    # Apply fallbacks
    owner = owner or "unknown-owner"
    repo_name = repo_name or "unknown-repository"
    branch = branch or None  # Keep as None if not detected

    logger.info(
        f"Final detected repository info - Owner: {owner}, Repo: {repo_name}, Branch: {branch}"
    )
    return owner, repo_name, branch


def generate_summary_for_local_scan(
    local_repo_reports_path: str, reports_output_dir_base: str
) -> Dict:
    """Generate summary for local repository scan"""
    logger.info(f"Generating summary for local scan from {reports_output_dir_base}")

    # For local scans, look for the direct report files in reports_output_dir_base
    gitleaks_report = os.path.join(reports_output_dir_base, "gitleaks-report.json")
    trivy_report = os.path.join(reports_output_dir_base, "trivy-fs-report.json")

    # Check if we have the raw scan reports
    if os.path.exists(gitleaks_report) or os.path.exists(trivy_report):
        logger.info("Processing local scan reports directly")

        # Process the reports and generate summary
        processed_results = process_scan_reports(
            gitleaks_report if os.path.exists(gitleaks_report) else None,
            trivy_report if os.path.exists(trivy_report) else None,
            None,  # No OSV scanner for local scans yet
        )

        scan_results_summary = processed_results["scan_results_summary"]
        detailed_reports_data = processed_results["detailed_reports_data"]

        # Detect actual repository information
        scan_path = local_repo_reports_path or reports_output_dir_base or os.getcwd()
        detected_owner, detected_repo, detected_branch = detect_repository_info(
            scan_path
        )

        # Generate the combined report with detected info
        combined_report = generate_combined_report(
            detected_owner,
            detected_repo,
            scan_results_summary,
            detailed_reports_data,
            detected_branch,
        )

        # Save the final reports
        save_final_reports(
            combined_report, reports_output_dir_base, detected_owner, detected_repo
        )

        return {"status": "success", "report": combined_report}

    # Fallback: look for summary.json files (for backward compatibility with multi-repo scans)
    if not os.path.exists(local_repo_reports_path):
        logger.error(f"Local reports path does not exist: {local_repo_reports_path}")
        return {"error": f"Local reports path not found: {local_repo_reports_path}"}

    # Find all summary.json files
    summary_files = []
    for root, dirs, files in os.walk(local_repo_reports_path):
        for file in files:
            if file == "summary.json":
                summary_files.append(os.path.join(root, file))

    if not summary_files:
        logger.warning(
            "No summary.json files found in local reports path and no raw scan reports found"
        )
        return {"error": "No summary files found"}

    logger.info(f"Found {len(summary_files)} summary files")

    # Process each summary file
    aggregated_summaries = []
    overall_totals = {
        "gitleaks_findings": 0,
        "trivy_vulnerabilities": 0,
        "trivy_misconfigurations": 0,
    }

    for summary_file in summary_files:
        try:
            with open(summary_file, "r", encoding="utf-8") as f:
                summary_data = json.load(f)

            aggregated_summaries.append(summary_data)

            # Aggregate totals
            results = summary_data.get("results", {})
            overall_totals["gitleaks_findings"] += results.get("gitleaks", {}).get(
                "findings_count", 0
            )
            overall_totals["trivy_vulnerabilities"] += results.get("trivy", {}).get(
                "vulnerabilities_count", 0
            )
            overall_totals["trivy_misconfigurations"] += results.get("trivy", {}).get(
                "misconfigurations_count", 0
            )

        except Exception as e:
            logger.error(f"Error processing summary file {summary_file}: {e}")

    # Generate overall summary
    current_time_obj = get_current_utc_time()
    current_date_str = current_time_obj.strftime("%Y-%m-%d")

    overall_summary_data = {
        "scan_date": current_date_str,
        "scan_time": current_time_obj.strftime("%H:%M:%S UTC"),
        "scan_type": "local_scan",
        "total_repositories_scanned": len(aggregated_summaries),
        "overall_totals": overall_totals,
        "repository_summaries": aggregated_summaries,
    }

    # Save overall summary
    overall_summary_path = os.path.join(
        reports_output_dir_base, "local-scan-overall-summary.json"
    )
    safe_remove_if_exists(overall_summary_path)
    with open(overall_summary_path, "w", encoding="utf-8") as f:
        json.dump(overall_summary_data, f, indent=2)

    logger.info(f"Local scan summary generated: {overall_summary_path}")

    total_local_issues = (
        overall_totals["gitleaks_findings"]
        + overall_totals["trivy_vulnerabilities"]
        + overall_totals["trivy_misconfigurations"]
    )

    # Slack notification removed

    return {
        "success": True,
        "repositories_scanned": len(aggregated_summaries),
        "total_issues": total_local_issues,
    }


def check_pipeline_exit_conditions(combined_report: Dict) -> bool:
    """Check if pipeline should exit based on scan results"""
    exec_summary = combined_report.get("executive_summary", {})
    total_issues = exec_summary.get("total_issues", 0)
    risk_level = exec_summary.get("risk_level", "INFO")

    # Exit on critical findings
    if risk_level == "CRITICAL":
        logger.error("CRITICAL security issues found. Pipeline will exit.")
        return True

    # Exit on high number of issues
    if total_issues > 50:
        logger.error(
            f"High number of security issues found ({total_issues}). Pipeline will exit."
        )
        return True

    return False


def fail_pipeline_on_critical_findings(
    combined_report: Dict, exit_code: int = 1
) -> None:
    """Fail the pipeline if critical findings are detected"""
    if check_pipeline_exit_conditions(combined_report):
        exec_summary = combined_report.get("executive_summary", {})
        total_issues = exec_summary.get("total_issues", 0)
        risk_level = exec_summary.get("risk_level", "INFO")

        logger.error(
            f"Pipeline failed due to security issues: {total_issues} issues, Risk Level: {risk_level}"
        )
        sys.exit(exit_code)


def main():
    """Main function to orchestrate the security scanning process"""
    print("🚀 SCRIPT STARTED: git-audit-script.py main() function")
    parser = argparse.ArgumentParser(description="GitHub Security Scanner")
    parser.add_argument(
        "--action",
        choices=["scan-single-repo", "scan-org", "scan-user", "generate-summary"],
        default="scan-single-repo",
        help="Action to perform",
    )
    parser.add_argument(
        "--repo-path", help="Path to local repository (for local scans)"
    )
    parser.add_argument(
        "--reports-dir",
        default="/scan_target/scan_reports",
        help="Directory for reports",
    )

    args = parser.parse_args()

    # Set global variables
    global REPO_PATH_FROM_ARGS
    REPO_PATH_FROM_ARGS = args.repo_path

    reports_dir = args.reports_dir
    os.makedirs(reports_dir, exist_ok=True)

    logger.info("=== GitHub Security Scanner ===")
    logger.info(f"Action: {args.action}")
    logger.info(f"Reports directory: {reports_dir}")

    try:
        if args.action == "scan-single-repo":
            if not GITHUB_OWNER or not GITHUB_REPO:
                logger.error(
                    "GITHUB_OWNER and GITHUB_REPO environment variables must be set for single repository scan"
                )
                sys.exit(1)

            result = scan_single_repository(
                GITHUB_OWNER,
                GITHUB_REPO,
                REPO_PATH_FROM_ARGS or "/scan_target",
                reports_dir,
            )

            if "error" in result:
                logger.error(f"Scan failed: {result['error']}")
                sys.exit(1)

            # Check for critical findings
            if "combined_report" in result:
                fail_pipeline_on_critical_findings(result["combined_report"])

        elif args.action == "scan-org":
            if not GITHUB_ORG:
                logger.error(
                    "GITHUB_ORG environment variable must be set for organization scan"
                )
                sys.exit(1)

            result = scan_organization_repositories(
                GITHUB_ORG, REPO_PATH_FROM_ARGS or "/scan_target", reports_dir
            )

            if "error" in result:
                logger.error(f"Organization scan failed: {result['error']}")
                sys.exit(1)

        elif args.action == "scan-user":
            if not GITHUB_OWNER:
                logger.error(
                    "GITHUB_OWNER environment variable must be set for user repository scan"
                )
                sys.exit(1)

            result = scan_user_repositories(
                GITHUB_OWNER, REPO_PATH_FROM_ARGS or "/scan_target", reports_dir
            )

            if "error" in result:
                logger.error(f"User scan failed: {result['error']}")
                sys.exit(1)

        elif args.action == "generate-summary":
            if not REPO_PATH_FROM_ARGS:
                logger.error(
                    "--repo-path must be specified for generate-summary action"
                )
                sys.exit(1)

            result = generate_summary_for_local_scan(REPO_PATH_FROM_ARGS, reports_dir)

            if "error" in result:
                logger.error(f"Summary generation failed: {result['error']}")
                sys.exit(1)

        logger.info("Security scan completed successfully")

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
