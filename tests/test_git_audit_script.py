import unittest
import os
import sys
from unittest.mock import patch, MagicMock
import importlib.util

# Add parent directory to path to import the script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock requests module since it might not be installed in the test environment
sys.modules["requests"] = MagicMock()

# Import the module to test
script_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "git-audit-script.py"
)
spec = importlib.util.spec_from_file_location("git_audit_script", script_path)
git_audit_script = importlib.util.module_from_spec(spec)
sys.modules["git_audit_script"] = git_audit_script
spec.loader.exec_module(git_audit_script)


class TestGitAuditScript(unittest.TestCase):
    def test_generate_dynamic_recommendations_empty(self):
        """Test recommendation generation with empty report"""
        report = {}
        recommendations = git_audit_script.generate_dynamic_recommendations(report)
        self.assertTrue(len(recommendations["info"]) > 0)
        self.assertEqual(len(recommendations["critical"]), 0)

    def test_generate_dynamic_recommendations_gitleaks(self):
        """Test recommendation generation with Gitleaks findings"""
        report = {"gitleaks": [{"Description": "AWS Access Key", "Secret": "AKIA..."}]}
        recommendations = git_audit_script.generate_dynamic_recommendations(report)
        self.assertTrue(len(recommendations["critical"]) > 0)
        self.assertIn("Secrets detected", recommendations["critical"][0])

    def test_generate_dynamic_recommendations_trivy_vuln(self):
        """Test recommendation generation with Trivy vulnerabilities"""
        report = {
            "trivy-fs": {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2023-1234"}
                        ]
                    }
                ]
            }
        }
        recommendations = git_audit_script.generate_dynamic_recommendations(report)
        self.assertTrue(len(recommendations["critical"]) > 0)
        self.assertIn(
            "critical vulnerabilities detected", recommendations["critical"][0]
        )

    def test_generate_combined_report(self):
        """Test combined report generation"""
        scan_summary = {
            "gitleaks": {"findings_count": 5},
            "trivy-fs": {"vulnerabilities_count": 2, "misconfigurations_count": 0},
        }
        detailed_reports = {}

        with patch.dict(
            os.environ, {"GITHUB_OWNER": "test-owner", "GITHUB_REPO": "test-repo"}
        ):
            report = git_audit_script.generate_combined_report(
                "test-owner", "test-repo", scan_summary, detailed_reports
            )

            self.assertEqual(report["executive_summary"]["total_issues"], 7)
            self.assertEqual(
                report["executive_summary"]["secret_exposure_risk"], "CRITICAL"
            )
            self.assertEqual(report["metadata"]["owner"], "test-owner")

    def test_convert_json_to_html(self):
        """Test HTML report generation"""
        report_data = {
            "metadata": {
                "owner": "test-owner",
                "repository": "test-repo",
                "scan_date": "2023-01-01",
            },
            "executive_summary": {"total_issues": 0, "risk_level": "INFO"},
            "recommendations": {"info": ["No issues found"]},
        }

        html_output = git_audit_script.convert_json_to_html(report_data)
        self.assertIn("<!DOCTYPE html>", html_output)
        self.assertIn("test-owner/test-repo", html_output)
        self.assertIn("No issues found", html_output)


if __name__ == "__main__":
    unittest.main()
