import json

from chainshield.evidence import normalize_snyk_report, normalize_snyk_report_data


def test_snyk_high_and_critical_vulnerabilities_deny(tmp_path):
    report = tmp_path / "snyk-high-critical.json"
    report.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"id": "SNYK-1", "packageName": "demo-low", "severity": "low", "title": "low issue"},
                    {"id": "SNYK-2", "packageName": "demo-high", "severity": "high", "title": "prototype pollution"},
                    {"id": "SNYK-3", "packageName": "demo-critical", "severity": "critical", "title": "rce"},
                ]
            }
        ),
        encoding="utf-8",
    )

    evidence = normalize_snyk_report(report, run_id="run-us1")

    assert evidence["gate"] == "snyk"
    assert evidence["status"] == "deny"
    assert evidence["risk_level"] == "critical"
    assert "demo-critical" in " ".join(evidence["reasons"])


def test_snyk_low_medium_passes_with_residual_risk():
    evidence = normalize_snyk_report_data(
        {
            "vulnerabilities": [
                {"id": "SNYK-LOW", "packageName": "left-pad", "severity": "low", "title": "informational"},
                {"id": "SNYK-MED", "packageName": "qs", "severity": "medium", "title": "denial of service"},
            ]
        },
        source_path="fixtures/reports/snyk-low-medium.json",
        run_id="run-us1",
    )

    assert evidence["status"] == "pass"
    assert evidence["risk_level"] == "medium"
    assert any("residual risk" in reason.lower() for reason in evidence["reasons"])
    assert "qs" in " ".join(evidence["reasons"])


def test_snyk_pass_report_passes():
    evidence = normalize_snyk_report_data(
        {"ok": True, "vulnerabilities": []},
        source_path="fixtures/reports/snyk-pass.json",
        run_id="run-us1",
    )

    assert evidence["status"] == "pass"
    assert evidence["risk_level"] == "none"


def test_snyk_unparseable_report_requires_manual_review(tmp_path):
    report = tmp_path / "not-json.txt"
    report.write_text("not json", encoding="utf-8")

    evidence = normalize_snyk_report(report, run_id="run-us1")

    assert evidence["status"] == "manual_review"
    assert evidence["risk_level"] == "unknown"
    assert any("parse" in reason.lower() for reason in evidence["reasons"])
