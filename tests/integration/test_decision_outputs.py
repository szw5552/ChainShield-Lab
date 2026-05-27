import json
from pathlib import Path

from chainshield import cli


def cleanup(*paths):
    for path in paths:
        if path:
            Path(path).unlink(missing_ok=True)


def test_decision_json_and_markdown_top_summary_for_manual_review(tmp_path):
    decision_path = Path("reports/test-us3-manual-review-decision.json")
    summary_path = Path("reports/test-us3-manual-review-summary.md")
    cleanup(decision_path, summary_path)
    config = {
        "version": 1,
        "request_id": "REQ-us3-manual-review",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "skip"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-pass.json",
            "socket_report": None,
            "openshell_log": None,
            "canary_secret": "fixtures/canary/synthetic-canary.txt",
        },
        "outputs": {"decision_json": str(decision_path), "markdown_summary": str(summary_path)},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "manual-review.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    assert cli.main(["evaluate", "--config", str(config_path)]) == 2

    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    markdown = summary_path.read_text(encoding="utf-8")
    assert decision["decision"] == "manual_review"
    assert "socket" in decision["missing_gates"]
    assert any("sanitized evidence/config" in action for action in decision["next_actions"])
    actions_text = " ".join(decision["next_actions"]).lower()
    assert "manually rewrite" in actions_text and "into allow" in actions_text
    assert "do not manually rewrite" in actions_text
    assert markdown.startswith("# ChainShield Decision: manual_review")
    assert "Result:" in markdown.splitlines()[2]
    assert "Primary reasons:" in markdown.splitlines()[3]
    assert "Missing gates:" in markdown.splitlines()[4]
    assert "Next actions:" in markdown.splitlines()[5]
    assert "Demo-only npm supply-chain defense PoC" in markdown
    assert str(decision_path) in markdown
    cleanup(decision_path, summary_path)
