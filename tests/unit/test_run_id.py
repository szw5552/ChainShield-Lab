from chainshield.config import build_run_id


def test_run_id_is_reproducible_for_fixed_inputs():
    run_id_1 = build_run_id(
        config_path="fixtures/configs/demo-fixture-deny.json",
        fixture_identity={"snyk": "fixtures/reports/snyk-high-critical.json"},
        timestamp="2026-05-27T00:00:00Z",
        evidence_hash="abc123",
    )
    run_id_2 = build_run_id(
        config_path="fixtures/configs/demo-fixture-deny.json",
        fixture_identity={"snyk": "fixtures/reports/snyk-high-critical.json"},
        timestamp="2026-05-27T00:00:00Z",
        evidence_hash="abc123",
    )

    assert run_id_1 == run_id_2
    assert run_id_1.startswith("run-20260527T000000Z-")


def test_run_id_changes_when_fixture_or_evidence_hash_changes():
    base = build_run_id("fixtures/configs/demo.json", {"snyk": "a"}, "2026-05-27T00:00:00Z", "abc")
    changed_fixture = build_run_id("fixtures/configs/demo.json", {"snyk": "b"}, "2026-05-27T00:00:00Z", "abc")
    changed_hash = build_run_id("fixtures/configs/demo.json", {"snyk": "a"}, "2026-05-27T00:00:00Z", "def")

    assert base != changed_fixture
    assert base != changed_hash
