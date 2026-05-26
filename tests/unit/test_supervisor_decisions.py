from chainshield.supervisor import GateEvidence, decide_static_gates


def evidence(gate, status, reasons=None):
    return GateEvidence(
        gate=gate,
        status=status,
        source_kind="fixture",
        source_path=f"fixtures/reports/{gate}.json",
        command=None,
        exit_code=0 if status == "pass" else 1,
        risk_level="critical" if status == "deny" else "none",
        reasons=reasons or [f"{gate} {status}"],
        observed_at="2026-05-27T00:00:00Z",
        run_id="run-foundation",
    )


def test_snyk_deny_wins_static_gate_matrix():
    decision = decide_static_gates([evidence("snyk", "deny"), evidence("socket", "pass")])

    assert decision.decision == "deny"
    assert "snyk" in decision.primary_reasons[0].lower()


def test_socket_deny_wins_static_gate_matrix():
    decision = decide_static_gates([evidence("snyk", "pass"), evidence("socket", "deny")])

    assert decision.decision == "deny"
    assert "socket" in decision.primary_reasons[0].lower()


def test_missing_evidence_yields_manual_review():
    decision = decide_static_gates([evidence("snyk", "pass")])

    assert decision.decision == "manual_review"
    assert decision.missing_gates == ["socket"]


def test_skipped_scanner_modes_yield_manual_review_with_missing_gates():
    decision = decide_static_gates(
        [], scanner_mode={"snyk": "skip", "socket": "skip"}
    )

    assert decision.decision == "manual_review"
    assert decision.missing_gates == ["snyk", "socket"]


def test_static_deny_cannot_be_overridden_by_sandbox_demo_override():
    decision = decide_static_gates(
        [evidence("snyk", "deny"), evidence("socket", "pass")],
        sandbox_demo_override=True,
    )

    assert decision.decision == "deny"
    assert any("override" in action.lower() for action in decision.next_actions)
