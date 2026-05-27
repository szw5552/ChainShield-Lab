from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PPT_DIR = REPO_ROOT / "docs" / "agent-flow-ppt"


def _read(name: str) -> str:
    return (PPT_DIR / name).read_text(encoding="utf-8")


def test_agent_flow_ppt_has_required_static_files():
    assert (PPT_DIR / "index.html").is_file()
    assert (PPT_DIR / "styles.css").is_file()
    assert (PPT_DIR / "app.js").is_file()


def test_agent_flow_ppt_contains_required_nodes_and_outputs():
    html = _read("index.html")
    required_terms = [
        "Demo Config",
        "Snyk Gate",
        "Socket Gate",
        "OpenShell Gate",
        "AI Worker Summary",
        "Supervisor Decision",
        "decision JSON",
        "Markdown summary",
        "allow",
        "deny",
        "manual_review",
    ]
    for term in required_terms:
        assert term in html


def test_agent_flow_ppt_documents_gate_conditions_and_safety_boundaries():
    html = _read("index.html")
    required_conditions = [
        "high / critical vulnerability",
        "policy violation",
        "malware risk",
        "supply-chain risk",
        "filesystem read block",
        "network egress block",
        "deterministic rules",
        "sanitized evidence",
        "不能直接裁決 allow / deny",
        "Do not run npm install on host",
    ]
    for condition in required_conditions:
        assert condition in html


def test_agent_flow_ppt_has_navigation_and_motion_hooks():
    html = _read("index.html")
    js = _read("app.js")
    css = _read("styles.css")

    assert 'data-action="prev"' in html
    assert 'data-action="next"' in html
    assert 'id="motion-canvas"' in html
    assert "ArrowRight" in js
    assert "ArrowLeft" in js
    assert "requestAnimationFrame" in js
    assert "@media" in css
    assert "prefers-reduced-motion" in css
