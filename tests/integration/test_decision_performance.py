import json
import time
from pathlib import Path

from chainshield import cli
from chainshield.config import DemoConfig, build_run_id
from chainshield.scanners import run_scanners
from chainshield.supervisor import decide_static_gates


REPORTS = Path("reports")


def cleanup(*paths):
    for path in paths:
        if path:
            Path(path).unlink(missing_ok=True)


def timed_call(label, limit_seconds, func):
    started_wall = time.time()
    started = time.perf_counter()
    try:
        result = func()
        failure_reason = None
        return result, {
            "label": label,
            "started_at_epoch": started_wall,
            "ended_at_epoch": time.time(),
            "elapsed_seconds": time.perf_counter() - started,
            "limit_seconds": limit_seconds,
            "failure_reason": failure_reason,
        }
    except Exception as exc:  # pragma: no cover - evidence path for unexpected failure
        observation = {
            "label": label,
            "started_at_epoch": started_wall,
            "ended_at_epoch": time.time(),
            "elapsed_seconds": time.perf_counter() - started,
            "limit_seconds": limit_seconds,
            "failure_reason": type(exc).__name__,
        }
        raise AssertionError(json.dumps(observation, sort_keys=True)) from exc


def test_fixture_scanner_report_processing_and_total_decision_runtime(tmp_path):
    decision_path = REPORTS / "test-performance-decision.json"
    summary_path = REPORTS / "test-performance-summary.md"
    cleanup(decision_path, summary_path)
    config_path = Path("fixtures/configs/demo-fixture-allow.json")
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    raw["outputs"] = {"decision_json": str(decision_path), "markdown_summary": str(summary_path)}
    test_config_path = tmp_path / "performance-config.json"
    test_config_path.write_text(json.dumps(raw), encoding="utf-8")
    config = DemoConfig.load(test_config_path)
    run_id = build_run_id(test_config_path, config.fixtures, "2026-05-27T00:00:00Z", "perfhash")

    scanner_results, scanner_obs = timed_call("fixture_scanner", 30, lambda: run_scanners(config, run_id=run_id))
    assert scanner_obs["elapsed_seconds"] < scanner_obs["limit_seconds"], scanner_obs

    _, supervisor_obs = timed_call(
        "supervisor_report_processing",
        30,
        lambda: decide_static_gates(
            scanner_results,
            scanner_mode=config.scanner_mode,
            request_id=config.request_id,
            run_id=run_id,
            artifacts={"decision_json": str(decision_path), "markdown_summary": str(summary_path), "reports": [], "logs": [], "worker": []},
            worker_provider=config.worker_provider,
        ).to_dict(),
    )
    assert supervisor_obs["elapsed_seconds"] < supervisor_obs["limit_seconds"], supervisor_obs

    exit_code, total_obs = timed_call("fixture_first_total_decision", 10, lambda: cli.main(["evaluate", "--config", str(test_config_path)]))
    performance_observation = tmp_path / "decision-performance-observation.json"
    performance_observation.write_text(
        json.dumps([scanner_obs, supervisor_obs, total_obs], indent=2, sort_keys=True),
        encoding="utf-8",
    )

    assert exit_code == 0
    assert total_obs["elapsed_seconds"] < total_obs["limit_seconds"], total_obs
    saved = json.loads(performance_observation.read_text(encoding="utf-8"))
    assert all("started_at_epoch" in item and "ended_at_epoch" in item for item in saved)
    assert all("failure_reason" in item for item in saved)
    cleanup(decision_path, summary_path)
