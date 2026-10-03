from unittest.mock import MagicMock, patch

from app.services.agent_huddle import run_agent_huddle


def test_huddle_skips_everything_before_evidence_selection():
    db = MagicMock()
    snap = {
        "job_id": "job-1",
        "row": {"id": "job-1", "status": "created", "disk_source": None},
        "status": "created",
        "stop_requested": False,
        "intake_started": False,
    }

    with patch("app.services.agent_huddle.observe_pipeline_snapshot", return_value=snap), patch(
        "app.services.performance_agent.apply_performance_advice"
    ) as perf, patch(
        "app.services.pipeline_supervisor.dispatch_stage_agent"
    ) as dispatch, patch(
        "app.services.pipeline_orchestrator.persist_drive_mount_complete"
    ) as persist_mount:
        result = run_agent_huddle(db, "job-1", schema_name="firm_test")

    assert result == {
        "status": "skipped",
        "reason": "awaiting_evidence_selection",
        "job_id": "job-1",
    }
    perf.assert_not_called()
    dispatch.assert_not_called()
    persist_mount.assert_not_called()
