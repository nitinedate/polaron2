from agent.main import _target_progress_snapshot


def test_target_progress_exposes_waiting_in_progress_completed_and_failed():
    targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    chunks = [["10.0.0.1", "10.0.0.2"], ["10.0.0.3", "10.0.0.4"]]
    snapshot = _target_progress_snapshot(
        all_targets=targets,
        chunks=chunks,
        pending=[1],
        in_flight={0: "task-a"},
        task_ids=["task-a", None],
        done_details={},
        poll_results={0: {"status": "running", "gmp_status": "running", "progress": 42, "evidence": {}}},
        skipped_hosts=[],
    )
    assert snapshot["10.0.0.1"]["status"] == "in_progress"
    assert snapshot["10.0.0.1"]["progress_pct"] == 42
    assert snapshot["10.0.0.3"]["status"] == "waiting"

    snapshot = _target_progress_snapshot(
        all_targets=targets,
        chunks=chunks,
        pending=[],
        in_flight={},
        task_ids=["task-a", "task-b"],
        done_details={
            0: {
                "status": "completed",
                "progress": 100,
                "evidence": {
                    "assessed_hosts": ["10.0.0.1"],
                    "missing_ip_targets": ["10.0.0.2"],
                },
            },
            1: {
                "status": "completed",
                "progress": 100,
                "evidence": {"assessed_hosts": ["10.0.0.3", "10.0.0.4"], "missing_ip_targets": []},
            },
        },
        poll_results={},
        skipped_hosts=[{"host": "10.0.0.2", "reason": "unreachable"}],
    )
    assert snapshot["10.0.0.1"]["status"] == "completed"
    assert snapshot["10.0.0.2"]["status"] == "failed"
    assert snapshot["10.0.0.3"]["status"] == "completed"
