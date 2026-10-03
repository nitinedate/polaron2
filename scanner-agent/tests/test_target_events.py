from unittest.mock import patch

from agent.api_client import CentralApi
import agent.ip_audit as audit


def test_api_client_posts_structured_target_event():
    api = CentralApi(base_url="https://central.example", tenant="firm", token="token", verify_tls=False)
    with patch.object(api, "_request", return_value={"status": "ok"}) as req:
        result = api.post_target_event(
            "job-1",
            {
                "job_id": "job-1",
                "ip": "10.0.0.8",
                "event": "progress",
                "status": "running",
                "progress": 42,
                "open_ports": [22, 443],
                "task_id": "task-1",
            },
        )
    assert result["status"] == "ok"
    args, kwargs = req.call_args
    assert args[:2] == ("POST", "/api/scanner-agent/jobs/job-1/target-events")
    assert kwargs["json"]["target"] == "10.0.0.8"
    assert kwargs["json"]["progress_pct"] == 42
    assert kwargs["json"]["open_ports"] == [22, 443]


def test_ip_event_sink_is_non_blocking_and_flushes(tmp_path, monkeypatch):
    monkeypatch.setenv("IP_SCAN_LOG_DIR", str(tmp_path))
    received = []
    audit.set_ip_event_sink(lambda payload: received.append(payload))
    audit.emit_ip_event("j1", "10.0.0.9", "queued")
    assert audit.flush_ip_events(2.0) is True
    assert received and received[-1]["event"] == "queued"
    assert (tmp_path / "j1" / "10.0.0.9.jsonl").is_file()
