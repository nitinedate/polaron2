from unittest.mock import patch

import agent.reachability as reach


def test_reachability_worker_floor_is_five_when_targets_allow(monkeypatch):
    monkeypatch.setenv('REACHABILITY_WORKERS', '2')
    assert reach._workers(50) == 5
    assert reach._workers(3) == 3


def test_partition_omits_only_failed_ip_and_keeps_order(monkeypatch):
    monkeypatch.setenv('SKIP_UNREACHABLE_TARGETS', 'true')

    def fake_probe(host, **kwargs):
        return {'host': host, 'reachable': host != '10.0.0.2', 'open_port': 443 if host != '10.0.0.2' else None}

    with patch('agent.reachability.probe_host', side_effect=fake_probe):
        out = reach.partition_targets(['10.0.0.1', '10.0.0.2', '10.0.0.3'], job_id='j')
    assert out['reachable'] == ['10.0.0.1', '10.0.0.3']
    assert out['unreachable'] == ['10.0.0.2']
    assert out['skipped_hosts'] == [{'host': '10.0.0.2', 'reason': 'unreachable'}]


def test_connection_refused_proves_host_is_alive(monkeypatch):
    monkeypatch.setenv("REACHABILITY_UNKNOWN_POLICY", "scan")
    monkeypatch.setattr(
        reach,
        "_probe_port",
        lambda host, port, timeout: (port, "closed_alive", "ConnectionRefusedError"),
    )
    out = reach.probe_host("10.0.0.10", ports=[22, 443], timeout=0.1)
    assert out["reachable"] is True
    assert out["probe_state"] == "alive"
    assert out["open_ports"] == []


def test_timeout_only_probe_is_inconclusive_and_scanned_by_default(monkeypatch):
    monkeypatch.setenv("REACHABILITY_UNKNOWN_POLICY", "scan")
    monkeypatch.setattr(
        reach,
        "_probe_port",
        lambda host, port, timeout: (port, "timeout", "TimeoutError"),
    )
    out = reach.probe_host("10.0.0.11", ports=[22, 443], timeout=0.1)
    assert out["reachable"] is True
    assert out["inconclusive"] is True
    assert out["probe_state"] == "inconclusive"


def test_discovery_collects_all_open_ports(monkeypatch):
    states = {22: "open", 80: "closed_alive", 443: "open"}
    monkeypatch.setattr(
        reach,
        "_probe_port",
        lambda host, port, timeout: (port, states[port], None),
    )
    out = reach.probe_host("10.0.0.12", ports=[22, 80, 443], timeout=0.1)
    assert out["reachable"] is True
    assert out["open_ports"] == [22, 443]
