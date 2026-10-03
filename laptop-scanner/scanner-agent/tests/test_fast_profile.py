from contextlib import contextmanager

import agent.gmp_local as gmp_local


class _StartResponse:
    def findtext(self, name):
        return "report-1" if name == "report_id" else None

    def __len__(self):
        return 0


class _FakeGmp:
    def __init__(self):
        self.target_kwargs = None
        self.task_kwargs = None

    def create_target(self, **kwargs):
        self.target_kwargs = kwargs
        return {"id": "target-1"}

    def create_task(self, **kwargs):
        self.task_kwargs = kwargs
        return {"id": "task-1"}

    def start_task(self, task_id):
        assert task_id == "task-1"
        return _StartResponse()


def test_fast_profile_uses_only_discovered_ports(monkeypatch):
    fake = _FakeGmp()

    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setenv("PORT_PROFILE", "fast")
    monkeypatch.setenv("GVM_MAX_CHECKS", "6")
    monkeypatch.setenv("GVM_MAX_HOSTS", "1")
    monkeypatch.setattr(gmp_local, "_session", fake_session)
    monkeypatch.setattr(gmp_local, "_find_config_id", lambda gmp, name: "config-1")
    monkeypatch.setattr(gmp_local, "_assert_feed_quality", lambda gmp, cid: {})
    monkeypatch.setattr(gmp_local, "_find_scanner_id", lambda gmp: "scanner-1")
    monkeypatch.setattr("agent.control_plane.port_range_without_control_plane", lambda spec, hosts: spec)

    scanner = gmp_local.LocalOpenVAS()
    task_id = scanner.start_scan(name="t", targets=["10.0.0.20"], ports=[443, 22, 443])

    assert task_id == "task-1"
    assert fake.target_kwargs["port_range"] == "T:22,443"
    assert fake.task_kwargs["preferences"]["max_checks"] == "16"
    assert fake.task_kwargs["preferences"]["max_hosts"] == "1"
    assert fake.task_kwargs["preferences"]["optimize_test"] == "yes"
    assert fake.task_kwargs["preferences"]["expand_vhosts"] == "no"
