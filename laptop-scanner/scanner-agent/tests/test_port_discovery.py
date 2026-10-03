from agent.port_discovery import (
    DEFAULT_FALLBACK_RANGE,
    discover_open_tcp_ports,
    parse_tcp_ports_from_range,
    ports_to_gvm_range,
    resolve_fast_scan_port_range,
)


class _FakeSocket:
    def close(self):
        return None


def test_parse_tcp_ports_from_range_expands_ranges():
    assert parse_tcp_ports_from_range("T:22,80-82,443") == [22, 80, 81, 82, 443]


def test_discovery_returns_per_host_and_union():
    open_pairs = {("10.0.0.1", 80), ("10.0.0.2", 443)}

    def connector(address, timeout):
        assert timeout > 0
        if address in open_pairs:
            return _FakeSocket()
        raise ConnectionRefusedError()

    result = discover_open_tcp_ports(
        ["10.0.0.1", "10.0.0.2"],
        "T:22,80,443",
        timeout=0.01,
        connector=connector,
    )
    assert result["by_host"]["10.0.0.1"] == [80]
    assert result["by_host"]["10.0.0.2"] == [443]
    assert result["open_ports"] == [80, 443]
    assert ports_to_gvm_range(result["open_ports"]) == "T:80,443"


def test_fast_resolver_uses_fallback_when_no_port_answers(monkeypatch):
    monkeypatch.setenv("PORT_DISCOVERY_ENABLED", "true")
    monkeypatch.setenv("PORT_DISCOVERY_FALLBACK_RANGE", DEFAULT_FALLBACK_RANGE)

    def no_ports(*args, **kwargs):
        return {
            "by_host": {"10.0.0.9": []},
            "open_ports": [],
            "candidate_ports": [22, 80],
            "probe_count": 2,
            "workers": 2,
            "timeout_sec": 0.01,
        }

    monkeypatch.setattr("agent.port_discovery.discover_open_tcp_ports", no_ports)
    selected, details = resolve_fast_scan_port_range(["10.0.0.9"], "T:22,80")
    assert selected == DEFAULT_FALLBACK_RANGE
    assert details["fallback_used"] is True


def test_fast_resolver_can_be_disabled(monkeypatch):
    monkeypatch.setenv("PORT_DISCOVERY_ENABLED", "false")
    selected, details = resolve_fast_scan_port_range(["10.0.0.9"], "T:22,80,443")
    assert selected == "T:22,80,443"
    assert details["enabled"] is False


def test_local_openvas_fast_profile_passes_discovered_range_to_greenbone(monkeypatch):
    from contextlib import contextmanager
    from lxml import etree
    from agent import gmp_local as mod

    monkeypatch.setenv("PORT_PROFILE", "fast")
    monkeypatch.setenv("GVM_OPTIMIZE_TEST", "yes")
    monkeypatch.setattr(
        "agent.port_discovery.resolve_fast_scan_port_range",
        lambda hosts, candidate: (
            "T:80,443",
            {"enabled": True, "fallback_used": False, "by_host": {hosts[0]: [80, 443]}},
        ),
    )

    class FakeGmp:
        def __init__(self):
            self.target_kwargs = None

        def create_target(self, **kwargs):
            self.target_kwargs = kwargs
            return {"id": "target-fast"}

        def create_task(self, **kwargs):
            return {"id": "task-fast"}

        def start_task(self, task_id):
            return etree.fromstring(b"<start_task_response><report_id>report-fast</report_id></start_task_response>")

    fake = FakeGmp()

    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setattr(mod, "_session", fake_session)
    monkeypatch.setattr(mod, "_find_config_id", lambda gmp, name: "config-fast")
    monkeypatch.setattr(mod, "_assert_feed_quality", lambda gmp, config_id: None)
    monkeypatch.setattr(mod, "_find_scanner_id", lambda gmp: "scanner-fast")

    scanner = mod.LocalOpenVAS()
    task_id = scanner.start_scan(name="fast-test", targets=["10.0.0.1"])

    assert task_id == "task-fast"
    assert fake.target_kwargs["port_range"] == "T:80,443"
    assert scanner.port_profile == "fast"
    assert scanner.optimize_test == "yes"
