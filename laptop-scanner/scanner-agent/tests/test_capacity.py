"""Laptop IP fan-out has a five-worker operational floor."""

from unittest.mock import patch

from agent.capacity import (
    IP_WORKERS_MIN,
    chunk_targets,
    ip_workers_for_cpu,
    probe_laptop_capacity,
)


def test_ip_workers_scale_from_five_upward(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    assert ip_workers_for_cpu(1, explicit='auto') == 5
    assert ip_workers_for_cpu(4, explicit='auto') == 5
    assert ip_workers_for_cpu(8, explicit='auto') == 6
    assert ip_workers_for_cpu(12, explicit='auto') == 8
    assert ip_workers_for_cpu(16, explicit='auto') == 10


def test_explicit_value_cannot_drop_below_five(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    assert ip_workers_for_cpu(16, explicit='2') == 5
    assert ip_workers_for_cpu(16, explicit='5') == 5
    assert ip_workers_for_cpu(16, explicit='8') == 8


def test_chunks_are_one_ip_each():
    chunks = chunk_targets(['10.0.0.1', '10.0.0.2', '10.0.0.3'], 1)
    assert chunks == [['10.0.0.1'], ['10.0.0.2'], ['10.0.0.3']]


def _probe_with(*, temp=55.0, cpu_pct=30.0, load=1.0, mem=8.0):
    with (
        patch('agent.capacity._cpu_count', return_value=12),
        patch('agent.capacity._read_cpu_temp_c', return_value=temp),
        patch('agent.capacity._cpu_percent_sample', return_value=cpu_pct),
        patch('agent.capacity._read_loadavg', return_value=load),
        patch('agent.capacity._mem_available_gb', return_value=mem),
    ):
        return probe_laptop_capacity(force=True)


def test_cool_host_scales_above_floor(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    plan = _probe_with()
    assert plan['thermal_state'] == 'cool'
    assert plan['semaphore_limit'] == 8
    assert plan['semaphore_limit'] >= IP_WORKERS_MIN
    assert plan['admission_paused'] is False


def test_hot_host_keeps_five_worker_floor(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    plan = _probe_with(temp=86.0)
    assert plan['thermal_state'] == 'hot'
    assert plan['ip_workers'] == 5
    assert plan['max_concurrent_jobs'] == 1
    assert plan['admission_paused'] is False


def test_critical_host_pauses_new_admission_not_floor(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    plan = _probe_with(temp=94.0)
    assert plan['thermal_state'] == 'critical'
    assert plan['semaphore_limit'] == 5
    assert plan['max_concurrent_jobs'] == 1
    assert plan['admission_paused'] is True


def test_high_load_uses_floor_or_pause(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '10')
    plan = _probe_with(load=15.0)
    assert plan['ip_workers'] >= 5
