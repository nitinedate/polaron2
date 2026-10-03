"""Local Greenbone GMP client for the Aetheris laptop scanner agent."""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

log = logging.getLogger("scanner_agent.gmp")

FULL_AND_FAST_ID = "daba56c8-73ec-11df-a475-002264764cea"

# Fast profile: common services. Omit 8000/8008/8081/8888 — Full-and-fast web NVTs
# (path traversal, win.ini probes) stall the last few percent for a long time.
FAST_PORTS = (
    "T:21-23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,631,993,995,"
    "1433,1521,1723,2049,3000,3306,3389,5432,5672,5900,5985,6379,6443,"
    "8080,8443,9000,9418,27017"
)

def _report_filter_string(*, first: int | None = None, rows: int | None = None) -> str:
    """Fetch Greenbone results. Default is the full set (rows=-1)."""
    raw = (os.environ.get("GVM_REPORT_MIN_QOD") or "0").strip()
    try:
        min_qod = int(raw)
    except (TypeError, ValueError):
        min_qod = 0
    min_qod = max(0, min(100, min_qod))
    parts: list[str] = []
    if first is not None:
        parts.append(f"first={max(1, int(first))}")
    if rows is not None:
        parts.append(f"rows={int(rows)}")
    elif first is None:
        parts.append("rows=-1")
    parts.append(f"min_qod={min_qod}")
    return " ".join(parts)


def _gmp_connection_lost(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "remote closed",
            "connection reset",
            "broken pipe",
            "timed out",
            "timeout",
            "socket is closed",
            "not connected",
        )
    )


def _gmp_timeout() -> float:
    try:
        return max(30.0, float(os.environ.get("GVM_GMP_TIMEOUT") or 300))
    except (TypeError, ValueError):
        return 300.0


def _report_page_rows() -> int:
    try:
        return max(50, int(os.environ.get("GVM_REPORT_PAGE_ROWS") or 200))
    except (TypeError, ValueError):
        return 200


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _canonical_severity(threat: str | None, cvss: float) -> str:
    """Never let a legacy Greenbone threat label downgrade a CVSS severity.

    Some report variants expose ``threat=Log/Info`` while retaining a non-zero
    numeric result severity.  Other variants use the broad legacy ``High`` band
    for CVSS 9.x.  Take the most severe trustworthy signal instead of trusting
    either field alone.
    """
    cvss_sev = _severity_from_cvss(cvss)
    raw = str(threat or "").strip().lower()
    if raw in {"log", "debug"}:
        raw = "info"
    threat_sev = raw if raw in _SEVERITY_RANK else "info"
    return cvss_sev if _SEVERITY_RANK[cvss_sev] >= _SEVERITY_RANK[threat_sev] else threat_sev


def _xml_result_nodes(report: Any) -> list[Any]:
    try:
        return list(report.xpath(".//results/result"))
    except Exception:
        return []


def _feed_count_from_xml(response: Any) -> int | None:
    """Best-effort total NVT count from GMP response metadata.

    Greenbone versions expose the count in slightly different shapes.  Returning
    None means "count unavailable", not zero.
    """
    if response is None or not hasattr(response, "xpath"):
        return None
    paths = (
        ".//nvt_count/filtered/text()",
        ".//nvt_count/total/text()",
        ".//nvt_count/text()",
        ".//config/nvt_count/text()",
    )
    values: list[int] = []
    for xpath in paths:
        try:
            for raw in response.xpath(xpath):
                try:
                    values.append(int(str(raw).strip()))
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
    return max(values) if values else None


def _feed_health(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    """Return conservative Greenbone feed/config health evidence."""
    syncing = False
    versions: list[str] = []
    try:
        feeds = gmp.get_feeds()
        if hasattr(feeds, "xpath"):
            syncing = any(
                str(x or "").strip().lower() in {"1", "true", "yes"}
                for x in feeds.xpath(".//currently_syncing/text()")
            )
            versions = [str(v).strip() for v in feeds.xpath(".//feed/version/text()") if str(v).strip()]
    except Exception:
        log.debug("Unable to read Greenbone feed metadata", exc_info=True)

    nvt_count: int | None = None
    try:
        resp = gmp.get_nvts(filter_string="rows=1 first=1")
        nvt_count = _feed_count_from_xml(resp)
        # If count metadata is absent, at least prove that one NVT exists.
        if nvt_count is None and hasattr(resp, "xpath") and resp.xpath(".//nvt"):
            nvt_count = -1  # present, total unknown
    except Exception:
        log.debug("Unable to read Greenbone NVT inventory", exc_info=True)

    config_nvt_count: int | None = None
    if config_id:
        getter = getattr(gmp, "get_scan_config", None)
        if callable(getter):
            try:
                config_nvt_count = _feed_count_from_xml(getter(config_id))
            except Exception:
                log.debug("Unable to read scan-config NVT count", exc_info=True)

    return {
        "syncing": syncing,
        "versions": versions,
        "nvt_count": nvt_count,
        "config_nvt_count": config_nvt_count,
    }


def _assert_feed_quality(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    health = _feed_health(gmp, config_id)
    if health["syncing"]:
        raise RuntimeError("Greenbone feed is still synchronizing; refusing to start a partial-quality scan")
    try:
        minimum = max(1, int(os.environ.get("GVM_MIN_NVT_COUNT") or 10000))
    except (TypeError, ValueError):
        minimum = 10000
    for label in ("nvt_count", "config_nvt_count"):
        count = health.get(label)
        if isinstance(count, int) and count >= 0 and count < minimum:
            raise RuntimeError(
                f"Greenbone {label}={count} is below required minimum {minimum}; "
                "feed/config import is incomplete, so the scanner will not claim the job"
            )
    if health.get("nvt_count") is None:
        log.warning("Greenbone NVT total count is unavailable; continuing because feed sync is not active")
    return health



def _imports():
    from gvm.connections import TLSConnection, UnixSocketConnection

    try:
        from gvm.protocols.gmp import GMP
    except ImportError:
        from gvm.protocols.gmp import Gmp as GMP  # type: ignore

    try:
        from gvm.transforms import EtreeCheckCommandTransform

        transform = EtreeCheckCommandTransform()
    except ImportError:
        from gvm.transforms import EtreeTransform

        transform = EtreeTransform()

    return TLSConnection, UnixSocketConnection, GMP, transform


@contextmanager
def _session(
    *,
    socket_path: str | None,
    host: str,
    port: int,
    username: str,
    password: str,
    verify: bool = False,
) -> Iterator[Any]:
    TLSConnection, UnixSocketConnection, GMP, transform = _imports()
    timeout = _gmp_timeout()
    if socket_path:
        try:
            conn = UnixSocketConnection(path=socket_path, timeout=timeout)
        except TypeError:
            conn = UnixSocketConnection(path=socket_path)
    else:
        conn = TLSConnection(hostname=host, port=port, timeout=timeout, verify=verify)

    # python-gvm manages connect/disconnect at the GMP protocol layer.
    # UnixSocketConnection itself is not a context manager in current 26.x.
    with GMP(connection=conn, transform=transform) as gmp:
        gmp.authenticate(username, password)
        yield gmp


def _find_config_id(gmp: Any, name: str = "Full and fast") -> str:
    resp = gmp.get_scan_configs()
    available: list[str] = []
    wanted = name.strip().casefold()
    for node in resp.xpath("config"):
        cid = (node.get("id") or "").strip()
        config_name = (node.findtext("name") or "").strip()
        if config_name:
            available.append(config_name)
        if cid and (config_name.casefold() == wanted or cid == FULL_AND_FAST_ID):
            return cid
    summary = ", ".join(available[:8]) if available else "none"
    raise RuntimeError(
        f"Scan config not found: {name}. Available configs: {summary}. "
        "Greenbone feed data is still loading or the Feed Import Owner/data-object rebuild is missing."
    )


def _find_scanner_id(gmp: Any) -> str:
    resp = gmp.get_scanners()
    for node in resp.xpath("scanner"):
        n = (node.findtext("name") or "").lower()
        if "openvas" in n or "default" in n:
            sid = node.get("id")
            if sid:
                return str(sid)
    node = resp.find("scanner")
    if node is not None and node.get("id"):
        return str(node.get("id"))
    raise RuntimeError("No OpenVAS scanner found in Greenbone")


def _ospd_feed_ready(gmp: Any) -> bool:
    """True when OSPd has published an NVT feed version (scans can actually run)."""
    try:
        resp = gmp.get_feeds()
        syncing = []
        versions = []
        if hasattr(resp, "xpath"):
            syncing = resp.xpath(".//currently_syncing")
            versions = [str(v).strip() for v in resp.xpath(".//feed/version/text()") if str(v).strip()]
        if syncing:
            return False
        if versions:
            return True
    except Exception:
        pass
    try:
        nvts = gmp.get_nvts(filter_string="rows=1 first=1")
        if hasattr(nvts, "xpath") and nvts.xpath(".//nvt"):
            return True
        if hasattr(nvts, "xpath"):
            return False
    except Exception:
        pass
    return True


def _task_status(gmp: Any, task_id: str) -> tuple[str, float, Any]:
    resp = gmp.get_task(task_id)
    task = resp.find("task")
    if task is None:
        nodes = resp.xpath(".//task")
        task = nodes[0] if nodes else None
    if task is None:
        return "unknown", 0.0, None
    status = (task.findtext("status") or "unknown").strip().lower()
    try:
        progress = float(task.findtext("progress") or 0)
    except (TypeError, ValueError):
        progress = 0.0
    return status, progress, task


def _split_host_list(text: str | None) -> list[str]:
    hosts: list[str] = []
    for raw in str(text or "").replace("\n", ",").split(","):
        host = raw.strip()
        if host:
            hosts.append(host)
    return hosts


def _hosts_from_target_elem(target: Any) -> list[str]:
    if target is None:
        return []
    for xpath in ("hosts", "hosts/host", "ip"):
        text = target.findtext(xpath) if hasattr(target, "findtext") else None
        hosts = _split_host_list(text)
        if hosts:
            return hosts
    return _split_host_list(target.findtext("hosts") if hasattr(target, "findtext") else None)


def _hosts_from_task_elem(task: Any) -> list[str]:
    if task is None:
        return []
    target = task.find("target") if hasattr(task, "find") else None
    hosts = _hosts_from_target_elem(target)
    if hosts:
        return hosts
    return _split_host_list(task.findtext("hosts") if hasattr(task, "findtext") else None)


def _task_report_id(task: Any) -> str | None:
    if task is None:
        return None
    for xpath in ("current_report/report", "last_report/report"):
        elem = task.find(xpath)
        if elem is not None and elem.get("id"):
            return str(elem.get("id"))
    return None


def _inner_report(response: Any) -> Any:
    """Return the report element that contains scan/host/result evidence."""
    candidates = response.xpath(".//report") if hasattr(response, "xpath") else []
    for node in candidates:
        if (
            node.find("scan_run_status") is not None
            or node.find("hosts") is not None
            or node.find("results") is not None
            or node.find("scan_start") is not None
        ):
            return node
    return candidates[-1] if candidates else response


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _text_values(node: Any, xpath: str) -> list[str]:
    try:
        values = node.xpath(xpath)
    except Exception:
        return []
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            out.append(text)
    return out


def _plugin_error_details(report: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    """Extract structured Greenbone report error records for audit/reporting."""
    try:
        nodes = report.xpath("./errors/error")
        if not nodes:
            nodes = report.xpath(".//errors/error")
    except Exception:
        nodes = []

    details: list[dict[str, Any]] = []
    for err in nodes[: max(0, limit)]:
        nvt = err.find("nvt")
        host = (err.findtext("host") or "").strip() or None
        port = (err.findtext("port") or "").strip() or None
        description = (err.findtext("description") or "").strip()
        severity = (err.findtext("severity") or "").strip() or None
        nvt_oid = (nvt.get("oid") or "").strip() if nvt is not None else ""
        nvt_name = (nvt.findtext("name") or "").strip() if nvt is not None else ""
        if not nvt_name:
            nvt_name = (err.findtext("name") or "").strip()
        details.append(
            {
                "host": host,
                "port": port,
                "nvt_oid": nvt_oid or None,
                "nvt_name": nvt_name or None,
                "severity": severity,
                "description": description[:2000] if description else None,
            }
        )
    return details


def _report_evidence_from_xml(
    response: Any,
    *,
    report_id: str,
    task_status: str,
    progress: float,
    expected_targets: list[str],
    alive_test: str,
) -> dict[str, Any]:
    report = _inner_report(response)

    # Greenbone native XML contains direct report/host/ip and host_start/host /
    # host_end/host nodes for hosts that actually entered the scan. Result host
    # values are included as an additional source, but are not required for a
    # clean host because a successfully assessed host may have zero actionable
    # findings.
    host_ips = set(_text_values(report, "./host/ip/text()"))
    host_ips.update(_text_values(report, "./host_start/host/text()"))
    host_ips.update(_text_values(report, "./host_end/host/text()"))
    host_ips.update(_text_values(report, ".//results/result/host/text()"))
    host_ips.update(_text_values(report, ".//host/ip/text()"))
    # Some Greenbone builds stash the address on host/@ip or asset attributes.
    try:
        for node in report.xpath(".//host"):
            for attr in ("ip", "host"):
                val = (node.get(attr) or "").strip()
                if val:
                    host_ips.add(val)
            asset = node.find("asset")
            if asset is not None:
                for attr in ("asset_id", "id"):
                    val = (asset.get(attr) or "").strip()
                    if val and val.replace(".", "").isdigit() is False and ":" not in val:
                        continue
                    if val:
                        host_ips.add(val)
    except Exception:
        pass
    host_ips = {h.strip() for h in host_ips if h and str(h).strip()}

    host_count = _as_int(report.findtext("hosts/count"), len(host_ips))
    hosts_assessed = max(host_count, len(host_ips))
    result_nodes = _xml_result_nodes(report)
    materialized_result_count = len(result_nodes)
    full_result_count = _as_int(report.findtext("result_count/full"), -1)
    filtered_result_count = _as_int(report.findtext("result_count/filtered"), -1)
    legacy_result_count = _as_int(report.findtext("result_count"), -1)

    # GMP's <full> count is the number before the report filter is applied.
    # The <filtered> count describes the rows returned under <results>.  Using
    # <full> as the upload count produced false failures such as full=36 while
    # filtered/materialized/parsed=35.  The materialized count remains the
    # authoritative upload-integrity boundary when filtered metadata is absent.
    if filtered_result_count >= 0:
        result_count = filtered_result_count
    elif materialized_result_count > 0:
        result_count = materialized_result_count
    elif legacy_result_count >= 0:
        result_count = legacy_result_count
    else:
        result_count = 0
    plugin_error_details = _plugin_error_details(report)
    plugin_errors = max(_as_int(report.findtext("errors/count"), 0), len(plugin_error_details))
    scan_start = (report.findtext("scan_start") or "").strip() or None
    scan_end = (report.findtext("scan_end") or "").strip() or None
    run_status = (report.findtext("scan_run_status") or task_status or "").strip()

    targets = [str(t).strip() for t in expected_targets if str(t).strip()]
    target_count = len(targets)
    report_has_host_evidence = bool(host_ips)

    # For literal IP targets, require identity evidence from the report, not just
    # a host count.  This prevents a different/resolved host from satisfying the
    # coverage gate.  Hostnames and network expressions still require host
    # evidence/count, but their identity is not guessed here.
    import ipaddress

    literal_ip_targets: list[str] = []
    for target in targets:
        try:
            literal_ip_targets.append(str(ipaddress.ip_address(target)))
        except ValueError:
            pass
    normalized_hosts: set[str] = set()
    for host in host_ips:
        try:
            normalized_hosts.add(str(ipaddress.ip_address(host)))
        except ValueError:
            normalized_hosts.add(host.casefold())
    missing_ip_targets = [t for t in literal_ip_targets if t not in normalized_hosts]
    assessed_expected = [t for t in literal_ip_targets if t in normalized_hosts]
    # Wrong-host guard: at least one expected literal IP must appear. Hosts
    # OpenVAS did not find alive stay in missing_ip_targets for skip accounting.
    target_identity_ok = not literal_ip_targets or bool(assessed_expected)

    timestamps_ok = bool(scan_start and scan_end)
    plugin_health_ok = plugin_errors == 0

    # Completion/coverage and scanner warnings are different concepts.
    # Greenbone report <errors> entries are per-VT/scanner errors and can
    # coexist with a successfully completed task and full host coverage.
    # They must prevent a *clean* conclusion, but must not turn a fully
    # assessed host into a failed scan.
    #
    # OpenVAS "1 alive hosts of 2" is the same: the missing IP was not alive.
    # Require the assessed IPs to be expected targets, not that every expected
    # IP appears in the report.
    assessment_complete = (
        task_status in {"done", "finished", "succeeded"}
        and bool(report_id)
        and report_has_host_evidence
        and timestamps_ok
        and (
            (bool(literal_ip_targets) and bool(assessed_expected))
            or (not literal_ip_targets and target_count > 0 and hosts_assessed >= 1)
        )
    )
    clean_eligible = bool(assessment_complete and plugin_health_ok and not missing_ip_targets)

    if assessment_complete and plugin_errors > 0:
        verdict = "assessed_with_warnings"
        log.warning(
            "OpenVAS report %s completed target coverage with %d plugin/scanner error(s); "
            "marking completed-with-warnings (not clean-eligible)",
            report_id,
            plugin_errors,
        )
    elif assessment_complete and missing_ip_targets:
        verdict = "assessed_with_unreachable_skips"
    elif assessment_complete:
        verdict = "assessed"
    elif not report_id:
        verdict = "no_report"
    elif not report_has_host_evidence:
        verdict = "no_host_evidence"
    elif missing_ip_targets:
        verdict = "target_not_in_report"
    elif hosts_assessed < target_count:
        verdict = "partial_coverage"
    elif not timestamps_ok:
        verdict = "missing_scan_timestamps"
    else:
        verdict = "unverified"

    return {
        "report_id": report_id,
        "task_status": task_status,
        "scan_run_status": run_status,
        "progress": progress,
        "hosts_attempted": target_count,
        "hosts_assessed": hosts_assessed,
        "assessed_hosts": sorted(host_ips),
        "missing_ip_targets": missing_ip_targets,
        "target_identity_ok": target_identity_ok,
        "report_result_count": result_count,
        "report_result_count_full": full_result_count,
        "report_result_count_filtered": filtered_result_count,
        "report_materialized_result_count": materialized_result_count,
        "plugin_error_count": plugin_errors,
        "plugin_error_details": plugin_error_details,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "assessment_complete": assessment_complete,
        "assessment_verdict": verdict,
        "plugin_health_ok": plugin_health_ok,
        "clean_eligible": clean_eligible,
        "alive_test": alive_test,
    }


def _vulnerabilities_from_report(response: Any) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for res in response.xpath(".//results/result"):
        nvt = res.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid") or ""
        name = nvt.findtext("name") or res.findtext("name") or ""
        family = nvt.findtext("family") or ""
        try:
            cvss = float(nvt.findtext("cvss_base") or res.findtext("severity") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        cve = None
        for ref in nvt.xpath("refs/ref"):
            if (ref.get("type") or "").lower() == "cve":
                cve = ref.get("id")
                break
        port_raw = res.findtext("port") or ""
        port = None
        protocol = None
        if "/" in port_raw:
            port_part, protocol = port_raw.split("/", 1)
            try:
                port = int(port_part)
            except ValueError:
                port = None
        threat = (res.findtext("threat") or "").lower()
        tags_raw = nvt.findtext("tags") or ""
        tag_values: dict[str, str] = {}
        for part in tags_raw.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value and key not in tag_values:
                tag_values[key] = value
        qod_raw = res.findtext("qod/value") or res.findtext("qod") or ""
        try:
            qod = float(qod_raw) if str(qod_raw).strip() else None
        except (TypeError, ValueError):
            qod = None
        qod_type = (res.findtext("qod/type") or "").strip() or None
        severity = _canonical_severity(threat, cvss)
        vulns.append(
            {
                "source_result_id": (res.get("id") or "").strip() or None,
                "result_id": (res.get("id") or "").strip() or None,
                "plugin_id": oid,
                "nvt_oid": oid,
                "plugin_family": family,
                "cve": cve,
                "score": cvss,
                "cvss": cvss,
                "severity": severity,
                "qod": qod,
                "qod_type": qod_type,
                "plugin_name": name,
                "description": res.findtext("description") or tag_values.get("insight") or tag_values.get("summary") or "",
                "synopsis": tag_values.get("summary") or name,
                "solution": tag_values.get("solution") or "",
                "port": port,
                "protocol": protocol,
                "host": res.findtext("host") or None,
            }
        )
    return vulns


def _get_report_once(gmp: Any, report_id: str, **kwargs: Any) -> Any:
    return gmp.get_report(report_id=report_id, **kwargs)


def _harvest_report_xml(gmp: Any, report_id: str) -> tuple[Any | None, list[dict[str, Any]], Exception | None]:
    """Load a Greenbone report without assuming one giant GMP reply.

    gvmd often closes the Unix socket when ``details=True`` + ``rows=-1`` is
    asked in one shot after a long scan. Metadata first, then paged results,
    then a full dump as last resort.
    """
    last_exc: Exception | None = None
    page_rows = _report_page_rows()

    meta = None
    for details, filt in (
        (False, _report_filter_string(first=1, rows=1)),
        (False, _report_filter_string(first=1, rows=10)),
    ):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=filt,
                ignore_pagination=False,
                details=details,
            )
            last_exc = None
            log.info("OpenVAS report %s metadata ok details=%s filter=%s", report_id, details, filt)
            break
        except Exception as exc:
            last_exc = exc
            log.warning(
                "get_report(%s) metadata details=%s filter=%s failed: %s",
                report_id,
                details,
                filt,
                exc,
            )
            if _gmp_connection_lost(exc):
                return None, [], last_exc

    vulns: list[dict[str, Any]] = []
    first = 1
    pages = 0
    while True:
        filt = _report_filter_string(first=first, rows=page_rows)
        chunk = None
        for details in (True, False):
            try:
                chunk = _get_report_once(
                    gmp,
                    report_id,
                    filter_string=filt,
                    ignore_pagination=False,
                    details=details,
                )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "get_report(%s, details=%s, first=%s) failed: %s",
                    report_id,
                    details,
                    first,
                    exc,
                )
                if _gmp_connection_lost(exc):
                    break
        if chunk is None:
            break
        if meta is None:
            meta = chunk
        try:
            page_vulns = _vulnerabilities_from_report(chunk)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities page first=%s: %s", first, exc)
            page_vulns = []
        vulns.extend(page_vulns)
        nodes = _xml_result_nodes(_inner_report(chunk))
        pages += 1
        if len(nodes) < page_rows:
            break
        first += page_rows
        if pages >= 500:
            log.warning("OpenVAS report %s page cap reached (%s pages)", report_id, pages)
            break

    if meta is None and pages == 0 and not (last_exc and _gmp_connection_lost(last_exc)):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=_report_filter_string(first=1, rows=page_rows),
                ignore_pagination=False,
                details=False,
            )
            last_exc = None
            vulns = _vulnerabilities_from_report(meta)
        except Exception as exc:
            last_exc = exc
            log.warning("get_report(%s) compact dump failed: %s", report_id, exc)

    return meta, vulns, last_exc


def _report_payload(
    gmp: Any,
    task_id: str,
    *,
    expected_targets: list[str],
    alive_test: str,
    task_status: str,
    progress: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _, _, task = _task_status(gmp, task_id)
    report_id = _task_report_id(task)
    if not report_id:
        evidence = {
            "report_id": None,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "no_report",
            "alive_test": alive_test,
        }
        return [], evidence

    response, paged_vulns, last_exc = _harvest_report_xml(gmp, report_id)
    if response is None:
        evidence = {
            "report_id": report_id,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "report_read_error",
            "alive_test": alive_test,
            "report_read_error": str(last_exc)[:1000] if last_exc else "get_report failed",
        }
        return [], evidence

    evidence = _report_evidence_from_xml(
        response,
        report_id=report_id,
        task_status=task_status,
        progress=progress,
        expected_targets=expected_targets,
        alive_test=alive_test,
    )
    vulns = paged_vulns
    if not vulns:
        try:
            vulns = _vulnerabilities_from_report(response)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities for report %s: %s", report_id, exc)
            vulns = []
            evidence["report_read_error"] = (
                ((evidence.get("report_read_error") or "") + f"; vuln_parse: {exc}")[:1000]
            )

    declared = int(evidence.get("report_result_count") or 0)
    full = int(evidence.get("report_result_count_full", -1))
    filtered = int(evidence.get("report_result_count_filtered", -1))
    materialized = int(evidence.get("report_materialized_result_count") or 0)
    parsed = len(vulns)
    if parsed and (materialized == 0 or materialized < parsed):
        evidence["report_materialized_result_count"] = parsed
        evidence["report_result_count"] = parsed
        materialized = parsed
        declared = parsed
    histogram: dict[str, int] = {}
    for row in vulns:
        sev = str(row.get("severity") or "info").lower()
        histogram[sev] = histogram.get(sev, 0) + 1
    log.info(
        "OpenVAS report %s result integrity full=%d filtered=%d materialized=%d parsed=%d severity=%s",
        report_id, full, filtered, materialized, parsed, histogram,
    )
    mismatch = ""
    # Paged harvest often returns fewer <results> in the metadata XML than the
    # combined pages. Do not fail coverage for that.
    if parsed > 0 and materialized == parsed:
        mismatch = ""
    elif filtered >= 0 and filtered != materialized and parsed == 0:
        mismatch = (
            f"filtered_result_count_mismatch filtered={filtered} "
            f"materialized={materialized}"
        )
    elif materialized != parsed:
        mismatch = f"parser_result_count_mismatch materialized={materialized} parsed={parsed}"
    elif declared != parsed:
        mismatch = f"result_count_mismatch returned={declared} parsed={parsed}"
    if mismatch:
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + mismatch)[:1000]
        )
        evidence["assessment_complete"] = False
        evidence["assessment_verdict"] = "result_count_mismatch"
    elif last_exc and (parsed == 0 or (filtered >= 0 and parsed < filtered)):
        err = str(last_exc)[:1000]
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + err)[:1000]
        )
    extra_hosts = {
        str(row.get("host") or "").strip()
        for row in vulns
        if str(row.get("host") or "").strip()
    }
    if extra_hosts:
        assessed = {str(h).strip() for h in (evidence.get("assessed_hosts") or []) if str(h).strip()}
        assessed.update(extra_hosts)
        evidence["assessed_hosts"] = sorted(assessed)
        evidence["hosts_assessed"] = max(int(evidence.get("hosts_assessed") or 0), len(assessed))
    return vulns, evidence


class LocalOpenVAS:
    def __init__(self) -> None:
        self.socket_path = (os.environ.get("GVM_SOCKET_PATH") or "").strip() or None
        url = (os.environ.get("GVM_URL") or "").strip()
        self.host, self.port = "127.0.0.1", 9390
        if url and not self.socket_path:
            if "://" not in url:
                url = f"tls://{url}"
            parsed = urlparse(url)
            self.host = parsed.hostname or "127.0.0.1"
            self.port = parsed.port or 9390
            if parsed.scheme == "unix":
                self.socket_path = parsed.path or None
        self.username = os.environ.get("GVM_USERNAME") or "admin"
        self.password = os.environ.get("GVM_PASSWORD") or "admin"
        self.port_profile = (os.environ.get("PORT_PROFILE") or "full").strip().lower()
        plugins_raw = int(os.environ.get("PLUGINS_TIMEOUT_SEC") or 0)
        scanner_raw = int(os.environ.get("SCANNER_PLUGINS_TIMEOUT_SEC") or 0)
        self.plugins_timeout = 86400 * 30 if plugins_raw <= 0 else max(30, plugins_raw)
        self.scanner_plugins_timeout = 86400 * 30 if scanner_raw <= 0 else max(self.plugins_timeout, scanner_raw)
        self.max_checks = max(1, int(os.environ.get("GVM_MAX_CHECKS") or 12))
        self.max_hosts = max(1, int(os.environ.get("GVM_MAX_HOSTS") or 4))
        self.checks_read_timeout = max(1, int(os.environ.get("GVM_CHECKS_READ_TIMEOUT") or 10))
        self.timeout_retry = max(0, int(os.environ.get("GVM_TIMEOUT_RETRY") or 3))
        self.open_sock_max_attempts = max(
            1, int(os.environ.get("GVM_OPEN_SOCK_MAX_ATTEMPTS") or 5)
        )
        self.scan_config_name = (os.environ.get("GVM_SCAN_CONFIG") or "Full and fast").strip()
        full_assessment = self.port_profile == "full"
        self.optimize_test = (
            os.environ.get("GVM_OPTIMIZE_TEST") or ("no" if full_assessment else "yes")
        ).strip().lower()
        # Use current OpenVAS scanner preference names.  A previous build sent
        # `thorough_tests`, which is not a current scanner preference and can
        # make gvmd reject the entire preference payload on some releases.
        self.safe_checks = (os.environ.get("GVM_SAFE_CHECKS") or "yes").strip().lower()
        self.expand_vhosts = (os.environ.get("GVM_EXPAND_VHOSTS") or "yes").strip().lower()
        self.test_empty_vhost = (os.environ.get("GVM_TEST_EMPTY_VHOST") or "yes").strip().lower()
        self.allow_bare_task_fallback = (
            os.environ.get("GVM_ALLOW_BARE_TASK_FALLBACK") or "false"
        ).strip().lower() in {"1", "true", "yes", "on"}
        # Explicitly authorized single-host scans must not be silently skipped
        # merely because ICMP/TCP discovery is blocked. python-gvm create_target
        # accepts the literal GMP alive-test string "Consider Alive".
        self.alive_test = (os.environ.get("GVM_ALIVE_TEST") or "Consider Alive").strip()
        self._next_not_ready_log = 0.0

    def ready(self) -> bool:
        sock = (self.socket_path or "").strip()
        if sock and not os.path.exists(sock):
            self._log_not_ready("GMP socket not present yet (%s) — waiting for gvmd" % sock)
            return False
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _find_scanner_id(gmp)
                config_id = _find_config_id(gmp, self.scan_config_name)
                if not _ospd_feed_ready(gmp):
                    self._log_not_ready(
                        "OSPd OpenVAS feed is still loading — not claiming jobs yet"
                    )
                    return False
                _assert_feed_quality(gmp, config_id)
            return True
        except Exception as exc:
            self._log_not_ready("Local OpenVAS not ready: %s" % exc)
            return False

    def _log_not_ready(self, message: str) -> None:
        now = time.monotonic()
        if now < self._next_not_ready_log:
            return
        log.warning("%s", message)
        self._next_not_ready_log = now + 60.0

    def start_scan(self, *, name: str, targets: list[str]) -> str:
        host_list = [t.strip() for t in targets if t and t.strip()]
        if not host_list:
            raise ValueError("At least one target is required")
        port_range = FAST_PORTS if self.port_profile != "full" else "T:1-65535"
        try:
            from agent.control_plane import port_range_without_control_plane

            adjusted = port_range_without_control_plane(port_range, host_list)
            if adjusted != port_range:
                log.info("OpenVAS port_range excludes Aetheris control-plane HTTP ports")
                port_range = adjusted
        except Exception:
            log.debug("Control-plane port exclusion skipped", exc_info=True)
        with _session(
            socket_path=self.socket_path,
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
        ) as gmp:
            config_id = _find_config_id(gmp, self.scan_config_name)
            _assert_feed_quality(gmp, config_id)
            scanner_id = _find_scanner_id(gmp)
            target = gmp.create_target(
                name=f"{name}-tgt-{int(time.time())}",
                hosts=host_list,
                port_range=port_range,
                alive_test=self.alive_test,
            )
            target_id = target.get("id")
            if not target_id:
                raise RuntimeError("Failed to create Greenbone target")
            # These names are current OpenVAS scanner preferences.  Do not
            # send legacy/non-scanner keys: one rejected key can cause the
            # whole task preference payload to be rejected.
            prefs = {
                "max_checks": str(self.max_checks),
                "max_hosts": str(self.max_hosts),
                "checks_read_timeout": str(self.checks_read_timeout),
                "timeout_retry": str(self.timeout_retry),
                "open_sock_max_attempts": str(self.open_sock_max_attempts),
                "optimize_test": self.optimize_test,
                "safe_checks": self.safe_checks,
                "plugins_timeout": str(self.plugins_timeout),
                "scanner_plugins_timeout": str(self.scanner_plugins_timeout),
                "expand_vhosts": self.expand_vhosts,
                "test_empty_vhost": self.test_empty_vhost,
                "report_host_details": "yes",
            }
            log.info(
                "OpenVAS quality profile max_checks=%s max_hosts=%s "
                "checks_read_timeout=%ss timeout_retry=%s open_sock_max_attempts=%s "
                "plugins_timeout=%ss scanner_plugins_timeout=%ss optimize_test=%s "
                "safe_checks=%s expand_vhosts=%s test_empty_vhost=%s",
                self.max_checks,
                self.max_hosts,
                self.checks_read_timeout,
                self.timeout_retry,
                self.open_sock_max_attempts,
                self.plugins_timeout,
                self.scanner_plugins_timeout,
                self.optimize_test,
                self.safe_checks,
                self.expand_vhosts,
                self.test_empty_vhost,
            )
            try:
                task = gmp.create_task(
                    name=name[:128],
                    config_id=config_id,
                    target_id=str(target_id),
                    scanner_id=scanner_id,
                    preferences=prefs,
                )
            except Exception as pref_exc:
                # Retry once with the smallest quality-critical preference set.
                # Do not silently fall back to a bare task: that can change
                # optimize/thorough behavior and produce a misleadingly shallow
                # report that still reaches 100%.
                minimal_prefs = {
                    "max_checks": str(self.max_checks),
                    "max_hosts": str(self.max_hosts),
                    "optimize_test": self.optimize_test,
                    "safe_checks": self.safe_checks,
                }
                log.warning(
                    "create_task full preferences failed (%s); retrying quality-critical preferences",
                    pref_exc,
                )
                try:
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                        preferences=minimal_prefs,
                    )
                except Exception as minimal_exc:
                    if not self.allow_bare_task_fallback:
                        raise RuntimeError(
                            "Greenbone rejected required task quality preferences; refusing a bare/degraded scan. "
                            "Set GVM_ALLOW_BARE_TASK_FALLBACK=true only for diagnostic compatibility."
                        ) from minimal_exc
                    log.error(
                        "DEGRADED SCAN: Greenbone rejected task preferences (%s); bare fallback explicitly enabled",
                        minimal_exc,
                    )
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                    )
            task_id = task.get("id")
            if not task_id:
                raise RuntimeError("Failed to create Greenbone task")
            start_response = gmp.start_task(str(task_id))
            report_id = None
            try:
                report_id = start_response.findtext("report_id") or (
                    start_response[0].text if len(start_response) else None
                )
            except Exception:
                report_id = None
            log.info(
                "Started local OpenVAS task %s report=%s hosts=%s alive_test=%s",
                task_id,
                report_id,
                host_list,
                self.alive_test,
            )
            return str(task_id)

    def get_task_hosts(self, task_id: str) -> list[str] | None:
        """Return the hosts bound to an OpenVAS task, or None if unverifiable.

        None means the task is missing or GMP did not return a host list. Callers
        must not guess by chunk index — that is how one network's IPs get
        attached to another job.
        """
        tid = str(task_id or "").strip()
        if not tid:
            return None
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _, _, task = _task_status(gmp, tid)
                if task is None:
                    return None
                hosts = _hosts_from_task_elem(task)
                if hosts:
                    return hosts
                target = task.find("target") if hasattr(task, "find") else None
                target_id = (target.get("id") if target is not None else None) or None
                if not target_id:
                    return None
                try:
                    tresp = gmp.get_target(str(target_id))
                except Exception:
                    tresp = gmp.get_targets(filter_string=f"uuid={target_id}")
                tnode = tresp.find("target") if hasattr(tresp, "find") else None
                if tnode is None and hasattr(tresp, "xpath"):
                    nodes = tresp.xpath(".//target")
                    tnode = nodes[0] if nodes else None
                hosts = _hosts_from_target_elem(tnode)
                return hosts or None
        except Exception as exc:
            msg = str(exc).lower()
            status = str(getattr(exc, "status", "") or "")
            if status == "404" or "failed to find task" in msg:
                log.info("OpenVAS task %s is gone; treating leftover id as stale", tid)
                return []
            log.warning("Could not read hosts for OpenVAS task %s", tid, exc_info=True)
            return None

    def _session_kwargs(self) -> dict[str, Any]:
        return {
            "socket_path": self.socket_path,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }

    def poll(self, task_id: str, *, expected_targets: list[str] | None = None) -> dict[str, Any]:
        targets = [str(t).strip() for t in (expected_targets or []) if str(t).strip()]
        with _session(**self._session_kwargs()) as gmp:
            status, progress, _ = _task_status(gmp, task_id)
        mapped = "running"
        # Greenbone stays at ~99% with status Processing while it writes the
        # report. That is not a failure — wait for Done, then harvest.
        if status in {"done", "finished", "succeeded"}:
            mapped = "completed"
        elif status in {"stopped", "interrupted"}:
            mapped = "stopped"
        elif status in {"failed", "internal error", "delete requested"}:
            mapped = "failed"
        elif status == "processing":
            mapped = "running"
            progress = max(progress, 99.0)

        vulns: list[dict[str, Any]] = []
        evidence: dict[str, Any] = {
            "report_id": None,
            "task_status": status,
            "progress": progress,
            "hosts_attempted": len(targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "assessment_complete": False,
            "assessment_verdict": "not_finished" if mapped == "running" else "pending_report",
            "alive_test": self.alive_test,
        }
        if mapped in {"completed", "stopped", "failed"}:
            last_exc: Exception | None = None
            for attempt in range(8):
                try:
                    # Never reuse a GMP socket after get_report. gvmd closes it
                    # under large XML and every retry on that handle fails fast.
                    with _session(**self._session_kwargs()) as gmp:
                        vulns, evidence = _report_payload(
                            gmp,
                            task_id,
                            expected_targets=targets,
                            alive_test=self.alive_test,
                            task_status=status,
                            progress=progress,
                        )
                    last_exc = None
                except Exception as exc:
                    last_exc = exc
                    evidence["assessment_verdict"] = "report_read_error"
                    evidence["report_read_error"] = str(exc)[:1000]
                    log.warning("Could not read results/evidence for %s (attempt %s)", task_id, attempt + 1)
                filtered_n = int(evidence.get("report_result_count_filtered") or 0)
                incomplete_results = bool(evidence.get("report_read_error")) and (
                    not evidence.get("scan_start")
                    or (filtered_n > 0 and len(vulns) < filtered_n)
                )
                if evidence.get("report_id") and not incomplete_results and (
                    evidence.get("assessment_complete")
                    or not evidence.get("report_read_error")
                ):
                    break
                if mapped != "completed":
                    break
                time.sleep(min(8, 2 + attempt))
                try:
                    with _session(**self._session_kwargs()) as gmp:
                        status, progress, _ = _task_status(gmp, task_id)
                    if status in {"done", "finished", "succeeded"}:
                        mapped = "completed"
                except Exception:
                    log.warning("Could not refresh task status for %s after harvest retry", task_id)
            if last_exc and not evidence.get("report_id"):
                log.warning("Could not read results/evidence for %s", task_id, exc_info=True)

        return {
            "status": mapped,
            "gmp_status": status,
            "progress": progress,
            "vulnerabilities": vulns,
            "evidence": evidence,
        }

    def stop(self, task_id: str) -> None:
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                gmp.stop_task(task_id)
        except Exception:
            log.warning("stop_task failed for %s", task_id, exc_info=True)
