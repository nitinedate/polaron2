"""Read already-accessible Android private app/system files over ADB + existing su.

Forensic guardrails:
- Does not root, exploit, unlock, bypass a screen lock, or alter boot state.
- Runs only when ``su -c id`` already returns uid=0 (or adbd itself is uid=0).
- Reads files one-by-one with ``adb exec-out ... cat`` and writes them into the
  acquisition directory. No temporary files are created on the handset.
- Paths are allow-listed to known app/system evidence roots.

This module is used by the Windows host acquisition helper because ``adb pull
/data/data`` cannot use ``su`` on production Android builds even when a root
manager is already available to the examiner.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from app.services.mobile_acquire.app_catalog import ANDROID_SOCIAL_PACKAGES

# Native/system providers that contain high-value mobile artifacts.
SYSTEM_PRIVATE_ROOTS: tuple[str, ...] = (
    "/data/user_de/0/com.android.providers.telephony/databases",
    "/data/user/0/com.android.providers.telephony/databases",
    "/data/data/com.android.providers.telephony/databases",
    "/data/user_de/0/com.android.providers.contacts/databases",
    "/data/user/0/com.android.providers.contacts/databases",
    "/data/data/com.android.providers.contacts/databases",
    "/data/user_de/0/com.android.providers.calendar/databases",
    "/data/user/0/com.android.providers.calendar/databases",
    "/data/data/com.android.providers.calendar/databases",
    "/data/user_de/0/com.android.providers.media/databases",
    "/data/user/0/com.android.providers.media/databases",
    "/data/data/com.android.providers.media/databases",
    "/data/system/users",
    "/data/system_ce",
    "/data/system_de",
)

# Chromium private data is useful for browser history/downloads. Keep package
# roots explicit so this helper cannot become an arbitrary remote-file reader.
EXTRA_APP_PACKAGES: tuple[str, ...] = (
    "com.android.chrome",
    "com.sec.android.app.sbrowser",
    "org.mozilla.firefox",
    "com.brave.browser",
    "com.microsoft.emmx",
)


def _run(args: list[str], *, timeout: int = 30, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        text=not binary,
    )


def _adb_prefix(adb: str, serial: str) -> list[str]:
    return [adb] + (["-s", serial] if serial else [])


def _root_mode(adb: str, serial: str) -> str | None:
    prefix = _adb_prefix(adb, serial)
    try:
        direct = _run(prefix + ["shell", "id"], timeout=10)
        if "uid=0" in (direct.stdout or ""):
            return "adbd_root"
    except Exception:
        pass
    try:
        su = _run(prefix + ["shell", "su", "-c", "id"], timeout=12)
        if "uid=0" in (su.stdout or ""):
            return "su"
    except Exception:
        pass
    return None


def _remote_exists(adb: str, serial: str, mode: str, remote: str) -> bool:
    quoted = shlex.quote(remote)
    cmd = f"test -e {quoted} && echo EXISTS"
    args = _adb_prefix(adb, serial) + ["shell"]
    if mode == "su":
        args += ["su", "-c", cmd]
    else:
        args += ["sh", "-c", cmd]
    try:
        cp = _run(args, timeout=12)
        return "EXISTS" in (cp.stdout or "")
    except Exception:
        return False


def _list_files(adb: str, serial: str, mode: str, root: str) -> list[str]:
    quoted = shlex.quote(root)
    # newline-separated is safe for Android application paths in practice and
    # avoids host shell parsing. Only regular files are returned.
    cmd = f"find {quoted} -xdev -type f -print 2>/dev/null"
    args = _adb_prefix(adb, serial) + ["shell"]
    if mode == "su":
        args += ["su", "-c", cmd]
    else:
        args += ["sh", "-c", cmd]
    try:
        cp = _run(args, timeout=180)
    except Exception:
        return []
    return [line.strip().replace("\r", "") for line in (cp.stdout or "").splitlines() if line.strip().startswith("/")]


def _safe_rel(remote: str) -> Path:
    parts = [p for p in PurePosixPath(remote).parts if p not in {"/", "", ".", ".."}]
    return Path(*parts)


def _cat_file(adb: str, serial: str, mode: str, remote: str, dest: Path) -> tuple[bool, str]:
    quoted = shlex.quote(remote)
    args = _adb_prefix(adb, serial) + ["exec-out"]
    if mode == "su":
        args += ["su", "-c", f"cat {quoted}"]
    else:
        args += ["sh", "-c", f"cat {quoted}"]
    try:
        cp = _run(args, timeout=180, binary=True)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as exc:
        return False, str(exc)
    if cp.returncode != 0:
        err = (cp.stderr or b"").decode("utf-8", "replace")[:240]
        return False, err or f"exit {cp.returncode}"
    data = cp.stdout or b""
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.write_bytes(data)
    except OSError as exc:
        return False, str(exc)
    return True, ""


def _write_progress(path: str, payload: dict[str, Any]) -> None:
    if not path:
        return
    try:
        Path(path).write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _candidate_roots(packages: Iterable[str], include_system: bool) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for pkg in packages:
        pkg = (pkg or "").strip()
        if not pkg or not all(c.isalnum() or c in "._" for c in pkg):
            continue
        for root in (f"/data/user/0/{pkg}", f"/data/data/{pkg}"):
            if root not in seen:
                roots.append(root)
                seen.add(root)
    if include_system:
        for root in SYSTEM_PRIVATE_ROOTS:
            if root not in seen:
                roots.append(root)
                seen.add(root)
    return roots


def pull_private_evidence(
    *,
    adb: str,
    serial: str,
    out: Path,
    progress_file: str = "",
    packages: Iterable[str] = (),
    include_system: bool = True,
    max_files: int = 0,
) -> dict[str, Any]:
    mode = _root_mode(adb, serial)
    result: dict[str, Any] = {
        "ok": False,
        "root_mode": mode or "unavailable",
        "files": 0,
        "bytes": 0,
        "roots_scanned": 0,
        "roots_present": 0,
        "errors": [],
        "limitations": [],
    }
    if not mode:
        result["limitations"].append(
            "Private application data was not acquired because the device did not already provide root/su access. "
            "No rooting or lock bypass was attempted."
        )
        return result

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    pkg_set = list(dict.fromkeys(tuple(packages) or (ANDROID_SOCIAL_PACKAGES + EXTRA_APP_PACKAGES)))
    roots = _candidate_roots(pkg_set, include_system)

    collected_app_packages: set[str] = set()
    for root in roots:
        # /data/data/<pkg> is normally an alias of /data/user/0/<pkg>. Prefer
        # user/0 and do not duplicate the same private app tree when both exist.
        app_pkg = ""
        if root.startswith("/data/user/0/"):
            app_pkg = root[len("/data/user/0/"):].split("/", 1)[0]
        elif root.startswith("/data/data/"):
            app_pkg = root[len("/data/data/"):].split("/", 1)[0]
            if app_pkg in collected_app_packages:
                continue
        if max_files and int(result["files"]) >= max_files:
            result["limitations"].append(f"Stopped after configured max_files={max_files}.")
            break
        result["roots_scanned"] += 1
        if not _remote_exists(adb, serial, mode, root):
            continue
        result["roots_present"] += 1
        if app_pkg:
            collected_app_packages.add(app_pkg)
        files = _list_files(adb, serial, mode, root)
        for remote in files:
            if max_files and int(result["files"]) >= max_files:
                break
            dest = out / _safe_rel(remote)
            ok, err = _cat_file(adb, serial, mode, remote, dest)
            if not ok:
                if len(result["errors"]) < 100:
                    result["errors"].append(f"{remote}: {err}")
                continue
            try:
                size = dest.stat().st_size
            except OSError:
                size = 0
            result["files"] += 1
            result["bytes"] += int(size)
            if int(result["files"]) % 10 == 0:
                _write_progress(
                    progress_file,
                    {
                        "stage": "acquire",
                        "item": "android_private_apps",
                        "files_seen": int(result["files"]),
                        "bytes_done": int(result["bytes"]),
                        "detail": f"Private app/system data: {result['files']} file(s)",
                        "category": "Collecting private application data",
                    },
                )

    result["ok"] = int(result["files"]) > 0
    _write_progress(
        progress_file,
        {
            "stage": "acquire",
            "item": "android_private_apps",
            "files_seen": int(result["files"]),
            "bytes_done": int(result["bytes"]),
            "detail": f"Private app/system acquisition complete: {result['files']} file(s)",
            "category": "Collected private application data",
        },
    )
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read already-accessible Android private evidence via existing root/su")
    p.add_argument("--adb", default="adb")
    p.add_argument("--serial", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--progress", default="")
    p.add_argument("--packages", default="")
    p.add_argument("--no-system", action="store_true")
    p.add_argument("--max-files", type=int, default=0)
    args = p.parse_args(argv)
    packages = [x.strip() for x in args.packages.split(",") if x.strip()] if args.packages else []
    result = pull_private_evidence(
        adb=args.adb,
        serial=args.serial,
        out=Path(args.out),
        progress_file=args.progress,
        packages=packages,
        include_system=not args.no_system,
        max_files=max(0, int(args.max_files or 0)),
    )
    print(json.dumps(result))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
