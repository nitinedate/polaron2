"""Android-only trash / WhatsApp leftover recovery from pulled shared storage.

iOS jobs must not import or call this module. iPhone backup unpacking and
lockdown media pulls live on the iOS agent modules only.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

_MEDIA_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".heic",
    ".heif",
    ".webp",
    ".mp4",
    ".mov",
    ".m4v",
    ".3gp",
    ".opus",
    ".aac",
    ".m4a",
    ".mp3",
    ".amr",
)

_TRASH_PARTS = (
    ".trashed",
    "/.trash/",
    "/trash/",
    "$recycle.bin",
    ".trashes",
    "/.deleted/",
)

_ANDROID_ROOTS = (
    "adb_logical",
    "filesystem",
    "shared_storage",
    "mtp_shared",
    "android_backup",
)


def _win_long(path: Path) -> str:
    text = str(path)
    if len(text) >= 240 and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + str(path.resolve())
    return text


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(_win_long(src), _win_long(dest))
        return
    except OSError:
        shutil.copy2(_win_long(src), _win_long(dest))


def _is_android_tree(original: Path) -> bool:
    if (original / "ios_image").is_dir() or (original / "ios_backup").is_dir():
        return False
    return any((original / name).is_dir() for name in _ANDROID_ROOTS)


def _is_trash_path(rel: str) -> bool:
    low = rel.replace("\\", "/").lower()
    return any(part in low for part in _TRASH_PARTS)


def _count_android_whatsapp_deleted(msgstore: Path) -> int:
    """Android msgstore flags only — never iOS Core Data message-type columns."""
    try:
        con = sqlite3.connect(f"file:{msgstore}?mode=ro", uri=True)
    except sqlite3.Error:
        return 0
    try:
        cur = con.cursor()
        tables = {r[0].lower(): r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        msg_t = tables.get("message") or tables.get("messages")
        if not msg_t:
            return 0
        cols = {r[1].lower(): r[1] for r in cur.execute(f'PRAGMA table_info("{msg_t}")')}
        total = 0
        for name in ("is_deleted", "deleted", "deleted_ts"):
            col = cols.get(name)
            if not col:
                continue
            if name == "deleted_ts":
                total = max(
                    total,
                    int(cur.execute(f'SELECT COUNT(*) FROM "{msg_t}" WHERE "{col}" IS NOT NULL AND "{col}" != 0').fetchone()[0] or 0),
                )
            else:
                total = max(
                    total,
                    int(cur.execute(f'SELECT COUNT(*) FROM "{msg_t}" WHERE CAST("{col}" AS INTEGER) != 0').fetchone()[0] or 0),
                )
        deleted_t = tables.get("deleted_messages") or tables.get("message_deletes")
        if deleted_t:
            total = max(total, int(cur.execute(f'SELECT COUNT(*) FROM "{deleted_t}"').fetchone()[0] or 0))
        return total
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def _carve_android_msgstore(msgstore: Path, dest: Path, out: dict[str, Any]) -> None:
    try:
        from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_residuals
    except Exception as exc:
        out["errors"].append(f"android sqlite carve unavailable: {exc}")
        return
    try:
        dest.mkdir(parents=True, exist_ok=True)
        item = recover_sqlite_residuals(msgstore, dest / msgstore.stem)
        out["deleted_sqlite_residuals"] = int(item.get("carved_strings") or 0)
        out["deleted_sqlite_chat_like"] = int(item.get("chat_like_residuals") or 0)
    except Exception as exc:
        out["errors"].append(f"android carve {msgstore.name}: {exc}")



def _looks_like_whatsapp_key(rel: str, name: str, size: int) -> bool:
    low = rel.replace("\\", "/").lower()
    if size < 32 or size > 512:
        return False
    if name.lower() != "key":
        return False
    return "whatsapp" in low and ("/files/key" in low or "/run_as_com.whatsapp/key" in low or "/com.whatsapp/" in low)


def _is_whatsapp_crypt_backup(name: str, rel: str) -> bool:
    low_name = name.lower()
    low = rel.replace("\\", "/").lower()
    return (
        "whatsapp" in low
        and "msgstore" in low_name
        and low_name.endswith((".crypt12", ".crypt14", ".crypt15"))
    )


def _materialize_whatsapp_decrypted(
    crypt_files: list[Path],
    key_files: list[Path],
    dest: Path,
    out: dict[str, Any],
) -> None:
    if not crypt_files:
        return
    if not key_files:
        out["whatsapp_decryption_state"] = "key_unavailable"
        out["limitations"] = list(out.get("limitations") or []) + [
            "Encrypted WhatsApp msgstore backups were collected, but no readable device key was present in the acquisition."
        ]
        return
    try:
        from app.services.mobile_forensic.whatsapp_crypt import cipher_key_from_material, try_decrypt_whatsapp_crypt
    except Exception as exc:
        out["errors"].append(f"WhatsApp decryptor unavailable: {exc}")
        return

    key32 = None
    key_source = None
    for key_path in key_files:
        try:
            material = key_path.read_bytes()
        except OSError:
            continue
        key32 = cipher_key_from_material(material)
        if key32:
            key_source = key_path
            break
    if not key32:
        out["whatsapp_decryption_state"] = "key_invalid"
        out["errors"].append("Collected WhatsApp key candidate could not be parsed as a supported device key.")
        return

    dest.mkdir(parents=True, exist_ok=True)
    seen_plain: set[str] = set()
    decrypted = 0
    failed = 0
    max_backups = max(1, int(os.environ.get("MOBILE_WHATSAPP_DECRYPT_MAX", "256") or 256))
    # Newer backups first; historical unique DBs are retained for deleted-history correlation.
    ordered = sorted(crypt_files, key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)[:max_backups]
    for src in ordered:
        try:
            raw = src.read_bytes()
            plain = try_decrypt_whatsapp_crypt(raw, key32)
        except Exception as exc:
            failed += 1
            if len(out["errors"]) < 50:
                out["errors"].append(f"WhatsApp decrypt {src.name}: {exc}")
            continue
        if not plain:
            failed += 1
            continue
        digest = hashlib.sha256(plain).hexdigest()
        if digest in seen_plain:
            continue
        seen_plain.add(digest)
        base = src.name
        for suf in (".crypt12", ".crypt14", ".crypt15"):
            if base.lower().endswith(suf):
                base = base[: -len(suf)]
                break
        if not base.lower().endswith(".db"):
            base += ".db"
        target = dest / f"{decrypted:04d}_{base}"
        try:
            target.write_bytes(plain)
        except OSError as exc:
            failed += 1
            out["errors"].append(f"Write decrypted WhatsApp DB {target.name}: {exc}")
            continue
        decrypted += 1
        out["copied"].append({
            "dest": str(target),
            "rel": str(src),
            "deleted": False,
            "recovery_state": "decrypted_backup",
        })

    out["whatsapp_decryption_state"] = "decrypted" if decrypted else "decrypt_failed"
    out["whatsapp_decrypted_backups"] = decrypted
    out["whatsapp_decrypt_failed"] = failed
    # Record only the path/provenance; never print or persist raw key bytes/hex here.
    if key_source is not None:
        out["whatsapp_key_source"] = str(key_source)

def materialize_android_readable_artifacts(
    original: Path,
    *,
    dest_root: Path | None = None,
) -> dict[str, Any]:
    """Copy Android trash + leftover WhatsApp media into readable_artifacts/."""
    original = Path(original)
    out: dict[str, Any] = {
        "ok": False,
        "agent": "androidagent",
        "copied": [],
        "errors": [],
        "deleted_whatsapp_messages": 0,
        "deleted_media": 0,
        "whatsapp_media": 0,
        "camera_media": 0,
        "whatsapp_decrypted_backups": 0,
        "whatsapp_decryption_state": "not_applicable",
        "limitations": [],
    }
    if not original.is_dir():
        out["errors"].append("No Android extraction directory.")
        return out
    if not _is_android_tree(original):
        out["errors"].append("Not an Android extraction — androidagent will not touch iOS trees.")
        return out

    readable = Path(dest_root) if dest_root else original / "readable_artifacts"
    try:
        readable.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out["errors"].append(str(exc))
        return out
    out["readable_root"] = str(readable)
    trash_dir = readable / "android_deleted"
    wa_dir = readable / "whatsapp"
    media_dir = readable / "media"

    msgstore: Path | None = None
    whatsapp_keys: list[Path] = []
    whatsapp_crypts: list[Path] = []
    for dirpath, _dirs, files in os.walk(original):
        for name in files:
            src = Path(dirpath) / name
            try:
                rel = str(src.relative_to(original)).replace("\\", "/")
            except ValueError:
                continue
            low = rel.lower()
            if "readable_artifacts" in low:
                continue
            try:
                size = src.stat().st_size
            except OSError:
                size = 0
            if _looks_like_whatsapp_key(rel, name, size):
                whatsapp_keys.append(src)
            if _is_whatsapp_crypt_backup(name, rel):
                whatsapp_crypts.append(src)
            suffix = Path(name).suffix.lower()
            is_media = suffix in _MEDIA_SUFFIXES
            is_wa = "whatsapp" in low or "com.whatsapp" in low
            is_camera = any(tok in low for tok in ("/dcim/", "\\dcim\\", "/pictures/", "/movies/", "/camera/"))
            if name.lower() in {"msgstore.db", "msgstore.db-wal"} and "crypt" not in low:
                if name.lower() == "msgstore.db":
                    msgstore = src
            if is_wa and is_media:
                dest = wa_dir / f"{abs(hash(rel)) & 0xFFFFFFFF:08x}_{name}"
                try:
                    _link_or_copy(src, dest)
                    out["whatsapp_media"] += 1
                    tagged = _is_trash_path(rel)
                    out["copied"].append({"dest": str(dest), "rel": rel, "deleted": tagged})
                    if tagged:
                        out["deleted_media"] += 1
                except OSError as exc:
                    out["errors"].append(f"{rel}: {exc}")
                continue
            if is_media and (_is_trash_path(rel) or is_camera):
                dest_root_dir = trash_dir if _is_trash_path(rel) else media_dir
                dest = dest_root_dir / f"{abs(hash(rel)) & 0xFFFFFFFF:08x}_{name}"
                try:
                    _link_or_copy(src, dest)
                    rec = {"dest": str(dest), "rel": rel, "deleted": _is_trash_path(rel)}
                    out["copied"].append(rec)
                    if _is_trash_path(rel):
                        out["deleted_media"] += 1
                    else:
                        out["camera_media"] += 1
                except OSError as exc:
                    out["errors"].append(f"{rel}: {exc}")

    _materialize_whatsapp_decrypted(
        whatsapp_crypts,
        whatsapp_keys,
        readable / "whatsapp_decrypted",
        out,
    )

    if msgstore and msgstore.is_file():
        out["deleted_whatsapp_messages"] = _count_android_whatsapp_deleted(msgstore)
        try:
            _link_or_copy(msgstore, wa_dir / msgstore.name)
        except OSError:
            pass
        _carve_android_msgstore(msgstore, readable / "deleted_recovery", out)

    out["ok"] = True
    return out
