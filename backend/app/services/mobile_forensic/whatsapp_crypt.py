"""WhatsApp crypt12 / crypt14 / crypt15 msgstore decryption (V45 rewrite).

Fail-closed, deterministic, no brute force. Only decrypts with key material the
examiner actually collected or entered:

  * the 158-byte Android ``/data/data/com.whatsapp/files/key`` file
    (crypt12 / crypt14) — the AES-256 key is the LAST 32 bytes (offset 126),
    NOT offset 30 (that is the ``t1`` header-match checksum; the pre-V45
    implementation used it as the key and therefore never decrypted anything);
  * the 32-byte ``encrypted_backup.key`` or the 64-digit end-to-end backup key
    the user sees in WhatsApp (crypt15) — the real AES key is derived with
    HKDF-SHA256 (zero salt, info ``"backup encryption"``, L=32);
  * a raw 32-byte AES key or 64-hex string.

Layouts (reference: public crypt12/14/15 research, e.g. wa-crypt-tools docs):

  crypt12 : [51 B header incl. t1 at 3:35][16 B IV][AES-256-GCM(zlib(sqlite))][16 B tag][4 B]
  crypt14 : [1 B protobuf length][BackupPrefix protobuf][16 B IV][AES-256-GCM(zlib(sqlite))][tag/trailer]
  crypt15 : [1 B protobuf length][BackupPrefix protobuf (contains c15 IV)][AES-256-GCM(zlib(sqlite))][tag/trailer]

Because WhatsApp changes the prefix layout between releases, decryption is
treated as a *search over a small, well-defined candidate set* (protobuf-derived
IV/body positions first, then the historical fixed offsets) verified with a
hard oracle: the plaintext must inflate to bytes starting with
``SQLite format 3\\0``. The oracle makes a false hit astronomically unlikely, and
the candidate set is tiny (<= ~40 AES-GCM attempts), so this is still
"deterministic decrypt with a known key", not brute force.

Returns SQLite bytes on success, else None, and records *why* in
``last_decrypt_diagnostics()`` so the UI/report can show the examiner the gap.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import zlib
from dataclasses import dataclass, field

log = logging.getLogger("mobile_forensic.whatsapp_crypt")

SQLITE_MAGIC = b"SQLite format 3\x00"

# --- key file layout ---------------------------------------------------------
KEYFILE_LEN = 158
KEYFILE_T1_OFFSET = 30        # 32-byte "t1" — must equal crypt12 header[3:35]
KEYFILE_KEY_OFFSET = 126      # 32-byte AES-256 key (LAST 32 bytes)
KEY_LEN = 32
IV_LEN = 16
GCM_TAG_LEN = 16

# --- crypt12 layout ----------------------------------------------------------
CRYPT12_HEADER_LEN = 51
CRYPT12_T1_SLICE = slice(3, 35)
CRYPT12_IV_SLICE = slice(51, 67)
CRYPT12_BODY_START = 67
CRYPT12_TRAILER_LEN = 20      # 16-byte GCM tag + 4 bytes

# Historical crypt14 body offsets observed across releases (IV = 16 bytes before).
_LEGACY_CRYPT14_BODY_OFFSETS = (67, 99, 162, 184, 191, 200, 227, 249)

# crypt15 HKDF info string (HKDF-SHA256, zero salt, one 32-byte block => "info || 0x01").
_C15_HKDF_INFO = b"backup encryption"


@dataclass
class DecryptDiagnostics:
    """Examiner-facing explanation of the last decrypt attempt in this thread."""

    key_kind: str = "none"            # keyfile158 | raw32 | hex64 | invalid
    key_sha256_prefix: str = ""
    container: str = "unknown"        # crypt12 | crypt14 | crypt15 | sqlite | unknown
    candidates_tried: int = 0
    strategy: str = ""                # which candidate succeeded
    reason: str = ""                  # failure reason when result is None
    t1_match: bool | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key_kind": self.key_kind,
            "key_sha256_prefix": self.key_sha256_prefix,
            "container": self.container,
            "candidates_tried": self.candidates_tried,
            "strategy": self.strategy,
            "reason": self.reason,
            "t1_match": self.t1_match,
            "notes": list(self.notes),
        }


_tls = threading.local()


def last_decrypt_diagnostics() -> dict:
    diag = getattr(_tls, "diag", None)
    return diag.as_dict() if isinstance(diag, DecryptDiagnostics) else {}


def _set_diag(diag: DecryptDiagnostics) -> None:
    _tls.diag = diag


# -----------------------------------------------------------------------------
# Key material
# -----------------------------------------------------------------------------

def looks_like_sqlite(data: bytes | None) -> bool:
    return bool(data) and data[:16] == SQLITE_MAGIC


@dataclass(frozen=True)
class KeyMaterial:
    kind: str                 # keyfile158 | raw32 | hex64
    raw32: bytes              # the 32-byte secret as collected/entered
    t1: bytes | None = None   # crypt12 header check (keyfile only)

    @property
    def key_crypt12_14(self) -> bytes:
        return self.raw32

    @property
    def key_crypt15(self) -> bytes:
        """HKDF-SHA256(salt=0^32, ikm=raw32, info="backup encryption", L=32)."""
        prk = hmac.new(b"\x00" * 32, self.raw32, hashlib.sha256).digest()
        return hmac.new(prk, _C15_HKDF_INFO + b"\x01", hashlib.sha256).digest()


def parse_key_material(key_material: bytes | str | None) -> KeyMaterial | None:
    """Accept: 158-byte key file, 32 raw bytes, 64 hex digits (optionally spaced/dashed)."""
    if key_material is None:
        return None
    if isinstance(key_material, str):
        s = "".join(ch for ch in key_material if ch not in " \n\r\t-:")
        if not s:
            return None
        try:
            blob = bytes.fromhex(s)
        except ValueError:
            log.warning("whatsapp key text is not hex (len=%d)", len(s))
            return None
        if len(blob) == KEY_LEN:
            return KeyMaterial("hex64", blob)
        key_material = blob  # could be a hex-encoded key file
    if not isinstance(key_material, (bytes, bytearray)):
        return None
    blob = bytes(key_material)
    if not blob:
        return None
    # adb `run-as` error text sometimes gets saved as files/key by naive pullers.
    if blob.lstrip()[:6].lower() in (b"run-as", b"error:"):
        return None
    if len(blob) == KEY_LEN:
        return KeyMaterial("raw32", blob)
    if len(blob) == KEYFILE_LEN:
        return KeyMaterial(
            "keyfile158",
            blob[KEYFILE_KEY_OFFSET : KEYFILE_KEY_OFFSET + KEY_LEN],
            t1=blob[KEYFILE_T1_OFFSET : KEYFILE_T1_OFFSET + KEY_LEN],
        )
    # Tolerate key files with a stray trailing newline / BOM.
    if KEYFILE_LEN < len(blob) <= KEYFILE_LEN + 4:
        core = blob[:KEYFILE_LEN]
        return KeyMaterial(
            "keyfile158",
            core[KEYFILE_KEY_OFFSET : KEYFILE_KEY_OFFSET + KEY_LEN],
            t1=core[KEYFILE_T1_OFFSET : KEYFILE_T1_OFFSET + KEY_LEN],
        )
    return None


def cipher_key_from_material(key_material: bytes | str | None) -> bytes | None:
    """Backwards-compatible helper (callers in android_readable/package_inventory).

    Returns the 32-byte *base* secret. crypt15 derivation happens inside
    ``try_decrypt_whatsapp_crypt``; passing this value back in is fine because a
    32-byte raw key is re-wrapped as ``raw32`` and derived again when needed.
    """
    km = parse_key_material(key_material)
    return km.raw32 if km else None


# -----------------------------------------------------------------------------
# Minimal protobuf wire-format walker (no protobuf dependency)
# -----------------------------------------------------------------------------

def _read_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    result = 0
    shift = 0
    while pos < len(buf) and shift <= 63:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return None


def _protobuf_length_delimited_fields(buf: bytes, *, depth: int = 0, max_depth: int = 4) -> list[bytes]:
    """Return every length-delimited field value, recursing into sub-messages.

    Tolerant: stops at the first malformed byte instead of raising. Used only
    to harvest IV candidates (16-byte values) from the BackupPrefix header.
    """
    out: list[bytes] = []
    pos = 0
    n = len(buf)
    while pos < n:
        tag = _read_varint(buf, pos)
        if tag is None:
            break
        key, pos = tag
        wire = key & 0x07
        if wire == 0:           # varint
            v = _read_varint(buf, pos)
            if v is None:
                break
            _, pos = v
        elif wire == 1:         # 64-bit
            pos += 8
        elif wire == 2:         # length-delimited
            ln = _read_varint(buf, pos)
            if ln is None:
                break
            length, pos = ln
            if length < 0 or pos + length > n:
                break
            val = buf[pos : pos + length]
            out.append(val)
            if depth < max_depth and length > 2:
                out.extend(_protobuf_length_delimited_fields(val, depth=depth + 1, max_depth=max_depth))
            pos += length
        elif wire == 5:         # 32-bit
            pos += 4
        else:
            break
    return out


# -----------------------------------------------------------------------------
# AES-GCM + inflate with the SQLite oracle
# -----------------------------------------------------------------------------

def _inflate_to_sqlite(plain: bytes | None) -> bytes | None:
    if not plain:
        return None
    if looks_like_sqlite(plain):
        return plain
    if plain[:1] != b"\x78":   # zlib header (CMF) — all WhatsApp bodies are zlib
        return None
    try:
        d = zlib.decompressobj()
        head = d.decompress(plain[: 64 * 1024], 64)   # cheap pre-check
        if not head.startswith(SQLITE_MAGIC[: len(head)]) or len(head) < 16:
            return None
        d = zlib.decompressobj()
        out = d.decompress(plain)      # tolerates trailing tag/trailer bytes
        out += d.flush()
    except zlib.error:
        return None
    return out if looks_like_sqlite(out) else None


def _aes_gcm_decrypt(key32: bytes, iv: bytes, blob: bytes) -> bytes | None:
    """Decrypt without tag verification (the tag position differs per release)."""
    if len(key32) != KEY_LEN or len(iv) != IV_LEN or len(blob) < 32:
        return None
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore

            # GCM is CTR with J0 = IV||0x00000001 for a 96-bit IV; for 128-bit IVs
            # GHASH is required — pycryptodome handles both, so prefer it.
            if len(iv) != 12:
                log.info("WhatsApp crypt decrypt needs pycryptodome for 16-byte IVs")
                return None
            ctr_iv = iv + b"\x00\x00\x00\x02"
            dec = Cipher(algorithms.AES(key32), modes.CTR(ctr_iv)).decryptor()
            return dec.update(blob) + dec.finalize()
        except Exception:
            log.info("WhatsApp crypt decrypt skipped — no AES provider available")
            return None
    try:
        return AES.new(key32, AES.MODE_GCM, nonce=iv).decrypt(blob)
    except Exception:
        return None


def _try_candidate(key32: bytes, iv: bytes, body: bytes, diag: DecryptDiagnostics, label: str) -> bytes | None:
    diag.candidates_tried += 1
    plain = _aes_gcm_decrypt(key32, iv, body)
    hit = _inflate_to_sqlite(plain)
    if hit:
        diag.strategy = label
    return hit


# -----------------------------------------------------------------------------
# Container classification
# -----------------------------------------------------------------------------

def classify_container(data: bytes, path: str = "") -> str:
    low = (path or "").lower()
    if looks_like_sqlite(data):
        return "sqlite"
    if low.endswith(".crypt15"):
        return "crypt15"
    if low.endswith(".crypt14"):
        return "crypt14"
    if low.endswith(".crypt12"):
        return "crypt12"
    # Heuristic when the extension was stripped: crypt12 starts with 0x00 0x01? no fixed magic,
    # but its header is exactly 51 bytes with t1 at 3:35; crypt14/15 start with the protobuf length byte.
    if len(data) > 67 and data[:1] == b"\x00":
        return "crypt12"
    return "unknown"


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def try_decrypt_whatsapp_crypt(
    data: bytes,
    key_material: str | bytes | None,
    *,
    path: str = "",
) -> bytes | None:
    """Decrypt crypt12/14/15 bytes with examiner-provided key material. Fail-closed."""
    diag = DecryptDiagnostics()
    _set_diag(diag)
    if not data:
        diag.reason = "empty_input"
        return None
    diag.container = classify_container(data, path)
    if diag.container == "sqlite":
        diag.strategy = "already_plaintext"
        return data

    km = parse_key_material(key_material)
    if km is None:
        diag.key_kind = "invalid" if key_material else "none"
        diag.reason = "key_material_missing_or_invalid"
        return None
    diag.key_kind = km.kind
    diag.key_sha256_prefix = hashlib.sha256(km.raw32).hexdigest()[:12]
    if len(data) < CRYPT12_BODY_START + 32:
        diag.reason = "file_too_small"
        return None

    # Which AES keys to try, most likely first.
    keys: list[tuple[str, bytes]] = []
    if diag.container == "crypt15":
        keys = [("c15_hkdf", km.key_crypt15), ("raw", km.key_crypt12_14)]
    elif diag.container in ("crypt12", "crypt14"):
        keys = [("raw", km.key_crypt12_14), ("c15_hkdf", km.key_crypt15)]
    else:
        keys = [("raw", km.key_crypt12_14), ("c15_hkdf", km.key_crypt15)]

    # ---- crypt12 fixed layout -------------------------------------------------
    if diag.container in ("crypt12", "unknown"):
        if km.t1 is not None:
            diag.t1_match = data[CRYPT12_T1_SLICE] == km.t1
            if diag.container == "crypt12" and diag.t1_match is False:
                diag.notes.append("crypt12 header t1 does not match key file t1 — wrong device key?")
        iv = data[CRYPT12_IV_SLICE]
        for klabel, key32 in keys:
            for body in (data[CRYPT12_BODY_START:-CRYPT12_TRAILER_LEN], data[CRYPT12_BODY_START:]):
                hit = _try_candidate(key32, iv, body, diag, f"crypt12/{klabel}")
                if hit:
                    return hit

    # ---- crypt14 / crypt15 protobuf-prefixed layout --------------------------
    candidates: list[tuple[str, bytes, bytes]] = []
    first = data[0]
    header_len_variants: list[tuple[int, int]] = []
    if 0 < first < 200 and 1 + first < len(data):
        header_len_variants.append((1, first))             # 1-byte length prefix (observed)
    vl = _read_varint(data, 0)
    if vl and 0 < vl[0] < 4096 and vl[1] + vl[0] < len(data) and (vl[1], vl[0]) not in header_len_variants:
        header_len_variants.append((vl[1], vl[0]))         # varint length prefix (defensive)
    for prefix_len, hlen in header_len_variants:
        hdr_end = prefix_len + hlen
        header = data[prefix_len:hdr_end]
        iv_fields = [f for f in _protobuf_length_delimited_fields(header) if len(f) == IV_LEN]
        # crypt15: IV lives inside the protobuf; body follows the header directly.
        for iv in iv_fields:
            candidates.append(("c15_proto_iv/body@hdr_end", iv, data[hdr_end:]))
            candidates.append(("c15_proto_iv/body@hdr_end+1", iv, data[hdr_end + 1 :]))
        # crypt14: IV is the 16 raw bytes after the protobuf; body follows the IV.
        candidates.append(("c14_raw_iv@hdr_end", data[hdr_end : hdr_end + IV_LEN], data[hdr_end + IV_LEN :]))
        candidates.append(("c14_raw_iv@hdr_end+1", data[hdr_end + 1 : hdr_end + 1 + IV_LEN], data[hdr_end + 1 + IV_LEN :]))
    # Historical fixed offsets (IV immediately precedes the body).
    for start in _LEGACY_CRYPT14_BODY_OFFSETS:
        if start + 32 <= len(data):
            candidates.append((f"legacy_body@{start}", data[start - IV_LEN : start], data[start:]))

    seen: set[tuple[bytes, int]] = set()
    for label, iv, body in candidates:
        if len(iv) != IV_LEN or len(body) < 32:
            continue
        sig = (iv, len(body))
        if sig in seen:
            continue
        seen.add(sig)
        for klabel, key32 in keys:
            hit = _try_candidate(key32, iv, body, diag, f"{label}/{klabel}")
            if hit:
                return hit

    diag.reason = "no_candidate_produced_sqlite"
    if km.kind == "keyfile158" and diag.container == "crypt15":
        diag.notes.append("crypt15 needs the 32-byte encrypted_backup.key / 64-digit backup key, not files/key")
    if km.kind in ("hex64", "raw32") and diag.container in ("crypt12", "crypt14"):
        diag.notes.append("crypt12/14 need the device files/key (158 bytes); a 64-digit backup key only opens crypt15")
    log.info(
        "WhatsApp %s decrypt failed: key=%s candidates=%d t1_match=%s",
        diag.container, diag.key_kind, diag.candidates_tried, diag.t1_match,
    )
    return None


# -----------------------------------------------------------------------------
# Test-support encoder (also lets QA build fixtures without a device).
# -----------------------------------------------------------------------------

def _encrypt_fixture(sqlite_bytes: bytes, km: KeyMaterial, *, container: str, iv: bytes) -> bytes:  # pragma: no cover
    """Build a synthetic crypt12/14/15 file using the documented layouts (QA only)."""
    from Crypto.Cipher import AES  # type: ignore

    body_plain = zlib.compress(sqlite_bytes)
    if container == "crypt12":
        c = AES.new(km.key_crypt12_14, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        header = bytearray(CRYPT12_HEADER_LEN)
        header[3:35] = km.t1 or b"\x00" * 32
        return bytes(header) + iv + ct + tag + b"\x00\x00\x00\x00"
    if container == "crypt14":
        c = AES.new(km.key_crypt12_14, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        proto = b"\x0a\x04\x08\x0e\x10\x01\x1a\x02\x08\x01"  # info{key_version=14,...} feature{}
        return bytes([len(proto)]) + proto + iv + ct + tag
    if container == "crypt15":
        c = AES.new(km.key_crypt15, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        # BackupPrefix{ info(1){key_version=15} ; c15_iv(2){ IV(1)=iv } }
        c15 = b"\x0a" + bytes([len(iv)]) + iv
        proto = b"\x0a\x02\x08\x0f" + b"\x12" + bytes([len(c15)]) + c15
        return bytes([len(proto)]) + proto + ct + tag
    raise ValueError(container)
