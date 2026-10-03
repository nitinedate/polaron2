"""WhatsApp crypt12/14/15 decrypt using the *same device* key file.

Fail-closed: never brute-force, never guess a key. Only decrypt when the
examiner already collected the 158-byte WhatsApp key (or a 32-byte AES key /
hex of either). Returns SQLite bytes on success, else None.
"""

from __future__ import annotations

import logging
import zlib

log = logging.getLogger("mobile_forensic.whatsapp_crypt")

SQLITE_MAGIC = b"SQLite format 3"
# Documented WhatsApp key-file layout: 32-byte AES key starts at offset 30.
_KEYFILE_KEY_OFFSET = 30
_KEYFILE_KEY_LEN = 32
# Known ciphertext start offsets after the crypt12/14 protobuf/header.
_CRYPT_BODY_OFFSETS = (67, 99, 162, 184, 191, 200, 227, 249)


def looks_like_sqlite(data: bytes | None) -> bool:
    return bool(data) and data[:15] == SQLITE_MAGIC


def cipher_key_from_material(key_material: bytes | str | None) -> bytes | None:
    """Accept hex, a raw 32-byte AES key, or a WhatsApp key file (≥62 bytes)."""
    if key_material is None:
        return None
    if isinstance(key_material, str):
        hex_s = key_material.strip().replace(" ", "").replace("\n", "")
        if not hex_s:
            return None
        try:
            key_material = bytes.fromhex(hex_s)
        except ValueError:
            log.warning("whatsapp key hex invalid")
            return None
    if not key_material:
        return None
    if len(key_material) == _KEYFILE_KEY_LEN:
        return key_material
    if len(key_material) >= _KEYFILE_KEY_OFFSET + _KEYFILE_KEY_LEN:
        return key_material[_KEYFILE_KEY_OFFSET : _KEYFILE_KEY_OFFSET + _KEYFILE_KEY_LEN]
    return None


def _maybe_inflate_sqlite(plain: bytes | None) -> bytes | None:
    if not plain:
        return None
    if looks_like_sqlite(plain):
        return plain
    if plain[:2] not in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        return None
    try:
        inflated = zlib.decompress(plain)
    except Exception:
        return None
    return inflated if looks_like_sqlite(inflated) else None


def _gcm_try(key32: bytes, iv: bytes, blob: bytes) -> bytes | None:
    if len(iv) not in (12, 16) or len(blob) < 32:
        return None
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception:
        log.info("WhatsApp crypt decrypt skipped — PyCryptodome not available")
        return None
    for tag_len in (16, 20, 0):
        if tag_len and len(blob) <= tag_len:
            continue
        ciphertext = blob[:-tag_len] if tag_len else blob
        tag = blob[-tag_len:] if tag_len else None
        try:
            cipher = AES.new(key32, AES.MODE_GCM, nonce=iv)
            if tag is not None:
                try:
                    plain = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    cipher = AES.new(key32, AES.MODE_GCM, nonce=iv)
                    plain = cipher.decrypt(ciphertext)
            else:
                plain = cipher.decrypt(ciphertext)
        except Exception:
            continue
        hit = _maybe_inflate_sqlite(plain)
        if hit:
            return hit
    return None


def _cbc_try(key32: bytes, iv: bytes, blob: bytes) -> bytes | None:
    if len(iv) != 16 or len(blob) < 16 or len(blob) % 16:
        return None
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception:
        return None
    try:
        plain = AES.new(key32, AES.MODE_CBC, iv).decrypt(blob)
    except Exception:
        return None
    return _maybe_inflate_sqlite(plain)


def try_decrypt_whatsapp_crypt(data: bytes, key_hex: str | bytes | None) -> bytes | None:
    """Decrypt crypt sidecar bytes with a collected device key. Fail-closed."""
    if not data:
        return None
    if looks_like_sqlite(data):
        return data
    key32 = cipher_key_from_material(key_hex)
    if not key32:
        return None
    if len(data) < 67:
        return None

    # crypt12-style: IV at 51:67, body after 67.
    hit = _gcm_try(key32, data[51:67], data[67:])
    if hit:
        return hit
    hit = _cbc_try(key32, data[51:67], data[67:])
    if hit:
        return hit

    # crypt14/15: variable protobuf header; IV is the 16 bytes before the body.
    for start in _CRYPT_BODY_OFFSETS:
        if start + 32 > len(data):
            continue
        iv = data[start - 16 : start]
        hit = _gcm_try(key32, iv, data[start:])
        if hit:
            return hit
        hit = _cbc_try(key32, iv, data[start:])
        if hit:
            return hit

    log.debug("whatsapp crypt decrypt produced no SQLite payload")
    return None
