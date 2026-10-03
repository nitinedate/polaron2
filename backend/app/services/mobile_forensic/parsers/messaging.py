"""Messaging application parsers.

WhatsApp is handled as a first-class forensic source.  The parser intentionally
probes schema variants instead of assuming one Android/iOS release and streams all
rows (no hidden 3k/5k message cap).
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Iterator

from app.services.mobile_forensic.models import Confidence, InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import (
    column_name_map,
    epoch_to_iso,
    iter_query,
    open_sqlite_bytes,
    resolve_table,
    safe_query,
    table_names,
)
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _first(cols: dict[str, str], *candidates: str) -> str | None:
    for c in candidates:
        if c.lower() in cols:
            return cols[c.lower()]
    return None


def _select_expr(col: str | None, alias: str) -> str:
    return f"{_q(col)} AS {_q(alias)}" if col else f"NULL AS {_q(alias)}"


def _truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return str(value).strip().lower() in {"true", "yes", "deleted", "revoked"}


def _scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {"binary_length": len(value), "hex_prefix": value[:24].hex()}
    return str(value)


_EXPLICIT_DELETED_COLUMNS = {
    "is_deleted", "deleted", "is_revoked", "revoked", "removed", "is_removed",
    "deleted_at", "deleted_timestamp", "deletion_timestamp", "revoke_timestamp",
}

def _row_is_explicitly_deleted(table: str, row: dict[str, Any]) -> bool:
    if "deleted" in table.lower() or "recovered" in table.lower():
        return True
    for key, value in row.items():
        if str(key).lower() not in _EXPLICIT_DELETED_COLUMNS:
            continue
        if value is None or value == "":
            continue
        if _truthy(value):
            return True
        # Timestamp/text deletion columns are evidence when populated, even if not numeric.
        if str(key).lower().endswith(("_at", "timestamp")) and str(value).strip() not in {"0", "0.0"}:
            return True
    return False

def _message_like_tables(conn) -> list[str]:
    out: list[str] = []
    preferred = ("messages", "message", "sms", "channel_messages_v2", "chat_messages", "message_v2")
    tables = table_names(conn)
    for name in preferred:
        if name in tables and name not in out:
            out.append(name)
    for table in sorted(tables):
        low = table.lower()
        if table in out or not any(token in low for token in ("message", "chat", "conversation")):
            continue
        try:
            cols = column_name_map(conn, table)
        except Exception:
            continue
        if any(c in cols for c in ("body", "text", "message", "content", "text_data", "caption", "payload")):
            out.append(table)
    return out


class WhatsAppParser(ArtifactParser):
    name = "whatsapp_parser"
    version = "2.0.0"
    domains = ("messaging_apps",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        if name.endswith((".crypt12", ".crypt14", ".crypt15")):
            return True
        if name.endswith(".enc") or ".sqlite.enc" in p:
            return False
        if name in {
            "chatstorage.sqlite",
            "extchatdatabase.sqlite",
            "chatsearchv5f.sqlite",
            "msgstore.db",
            "wa.db",
            "call_log.db",
            "call_log_database.db",
        }:
            return True
        if "whatsapp" not in p and "net.whatsapp" not in p and "com.whatsapp" not in p:
            return False
        return name.endswith((".db", ".sqlite", ".sqlite3")) and name not in {
            "observations.db",
            "pcm.db",
            "assets.db",
            "localstorage.sqlite3",
            "sticker.sqlite",
            "deviceagents.sqlite",
        }

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        name = PurePosixPath(item.path).name.lower()
        if name.endswith((".crypt12", ".crypt14", ".crypt15")):
            key_present = bool(context.whatsapp_key_hex)
            yield NormalizedArtifact.create(
                artifact_type="app_backup_encrypted",
                source_domain="messaging_apps",
                data={
                    "application": "whatsapp",
                    "artifact_family": "whatsapp_encrypted_backups",
                    "path": item.path,
                    "name": PurePosixPath(item.path).name,
                    "size": item.size,
                    "sha256": item.sha256,
                    "encrypted": True,
                    "key_available": key_present,
                    "note": (
                        "Encrypted WhatsApp backup; decryption attempted with supplied key"
                        if key_present
                        else "Encrypted WhatsApp backup; matching device key is required"
                    ),
                },
                state="unverified" if not key_present else "historical",
                recovery_source="encrypted_backup",
                source_path=item.path,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                confidence=Confidence(
                    label="MEDIUM" if key_present else "UNVERIFIED",
                    score=0.55 if key_present else 0.2,
                    validation=["crypt_sidecar_present"]
                    + (["key_material_present"] if key_present else ["key_material_missing"]),
                ),
                job_id=context.job_id,
                source_id=context.source_id,
            )
            if key_present:
                decrypted = self._try_decrypt(item, context)
                if decrypted:
                    yield from self._parse_database_bytes(
                        decrypted, item, context, default_state="backup_historical", recovery_source="decrypted_backup"
                    )
            return

        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        yield from self._parse_database_bytes(
            data, item, context, default_state="allocated", recovery_source="live_database"
        )

    def _try_decrypt(self, item: InventoryItem, context: ParseContext) -> bytes | None:
        try:
            from app.services.mobile_forensic.whatsapp_crypt import try_decrypt_whatsapp_crypt

            raw = context.read_artifact_bytes(item.path)
            if not raw or not context.whatsapp_key_hex:
                return None
            return try_decrypt_whatsapp_crypt(raw, context.whatsapp_key_hex)
        except Exception:
            return None

    def _parse_database_bytes(
        self,
        data: bytes,
        item: InventoryItem,
        context: ParseContext,
        *,
        default_state: str,
        recovery_source: str,
    ) -> Iterator[NormalizedArtifact]:
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            yielded_any = False

            # Messages (Android msgstore + iOS CoreData schema variants).
            msg_table = resolve_table(conn, "message", "messages", "msg", "ZWAMESSAGE")
            if msg_table:
                yielded_any = True
                yield from self._parse_messages(
                    conn, msg_table, item, context, default_state=default_state, recovery_source=recovery_source
                )

            # Chat/conversation metadata.
            chat_table = resolve_table(conn, "chat", "chats", "chat_list", "ZWACHATSESSION")
            if chat_table:
                yielded_any = True
                yield from self._parse_generic_table(
                    conn,
                    chat_table,
                    item,
                    context,
                    artifact_type="conversation",
                    family="whatsapp_chats",
                    default_state=default_state,
                    recovery_source=recovery_source,
                )

            # Contacts/JIDs. wa.db commonly has wa_contacts; msgstore has jid.
            for contact_table in (
                resolve_table(conn, "wa_contacts", "ZWAPHONE", "ZWACONTACT"),
                resolve_table(conn, "jid"),
            ):
                if contact_table:
                    yielded_any = True
                    yield from self._parse_contacts(
                        conn, contact_table, item, context, default_state=default_state, recovery_source=recovery_source
                    )

            # Call history table names differ by release.
            call_table = resolve_table(conn, "call_log", "call_log_participant", "ZWACALLRECORD")
            if call_table:
                yielded_any = True
                yield from self._parse_calls(
                    conn, call_table, item, context, default_state=default_state, recovery_source=recovery_source
                )

            # Surface other WhatsApp DBs as evidence even if a known table was not found.
            if not yielded_any:
                yield NormalizedArtifact.create(
                    artifact_type="app_database",
                    source_domain="messaging_apps",
                    data={
                        "application": "whatsapp",
                        "artifact_family": "whatsapp_database",
                        "path": item.path,
                        "name": PurePosixPath(item.path).name,
                        "sha256": item.sha256,
                        "tables": sorted(tables)[:100],
                    },
                    state=default_state,  # type: ignore[arg-type]
                    recovery_source=recovery_source,
                    source_path=item.path,
                    source_sha256=item.sha256,
                    parser=self.name,
                    parser_version=self.version,
                    job_id=context.job_id,
                    source_id=context.source_id,
                )

    def _parse_messages(
        self,
        conn,
        table: str,
        item: InventoryItem,
        context: ParseContext,
        *,
        default_state: str,
        recovery_source: str,
    ) -> Iterator[NormalizedArtifact]:
        cols = column_name_map(conn, table)
        id_col = _first(cols, "_id", "message_row_id", "z_pk", "id")
        ts_col = _first(cols, "timestamp", "date", "zmessagedate", "sort_id", "received_timestamp")
        text_col = _first(cols, "text_data", "data", "body", "ztext", "message", "caption")
        from_me_col = _first(cols, "from_me", "zisfromme", "key_from_me")
        sender_col = _first(cols, "sender_jid_row_id", "sender", "from_jid", "zfromjid", "remote_resource")
        chat_col = _first(cols, "chat_row_id", "chat_id", "key_remote_jid", "zchatsession")
        key_col = _first(cols, "key_id", "stanza_id", "zstanzaid", "uuid", "message_id")
        status_col = _first(cols, "status", "zstatus", "messagestatus", "zmessagestatus")
        type_col = _first(cols, "message_type", "media_wa_type", "messagetype", "zmessagetype")
        deleted_col = _first(cols, "is_deleted", "deleted", "is_revoked", "revoke_timestamp", "zdeleted")
        media_name_col = _first(cols, "media_name", "file_name", "filename", "zmediafilename")
        media_path_col = _first(cols, "media_url", "file_path", "path", "zmediapath")
        mime_col = _first(cols, "media_mime_type", "mime_type", "mimetype", "zmimetype")
        media_size_col = _first(cols, "media_file_length", "file_size", "size", "zfilesize")
        latitude_col = _first(cols, "latitude", "zlatitude")
        longitude_col = _first(cols, "longitude", "zlongitude")

        id_expr = _q(id_col) if id_col else "rowid"
        select = [
            f"{id_expr} AS __row_id",
            _select_expr(ts_col, "ts"),
            _select_expr(text_col, "body"),
            _select_expr(from_me_col, "from_me"),
            _select_expr(sender_col, "sender"),
            _select_expr(chat_col, "chat_id"),
            _select_expr(key_col, "message_id"),
            _select_expr(status_col, "status"),
            _select_expr(type_col, "message_type"),
            _select_expr(deleted_col, "deleted_flag"),
            _select_expr(media_name_col, "media_name"),
            _select_expr(media_path_col, "media_path"),
            _select_expr(mime_col, "media_mime"),
            _select_expr(media_size_col, "media_size"),
            _select_expr(latitude_col, "latitude"),
            _select_expr(longitude_col, "longitude"),
        ]
        sql = f"SELECT {', '.join(select)} FROM {_q(table)}"

        for r in iter_query(conn, sql):
            row_id = str(r.get("__row_id") or "")
            state = "database_deleted" if _truthy(r.get("deleted_flag")) else default_state
            rec_source = "database_deleted_flag" if state == "database_deleted" else recovery_source
            media_ref = r.get("media_path") or r.get("media_name")
            body = _scalar(r.get("body"))
            data = {
                "application": "whatsapp",
                "artifact_family": "whatsapp_messages",
                "message_id": _scalar(r.get("message_id")) or row_id,
                "conversation_id": _scalar(r.get("chat_id")),
                "sender": _scalar(r.get("sender")),
                "from_me": _scalar(r.get("from_me")),
                "direction": "outgoing" if _truthy(r.get("from_me")) else "incoming",
                "body": body,
                "status": _scalar(r.get("status")),
                "message_type": _scalar(r.get("message_type")),
                "deleted_flag": _scalar(r.get("deleted_flag")),
                "media_name": _scalar(r.get("media_name")),
                "media_path": _scalar(r.get("media_path")),
                "media_mime": _scalar(r.get("media_mime")),
                "media_size": _scalar(r.get("media_size")),
                "latitude": _scalar(r.get("latitude")),
                "longitude": _scalar(r.get("longitude")),
                "has_attachment": bool(media_ref),
            }
            yield NormalizedArtifact.create(
                artifact_type="app_message",
                source_domain="messaging_apps",
                data=data,
                timestamp_utc=epoch_to_iso(r.get("ts")),
                state=state,  # type: ignore[arg-type]
                recovery_source=rec_source,
                source_path=item.path,
                source_table=table,
                source_row_id=row_id,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                job_id=context.job_id,
                source_id=context.source_id,
            )

    def _parse_generic_table(
        self,
        conn,
        table: str,
        item: InventoryItem,
        context: ParseContext,
        *,
        artifact_type: str,
        family: str,
        default_state: str,
        recovery_source: str,
    ) -> Iterator[NormalizedArtifact]:
        cols = column_name_map(conn, table)
        id_col = _first(cols, "_id", "id", "z_pk", "chat_row_id")
        id_expr = _q(id_col) if id_col else "rowid"
        for r in iter_query(conn, f"SELECT {id_expr} AS __row_id, * FROM {_q(table)}"):
            row_id = str(r.get("__row_id") or "")
            raw = {str(k): _scalar(v) for k, v in list(r.items())[:40] if k != "__row_id"}
            yield NormalizedArtifact.create(
                artifact_type=artifact_type,
                source_domain="messaging_apps",
                data={"application": "whatsapp", "artifact_family": family, "raw": raw},
                state=default_state,  # type: ignore[arg-type]
                recovery_source=recovery_source,
                source_path=item.path,
                source_table=table,
                source_row_id=row_id,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                job_id=context.job_id,
                source_id=context.source_id,
            )

    def _parse_contacts(
        self, conn, table: str, item: InventoryItem, context: ParseContext, *, default_state: str, recovery_source: str
    ) -> Iterator[NormalizedArtifact]:
        cols = column_name_map(conn, table)
        id_col = _first(cols, "_id", "id", "z_pk")
        jid_col = _first(cols, "jid", "raw_string", "zjid", "phone_number")
        name_col = _first(cols, "display_name", "wa_name", "given_name", "zfullname", "sort_name")
        status_col = _first(cols, "status", "status_text", "zstatus")
        id_expr = _q(id_col) if id_col else "rowid"
        select = [
            f"{id_expr} AS __row_id",
            _select_expr(jid_col, "jid"),
            _select_expr(name_col, "display_name"),
            _select_expr(status_col, "status"),
        ]
        for r in iter_query(conn, f"SELECT {', '.join(select)} FROM {_q(table)}"):
            row_id = str(r.get("__row_id") or "")
            yield NormalizedArtifact.create(
                artifact_type="contact",
                source_domain="accounts_contacts",
                data={
                    "application": "whatsapp",
                    "artifact_family": "whatsapp_contacts",
                    "contact_id": row_id,
                    "jid": _scalar(r.get("jid")),
                    "display_name": _scalar(r.get("display_name")),
                    "status": _scalar(r.get("status")),
                },
                state=default_state,  # type: ignore[arg-type]
                recovery_source=recovery_source,
                source_path=item.path,
                source_table=table,
                source_row_id=row_id,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                job_id=context.job_id,
                source_id=context.source_id,
            )

    def _parse_calls(
        self, conn, table: str, item: InventoryItem, context: ParseContext, *, default_state: str, recovery_source: str
    ) -> Iterator[NormalizedArtifact]:
        cols = column_name_map(conn, table)
        id_col = _first(cols, "_id", "id", "z_pk", "call_id")
        peer_col = _first(cols, "jid_row_id", "peer_jid", "remote_jid", "zpeerjid")
        ts_col = _first(cols, "timestamp", "call_time", "date", "zdate")
        duration_col = _first(cols, "duration", "duration_seconds", "zduration")
        video_col = _first(cols, "video_call", "is_video", "zvideo")
        from_me_col = _first(cols, "from_me", "zisfromme")
        id_expr = _q(id_col) if id_col else "rowid"
        select = [
            f"{id_expr} AS __row_id",
            _select_expr(peer_col, "peer"),
            _select_expr(ts_col, "ts"),
            _select_expr(duration_col, "duration"),
            _select_expr(video_col, "is_video"),
            _select_expr(from_me_col, "from_me"),
        ]
        for r in iter_query(conn, f"SELECT {', '.join(select)} FROM {_q(table)}"):
            row_id = str(r.get("__row_id") or "")
            yield NormalizedArtifact.create(
                artifact_type="app_call",
                source_domain="messaging_apps",
                data={
                    "application": "whatsapp",
                    "artifact_family": "whatsapp_calls",
                    "call_id": row_id,
                    "peer_identity": _scalar(r.get("peer")),
                    "duration_seconds": _scalar(r.get("duration")),
                    "call_type": "video" if _truthy(r.get("is_video")) else "voice",
                    "direction": "outgoing" if _truthy(r.get("from_me")) else "incoming",
                },
                timestamp_utc=epoch_to_iso(r.get("ts")),
                state=default_state,  # type: ignore[arg-type]
                recovery_source=recovery_source,
                source_path=item.path,
                source_table=table,
                source_row_id=row_id,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                job_id=context.job_id,
                source_id=context.source_id,
            )


class _GenericAppDbParser(ArtifactParser):
    app_name: str = "app"
    path_markers: tuple[str, ...] = ()

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return name.endswith((".db", ".sqlite", ".sqlitedb")) and any(m in p for m in self.path_markers)

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            msg_tables = _message_like_tables(conn)
            if msg_tables:
                for msg_table in msg_tables:
                    id_cols = column_name_map(conn, msg_table)
                    id_col = _first(id_cols, "_id", "id", "z_pk", "message_id", "mid")
                    id_expr = _q(id_col) if id_col else "rowid"
                    for r in iter_query(conn, f"SELECT {id_expr} AS __row_id, * FROM {_q(msg_table)}"):
                        row_id = str(r.get("__row_id") or "")
                        deleted = _row_is_explicitly_deleted(msg_table, r)
                        family = f"{self.app_name}_deleted" if deleted else f"{self.app_name}_messages"
                        yield NormalizedArtifact.create(
                            artifact_type="app_message",
                            source_domain="messaging_apps",
                            data={
                                "application": self.app_name,
                                "artifact_family": family,
                                "is_deleted": deleted,
                                "raw": {str(k): _scalar(v) for k, v in list(r.items())[:60] if k != "__row_id"},
                            },
                            state="database_deleted" if deleted else "allocated",
                            recovery_source="database_deleted_flag" if deleted else "live_database",
                            source_path=item.path,
                            source_table=msg_table,
                            source_row_id=row_id,
                            source_sha256=item.sha256,
                            parser=self.name,
                            parser_version=self.version,
                            job_id=context.job_id,
                            source_id=context.source_id,
                        )
            else:
                yield NormalizedArtifact.create(
                    artifact_type="app_database",
                    source_domain="messaging_apps",
                    data={"application": self.app_name, "path": item.path, "tables": sorted(tables)[:100]},
                    state="allocated",
                    source_path=item.path,
                    source_sha256=item.sha256,
                    parser=self.name,
                    parser_version=self.version,
                    job_id=context.job_id,
                    source_id=context.source_id,
                )


class TelegramParser(_GenericAppDbParser):
    name = "telegram_parser"
    version = "2.0.0"
    domains = ("messaging_apps",)
    app_name = "telegram"
    path_markers = ("telegram", "org.telegram", "nickname.db", "cache4.db")


class SignalParser(_GenericAppDbParser):
    name = "signal_parser"
    version = "2.0.0"
    domains = ("messaging_apps",)
    app_name = "signal"
    path_markers = ("signal", "org.thoughtcrime.securesms")

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        if not context.signal_db_key_hex and "signal" in item.path.lower():
            yield NormalizedArtifact.create(
                artifact_type="app_database",
                source_domain="messaging_apps",
                data={
                    "application": "signal",
                    "path": item.path,
                    "key_available": False,
                    "note": "Signal DB may require signal_db_key_hex (SQLCipher)",
                },
                state="unverified",
                recovery_source="encrypted_database",
                source_path=item.path,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                confidence=Confidence(
                    label="UNVERIFIED", score=0.25, validation=["signal_db_present", "key_material_missing"]
                ),
                job_id=context.job_id,
                source_id=context.source_id,
            )
        yield from super().parse(item, context)


class MessengerParser(_GenericAppDbParser):
    name = "messenger_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "facebook"
    path_markers = ("com.facebook.orca", "com.facebook.mlite", "messenger", "fb-msys")


class InstagramParser(_GenericAppDbParser):
    name = "instagram_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "instagram"
    path_markers = ("instagram", "com.instagram", "com.burbn.instagram")


class SnapchatParser(_GenericAppDbParser):
    name = "snapchat_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "snapchat"
    path_markers = ("snapchat", "com.snapchat")


class DiscordParser(_GenericAppDbParser):
    name = "discord_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "discord"
    path_markers = ("discord", "com.discord")


class ViberParser(_GenericAppDbParser):
    name = "viber_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "viber"
    path_markers = ("viber", "com.viber")


class WeChatParser(_GenericAppDbParser):
    name = "wechat_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "wechat"
    path_markers = ("wechat", "com.tencent.mm", "micromsg")


class LineParser(_GenericAppDbParser):
    name = "line_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "line"
    path_markers = ("jp.naver.line", "/line/")


class TikTokParser(_GenericAppDbParser):
    name = "tiktok_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "tiktok"
    path_markers = ("tiktok", "com.zhiliaoapp.musically", "com.ss.android.ugc.trill")


class LinkedInParser(_GenericAppDbParser):
    name = "linkedin_parser"
    version = "2.1.0"
    domains = ("messaging_apps",)
    app_name = "linkedin"
    path_markers = ("linkedin", "com.linkedin")
