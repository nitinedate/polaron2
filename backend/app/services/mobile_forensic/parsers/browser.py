"""Browser history / bookmarks parser (Chrome, Safari)."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import epoch_to_iso, iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class BrowserHistoryParser(ArtifactParser):
    name = "browser_parser"
    version = "2.0.0"
    domains = ("browser",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return (
            name in {"history", "browser2.db", "history.db", "bookmarks.db"}
            or ("/chrome/" in p and name in {"history", "history-journal"})
            or ("safari" in p and name.endswith((".db", ".sqlite")))
            or name == "history.plist"
        )

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        if item.path.lower().endswith(".plist"):
            yield NormalizedArtifact.create(
                artifact_type="browser_source", source_domain="browser",
                data={"artifact_family": "browser", "path": item.path, "format": "plist"},
                state="allocated", source_path=item.path, source_sha256=item.sha256,
                parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
            )
            return
        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            if "urls" in tables:
                sql = "SELECT id, url, title, last_visit_time AS ts, visit_count FROM urls ORDER BY last_visit_time DESC"
                for r in iter_query(conn, sql):
                    ts = r.get("ts")
                    try:
                        n = int(ts)
                        if n > 10_000_000_000_000:
                            ts = (n // 1_000_000) - 11644473600
                    except (TypeError, ValueError):
                        pass
                    yield NormalizedArtifact.create(
                        artifact_type="browser_visit", source_domain="browser",
                        data={"artifact_family": "browser_history", "url": r.get("url"), "title": r.get("title"), "visit_count": r.get("visit_count")},
                        timestamp_utc=epoch_to_iso(ts), state="allocated", source_path=item.path,
                        source_table="urls", source_row_id=str(r.get("id") or ""), source_sha256=item.sha256,
                        parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
                    )
            elif "history" in tables:
                for r in iter_query(conn, "SELECT rowid AS __row_id, * FROM history"):
                    yield NormalizedArtifact.create(
                        artifact_type="browser_visit", source_domain="browser",
                        data={"artifact_family": "browser_history", "raw": {str(k): v for k, v in list(r.items())[:30] if not isinstance(v, (bytes, bytearray))}},
                        state="allocated", source_path=item.path, source_table="history",
                        source_row_id=str(r.get("__row_id") or ""), source_sha256=item.sha256,
                        parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
                    )
