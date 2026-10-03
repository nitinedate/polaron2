"""Plugin contracts for mobile artifact parsers and recovery analyzers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Iterable, Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact

log = logging.getLogger("mobile_forensic.plugins")


class ParseContext:
    """Read-only parse context shared across domain parsers."""

    def __init__(
        self,
        *,
        job_id: str,
        platform: str,
        source_id: str | None = None,
        whatsapp_key_hex: str | None = None,
        signal_db_key_hex: str | None = None,
        ios_backup_password: str | None = None,
        root_paths: list[str] | None = None,
        read_bytes: Any | None = None,
        db: Any | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.job_id = job_id
        self.platform = (platform or "Android").strip()
        self.source_id = source_id
        self.whatsapp_key_hex = whatsapp_key_hex
        self.signal_db_key_hex = signal_db_key_hex
        self.ios_backup_password = ios_backup_password
        self.root_paths = list(root_paths or [])
        self._read_bytes = read_bytes
        self.db = db
        self.extra = dict(extra or {})

    def read_artifact_bytes(self, path: str, *, max_bytes: int = 120_000_000) -> bytes | None:
        if callable(self._read_bytes):
            try:
                return self._read_bytes(path, max_bytes=max_bytes)
            except TypeError:
                return self._read_bytes(path)
            except Exception:
                return None
        return None


class ArtifactParser(ABC):
    name: str = "base"
    version: str = "1.0.0"
    domains: tuple[str, ...] = ()

    @abstractmethod
    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        ...

    @abstractmethod
    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        ...


class RecoveryAnalyzer(ABC):
    name: str = "base_recovery"
    version: str = "1.0.0"

    @abstractmethod
    def analyze(
        self,
        items: list[InventoryItem],
        parsed: list[NormalizedArtifact],
        context: ParseContext,
    ) -> Iterator[NormalizedArtifact]:
        ...


class PluginRegistry:
    def __init__(self) -> None:
        self._parsers: list[ArtifactParser] = []
        self._recovery: list[RecoveryAnalyzer] = []

    def register_parser(self, parser: ArtifactParser) -> None:
        self._parsers.append(parser)
        log.debug("registered parser %s@%s", parser.name, parser.version)

    def register_recovery(self, analyzer: RecoveryAnalyzer) -> None:
        self._recovery.append(analyzer)

    @property
    def parsers(self) -> list[ArtifactParser]:
        return list(self._parsers)

    @property
    def recovery_analyzers(self) -> list[RecoveryAnalyzer]:
        return list(self._recovery)

    def route(self, item: InventoryItem, context: ParseContext) -> list[ArtifactParser]:
        return [p for p in self._parsers if p.supports(item, context)]


_REGISTRY: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PluginRegistry()
        _register_builtin_plugins(_REGISTRY)
    return _REGISTRY


def reset_plugin_registry_for_tests() -> None:
    global _REGISTRY
    _REGISTRY = None


def _register_builtin_plugins(reg: PluginRegistry) -> None:
    from app.services.mobile_forensic.parsers.browser import BrowserHistoryParser
    from app.services.mobile_forensic.parsers.calendar_notes import CalendarNotesParser
    from app.services.mobile_forensic.parsers.contacts import ContactsParser
    from app.services.mobile_forensic.parsers.device_os import DeviceOsParser
    from app.services.mobile_forensic.parsers.files_media import FilesMediaParser
    from app.services.mobile_forensic.parsers.location import LocationParser
    from app.services.mobile_forensic.parsers.messaging import (
        DiscordParser,
        InstagramParser,
        LineParser,
        LinkedInParser,
        MessengerParser,
        SignalParser,
        SnapchatParser,
        TelegramParser,
        TikTokParser,
        ViberParser,
        WeChatParser,
        WhatsAppParser,
    )
    from app.services.mobile_forensic.parsers.sms_calls import SmsCallsParser
    from app.services.mobile_forensic.parsers.system_network import SystemNetworkParser
    from app.services.mobile_forensic.recovery.analyzers import (
        CacheThumbnailAnalyzer,
        OrphanMediaAnalyzer,
        SqliteHistoryAnalyzer,
        TrashPathAnalyzer,
    )

    for p in (
        DeviceOsParser(),
        ContactsParser(),
        SmsCallsParser(),
        WhatsAppParser(),
        TelegramParser(),
        SignalParser(),
        MessengerParser(),
        InstagramParser(),
        SnapchatParser(),
        DiscordParser(),
        ViberParser(),
        WeChatParser(),
        LineParser(),
        TikTokParser(),
        LinkedInParser(),
        FilesMediaParser(),
        BrowserHistoryParser(),
        LocationParser(),
        CalendarNotesParser(),
        SystemNetworkParser(),
    ):
        reg.register_parser(p)
    for a in (
        SqliteHistoryAnalyzer(),
        OrphanMediaAnalyzer(),
        TrashPathAnalyzer(),
        CacheThumbnailAnalyzer(),
    ):
        reg.register_recovery(a)
