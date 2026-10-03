from __future__ import annotations

from typing import Any

import httpx


class CentralApi:
    def __init__(
        self,
        *,
        base_url: str,
        tenant: str,
        token: str,
        verify_tls: bool = True,
        timeout: float = 60.0,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant": tenant.strip().lower(),
            "Content-Type": "application/json",
        }
        self.verify = verify_tls
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def heartbeat(self, *, version: str | None = None, openvas_ready: bool | None = None) -> dict[str, Any]:
        with httpx.Client(verify=self.verify, timeout=self.timeout) as client:
            r = client.post(
                self._url("/api/scanner-agent/heartbeat"),
                headers=self.headers,
                json={"version": version, "openvas_ready": openvas_ready},
            )
            r.raise_for_status()
            return r.json()

    def next_job(self) -> dict[str, Any] | None:
        with httpx.Client(verify=self.verify, timeout=self.timeout) as client:
            r = client.get(self._url("/api/scanner-agent/jobs/next"), headers=self.headers)
            r.raise_for_status()
            data = r.json()
            return data.get("job")

    def patch_job(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(verify=self.verify, timeout=self.timeout) as client:
            r = client.patch(
                self._url(f"/api/scanner-agent/jobs/{job_id}"),
                headers=self.headers,
                json=payload,
            )
            r.raise_for_status()
            return r.json()

    def upload_results(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(verify=self.verify, timeout=max(self.timeout, 120.0)) as client:
            r = client.post(
                self._url(f"/api/scanner-agent/jobs/{job_id}/results"),
                headers=self.headers,
                json=payload,
            )
            r.raise_for_status()
            return r.json()
