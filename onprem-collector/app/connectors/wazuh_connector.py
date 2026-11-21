"""Decoupled REST API client for optional Wazuh FIM telemetry (GPLv2-safe)."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import httpx


class WazuhConnector:
    """
    Interacts strictly with external Wazuh Manager REST API over HTTP/HTTPS.
    Zero GPL-licensed Wazuh libraries or source code are linked or imported.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        timeout_seconds: float = 3.0,
    ):
        self.api_url = (
            api_url if api_url is not None else os.getenv("WAZUH_API_URL", "")
        ).strip().rstrip("/")
        self.username = username if username is not None else os.getenv("WAZUH_API_USER", "")
        self.password = password if password is not None else os.getenv("WAZUH_API_PASS", "")
        if verify_tls is None:
            self.verify_tls = os.getenv("WAZUH_VERIFY_TLS", "true").lower() == "true"
        else:
            self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds

    @property
    def is_configured(self) -> bool:
        return bool(self.api_url)

    async def probe(self, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Probe Wazuh Manager API health and recent FIM summary."""
        if not self.is_configured:
            return {
                "configured": False,
                "status": "OFFLINE",
                "latency_ms": 0.0,
                "last_error": "Wazuh API not configured (WAZUH_API_URL unset)",
                "agents_active": 0,
                "fim_events_summary": {},
            }

        start = time.perf_counter()
        owns_client = client is None
        http_client = client or httpx.AsyncClient(
            timeout=self.timeout_seconds, verify=self.verify_tls
        )
        try:
            headers: Dict[str, str] = {}
            if self.username and self.password:
                auth_resp = await http_client.post(
                    f"{self.api_url}/security/user/authenticate",
                    auth=(self.username, self.password),
                )
                if auth_resp.status_code != 200:
                    latency_ms = round((time.perf_counter() - start) * 1000, 1)
                    return {
                        "configured": True,
                        "status": "DEGRADED",
                        "latency_ms": latency_ms,
                        "last_error": f"Wazuh auth failed with HTTP {auth_resp.status_code}",
                        "agents_active": 0,
                        "fim_events_summary": {},
                    }
                token = (auth_resp.json().get("data") or {}).get("token")
                if token:
                    headers["Authorization"] = f"Bearer {token}"

            info_resp = await http_client.get(f"{self.api_url}/manager/info", headers=headers)
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            if info_resp.status_code != 200:
                return {
                    "configured": True,
                    "status": "DEGRADED" if info_resp.status_code < 500 else "OFFLINE",
                    "latency_ms": latency_ms,
                    "last_error": f"Wazuh /manager/info returned HTTP {info_resp.status_code}",
                    "agents_active": 0,
                    "fim_events_summary": {},
                }

            agents_active = 0
            try:
                agents_resp = await http_client.get(
                    f"{self.api_url}/agents/summary/status", headers=headers
                )
                if agents_resp.status_code == 200:
                    conn_data = (agents_resp.json().get("data") or {}).get("connection") or {}
                    agents_active = int(conn_data.get("active", 0))
            except Exception:
                pass

            return {
                "configured": True,
                "status": "DEGRADED" if latency_ms >= 2000 else "ONLINE",
                "latency_ms": latency_ms,
                "last_error": None,
                "agents_active": agents_active,
                "fim_events_summary": {"manager_reachable": True},
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            return {
                "configured": True,
                "status": "OFFLINE",
                "latency_ms": latency_ms,
                "last_error": f"Wazuh API unreachable at {self.api_url}: {exc}",
                "agents_active": 0,
                "fim_events_summary": {},
            }
        finally:
            if owns_client:
                await http_client.aclose()
