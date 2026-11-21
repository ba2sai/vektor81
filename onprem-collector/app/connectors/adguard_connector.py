"""Live AdGuard Home DNS connector for Shadow AI telemetry and health checks."""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

AI_DOMAINS_FILE = Path(__file__).resolve().parent.parent / "ai_domains.json"


def load_ai_domains_dictionary(domains_file: Path = AI_DOMAINS_FILE) -> Dict[str, str]:
    """Load local dictionary of 150+ Shadow AI domains mapped to risk categories."""
    if domains_file.exists():
        with open(domains_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return {str(k).lower().strip(): str(v) for k, v in data.items()}
    return {
        "chatgpt.com": "LLM Conversacional",
        "claude.ai": "LLM Conversacional",
        "deepseek.com": "LLM Conversacional",
        "ilovepdf.com": "Procesamiento PDF / Docs",
        "perplexity.ai": "Buscador IA",
    }


AI_DOMAINS_MAP: Dict[str, str] = load_ai_domains_dictionary()


def match_shadow_ai_domain(
    qname: str, domains_map: Optional[Dict[str, str]] = None
) -> Optional[Tuple[str, str]]:
    """Match an inspected FQDN against the Shadow AI domain dictionary."""
    lookup = domains_map or AI_DOMAINS_MAP
    clean = qname.lower().strip().rstrip(".")
    if not clean:
        return None
    if clean in lookup:
        return clean, lookup[clean]
    for registered_domain, category in lookup.items():
        if clean.endswith("." + registered_domain):
            return registered_domain, category
    return None


class AdGuardConnector:
    """Queries AdGuard Home /control/status and /control/querylog without masking outages."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout_seconds: float = 3.0,
        domains_map: Optional[Dict[str, str]] = None,
    ):
        self.base_url = (base_url or os.getenv("ADGUARD_URL", "http://adguard:3000")).rstrip("/")
        self.username = username if username is not None else os.getenv("ADGUARD_USER", "admin")
        self.password = password if password is not None else os.getenv("ADGUARD_PASS", "")
        self.timeout_seconds = timeout_seconds
        self.domains_map = domains_map or AI_DOMAINS_MAP

    def _auth(self) -> Optional[Tuple[str, str]]:
        if self.username and self.password:
            return (self.username, self.password)
        return None

    async def probe_status(
        self, client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """Probe /control/status and report ONLINE / DEGRADED / OFFLINE with latency_ms."""
        start = time.perf_counter()
        owns_client = client is None
        http_client = client or httpx.AsyncClient(timeout=self.timeout_seconds)
        try:
            resp = await http_client.get(f"{self.base_url}/control/status", auth=self._auth())
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            if resp.status_code == 200:
                status_val = "DEGRADED" if latency_ms >= 2000 else "ONLINE"
                body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                return {
                    "adguard_status": status_val,
                    "adguard_live_connected": True,
                    "latency_ms": latency_ms,
                    "last_error": "High latency >= 2000ms" if status_val == "DEGRADED" else None,
                    "protection_enabled": body.get("protection_enabled"),
                    "version": body.get("version"),
                }
            return {
                "adguard_status": "DEGRADED" if resp.status_code < 500 else "OFFLINE",
                "adguard_live_connected": False,
                "latency_ms": latency_ms,
                "last_error": f"AdGuard /control/status returned HTTP {resp.status_code}",
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            return {
                "adguard_status": "OFFLINE",
                "adguard_live_connected": False,
                "latency_ms": latency_ms,
                "last_error": f"AdGuard unreachable at {self.base_url}: {exc}",
            }
        finally:
            if owns_client:
                await http_client.aclose()

    async def fetch_querylog_stats(
        self,
        tenant_id: str = "default-tenant",
        limit: int = 500,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Fetch /control/querylog, classify Shadow AI queries, and report honest status."""
        start = time.perf_counter()
        owns_client = client is None
        http_client = client or httpx.AsyncClient(timeout=self.timeout_seconds)

        by_client_ip: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"total_hits": 0, "domains": defaultdict(int)}
        )
        by_category: Dict[str, int] = defaultdict(int)
        by_domain: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "category": "", "blocked_hits": 0}
        )
        grouped_events: Dict[Tuple[str, str, bool], Dict[str, Any]] = {}

        total_inspected = 0
        adguard_status = "OFFLINE"
        adguard_live = False
        last_error: Optional[str] = None
        latency_ms: float = 0.0

        try:
            status_info = await self.probe_status(client=http_client)
            adguard_status = status_info["adguard_status"]
            last_error = status_info["last_error"]

            resp = await http_client.get(
                f"{self.base_url}/control/querylog",
                params={"limit": limit},
                auth=self._auth(),
            )
            latency_ms = round((time.perf_counter() - start) * 1000, 1)

            if resp.status_code == 200:
                adguard_live = True
                adguard_status = "DEGRADED" if latency_ms >= 2000 else "ONLINE"
                last_error = "High latency >= 2000ms" if adguard_status == "DEGRADED" else None
                payload = resp.json()
                entries = payload.get("data", []) if isinstance(payload, dict) else []
                total_inspected = len(entries)

                for entry in entries:
                    question = entry.get("question") or {}
                    qname = str(question.get("name") or "")
                    client_ip = str(entry.get("client") or "unknown")
                    rules = entry.get("rules") or []
                    reason = str(entry.get("reason") or "")
                    is_blocked = bool(rules) or "Filtered" in reason or "Blocked" in reason
                    ts = entry.get("time") or datetime.now(timezone.utc).isoformat()

                    matched = match_shadow_ai_domain(qname, self.domains_map)
                    if not matched:
                        continue

                    canonical_dom, category = matched
                    by_client_ip[client_ip]["total_hits"] += 1
                    by_client_ip[client_ip]["domains"][canonical_dom] += 1
                    by_category[category] += 1
                    by_domain[canonical_dom]["count"] += 1
                    by_domain[canonical_dom]["category"] = category
                    if is_blocked:
                        by_domain[canonical_dom]["blocked_hits"] += 1

                    ev_key = (client_ip, canonical_dom, is_blocked)
                    if ev_key not in grouped_events:
                        grouped_events[ev_key] = {
                            "client_ip": client_ip,
                            "domain": canonical_dom,
                            "category": category,
                            "hits": 1,
                            "blocked": is_blocked,
                            "timestamp": ts,
                        }
                    else:
                        grouped_events[ev_key]["hits"] += 1
                        grouped_events[ev_key]["timestamp"] = ts
            else:
                adguard_live = False
                if adguard_status == "ONLINE":
                    adguard_status = "DEGRADED"
                last_error = f"AdGuard /control/querylog returned HTTP {resp.status_code}"
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            adguard_live = False
            adguard_status = "OFFLINE"
            last_error = f"AdGuard unreachable at {self.base_url}: {exc}"
        finally:
            if owns_client:
                await http_client.aclose()

        formatted_clients = [
            {
                "client": client_key,
                "total_hits": info["total_hits"],
                "domains": [
                    {"domain": d, "count": c}
                    for d, c in sorted(info["domains"].items(), key=lambda x: -x[1])
                ],
            }
            for client_key, info in sorted(
                by_client_ip.items(), key=lambda x: -x[1]["total_hits"]
            )
        ]

        formatted_domains = [
            {
                "domain": dom,
                "count": info["count"],
                "category": info["category"],
                "blocked_hits": info["blocked_hits"],
            }
            for dom, info in sorted(by_domain.items(), key=lambda x: -x[1]["count"])
        ]

        formatted_categories = [
            {"category": cat, "count": cnt}
            for cat, cnt in sorted(by_category.items(), key=lambda x: -x[1])
        ]

        events_list = list(grouped_events.values())

        return {
            "adguard_status": adguard_status,
            "adguard_live_connected": adguard_live,
            "latency_ms": latency_ms,
            "last_error": last_error,
            "adguard_endpoint": f"{self.base_url}/control/querylog",
            "dictionary_domains_loaded": len(self.domains_map),
            "total_queries_inspected": total_inspected,
            "shadow_ai_hits_total": sum(d["count"] for d in formatted_domains),
            "by_client_ip": formatted_clients,
            "by_category": formatted_categories,
            "top_domains": formatted_domains[:15],
            "shadow_ai_batch": {
                "tenant_id": tenant_id,
                "source": "ADGUARD_DNS",
                "total_queries_inspected": total_inspected,
                "events": events_list,
            },
        }
