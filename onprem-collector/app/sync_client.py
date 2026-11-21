"""Store-and-forward sync client pushing anonymized batches and heartbeats to Control Plane."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from .health_monitor import collect_health_snapshot
from .models import PendingSyncQueue
from .pii_bridge import mask_pii_value


def sanitize_endpoint_payload_for_control_plane(
    tenant_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert local endpoint ingest payload into Control Plane EndpointIngestSchema,
    ensuring any sample filenames or identifiers are strictly masked.
    """
    box_raw = payload.get("box_audit") or {}
    raw_box_samples = box_raw.get("sample_files_masked") or box_raw.get("sample_files") or []
    masked_box_samples = [
        mask_pii_value(str(name)) if len(str(name)) > 6 else "***"
        for name in raw_box_samples
    ]

    onedrive_raw = payload.get("onedrive_audit")
    onedrive_clean = None
    if isinstance(onedrive_raw, dict):
        raw_od_samples = (
            onedrive_raw.get("sample_files_masked") or onedrive_raw.get("sample_files") or []
        )
        onedrive_clean = {
            "provider": onedrive_raw.get("provider") or "OneDrive",
            "installed": bool(onedrive_raw.get("installed", False)),
            "sync_path": onedrive_raw.get("sync_path"),
            "total_synced_files": int(onedrive_raw.get("total_synced_files", 0)),
            "sensitive_files_count": int(onedrive_raw.get("sensitive_files_count", 0)),
            "dlp_enabled": bool(onedrive_raw.get("dlp_enabled", False)),
            "sample_files_masked": [
                mask_pii_value(str(name)) if len(str(name)) > 6 else "***"
                for name in raw_od_samples
            ],
        }

    return {
        "tenant_id": tenant_id,
        "hostname": str(payload.get("hostname", "")).strip().upper(),
        "username": str(payload.get("username", "")),
        "ip_address": payload.get("ip_address"),
        "os_version": payload.get("os_version") or "Windows 11 Pro",
        "agent_version": payload.get("agent_version") or "2.0.0",
        "shadow_ai_dns_hits": payload.get("shadow_ai_dns_hits") or [],
        "risky_extensions": payload.get("risky_extensions") or [],
        "box_audit": {
            "provider": box_raw.get("provider") or "BoxDrive",
            "installed": bool(box_raw.get("installed", False)),
            "sync_path": box_raw.get("sync_path"),
            "total_synced_files": int(box_raw.get("total_synced_files", 0)),
            "sensitive_files_count": int(box_raw.get("sensitive_files_count", 0)),
            "dlp_enabled": bool(box_raw.get("dlp_enabled", False)),
            "sample_files_masked": masked_box_samples,
        },
        "onedrive_audit": onedrive_clean,
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    }


class ControlPlaneSyncClient:
    """HTTP sync client with SQLite PendingSyncQueue persistence for offline resilience."""

    def __init__(
        self,
        control_plane_url: Optional[str] = None,
        collector_token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout_seconds: float = 5.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.control_plane_url = (
            control_plane_url
            if control_plane_url is not None
            else os.getenv("CONTROL_PLANE_URL", "")
        ).strip().rstrip("/")
        self.collector_token = (
            collector_token
            if collector_token is not None
            else os.getenv("COLLECTOR_TOKEN", "")
        ).strip()
        self.tenant_id = (
            tenant_id if tenant_id is not None else os.getenv("TENANT_ID", "default-tenant")
        ).strip() or "default-tenant"
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    @property
    def is_configured(self) -> bool:
        return bool(self.control_plane_url and self.collector_token)

    def _headers(self, tenant_id: Optional[str] = None) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.collector_token}",
            "X-Tenant-Id": tenant_id or self.tenant_id,
            "Content-Type": "application/json",
        }

    def _build_client(self) -> httpx.AsyncClient:
        kwargs: Dict[str, Any] = {"timeout": self.timeout_seconds}
        if self.transport is not None:
            kwargs["transport"] = self.transport
        return httpx.AsyncClient(**kwargs)

    def enqueue_payload(
        self,
        db: Session,
        endpoint_path: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        error: Optional[str] = None,
        attempts: int = 1,
    ) -> PendingSyncQueue:
        """Persist an unsent anonymized batch into SQLite PendingSyncQueue."""
        now = datetime.now(timezone.utc)
        backoff_sec = min(300, 15 * (2 ** max(0, attempts - 1)))
        item = PendingSyncQueue(
            tenant_id=tenant_id or str(payload.get("tenant_id") or self.tenant_id),
            endpoint_path=endpoint_path,
            payload_json=payload,
            attempts=attempts,
            last_error=error,
            status="PENDING",
            created_at=now,
            next_retry_at=now + timedelta(seconds=backoff_sec),
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item

    async def _post_payload(
        self,
        http_client: httpx.AsyncClient,
        endpoint_path: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> TupleResult:
        url = f"{self.control_plane_url}{endpoint_path}"
        resp = await http_client.post(
            url,
            json=payload,
            headers=self._headers(tenant_id=tenant_id),
        )
        if 200 <= resp.status_code < 300:
            return True, resp.status_code, None
        return False, resp.status_code, f"HTTP {resp.status_code}: {resp.text[:250]}"

    async def send_or_queue(
        self,
        db: Session,
        endpoint_path: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Attempt immediate Control Plane push; enqueue in SQLite if unconfigured or unreachable."""
        resolved_tenant = tenant_id or str(payload.get("tenant_id") or self.tenant_id)
        if not self.is_configured:
            err = "Control Plane sync unconfigured (CONTROL_PLANE_URL or COLLECTOR_TOKEN missing)"
            queued = self.enqueue_payload(
                db, endpoint_path, payload, tenant_id=resolved_tenant, error=err, attempts=0
            )
            return {"sent": False, "queued": True, "queue_id": queued.id, "error": err}

        owns_client = client is None
        http_client = client or self._build_client()
        try:
            ok, status_code, err = await self._post_payload(
                http_client, endpoint_path, payload, tenant_id=resolved_tenant
            )
            if ok:
                return {"sent": True, "queued": False, "status_code": status_code, "error": None}
            queued = self.enqueue_payload(
                db, endpoint_path, payload, tenant_id=resolved_tenant, error=err, attempts=1
            )
            return {
                "sent": False,
                "queued": True,
                "queue_id": queued.id,
                "status_code": status_code,
                "error": err,
            }
        except Exception as exc:
            err = f"Control Plane push error: {exc}"
            queued = self.enqueue_payload(
                db, endpoint_path, payload, tenant_id=resolved_tenant, error=err, attempts=1
            )
            return {"sent": False, "queued": True, "queue_id": queued.id, "error": err}
        finally:
            if owns_client:
                await http_client.aclose()

    async def flush_queue(
        self,
        db: Session,
        limit: int = 100,
        ignore_backoff: bool = True,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """Retry and flush pending queued batches in chronological FIFO order."""
        now = datetime.now(timezone.utc)
        pending_items: List[PendingSyncQueue] = (
            db.query(PendingSyncQueue)
            .filter(PendingSyncQueue.status == "PENDING")
            .order_by(PendingSyncQueue.id.asc())
            .limit(limit)
            .all()
        )

        if not self.is_configured:
            return {
                "flushed": 0,
                "failed": 0,
                "remaining": len(pending_items),
                "errors": ["CONTROL_PLANE_URL or COLLECTOR_TOKEN not configured"],
            }

        flushed = 0
        failed = 0
        errors: List[str] = []

        owns_client = client is None
        http_client = client or self._build_client()
        try:
            for item in pending_items:
                if not ignore_backoff and item.next_retry_at is not None:
                    next_retry = item.next_retry_at
                    if next_retry.tzinfo is None:
                        next_retry = next_retry.replace(tzinfo=timezone.utc)
                    if next_retry > now:
                        continue

                try:
                    ok, _code, err = await self._post_payload(
                        http_client,
                        item.endpoint_path,
                        item.payload_json,
                        tenant_id=item.tenant_id,
                    )
                    if ok:
                        item.status = "SENT"
                        item.sent_at = datetime.now(timezone.utc)
                        item.last_error = None
                        flushed += 1
                    else:
                        item.attempts += 1
                        item.last_error = err
                        item.next_retry_at = datetime.now(timezone.utc) + timedelta(
                            seconds=min(300, 15 * (2 ** max(0, item.attempts - 1)))
                        )
                        failed += 1
                        if err:
                            errors.append(err)
                except Exception as exc:
                    err = f"Retry failed for queue#{item.id}: {exc}"
                    item.attempts += 1
                    item.last_error = err
                    item.next_retry_at = datetime.now(timezone.utc) + timedelta(
                        seconds=min(300, 15 * (2 ** max(0, item.attempts - 1)))
                    )
                    failed += 1
                    errors.append(err)
            db.commit()
        finally:
            if owns_client:
                await http_client.aclose()

        remaining = (
            db.query(PendingSyncQueue).filter(PendingSyncQueue.status == "PENDING").count()
        )
        return {
            "flushed": flushed,
            "failed": failed,
            "remaining": remaining,
            "errors": errors[:20],
        }

    async def sync_once(
        self,
        db: Session,
        include_heartbeats: bool = True,
        health_snapshot: Optional[Dict[str, Any]] = None,
        extra_batches: Optional[List[tuple[str, Dict[str, Any]]]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """
        Execute one full deterministic sync cycle:
        1. Flush existing PendingSyncQueue items.
        2. Push any new extra_batches (or queue on failure).
        3. Push fresh component heartbeats (or queue on failure).
        """
        owns_client = client is None
        http_client = client or self._build_client()
        try:
            flush_result = await self.flush_queue(db, ignore_backoff=True, client=http_client)

            sent_now = 0
            queued_now = 0
            errors: List[str] = list(flush_result["errors"])

            for path, batch_payload in extra_batches or []:
                res = await self.send_or_queue(
                    db, path, batch_payload, tenant_id=self.tenant_id, client=http_client
                )
                if res["sent"]:
                    sent_now += 1
                else:
                    queued_now += 1
                    if res.get("error"):
                        errors.append(res["error"])

            heartbeats_pushed = 0
            if include_heartbeats:
                snapshot = health_snapshot or await collect_health_snapshot(
                    db, tenant_id=self.tenant_id
                )
                for hb in snapshot.get("heartbeats", []):
                    res = await self.send_or_queue(
                        db,
                        "/api/v2/health/heartbeat",
                        hb,
                        tenant_id=hb.get("tenant_id", self.tenant_id),
                        client=http_client,
                    )
                    if res["sent"]:
                        sent_now += 1
                        heartbeats_pushed += 1
                    else:
                        queued_now += 1
                        if res.get("error"):
                            errors.append(res["error"])

            remaining = (
                db.query(PendingSyncQueue).filter(PendingSyncQueue.status == "PENDING").count()
            )
            return {
                "ok": len(errors) == 0,
                "control_plane_configured": self.is_configured,
                "flushed_from_queue": flush_result["flushed"],
                "sent_new": sent_now,
                "queued_new": queued_now,
                "heartbeats_pushed": heartbeats_pushed,
                "pending_queue_remaining": remaining,
                "errors": errors[:20],
            }
        finally:
            if owns_client:
                await http_client.aclose()


TupleResult = tuple[bool, int, Optional[str]]
