"""Alerts: signed webhooks for the events a catalogue owner must hear about.

Events (payloads carry ids, names, levels and counts, never skill contents):
- version.block_level_addition  a registered version adds a block-level capability over the approved one
- version.promoted / version.rolled_back
- evaluation.finished / evaluation.failed
- fleet.running_unapproved      an installed skill differs from its approved version (catalogue-check)

A tenant admin registers endpoints. Each event becomes a notification per subscribed endpoint and is delivered by a
background deliverer: POST JSON with `X-SkillProof-Event` and `X-SkillProof-Signature: sha256=<HMAC of the body with the
endpoint's secret>`, no redirects followed, retried with back-off (1 min, 5 min, 30 min, 2 h, 6 h) and then marked
failed. `notifications` and `webhooks` have tenant row-level security; `delivery_queue` holds only ids, so the
deliverer finds due work without reading tenant content.
"""
from __future__ import annotations

from skillproof.errors import Conflict, NotFound

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from skillproof.config import settings
from skillproof.logs import log
from skillproof.storage import Database, migrate, tenant_policy

EVENTS = ("version.block_level_addition", "version.promoted", "version.rolled_back", "evaluation.finished",
          "evaluation.failed", "fleet.running_unapproved")
BACKOFF_MINUTES = (1, 5, 30, 120, 360)
SCHEMA = """
    CREATE TABLE IF NOT EXISTS webhooks (
        webhook_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        url TEXT NOT NULL,
        secret TEXT NOT NULL,
        events_json TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        webhook_id TEXT NOT NULL,
        event TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('queued','sent','failed')),
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        created_at TEXT NOT NULL,
        sent_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS delivery_queue (
        notification_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        due_at TEXT NOT NULL
    );
"""


class NotifyError(Conflict):
    """Invalid webhook or notification operation."""


class NotifyNotFound(NotifyError, NotFound):
    """The notify item asked for does not exist in this tenant."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def check_endpoint(url: str, *, resolve: Callable[[str], list[str]] | None = None) -> None:
    """HTTPS only; plain HTTP only to this machine outside production. In production an endpoint whose host resolves
    to a private, loopback or link-local address is refused, so a webhook cannot be aimed at the internal network."""
    parsed = urlparse(url)
    production = settings().production
    host = parsed.hostname or ""
    if parsed.username or parsed.password or not host:
        raise NotifyError("the endpoint must be a URL with a host and no embedded credentials")
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback and not production):
        raise NotifyError("the endpoint must use HTTPS (plain HTTP only to this machine, outside production)")
    if production:
        addresses = (resolve or (lambda h: [i[4][0] for i in socket.getaddrinfo(h, None)]))(host)
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise NotifyError(f"the endpoint resolves to a non-public address ({address})")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect could lead the signed payload somewhere else
        return None


def post(url: str, body: bytes, headers: dict[str, str], timeout: float = 10) -> int:
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


class NotificationStore:
    def __init__(self, database: str | Path):
        self.db = Database(database)
        migrate(self.db, "notify", [(1, "webhooks, notifications and id-only delivery queue", SCHEMA,
                                     SCHEMA + tenant_policy("webhooks") + tenant_policy("notifications"))])

    # ---------------------------------------------------------------------------------------------- webhooks
    def add_webhook(self, tenant_id: str, url: str, events: list[str], *, actor_id: str) -> dict[str, Any]:
        """Register an endpoint. The signing secret is returned once, here; later reads never show it."""
        unknown = sorted(set(events) - set(EVENTS))
        if unknown or not events:
            raise NotifyError(f"events must be a non-empty subset of {', '.join(EVENTS)}; unknown: {', '.join(unknown)}")
        check_endpoint(url)
        webhook_id, secret = str(uuid.uuid4()), secrets.token_hex(32)
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute("INSERT INTO webhooks (webhook_id, tenant_id, url, secret, events_json, created_by, created_at) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?)", (webhook_id, tenant_id, url, secret, json.dumps(sorted(set(events))), actor_id, _stamp(_now())))
        return {**self.webhook(tenant_id, webhook_id), "secret": secret}

    def webhook(self, tenant_id: str, webhook_id: str) -> dict[str, Any]:
        with self.db.transaction(tenant_id) as db:
            row = db.execute("SELECT * FROM webhooks WHERE tenant_id=? AND webhook_id=?", (tenant_id, webhook_id)).fetchone()
        if row is None:
            raise NotifyNotFound("webhook not found in this tenant")
        return {"webhook_id": row["webhook_id"], "url": row["url"], "events": json.loads(row["events_json"]),
                "created_by": row["created_by"], "created_at": row["created_at"]}

    def webhooks(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.db.transaction(tenant_id) as db:
            ids = [r["webhook_id"] for r in db.execute("SELECT webhook_id FROM webhooks WHERE tenant_id=? ORDER BY created_at", (tenant_id,)).fetchall()]
        return [self.webhook(tenant_id, i) for i in ids]

    def remove_webhook(self, tenant_id: str, webhook_id: str) -> None:
        with self.db.transaction(tenant_id, write=True) as db:
            if db.execute("DELETE FROM webhooks WHERE tenant_id=? AND webhook_id=?", (tenant_id, webhook_id)).rowcount == 0:
                raise NotifyNotFound("webhook not found in this tenant")

    # ---------------------------------------------------------------------------------------------- events
    def emit(self, tenant_id: str, event: str, payload: dict[str, Any]) -> int:
        """Queue the event for every endpoint of the tenant subscribed to it. Returns how many were queued."""
        if event not in EVENTS:
            raise NotifyError(f"unknown event {event}")
        now = _stamp(_now())
        body = {"event": event, "tenant_id": tenant_id, "occurred_at": now, **payload}
        queued = []
        with self.db.transaction(tenant_id, write=True) as db:
            for row in db.execute("SELECT webhook_id, events_json FROM webhooks WHERE tenant_id=?", (tenant_id,)).fetchall():
                if event in json.loads(row["events_json"]):
                    notification_id = str(uuid.uuid4())
                    db.execute("INSERT INTO notifications (notification_id, tenant_id, webhook_id, event, payload_json, state, created_at) "
                               "VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                               (notification_id, tenant_id, row["webhook_id"], event, json.dumps({**body, "notification_id": notification_id}), now))
                    queued.append(notification_id)
        if queued:
            with self.db.transaction(None, write=True) as db:
                for notification_id in queued:
                    db.execute("INSERT INTO delivery_queue (notification_id, tenant_id, due_at) VALUES (?, ?, ?)", (notification_id, tenant_id, now))
        return len(queued)

    def notifications(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.transaction(tenant_id) as db:
            rows = db.execute("SELECT notification_id, webhook_id, event, state, attempts, last_error, created_at, sent_at "
                              "FROM notifications WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?", (tenant_id, min(limit, 500))).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------------------------------------- delivery
    def deliver_once(self, sender: Callable[[str, bytes, dict[str, str]], int] = post) -> dict[str, Any] | None:
        """Deliver the next due notification. Returns what happened, or None when nothing is due."""
        now = _now()
        with self.db.transaction(None, write=True) as db:
            due = db.execute("SELECT notification_id, tenant_id FROM delivery_queue WHERE due_at <= ? ORDER BY due_at, notification_id LIMIT 1",
                             (_stamp(now),)).fetchone()
            if due is None:
                return None
            # Claim it by moving it out of reach while it is sent; a failure puts it back with its next time.
            db.execute("UPDATE delivery_queue SET due_at=? WHERE notification_id=?", (_stamp(now + timedelta(minutes=10)), due["notification_id"]))
        tenant_id, notification_id = due["tenant_id"], due["notification_id"]
        with self.db.transaction(tenant_id) as db:
            note = db.execute("SELECT * FROM notifications WHERE notification_id=?", (notification_id,)).fetchone()
            hook = db.execute("SELECT * FROM webhooks WHERE webhook_id=?", (note["webhook_id"],)).fetchone() if note else None
        if note is None or hook is None:  # the endpoint was removed
            self._settle(tenant_id, notification_id, "failed", note["attempts"] if note else 0, "endpoint removed")
            return {"notification_id": notification_id, "state": "failed", "reason": "endpoint removed"}
        body = note["payload_json"].encode()
        attempts = note["attempts"] + 1
        try:
            check_endpoint(hook["url"])
            status = sender(hook["url"], body, {"X-SkillProof-Event": note["event"], "X-SkillProof-Delivery": notification_id,
                                                "X-SkillProof-Signature": sign(hook["secret"], body)})
            error = None if 200 <= status < 300 else f"HTTP {status}"
        except (OSError, NotifyError, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"[:500]
        if error is None:
            self._settle(tenant_id, notification_id, "sent", attempts, None)
            return {"notification_id": notification_id, "state": "sent", "attempts": attempts}
        if attempts > len(BACKOFF_MINUTES):
            self._settle(tenant_id, notification_id, "failed", attempts, error)
            return {"notification_id": notification_id, "state": "failed", "attempts": attempts, "error": error}
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute("UPDATE notifications SET attempts=?, last_error=? WHERE notification_id=?", (attempts, error, notification_id))
        with self.db.transaction(None, write=True) as db:
            db.execute("UPDATE delivery_queue SET due_at=? WHERE notification_id=?",
                       (_stamp(now + timedelta(minutes=BACKOFF_MINUTES[attempts - 1])), notification_id))
        return {"notification_id": notification_id, "state": "queued", "attempts": attempts, "error": error}

    def _settle(self, tenant_id: str, notification_id: str, state: str, attempts: int, error: str | None) -> None:
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute("UPDATE notifications SET state=?, attempts=?, last_error=?, sent_at=? WHERE notification_id=?",
                       (state, attempts, error, _stamp(_now()) if state == "sent" else None, notification_id))
        with self.db.transaction(None, write=True) as db:
            db.execute("DELETE FROM delivery_queue WHERE notification_id=?", (notification_id,))

    def close(self) -> None:
        self.db.close()


def start_deliverer(store_factory: Callable[[], NotificationStore | None], stop: threading.Event, idle_seconds: float = 5.0) -> threading.Thread:
    def loop() -> None:
        store = store_factory()
        if store is None:
            return
        while not stop.is_set():
            outcome = store.deliver_once()
            if outcome is None:
                stop.wait(idle_seconds)
            else:
                log("alert_delivery", logging.INFO if outcome["state"] != "failed" else logging.WARNING,
                    notification_id=outcome["notification_id"], state=outcome["state"], attempts=outcome.get("attempts"),
                    error=outcome.get("error") or outcome.get("reason"))
    thread = threading.Thread(target=loop, name="skillproof-webhooks", daemon=True)
    thread.start()
    return thread
