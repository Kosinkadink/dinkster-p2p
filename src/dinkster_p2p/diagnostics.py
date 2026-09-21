"""Bounded observations, never peer authority or transfer progress."""

from __future__ import annotations

import re
import time
from collections import OrderedDict, deque
from ipaddress import ip_address
from typing import Any

MAX_EVENTS = 64
MAX_LISTENERS = 32
MAX_TORRENTS = 68
_MAX_INTEGER = (1 << 63) - 1
_DIGEST = re.compile(r"blake3:[0-9a-f]{64}")
_HASH = re.compile(r"[0-9a-f]{64}")
_ALERTS = {
    "listen_succeeded_alert": "listener_bound",
    "listen_failed_alert": "listener_failed",
    "peer_connect_alert": "peer_connected",
    "peer_disconnected_alert": "peer_disconnected",
    "peer_error_alert": "peer_error",
    "lsd_peer_alert": "lsd_peer_observed",
    "lsd_error_alert": "lsd_error",
    "alerts_dropped_alert": "native_alerts_dropped",
}


def _integer(value: object) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_INTEGER
        else None
    )


def _address(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


class NativeDiagnostics:
    """Single-event-loop history with detached, bounded status snapshots and no I/O."""

    def __init__(self) -> None:
        self._events: deque[dict[str, object]] = deque(maxlen=MAX_EVENTS)
        self._listeners: OrderedDict[tuple[str, int], dict[str, object]] = OrderedDict()
        self._samples: OrderedDict[str, dict[str, object]] = OrderedDict()
        self._configured: set[tuple[str, int]] = set()
        self._sequence = 0
        self._overwritten = 0
        self._malformed = 0
        self._listener_overflow = 0
        self._sample_overflow = 0
        self._native_loss = False

    def _append(self, kind: str, fields: dict[str, object]) -> dict[str, object]:
        self._sequence += 1
        event = {
            "sequence": self._sequence,
            "utcSeconds": time.time(),
            "monotonicSeconds": time.monotonic(),
            "kind": kind,
            **fields,
        }
        if len(self._events) == MAX_EVENTS:
            self._overwritten += 1
        self._events.append(event)
        return dict(event)

    def configure_listeners(self, interfaces: str) -> None:
        configured: set[tuple[str, int]] = set()
        for target in interfaces.split(",")[:MAX_LISTENERS]:
            address, separator, raw_port = target.rpartition(":")
            if separator and (normalized := _address(address)) is not None:
                port = raw_port.removesuffix("l")
                if (
                    len(port) <= 5
                    and port.isascii()
                    and port.isdecimal()
                    and 0 < int(port) <= 65535
                ):
                    configured.add((normalized, int(port)))
        if configured != self._configured:
            self._configured = configured
            for key, event in list(self._listeners.items()):
                if (event["address"], event["port"]) not in configured and (
                    "0.0.0.0",
                    event["port"],
                ) not in configured:
                    del self._listeners[key]
            self._append("listener_configuration_changed", {"configuredCount": len(configured)})

    def selection_failed(self) -> dict[str, object]:
        # Selection errors can contain OS text; native bind events carry numeric detail.
        return self._append("listener_selection_failed", {})

    def observe_alert(
        self, alert: Any, native: Any, digest: str | None
    ) -> dict[str, object] | None:
        kind = next(
            (
                kind
                for name, kind in _ALERTS.items()
                if isinstance(alert, getattr(native, name, ()))
            ),
            None,
        )
        if kind is None:
            return None
        fields: dict[str, object] = {}
        if digest is not None and _DIGEST.fullmatch(digest):
            fields["digest"] = digest
        try:
            if kind.startswith("listener_"):
                address = _address(alert.address)
                port = _integer(alert.port)
            elif kind.startswith("peer_") or kind == "lsd_peer_observed":
                endpoint = alert.ip
                address = _address(endpoint[0])
                port = _integer(endpoint[1])
            else:
                address, port = None, None
            if kind.startswith(("listener_", "peer_")) or kind == "lsd_peer_observed":
                if address is None or port is None or port > 65535:
                    self._malformed += 1
                    return None
                fields.update({"address": address, "port": port})
            for source, target in (
                ("socket_type", "socketType"),
                ("op", "operation"),
                ("reason", "reason"),
            ):
                if (value := _integer(getattr(alert, source, None))) is not None:
                    fields[target] = value
            error = getattr(alert, "error", None)
            if error is not None and (code := _integer(error.value())) is not None:
                fields["errorCode"] = code
        except (AttributeError, IndexError, TypeError, ValueError, RuntimeError):
            self._malformed += 1
            return None
        if kind == "native_alerts_dropped":
            self._native_loss = True
        event = self._append(kind, fields)
        if kind in {"listener_bound", "listener_failed"}:
            assert address is not None and port is not None
            socket_type = _integer(getattr(alert, "socket_type", None))
            if socket_type is not None:
                key = (address, socket_type)
                if kind == "listener_failed":
                    current = self._listeners.get(key)
                    if current is not None and current["port"] == port:
                        del self._listeners[key]
                elif (address, port) in self._configured or ("0.0.0.0", port) in self._configured:
                    if key not in self._listeners and len(self._listeners) == MAX_LISTENERS:
                        self._listeners.popitem(last=False)
                        self._listener_overflow += 1
                    self._listeners[key] = dict(event)
        return event

    def sample_upload(
        self,
        info_hash: str,
        digest: str | None,
        status: Any,
        lan_uploaded: int | None,
        lan_baseline: int | None,
    ) -> None:
        if _HASH.fullmatch(info_hash) is None:
            self._malformed += 1
            return
        fields: dict[str, object] = {
            "infoHash": info_hash,
            "digest": digest if digest is not None and _DIGEST.fullmatch(digest) else None,
            "nativeAllTimeUpload": _integer(getattr(status, "all_time_upload", None)),
            "nativePayloadUpload": _integer(getattr(status, "total_payload_upload", None)),
            "nativePeers": _integer(getattr(status, "num_peers", None)),
            "lanApplicationUploadedBytes": _integer(lan_uploaded),
            "lanTransportUploadSample": _integer(lan_baseline),
        }
        previous = self._samples.get(info_hash)
        if previous is not None and all(
            previous.get(key) == value for key, value in fields.items()
        ):
            return
        event = self._append("upload_sample", fields)
        if info_hash not in self._samples and len(self._samples) == MAX_TORRENTS:
            self._samples.popitem(last=False)
            self._sample_overflow += 1
        self._samples[info_hash] = event
        self._samples.move_to_end(info_hash)

    def stopped(self, digest: str) -> None:
        self._append("torrent_stopped", {"digest": digest})

    def snapshot(self, *, lsd_peer_events_available: bool) -> dict[str, object]:
        return {
            "events": [dict(event) for event in self._events],
            "listeners": [dict(event) for event in self._listeners.values()],
            "uploadSamples": [dict(sample) for sample in self._samples.values()],
            "overwrittenEvents": self._overwritten,
            "malformedEvents": self._malformed,
            "omittedListeners": self._listener_overflow,
            "omittedUploadSamples": self._sample_overflow,
            "nativeAlertLossObserved": self._native_loss,
            "lsdPeerEventsAvailable": lsd_peer_events_available,
        }

    def clear(self) -> None:
        self._events.clear()
        self._listeners.clear()
        self._samples.clear()
        self._configured.clear()
        self._native_loss = False
