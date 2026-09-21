"""Bounded dual-protocol listener selection for the shared session."""

from __future__ import annotations

import errno
import logging
import random
import socket
from collections.abc import Callable

_PROBE_ATTEMPTS = 32
_HANDOFF_ATTEMPTS = 4
_BIND_ERRORS = frozenset({errno.EACCES, errno.EADDRINUSE, 10013, 10048})
_LOG = logging.getLogger(__name__)


def select_listen_port(address: str, excluded: frozenset[int] = frozenset()) -> int:
    # TCP port-zero allocation can walk an entire UDP-excluded Windows range.
    candidates = random.SystemRandom().sample(range(49152, 65536), _PROBE_ATTEMPTS)
    last_error: OSError | None = None
    for port in candidates:
        if port in excluded:
            continue
        try:
            with (
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
            ):
                for probe in (tcp, udp):
                    exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                    if isinstance(exclusive, int):
                        probe.setsockopt(socket.SOL_SOCKET, exclusive, 1)
                    probe.bind((address, port))
                tcp.listen(1)
                return port
        except OSError as error:
            if (
                error.errno not in _BIND_ERRORS
                and getattr(error, "winerror", None) not in _BIND_ERRORS
            ):
                raise
            last_error = error
    raise OSError(f"no dual TCP/UDP listener available on {address}: {last_error}")


class ListenerBindings:
    """Retain ports across policy updates and bound native bind-race recovery."""

    def __init__(self, report_error: Callable[[str], None] = _LOG.error) -> None:
        self._report_error = report_error
        self._template = ""
        self._ports: dict[str, int | None] = {}
        self._attempts: dict[str, int] = {}
        # Native alerts have no generation; reused ports could accept stale successes.
        self._used: set[int] = set()
        self._current_used: set[int] = set()
        self._tcp_bound: set[tuple[str, int]] = set()

    def configure(self, template: str) -> str:
        if template != self._template:
            self._template = template
            self._ports = {}
            self._attempts = {}
            self._current_used.clear()
            self._tcp_bound.clear()
            for target in filter(None, template.split(",")):
                address, _port = target.rsplit(":", 1)
                self._ports[address] = None
                self._attempts[address] = 1
                self._select(address)
        return self.interfaces

    def _select(self, address: str) -> None:
        try:
            port = select_listen_port(address, frozenset(self._used))
        except OSError as error:
            self._report_error(f"P2P listener closed on {address}: {error}")
        else:
            self._ports[address] = port
            self._used.add(port)
            self._current_used.add(port)

    @property
    def interfaces(self) -> str:
        suffix = "l" if self._template.endswith("l") else ""
        return ",".join(
            f"{address}:{port}{suffix}" for address, port in self._ports.items() if port is not None
        )

    @property
    def tcp_endpoints(self) -> tuple[tuple[str, int], ...]:
        return tuple(
            sorted(
                (address, port)
                for address, port in self._tcp_bound
                if self._ports.get(address, self._ports.get("0.0.0.0")) == port
            )
        )

    def tcp_succeeded(self, address: str, port: int) -> None:
        if self._ports.get(address, self._ports.get("0.0.0.0")) == port:
            self._tcp_bound.add((address, port))
            # Reopens and their alerts are ordered. Earlier templates are drained,
            # but current-template retries may still have successes queued.
            self._used = self._current_used.copy()

    def tcp_ready(self, addresses: tuple[str, ...]) -> bool:
        return bool(addresses) and all(
            (address, self._ports.get(address, self._ports.get("0.0.0.0"))) in self._tcp_bound
            for address in addresses
        )

    def failed(self, address: str, port: int, error: int, *, tcp: bool = True) -> bool:
        if tcp:
            self._tcp_bound.discard((address, port))
        if self._ports.get(address) != port:
            return False
        self._tcp_bound.discard((address, port))
        self._ports[address] = None
        if error not in _BIND_ERRORS or self._attempts[address] >= _HANDOFF_ATTEMPTS:
            self._report_error(
                f"P2P listener closed on {address} after native bind failure {error}"
            )
            return True
        self._attempts[address] += 1
        self._select(address)
        return True
