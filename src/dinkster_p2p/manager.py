"""Host ownership, lifecycle, and IPC client for the libtorrent sidecar."""

# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from dinkster_assets import P2P_FORMAT_POLICY_VERSION, AssetError, AssetVault
from dinkster_workers.boundary import BoundaryError, read_frame, write_frame
from dinkster_workers.transport import BoundaryListener, TransportChoice

from .artifacts import LIBTORRENT_VERSION
from .contracts import DownloadLease, SeedLease
from .global_leases import AuthorizedGlobalLease
from .runtime import IPC_VERSION
from .settings import default_p2p_settings, normalize_p2p_settings

# Startup and control operations can verify or persist the configured seed set.
_CONNECT_TIMEOUT_SECONDS = 4 * 60 * 60.0
_REQUEST_TIMEOUT_SECONDS = 4 * 60 * 60.0
_STOP_TIMEOUT_SECONDS = 10.0
_RESTART_LIMIT = 3
_RESTART_WINDOW_SECONDS = 60.0
_RESTART_BACKOFF_SECONDS = (0.25, 1.0, 3.0)
_GLOBAL_NETWORK_COSTS = frozenset({"metered", "unmetered", "unknown"})


class P2PManagerError(RuntimeError):
    """The host could not complete a sidecar operation."""


class P2PManagerConflict(P2PManagerError):
    """The requested operation conflicts with the transfer state."""


class P2PManagerNotFound(P2PManagerError):
    """The requested transfer does not exist."""


class _P2PTransportError(P2PManagerError):
    pass


class P2PSidecarManager:
    """Own at most one sidecar for an installation and vault."""

    def __init__(
        self,
        *,
        vault_root: Path,
        installation_root: Path | None = None,
        transport: TransportChoice = "auto",
    ) -> None:
        self.vault_root = vault_root.resolve()
        self.installation_root = installation_root.resolve() if installation_root else None
        self.state_root = self.vault_root / ".p2p"
        self._transport_choice: TransportChoice = transport
        self._settings = default_p2p_settings()
        self._started = False
        self._lock = asyncio.Lock()
        self._process: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._listener: BoundaryListener | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._monitor: asyncio.Task[None] | None = None
        self._restart_task: asyncio.Task[None] | None = None
        self._restart_times: list[float] = []
        self._request_id = 0
        self._last_error: str | None = None
        self._state = "disabled"
        self._network_paused = False
        self._global_network_policy = ("unknown", False)
        self._global_authorizations: dict[str, AuthorizedGlobalLease] = {}

    @property
    def process(self) -> asyncio.subprocess.Process | None:
        return self._process

    @property
    def settings(self) -> dict[str, object]:
        return dict(self._settings)

    @property
    def network_paused(self) -> bool:
        return self._network_paused

    @property
    def global_network_policy(self) -> tuple[str, bool]:
        return self._global_network_policy

    def _enabled(self) -> bool:
        return bool(self._settings["downloadsEnabled"] or self._settings["seedingEnabled"])

    async def start(self, settings: object, *, network_paused: bool = False) -> None:
        async with self._lock:
            self._settings = normalize_p2p_settings(settings)
            self._network_paused = network_paused
            self._started = True
            await self._reconcile_locked()

    async def update(self, settings: object, *, network_paused: bool | None = None) -> None:
        async with self._lock:
            self._settings = normalize_p2p_settings(settings)
            if network_paused is not None:
                self._network_paused = network_paused
            await self._reconcile_locked()

    async def close(self) -> None:
        async with self._lock:
            self._started = False
            restart = self._restart_task
            self._restart_task = None
            if restart is not None and restart is not asyncio.current_task():
                restart.cancel()
            await self._stop_locked()
            self._state = "disabled"
            self._last_error = None
            self._restart_times.clear()
            self._global_authorizations.clear()

    async def _reconcile_locked(self) -> None:
        if not self._started or not self._enabled():
            restart = self._restart_task
            self._restart_task = None
            if restart is not None and restart is not asyncio.current_task():
                restart.cancel()
            await self._stop_locked()
            self._state = "disabled"
            self._last_error = None
            self._restart_times.clear()
            return
        if self._process is None:
            if self._restart_task is None:
                await self._try_start_locked()
            return
        try:
            await self._request_locked("configure", self._settings)
            await self._request_locked("set-network-paused", {"paused": self._network_paused})
            cost, paused = self._global_network_policy
            await self._request_locked(
                "set-global-network-policy",
                {"cost": cost, "paused": paused},
            )
            self._state = "running"
            self._last_error = None
        except (BoundaryError, ConnectionError, OSError, P2PManagerError, TimeoutError) as error:
            await self._discard_process_locked()
            self._record_failure_locked(str(error))

    async def _try_start_locked(self) -> None:
        self._state = "starting"
        try:
            await self._start_locked()
        except (BoundaryError, ConnectionError, OSError, P2PManagerError, TimeoutError) as error:
            await self._discard_process_locked()
            self._record_failure_locked(str(error))

    def _sidecar_command(self, endpoint: str) -> list[str]:
        command = [
            sys.executable,
            "-m",
            "dinkster_p2p",
            "--endpoint",
            endpoint,
            "--state-root",
            str(self.state_root),
            "--vault-root",
            str(self.vault_root),
            "--settings-json",
            json.dumps(self._settings, sort_keys=True, separators=(",", ":")),
        ]
        if self.installation_root is not None:
            command.extend(("--installation-root", str(self.installation_root)))
        if self._network_paused:
            command.append("--network-paused")
        return command

    async def _start_locked(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="dinkster-p2p-")
        self._listener = await BoundaryListener.create(
            Path(self._tmpdir.name), transport=self._transport_choice
        )
        listener = self._listener
        env = {**os.environ, **listener.child_env}
        process = await asyncio.create_subprocess_exec(
            *self._sidecar_command(listener.endpoint),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._process = process
        connection = asyncio.ensure_future(listener.connected)
        exited = asyncio.create_task(process.wait())
        done, _ = await asyncio.wait(
            (connection, exited),
            timeout=_CONNECT_TIMEOUT_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if connection in done:
            self._reader, self._writer = connection.result()
        elif exited in done:
            connection.cancel()
            raise P2PManagerError(
                f"sidecar exited before IPC connection with status {exited.result()}"
            )
        else:
            connection.cancel()
            raise TimeoutError("sidecar did not connect to private IPC")
        exited.cancel()
        status = await self._request_locked("status", {})
        if status.get("libtorrentVersion") != LIBTORRENT_VERSION:
            raise P2PManagerError("sidecar reported an unexpected libtorrent version")
        cost, paused = self._global_network_policy
        await self._request_locked(
            "set-global-network-policy",
            {"cost": cost, "paused": paused},
        )
        self._state = "running"
        self._last_error = None
        process = self._process
        assert process is not None
        self._monitor = asyncio.create_task(self._monitor_process(process))

    async def _monitor_process(self, process: asyncio.subprocess.Process) -> None:
        status = await process.wait()
        async with self._lock:
            if self._process is not process:
                return
            await self._discard_process_locked(terminate=False)
            if self._started and self._enabled():
                self._record_failure_locked(f"sidecar exited unexpectedly with status {status}")

    def _record_failure_locked(self, error: str) -> None:
        now = time.monotonic()
        self._restart_times = [
            value for value in self._restart_times if now - value <= _RESTART_WINDOW_SECONDS
        ]
        self._last_error = error
        if len(self._restart_times) >= _RESTART_LIMIT:
            self._state = "failed"
            self._restart_task = None
            return
        self._restart_times.append(now)
        self._state = "restarting"
        delay = _RESTART_BACKOFF_SECONDS[len(self._restart_times) - 1]
        self._restart_task = asyncio.create_task(self._restart_after(delay))

    async def _restart_after(self, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
            async with self._lock:
                self._restart_task = None
                if self._started and self._enabled() and self._process is None:
                    await self._try_start_locked()
        except asyncio.CancelledError:
            return

    async def _request_locked(self, operation: str, body: object) -> dict[str, Any]:
        if self._reader is None or self._writer is None:
            raise _P2PTransportError("P2P sidecar is not running")
        self._request_id += 1
        request_id = self._request_id
        try:
            await asyncio.wait_for(
                write_frame(
                    self._writer,
                    {
                        "version": IPC_VERSION,
                        "id": request_id,
                        "operation": operation,
                        "body": body,
                    },
                    [],
                ),
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            frame = await asyncio.wait_for(
                read_frame(self._reader), timeout=_REQUEST_TIMEOUT_SECONDS
            )
        except TimeoutError as error:
            raise _P2PTransportError(
                f"P2P sidecar {operation} timed out after {_REQUEST_TIMEOUT_SECONDS:g} seconds"
            ) from error
        if frame is None:
            raise _P2PTransportError("P2P sidecar closed the IPC connection")
        response, blobs = frame
        if blobs or response.get("version") != IPC_VERSION or response.get("id") != request_id:
            raise _P2PTransportError("P2P sidecar returned an invalid response frame")
        if response.get("ok") is not True:
            if set(response) != {"version", "id", "ok", "error", "errorType", "blobs"}:
                raise _P2PTransportError("P2P sidecar returned an invalid error frame")
            message = response.get("error")
            detail = message if isinstance(message, str) else "P2P operation failed"
            error_type = response.get("errorType")
            if error_type == "SidecarConflict":
                raise P2PManagerConflict(detail)
            if error_type == "SidecarNotFound":
                raise P2PManagerNotFound(detail)
            raise P2PManagerError(detail)
        if set(response) != {"version", "id", "ok", "result", "blobs"}:
            raise _P2PTransportError("P2P sidecar returned an invalid success frame")
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise _P2PTransportError("P2P sidecar returned a non-object result")
        return cast("dict[str, Any]", dict(result))

    async def _stop_locked(self) -> None:
        if self._process is None:
            await self._discard_process_locked(terminate=False)
            return
        process = self._process
        try:
            await self._request_locked("shutdown", {})
            await asyncio.wait_for(process.wait(), timeout=_STOP_TIMEOUT_SECONDS)
        except (BoundaryError, ConnectionError, OSError, P2PManagerError, TimeoutError):
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=_STOP_TIMEOUT_SECONDS)
                except TimeoutError:
                    process.kill()
                    await process.wait()
        await self._discard_process_locked(terminate=False)

    async def _discard_process_locked(self, *, terminate: bool = True) -> None:
        process = self._process
        self._process = None
        if terminate and process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=_STOP_TIMEOUT_SECONDS)
            except TimeoutError:
                process.kill()
                await process.wait()
        monitor = self._monitor
        self._monitor = None
        if monitor is not None and monitor is not asyncio.current_task():
            monitor.cancel()
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None
        self._global_authorizations.clear()
        if self._listener is not None:
            await self._listener.close()
            self._listener = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None

    async def _request_with_recovery_locked(self, operation: str, body: object) -> dict[str, Any]:
        try:
            return await self._request_locked(operation, body)
        except asyncio.CancelledError:
            await self._discard_process_locked()
            self._record_failure_locked(f"P2P sidecar {operation} was cancelled before response")
            raise
        except (BoundaryError, ConnectionError, OSError, _P2PTransportError) as error:
            await self._discard_process_locked()
            self._record_failure_locked(str(error))
            raise P2PManagerError(str(error)) from error

    async def _operation(self, operation: str, body: object) -> dict[str, Any]:
        async with self._lock:
            if self._process is None:
                raise P2PManagerError("P2P sidecar is not running")
            return await self._request_with_recovery_locked(operation, body)

    async def grant_download(self, lease: DownloadLease) -> dict[str, Any]:
        if lease.scope != "lan-only":
            raise P2PManagerError("global downloads require trusted provider authority")
        return await self._operation("grant-download", lease.to_wire())

    async def grant_seed(self, lease: SeedLease) -> dict[str, Any]:
        if lease.scope != "lan-only":
            raise P2PManagerError("global seeding requires trusted provider authority")
        return await self._operation("grant-seed", lease.to_wire())

    @staticmethod
    def _global_lease(authorization: object) -> DownloadLease | SeedLease:
        if not isinstance(authorization, AuthorizedGlobalLease):
            raise P2PManagerError("global lease lacks trusted provider authority")
        return authorization.lease

    def _verify_global_seed(self, lease: DownloadLease | SeedLease) -> None:
        if isinstance(lease, SeedLease):
            try:
                AssetVault(self.vault_root).verify_p2p_local_file(
                    lease.digest,
                    lease.size_bytes,
                    lease.local_path,
                    P2P_FORMAT_POLICY_VERSION,
                ).require_current()
            except (AssetError, OSError) as error:
                raise P2PManagerError(
                    f"global seed mapping is not safe and current: {error}"
                ) from error

    async def _grant_global_locked(self, authorization: AuthorizedGlobalLease) -> dict[str, Any]:
        lease = self._global_lease(authorization)
        self._verify_global_seed(lease)
        result = await self._request_with_recovery_locked("grant-global", authorization.to_wire())
        self._global_authorizations[lease.lease_id] = authorization
        return result

    async def grant_global(self, authorization: AuthorizedGlobalLease) -> dict[str, Any]:
        async with self._lock:
            if self._process is None:
                raise P2PManagerError("P2P sidecar is not running")
            return await self._grant_global_locked(authorization)

    async def reconcile_global(
        self, authorizations: Sequence[AuthorizedGlobalLease], *, revoke_only: bool = False
    ) -> dict[str, tuple[str, ...]]:
        """Replace active internet authority with one current provider snapshot."""
        desired: dict[str, AuthorizedGlobalLease] = {}
        digests: set[str] = set()
        now = time.time()
        for authorization in authorizations:
            lease = self._global_lease(authorization)
            if lease.expires_at <= now:
                continue
            if lease.lease_id in desired or lease.digest in digests:
                raise P2PManagerError(
                    "global authorizations must have unique lease IDs and digests"
                )
            desired[lease.lease_id] = authorization
            digests.add(lease.digest)

        granted: list[str] = []
        revoked: list[str] = []
        async with self._lock:
            for lease_id, current in tuple(self._global_authorizations.items()):
                if desired.get(lease_id) == current:
                    continue
                await self._request_with_recovery_locked("revoke", {"leaseId": lease_id})
                self._global_authorizations.pop(lease_id, None)
                revoked.append(lease_id)
            if revoke_only:
                return {"granted": (), "revoked": tuple(revoked)}
            for lease_id, authorization in desired.items():
                if self._global_authorizations.get(lease_id) == authorization:
                    continue
                if self._process is None:
                    raise P2PManagerError("P2P sidecar is not running")
                await self._grant_global_locked(authorization)
                granted.append(lease_id)
        return {"granted": tuple(granted), "revoked": tuple(revoked)}

    async def revoke(self, lease_id: str) -> dict[str, Any]:
        async with self._lock:
            if self._process is None:
                raise P2PManagerError("P2P sidecar is not running")
            result = await self._request_with_recovery_locked("revoke", {"leaseId": lease_id})
            self._global_authorizations.pop(lease_id, None)
            return result

    async def pause(self) -> dict[str, Any]:
        return await self._operation("pause", {})

    async def resume(self) -> dict[str, Any]:
        return await self._operation("resume", {})

    async def remove_partial(self, lease_id: str) -> dict[str, Any]:
        return await self._operation("remove-partial", {"leaseId": lease_id})

    async def pause_transfer(self, digest: str) -> dict[str, Any]:
        return await self._operation("pause-transfer", {"digest": digest})

    async def resume_transfer(self, digest: str) -> dict[str, Any]:
        return await self._operation("resume-transfer", {"digest": digest})

    async def stop_transfer(self, digest: str) -> dict[str, Any]:
        return await self._operation("stop-transfer", {"digest": digest})

    async def remove_transfer_partial(self, digest: str) -> dict[str, Any]:
        return await self._operation("remove-transfer-partial", {"digest": digest})

    async def reset_transfer_budget(self, digest: str) -> dict[str, Any]:
        return await self._operation("reset-transfer-budget", {"digest": digest})

    async def make_transfer_continuous(self, digest: str) -> dict[str, Any]:
        return await self._operation("make-transfer-continuous", {"digest": digest})

    async def set_network_paused(self, paused: bool) -> None:
        async with self._lock:
            self._network_paused = paused
            if self._process is not None:
                await self._request_with_recovery_locked("set-network-paused", {"paused": paused})

    async def set_global_network_policy(self, cost: str, paused: bool) -> None:
        if cost not in _GLOBAL_NETWORK_COSTS:
            raise P2PManagerError("global network cost is invalid")
        if type(paused) is not bool:
            raise P2PManagerError("global network pause must be a boolean")
        if paused and cost == "unmetered":
            raise P2PManagerError("unmetered global network policy cannot be paused")
        async with self._lock:
            if self._process is not None:
                await self._request_with_recovery_locked(
                    "set-global-network-policy",
                    {"cost": cost, "paused": paused},
                )
            self._global_network_policy = (cost, paused)

    async def lease_status(self, lease_id: str) -> dict[str, Any]:
        return await self._operation("lease-status", {"leaseId": lease_id})

    async def save_state(self) -> dict[str, Any]:
        return await self._operation("save-state", {})

    async def status(self) -> dict[str, object]:
        async with self._lock:
            sidecar: dict[str, Any] | None = None
            if self._process is not None:
                try:
                    sidecar = await self._request_locked("status", {})
                except (
                    BoundaryError,
                    ConnectionError,
                    OSError,
                    P2PManagerError,
                    TimeoutError,
                ) as error:
                    await self._discard_process_locked()
                    self._record_failure_locked(str(error))
            return {
                "state": self._state,
                "settings": dict(self._settings),
                "restartCount": len(self._restart_times),
                "lastError": self._last_error,
                "sidecar": sidecar,
            }
