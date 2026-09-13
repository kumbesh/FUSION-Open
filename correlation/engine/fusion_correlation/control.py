"""Container-private lifecycle control for the single correlation writer."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from .runtime_models import IncidentRecord


MAX_CONTROL_REQUEST_BYTES = 4_096
_INCIDENT_ID = re.compile(r"^[0-9a-f]{64}$")
_TRANSITION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class LifecycleStore(Protocol):
    def transition_incident(
        self, incident_id: str, target_status: str, transition_id: str
    ) -> IncidentRecord: ...


class LifecycleControlServer:
    """Serve one bounded JSON request at a time over a mode-0600 Unix socket."""

    def __init__(
        self,
        socket_path: Path,
        store: LifecycleStore,
        mutation_lock: threading.RLock,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.store = store
        self.mutation_lock = mutation_lock
        self.on_error = on_error or (lambda _message: None)
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        parent = self.socket_path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            mode = self.socket_path.lstat().st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(
                    f"refusing to replace non-socket control path: {self.socket_path}"
                )
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(os.fspath(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(4)
        server.settimeout(0.25)
        self._socket = server
        self._thread = threading.Thread(
            target=self._serve, name="fusion-correlation-control", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self.socket_path.exists() and stat.S_ISSOCK(
            self.socket_path.lstat().st_mode
        ):
            self.socket_path.unlink()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.on_error("control_socket_accept_failed")
                return
            with connection:
                try:
                    request = _receive_request(connection)
                    incident_id, target_status, transition_id = _validate_request(
                        request
                    )
                    with self.mutation_lock:
                        record = self.store.transition_incident(
                            incident_id, target_status, transition_id
                        )
                    response: dict[str, Any] = {
                        "ok": True,
                        "incident_id": record.incident_id,
                        "status": str(record.values["status"]),
                        "revision": record.revision,
                        "transition_id": transition_id,
                    }
                except Exception as exc:
                    self.on_error(type(exc).__name__)
                    response = {
                        "ok": False,
                        "error": type(exc).__name__,
                        "message": str(exc)[:512],
                    }
                connection.sendall(
                    json.dumps(response, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                    + b"\n"
                )


def request_transition(
    socket_path: Path,
    incident_id: str,
    target_status: str,
    transition_id: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    request = {
        "incident_id": incident_id,
        "target_status": target_status,
        "transition_id": transition_id,
    }
    _validate_request(request)
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout_seconds)
        client.connect(os.fspath(socket_path))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        raw = _receive_response(client)
    result = json.loads(raw.decode("utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("invalid lifecycle control response")
    return result


def _receive_request(connection: socket.socket) -> dict[str, Any]:
    raw = _receive_response(connection)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("control request must be a JSON object")
    return value


def _receive_response(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = connection.recv(min(1024, MAX_CONTROL_REQUEST_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_CONTROL_REQUEST_BYTES:
            raise ValueError("control message exceeds size limit")
        if b"\n" in chunk:
            break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    if not raw:
        raise ValueError("empty control message")
    return raw


def _validate_request(request: dict[str, Any]) -> tuple[str, str, str]:
    expected = {"incident_id", "target_status", "transition_id"}
    if set(request) != expected:
        raise ValueError("control request has unknown or missing fields")
    incident_id = request["incident_id"]
    target_status = request["target_status"]
    transition_id = request["transition_id"]
    if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
        raise ValueError("incident_id must be a lowercase SHA-256 hex identifier")
    if target_status not in {"acknowledged", "closed"}:
        raise ValueError("target_status must be acknowledged or closed")
    if not isinstance(transition_id, str) or not _TRANSITION_ID.fullmatch(
        transition_id
    ):
        raise ValueError("transition_id must be a bounded opaque identifier")
    return incident_id, target_status, transition_id
