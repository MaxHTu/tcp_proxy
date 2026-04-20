import asyncio
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional

try:
    import uvloop
except ModuleNotFoundError:
    uvloop = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ModuleNotFoundError:
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None

from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler
from utils.config_loading import ConfigValidationError, load_proxy_config
from utils.contracts import ForwardingContext, SourceConfig


def log_event(event: str, **fields: Any) -> None:
    """Emit machine-readable proxy events for operators and tests."""
    payload = {
        "component": "tcp_proxy",
        "event": event,
        "timestamp": time.time(),
        **fields,
    }
    print(json.dumps(payload, default=str))


@dataclass(frozen=True)
class RuntimeSnapshot:
    """Consistent runtime view used by startup code and tests."""

    source: SourceConfig
    payload_handler: PayloadHandler
    config_version: int


class ProxyRuntimeState:
    """Owns reloadable proxy config without exposing module-global state."""

    def __init__(self, config_path: str):
        self.config_path = os.path.abspath(config_path)
        self._lock = threading.Lock()
        self._source: Optional[SourceConfig] = None
        self._payload_handler: Optional[PayloadHandler] = None
        self._config_version = 0

    def load_initial(self) -> None:
        """Load the initial config before the listener is bound."""
        loaded = load_proxy_config(self.config_path)
        self._log_warnings(loaded.warnings, phase="initial")

        handler = PayloadHandler(config=loaded.config, config_version=0)
        with self._lock:
            self._source = loaded.config.source
            self._payload_handler = handler
            self._config_version = 0

        log_event(
            "config_loaded",
            path=self.config_path,
            config_version=0,
            host=loaded.config.source.host,
            port=loaded.config.source.port,
        )

    def reload_from_file(self) -> bool:
        """Reload payload rules while keeping the already-bound listener stable."""
        try:
            loaded = load_proxy_config(self.config_path)
        except ConfigValidationError as exc:
            log_event("config_reload_failed", reason="validation", errors=exc.errors)
            return False
        except Exception as exc:
            log_event("config_reload_failed", reason="read", error=str(exc))
            return False

        current = self.snapshot()
        self._log_warnings(loaded.warnings, phase="reload")

        # Changing src.host/src.port after bind would require rebuilding the server socket.
        if loaded.config.source != current.source:
            log_event(
                "config_reload_listener_ignored",
                active_host=current.source.host,
                active_port=current.source.port,
                requested_host=loaded.config.source.host,
                requested_port=loaded.config.source.port,
            )

        next_version = current.config_version + 1
        try:
            next_handler = PayloadHandler(config=loaded.config, config_version=next_version)
        except Exception as exc:
            log_event("config_reload_failed", reason="build", error=str(exc))
            return False

        with self._lock:
            self._payload_handler = next_handler
            self._config_version = next_version

        log_event("config_reloaded", path=self.config_path, config_version=next_version)
        return True

    def payload_handler(self) -> PayloadHandler:
        """Return the current handler without allocating a full snapshot per frame."""
        with self._lock:
            if self._payload_handler is None:
                raise RuntimeError("runtime state has not been initialized")
            return self._payload_handler

    def snapshot(self) -> RuntimeSnapshot:
        """Return a full runtime snapshot for low-frequency control paths."""
        with self._lock:
            if self._source is None or self._payload_handler is None:
                raise RuntimeError("runtime state has not been initialized")

            return RuntimeSnapshot(
                source=self._source,
                payload_handler=self._payload_handler,
                config_version=self._config_version,
            )

    def _log_warnings(self, warnings: tuple[str, ...], *, phase: str) -> None:
        for warning in warnings:
            log_event("config_warning", path=self.config_path, phase=phase, warning=warning)


class ConfigReloader(FileSystemEventHandler):
    """Watchdog adapter that reloads only the configured YAML file."""

    def __init__(self, runtime_state: ProxyRuntimeState):
        self.runtime_state = runtime_state
        self.config_path = runtime_state.config_path

    def on_modified(self, event: Any) -> None:
        src_path = os.path.abspath(getattr(event, "src_path", ""))
        if src_path != self.config_path:
            return

        self.runtime_state.reload_from_file()


async def finish_writer_output(writer: asyncio.StreamWriter, context: ForwardingContext) -> None:
    """Signal EOF to the peer without closing the opposite read direction."""
    try:
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
            return
    except (ConnectionError, OSError, RuntimeError) as exc:
        log_event(
            "writer_eof_failed",
            connection_id=context.connection_id,
            direction=context.direction_label,
            error=str(exc),
        )

    writer.close()
    await writer.wait_closed()


async def forward_data(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    runtime_state: ProxyRuntimeState,
    context: ForwardingContext,
) -> None:
    """Forward one direction of traffic through the frame-aware rule engine."""
    decoder = PickleDecoder()

    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break

            frames = decoder.add_data_frames(data)
            if not frames:
                continue

            for frame in frames:
                handler = runtime_state.payload_handler()
                decision = await handler.process_frame(
                    frame=frame,
                    context=context,
                )

                for insertion in decision.before_insertions:
                    writer.write(insertion.data)

                if decision.forward_original:
                    writer.write(frame.raw_frame)

                for insertion in decision.after_insertions:
                    writer.write(insertion.data)

                await writer.drain()

    except Exception as exc:
        log_event(
            "forward_error",
            connection_id=context.connection_id,
            direction=context.direction_label,
            error=str(exc),
        )
    finally:
        if decoder.buffer:
            log_event(
                "partial_frame_dropped",
                connection_id=context.connection_id,
                direction=context.direction_label,
                buffered_bytes=len(decoder.buffer),
            )
        await finish_writer_output(writer, context)


def get_original_dest(sock: socket.socket) -> tuple[str, int]:
    """Read Linux SO_ORIGINAL_DST for a transparently redirected connection."""
    so_original_dst = 80
    original_dest = sock.getsockopt(socket.SOL_IP, so_original_dst, 16)
    port = struct.unpack_from("!H", original_dest, 2)[0]
    ip = socket.inet_ntoa(original_dest[4:8])
    return ip, port


async def handle_connection(
    src_reader: asyncio.StreamReader,
    src_writer: asyncio.StreamWriter,
    runtime_state: ProxyRuntimeState,
) -> None:
    """Bridge a redirected client connection to its original destination."""
    client_addr = src_writer.get_extra_info("peername")
    sock = src_writer.get_extra_info("socket")

    if not client_addr or not sock:
        src_writer.close()
        await src_writer.wait_closed()
        return

    try:
        orig_dst_ip, orig_dst_port = get_original_dest(sock)
        client_ip, client_port = client_addr
    except Exception as exc:
        log_event("connection_rejected", reason="original_dest_lookup", error=str(exc))
        src_writer.close()
        await src_writer.wait_closed()
        return

    connection_id = f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}@{int(time.time() * 1000)}"
    log_event(
        "connection_open",
        connection_id=connection_id,
        client_ip=client_ip,
        client_port=client_port,
        original_dst_ip=orig_dst_ip,
        original_dst_port=orig_dst_port,
    )

    remote_writer: Optional[asyncio.StreamWriter] = None

    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.setblocking(False)
        # IP_TRANSPARENT requires Linux support and elevated network privileges.
        remote_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

        try:
            remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote_socket.bind((client_ip, client_port))
        except Exception as exc:
            log_event(
                "connection_rejected",
                connection_id=connection_id,
                reason="transparent_bind",
                error=str(exc),
            )
            src_writer.close()
            await src_writer.wait_closed()
            return

        loop = asyncio.get_running_loop()
        await loop.sock_connect(remote_socket, (orig_dst_ip, orig_dst_port))

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)

        client_to_remote = asyncio.create_task(
            forward_data(
                src_reader,
                remote_writer,
                runtime_state,
                ForwardingContext(
                    connection_id=connection_id,
                    direction_label=f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}",
                    source_ip=client_ip,
                    target_ip=orig_dst_ip,
                ),
            )
        )
        remote_to_client = asyncio.create_task(
            forward_data(
                remote_reader,
                src_writer,
                runtime_state,
                ForwardingContext(
                    connection_id=connection_id,
                    direction_label=f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}",
                    source_ip=orig_dst_ip,
                    target_ip=client_ip,
                ),
            )
        )

        # A TCP half-close in one direction is not the end of the whole exchange.
        await asyncio.gather(
            client_to_remote,
            remote_to_client,
            return_exceptions=True,
        )

    except ConnectionRefusedError:
        log_event("connection_refused", connection_id=connection_id)
    except Exception as exc:
        log_event("connection_error", connection_id=connection_id, error=str(exc))
    finally:
        src_writer.close()
        await src_writer.wait_closed()
        if remote_writer is not None:
            remote_writer.close()
            await remote_writer.wait_closed()

    log_event("connection_closed", connection_id=connection_id)


async def start_proxy(src_host: str, src_port: int, runtime_state: ProxyRuntimeState) -> None:
    """Bind the transparent listening socket and serve connections forever."""
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # The proxy is intended for transparent interception, not ordinary TCP forwarding.
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    listening_socket.bind((src_host, src_port))
    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False)

    server = await asyncio.start_server(
        partial(handle_connection, runtime_state=runtime_state),
        sock=listening_socket,
    )

    addr = server.sockets[0].getsockname()
    log_event("proxy_listening", host=addr[0], port=addr[1], transparent=True)

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        log_event("server_cancelled")
        raise


def main() -> None:
    """Start the proxy from the default project config file."""
    config_path = "config/config.yaml"
    runtime_state = ProxyRuntimeState(config_path)

    try:
        runtime_state.load_initial()
    except ConfigValidationError as exc:
        log_event("startup_failed", reason="config_validation", errors=exc.errors)
        return
    except Exception as exc:
        log_event("startup_failed", reason="config_read", error=str(exc))
        return

    observer = None
    if Observer is not None:
        event_handler = ConfigReloader(runtime_state)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(config_path) or ".", recursive=False)
        observer.daemon = True
        observer.start()
        log_event("config_watch_enabled", path=config_path)
    else:
        log_event("config_watch_disabled", reason="watchdog_not_installed")

    source = runtime_state.snapshot().source
    src_host = source.host
    src_port = source.port

    try:
        if uvloop is not None:
            uvloop.run(start_proxy(src_host, src_port, runtime_state))
        else:
            asyncio.run(start_proxy(src_host, src_port, runtime_state))
    except KeyboardInterrupt:
        log_event("shutdown", reason="keyboard_interrupt")
    except Exception as exc:
        log_event("runtime_error", error=str(exc))
    finally:
        if observer is not None:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    main()
