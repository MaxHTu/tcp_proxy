import asyncio
import copy
import json
import os
import socket
import struct
import threading
import time
from typing import Any, Dict, Optional

import yaml

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


global_config: Dict[str, Any] = {}
config_lock = threading.Lock()

global_payload_handler: Optional[PayloadHandler] = None
global_config_version = 0


def log_event(event: str, **fields: Any) -> None:
    payload = {
        "component": "tcp_proxy",
        "event": event,
        "timestamp": time.time(),
        **fields,
    }
    print(json.dumps(payload, default=str))


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError("config root must be a mapping")
    return loaded


def update_payload_handler(config_snapshot: Dict[str, Any]) -> bool:
    global global_payload_handler
    global global_config
    global global_config_version

    is_valid, errors = PayloadHandler.validate_config(config_snapshot)
    if not is_valid:
        log_event("config_reload_failed", reason="validation", errors=errors)
        return False

    try:
        next_version = global_config_version + 1
        next_handler = PayloadHandler(config=copy.deepcopy(config_snapshot), config_version=next_version)
    except Exception as exc:
        log_event("config_reload_failed", reason="build", error=str(exc))
        return False

    with config_lock:
        global_payload_handler = next_handler
        global_config.clear()
        global_config.update(copy.deepcopy(config_snapshot))
        global_config_version = next_version

    log_event("config_reloaded", config_version=global_config_version)
    return True


class ConfigReloader(FileSystemEventHandler):
    def __init__(self, config_path: str):
        self.config_path = os.path.abspath(config_path)

    def on_modified(self, event: Any) -> None:
        src_path = os.path.abspath(getattr(event, "src_path", ""))
        if src_path != self.config_path:
            return

        try:
            new_config = load_config(self.config_path)
        except Exception as exc:
            log_event("config_reload_failed", reason="read", error=str(exc))
            return

        update_payload_handler(new_config)


async def forward_data(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction_label: str,
    source_ip: str,
    target_ip: str,
    connection_id: str,
) -> None:
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
                with config_lock:
                    handler = global_payload_handler

                if handler is None:
                    writer.write(frame.raw_frame)
                    await writer.drain()
                    continue

                decision = await handler.process_frame(
                    frame=frame,
                    source_ip=source_ip,
                    target_ip=target_ip,
                    connection_id=connection_id,
                    direction_label=direction_label,
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
            connection_id=connection_id,
            direction=direction_label,
            error=str(exc),
        )
    finally:
        if decoder.buffer:
            log_event(
                "partial_frame_dropped",
                connection_id=connection_id,
                direction=direction_label,
                buffered_bytes=len(decoder.buffer),
            )
        writer.close()
        await writer.wait_closed()


def get_original_dest(sock: socket.socket) -> tuple[str, int]:
    so_original_dst = 80
    original_dest = sock.getsockopt(socket.SOL_IP, so_original_dst, 16)
    port = struct.unpack_from("!H", original_dest, 2)[0]
    ip = socket.inet_ntoa(original_dest[4:8])
    return ip, port


async def handle_connection(src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter) -> None:
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
                f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}",
                client_ip,
                orig_dst_ip,
                connection_id,
            )
        )
        remote_to_client = asyncio.create_task(
            forward_data(
                remote_reader,
                src_writer,
                f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}",
                orig_dst_ip,
                client_ip,
                connection_id,
            )
        )

        done, pending = await asyncio.wait(
            [client_to_remote, remote_to_client],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*done, return_exceptions=True)

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


async def start_proxy(src_host: str, src_port: int) -> None:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    listening_socket.bind((src_host, src_port))
    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False)

    server = await asyncio.start_server(handle_connection, sock=listening_socket)

    addr = server.sockets[0].getsockname()
    log_event("proxy_listening", host=addr[0], port=addr[1], transparent=True)

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        log_event("server_cancelled")
        raise


def main() -> None:
    config_path = "config/config.yaml"

    try:
        initial_config = load_config(config_path)
    except Exception as exc:
        log_event("startup_failed", reason="config_read", error=str(exc))
        return

    if not update_payload_handler(initial_config):
        log_event("startup_failed", reason="invalid_initial_config")
        return

    observer = None
    if Observer is not None:
        event_handler = ConfigReloader(config_path)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(config_path) or ".", recursive=False)
        observer.daemon = True
        observer.start()
        log_event("config_watch_enabled", path=config_path)
    else:
        log_event("config_watch_disabled", reason="watchdog_not_installed")

    with config_lock:
        src_config = copy.deepcopy(global_config.get("src", {}))

    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    try:
        if uvloop is not None:
            uvloop.run(start_proxy(src_host, src_port))
        else:
            asyncio.run(start_proxy(src_host, src_port))
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
