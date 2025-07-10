import asyncio
import yaml
import uvloop
import socket
import struct
from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import json
from datetime import datetime

# Shared config object
global_config = {}
config_lock = threading.Lock()

# Shared PayloadHandler instance
global_payload_handler = None

def load_config(config_path):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def update_payload_handler():
    global global_payload_handler
    with config_lock:
        global_payload_handler = PayloadHandler(config=global_config.copy())

class ConfigReloader(FileSystemEventHandler):
    def __init__(self, config_path):
        self.config_path = config_path

    def on_modified(self, event):
        if event.src_path.endswith(self.config_path):
            try:
                new_config = load_config(self.config_path)
                with config_lock:
                    global_config.clear()
                    global_config.update(new_config)
                update_payload_handler()
                print(f"[*] Config reloaded from {self.config_path}")
            except Exception as e:
                print(f"[!] Failed to reload config: {e}")


async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, source_ip: str, target_ip: str, json_filename: str = None) -> None:
    decoder = PickleDecoder()
    # Use the global payload handler
    global global_payload_handler
    decoded_messages = {}
    message_counter = 1
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break

            # print(f"[DEBUG] {direction}] [{data!r}")

            original_data = data

            message_pairs = decoder.add_data_with_raw(data)

            if message_pairs:
                print(f"[{direction}] Decoded {len(message_pairs)} message(s):")
                for _, (raw_msg, formatted_msg, msg_len) in enumerate(message_pairs, 1):
                    print(f"[{direction}] Message {message_counter}:")
                    print(f"{formatted_msg}")
                    # Store the raw decoded message for JSON output with message number and length
                    key = f"Message {message_counter}, Length {msg_len}"
                    decoded_messages[key] = raw_msg
                    message_counter += 1
            else:
                print(f"[{direction}] No complete messages in chunk ({len(data)} bytes)")

            should_forward = True
            insertions = []

            for raw_msg, _, _ in message_pairs:
                # Always use the latest handler
                handler = global_payload_handler
                should_forward, msg_insertions = await handler.process_messages(raw_msg, source_ip, target_ip)
                insertions.extend(msg_insertions)

                if not should_forward:
                    break

            if should_forward:
                for insert_data, position, _ in insertions:
                    if position == "before":
                        writer.write(insert_data)
                        await writer.drain()
                
                writer.write(original_data)
                await writer.drain()

                for insert_data, position, _ in insertions:
                    if position == "after":
                        writer.write(insert_data)
                        await writer.drain()
            else:
                print(f"[{direction}] Message blocked by rules")

    except Exception as e:
        print(f"[!] Error forwarding data ({direction}): {e}")
        # import traceback
        # traceback.print_exc()
    finally:
        # Write all decoded messages to JSON file if filename is provided
        if json_filename is not None:
            try:
                os.makedirs(os.path.dirname(json_filename), exist_ok=True)
                with open(json_filename, 'w') as f:
                    json.dump(decoded_messages, f, indent=2, default=str)
            except Exception as e:
                print(f"[!] Failed to write decoded output to {json_filename}: {e}")
        writer.close()
        await writer.wait_closed()

def get_original_dest(sock: socket.socket):
    SO_ORIGINAL_DST = 80
    original_dest = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack_from("!H", original_dest, 2)[0]
    ip = socket.inet_ntoa(original_dest[4:8])
    return ip, port

async def handle_connection(src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter) -> None:
    client_addr = src_writer.get_extra_info('peername')
    sock = src_writer.get_extra_info('socket')

    try:
        orig_dst_ip, orig_dst_port = get_original_dest(sock)
        client_ip, client_port = client_addr
        print(f"[*] TPROXY connection from {client_ip}:{client_port} intended for {orig_dst_ip}:{orig_dst_port}")
        # Generate a unique, human-readable filename for decoded output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        base_dir = "decoded_output"
        # Use dashes for IP/port, and _to_ for direction
        client_to_remote_file = os.path.join(base_dir, f"decoded_{client_ip}-{client_port}_to_{orig_dst_ip}-{orig_dst_port}_{timestamp}.json")
        remote_to_client_file = os.path.join(base_dir, f"decoded_{orig_dst_ip}-{orig_dst_port}_to_{client_ip}-{client_port}_{timestamp}.json")
    except Exception as e:
         print(f"[!] Error getting socket names: {e}")
         src_writer.close()
         await src_writer.wait_closed()
         return
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.setblocking(False)
        remote_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

        try:
            remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote_socket.bind((client_ip, client_port))
            print(f"[*] Outgoing socket bound to {client_ip}:{client_port}")
        except Exception as e:
            print(f"[!] Warning: Could not bind outgoing socket to {client_ip}:{client_port} (requires CAP_NET_ADMIN or root): {e}. Proceeding with default source.")
            src_writer.close()
            await src_writer.wait_closed()
            return

        loop = asyncio.get_running_loop()

        await loop.sock_connect(remote_socket, (orig_dst_ip, orig_dst_port))

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)
        print(f"[*] Connected to original destination {orig_dst_ip}:{orig_dst_port}")

        # Pass the unique JSON filenames to forward_data
        client_to_remote = asyncio.create_task(forward_data(src_reader, remote_writer, f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}", client_ip, orig_dst_ip, client_to_remote_file))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, src_writer, f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}", orig_dst_ip, client_ip, remote_to_client_file))

        await asyncio.gather(client_to_remote, remote_to_client)

    except ConnectionRefusedError:
        print(f"[!] Connection refused by {orig_dst_ip}:{orig_dst_port}")
    except Exception as e:
        print(f"[!] Error in handle_connection: {e}")
        #  import traceback
        # traceback.print_exc()
    finally:
        src_writer.close()
        await src_writer.wait_closed()
    print(f"[*] Connection from {client_addr[0]}:{client_addr[1]} closed")

async def start_proxy(src_host: str, src_port: int) -> None:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    listening_socket.bind((src_host, src_port))
    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False)

    server = await asyncio.start_server(handle_connection, sock=listening_socket)

    addr = server.sockets[0].getsockname()
    print(f"[*] Listening on {addr[0]}:{addr[1]} (transparent)")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        print("[*] Server cancelled.")
        raise

def main():
    config_path = "config/config.yaml"

    # Initial config load
    initial_config = load_config(config_path)
    with config_lock:
        global_config.clear()
        global_config.update(initial_config)
    update_payload_handler()

    # Start watchdog observer in a separate thread
    event_handler = ConfigReloader(config_path)
    observer = Observer()
    observer.schedule(event_handler, path="config/", recursive=False)
    observer.daemon = True
    observer.start()
    print(f"[*] Watching {config_path} for changes...")

    src_config = global_config.get("src", {})
    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    try:
        uvloop.run(start_proxy(src_host, src_port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down from keyboard interrupt...")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        observer.stop()
        observer.join()


if __name__ == '__main__':
    main()