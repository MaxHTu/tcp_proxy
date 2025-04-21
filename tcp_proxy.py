import asyncio
import yaml
import uvloop
import socket
import struct
from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler
import argparse


async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, proxy_queue: asyncio.Queue = None) -> None:
    decoder = PickleDecoder()
    payload_handler = PayloadHandler()
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break

            #print(f"[{direction}] [{data!r}]")

            # Store the original data for forwarding
            original_data = data

            # Decode messages with raw message objects for rule processing
            message_pairs = decoder.add_data_with_raw(data)

            # Log decoded messages
            if message_pairs:
                log_msg = f"[{direction}] Decoded {len(message_pairs)} message(s):"
                print(log_msg)

                for i, (raw_msg, formatted_msg) in enumerate(message_pairs, 1):
                    print(f"[{direction}] Message {i}:")
                    print(f"{formatted_msg}")

                    # Send message to GUI if queue is available
                    if proxy_queue:
                        await proxy_queue.put({
                            "type": "message",
                            "direction": direction,
                            "content": formatted_msg
                        })
            else:
                log_msg = f"[{direction}] No complete messages in chunk ({len(data)} bytes)"
                print(log_msg)
                if proxy_queue:
                    await proxy_queue.put({
                        "type": "status",
                        "status": f"No complete messages in chunk ({len(data)} bytes)"
                    })

            # Apply rules to each message
            should_forward = True
            all_replayed_messages = []

            for raw_msg, _ in message_pairs:
                # Apply rules to the raw message object
                should_forward, replayed_messages = await payload_handler.process_message(raw_msg)

                # Check if message was blocked
                if not should_forward and proxy_queue and isinstance(raw_msg, dict):
                    action = raw_msg.get("action", "unknown")
                    await proxy_queue.put({
                        "type": "block",
                        "action": action
                    })

                # Check if message was delayed
                delay_ms = payload_handler.delay_action.get_delay(raw_msg)
                if delay_ms is not None and proxy_queue and isinstance(raw_msg, dict):
                    action = raw_msg.get("action", "unknown")
                    await proxy_queue.put({
                        "type": "delay",
                        "action": action,
                        "delay_ms": delay_ms
                    })

                # Check if message was replayed
                replay_count = payload_handler.replay_action.get_replay_count(raw_msg)
                if replay_count is not None and replay_count > 0 and proxy_queue and isinstance(raw_msg, dict):
                    action = raw_msg.get("action", "unknown")
                    await proxy_queue.put({
                        "type": "replay",
                        "action": action,
                        "count": replay_count
                    })

                # Collect any replayed messages
                all_replayed_messages.extend(replayed_messages)

                if not should_forward:
                    break

            # Forward the data if it passes all rules
            if should_forward:
                writer.write(original_data)
                await writer.drain()

                # Handle any replayed messages
                if all_replayed_messages:
                    replay_msg = f"[{direction}] Forwarding {len(all_replayed_messages)} replayed messages"
                    print(replay_msg)

                    # In a real implementation, we would need to encode the replayed messages
                    # back to the original format. For now, we'll just log them.
                    for i, replayed_msg in enumerate(all_replayed_messages, 1):
                        print(f"[{direction}] Replayed message {i}: {replayed_msg}")

                        # Send replayed message to GUI if queue is available
                        if proxy_queue and isinstance(replayed_msg, dict):
                            await proxy_queue.put({
                                "type": "message",
                                "direction": f"{direction} (replay {i})",
                                "content": str(replayed_msg)
                            })

                        # Here we would encode and forward the replayed message
                        # This is a placeholder for the actual implementation
                        # writer.write(encoded_replayed_msg)
                        # await writer.drain()
            else:
                block_msg = f"[{direction}] Message blocked by rules"
                print(block_msg)
                if proxy_queue:
                    await proxy_queue.put({
                        "type": "status",
                        "status": "Message blocked by rules"
                    })
    except Exception as e:
        error_msg = f"[!] Error forwarding data ({direction}): {e}"
        print(error_msg)
        if proxy_queue:
            await proxy_queue.put({
                "type": "error",
                "error": f"Error forwarding data: {e}"
            })
    finally:
            writer.close()
            await writer.wait_closed()

def get_original_dest(sock: socket.socket):
    SO_ORIGINAL_DST = 80
    original_dest = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack_from("!H", original_dest, 2)[0]
    ip = socket.inet_ntoa(original_dest[4:8])
    return ip, port

async def handle_connection(src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter, proxy_queue: asyncio.Queue = None) -> None:
    client_addr = src_writer.get_extra_info('peername')
    sock = src_writer.get_extra_info('socket')

    try:
        orig_dst_ip, orig_dst_port = get_original_dest(sock)
        client_ip, client_port = client_addr
        connection_msg = f"[*] TPROXY connection from {client_ip}:{client_port} intended for {orig_dst_ip}:{orig_dst_port}"
        print(connection_msg)

        # Send connection event to GUI if queue is available
        if proxy_queue:
            await proxy_queue.put({
                "type": "connection",
                "event": "new",
                "details": f"Connection from {client_ip}:{client_port} to {orig_dst_ip}:{orig_dst_port}"
            })
    except Exception as e:
        error_msg = f"[!] Error getting socket names: {e}"
        print(error_msg)
        if proxy_queue:
            await proxy_queue.put({
                "type": "error",
                "error": f"Error getting socket names: {e}"
            })
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
            bind_msg = f"[*] Outgoing socket bound to {client_ip}:{client_port}"
            print(bind_msg)
            if proxy_queue:
                await proxy_queue.put({
                    "type": "status",
                    "status": f"Outgoing socket bound to {client_ip}:{client_port}"
                })
        except Exception as e:
            error_msg = f"[!] Warning: Could not bind outgoing socket to {client_ip}:{client_port} (requires CAP_NET_ADMIN or root): {e}. Proceeding with default source."
            print(error_msg)
            if proxy_queue:
                await proxy_queue.put({
                    "type": "error",
                    "error": f"Could not bind outgoing socket: {e}"
                })
            src_writer.close()
            await src_writer.wait_closed()
            return

        loop = asyncio.get_running_loop()

        await loop.sock_connect(remote_socket, (orig_dst_ip, orig_dst_port))

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)
        connect_msg = f"[*] Connected to original destination {orig_dst_ip}:{orig_dst_port}"
        print(connect_msg)
        if proxy_queue:
            await proxy_queue.put({
                "type": "status",
                "status": f"Connected to {orig_dst_ip}:{orig_dst_port}"
            })

        client_to_remote = asyncio.create_task(
            forward_data(
                src_reader, 
                remote_writer, 
                f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}",
                proxy_queue
            )
        )
        remote_to_client = asyncio.create_task(
            forward_data(
                remote_reader, 
                src_writer, 
                f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}",
                proxy_queue
            )
        )

        await asyncio.gather(client_to_remote, remote_to_client)

    except ConnectionRefusedError:
        error_msg = f"[!] Connection refused by {orig_dst_ip}:{orig_dst_port}"
        print(error_msg)
        if proxy_queue:
            await proxy_queue.put({
                "type": "error",
                "error": f"Connection refused by {orig_dst_ip}:{orig_dst_port}"
            })
    except Exception as e:
        error_msg = f"[!] Error in handle_connection: {e}"
        print(error_msg)
        if proxy_queue:
            await proxy_queue.put({
                "type": "error",
                "error": f"Error in connection: {e}"
            })
    finally:
        src_writer.close()
        await src_writer.wait_closed()

    close_msg = f"[*] Connection from {client_addr[0]}:{client_addr[1]} closed"
    print(close_msg)
    if proxy_queue:
        await proxy_queue.put({
            "type": "connection",
            "event": "closed",
            "details": f"Connection from {client_addr[0]}:{client_addr[1]} closed"
        })

async def start_proxy(src_host: str, src_port: int, proxy_queue: asyncio.Queue = None) -> None:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    listening_socket.bind((src_host, src_port))
    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False)

    # Create a factory function that will pass the queue to handle_connection
    def connection_factory(reader, writer):
        return handle_connection(reader, writer, proxy_queue)

    server = await asyncio.start_server(connection_factory, sock=listening_socket)

    addr = server.sockets[0].getsockname()
    status_msg = f"[*] Listening on {addr[0]}:{addr[1]} (transparent)"
    print(status_msg)

    # Send status message to GUI if queue is available
    if proxy_queue:
        await proxy_queue.put({
            "type": "status",
            "status": f"Listening on {addr[0]}:{addr[1]} (transparent)"
        })

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        print("[*] Server cancelled.")
        if proxy_queue:
            await proxy_queue.put({
                "type": "status",
                "status": "Server cancelled"
            })
        raise

def main():
    parser = argparse.ArgumentParser(description="Transparent TCP Proxy with GUI")
    parser.add_argument("--gui", action="store_true", help="Start with GUI interface")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config file")
    args = parser.parse_args()

    config_path = args.config

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    src_config = config.get("src", {})

    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    try:
        if args.gui:
            # Import GUI module only when needed
            from gui import start_gui

            # Create a queue for communication between proxy and GUI
            proxy_queue = asyncio.Queue()

            # Start both the proxy and the GUI
            uvloop.run(start_proxy_with_gui(src_host, src_port, proxy_queue))
        else:
            uvloop.run(start_proxy(src_host, src_port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down from keyboard interrupt...")
    except Exception as e:
        print(f"[!] Error: {e}")

async def start_proxy_with_gui(src_host: str, src_port: int, proxy_queue: asyncio.Queue) -> None:
    """Start the proxy with GUI interface."""
    from gui import start_gui

    # Start the proxy in a separate task
    proxy_task = asyncio.create_task(start_proxy(src_host, src_port, proxy_queue))

    # Start the GUI
    gui_task = asyncio.create_task(start_gui(proxy_queue))

    # Wait for both tasks to complete
    await asyncio.gather(proxy_task, gui_task)


if __name__ == '__main__':
    main()
