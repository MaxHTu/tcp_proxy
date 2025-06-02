import asyncio
import yaml
import uvloop
import socket
import struct
from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler


async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, source_ip: str, target_ip: str) -> None:
    decoder = PickleDecoder()
    payload_handler = PayloadHandler()

    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break

            # print(f"[DEBUG] {direction}] [{data!r}")

            original_data = data

            message_pairs = decoder.add_data_with_raw(data)

            if message_pairs:
                print(f"[{direction}] Decoded {len(message_pairs)} message(s):")
                for i, (_, formatted_msg) in enumerate(message_pairs, 1):
                    print(f"[{direction}] Message {i}:")
                    print(f"{formatted_msg}")
            else:
                print(f"[{direction}] No complete messages in chunk ({len(data)} bytes)")

            should_forward = True
            all_replayed_messages = []

            for raw_msg, _ in message_pairs:
                should_forward, replayed_messages = await payload_handler.process_messages(raw_msg, source_ip, target_ip)

                all_replayed_messages.extend(replayed_messages)

                if not should_forward:
                    break

            if should_forward:
                writer.write(original_data)
                await writer.drain()
            else:
                print(f"[{direction}] Message blocked by rules")

    except Exception as e:
        print(f"[!] Error forwarding data ({direction}): {e}")
        # import traceback
        # traceback.print_exc()
    finally:
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

        client_to_remote = asyncio.create_task(forward_data(src_reader, remote_writer, f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}", client_ip, orig_dst_ip))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, src_writer, f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}", orig_dst_ip, client_ip))

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

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    src_config = config.get("src", {})

    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    try:
        uvloop.run(start_proxy(src_host, src_port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down from keyboard interrupt...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == '__main__':
    main()
