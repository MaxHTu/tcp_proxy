import asyncio
import yaml
import uvloop
import socket
import struct
import binascii
import logging
import os
from datetime import datetime
from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler
from utils.mitm_attack_handler import MitmAttackHandler

# Setup logging
def setup_logging():
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

    # Create a unique log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"logs/tcp_proxy_{timestamp}.log"

    # Configure logging to write to both file and console
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )

    print(f"[*] Logging to file: {log_filename}")
    return log_filename

async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, source_ip: str, target_ip: str) -> None:
    decoder = PickleDecoder()
    payload_handler = PayloadHandler()
    direction_name = payload_handler.get_matching_direction(source_ip, target_ip)
    mitm_handler = MitmAttackHandler(direction_name, payload_handler)
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break
            original_data = data
            message_pairs = decoder.add_data_with_raw(data)

            if message_pairs:
                logging.info(f"[{direction}] Decoded {len(message_pairs)} message(s):")
                for i, (_, formatted_msg) in enumerate(message_pairs, 1):
                    logging.info(f"[{direction}] Message {i}:")
                    logging.info(f"{formatted_msg}")
                    # Add hex dump for debugging
                    if direction_name and payload_handler.should_log_attack(direction_name):
                        logging.info(f"[{direction}] Raw data hex: {data[:100].hex()}")
            else:
                logging.info(f"[{direction}] No complete messages in chunk ({len(data)} bytes)")
                # Add hex dump for debugging even when no messages decoded
                if direction_name and payload_handler.should_log_attack(direction_name):
                    logging.info(f"[{direction}] Raw data hex: {data[:100].hex()}")
            should_forward = True
            insertions = []
            for raw_msg, _ in message_pairs:
                mitm_result = await mitm_handler.process_message(raw_msg, original_data, writer, source_ip, target_ip)
                
                # Handle special MITM signals
                if mitm_result == "RST_CONNECTION":
                    if direction_name and payload_handler.should_log_attack(direction_name):
                        logging.info(f"[{direction}] MITM handler requested connection reset")
                    # Force TCP RST by closing the writer abruptly
                    try:
                        sock = writer.get_extra_info('socket')
                        if sock:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    except:
                        pass
                    writer.close()
                    return  # Exit the function to trigger connection reset
                
                elif mitm_result == "RST_ALL_CONNECTIONS":
                    if direction_name and payload_handler.should_log_attack(direction_name):
                        logging.info(f"[{direction}] MITM handler requested reset of ALL connections")
                    # Force TCP RST by closing the writer abruptly
                    try:
                        sock = writer.get_extra_info('socket')
                        if sock:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    except:
                        pass
                    writer.close()
                    # Also close the other direction's connection by raising an exception
                    # This will cause both forward_data tasks to exit
                    raise ConnectionResetError("MITM attack reset all connections")
                
                if mitm_result is False:
                    should_forward = False
                    break
                    
                should_forward2, msg_insertions = await payload_handler.process_messages(raw_msg, source_ip, target_ip)
                insertions.extend(msg_insertions)
                if not should_forward2:
                    should_forward = False
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
                logging.info(f"[{direction}] Message blocked by rules")
    except Exception as e:
        logging.error(f"Error forwarding data ({direction}): {e}")
        # Don't print full traceback for expected connection resets
        if "Connection reset by peer" not in str(e) and "Broken pipe" not in str(e):
            import traceback
            logging.error(traceback.format_exc())
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
        logging.info(f"TPROXY connection from {client_ip}:{client_port} intended for {orig_dst_ip}:{orig_dst_port}")
    except Exception as e:
        logging.error(f"Error getting socket names: {e}")
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
            logging.info(f"Outgoing socket bound to {client_ip}:{client_port}")
        except Exception as e:
            logging.warning(f"Could not bind outgoing socket to {client_ip}:{client_port} (requires CAP_NET_ADMIN or root): {e}. Proceeding with default source.")
            src_writer.close()
            await src_writer.wait_closed()
            return

        loop = asyncio.get_running_loop()
        # Retry connect briefly on ECONNREFUSED to allow remote to settle after resets
        connect_attempts = [0.2, 0.4, 0.8]  # seconds
        while True:
            try:
                await loop.sock_connect(remote_socket, (orig_dst_ip, orig_dst_port))
                break
            except ConnectionRefusedError:
                if not connect_attempts:
                    raise
                delay = connect_attempts.pop(0)
                logging.info(f"Connect to {orig_dst_ip}:{orig_dst_port} refused, retrying in {delay:.1f}s")
                await asyncio.sleep(delay)

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)
        logging.info(f"Connected to original destination {orig_dst_ip}:{orig_dst_port}")

        client_to_remote = asyncio.create_task(forward_data(src_reader, remote_writer, f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}", client_ip, orig_dst_ip))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, src_writer, f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}", orig_dst_ip, client_ip))

        await asyncio.gather(client_to_remote, remote_to_client)

    except ConnectionRefusedError:
        logging.error(f"Connection refused by {orig_dst_ip}:{orig_dst_port}")
    except Exception as e:
        logging.error(f"Error in handle_connection: {e}")
        #  import traceback
        # traceback.print_exc()
    finally:
        src_writer.close()
        await src_writer.wait_closed()
    logging.info(f"Connection from {client_addr[0]}:{client_addr[1]} closed")

async def start_proxy(src_host: str, src_port: int) -> None:
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

    listening_socket.bind((src_host, src_port))
    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False)

    server = await asyncio.start_server(handle_connection, sock=listening_socket)

    addr = server.sockets[0].getsockname()
    logging.info(f"Listening on {addr[0]}:{addr[1]} (transparent)")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        logging.info("Server cancelled.")
        raise

def main():
    config_path = "config/config.yaml"

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    src_config = config.get("src", {})

    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    # Setup logging
    log_filename = setup_logging()
    logging.info("Starting TCP proxy with MITM attack capabilities")

    try:
        uvloop.run(start_proxy(src_host, src_port))
    except KeyboardInterrupt:
        logging.info("Shutting down from keyboard interrupt...")
    except Exception as e:
        logging.error(f"Error: {e}")
        import traceback
        logging.error(traceback.format_exc())


if __name__ == '__main__':
    main()