import asyncio
import yaml
import uvloop
import socket
import struct
import time # Added
from typing import Optional, Tuple # Added for type hinting
from utils.decode_pickle import PickleDecoder
from utils.payload_handling import PayloadHandler

# Global Proxy Start Time
PROXY_START_TIME = 0.0 # Added

async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, source_ip: str, target_ip: str) -> None:
    decoder = PickleDecoder()
    # Modified instantiation of PayloadHandler
    payload_handler = PayloadHandler(proxy_start_time=PROXY_START_TIME)

    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break

            original_data = data # Keep a reference to the original chunk

            message_pairs = decoder.add_data_with_raw(data)

            should_forward_chunk = True 
            chunk_insert_data: Optional[Tuple[bytes, str]] = None
            all_replayed_messages_for_chunk = [] # Though not used yet by PayloadHandler

            if message_pairs:
                print(f"[{direction}] Decoded {len(message_pairs)} message(s):")
                for i, (raw_msg, formatted_msg) in enumerate(message_pairs, 1):
                    print(f"[{direction}] Message {i}:")
                    print(f"{formatted_msg}")

                    # Process each message
                    # Updated unpacking for the return values of process_messages
                    should_forward_msg, msg_insert_data_tuple, replayed_msgs_for_msg = await payload_handler.process_messages(
                        raw_msg, source_ip, target_ip
                    )
                    all_replayed_messages_for_chunk.extend(replayed_msgs_for_msg)

                    if not should_forward_msg:
                        should_forward_chunk = False
                        print(f"[{direction}] Original data chunk blocked due to message {i} with action: {raw_msg.get('action', 'N/A')}")
                        break 

                    if msg_insert_data_tuple and not chunk_insert_data:
                        chunk_insert_data = msg_insert_data_tuple
                        print(f"[{direction}] Data insertion triggered by message {i} for the chunk. Action: {raw_msg.get('action', 'N/A')}")
            else:
                print(f"[{direction}] No complete messages in chunk ({len(data)} bytes)")
                # Potentially, global rules (not tied to a specific message) could still apply to the raw chunk.
                # For insert_data, it's currently tied to a message action.
                # If there was a global rule to insert data for ANY traffic, it would be handled here.
                # For now, we assume insert_data is triggered by a decoded message.
                # Check if any global "always-on" insert rule should apply to this raw chunk.
                # This would require a different call to payload_handler or a different method.
                # For now, if no message_pairs, no insert_data for the chunk unless a global rule applies.
                # Example: Create a dummy message or pass None if your handler supports it for global non-message rules
                # For this iteration, we only trigger insertion based on decoded messages.
                pass


            if should_forward_chunk:
                if chunk_insert_data:
                    inserted_bytes, insert_pos = chunk_insert_data
                    if insert_pos == "before":
                        print(f"[{direction}] Inserting {len(inserted_bytes)} bytes BEFORE original chunk")
                        writer.write(inserted_bytes)
                        await writer.drain()
                
                writer.write(original_data) 
                await writer.drain()

                if chunk_insert_data:
                    inserted_bytes, insert_pos = chunk_insert_data 
                    if insert_pos == "after":
                        print(f"[{direction}] Inserting {len(inserted_bytes)} bytes AFTER original chunk")
                        writer.write(inserted_bytes)
                        await writer.drain()
            else:
                # If the chunk is blocked, we don't forward original_data or inserted_data
                print(f"[{direction}] Original data chunk not forwarded.")
            
            # Handle replayed messages - current payload_handler returns empty list
            # if all_replayed_messages_for_chunk:
            # print(f"[{direction}] Replaying {len(all_replayed_messages_for_chunk)} messages...")
            # for replay_msg_bytes in all_replayed_messages_for_chunk:
            # writer.write(replay_msg_bytes)
            # await writer.drain()

    except ConnectionResetError:
        print(f"[!] Connection reset by peer ({direction})")
    except asyncio.exceptions.IncompleteReadError:
        print(f"[!] Incomplete read from peer ({direction}), connection likely closed.")
    except Exception as e:
        print(f"[!] Error forwarding data ({direction}): {e.__class__.__name__} {e}")
        # import traceback
        # traceback.print_exc()
    finally:
        print(f"[{direction}] Closing writer.")
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
    
    remote_reader = None # Ensure remote_reader and remote_writer are defined for finally block
    remote_writer = None

    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.setblocking(False)
        # IP_TRANSPARENT allows binding to a non-local IP if this machine is a router/gateway for that IP.
        # It also allows binding to a local IP that is not the primary IP of any interface.
        remote_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)

        try:
            # SO_REUSEADDR allows reusing a local address, but it's more nuanced with IP_TRANSPARENT.
            # It's generally good practice for servers.
            remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the outgoing connection to the original client's IP and port.
            # This makes the connection to the destination server appear to come directly from the client.
            remote_socket.bind((client_ip, client_port))
            print(f"[*] Outgoing socket bound to {client_ip}:{client_port}")
        except OSError as e:
            # Common error is EADDRNOTAVAIL if client_ip is not local, or EACCES if not privileged.
            print(f"[!] Warning: Could not bind outgoing socket to {client_ip}:{client_port} (requires CAP_NET_ADMIN or root, or IP to be local): {e}. Proceeding with default source IP/port.")
            # If binding fails, we can still proceed, but the source IP will be one of the machine's own IPs.
            # Depending on routing, this might still work, or it might break if the server expects the original client IP.
            # For true transparent proxying where the server sees the original client IP, this bind must succeed.
        except Exception as e: # Catch other potential exceptions too
            print(f"[!] Error binding outgoing socket: {e}. Closing connection.")
            src_writer.close()
            await src_writer.wait_closed()
            return


        loop = asyncio.get_running_loop()
        await loop.sock_connect(remote_socket, (orig_dst_ip, orig_dst_port))

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)
        print(f"[*] Connected to original destination {orig_dst_ip}:{orig_dst_port}")

        # Create tasks for data forwarding in both directions
        # Pass client_ip and orig_dst_ip for direction-specific rules
        client_to_remote = asyncio.create_task(forward_data(src_reader, remote_writer, f"{client_ip}:{client_port}->{orig_dst_ip}:{orig_dst_port}", client_ip, orig_dst_ip))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, src_writer, f"{client_ip}:{client_port}<-{orig_dst_ip}:{orig_dst_port}", orig_dst_ip, client_ip))

        await asyncio.gather(client_to_remote, remote_to_client)

    except ConnectionRefusedError:
        print(f"[!] Connection refused by {orig_dst_ip}:{orig_dst_port}")
    except socket.gaierror as e: # getaddrinfo error
        print(f"[!] Could not resolve original destination {orig_dst_ip}: {e}")
    except OSError as e: # e.g. "No route to host" or other network errors
        print(f"[!] Network error connecting to {orig_dst_ip}:{orig_dst_port}: {e.strerror} (errno {e.errno})")
    except Exception as e:
        print(f"[!] Error in handle_connection: {e.__class__.__name__}: {e}")
        # import traceback
        # traceback.print_exc()
    finally:
        if remote_writer:
            remote_writer.close()
            await remote_writer.wait_closed()
        src_writer.close()
        await src_writer.wait_closed()
    print(f"[*] Connection from {client_ip}:{client_port} to {orig_dst_ip}:{orig_dst_port} closed")


async def start_proxy(src_host: str, src_port: int) -> None:
    # Create a listening socket with IP_TRANSPARENT option
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1) # Crucial for TPROXY

    try:
        listening_socket.bind((src_host, src_port))
    except OSError as e:
        print(f"[!] Failed to bind listening socket to {src_host}:{src_port}: {e.strerror} (errno {e.errno}). Ensure you have CAP_NET_ADMIN or run as root.")
        return # Exit if binding fails

    listening_socket.listen(socket.SOMAXCONN)
    listening_socket.setblocking(False) # Required for asyncio server

    # Start the asyncio server with the custom socket
    server = await asyncio.start_server(handle_connection, sock=listening_socket)

    addr = server.sockets[0].getsockname()
    print(f"[*] Listening on {addr[0]}:{addr[1]} (transparent proxy mode)")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        print("[*] Server task cancelled.") # Should not happen in normal operation unless main() cancels it
    finally:
        print("[*] Server stopped.")


def main():
    config_path = "config/config.yaml" # Define config path

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[!] Error: Configuration file '{config_path}' not found.")
        return
    except yaml.YAMLError as e:
        print(f"[!] Error parsing YAML configuration: {e}")
        return


    src_config = config.get("src", {})
    src_host = src_config.get("host", "0.0.0.0")
    src_port = src_config.get("port", 8000)

    global PROXY_START_TIME # Added
    PROXY_START_TIME = time.time() # Added

    try:
        uvloop.install() # Install uvloop for performance
        print("[*] uvloop installed.")
        asyncio.run(start_proxy(src_host, src_port)) # Use asyncio.run for Python 3.7+
    except KeyboardInterrupt:
        print("\n[*] Shutting down from keyboard interrupt...")
    except Exception as e: # Catch-all for other potential errors during startup or shutdown
        print(f"[!] Critical Error: {e}")
    finally:
        print("[*] Proxy shutdown complete.")


if __name__ == '__main__':
    main()
