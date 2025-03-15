import asyncio
import argparse
import functools


async def forward_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str) -> None:
    try:
        while True:
            data = await reader.read(1504)
            if not data:
                break
            print(f"[{direction}] [{data!r}]")
            writer.write(data)
            await writer.drain()
    except Exception as e:
        print(f"[!] Error forwarding data ({direction}): {e}")
    finally:
        if not writer.is_closing():
            writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

async def handle_connection(src_reader: asyncio.StreamReader, src_writer: asyncio.StreamWriter, dst_host: str, dst_port: int) -> None:
    client_addr = src_writer.get_extra_info('peername')
    print(f"[*] New connection from {client_addr[0]}:{client_addr[1]}")

    try:
        remote_reader, remote_writer = await asyncio.open_connection(dst_host, dst_port)
        print(f"[*] Connected to remote host {dst_host}:{dst_port}")

        client_to_remote = asyncio.create_task(forward_data(src_reader, remote_writer, "client->remote"))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, src_writer, "client<-remote"))

        done, pending = await asyncio.wait([client_to_remote, remote_to_client], return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()

    except Exception as e:
        print(f"[!] Error connecting to remote host: {e}")
    finally:
        if not src_writer.is_closing():
            src_writer.close()
        try:
            await src_writer.wait_closed()
        except:
            pass
    print(f"[*] Connection from {client_addr[0]}:{client_addr[1]} closed")

async def start_proxy(src_host: str, src_port: str, dst_host: str, dst_port: str) -> None:
    handler = functools.partial(handle_connection, dst_host=dst_host, dst_port=dst_port)
    server = await asyncio.start_server(handler, src_host, src_port)

    addr = server.sockets[0].getsockname()
    print(f"[*] Listening on {addr[0]}:{addr[1]}")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        print("[*] Server cancelled.")


def main():
    parser = argparse.ArgumentParser(description='TCP Proxy')
    parser.add_argument("--src-host", default="0.0.0.0")
    parser.add_argument("--src-port", type=int, default=8080)
    parser.add_argument("--dst-host", required=True)
    parser.add_argument("--dst-port", type=int, required=True)
    args = parser.parse_args()

    try:
        asyncio.run(start_proxy(args.src_host, args.src_port, args.dst_host, args.dst_port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down from keyboard interrupt...")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == '__main__':
    main()