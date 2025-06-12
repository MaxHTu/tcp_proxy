from scapy.all import rdpcap
from scapy.layers.inet import TCP
from scapy.packet import Raw
import socket
import time


def replay_payloads(pcap_file, server_host, server_port, speed_factor=1.0):
    packets = rdpcap(pcap_file)

    payload_events = []
    start_time = None

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if start_time is None:
                start_time = pkt.time
            relative_time = float(pkt.time - start_time)
            payload = bytes(pkt[Raw].load)

            payload_events.append((relative_time, payload))

    payload_events.sort()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_host, server_port))

        replay_start = time.time()
        for i, (rel_ts, data) in enumerate(payload_events):
            target_time = replay_start + (float(rel_ts) / speed_factor)
            sleep_time = float(target_time - time.time())
            if sleep_time > 0.1:
                time.sleep(float(sleep_time - 0.05))

            while time.time() < target_time:
                time.sleep(0.001)

            sock.sendall(data)
            print(f"Sent packet {i + 1}/{len(payload_events)} at time +{time.time() - replay_start:.6f}s")


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        pcap_path = sys.argv[3] if len(sys.argv) >= 4 else os.path.join(os.path.dirname(__file__), "revised.pcap")
        speed_factor = float(sys.argv[4]) if len(sys.argv) >= 5 else 1.0

        print(f"Replaying {pcap_path} to {host}:{port} at speed {speed_factor}x")
        replay_payloads(pcap_path, host, port, speed_factor)
    else:
        print("Usage: python tests/test_replay_pcap.py <host> <port> [pcap_path] [speed_factor]")