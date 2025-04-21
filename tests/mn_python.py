import os
from time import sleep
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import pickle
import struct


class MininetNetwork:

    def __init__(self):
        self.net = None

    def setup_network(self):
        self.net = Mininet()

        h1 = self.net.addHost('h1', ip=None)
        h2 = self.net.addHost('h2', ip=None)
        h3 = self.net.addHost('h3', ip=None)

        self.net.addLink(h1, h2, intfName1='h1-eth0', intfName2='h2-eth0')
        self.net.addLink(h2, h3, intfName1='h2-eth1', intfName2='h3-eth0')

        self.net.start()

        h1.intf('h1-eth0').setIP('10.0.1.1', 24)
        h2.intf('h2-eth0').setIP('10.0.1.2', 24)
        h2.intf('h2-eth1').setIP('10.0.2.1', 24)
        h3.intf('h3-eth0').setIP('10.0.2.2', 24)

        h2.cmd('sysctl -w net.ipv4.ip_forward=1')

        h2.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
        h2.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
        h2.cmd('sysctl -w net.ipv4.conf.h2-eth0.rp_filter=0')
        h2.cmd('sysctl -w net.ipv4.conf.h2-eth1.rp_filter=0')

        h1.cmd('ip route add default via 10.0.1.2')
        h3.cmd('ip route add default via 10.0.2.1')

        return self.net

    def setup_tproxy(self):
        h2 = self.net.get('h2')

        h2.cmd('iptables -t mangle -F')
        h2.cmd('iptables -t mangle -X DIVERT 2>/dev/null || true')
        h2.cmd('ip rule del fwmark 1 lookup 100 2>/dev/null || true')
        h2.cmd('ip route flush table 100 2>/dev/null || true')

        h2.cmd('ip rule add fwmark 1 lookup 100')
        h2.cmd('ip route add local 0.0.0.0/0 dev lo table 100')

        h2.cmd('iptables -t mangle -N DIVERT')
        h2.cmd('iptables -t mangle -A DIVERT -j MARK --set-mark 1')
        h2.cmd('iptables -t mangle -A DIVERT -j ACCEPT')

        h2.cmd('iptables -t mangle -A PREROUTING -p tcp -s 10.0.1.1 -d 10.0.2.2 --dport 9000 -j TPROXY --on-port 8000 --tproxy-mark 1')

        h2.cmd('iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT')

    def start_proxy(self):
        h2 = self.net.get('h2')

        h2.cmd('pkill -f "python.*proxy" || true')
        h2.cmd('> /tmp/proxy.log')
        h2.cmd('fuser -k 8000/tcp || true')

        venv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.venv'))

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

        activation_cmd = f"cd {project_root} && source {venv_path}/bin/activate && "

        h2.cmd(f"{activation_cmd} python3 -u tcp_proxy.py > proxy.log 2>&1 &")

        sleep(2)

        pid = h2.cmd('pgrep -f "python.*tcp_proxy.py"').strip()
        info(f'*** Original TCP proxy started on h2 (PID: {pid})\n')

        listening = h2.cmd('ss -tuln | grep 8000')
        info(f'*** Proxy listening status: {listening}')

    def cleanup_network(self):
        if self.net:
            self.net.stop()

        os.system('sudo pkill -f "python.*proxy" > /dev/null 2>&1')
        os.system('sudo pkill -f "http.server" > /dev/null 2>&1')
        os.system('sudo pkill -f tcpdump > /dev/null 2>&1')
        os.system('sudo iptables -t mangle -F')
        os.system('sudo iptables -t mangle -X DIVERT 2>/dev/null || true')
        os.system('sudo ip rule del fwmark 1 lookup 100 2>/dev/null || true')
        os.system('sudo ip route flush table 100 2>/dev/null || true')

    def monitor_traffic(self):
        h2 = self.net.get('h2')

        h2.cmd('tcpdump -i any port 80 or port 8000 -n -w test.pcap > /dev/null 2>&1 &')

    def start_server(self):
        h3 = self.net.get('h3')

        h3.cmd('pkill -f "nc -l" || true')
        h3.cmd('nc -l -p 9000 -k> /tmp/received_data.bin 2>&1 &')

    def send_python_messages(self):
        """
        Send Python-specific messages (pickle-encoded) to test the proxy's handling
        of Python objects and rule application.
        """
        h1 = self.net.get('h1')
        info('*** Sending Python messages to test proxy rules\n')

        # Create test messages with different actions
        messages = [
            {"action": "update_tt_remote", "data": "This should be blocked"},
            {"action": "get_status", "data": "This should be replayed 3 times"},
            {"action": "normal_action", "data": "This should pass through normally"}
        ]

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        venv_path = os.path.abspath(os.path.join(project_root, '.venv'))
        activation_cmd = f"cd {project_root} && source {venv_path}/bin/activate && "

        # Create a temporary Python script to send the messages
        script_path = "/tmp/send_python_messages.py"
        with open(script_path, "w") as f:
            f.write("""
import socket
import pickle
import struct
import time

def send_pickle_message(sock, message):
    # Pickle the message
    pickled_data = pickle.dumps(message)
    
    # Create a header with the message length
    header = struct.pack('>I', len(pickled_data))
    
    # Send the header and the pickled data
    sock.sendall(header + pickled_data)
    print(f"Sent message with action: {message.get('action', 'unknown')}")

# Connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('10.0.2.2', 9000))
    
    # Send test messages
    messages = [
        {"action": "update_tt_remote", "data": "This should be blocked"},
        {"action": "get_status", "data": "This should be replayed 3 times"},
        {"action": "normal_action", "data": "This should pass through normally"}
    ]
    
    for message in messages:
        send_pickle_message(s, message)
        time.sleep(1)  # Wait a bit between messages
""")

        # Run the script
        h1.cmd(f"{activation_cmd} python3 {script_path}")
        info('*** Python messages sent\n')

if __name__ == '__main__':
    setLogLevel('info')

    mininet = MininetNetwork()
    mininet.setup_network()

    mininet.setup_tproxy()

    mininet.start_server()

    mininet.start_proxy()

    # Instead of running the replay test, send Python-specific messages
    mininet.send_python_messages()

    CLI(mininet.net)

    mininet.cleanup_network()