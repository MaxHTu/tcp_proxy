import os
from time import sleep
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class MininetNetwork:

    def __init__(self):
        self.net = None

    def setup_network(self):
        self.net = Mininet()

        # alice
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

        h2.cmd('iptables -t mangle -A PREROUTING -p tcp --dport 9000 -j TPROXY --on-port 8000 --tproxy-mark 1')

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

        # Show listening status
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

    def run_replay_test(self):
        h1 = self.net.get('h1')

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        venv_path = os.path.abspath(os.path.join(project_root, '.venv'))
        activation_cmd = f"cd {project_root} && source {venv_path}/bin/activate && "

        pcap_path = os.path.join(project_root, 'tests', 'revised.pcap')
        output = h1.cmd(f"{activation_cmd} python3 -u tests/test_replay_pcap.py 10.0.2.2 9000 {pcap_path}")



if __name__ == '__main__':
    setLogLevel('info')

    mininet = MininetNetwork()
    mininet.setup_network()

    mininet.setup_tproxy()

    mininet.start_server()

    mininet.start_proxy()

    mininet.run_replay_test()

    os.system('sudo chmod 777 ../proxy.log')

    mininet.cleanup_network()