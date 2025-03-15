import os
from time import sleep
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class MininetNetwork:

    def __init__(self):
        self.net = None

    def mininet_2h_1s(self):
        self.net = Mininet()

        # alice
        h1 = self.net.addHost('h1', ip='10.10.20.11/24', mac='3c:ec:ef:e3:9e:0c')
        # bob
        h2 = self.net.addHost('h2', ip='10.10.20.13/24', mac='3c:ec:ef:e3:99:c2')
        # mitm
        h3 = self.net.addHost('h3', ip='0.0.0.0/24', mac='3c:ec:ef:e3:99:c3')
        s1 = self.net.addSwitch('s1', failMode='standalone')
        s2 = self.net.addSwitch('s2', failMode='standalone')

        self.net.addLink(h1, s1)
        self.net.addLink(s1, h3)
        self.net.addLink(h3, s2)
        self.net.addLink(s2, h2)

        self.net.start()

        h3.cmd("ifconfig h3-eth0 10.10.20.12 netmask 255.255.255.0")
        h3.cmd("ifconfig h3-eth1 10.10.21.12 netmask 255.255.255.0")

        h2.cmd("ifconfig h2-eth0 10.10.21.13 netmask 255.255.255.0")

        h1.cmd("ip route add default via 10.10.20.12")
        h2.cmd("ip route add default via 10.10.21.12")

        h3.cmd("sysctl -w net.ipv4.ip_forward=1")

        CLI(self.net)

    def stop_mininet(self):
        if self.net:
            self.net.stop()

    @staticmethod
    def cleanup_network():
        os.system('sudo mn -c')
        os.system('sudo fuser -k 6653/tcp')

if __name__ == '__main__':
    setLogLevel('info')

    mininet = MininetNetwork()
    mininet.mininet_2h_1s()
    #mininet.stop_mininet()
    mininet.cleanup_network()