#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


class ChokepointTopo(Topo):
    def build(self):
    	# The hosts and the switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
	
        h_attacker = self.addHost('h_atk', ip='10.0.0.10/24')  
        h_user1 = self.addHost('h_user1', ip='10.0.0.11/24')
        h_user2 = self.addHost('h_user2', ip='10.0.0.12/24')
        h_scanner = self.addHost('h_scan', ip='10.0.0.13/24')
        srv_critical = self.addHost('srv_crit', ip='10.0.0.20/24')
        srv_lowpri = self.addHost('srv_low', ip='10.0.0.21/24')
	
	#The links between the devices
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)

        self.addLink(s2, h_attacker)
        self.addLink(s2, h_user1)

        self.addLink(s3, h_user2)
        self.addLink(s3, h_scanner)

        self.addLink(s4, srv_critical)
        self.addLink(s4, srv_lowpri)


def run():
    setLogLevel('info')

    topo = ChokepointTopo()

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        controller=None,
        autoSetMacs=True,
    )
	
    net.addController(
        'c0', controller=RemoteController, ip='127.0.0.1', port=6653,  
    )

    net.start()

    info('Topology up: s1 (core) <-> s2, s3, s4\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()
