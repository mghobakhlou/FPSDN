from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch

class CustomTopo(Topo):
    def build(self):
        # Add controllers
        c1 = self.addSwitch('c1')
        c2 = self.addSwitch('c2')
        c3 = self.addSwitch('c3')
        c4 = self.addSwitch('c4')

        # Add aggregation switches
        a1 = self.addSwitch('a1')
        a2 = self.addSwitch('a2')
        a3 = self.addSwitch('a3')
        a4 = self.addSwitch('a4')
        a5 = self.addSwitch('a5')
        a6 = self.addSwitch('a6')
        a7 = self.addSwitch('a7')
        a8 = self.addSwitch('a8')

        # Add Top-of-Rack switches
        tor1 = self.addSwitch('tor1')
        tor2 = self.addSwitch('tor2')
        tor3 = self.addSwitch('tor3')
        tor4 = self.addSwitch('tor4')
        tor5 = self.addSwitch('tor5')
        tor6 = self.addSwitch('tor6')
        tor7 = self.addSwitch('tor7')
        tor8 = self.addSwitch('tor8')

        # Add terminal hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')
        h11 = self.addHost('h11')
        h12 = self.addHost('h12')
        h13 = self.addHost('h13')
        h14 = self.addHost('h14')
        h15 = self.addHost('h15')
        h16 = self.addHost('h16')

        # Add links between controllers and aggregation switches
        self.addLink(a1, c1)
        self.addLink(a1, c2)
        self.addLink(a2, c3)
        self.addLink(a2, c4)
        self.addLink(a3, c1)
        self.addLink(a3, c2)
        self.addLink(a4, c3)
        self.addLink(a4, c4)
        self.addLink(a5, c1)
        self.addLink(a5, c2)
        self.addLink(a6, c3)
        self.addLink(a6, c4)
        self.addLink(a7, c1)
        self.addLink(a7, c2)
        self.addLink(a8, c3)
        self.addLink(a8, c4)

        # Add links between aggregation switches and Top-of-Rack switches
        self.addLink(tor1, a1)
        self.addLink(tor1, a2)
        self.addLink(tor2, a1)
        self.addLink(tor2, a2)

        self.addLink(tor3, a3)
        self.addLink(tor3, a4)
        self.addLink(tor4, a3)
        self.addLink(tor4, a4)

        self.addLink(tor5, a5)
        self.addLink(tor5, a6)
        self.addLink(tor6, a5)
        self.addLink(tor6, a6)

        self.addLink(tor7, a7)
        self.addLink(tor7, a8)
        self.addLink(tor8, a7)
        self.addLink(tor8, a8)

        # Add links between aggregation switches and Top-of-Rack switches
        self.addLink(h1, tor1)
        self.addLink(h2, tor1)
        self.addLink(h3, tor2)
        self.addLink(h4, tor2)
        self.addLink(h5, tor3)
        self.addLink(h6, tor3)
        self.addLink(h7, tor4)
        self.addLink(h8, tor4)
        self.addLink(h9, tor5)
        self.addLink(h10, tor5)
        self.addLink(h11, tor6)
        self.addLink(h12, tor6)
        self.addLink(h13, tor7)
        self.addLink(h14, tor7)
        self.addLink(h15, tor8)
        self.addLink(h16, tor8)

def run():
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    topo = CustomTopo()

    net = Mininet(topo=topo, controller=c0)
    # net.build()
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
