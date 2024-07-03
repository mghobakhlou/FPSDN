from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

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

        # Add terminal hosts
        t1 = self.addHost('t1')
        t2 = self.addHost('t2')
        t3 = self.addHost('t3')
        t4 = self.addHost('t4')
        t5 = self.addHost('t5')
        t6 = self.addHost('t6')
        t7 = self.addHost('t7')
        t8 = self.addHost('t8')

        # Add links between controllers and aggregation switches
        self.addLink(c1, a1)
        self.addLink(c1, a2)
        self.addLink(c1, a3)
        self.addLink(c2, a3)
        self.addLink(c2, a4)
        self.addLink(c2, a5)
        self.addLink(c3, a4)
        self.addLink(c3, a5)
        self.addLink(c3, a6)
        self.addLink(c4, a6)
        self.addLink(c4, a7)
        self.addLink(c4, a8)

        # Add links between aggregation switches and terminal hosts
        self.addLink(a1, t1)
        self.addLink(a1, t2)
        self.addLink(a2, t1)
        self.addLink(a2, t2)
        self.addLink(a3, t3)
        self.addLink(a3, t4)
        self.addLink(a4, t3)
        self.addLink(a4, t4)
        self.addLink(a5, t5)
        self.addLink(a5, t6)
        self.addLink(a6, t5)
        self.addLink(a6, t6)
        self.addLink(a7, t7)
        self.addLink(a7, t8)
        self.addLink(a8, t7)
        self.addLink(a8, t8)

def run():
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    topo = CustomTopo()
    # link = TCLink

    net = Mininet(topo=topo, controller=c0)
    # net.build()
    net.start()
    CLI(net)
    net.stop()


    # topo = CustomTopo()
    # net = Mininet(topo=topo, controller=RemoteController)
    
    # # Add remote controller
    # net.addController('c0', controller=RemoteController, port=6653)
    
    # net.start()
    # CLI(net)
    # net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
