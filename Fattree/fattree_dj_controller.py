from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
from pox.lib.recoco import Timer
import pox.lib.packet as pkt

from collections import defaultdict
import heapq

log = core.getLogger()

class DijkstraController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.graph = defaultdict(dict)
        self.paths = defaultdict(lambda: defaultdict(list))

    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.debug("Switch %s has come up.", dpid)

    def _handle_LinkEvent(self, event):
        link = event.link
        if event.added:
            self.graph[link.dpid1][link.dpid2] = link.port1
            self.graph[link.dpid2][link.dpid1] = link.port2
            self._calculate_paths()
        elif event.removed:
            if link.dpid2 in self.graph[link.dpid1]:
                del self.graph[link.dpid1][link.dpid2]
                del self.graph[link.dpid2][link.dpid1]
            self._calculate_paths()

    def _calculate_paths(self):
        log.debug("Calculating shortest paths.")
        for src in self.graph:
            paths, distances = self._dijkstra(src)
            for dst in paths:
                self.paths[src][dst] = paths[dst]

    def _dijkstra(self, src):
        distances = {}
        previous = {}
        nodes = []
        for vertex in self.graph:
            if vertex == src:
                distances[vertex] = 0
                heapq.heappush(nodes, (0, vertex))
            else:
                distances[vertex] = float('inf')
                heapq.heappush(nodes, (float('inf'), vertex))
            previous[vertex] = None

        while nodes:
            smallest_distance, smallest_vertex = heapq.heappop(nodes)
            if smallest_distance == float('inf'):
                break

            for neighbor, port in self.graph[smallest_vertex].items():
                alt = distances[smallest_vertex] + 1  # Assume each link has a weight of 1
                if alt < distances[neighbor]:
                    distances[neighbor] = alt
                    previous[neighbor] = smallest_vertex
                    heapq.heappush(nodes, (alt, neighbor))

        # Reconstruct paths
        paths = {}
        for vertex in previous:
            path = []
            while vertex:
                path.append(vertex)
                vertex = previous[vertex]
            path = path[::-1]
            paths[vertex] = path[1:]  # Exclude the source itself

        return paths, distances

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == pkt.ethernet.ARP_TYPE:
            self._flood_packet(event)
        elif packet.type == pkt.ethernet.IP_TYPE:
            self._route_packet(event)

    def _flood_packet(self, event):
        """
        Floods the packet on all ports except the port it came in on.
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp.data
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _route_packet(self, event):
        """
        Route the packet based on precomputed paths
        """
        packet = event.parsed
        src_mac = packet.src
        dst_mac = packet.dst
        dpid = event.dpid

        if dst_mac in self.paths[dpid]:
            path = self.paths[dpid][dst_mac]
            if path:
                next_hop = path[0]
                out_port = self.graph[dpid][next_hop]
                self._send_packet(event, out_port)
            else:
                log.debug("No path to destination, flooding")
                self._flood_packet(event)
        else:
            log.debug("Destination not known, flooding")
            self._flood_packet(event)

    def _send_packet(self, event, out_port):
        """
        Sends a packet out of the specified switch port.
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp.data
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

def launch():
    core.registerNew(DijkstraController)
