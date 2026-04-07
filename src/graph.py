import networkx as nx
from typing import Any, Dict, List, Set

from models import PacketRecord


class ConnectionGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self._node_attributes: Dict[str, Dict] = {}
        self._edge_attributes: Dict[tuple, Dict] = {}

    def add_packet(self, packet: PacketRecord):
        for ip in [packet.src_ip, packet.dst_ip]:
            if ip not in self.graph:
                self.graph.add_node(ip)
                self._node_attributes[ip] = {
                    "first_seen": packet.timestamp,
                    "packet_count": 0,
                    "flagged": False,
                    "internal": self._is_internal(ip),
                }
            self._node_attributes[ip]["packet_count"] += 1

        edge = (packet.src_ip, packet.dst_ip)
        if not self.graph.has_edge(*edge):
            self.graph.add_edge(*edge)
            self._edge_attributes[edge] = {
                "packet_count": 0,
                "total_bytes": 0,
                "protocols": set(),
                "first_seen": packet.timestamp,
            }
        self._edge_attributes[edge]["packet_count"] += 1
        self._edge_attributes[edge]["total_bytes"] += packet.payload_size
        self._edge_attributes[edge]["protocols"].add(packet.protocol)

    def _is_internal(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    def get_neighbors(self, ip: str) -> List[str]:
        if ip not in self.graph:
            return []
        return list(self.graph.neighbors(ip))

    def get_summary(self) -> Dict[str, Any]:
        summary = {
            "nodes": [],
            "edges": [],
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
        }
        for node in self.graph.nodes():
            attrs = self._node_attributes.get(node, {})
            summary["nodes"].append({
                "ip": node,
                "first_seen": attrs.get("first_seen"),
                "packet_count": attrs.get("packet_count"),
                "internal": attrs.get("internal"),
            })
        for src, dst in self.graph.edges():
            attrs = self._edge_attributes.get((src, dst), {})
            summary["edges"].append({
                "src": src,
                "dst": dst,
                "packet_count": attrs.get("packet_count"),
                "protocols": list(attrs.get("protocols", set())),
            })
        return summary

    def get_suspicious_subgraph(self) -> "ConnectionGraph":
        suspicious = ConnectionGraph()
        flagged_nodes = [n for n in self.graph.nodes() if self._node_attributes.get(n, {}).get("flagged")]
        suspicious.graph = self.graph.subgraph(flagged_nodes).copy()
        for n in flagged_nodes:
            suspicious._node_attributes[n] = self._node_attributes.get(n, {}).copy()
        return suspicious