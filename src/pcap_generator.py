import json
from pathlib import Path
from typing import List, Tuple, Dict, Any
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
from faker import Faker

from models import PacketRecord, TaskConfig, GroundTruth


fake = Faker()


def parse_packets(pcap_path: str) -> Tuple[List[PacketRecord], GroundTruth]:
    packets = []
    ground_truth = GroundTruth(
        malicious_packets=[],
        packet_roles={},
        sessions={},
        session_roles={},
        entry_point=None,
    )

    try:
        scapy_packets = rdpcap(pcap_path)
    except FileNotFoundError:
        return packets, ground_truth
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return packets, ground_truth

    for idx, pkt in enumerate(scapy_packets):
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        flags = []

        if TCP in pkt:
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = []
            if tcp_layer.flags & 0x02:
                flags.append("SYN")
            if tcp_layer.flags & 0x10:
                flags.append("ACK")
            if tcp_layer.flags & 0x01:
                flags.append("FIN")
            if tcp_layer.flags & 0x04:
                flags.append("RST")
            if tcp_layer.flags & 0x08:
                flags.append("PSH")
        elif UDP in pkt:
            protocol = "UDP"
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif ICMP in pkt:
            protocol = "ICMP"
        elif DNS in pkt:
            protocol = "DNS"
            dst_port = 53

        raw_payload = b""
        if Raw in pkt:
            raw_payload = bytes(pkt[Raw].load)
        elif bytes(ip_layer.payload):
            raw_payload = bytes(ip_layer.payload)

        payload_size = len(ip_layer.payload) if ip_layer else 0
        payload_preview = ""
        full_payload = None
        if raw_payload[:20]:
            payload_preview = raw_payload[:20].hex()[:40]
            try:
                full_payload = raw_payload.decode("utf-8", errors="replace")
            except Exception:
                full_payload = raw_payload.hex()

        packets.append(PacketRecord(
            packet_id=f"pkt_{idx+1:04d}",
            timestamp=float(pkt.time) if hasattr(pkt, 'time') else float(idx),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload_size=payload_size,
            ttl=ip_layer.ttl if hasattr(ip_layer, 'ttl') else 64,
            flags=flags,
            is_revealed=False,
            payload_preview=payload_preview,
            full_payload=full_payload,
        ))

    return packets, ground_truth


def load_task_annotation(annotation_path: str) -> Dict[str, Any]:
    path = Path(annotation_path)
    if not path.exists():
        return {}
    with open(path, 'r') as f:
        return json.load(f)


class RealPCAPGenerator:
    def __init__(self, config: TaskConfig, annotation: Dict[str, Any]):
        self.config = config
        self.annotation = annotation
        self.pcap_file = annotation.get("pcap_file", "")

    def generate(self, seed: int = None) -> Tuple[List[PacketRecord], GroundTruth]:
        if not self.pcap_file:
            return [], GroundTruth()

        base_dir = Path(__file__).parent.parent / "pcaps"
        pcap_path = base_dir / self.pcap_file

        packets, ground_truth = parse_packets(str(pcap_path))

        malicious_ids = [self._normalize_packet_id(pid) for pid in self.annotation.get("malicious_packets", [])]
        packet_roles = {
            self._normalize_packet_id(pid): role
            for pid, role in self.annotation.get("packet_roles", {}).items()
        }
        sessions = {
            session_name: [self._normalize_packet_id(pid) for pid in packet_ids]
            for session_name, packet_ids in self.annotation.get("sessions", {}).items()
        }
        session_roles = {
            session_name: role
            for session_name, role in self.annotation.get("session_roles", {}).items()
        }

        ground_truth.malicious_packets = malicious_ids
        ground_truth.packet_roles = packet_roles
        ground_truth.sessions = sessions
        ground_truth.session_roles = session_roles
        entry_point = self.annotation.get("entry_point")
        ground_truth.entry_point = self._normalize_packet_id(entry_point) if entry_point else None

        packet_lookup = {packet.packet_id: packet for packet in packets}
        for packet_id in malicious_ids:
            packet = packet_lookup.get(packet_id)
            if packet:
                packet.is_malicious = True
                packet.attack_role = packet_roles.get(packet_id)

        return packets, ground_truth

    @staticmethod
    def _normalize_packet_id(value: Any) -> str:
        text = str(value)
        if text.startswith("pkt_"):
            return text
        if text.isdigit():
            return f"pkt_{int(text):04d}"
        return text


class PCAPGenerator:
    def __init__(self, config: TaskConfig, annotation: Dict[str, Any] = None):
        self.config = config
        self.annotation = annotation or {}

    def generate(self, seed: int = None) -> Tuple[List[PacketRecord], GroundTruth]:
        pcap_file = getattr(self.config, 'pcap_file', None)
        if pcap_file:
            annotation_path = Path(__file__).parent.parent / "pcaps" / f"{pcap_file}.json"
            self.annotation = load_task_annotation(str(annotation_path))
            return RealPCAPGenerator(self.config, self.annotation).generate(seed)

        rng = __import__('random').Random(seed or self.config.seed)
        packets = []
        ground_truth = GroundTruth(
            malicious_packets=[],
            packet_roles={},
            sessions={},
            session_roles={},
            entry_point=None,
        )

        attacker_ip = f"10.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        target_network = "192.168.1"
        target_ip = f"{target_network}.{rng.randint(1, 254)}"

        scan_count = int(self.config.total_packets * 0.1)
        for i in range(scan_count):
            pkt_id = f"pkt_{i+1:04d}"
            packets.append(PacketRecord(
                packet_id=pkt_id,
                timestamp=1000.0 + i * 0.001,
                src_ip=attacker_ip,
                dst_ip=f"{target_network}.{i+1}",
                src_port=rng.randint(40000, 60000),
                dst_port=i + 1,
                protocol="TCP",
                payload_size=0,
                ttl=rng.randint(32, 64),
                flags=["SYN"],
                is_revealed=False,
                payload_preview="",
                is_malicious=True,
                attack_role="scan",
            ))
            ground_truth.malicious_packets.append(pkt_id)
            ground_truth.packet_roles[pkt_id] = "scan"
            ground_truth.scan_packets.append(pkt_id)
            if i == 0:
                ground_truth.entry_point = pkt_id

        c2_count = int(self.config.total_packets * 0.3)
        c2_port = 4444
        for i in range(c2_count):
            pkt_id = f"pkt_{scan_count + i+1:04d}"
            packets.append(PacketRecord(
                packet_id=pkt_id,
                timestamp=1001.0 + i * 1.0,
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=rng.randint(40000, 60000),
                dst_port=c2_port,
                protocol="TCP",
                payload_size=rng.randint(32, 128),
                ttl=128,
                flags=["PSH", "ACK"],
                is_revealed=False,
                payload_preview=fake.sha256()[:20],
                is_malicious=True,
                attack_role="c2",
            ))
            ground_truth.malicious_packets.append(pkt_id)
            ground_truth.packet_roles[pkt_id] = "c2"

        noise_count = int(self.config.total_packets * 0.6)
        base_idx = scan_count + c2_count
        for i in range(noise_count):
            protocol = rng.choice(["TCP", "UDP", "DNS", "HTTPS"])
            pkt_id = f"pkt_{base_idx + i+1:04d}"

            if protocol == "DNS":
                dst_ip = "8.8.8.8"
                dst_port = 53
            elif protocol == "HTTPS":
                dst_ip = fake.ipv4()
                dst_port = 443
            else:
                dst_ip = target_ip
                dst_port = rng.choice([80, 443, 445, 3389])

            packets.append(PacketRecord(
                packet_id=pkt_id,
                timestamp=1000.0 + rng.uniform(0, 100),
                src_ip=target_ip if rng.random() > 0.3 else fake.ipv4(),
                dst_ip=dst_ip,
                src_port=rng.randint(40000, 60000),
                dst_port=dst_port,
                protocol=protocol,
                payload_size=rng.randint(40, 1500),
                ttl=rng.choice([64, 128, 255]),
                flags=[],
                is_revealed=False,
                payload_preview="",
                is_malicious=False,
            ))

        packets.sort(key=lambda p: p.timestamp)
        for i, p in enumerate(packets):
            p.packet_id = f"pkt_{i+1:04d}"

        return packets, ground_truth
