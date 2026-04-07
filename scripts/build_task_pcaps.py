import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, wrpcap


ROOT = Path(__file__).resolve().parents[1]
CSV_DIR = ROOT.parent / "csv"
OUTPUT_DIR = ROOT / "pcaps"
OUTPUT_DIR.mkdir(exist_ok=True)


@dataclass(frozen=True)
class TaskSpec:
    name: str
    source_csv: str
    samples: Dict[str, int]
    seed: int
    description: str


TASK_SPECS = [
    TaskSpec(
        name="easy_task",
        source_csv="Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        samples={"BENIGN": 32, "DDoS": 36},
        seed=7,
        description="Easy DDoS vs benign traffic.",
    ),
    TaskSpec(
        name="medium_task",
        source_csv="Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        samples={
            "BENIGN": 40,
            "Web Attack ? Brute Force": 16,
            "Web Attack ? XSS": 12,
            "Web Attack ? Sql Injection": 8,
        },
        seed=11,
        description="Medium web attack traffic with three attack types.",
    ),
    TaskSpec(
        name="hard_task",
        source_csv="Wednesday-workingHours.pcap_ISCX.csv",
        samples={
            "BENIGN": 48,
            "DoS Hulk": 18,
            "DoS GoldenEye": 12,
            "DoS slowloris": 12,
            "DoS Slowhttptest": 12,
            "Heartbleed": 8,
        },
        seed=19,
        description="Hard high-noise DoS dataset with a rare Heartbleed stream.",
    ),
]


def clean_columns(frame: pd.DataFrame) -> pd.DataFrame:
    frame.columns = [column.strip() for column in frame.columns]
    if "Label" in frame.columns:
        frame["Label"] = frame["Label"].astype(str).map(normalize_source_label)
    return frame


def normalize_source_label(label: str) -> str:
    cleaned = label.replace("\ufffd", "?").strip()
    cleaned = " ".join(cleaned.split())
    replacements = {
        "Web Attack ?Brute Force": "Web Attack ? Brute Force",
        "Web Attack ?Sql Injection": "Web Attack ? Sql Injection",
    }
    return replacements.get(cleaned, cleaned)


def normalize_label(label: str) -> str:
    label = normalize_source_label(label)
    mapping = {
        "BENIGN": "benign",
        "DDoS": "ddos",
        "Web Attack ? Brute Force": "web_bruteforce",
        "Web Attack ? XSS": "web_xss",
        "Web Attack ? Sql Injection": "web_sql_injection",
        "DoS Hulk": "dos_hulk",
        "DoS GoldenEye": "dos_goldeneye",
        "DoS slowloris": "dos_slowloris",
        "DoS Slowhttptest": "dos_slowhttptest",
        "Heartbleed": "heartbleed",
    }
    return mapping.get(label, label.lower().replace(" ", "_"))


def payload_for(label: str, flow_index: int) -> bytes:
    role = normalize_label(label)
    templates = {
        "ddos": f"HTTP flood burst {flow_index} / GET /index.html",
        "web_bruteforce": f"POST /login username=admin attempt={flow_index}",
        "web_xss": f"GET /search?q=<script>alert({flow_index})</script>",
        "web_sql_injection": f"GET /items?id=1%20OR%201=1-- flow={flow_index}",
        "dos_hulk": f"HULK spray {flow_index} keepalive burst",
        "dos_goldeneye": f"GoldenEye header flood {flow_index}",
        "dos_slowloris": f"Slowloris partial header flow={flow_index}",
        "dos_slowhttptest": f"SlowHTTPTest chunked body {flow_index}",
        "heartbleed": f"TLS heartbeat malformed payload leak={flow_index}",
        "benign": f"normal application traffic flow={flow_index}",
    }
    return templates[role].encode("utf-8")


def choose_port(label: str, dst_port: int) -> int:
    role = normalize_label(label)
    if role.startswith("web_") or role.startswith("dos_"):
        return 80
    if role == "heartbleed":
        return 443
    if role == "ddos":
        return 80
    return dst_port if dst_port > 0 else 443


def make_ip_pair(label: str, group_index: int) -> Tuple[str, str]:
    role = normalize_label(label)
    victim = f"192.168.10.{10 + (group_index % 40)}"
    if role == "benign":
        src = f"10.0.{group_index % 8}.{20 + (group_index % 180)}"
        dst = f"172.16.{group_index % 6}.{30 + (group_index % 180)}"
        return src, dst
    attacker = f"203.0.113.{50 + (group_index % 150)}"
    return attacker, victim


def make_packets_for_flow(row: pd.Series, label: str, flow_index: int) -> List:
    total_fwd = max(1, min(int(float(row.get("Total Fwd Packets", 2))), 4))
    total_bwd = max(0, min(int(float(row.get("Total Backward Packets", 1))), 3))
    dst_port = choose_port(label, int(float(row.get("Destination Port", 80))))
    base_ttl = int(float(row.get("Init_Win_bytes_forward", 64)) or 64)
    ttl = 64 if base_ttl <= 0 else max(32, min(base_ttl, 128))
    src_ip, dst_ip = make_ip_pair(label, flow_index)
    payload = payload_for(label, flow_index)
    protocol = UDP if dst_port == 53 else TCP
    packets = []
    timestamp = 1.0 + flow_index * 0.01

    for offset in range(total_fwd):
        if protocol is TCP:
            l4 = TCP(
                sport=40000 + ((flow_index + offset) % 20000),
                dport=dst_port,
                flags="PA" if normalize_label(label) != "benign" else "A",
            )
        else:
            l4 = UDP(
                sport=40000 + ((flow_index + offset) % 20000),
                dport=dst_port,
            )
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl) / l4 / Raw(load=payload[:64])
        packet.time = timestamp + offset * 0.0001
        packets.append(packet)

    for offset in range(total_bwd):
        if protocol is TCP:
            l4 = TCP(
                sport=dst_port,
                dport=40000 + ((flow_index + offset) % 20000),
                flags="A",
            )
        else:
            l4 = UDP(
                sport=dst_port,
                dport=40000 + ((flow_index + offset) % 20000),
            )
        packet = IP(src=dst_ip, dst=src_ip, ttl=64) / l4 / Raw(load=b"ACK")
        packet.time = timestamp + (total_fwd + offset) * 0.0001
        packets.append(packet)

    return packets


def load_sample(spec: TaskSpec) -> pd.DataFrame:
    path = CSV_DIR / spec.source_csv
    frame = clean_columns(pd.read_csv(path, encoding="utf-8-sig", low_memory=False))
    sampled = []
    for label, sample_size in spec.samples.items():
        subset = frame[frame["Label"] == label]
        sampled.append(subset.sample(n=min(sample_size, len(subset)), random_state=spec.seed))
    result = pd.concat(sampled, ignore_index=True)
    return result.sample(frac=1.0, random_state=spec.seed).reset_index(drop=True)


def build_task(spec: TaskSpec) -> None:
    frame = load_sample(spec)
    packets = []
    annotation = {
        "pcap_file": f"{spec.name}.pcap",
        "source_csv": spec.source_csv,
        "description": spec.description,
        "malicious_packets": [],
        "packet_roles": {},
        "sessions": {},
        "session_roles": {},
        "entry_point": None,
    }

    packet_counter = 0
    session_counter: Dict[str, int] = {}

    for flow_index, row in frame.iterrows():
        label = row["Label"]
        role = normalize_label(label)
        flow_packets = make_packets_for_flow(row, label, flow_index)
        packet_ids = []
        for packet in flow_packets:
            packet_counter += 1
            packet_ids.append(f"pkt_{packet_counter:04d}")
            packets.append(packet)

        if role != "benign":
            annotation["malicious_packets"].extend(packet_ids)
            for packet_id in packet_ids:
                annotation["packet_roles"][packet_id] = role
            session_counter[role] = session_counter.get(role, 0) + 1
            session_name = f"{role}_session_{session_counter[role]:02d}"
            annotation["sessions"][session_name] = packet_ids
            annotation["session_roles"][session_name] = role
            if annotation["entry_point"] is None:
                annotation["entry_point"] = packet_ids[0]

    pcap_path = OUTPUT_DIR / f"{spec.name}.pcap"
    json_path = OUTPUT_DIR / f"{spec.name}.json"
    wrpcap(str(pcap_path), packets)
    json_path.write_text(json.dumps(annotation, indent=2), encoding="utf-8")
    print(f"Wrote {pcap_path.name} with {len(packets)} packets")
    print(f"Wrote {json_path.name} with {len(annotation['sessions'])} sessions")


def main() -> None:
    for spec in TASK_SPECS:
        build_task(spec)


if __name__ == "__main__":
    main()
