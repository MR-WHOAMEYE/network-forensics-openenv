import json
import os
import sys
import asyncio
import inspect
import random
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI
from openenv.core.containers.runtime.providers import LocalDockerProvider

sys.path.insert(0, str(Path(__file__).parent))

from client import NetworkForensicsEnv
from models import NetworkForensicsAction


load_dotenv(Path(__file__).parent / ".env")

API_BASE_URL = os.getenv("API_BASE_URL")
MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-oss-120b")
API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY") or os.getenv("HF_TOKEN")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME", "network-forensics-env:latest")
ENV_MODE = (
    os.getenv("NETWORK_FORENSICS_ENV_MODE") or os.getenv("ENV_MODE") or "docker"
).lower()
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:8000")
HF_SPACE_ID = (
    os.getenv("HF_SPACE_ID") or os.getenv("SPACE_ID") or "WHOAM-EYE/network_forensics"
)
HF_SPACE_URL = os.getenv("HF_SPACE_URL", "https://whoam-eye-network-forensics.hf.space")
ALLOW_HF_FALLBACK = os.getenv("ALLOW_HF_FALLBACK", "false").lower() in {
    "1",
    "true",
    "yes",
}
DOCKER_READY_TIMEOUT_S = float(os.getenv("DOCKER_READY_TIMEOUT_S", "120"))
_ASYNC_LOOP: asyncio.AbstractEventLoop | None = None

SYSTEM_PROMPT = """You are a senior Network Forensics Analyst. Your goal is to investigate malicious network traffic and achieve a 100% detection score.

### SCORING RULES:
- You MUST identify and `flag_as_suspicious` EVERY malicious packet to maximize RECALL (very important!).
- Only grouped packets or flagged packets contribute towards your score.
- If RECALL is < 0.5, your score will be 0.0. DO NOT stop until you have flagged/grouped at least 60% of visible malicious packets.
- Entry point must be the EARLIEST packet that initiated the attack (often in first group).
- For HARD tasks: wrong entry point = score 0. Always identify_entry_point before submitting.

### WORKFLOW:
1. **Explore**: `inspect_packet` on suspicious samples.
2. **Flag**: `flag_as_suspicious` on ALL revealed malicious packets.
3. **Correlate**: `group_into_session` with descriptive names.
4. **Classify**: `tag_pattern` with a valid type.
5. **Root Cause**: `identify_entry_point` with the earliest malicious packet.
6. **Report**: `submit_report` ONLY when you have covered all visible malicious sessions.

### VALID PATTERN TYPES:
ddos, dos_slowloris, dos_slowhttptest, dos_goldeneye, dos_hulk, heartbleed, web_sql_injection, web_xss, web_bruteforce, c2, exfiltration, scan, lateral

### JSON SCHEMA EXAMPLES (Use these exactly):
- Inspect: {"action_type":"inspect_packet","packet_id":"pkt_0001"}
- Flag: {"action_type":"flag_as_suspicious","packet_id":"pkt_0001"}
- Group: {"action_type":"group_into_session","session_name":"DDoS_Burst_2","packet_ids":["pkt_0001","pkt_0002"]}
- Tag: {"action_type":"tag_pattern","session_name":"DDoS_Burst_2","pattern_type":"ddos"}
- Entry: {"action_type":"identify_entry_point","claimed_entry_point":"pkt_0001"}
- Report: {"action_type":"submit_report","incident_summary":"Detailed incident summary here.","claimed_entry_point":"pkt_0001"}"""

HISTORY_WINDOW = 20
REPEAT_ACTION_LIMIT = 3
CORRECTION_WINDOW = 5
UNTAGGED_BACKLOG_LIMIT = 6
INSPECT_SOFT_RATIO_THRESHOLD = 0.60
SOFT_STEP_BUDGETS = {"easy": 14, "medium": 28, "hard": 40}
HARD_STEP_CAPS = {"easy": 30, "medium": 50, "hard": 65}
TASK_SCORE_TARGETS = {"easy": 0.70, "medium": 0.68, "hard": 0.66}
TASK_COVERAGE_TARGETS = {"easy": 0.32, "medium": 0.24, "hard": 0.20}
MAX_TASK_SECONDS = float(os.getenv("MAX_TASK_SECONDS", "780"))
TASK_TIME_BUDGET_SECONDS = {
    "easy": float(os.getenv("EASY_MAX_SECONDS", "150")),
    "medium": float(os.getenv("MEDIUM_MAX_SECONDS", "220")),
    "hard": float(os.getenv("HARD_MAX_SECONDS", "320")),
}


def build_client() -> OpenAI:
    return OpenAI(base_url=API_BASE_URL, api_key=API_KEY)


def validate_config() -> None:
    missing = []
    if not API_BASE_URL:
        missing.append("API_BASE_URL")
    if not API_KEY:
        missing.append("OPENAI_API_KEY/API_KEY/HF_TOKEN")
    if ENV_MODE == "hf" and not (HF_SPACE_URL or HF_SPACE_ID):
        missing.append("HF_SPACE_URL or HF_SPACE_ID/SPACE_ID")
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}"
        )
    if ENV_MODE not in {"server", "docker", "hf", "embedded", "local"}:
        raise RuntimeError(
            "NETWORK_FORENSICS_ENV_MODE must be one of: server, docker, hf, embedded, local"
        )


def format_action(action: NetworkForensicsAction) -> str:
    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)
    payload = {
        key: value for key, value in payload.items() if value not in ("", [], {})
    }
    return json.dumps(payload, separators=(",", ":"))


def summarize_observation(obs: Any, agent_state: dict[str, Any]) -> str:
    """Provide a compact structured summary for low-latency policy learning."""
    packets = obs.visible_packets
    revealed = [p for p in packets if p.is_revealed]
    revealed_ids = [p.packet_id for p in revealed]
    sessions = obs.grouped_sessions or {}
    tags = obs.tagged_patterns or {}
    untagged_sessions = [s for s in sessions.keys() if s not in tags]
    last_reward = agent_state.get("last_step_reward")
    reward_feedback = agent_state.get("last_reward_feedback", "n/a")
    recent_corrections = agent_state.get("recent_corrections", [])[-CORRECTION_WINDOW:]
    strategy_hints = agent_state.get("strategy_hints", [])
    task_name = agent_state.get("current_task_name", "")

    flagged_count = len(obs.flagged_packet_ids)
    total_visible = max(1, len(obs.visible_packets))
    coverage = flagged_count / total_visible
    coverage_target = TASK_COVERAGE_TARGETS.get(task_name, 0.25)
    score_target = TASK_SCORE_TARGETS.get(task_name, 0.65)
    grouped_count = len(sessions)
    tagged_count = len(tags)
    ready_to_submit = (
        obs.current_score_estimate >= score_target
        and coverage >= coverage_target
        and (task_name == "easy" or grouped_count >= 2)
        and (task_name == "easy" or tagged_count >= 1)
    )

    summary = [
        f"Step: {obs.step_number}/{obs.step_number + obs.steps_remaining}",
        f"Current Progress: {obs.current_score_estimate:.2f}",
        f"Coverage: {flagged_count}/{total_visible} ({coverage:.2%}) | target {coverage_target:.0%}",
        f"Sessions: grouped={grouped_count}, tagged={tagged_count}",
        f"Submit Readiness: {'READY' if ready_to_submit else 'KEEP INVESTIGATING'}",
        f"Last Step Reward: {last_reward:.2f}" if isinstance(last_reward, (int, float)) else "Last Step Reward: n/a",
        f"Last Reward Feedback: {reward_feedback}",
        f"ALREADY REVEALED: {', '.join(revealed_ids[-6:])} " + ("..." if len(revealed_ids) > 6 else ""),
        "\n### SESSIONS PENDING TAGGING:",
    ]

    if recent_corrections:
        summary.append("\n### RECENT CORRECTIONS:")
        for reason in recent_corrections:
            summary.append(f"- {reason}")

    if strategy_hints:
        summary.append("\n### STRATEGY HINTS:")
        for hint in strategy_hints:
            summary.append(f"- {hint}")

    if untagged_sessions:
        for s in untagged_sessions[:6]:
            summary.append(f"- {s} ({len(sessions[s])} packets)")
    else:
        summary.append("- [No pending sessions]")

    summary.append("\n### REVEALED INDICATORS:")
    for p in revealed[-4:]:
        payload = (p.full_payload or "")[:150]
        if payload:
            summary.append(f"- {p.packet_id}: {payload}")

    summary.append("\n### UNKNOWN PACKETS (Must Inspect):")
    unknown = [p for p in packets if not p.is_revealed][:10]
    for p in unknown:
        summary.append(f"- {p.packet_id} | {p.src_ip} -> {p.dst_ip} | Proto: {p.protocol}")

    return "\n".join(summary)


def parse_action(raw_text: str) -> NetworkForensicsAction:
    text = raw_text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("model did not return JSON")
    data = json.loads(text[start : end + 1])
    data.pop("metadata", None)
    for key in ("session_name", "pattern_type", "claimed_entry_point"):
        if data.get(key) == "":
            data.pop(key, None)
    if data.get("packet_ids") == []:
        data.pop("packet_ids", None)
    return NetworkForensicsAction(**data)


def sanitize_action(action: NetworkForensicsAction) -> NetworkForensicsAction:
    payload = {"action_type": action.action_type}
    if (
        action.action_type in {"inspect_packet", "flag_as_suspicious"}
        and action.packet_id
    ):
        payload["packet_id"] = action.packet_id
    elif action.action_type == "group_into_session":
        if action.session_name:
            payload["session_name"] = action.session_name
        if action.packet_ids:
            payload["packet_ids"] = action.packet_ids
    elif action.action_type == "tag_pattern":
        if action.session_name:
            payload["session_name"] = action.session_name
        if action.pattern_type:
            payload["pattern_type"] = action.pattern_type
    elif action.action_type == "identify_entry_point" and action.claimed_entry_point:
        payload["claimed_entry_point"] = action.claimed_entry_point
    if action.action_type == "submit_report":
        if action.incident_summary:
            payload["incident_summary"] = action.incident_summary
        if action.claimed_entry_point:
            payload["claimed_entry_point"] = action.claimed_entry_point
    return NetworkForensicsAction(**payload)


def decode_payload_preview(payload_preview: str) -> str:
    preview = (payload_preview or "").strip()
    compact = "".join(preview.split())
    if compact and len(compact) % 2 == 0:
        try:
            decoded = bytes.fromhex(compact).decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded
        except ValueError:
            pass
    return preview


def packet_payload_text(packet: Any) -> str:
    return packet.full_payload or decode_payload_preview(packet.payload_preview)


def keyword_to_pattern(payload: str) -> str | None:
    text = payload.lower()
    # --- DoS / DDoS variants ---
    if "slowloris" in text:
        return "dos_slowloris"
    if "slowhttptest" in text or "slow http" in text:
        return "dos_slowhttptest"
    if "goldeneye" in text or "golden eye" in text:
        return "dos_goldeneye"
    if "hulk" in text:
        return "dos_hulk"
    if "heartbeat" in text or "heartbleed" in text or ("tls" in text and "ext" in text):
        return "heartbleed"
    if "flood" in text or "burst" in text or "ddos" in text:
        return "ddos"
    # HTTP flood indicators (repeated GET/POST to same endpoint)
    if text.startswith("get /") or text.startswith("post /") or text.startswith("get http"):
        if "accept-encoding" in text or "connection" in text or "keep-alive" in text:
            return "ddos"
    # SYN flood / connection flood
    if "syn" in text and "ack" not in text and len(text) < 30:
        return "ddos"
    # ICMP flood
    if "icmp" in text and ("echo" in text or "request" in text or len(text) < 20):
        return "ddos"
    # --- Web attacks ---
    if "xss" in text or "<script>" in text or "<scrip" in text or "/search?q=" in text or "onerror" in text or "onload" in text or "javascript:" in text or "alert(" in text or "%3cscript" in text:
        return "web_xss"
    if (
        "or 1=1" in text
        or "%20or" in text
        or "/items?id=" in text
        or "1=1" in text
        or "' or " in text
        or "'--" in text
        or "union select" in text
        or "union all select" in text
        or "drop table" in text
        or "select * from" in text
        or "sql" in text
        or "%27" in text  # URL-encoded single quote
        or "' and " in text
        or "admin'--" in text
    ):
        return "web_sql_injection"
    if (
        "login" in text
        or "username=admin" in text
        or "password=" in text
        or "passwd=" in text
        or "user=admin" in text
        or "brute" in text
        or "/login" in text
        or "/signin" in text
        or "/auth" in text
        or "post /login" in text
        or "post /sign" in text
    ):
        return "web_bruteforce"
    # --- C2 / exfil / scan / lateral ---
    if "c2" in text or "command" in text or "shell" in text or "cmd" in text or "/bin/" in text or "reverse" in text:
        return "c2"
    if "exfil" in text or "exfiltrat" in text or "data_leak" in text or "dns_tunnel" in text:
        return "exfiltration"
    if "scan" in text or "nmap" in text or "port_scan" in text or "recon" in text:
        return "scan"
    if "lateral" in text or "pivot" in text or "spread" in text or "propagat" in text:
        return "lateral"
    return None


def packet_sort_key(packet_id: str) -> int:
    try:
        return int(packet_id.rsplit("_", 1)[-1])
    except ValueError:
        return 0


def packet_signature(packet: Any, pattern: str) -> tuple[str, str, int, str]:
    return (packet.src_ip, packet.dst_ip, packet.dst_port, pattern)


SUSPICIOUS_PORTS = {22, 23, 445, 1433, 3306, 5432, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 31337}
SUSPICIOUS_PROTOCOLS = {"ICMP"}


def _infer_flow_pattern(packet: Any, flow_size: int) -> str | None:
    """Heuristic pattern inference from flow characteristics when keyword matching fails."""
    dst_port = packet.dst_port
    protocol = packet.protocol
    flags = getattr(packet, "flags", []) or []
    # High-density flows to web ports → likely DDoS
    if flow_size >= 5 and dst_port in {80, 8080, 443, 8443}:
        return "ddos"
    # SYN-only flood
    if flow_size >= 5 and flags == ["SYN"]:
        return "ddos"
    # Suspicious ports → C2 or lateral
    if dst_port in SUSPICIOUS_PORTS:
        if dst_port in {4444, 5555, 6666, 7777, 31337}:
            return "c2"
        if dst_port in {445, 1433, 3306, 5432}:
            return "lateral"
    # ICMP flood
    if protocol in SUSPICIOUS_PROTOCOLS and flow_size >= 3:
        return "ddos"
    # High-density flow to non-standard port
    if flow_size >= 8 and dst_port not in {53, 80, 443, 8080}:
        return "scan"
    return None


def session_candidates(obs: Any) -> list[tuple[tuple[str, str, int, str], list[Any]]]:
    grouped: dict[tuple[str, str, int, str], list[Any]] = {}
    attack_source_ports: dict[tuple[str, str, int, str], set[int]] = {}
    # Phase 1: keyword-based grouping (high confidence)
    for packet in obs.visible_packets:
        pattern = keyword_to_pattern(packet_payload_text(packet))
        if pattern:
            key = packet_signature(packet, pattern)
            grouped.setdefault(key, []).append(packet)
            attack_source_ports.setdefault(key, set()).add(packet.src_port)

    # Add reverse-response packets to keyword-matched sessions
    for key, source_ports in attack_source_ports.items():
        src_ip, dst_ip, dst_port, _pattern = key
        for packet in obs.visible_packets:
            is_reverse_response = (
                packet.src_ip == dst_ip
                and packet.dst_ip == src_ip
                and packet.src_port == dst_port
                and packet.dst_port in source_ports
            )
            if is_reverse_response:
                grouped[key].append(packet)

    # Phase 2: flow-based grouping for packets without keyword match
    # Group unclaimed packets by (src_ip, dst_ip, dst_port) and infer pattern
    claimed_ids: set[str] = set()
    for items in grouped.values():
        for p in items:
            claimed_ids.add(p.packet_id)

    flow_buckets: dict[tuple[str, str, int], list[Any]] = {}
    for packet in obs.visible_packets:
        if packet.packet_id in claimed_ids:
            continue
        flow_key = (packet.src_ip, packet.dst_ip, packet.dst_port)
        flow_buckets.setdefault(flow_key, []).append(packet)

    for flow_key, items in flow_buckets.items():
        if len(items) < 2:
            continue
        pattern = _infer_flow_pattern(items[0], len(items))
        if pattern:
            session_key = (*flow_key, pattern)
            grouped.setdefault(session_key, []).extend(items)
            for p in items:
                claimed_ids.add(p.packet_id)

    candidates = [
        (
            key,
            sorted(
                {packet.packet_id: packet for packet in items}.values(),
                key=lambda pkt: packet_sort_key(pkt.packet_id),
            ),
        )
        for key, items in grouped.items()
        if len(items) >= 2
    ]
    return sorted(candidates, key=lambda item: packet_sort_key(item[1][0].packet_id))


def required_tag_count(task_name: str, total_sessions: int) -> int:
    if task_name == "hard":
        return (total_sessions + 1) // 2
    return 0


def select_inspect_packet(
    obs: Any,
    inspected_ids: set[str],
    flagged_ids: set[str] | None = None,
) -> str | None:
    flagged_ids = flagged_ids or set()
    unrevealed = [
        p
        for p in obs.visible_packets
        if (not p.is_revealed)
        and (p.packet_id not in inspected_ids)
        and (p.packet_id not in flagged_ids)
    ]
    if not unrevealed:
        return None

    flow_counts: dict[tuple[str, str, int], int] = {}
    for packet in obs.visible_packets:
        key = (packet.src_ip, packet.dst_ip, packet.dst_port)
        flow_counts[key] = flow_counts.get(key, 0) + 1

    # Bias toward denser flows first to speed up session construction.
    ranked = sorted(
        unrevealed,
        key=lambda p: (
            -flow_counts.get((p.src_ip, p.dst_ip, p.dst_port), 0),
            packet_sort_key(p.packet_id),
        ),
    )

    top_tier = ranked[: min(4, len(ranked))]
    rng = random.Random(f"{obs.step_number}:{len(inspected_ids)}:{len(unrevealed)}")
    return rng.choice(top_tier).packet_id


def append_action_history(agent_state: dict[str, Any], action: NetworkForensicsAction) -> None:
    history = agent_state.setdefault("previous_actions", [])
    history.append(format_action(action))
    if action.action_type == "inspect_packet" and action.packet_id:
        inspected_ids = agent_state.setdefault("inspected_ids", set())
        inspected_ids.add(action.packet_id)
    if len(history) > HISTORY_WINDOW:
        del history[:-HISTORY_WINDOW]


def record_correction(agent_state: dict[str, Any], reason: str) -> None:
    corrections = agent_state.setdefault("recent_corrections", [])
    corrections.append(reason)
    if len(corrections) > CORRECTION_WINDOW:
        del corrections[:-CORRECTION_WINDOW]


def candidate_evidence(
    candidate_packets: list[Any],
    flagged_ids: set[str],
    visible_by_id: dict[str, Any],
) -> tuple[int, int, int]:
    flagged = 0
    revealed = 0
    malicious_revealed = 0
    for item in candidate_packets:
        packet = visible_by_id.get(item.packet_id, item)
        if packet.packet_id in flagged_ids:
            flagged += 1
        if packet.is_revealed:
            revealed += 1
            if keyword_to_pattern(packet_payload_text(packet)):
                malicious_revealed += 1
    return flagged, revealed, malicious_revealed


def group_meets_evidence_gate(
    candidate_packets: list[Any],
    flagged_ids: set[str],
    visible_by_id: dict[str, Any],
    task_name: str,
    trusted_pattern: bool = False,
) -> bool:
    flagged, revealed, malicious_revealed = candidate_evidence(
        candidate_packets, flagged_ids, visible_by_id
    )
    size = len(candidate_packets)
    # Lowered thresholds for more aggressive grouping
    if task_name == "easy":
        min_flagged = 1 if size >= 2 else 0
    elif task_name == "medium":
        min_flagged = 1 if size >= 2 else 0
    else:
        min_flagged = 1 if size >= 3 else 0
    if trusted_pattern and size >= 3:
        min_flagged = 1
    if flagged >= min_flagged:
        return True
    # Allow grouping with strong revealed malicious evidence.
    if task_name == "easy" and (malicious_revealed >= 1 or revealed >= 1):
        return True
    if task_name == "medium" and malicious_revealed >= 1 and revealed >= 1:
        return True
    if malicious_revealed >= 1 and revealed >= min(2, size):
        return True
    # After a pattern has been confirmed by tagging, allow structure-first grouping.
    if trusted_pattern and size >= 3:
        return True
    # Large flows are very likely attack sessions - allow with minimal evidence
    if size >= 6 and (flagged >= 1 or revealed >= 2 or malicious_revealed >= 1):
        return True
    return False


def trusted_patterns(
    session_map: dict[tuple[str, str, int, str], str], tagged_sessions: set[str]
) -> set[str]:
    return {key[3] for key, name in session_map.items() if name in tagged_sessions}


def derive_strategy_hints(obs: Any, agent_state: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    previous_actions = agent_state.get("previous_actions", [])
    recent = previous_actions[-HISTORY_WINDOW:]
    if recent:
        inspect_recent = sum(1 for a in recent if '"inspect_packet"' in a)
        inspect_ratio = inspect_recent / len(recent)
    else:
        inspect_ratio = 0.0

    revealed_count = sum(1 for p in obs.visible_packets if p.is_revealed)
    flagged_count = len(obs.flagged_packet_ids)
    soft_limit = max(6, min(14, len(obs.visible_packets) // 15))
    if revealed_count >= soft_limit and inspect_ratio >= INSPECT_SOFT_RATIO_THRESHOLD:
        hints.append(
            "Inspection is high. Prefer flagging suspicious revealed packets, then group/tag before further inspection."
        )
    if flagged_count == 0 and revealed_count >= 4:
        hints.append(
            "You have enough revealed packets. Start flagging suspicious packets before creating more sessions."
        )

    sessions = agent_state.get("sessions", {})
    tagged_sessions = agent_state.get("tagged_sessions", set())
    untagged_backlog = max(0, len(sessions) - len(tagged_sessions))
    if untagged_backlog > UNTAGGED_BACKLOG_LIMIT:
        hints.append(
            "Tag pending sessions before creating new groups to avoid over-grouping."
        )

    inspect_limit = {
        "easy": 18,
        "medium": 20,
        "hard": 25,
    }.get(agent_state.get("current_task_name", ""), 15)
    if len(previous_actions) >= inspect_limit and inspect_ratio >= INSPECT_SOFT_RATIO_THRESHOLD:
        hints.append(
            "You are over-inspecting. Shift to flagging, grouping, tagging, or report submission unless the next packet is clearly high-value."
        )
    return hints


def should_submit_early(task_name: str, obs: Any, agent_state: dict[str, Any]) -> bool:
    flagged_count = len(obs.flagged_packet_ids)
    total_visible = max(1, len(obs.visible_packets))
    coverage = flagged_count / total_visible
    score = float(obs.current_score_estimate)
    sessions = obs.grouped_sessions or {}
    tags = obs.tagged_patterns or {}

    score_target = TASK_SCORE_TARGETS.get(task_name, 0.65)
    coverage_target = TASK_COVERAGE_TARGETS.get(task_name, 0.25)

    if task_name == "easy":
        return (
            coverage >= max(coverage_target * 0.7, 0.20)
            and flagged_count >= 6
            and len(sessions) >= 1
        )
    if task_name == "medium":
        return (
            score >= score_target * 0.8
            and coverage >= coverage_target * 0.7
            and len(sessions) >= 1
            and len(tags) >= 1
        )
    return (
        score >= score_target * 0.8
        and coverage >= coverage_target * 0.7
        and len(sessions) >= 2
        and len(tags) >= 1
        and bool(agent_state.get("claimed_entry_point") or obs.claimed_entry_point)
    )


def build_fallback_action(
    task_name: str, obs: Any, agent_state: dict[str, Any]
) -> NetworkForensicsAction:
    """Smart workflow engine: Flag aggressive -> Group -> Tag -> Entry Point -> Report."""
    inspected_ids = agent_state.setdefault("inspected_ids", set())
    flagged_ids = agent_state.setdefault("flagged_ids", set())
    session_map = agent_state.setdefault("sessions", {})  # key -> session_name
    tagged_sessions = agent_state.setdefault("tagged_sessions", set())
    claimed_entry = agent_state.get("claimed_entry_point")
    visible_by_id = {p.packet_id: p for p in obs.visible_packets}
    trusted = trusted_patterns(session_map, tagged_sessions)

    if obs.steps_remaining <= 1 or should_submit_early(task_name, obs, agent_state):
        summary = _build_report_summary(obs, agent_state)
        return NetworkForensicsAction(
            action_type="submit_report",
            incident_summary=summary,
            claimed_entry_point=claimed_entry,
        )

    # PHASE 1: Aggressive flag of ALL revealed malicious packets
    # This maximizes recall by comprehensively flagging known-bad traffic
    unflagged_malicious = []
    for packet in obs.visible_packets:
        if packet.is_revealed and packet.packet_id not in flagged_ids:
            payload = packet.full_payload or ""
            pattern = keyword_to_pattern(payload)
            if pattern:
                unflagged_malicious.append(packet.packet_id)
    
    if unflagged_malicious:
        # Flag up to 5 per turn for aggressive recall buildup
        target = min(5, len(unflagged_malicious))
        for _ in range(target):
            if unflagged_malicious:
                pid = unflagged_malicious.pop(0)
                flagged_ids.add(pid)
                return NetworkForensicsAction(
                    action_type="flag_as_suspicious",
                    packet_id=pid,
                )

    # PHASE 2: Group flagged packets into sessions with evidence gate and backlog pacing.
    min_flagged_before_group = 1 if task_name == "easy" else 2
    untagged_backlog = max(0, len(session_map) - len(tagged_sessions))
    if len(flagged_ids) >= min_flagged_before_group and untagged_backlog <= UNTAGGED_BACKLOG_LIMIT:
        candidates = session_candidates(obs)
        for key, items in candidates:
            if key in session_map:
                continue
            if not group_meets_evidence_gate(
                items,
                flagged_ids,
                visible_by_id,
                task_name=task_name,
                trusted_pattern=key[3] in trusted,
            ):
                continue
            packet_ids = [p.packet_id for p in items]
            session_name = f"{task_name}_session_{len(session_map) + 1:02d}"
            session_map[key] = session_name
            return NetworkForensicsAction(
                action_type="group_into_session",
                session_name=session_name,
                packet_ids=packet_ids,
            )

    # PHASE 2.5: Recall sweep - flag packets that are already part of grouped sessions.
    # This boosts recall quickly without requiring more inspections.
    grouped_packets = []
    for packet_ids in (obs.grouped_sessions or {}).values():
        grouped_packets.extend(packet_ids)
    for pid in sorted(set(grouped_packets), key=packet_sort_key):
        if pid in flagged_ids:
            continue
        if pid in visible_by_id:
            flagged_ids.add(pid)
            return NetworkForensicsAction(
                action_type="flag_as_suspicious",
                packet_id=pid,
            )

    # PHASE 3: Tag ALL untagged sessions aggressively (critical for medium/hard logic_score).
    # Tagging helps LLM report score and logic_score for all difficulties.
    for key, session_name in session_map.items():
        if session_name in tagged_sessions:
            continue
        _src_ip, _dst_ip, _dst_port, pattern = key
        tagged_sessions.add(session_name)
        return NetworkForensicsAction(
            action_type="tag_pattern",
            session_name=session_name,
            pattern_type=pattern,
        )
    # Also tag any observed sessions not yet in our session_map
    for session_name, session_data in (obs.grouped_sessions or {}).items():
        if session_name in tagged_sessions:
            continue
        if session_name in (obs.tagged_patterns or {}):
            tagged_sessions.add(session_name)
            continue
        # Infer pattern from session packets
        pattern = None
        for pid in session_data:
            pkt = visible_by_id.get(pid)
            if pkt and pkt.is_revealed:
                pattern = keyword_to_pattern(packet_payload_text(pkt))
                if pattern:
                    break
        if not pattern:
            # Try flow-based inference
            pkt = visible_by_id.get(session_data[0]) if session_data else None
            if pkt:
                pattern = _infer_flow_pattern(pkt, len(session_data))
        if pattern:
            tagged_sessions.add(session_name)
            return NetworkForensicsAction(
                action_type="tag_pattern",
                session_name=session_name,
                pattern_type=pattern,
            )

    # PHASE 4: Identify entry point - CRITICAL for hard mode (score=0 without it)
    if not claimed_entry:
        entry_candidate = None
        # Strategy 1: earliest packet in any grouped session from observation
        try:
            grouped_packets = set()
            for session_name in session_map.values():
                if obs.grouped_sessions and session_name in obs.grouped_sessions:
                    grouped_packets.update(obs.grouped_sessions[session_name])
            if grouped_packets:
                entry_candidate = min(grouped_packets, key=lambda pid: packet_sort_key(pid))
        except Exception:
            pass
        # Strategy 2: earliest flagged packet (often the first discovered attack)
        if not entry_candidate and flagged_ids:
            entry_candidate = min(flagged_ids, key=lambda pid: packet_sort_key(pid))
        # Strategy 3: earliest revealed malicious packet
        if not entry_candidate:
            revealed_malicious = [
                p for p in obs.visible_packets
                if p.is_revealed and keyword_to_pattern(packet_payload_text(p))
            ]
            if revealed_malicious:
                entry_candidate = min(
                    revealed_malicious, key=lambda p: packet_sort_key(p.packet_id)
                ).packet_id
        # Strategy 4: earliest packet in session_candidates
        if not entry_candidate:
            all_session_packets = []
            for key, items in session_candidates(obs):
                for p in items:
                    all_session_packets.append(p.packet_id)
            if all_session_packets:
                entry_candidate = min(all_session_packets, key=packet_sort_key)
        # Strategy 5: earliest flagged packet from observation
        if not entry_candidate and obs.flagged_packet_ids:
            entry_candidate = min(obs.flagged_packet_ids, key=packet_sort_key)
        if entry_candidate:
            agent_state["claimed_entry_point"] = entry_candidate
            return NetworkForensicsAction(
                action_type="identify_entry_point",
                claimed_entry_point=entry_candidate,
            )

    # PHASE 5: Inspect more unrevealed packets (to discover more malicious traffic)
    inspect_id = select_inspect_packet(obs, inspected_ids, flagged_ids)
    if inspect_id is not None:
        return NetworkForensicsAction(action_type="inspect_packet", packet_id=inspect_id)

    # PHASE 6: Submit report
    summary = _build_report_summary(obs, agent_state)
    return NetworkForensicsAction(
        action_type="submit_report",
        incident_summary=summary,
        claimed_entry_point=claimed_entry,
    )


def _build_report_summary(obs: Any, agent_state: dict[str, Any]) -> str:
    """Generate a detailed incident summary for high LLM judge scores."""
    flagged = agent_state.get("flagged_ids", set())
    sessions = agent_state.get("sessions", {})
    tagged = agent_state.get("tagged_sessions", set())
    entry_point = agent_state.get("claimed_entry_point") or getattr(obs, "claimed_entry_point", None)
    patterns_by_session: dict[str, str] = {}
    src_ips_by_pattern: dict[str, set[str]] = {}
    dst_ips_by_pattern: dict[str, set[str]] = {}
    for key, session_name in sessions.items():
        if len(key) >= 4:
            pattern = key[3]
            patterns_by_session[session_name] = pattern
            src_ips_by_pattern.setdefault(pattern, set()).add(key[0])
            dst_ips_by_pattern.setdefault(pattern, set()).add(key[1])

    # Build detailed per-pattern section
    pattern_details = []
    for pattern in sorted(set(patterns_by_session.values())):
        srcs = ", ".join(sorted(src_ips_by_pattern.get(pattern, set()))[:5])
        dsts = ", ".join(sorted(dst_ips_by_pattern.get(pattern, set()))[:5])
        session_names = [n for n, p in patterns_by_session.items() if p == pattern]
        pattern_details.append(
            f"  - {pattern}: {len(session_names)} session(s) from {srcs} targeting {dsts}"
        )
    pattern_section = "\n".join(pattern_details) if pattern_details else "  - No patterns classified"

    # Tagged pattern summary
    tagged_details = []
    for session_name in sorted(tagged):
        pattern = patterns_by_session.get(session_name, "unknown")
        tagged_details.append(f"{session_name}={pattern}")
    tagged_section = "; ".join(tagged_details) if tagged_details else "none"

    entry_section = f"Entry point: {entry_point}" if entry_point else "Entry point: not identified"

    return (
        f"INCIDENT REPORT\n\n"
        f"Summary: Detected {len(flagged)} malicious packets across "
        f"{len(sessions)} attack sessions.\n\n"
        f"Attack Patterns:\n{pattern_section}\n\n"
        f"Tagged Sessions: {tagged_section}\n\n"
        f"{entry_section}\n\n"
        f"Total flagged: {len(flagged)} | Total sessions: {len(sessions)} | "
        f"Classified sessions: {len(tagged)}"
    )


def should_override_action(
    action: NetworkForensicsAction,
    obs: Any,
    agent_state: dict[str, Any],
    task_name: str,
) -> str | None:
    """Checks if the action should be overridden. Returns the reason for override, or None."""
    previous_actions = agent_state.setdefault("previous_actions", [])
    flagged_ids = agent_state.setdefault("flagged_ids", set())
    action_repr = format_action(action)
    visible_by_id = {p.packet_id: p for p in obs.visible_packets}
    sessions = agent_state.setdefault("sessions", {})
    tagged_sessions = agent_state.setdefault("tagged_sessions", set())
    trusted = trusted_patterns(sessions, tagged_sessions)
    inspect_count = sum(1 for a in previous_actions if '"inspect_packet"' in a)
    revealed_count = sum(1 for p in obs.visible_packets if p.is_revealed)
    inspect_limit = {
        "easy": 25,
        "medium": 18,
        "hard": 25,
    }.get(task_name, 15)

    if action.action_type not in {
        "inspect_packet",
        "flag_as_suspicious",
        "group_into_session",
        "tag_pattern",
        "identify_entry_point",
        "submit_report",
    }:
        return "Invalid action_type"

    if len(previous_actions) >= 3:
        if all(a == action_repr for a in previous_actions[-REPEAT_ACTION_LIMIT:]):
            return "Identical action repeated 3 times consecutively (Infinite Loop)"

    if action.action_type == "inspect_packet":
        if not action.packet_id:
            return "Missing packet_id for inspect_packet"
        if action.packet_id not in {p.packet_id for p in obs.visible_packets}:
            return f"Invalid packet_id {action.packet_id} - not in visible_packets"
        inspected_ids = agent_state.setdefault("inspected_ids", set())
        if action.packet_id in inspected_ids:
            return f"Packet {action.packet_id} was already inspected. Choose a different hidden packet."
        revealed_ids = {p.packet_id for p in obs.visible_packets if p.is_revealed}
        if action.packet_id in revealed_ids:
            return f"Packet {action.packet_id} is ALREADY revealed. Choose a HIDDEN packet."
        if action.packet_id in set(obs.flagged_packet_ids):
            return (
                f"Packet {action.packet_id} is already flagged. Inspect a new hidden unflagged packet instead."
            )
        revealed_unflagged_malicious = [
            p.packet_id
            for p in obs.visible_packets
            if p.is_revealed
            and p.packet_id not in set(obs.flagged_packet_ids)
            and keyword_to_pattern(packet_payload_text(p))
        ]
        if revealed_unflagged_malicious:
            return (
                "Recall-first policy: revealed malicious packets exist and must be flagged before new inspection."
            )
        grouped_unflagged = [
            pid
            for packet_ids in (obs.grouped_sessions or {}).values()
            for pid in packet_ids
            if pid not in set(obs.flagged_packet_ids)
        ]
        if grouped_unflagged:
            return (
                "Recall-first policy: grouped session packets remain unflagged. Flag them before further inspection."
            )
        if task_name == "easy" and len(flagged_ids) >= 4:
            grouped_session_names = set((obs.grouped_sessions or {}).keys())
            for key, items in session_candidates(obs):
                if key in sessions:
                    continue
                if len(items) >= 4:
                    return (
                        "Exploit mode: enough evidence exists. Group high-confidence attack flows before more inspection."
                    )
        if inspect_count >= inspect_limit and (len(sessions) > 0 or len(flagged_ids) > 0 or revealed_count >= 4):
            # Only block inspections for medium/hard modes; easy mode needs discovery
            if task_name != "easy":
                return (
                    f"Inspection budget reached for {task_name}. Shift to flagging, grouping, tagging, or report submission."
                )

    if action.action_type == "flag_as_suspicious":
        if not action.packet_id:
            return "Missing packet_id for flag_as_suspicious"
        if action.packet_id not in {p.packet_id for p in obs.visible_packets}:
            return f"Invalid packet_id {action.packet_id} - not in visible_packets"
        if action.packet_id in set(obs.flagged_packet_ids):
            return f"Packet {action.packet_id} is ALREADY flagged."

    if action.action_type == "group_into_session":
        if not action.session_name:
            return "Missing session_name for group_into_session"
        if not action.packet_ids or len(action.packet_ids) < 2:
            return "Need at least 2 packet_ids to form a session"
        invalid_ids = set(action.packet_ids) - {
            p.packet_id for p in obs.visible_packets
        }
        if invalid_ids:
            return f"Invalid packet_ids in session: {invalid_ids}"
        if action.session_name in sessions.values():
            return f"Session name {action.session_name} is already used."
        min_flagged_before_group = 1 if task_name == "easy" else 1
        if len(flagged_ids) < min_flagged_before_group:
            return (
                f"Group blocked until enough evidence is flagged ({len(flagged_ids)}/{min_flagged_before_group}). "
                "Inspect and flag suspicious packets first."
            )
        new_group_ids = set(action.packet_ids)
        for existing_ids in (obs.grouped_sessions or {}).values():
            existing_set = set(existing_ids)
            if not existing_set:
                continue
            overlap = len(new_group_ids & existing_set) / max(1, len(new_group_ids))
            if overlap >= 0.8:
                return "This grouping heavily overlaps an existing session. Prioritize new evidence."
        untagged_backlog = max(0, len(sessions) - len(tagged_sessions))
        if untagged_backlog > UNTAGGED_BACKLOG_LIMIT:
            return (
                "Too many untagged sessions pending. Tag existing sessions before grouping new ones."
            )
        candidate_packets = [visible_by_id[pid] for pid in action.packet_ids if pid in visible_by_id]
        inferred_patterns = {
            keyword_to_pattern(packet_payload_text(packet))
            for packet in candidate_packets
            if keyword_to_pattern(packet_payload_text(packet))
        }
        trusted_pattern = any(pattern in trusted for pattern in inferred_patterns)
        if not group_meets_evidence_gate(
            candidate_packets,
            flagged_ids,
            visible_by_id,
            task_name=task_name,
            trusted_pattern=trusted_pattern,
        ):
            return (
                "Insufficient evidence for grouping. Flag or reveal more suspicious packets in this flow first."
            )

    if action.action_type == "submit_report":
        untagged_backlog = max(0, len(sessions) - len(tagged_sessions))
        total_visible = max(1, len(obs.visible_packets))
        flagged_count = len(obs.flagged_packet_ids)
        coverage = flagged_count / total_visible
        min_cov = TASK_COVERAGE_TARGETS.get(task_name, 0.25) * 0.6
        min_flags = 4 if task_name == "easy" else (3 if task_name == "medium" else 4)
        min_groups = 1 if task_name == "easy" else (2 if task_name == "medium" else 2)
        if (
            obs.steps_remaining > 2
            and obs.current_score_estimate < 0.40
            and not should_submit_early(task_name, obs, agent_state)
        ):
            return (
                "Premature report submission. Improve coverage and score estimate before submit_report."
            )
        if obs.steps_remaining > 1 and (coverage < min_cov or flagged_count < min_flags):
            return (
                f"Premature report submission. Need stronger recall coverage before submit_report "
                f"(coverage {coverage:.0%}/{min_cov:.0%}, flags {flagged_count}/{min_flags})."
            )
        if obs.steps_remaining > 1 and len(sessions) < min_groups:
            return (
                f"Premature report submission. Need stronger session evidence before submit_report "
                f"(grouped {len(sessions)}/{min_groups})."
            )
        if task_name == "hard" and obs.steps_remaining > 3 and untagged_backlog > 0:
            return "Premature report submission. Tag pending sessions before submitting report."
        # CRITICAL: Hard mode zero-out if no entry point identified
        if task_name == "hard" and not (agent_state.get("claimed_entry_point") or obs.claimed_entry_point):
            return (
                "FATAL: Hard mode requires identify_entry_point before submit_report. "
                "No entry point claimed yet — score will be 0.0 without it. "
                "Use identify_entry_point with the earliest malicious packet first."
            )
        # Medium mode: need entry point for good logic_score
        if task_name == "medium" and obs.steps_remaining > 5 and not (agent_state.get("claimed_entry_point") or obs.claimed_entry_point):
            return (
                "Missing entry point. Use identify_entry_point before submit_report for higher score."
            )
        # Require minimum tagging coverage for medium/hard
        min_tagged = 1 if task_name == "medium" else 2
        if task_name in {"medium", "hard"} and len(tagged_sessions) < min_tagged and obs.steps_remaining > 3:
            return (
                f"Premature report submission. Need at least {min_tagged} tagged session(s) before submit_report "
                f"(currently {len(tagged_sessions)})."
            )

    if action.action_type == "tag_pattern":
        if not action.session_name:
            return "Missing session_name for tag_pattern"
        if not action.pattern_type:
            return "Missing pattern_type for tag_pattern"
        if action.session_name in set((obs.tagged_patterns or {}).keys()):
            return f"Session {action.session_name} is already tagged."
        if task_name == "easy" and obs.steps_remaining > 8:
            return "For easy mode, prioritize recall actions (inspect/flag/group) before tagging."
        valid_patterns = {
            "ddos", "dos_slowloris", "dos_slowhttptest", "dos_goldeneye", "dos_hulk",
            "heartbleed", "web_sql_injection", "web_xss", "web_bruteforce",
            "c2", "exfiltration", "scan", "lateral",
        }
        if action.pattern_type.lower() not in valid_patterns:
            return f"Unknown pattern_type '{action.pattern_type}'"

    if action.action_type == "identify_entry_point":
        if not action.claimed_entry_point:
            return "Missing claimed_entry_point for identify_entry_point"
        # Lenient gating for easy mode
        min_flags_needed = 1 if task_name == "easy" else (2 if task_name == "medium" else 2)
        if obs.steps_remaining > 8 and len(flagged_ids) < min_flags_needed:
            return (
                "Premature entry-point claim. Gather and flag more evidence before identify_entry_point."
            )

    return None


def choose_action(
    client: OpenAI,
    task_name: str,
    obs: Any,
    agent_state: dict[str, Any],
    model_name: str | None = None,
) -> NetworkForensicsAction:
    agent_state["current_task_name"] = task_name
    agent_state["strategy_hints"] = derive_strategy_hints(obs, agent_state)
    if should_submit_early(task_name, obs, agent_state):
        action = NetworkForensicsAction(
            action_type="submit_report",
            incident_summary=_build_report_summary(obs, agent_state),
            claimed_entry_point=agent_state.get("claimed_entry_point") or obs.claimed_entry_point,
        )
        append_action_history(agent_state, action)
        return action
    history = agent_state.get("previous_actions", [])[-HISTORY_WINDOW:]
    history_str = "\n".join([f"Step {i+1}: {a}" for i, a in enumerate(history)])

    # Persist correction feedback so repeated mistakes remain visible.
    recent_corrections = agent_state.get("recent_corrections", [])[-CORRECTION_WINDOW:]
    correction_text = ""
    if recent_corrections:
        correction_text = "\n".join(f"- {item}" for item in recent_corrections)
        correction_text = (
            "\n### SYSTEM CORRECTIONS (recent):\n"
            f"{correction_text}\n"
            "Follow the JSON schema in the system prompt."
        )

    try:
        response = client.chat.completions.create(
            model=model_name or MODEL_NAME,
            temperature=0.1,
            timeout=LLM_TIMEOUT_S,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"TASK: {task_name}{correction_text}\n\n### RECENT HISTORY:\n{history_str}\n\n### CURRENT OBSERVATION:\n{summarize_observation(obs, agent_state)}",
                },
            ],
        )
    except Exception as llm_exc:
        print(f"[WARN] LLM call failed/timed out: {llm_exc}")
        fallback = build_fallback_action(task_name, obs, agent_state)
        append_action_history(agent_state, fallback)
        return fallback
    content = response.choices[0].message.content or ""
    try:
        action = sanitize_action(parse_action(content))
    except Exception as e:
        reason = f"Invalid JSON ({str(e)})"
        record_correction(agent_state, reason)
        fallback = build_fallback_action(task_name, obs, agent_state)
        append_action_history(agent_state, fallback)
        return fallback

    reason = should_override_action(action, obs, agent_state, task_name)
    if reason:
        record_correction(agent_state, reason)
        fallback = build_fallback_action(task_name, obs, agent_state)
        append_action_history(agent_state, fallback)
        return fallback

    append_action_history(agent_state, action)
    return action


def reward_feedback(action: NetworkForensicsAction, reward: float) -> str:
    if action.action_type == "inspect_packet":
        if reward < 0:
            return "Inspect action was not useful. Try new packets or move to flag/group/tag."
        return "Inspect yielded useful signal."
    if action.action_type == "flag_as_suspicious":
        if reward < 0:
            return "Flagging was low quality or duplicate."
        return "Flagging improved recall progress."
    if action.action_type == "group_into_session":
        if reward < 0:
            return "Grouping did not match a strong attack session."
        return "Grouping improved session structure."
    if action.action_type == "tag_pattern":
        if reward < 0:
            return "Tag mismatch. Re-evaluate session characteristics."
        return "Tag assignment was useful."
    if action.action_type == "submit_report":
        return "Report submitted. Score now reflects report quality and coverage."
    return "Action completed."


def sync_agent_state(obs: Any, agent_state: dict[str, Any]) -> None:
    inspected_ids = agent_state.setdefault("inspected_ids", set())
    for packet in obs.visible_packets:
        if packet.is_revealed:
            inspected_ids.add(packet.packet_id)
    flagged_ids = agent_state.setdefault("flagged_ids", set())
    flagged_ids.update(obs.flagged_packet_ids)
    tagged_sessions = agent_state.setdefault("tagged_sessions", set())
    tagged_sessions.update(obs.tagged_patterns.keys())
    if obs.claimed_entry_point:
        agent_state["claimed_entry_point"] = obs.claimed_entry_point


def emit_step(
    step_number: int,
    action: NetworkForensicsAction,
    reward: float,
    done: bool,
    error: str | None,
) -> None:
    error_text = error if error is not None else "null"
    done_text = str(done).lower()
    print(
        f"[STEP] step={step_number} action={format_action(action)} "
        f"reward={reward:.2f} done={done_text} error={error_text}"
    )


def normalize_score(score: float) -> float:
    return max(0.0, min(1.0, score))


def final_metrics(obs: Any) -> dict[str, Any]:
    return getattr(obs, "final_metrics", None) or getattr(obs, "metadata", None) or {}


class ExtendedWaitDockerProvider(LocalDockerProvider):
    def wait_for_ready(self, base_url: str, timeout_s: float = 30.0) -> None:
        super().wait_for_ready(base_url, timeout_s=DOCKER_READY_TIMEOUT_S)


def get_async_loop() -> asyncio.AbstractEventLoop:
    global _ASYNC_LOOP
    if _ASYNC_LOOP is None or _ASYNC_LOOP.is_closed():
        _ASYNC_LOOP = asyncio.new_event_loop()
    return _ASYNC_LOOP


def resolve_maybe_awaitable(value: Any) -> Any:
    if inspect.isawaitable(value):
        return get_async_loop().run_until_complete(value)
    return value


def create_env() -> NetworkForensicsEnv:
    # Preferred path: Hugging Face Space.
    if ENV_MODE == "hf":
        if HF_SPACE_URL:
            return NetworkForensicsEnv(base_url=HF_SPACE_URL.rstrip("/"))
        space_slug = HF_SPACE_ID.lower().replace("/", "-").replace("_", "-")
        return NetworkForensicsEnv(base_url=f"https://{space_slug}.hf.space")

    if ENV_MODE == "docker":
        provider = ExtendedWaitDockerProvider()
        return resolve_maybe_awaitable(
            NetworkForensicsEnv.from_docker_image(LOCAL_IMAGE_NAME, provider=provider)
        )

    if ENV_MODE == "server":
        return NetworkForensicsEnv(base_url=ENV_BASE_URL)

    return NetworkForensicsEnv(base_url=ENV_BASE_URL)


def create_env_with_fallback() -> NetworkForensicsEnv:
    # Explicit manual server mode
    if ENV_MODE == "server":
        print(f"[INFO] Manual Server Mode Active: Using {ENV_BASE_URL}")
        return NetworkForensicsEnv(base_url=ENV_BASE_URL)

    # Explicit in-process mode (no server/docker/HF required)
    if ENV_MODE in {"embedded", "local"}:
        from server.network_forensics_environment import NetworkForensicsEnvironment

        print("[INFO] Embedded mode active: using in-process environment")
        return NetworkForensicsEnvironment(task_id="easy")  # type: ignore[return-value]

    # Primary local-first path for docker mode/default.
    if ENV_MODE == "docker":
        try:
            provider = ExtendedWaitDockerProvider()
            env = resolve_maybe_awaitable(
                NetworkForensicsEnv.from_docker_image(LOCAL_IMAGE_NAME, provider=provider)
            )
            _ = reset_env(env, "easy")
            return env
        except Exception as exc:
            print(f"[WARN] Docker failed ({exc}); trying in-process environment.")

        try:
            from server.network_forensics_environment import NetworkForensicsEnvironment

            return NetworkForensicsEnvironment(task_id="easy")  # type: ignore[return-value]
        except Exception as exc:
            print(f"[WARN] In-process fallback failed ({exc}).")

        if ALLOW_HF_FALLBACK:
            try:
                env = NetworkForensicsEnv(base_url=HF_SPACE_URL.rstrip("/"))
                _ = reset_env(env, "easy")
                return env
            except Exception as exc:
                print(f"[WARN] HF fallback failed ({exc}).")

        raise RuntimeError(
            "No available backend. Docker and in-process environment both failed. "
            "Set NETWORK_FORENSICS_ENV_MODE=embedded to force local in-process mode."
        )

    # Explicit HF mode: try HF first, then local fallbacks.
    try:
        env = NetworkForensicsEnv(base_url=HF_SPACE_URL.rstrip("/"))
        _ = reset_env(env, "easy")
        return env
    except Exception as exc:
        print(f"[WARN] HF space failed ({exc}); trying Docker.")

    try:
        provider = ExtendedWaitDockerProvider()
        env = resolve_maybe_awaitable(
            NetworkForensicsEnv.from_docker_image(LOCAL_IMAGE_NAME, provider=provider)
        )
        _ = reset_env(env, "easy")
        return env
    except Exception as exc:
        print(f"[WARN] Docker failed ({exc}); falling back to local simulation.")

    # Last resort: in-process environment.
    try:
        from server.network_forensics_environment import NetworkForensicsEnvironment

        return NetworkForensicsEnvironment(task_id="easy")  # type: ignore[return-value]
    except Exception as exc:
        raise RuntimeError(f"All environment backends failed: {exc}") from exc


def reset_env(env: NetworkForensicsEnv, task_name: str) -> Any:
    result = resolve_maybe_awaitable(env.reset(task_id=task_name))
    return result


def step_env(env: NetworkForensicsEnv, action: NetworkForensicsAction) -> Any:
    result = resolve_maybe_awaitable(env.step(action))
    return result


WS_RETRY_COUNT = 3
WS_RETRY_DELAY_S = 2.0
LLM_TIMEOUT_S = 45.0


def step_env_with_retry(
    env: NetworkForensicsEnv,
    action: NetworkForensicsAction,
    task_name: str,
    agent_state: dict[str, Any],
) -> tuple[Any, NetworkForensicsEnv | None]:
    """Try step_env with retries on WebSocket timeout.

    Returns (step_result, new_env_or_None).
    If the WebSocket connection drops, reconnects and retries.
    """
    last_exc = None
    for attempt in range(1, WS_RETRY_COUNT + 1):
        try:
            result = step_env(env, action)
            return result, None
        except Exception as exc:
            last_exc = exc
            exc_str = str(exc).lower()
            is_ws_timeout = any(
                kw in exc_str
                for kw in ("keepalive", "ping timeout", "1011", "websocket", "connection")
            )
            if not is_ws_timeout:
                raise
            print(
                f"[WARN] WebSocket timeout on attempt {attempt}/{WS_RETRY_COUNT}: {exc}"
            )
            if attempt < WS_RETRY_COUNT:
                time.sleep(WS_RETRY_DELAY_S * attempt)
                # Try reconnecting
                try:
                    close_env(env)
                except Exception:
                    pass
                try:
                    env = create_env()
                    reset_result = reset_env(env, task_name)
                    obs = reset_result.observation
                    sync_agent_state(obs, agent_state)
                    print(f"[INFO] Reconnected to environment, resuming task={task_name}")
                except Exception as reconnect_exc:
                    print(f"[WARN] Reconnect failed: {reconnect_exc}")
                    continue
    raise last_exc  # type: ignore[misc]


def close_env(env: NetworkForensicsEnv | None) -> None:
    if env is None:
        return
    try:
        resolve_maybe_awaitable(env.close())
    except Exception:
        pass


def close_async_loop() -> None:
    global _ASYNC_LOOP
    if _ASYNC_LOOP is not None and not _ASYNC_LOOP.is_closed():
        _ASYNC_LOOP.close()
    _ASYNC_LOOP = None


def run_task(task_name: str) -> None:
    env: NetworkForensicsEnv | None = None
    rewards: list[float] = []
    final_steps = 0
    final_score = 0.0
    success = False
    agent_state: dict[str, Any] = {}
    client = build_client()
    print(f"[START] task={task_name} env=network_forensics model={MODEL_NAME}")

    try:
        env = create_env_with_fallback()
        reset_result = reset_env(env, task_name)
        obs = reset_result.observation
        sync_agent_state(obs, agent_state)
        max_steps = obs.steps_remaining or 50
        soft_budget = min(max_steps, SOFT_STEP_BUDGETS.get(task_name, max_steps))
        hard_budget = min(max_steps, HARD_STEP_CAPS.get(task_name, max_steps))
        start_ts = time.monotonic()
        task_time_budget = min(MAX_TASK_SECONDS, TASK_TIME_BUDGET_SECONDS.get(task_name, MAX_TASK_SECONDS))

        for _ in range(hard_budget):
            if obs.done:
                break

            elapsed = time.monotonic() - start_ts
            total_visible = max(1, len(obs.visible_packets))
            current_coverage = len(obs.flagged_packet_ids) / total_visible
            min_cov = TASK_COVERAGE_TARGETS.get(task_name, 0.25)
            ready_for_budget_submit = (
                obs.step_number >= soft_budget
                and should_submit_early(task_name, obs, agent_state)
            )
            forced_at_hard_cap = (
                obs.step_number >= max(1, hard_budget - 1)
                and (should_submit_early(task_name, obs, agent_state) or task_name != "easy")
            )
            nearing_time_limit = elapsed >= max(20.0, task_time_budget - 12.0)

            error = None
            try:
                if forced_at_hard_cap or nearing_time_limit or ready_for_budget_submit:
                    action = NetworkForensicsAction(
                        action_type="submit_report",
                        incident_summary=_build_report_summary(obs, agent_state),
                        claimed_entry_point=agent_state.get("claimed_entry_point") or obs.claimed_entry_point,
                    )
                else:
                    action = choose_action(client, task_name, obs, agent_state)
            except Exception as exc:
                error = str(exc).replace("\n", " ")
                action = build_fallback_action(task_name, obs, agent_state)

            try:
                step_result, new_env = step_env_with_retry(env, action, task_name, agent_state)
                if new_env is not None:
                    env = new_env
            except Exception as exc:
                print(f"[WARN] step failure on task={task_name}: {exc}")
                break
            obs = step_result.observation
            sync_agent_state(obs, agent_state)
            step_reward = float(step_result.reward or 0.0)
            rewards.append(step_reward)
            agent_state["last_step_reward"] = step_reward
            agent_state["last_reward_feedback"] = reward_feedback(action, step_reward)
            final_steps = obs.step_number
            # Track the report quality score from the last submit_report step
            metrics = final_metrics(obs)
            if action.action_type == "submit_report" and metrics:
                report_qs = metrics.get("final_score")
                if report_qs is not None:
                    final_score = normalize_score(float(report_qs))
            elif final_score == 0.0:
                final_score = normalize_score(
                    metrics.get("final_score", obs.current_score_estimate)
                    if metrics
                    else obs.current_score_estimate
                )
            emit_step(
                obs.step_number,
                action,
                step_reward,
                bool(step_result.done),
                error,
            )

            if step_result.done:
                break

        metrics = final_metrics(obs)
        threshold_met = (
            float(metrics.get("success_threshold_met", 0.0)) >= 1.0
            if metrics
            else False
        )
        success = bool(obs.done and (threshold_met or final_score >= 0.6))
    except Exception:
        success = False
        raise
    finally:
        close_env(env)
        rewards_text = ",".join(f"{reward:.2f}" for reward in rewards)
        print(
            f"[END] success={str(success).lower()} steps={final_steps} "
            f"score={final_score:.2f} rewards={rewards_text}"
        )


def main() -> None:
    validate_config()
    try:
        for task_name in ("easy", "medium", "hard"):
            run_task(task_name)
    finally:
        close_async_loop()


if __name__ == "__main__":
    main()
