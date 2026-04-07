import json
import os
import sys
import asyncio
import inspect
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
MODEL_NAME = os.getenv("MODEL_NAME")
API_KEY = os.getenv("API_KEY") or os.getenv("HF_TOKEN")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME", "network-forensics-env:latest")
ENV_MODE = (os.getenv("NETWORK_FORENSICS_ENV_MODE") or os.getenv("ENV_MODE") or "docker").lower()
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:8000")
DOCKER_READY_TIMEOUT_S = float(os.getenv("DOCKER_READY_TIMEOUT_S", "120"))
_ASYNC_LOOP: asyncio.AbstractEventLoop | None = None

SYSTEM_PROMPT = """You are a network forensics analyst operating in an RL environment.

Choose exactly one next action using this JSON schema:
{"action_type":"inspect_packet|flag_as_suspicious|group_into_session|tag_pattern|identify_entry_point|submit_report","packet_id":"pkt_0001","packet_ids":["pkt_0001","pkt_0002"],"session_name":"name","pattern_type":"ddos","claimed_entry_point":"pkt_0001"}

Rules:
- Return JSON only.
- Prefer inspecting packets with suspicious payload previews, HTTP attack strings, DDoS bursts, or repeated unusual destinations.
- Flag packets only after some evidence.
- Group packets into a session only when they share the same src_ip, dst_ip, dst_port, and likely role.
- Tag patterns using labels like ddos, web_bruteforce, web_xss, web_sql_injection, dos_hulk, dos_goldeneye, dos_slowloris, dos_slowhttptest, heartbleed.
- Identify the entry point only when you have a strong guess.
- Submit the report when you have already flagged multiple suspicious packets and created at least one session."""


def build_client() -> OpenAI:
    return OpenAI(base_url=API_BASE_URL, api_key=API_KEY)


def validate_config() -> None:
    missing = []
    if not API_BASE_URL:
        missing.append("API_BASE_URL")
    if not MODEL_NAME:
        missing.append("MODEL_NAME")
    if not API_KEY:
        missing.append("API_KEY")
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
    if ENV_MODE not in {"server", "docker"}:
        raise RuntimeError("NETWORK_FORENSICS_ENV_MODE must be one of: server, docker")


def format_action(action: NetworkForensicsAction) -> str:
    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)
    payload = {
        key: value
        for key, value in payload.items()
        if value not in ("", [], {})
    }
    return json.dumps(payload, separators=(",", ":"))


def summarize_observation(obs: Any) -> str:
    packets = []
    for packet in obs.visible_packets[:25]:
        packets.append(
            {
                "packet_id": packet.packet_id,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "dst_port": packet.dst_port,
                "protocol": packet.protocol,
                "ttl": packet.ttl,
                "payload_size": packet.payload_size,
                "payload_preview": packet.payload_preview,
                "revealed_payload": packet.full_payload if packet.is_revealed else None,
            }
        )

    summary = {
        "step_number": obs.step_number,
        "steps_remaining": obs.steps_remaining,
        "current_score_estimate": obs.current_score_estimate,
        "total_packets": obs.total_packets,
        "flagged_packet_ids": obs.flagged_packet_ids,
        "grouped_sessions": obs.grouped_sessions,
        "tagged_patterns": obs.tagged_patterns,
        "claimed_entry_point": obs.claimed_entry_point,
        "visible_packets": packets,
    }
    return json.dumps(summary, separators=(",", ":"))


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
    if action.action_type in {"inspect_packet", "flag_as_suspicious"} and action.packet_id:
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
    return NetworkForensicsAction(**payload)


def keyword_to_pattern(payload: str) -> str | None:
    text = payload.lower()
    if "slowloris" in text:
        return "dos_slowloris"
    if "slowhttptest" in text:
        return "dos_slowhttptest"
    if "goldeneye" in text:
        return "dos_goldeneye"
    if "hulk" in text:
        return "dos_hulk"
    if "heartbeat" in text or "tls" in text:
        return "heartbleed"
    if "xss" in text or "<script>" in text:
        return "web_xss"
    if "or 1=1" in text or "sql" in text:
        return "web_sql_injection"
    if "login" in text or "username=admin" in text:
        return "web_bruteforce"
    if "flood" in text or "burst" in text:
        return "ddos"
    return None


def packet_signature(packet: Any) -> tuple[str, str, int]:
    return (packet.src_ip, packet.dst_ip, packet.dst_port)


def build_fallback_action(task_name: str, obs: Any, agent_state: dict[str, Any]) -> NetworkForensicsAction:
    inspected_ids = agent_state.setdefault("inspected_ids", set())
    flagged_ids = agent_state.setdefault("flagged_ids", set())
    session_map = agent_state.setdefault("sessions", {})
    tagged_sessions = agent_state.setdefault("tagged_sessions", set())
    claimed_entry = agent_state.setdefault("claimed_entry_point", None)

    suspicious_revealed = []
    for packet in obs.visible_packets:
        payload = packet.full_payload or ""
        pattern = keyword_to_pattern(payload) if packet.is_revealed else None
        if pattern:
            suspicious_revealed.append((packet, pattern))

    for packet, _pattern in suspicious_revealed:
        if packet.packet_id not in flagged_ids:
            flagged_ids.add(packet.packet_id)
            return NetworkForensicsAction(
                action_type="flag_as_suspicious",
                packet_id=packet.packet_id,
            )

    grouped_candidates: dict[tuple[str, str, int], list[Any]] = {}
    for packet, pattern in suspicious_revealed:
        key = packet_signature(packet)
        grouped_candidates.setdefault(key, []).append((packet, pattern))

    for key, items in grouped_candidates.items():
        packet_ids = [packet.packet_id for packet, _ in items]
        if len(packet_ids) >= 2 and key not in session_map:
            session_name = f"{task_name}_session_{len(session_map) + 1:02d}"
            session_map[key] = session_name
            return NetworkForensicsAction(
                action_type="group_into_session",
                session_name=session_name,
                packet_ids=packet_ids,
            )

    for key, session_name in session_map.items():
        if session_name in tagged_sessions:
            continue
        packets = grouped_candidates.get(key, [])
        if not packets:
            continue
        pattern = keyword_to_pattern(packets[0][0].full_payload or "")
        if pattern:
            tagged_sessions.add(session_name)
            return NetworkForensicsAction(
                action_type="tag_pattern",
                session_name=session_name,
                pattern_type=pattern,
            )

    if suspicious_revealed and not claimed_entry:
        earliest_packet = min(suspicious_revealed, key=lambda item: item[0].packet_id)[0]
        agent_state["claimed_entry_point"] = earliest_packet.packet_id
        return NetworkForensicsAction(
            action_type="identify_entry_point",
            claimed_entry_point=earliest_packet.packet_id,
        )

    for packet in obs.visible_packets:
        if not packet.is_revealed and packet.packet_id not in inspected_ids:
            return NetworkForensicsAction(
                action_type="inspect_packet",
                packet_id=packet.packet_id,
            )

    ready_to_submit = bool(flagged_ids) and bool(session_map)
    if ready_to_submit or obs.steps_remaining <= 3:
        return NetworkForensicsAction(action_type="submit_report")

    for packet in obs.visible_packets:
        if not packet.is_revealed and packet.packet_id not in flagged_ids:
            return NetworkForensicsAction(
                action_type="inspect_packet",
                packet_id=packet.packet_id,
            )

    return NetworkForensicsAction(action_type="submit_report")


def should_override_action(action: NetworkForensicsAction, obs: Any, agent_state: dict[str, Any]) -> bool:
    previous_actions = agent_state.setdefault("previous_actions", [])
    inspected_ids = agent_state.setdefault("inspected_ids", set())
    flagged_ids = agent_state.setdefault("flagged_ids", set())
    tagged_sessions = agent_state.setdefault("tagged_sessions", set())
    action_repr = format_action(action)
    visible_lookup = {packet.packet_id: packet for packet in obs.visible_packets}
    if action.action_type not in {
        "inspect_packet",
        "flag_as_suspicious",
        "group_into_session",
        "tag_pattern",
        "identify_entry_point",
        "submit_report",
    }:
        return True
    if action.action_type == "inspect_packet" and not action.packet_id:
        return True
    if action.action_type == "inspect_packet" and action.packet_id:
        packet = visible_lookup.get(action.packet_id)
        if packet is None or packet.is_revealed or action.packet_id in inspected_ids:
            return True
    if action.action_type == "flag_as_suspicious" and not action.packet_id:
        return True
    if action.action_type == "flag_as_suspicious" and action.packet_id:
        if action.packet_id in flagged_ids:
            return True
    if action.action_type == "group_into_session" and (not action.session_name or not action.packet_ids):
        return True
    if action.action_type == "group_into_session" and action.packet_ids:
        if len(set(action.packet_ids)) < 2:
            return True
    if action.action_type == "tag_pattern" and (not action.session_name or not action.pattern_type):
        return True
    if action.action_type == "tag_pattern" and action.session_name in tagged_sessions:
        return True
    if action.action_type == "identify_entry_point" and not action.claimed_entry_point:
        return True
    if action.action_type == "identify_entry_point" and agent_state.get("claimed_entry_point"):
        return True
    if len(previous_actions) >= 2 and previous_actions[-1] == action_repr and previous_actions[-2] == action_repr:
        return True
    return False


def choose_action(
    client: OpenAI,
    task_name: str,
    obs: Any,
    agent_state: dict[str, Any],
    model_name: str | None = None,
) -> NetworkForensicsAction:
    response = client.chat.completions.create(
        model=model_name or MODEL_NAME,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"task={task_name}\nobservation={summarize_observation(obs)}",
            },
        ],
    )
    content = response.choices[0].message.content or ""
    action = sanitize_action(parse_action(content))
    if should_override_action(action, obs, agent_state):
        action = build_fallback_action(task_name, obs, agent_state)
    agent_state.setdefault("previous_actions", []).append(format_action(action))
    return action


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


def emit_step(step_number: int, action: NetworkForensicsAction, reward: float, done: bool, error: str | None) -> None:
    error_text = error if error is not None else "null"
    done_text = str(done).lower()
    print(
        f"[STEP] step={step_number} action={format_action(action)} "
        f"reward={reward:.2f} done={done_text} error={error_text}"
    )


def normalize_score(score: float) -> float:
    return max(0.0, min(1.0, score))


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
    if ENV_MODE == "docker":
        provider = ExtendedWaitDockerProvider()
        return resolve_maybe_awaitable(
            NetworkForensicsEnv.from_docker_image(LOCAL_IMAGE_NAME, provider=provider)
        )
    return NetworkForensicsEnv(base_url=ENV_BASE_URL)


def reset_env(env: NetworkForensicsEnv, task_name: str) -> Any:
    result = resolve_maybe_awaitable(env.reset(task_id=task_name))
    return result


def step_env(env: NetworkForensicsEnv, action: NetworkForensicsAction) -> Any:
    result = resolve_maybe_awaitable(env.step(action))
    return result


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
        env = create_env()
        reset_result = reset_env(env, task_name)
        obs = reset_result.observation
        sync_agent_state(obs, agent_state)
        max_steps = obs.steps_remaining or 50

        for _ in range(max_steps):
            if obs.done:
                break

            error = None
            try:
                action = choose_action(client, task_name, obs, agent_state)
            except Exception as exc:
                error = str(exc).replace("\n", " ")
                action = build_fallback_action(task_name, obs, agent_state)

            step_result = step_env(env, action)
            obs = step_result.observation
            sync_agent_state(obs, agent_state)
            rewards.append(float(step_result.reward or 0.0))
            final_steps = obs.step_number
            final_score = normalize_score(obs.metadata.get("final_score", obs.current_score_estimate))
            emit_step(obs.step_number, action, float(step_result.reward or 0.0), bool(step_result.done), error)

            if step_result.done:
                break

        success = bool(obs.done and final_score >= 0.6)
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
