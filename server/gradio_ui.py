from __future__ import annotations

import json
import time
from typing import Any, Tuple

import gradio as gr

try:
    from ..inference import build_client, build_fallback_action, choose_action, packet_payload_text, sync_agent_state
    from ..models import NetworkForensicsAction, NetworkForensicsObservation
    from .network_forensics_environment import NetworkForensicsEnvironment
except ImportError:
    from inference import build_client, build_fallback_action, choose_action, packet_payload_text, sync_agent_state
    from models import NetworkForensicsAction, NetworkForensicsObservation
    from server.network_forensics_environment import NetworkForensicsEnvironment


# ---------------------------------------------------------------------------
# Global state (single-session; fine for HF Spaces single-user demo)
# ---------------------------------------------------------------------------
env: NetworkForensicsEnvironment | None = None
current_obs: NetworkForensicsObservation | None = None
agent_state: dict[str, Any] = {}
last_step_reward: float = 0.0
last_final_meta: dict[str, Any] = {}

PATTERN_CHOICES = [
    "ddos",
    "web_bruteforce",
    "web_xss",
    "web_sql_injection",
    "dos_hulk",
    "dos_goldeneye",
    "dos_slowloris",
    "dos_slowhttptest",
    "heartbleed",
]

MODEL_CHOICES = [
    "openai/gpt-oss-120b",
    "mistralai/mistral-small-4-119b-2603",
    "mistralai/mamba-codestral-7b-v0.1",
    "nvidia/nvidia-nemotron-nano-9b-v2",
]

ACTION_TYPES = [
    "inspect_packet",
    "flag_as_suspicious",
    "group_into_session",
    "tag_pattern",
    "identify_entry_point",
    "submit_report",
]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _parse_packet_ids(packet_ids: Any) -> list[str] | None:
    if packet_ids is None or packet_ids == "":
        return None
    if isinstance(packet_ids, list):
        values = [str(v).strip() for v in packet_ids if str(v).strip()]
        return values or None
    values = [v.strip() for v in str(packet_ids).split(",") if v.strip()]
    return values or None


def _format_packets(obs: NetworkForensicsObservation) -> list[list[Any]]:
    rows: list[list[Any]] = []
    flagged = set(obs.flagged_packet_ids)
    grouped = {
        packet_id
        for packet_ids in obs.grouped_sessions.values()
        for packet_id in packet_ids
    }
    for packet in obs.visible_packets[:30]:
        preview = packet_payload_text(packet)
        status = ""
        if packet.packet_id in flagged:
            status = "FLAG"
        elif packet.packet_id in grouped:
            status = "GROUP"
        rows.append([
            status,
            packet.packet_id,
            packet.src_ip,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
            packet.ttl,
            packet.payload_size,
            "full" if packet.is_revealed else "preview",
            (preview or "")[:120],
        ])
    return rows


def _format_summary(obs: NetworkForensicsObservation) -> str:
    pct_flagged = (
        round(len(obs.flagged_packet_ids) / max(1, obs.total_packets) * 100, 1)
    )
    lines = [
        "### Episode Status",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Step | **{obs.step_number}** (remaining: {obs.steps_remaining}) |",
        f"| Running Score | **{obs.current_score_estimate:.3f}** |",
        f"| Total Packets | **{obs.total_packets}** |",
        f"| Flagged | **{len(obs.flagged_packet_ids)}** ({pct_flagged}%) |",
        f"| Sessions | **{len(obs.grouped_sessions)}** |",
        f"| Tagged Patterns | **{len(obs.tagged_patterns)}** |",
    ]
    if obs.claimed_entry_point:
        lines.append(f"| Entry Point | `{obs.claimed_entry_point}` |")
    if obs.tagged_patterns:
        lines.append("\n**Tags:**")
        for session, tag in obs.tagged_patterns.items():
            lines.append(f"- `{session}` -> `{tag}`")
    return "\n".join(lines)


def _format_graph(obs: NetworkForensicsObservation) -> str:
    g = obs.connection_graph_summary
    if not g:
        return "_No graph data yet. Inspect packets to build the topology._"

    lines = ["### Connection Graph Summary"]

    # Top talkers
    talkers = g.get("top_talkers", [])
    if talkers:
        lines.append("\n**Top Talkers (by packet count)**")
        lines.append("| IP | Packets |")
        lines.append("|----|---------|")
        for entry in talkers[:10]:
            ip = entry.get("ip", entry) if isinstance(entry, dict) else str(entry)
            count = entry.get("packet_count", entry.get("count", "")) if isinstance(entry, dict) else ""
            lines.append(f"| `{ip}` | {count} |")

    # Top flows
    flows = g.get("top_flows", [])
    if flows:
        lines.append("\n**Top Flows**")
        lines.append("| Src -> Dst | Protocol | Packets |")
        lines.append("|-----------|----------|---------|")
        for flow in flows[:12]:
            if isinstance(flow, dict):
                src = flow.get("src", "?")
                dst = flow.get("dst", "?")
                protocols = flow.get("protocols", flow.get("protocol", "?"))
                proto = ", ".join(protocols) if isinstance(protocols, list) else str(protocols)
                count = flow.get("packet_count", flow.get("count", ""))
                lines.append(f"| `{src}` -> `{dst}` | {proto} | {count} |")
            else:
                lines.append(f"| {flow} | | |")

    # Stats
    stats = g.get("stats", {})
    if stats:
        lines.append("\n**Graph Stats**")
        for k, v in stats.items():
            lines.append(f"- **{k}**: {v}")

    return "\n".join(lines)


def _format_final_scores(meta: dict[str, Any]) -> str:
    if not meta:
        return "_Submit an incident report to see final evaluation scores._"
    keys = [
        ("final_precision", "Precision"),
        ("final_recall", "Recall"),
        ("final_logic", "Logic"),
        ("final_llm_report", "LLM Report Quality"),
        ("final_session_overlap", "Session Overlap"),
        ("final_pattern_score", "Pattern Score"),
        ("final_entry_score", "Entry Point Score"),
        ("final_score", "**FINAL SCORE**"),
    ]
    lines = ["### Final Evaluation Scores", "| Metric | Score |", "|--------|-------|"]
    for key, label in keys:
        if key in meta:
            val = meta[key]
            bar = "█" * int(float(val) * 10) + "░" * (10 - int(float(val) * 10))
            lines.append(f"| {label} | {float(val):.3f} `{bar}` |")
    success = meta.get("success_threshold_met", 0)
    lines.append(f"\n**Success:** {'YES' if success else 'NO'}")
    return "\n".join(lines)


def _final_metrics(obs: NetworkForensicsObservation | None) -> dict[str, Any]:
    if obs is None:
        return {}
    return getattr(obs, "final_metrics", None) or getattr(obs, "metadata", None) or {}


def _control_updates(obs: NetworkForensicsObservation) -> tuple:
    packet_choices = [p.packet_id for p in obs.visible_packets]
    session_choices = list(obs.grouped_sessions.keys())
    return (
        gr.Dropdown(choices=packet_choices, value=None),
        gr.Dropdown(choices=packet_choices, value=[]),
        gr.Dropdown(choices=session_choices, value=None),
        gr.Dropdown(choices=PATTERN_CHOICES, value=None),
        gr.Dropdown(choices=packet_choices, value=None),
    )


def _mode_updates(mode: str) -> tuple:
    manual = mode == "Manual"
    return (
        gr.Dropdown(interactive=manual),
        gr.Dropdown(interactive=manual),
        gr.Dropdown(interactive=manual),
        gr.Dropdown(interactive=manual),
        gr.Dropdown(interactive=manual),
        gr.Dropdown(interactive=manual),
        gr.Button(interactive=manual),
        gr.Button(interactive=manual),
        gr.Button(interactive=not manual),
        gr.Button(interactive=not manual),
    )


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def reset_env(task_name: str):
    global env, current_obs, agent_state, last_step_reward, last_final_meta
    env = NetworkForensicsEnvironment(task_id=task_name)
    current_obs = env.reset()
    agent_state = {}
    last_step_reward = 0.0
    last_final_meta = {}
    sync_agent_state(current_obs, agent_state)
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        _format_graph(current_obs),
        _format_final_scores({}),
        f"Episode reset for **{task_name}** task.",
        *_control_updates(current_obs),
    )


def set_mode(mode: str) -> tuple:
    msg = (
        "**Manual mode** - pick actions yourself to explore reward shaping."
        if mode == "Manual"
        else "**Agent mode** - use Run Agent Step / Replay to watch the policy."
    )
    return (*_mode_updates(mode), msg)


def suggest_action(task_name: str, model_name: str):
    global current_obs, agent_state
    if current_obs is None:
        return "{}", None, [], None, None, None
    client = build_client()
    action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)
    return (
        json.dumps(payload, indent=2),
        action.packet_id,
        action.packet_ids or [],
        action.session_name,
        action.pattern_type,
        action.claimed_entry_point,
    )


def run_agent_step(task_name: str, model_name: str):
    global current_obs, agent_state, env, last_step_reward, last_final_meta
    if env is None or current_obs is None:
        reset_env(task_name)

    client = build_client()
    try:
        action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
    except Exception:
        action = build_fallback_action(task_name, current_obs, agent_state)

    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)

    current_obs = env.step(action)
    reward = current_obs.reward
    last_step_reward = reward

    meta = _final_metrics(current_obs)
    if meta:
        last_final_meta = dict(meta)

    sync_agent_state(current_obs, agent_state)

    log_line = f"Step {current_obs.step_number}: {json.dumps(payload)} -> reward {reward:.3f}"
    status = (
        f"Episode finished. Step reward: **{reward:.3f}**"
        if current_obs.done
        else f"Agent step done. Reward: **{reward:.3f}**"
    )
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        _format_graph(current_obs),
        _format_final_scores(last_final_meta),
        status,
        json.dumps(payload, indent=2),
        log_line,
        *_control_updates(current_obs),
    )


def replay_agent(task_name: str, model_name: str):
    global current_obs, agent_state, env, last_step_reward, last_final_meta
    if env is None or current_obs is None or current_obs.done:
        reset_env(task_name)

    client = build_client()
    replay_lines: list[str] = []
    max_steps = current_obs.steps_remaining or 50

    for _ in range(max_steps):
        if current_obs.done:
            break
        try:
            action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
        except Exception:
            action = build_fallback_action(task_name, current_obs, agent_state)

        payload = action.model_dump(exclude_none=True, exclude_defaults=True)
        payload.pop("metadata", None)

        current_obs = env.step(action)
        reward = float(getattr(current_obs, 'reward', 0.0))
        meta = _final_metrics(current_obs)

        if action.action_type == "submit_report" and meta:
            last_final_meta = dict(meta)
        elif meta:
            last_final_meta = dict(meta)

        sync_agent_state(current_obs, agent_state)
        replay_lines.append(f"Step {current_obs.step_number}: {json.dumps(payload)} -> {reward:.3f}")

        status = (
            f"Replay complete. Final reward: **{reward:.3f}**"
            if current_obs.done
            else f"Replaying... step {current_obs.step_number} reward {reward:.3f}"
        )
        yield (
            _format_summary(current_obs),
            _format_packets(current_obs),
            _format_graph(current_obs),
            _format_final_scores(last_final_meta),
            status,
            json.dumps(payload, indent=2),
            "\n".join(replay_lines),
            *_control_updates(current_obs),
        )
        time.sleep(0.3)


def step_env_manual(
    action_type: str,
    packet_id: str,
    packet_ids: Any,
    session_name: str,
    pattern_type: str,
    claimed_entry_point: str,
    incident_summary: str,
):
    global env, current_obs, last_final_meta

    if env is None:
        return (
            "### No episode running",
            [],
            "_No graph yet._",
            "_No scores yet._",
            "Choose a task and click **Reset Episode** first.",
            gr.Dropdown(), gr.Dropdown(), gr.Dropdown(), gr.Dropdown(), gr.Dropdown(),
        )

    action = NetworkForensicsAction(
        action_type=action_type,
        packet_id=packet_id or None,
        packet_ids=_parse_packet_ids(packet_ids),
        session_name=session_name or None,
        pattern_type=pattern_type or None,
        claimed_entry_point=claimed_entry_point or None,
        incident_summary=incident_summary or None,
    )

    current_obs = env.step(action)
    reward = float(getattr(current_obs, 'reward', 0.0))
    meta = _final_metrics(current_obs)

    if action.action_type == "submit_report" and meta:
        last_final_meta = dict(meta)
    elif meta:
        last_final_meta = dict(meta)

    sync_agent_state(current_obs, agent_state)

    status = (
        f"Episode complete. Step reward: **{reward:.3f}**"
        if current_obs.done
        else f"Action applied. Step reward: **{reward:.3f}**"
    )
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        _format_graph(current_obs),
        _format_final_scores(last_final_meta),
        status,
        *_control_updates(current_obs),
    )


# ---------------------------------------------------------------------------
# UI layout
# ---------------------------------------------------------------------------

def create_demo() -> gr.Blocks:
    css = """
    body, .gradio-container { background: #0a0f1e !important; }
    .app-shell { max-width: 1600px; margin: 0 auto; }
    .panel {
        border: 1px solid rgba(99,179,237,0.15);
        border-radius: 16px;
        padding: 16px;
        background: rgba(10,20,40,0.85);
        backdrop-filter: blur(8px);
    }
    .hero {
        padding: 20px 28px;
        border-radius: 20px;
        background: linear-gradient(135deg, #05090f 0%, #0d2240 50%, #0a3060 100%);
        border: 1px solid rgba(99,179,237,0.2);
        margin-bottom: 12px;
    }
    .hero h1 { color: #63b3ed; margin: 0; font-size: 1.6rem; }
    .hero p { opacity: 0.7; margin-top: 6px; color: #a0c4e8; }
    .score-good { color: #68d391 !important; }
    .score-bad  { color: #fc8181 !important; }
    """

    with gr.Blocks(
        title="NetForensics-RL · Analyst Console",
    ) as demo:
        with gr.Column(elem_classes=["app-shell"]):
            gr.HTML(f"<style>{css}</style>")
            gr.HTML("""
            <div class="hero">
              <h1>NetForensics-RL &nbsp;·&nbsp; Analyst Console</h1>
              <p>Investigate network attacks with an AI agent or step through manually.
                 Watch the connection graph build in real-time as packets are revealed.</p>
            </div>
            """)

            with gr.Row():
                # ── Left sidebar ────────────────────────────────────────────
                with gr.Column(scale=1, min_width=280, elem_classes=["panel"]):
                    gr.Markdown("### ⚙️ Episode Control")
                    mode = gr.Radio(["Manual", "Agent"], label="Mode", value="Manual")
                    task_select = gr.Radio(["easy", "medium", "hard"], label="Task", value="easy")
                    model_name = gr.Dropdown(
                        choices=MODEL_CHOICES,
                        value=MODEL_CHOICES[0],
                        label="LLM Model",
                    )
                    reset_btn = gr.Button("Reset Episode", variant="primary")

                    gr.Markdown("---")
                    gr.Markdown("### Agent Controls")
                    suggest_btn = gr.Button("Suggest Action (LLM)")
                    agent_step_btn = gr.Button("Run Agent Step", interactive=False)
                    replay_btn = gr.Button("Run Agent Replay", interactive=False)

                    gr.Markdown("---")
                    gr.Markdown("### Manual Action")
                    action_type = gr.Dropdown(ACTION_TYPES, label="Action Type", value="inspect_packet")
                    packet_id = gr.Dropdown(label="Packet ID", choices=[], value=None)
                    packet_ids = gr.Dropdown(label="Packet IDs (multi)", choices=[], value=[], multiselect=True)
                    session_name = gr.Dropdown(label="Session Name", choices=[], value=None, allow_custom_value=True)
                    pattern_type = gr.Dropdown(label="Pattern Type", choices=PATTERN_CHOICES, value=None)
                    claimed_entry_point = gr.Dropdown(label="Entry Point Packet", choices=[], value=None)
                    incident_summary = gr.Textbox(
                        label="Incident Summary (for submit_report)",
                        lines=4,
                        placeholder="Describe the attack: actors, targets, techniques, timeline…",
                    )
                    step_btn = gr.Button("Apply Action", variant="secondary")

                # ── Main content area ────────────────────────────────────────
                with gr.Column(scale=3):
                    # Top row: status + LLM output
                    with gr.Row():
                        with gr.Column(scale=2, elem_classes=["panel"]):
                            summary = gr.Markdown("Click **Reset Episode** to begin.")
                            status = gr.Markdown("")
                        with gr.Column(scale=1, elem_classes=["panel"]):
                            llm_json = gr.Code(label="LLM Action JSON", language="json", value="{}")

                    # Middle: packet table
                    with gr.Row():
                        with gr.Column(elem_classes=["panel"]):
                            packets = gr.Dataframe(
                                headers=["Status", "ID", "Src IP", "Dst IP", "Port", "Protocol", "TTL", "Size", "Payload Source", "Payload"],
                                datatype=["str", "str", "str", "str", "number", "str", "number", "number", "str", "str"],
                                interactive=False,
                                wrap=True,
                                label="Packet Stream",
                            )

                    # Bottom: graph + scores + replay log
                    with gr.Row():
                        with gr.Column(scale=2, elem_classes=["panel"]):
                            graph_md = gr.Markdown("_No graph data yet._", label="")
                            gr.Markdown("#### Connection Graph", visible=False)  # label handled above
                        with gr.Column(scale=1, elem_classes=["panel"]):
                            scores_md = gr.Markdown("_Submit a report to see scores._")
                        with gr.Column(scale=2, elem_classes=["panel"]):
                            replay_log = gr.Code(label="Agent Replay Log", language="markdown", value="")

        # ── Common output list helpers ───────────────────────────────────────
        # Order: summary, packets, graph, scores, status, packet_id, packet_ids,
        #        session_name, pattern_type, claimed_entry_point
        common_outs = [summary, packets, graph_md, scores_md, status,
                       packet_id, packet_ids, session_name, pattern_type, claimed_entry_point]

        # ── Wiring ──────────────────────────────────────────────────────────
        reset_btn.click(
            reset_env,
            inputs=task_select,
            outputs=common_outs,
        )
        reset_btn.click(lambda: "", outputs=replay_log)

        step_btn.click(
            step_env_manual,
            inputs=[action_type, packet_id, packet_ids, session_name,
                    pattern_type, claimed_entry_point, incident_summary],
            outputs=common_outs,
        )

        suggest_btn.click(
            suggest_action,
            inputs=[task_select, model_name],
            outputs=[llm_json, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )

        agent_step_btn.click(
            run_agent_step,
            inputs=[task_select, model_name],
            outputs=[summary, packets, graph_md, scores_md, status, llm_json, replay_log,
                     packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )

        replay_btn.click(
            replay_agent,
            inputs=[task_select, model_name],
            outputs=[summary, packets, graph_md, scores_md, status, llm_json, replay_log,
                     packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )

        mode.change(
            set_mode,
            inputs=mode,
            outputs=[action_type, packet_id, packet_ids, session_name, pattern_type,
                     claimed_entry_point, step_btn, suggest_btn, agent_step_btn, replay_btn, status],
        )

        task_select.change(lambda: "", outputs=replay_log)

        demo.load(
            set_mode,
            inputs=mode,
            outputs=[action_type, packet_id, packet_ids, session_name, pattern_type,
                     claimed_entry_point, step_btn, suggest_btn, agent_step_btn, replay_btn, status],
        )

    return demo
