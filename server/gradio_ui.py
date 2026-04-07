from __future__ import annotations

import time
from typing import Any, Tuple

import gradio as gr

try:
    from ..inference import build_client, choose_action, sync_agent_state
    from ..models import NetworkForensicsAction, NetworkForensicsObservation
    from .network_forensics_environment import NetworkForensicsEnvironment
except ImportError:
    from inference import build_client, choose_action, sync_agent_state
    from models import NetworkForensicsAction, NetworkForensicsObservation
    from server.network_forensics_environment import NetworkForensicsEnvironment


env: NetworkForensicsEnvironment | None = None
current_obs: NetworkForensicsObservation | None = None
agent_state: dict[str, Any] = {}


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


def _parse_packet_ids(packet_ids: Any) -> list[str] | None:
    if packet_ids is None or packet_ids == "":
        return None
    if isinstance(packet_ids, list):
        values = [str(value).strip() for value in packet_ids if str(value).strip()]
        return values or None
    values = [value.strip() for value in str(packet_ids).split(",") if value.strip()]
    return values or None


def _format_packets(obs: NetworkForensicsObservation) -> list[list[str | int]]:
    rows: list[list[str | int]] = []
    for packet in obs.visible_packets[:25]:
        preview = packet.full_payload if packet.is_revealed and packet.full_payload else packet.payload_preview
        rows.append(
            [
                packet.packet_id,
                packet.src_ip,
                packet.dst_ip,
                packet.dst_port,
                packet.protocol,
                packet.ttl,
                packet.payload_size,
                preview,
            ]
        )
    return rows


def _format_summary(obs: NetworkForensicsObservation) -> str:
    lines = [
        f"### Episode Status",
        f"- Step: **{obs.step_number}** / remaining **{obs.steps_remaining}**",
        f"- Score: **{obs.current_score_estimate:.2f}**",
        f"- Total packets: **{obs.total_packets}**",
        f"- Flagged packets: **{len(obs.flagged_packet_ids)}**",
    ]
    if obs.grouped_sessions:
        lines.append(f"- Sessions: **{', '.join(obs.grouped_sessions.keys())}**")
    if obs.tagged_patterns:
        lines.append(f"- Tagged patterns: **{obs.tagged_patterns}**")
    if obs.claimed_entry_point:
        lines.append(f"- Claimed entry point: **{obs.claimed_entry_point}**")
    return "\n".join(lines)


def _control_updates(obs: NetworkForensicsObservation) -> tuple:
    packet_choices = [packet.packet_id for packet in obs.visible_packets]
    session_choices = list(obs.grouped_sessions.keys())
    return (
        gr.Dropdown(choices=packet_choices, value=None),
        gr.Dropdown(choices=packet_choices, value=[]),
        gr.Dropdown(choices=session_choices, value=None),
        gr.Dropdown(choices=PATTERN_CHOICES, value=None),
        gr.Dropdown(choices=packet_choices, value=None),
    )


def _mode_updates(mode: str) -> tuple:
    manual_enabled = mode == "Manual"
    return (
        gr.Dropdown(interactive=manual_enabled),
        gr.Dropdown(interactive=manual_enabled),
        gr.Dropdown(interactive=manual_enabled),
        gr.Dropdown(interactive=manual_enabled),
        gr.Dropdown(interactive=manual_enabled),
        gr.Dropdown(interactive=manual_enabled),
        gr.Button(interactive=manual_enabled),
        gr.Button(interactive=manual_enabled),
        gr.Button(interactive=not manual_enabled),
        gr.Button(interactive=not manual_enabled),
    )


def reset_env(task_name: str) -> Tuple[str, list[list[str | int]], str, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown]:
    global env, current_obs, agent_state
    env = NetworkForensicsEnvironment(task_id=task_name)
    current_obs = env.reset()
    agent_state = {}
    sync_agent_state(current_obs, agent_state)
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        "Episode reset.",
        *_control_updates(current_obs),
    )


def set_mode(mode: str) -> tuple:
    message = (
        "Manual mode enabled. Pick actions yourself to test reward shaping."
        if mode == "Manual"
        else "Agent mode enabled. Use Run Agent Replay to watch the policy navigate the PCAP."
    )
    return (*_mode_updates(mode), message)


def suggest_action(task_name: str, model_name: str) -> Tuple[str, str | None, list[str], str | None, str | None, str | None]:
    global current_obs, agent_state
    if current_obs is None:
        return "{}", None, [], None, None, None

    client = build_client()
    action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)
    return (
        __import__("json").dumps(payload, indent=2),
        action.packet_id,
        action.packet_ids or [],
        action.session_name,
        action.pattern_type,
        action.claimed_entry_point,
    )


def run_agent_step(task_name: str, model_name: str) -> Tuple[str, list[list[str | int]], str, str, str, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown]:
    global current_obs, agent_state, env
    if env is None or current_obs is None:
        reset_env(task_name)

    client = build_client()
    action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
    payload = action.model_dump(exclude_none=True, exclude_defaults=True)
    payload.pop("metadata", None)
    current_obs = env.step(action)
    sync_agent_state(current_obs, agent_state)
    log_line = f"Step {current_obs.step_number}: {payload} -> reward {current_obs.reward:.2f}"
    status = (
        f"Agent finished the episode. Step reward: {current_obs.reward:.2f}"
        if current_obs.done
        else f"Agent applied one action. Step reward: {current_obs.reward:.2f}"
    )
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        status,
        __import__("json").dumps(payload, indent=2),
        log_line,
        *_control_updates(current_obs),
    )


def replay_agent(task_name: str, model_name: str):
    global current_obs, agent_state, env
    if env is None or current_obs is None or current_obs.done:
        reset_env(task_name)

    client = build_client()
    replay_lines: list[str] = []
    max_steps = current_obs.steps_remaining or 50

    for _ in range(max_steps):
        if current_obs.done:
            break

        action = choose_action(client, task_name, current_obs, agent_state, model_name=model_name)
        payload = action.model_dump(exclude_none=True, exclude_defaults=True)
        payload.pop("metadata", None)
        current_obs = env.step(action)
        sync_agent_state(current_obs, agent_state)

        replay_lines.append(
            f"Step {current_obs.step_number}: {payload} -> reward {current_obs.reward:.2f}"
        )
        status = (
            f"Replay complete. Final step reward: {current_obs.reward:.2f}"
            if current_obs.done
            else f"Agent replay running. Latest reward: {current_obs.reward:.2f}"
        )

        yield (
            _format_summary(current_obs),
            _format_packets(current_obs),
            status,
            __import__("json").dumps(payload, indent=2),
            "\n".join(replay_lines),
            *_control_updates(current_obs),
        )
        time.sleep(0.35)


def step_env(
    action_type: str,
    packet_id: str,
    packet_ids: str,
    session_name: str,
    pattern_type: str,
    claimed_entry_point: str,
) -> Tuple[str, list[list[str | int]], str, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown, gr.Dropdown]:
    global env, current_obs

    if env is None:
        return (
            "### No episode running",
            [],
            "Choose a task and click Reset Episode first.",
            gr.Dropdown(),
            gr.Dropdown(),
            gr.Dropdown(),
            gr.Dropdown(),
            gr.Dropdown(),
        )

    action = NetworkForensicsAction(
        action_type=action_type,
        packet_id=packet_id or None,
        packet_ids=_parse_packet_ids(packet_ids),
        session_name=session_name or None,
        pattern_type=pattern_type or None,
        claimed_entry_point=claimed_entry_point or None,
    )
    current_obs = env.step(action)
    sync_agent_state(current_obs, agent_state)
    status = (
        f"Episode complete. Step reward: {current_obs.reward:.2f}"
        if current_obs.done
        else f"Action applied. Step reward: {current_obs.reward:.2f}"
    )
    return (
        _format_summary(current_obs),
        _format_packets(current_obs),
        status,
        *_control_updates(current_obs),
    )


def create_demo() -> gr.Blocks:
    theme = gr.themes.Base(
        primary_hue="cyan",
        secondary_hue="blue",
        neutral_hue="slate",
    )
    css = """
    .app-shell {max-width: 1440px; margin: 0 auto;}
    .panel {border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 14px; background: rgba(8,15,27,0.78);}
    .hero {padding: 18px 22px; border-radius: 22px; background: linear-gradient(135deg, #081221 0%, #102845 55%, #16375f 100%);}
    .hero h1, .hero p {margin: 0;}
    .hero p {opacity: 0.82; margin-top: 8px;}
    """
    with gr.Blocks(title="Network Forensics Analyst Console", theme=theme, css=css) as demo:
        with gr.Column(elem_classes=["app-shell"]):
            gr.Markdown(
                """
                <div class="hero">
                  <h1>Network Forensics Analyst Console</h1>
                  <p>Switch between manual investigation and agent replay while inspecting packets, sessions, and model decisions in real time.</p>
                </div>
                """
            )

            with gr.Row():
                with gr.Column(scale=1, elem_classes=["panel"]):
                    mode = gr.Radio(["Manual", "Agent"], label="Mode", value="Manual")
                    task_select = gr.Radio(["easy", "medium", "hard"], label="Task", value="easy")
                    model_name = gr.Dropdown(
                        choices=MODEL_CHOICES,
                        value=MODEL_CHOICES[0],
                        label="LLM Model",
                        info="Used for action suggestions and agent replay.",
                    )
                    reset_btn = gr.Button("Reset Episode", variant="primary")
                    suggest_btn = gr.Button("Suggest Action (LLM)")
                    agent_step_btn = gr.Button("Run Agent Step", interactive=False)
                    replay_btn = gr.Button("Run Agent Replay", interactive=False)

                    gr.Markdown("### Action")
                    action_type = gr.Dropdown(
                        [
                            "inspect_packet",
                            "flag_as_suspicious",
                            "group_into_session",
                            "tag_pattern",
                            "identify_entry_point",
                            "submit_report",
                        ],
                        label="Action Type",
                        value="inspect_packet",
                    )
                    packet_id = gr.Dropdown(label="Packet ID", choices=[], value=None, allow_custom_value=False)
                    packet_ids = gr.Dropdown(
                        label="Packet IDs",
                        choices=[],
                        value=[],
                        multiselect=True,
                        allow_custom_value=False,
                    )
                    session_name = gr.Dropdown(label="Session Name", choices=[], value=None, allow_custom_value=False)
                    pattern_type = gr.Dropdown(
                        label="Pattern Type",
                        choices=PATTERN_CHOICES,
                        value=None,
                        allow_custom_value=False,
                    )
                    claimed_entry_point = gr.Dropdown(
                        label="Claimed Entry Point",
                        choices=[],
                        value=None,
                        allow_custom_value=False,
                    )
                    step_btn = gr.Button("Apply Action")

                with gr.Column(scale=2):
                    with gr.Row():
                        with gr.Column(scale=1, elem_classes=["panel"]):
                            summary = gr.Markdown("Click **Reset Episode** to begin.")
                            status = gr.Markdown("")
                        with gr.Column(scale=1, elem_classes=["panel"]):
                            llm_json = gr.Code(label="LLM Output JSON", language="json", value="{}")

                    with gr.Row():
                        with gr.Column(scale=2, elem_classes=["panel"]):
                            packets = gr.Dataframe(
                                headers=["ID", "Src IP", "Dst IP", "Port", "Protocol", "TTL", "Size", "Preview"],
                                datatype=["str", "str", "str", "number", "str", "number", "number", "str"],
                                interactive=False,
                                wrap=True,
                            )
                        with gr.Column(scale=1, elem_classes=["panel"]):
                            replay_log = gr.Code(label="Agent Replay", language="markdown", value="")

        reset_btn.click(
            reset_env,
            inputs=task_select,
            outputs=[summary, packets, status, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )
        step_btn.click(
            step_env,
            inputs=[action_type, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
            outputs=[summary, packets, status, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )
        suggest_btn.click(
            suggest_action,
            inputs=[task_select, model_name],
            outputs=[llm_json, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )
        agent_step_btn.click(
            run_agent_step,
            inputs=[task_select, model_name],
            outputs=[summary, packets, status, llm_json, replay_log, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )
        mode.change(
            set_mode,
            inputs=mode,
            outputs=[action_type, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point, step_btn, suggest_btn, agent_step_btn, replay_btn, status],
        )
        task_select.change(
            lambda: "",
            outputs=replay_log,
        )
        reset_btn.click(
            lambda: "",
            outputs=replay_log,
        )
        demo.load(
            set_mode,
            inputs=mode,
            outputs=[action_type, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point, step_btn, suggest_btn, agent_step_btn, replay_btn, status],
        )
        replay_btn.click(
            replay_agent,
            inputs=[task_select, model_name],
            outputs=[summary, packets, status, llm_json, replay_log, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        )

    return demo
