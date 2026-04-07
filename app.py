import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gradio as gr
from server.network_forensics_environment import NetworkForensicsEnvironment
from models import NetworkForensicsAction


env = None
current_obs = None


def reset_env(task_name):
    global env, current_obs
    env = NetworkForensicsEnvironment(task_id=task_name)
    current_obs = env.reset()
    return format_obs(current_obs)


def format_obs(obs):
    lines = [
        f"**Step**: {obs.step_number}/{obs.steps_remaining}",
        f"**Score**: {obs.current_score_estimate:.2f}",
        f"**Total Packets**: {obs.total_packets}",
        f"**Flagged**: {len(obs.flagged_packet_ids)} packets",
    ]
    if obs.grouped_sessions:
        lines.append(f"**Sessions**: {', '.join(obs.grouped_sessions.keys())}")
    if obs.tagged_patterns:
        lines.append(f"**Tags**: {obs.tagged_patterns}")
    packet_table = "ID|Src|Dst|Port|Protocol|TTL|Size|Preview\n"
    packet_table += "-|-|-|-|-|-|-|-\n"
    for p in obs.visible_packets[:20]:
        preview = p.full_payload if p.is_revealed and p.full_payload else p.payload_preview
        packet_table += f"{p.packet_id}|{p.src_ip}|{p.dst_ip}|{p.dst_port}|{p.protocol}|{p.ttl}|{p.payload_size}|{preview}\n"
    return "\n".join(lines), packet_table


def step(action_type, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point):
    global env, current_obs
    if env is None:
        return "Please select a task and click Run Episode first", ""

    parsed_packet_ids = [value.strip() for value in (packet_ids or "").split(",") if value.strip()]
    action = NetworkForensicsAction(
        action_type=action_type,
        packet_id=packet_id if packet_id else None,
        packet_ids=parsed_packet_ids or None,
        session_name=session_name if session_name else None,
        pattern_type=pattern_type if pattern_type else None,
        claimed_entry_point=claimed_entry_point if claimed_entry_point else None,
    )
    current_obs = env.step(action)

    if current_obs.done:
        result = f"Episode complete! Final score: {current_obs.current_score_estimate:.2f}"
    else:
        result = f"Step {current_obs.step_number}: reward = {current_obs.reward:.2f}"

    return format_obs(current_obs)[0], result


with gr.Blocks(title="Network Forensics") as demo:
    gr.Markdown("# Network Packet Forensics RL Environment")
    gr.Markdown("Analyze network packet captures to identify attack patterns")

    with gr.Row():
        with gr.Column():
            task_select = gr.Radio(["easy", "medium", "hard"], label="Task", value="easy")
            run_btn = gr.Button("Run Episode", variant="primary")

        with gr.Column():
            output_text = gr.Markdown("Click Run Episode to start")

    gr.Markdown("### Packet Stream")

    packet_display = gr.Dataframe(
        headers=["ID", "Src IP", "Dst IP", "Port", "Protocol", "TTL", "Size"],
        datatype=["str", "str", "str", "number", "str", "number", "number"],
        interactive=False,
    )

    gr.Markdown("### Actions")

    with gr.Row():
        action_type = gr.Dropdown(
            ["inspect_packet", "flag_as_suspicious", "group_into_session", "tag_pattern", "identify_entry_point", "submit_report"],
            label="Action",
            value="inspect_packet",
        )
        packet_id = gr.Textbox(label="Packet ID", placeholder="pkt_0001")
        packet_ids = gr.Textbox(label="Packet IDs", placeholder="pkt_0001,pkt_0002")
        session_name = gr.Textbox(label="Session Name", placeholder="session_1")
        pattern_type = gr.Textbox(label="Pattern", placeholder="ddos / web_xss / heartbleed")
        claimed_entry_point = gr.Textbox(label="Claimed Entry Point", placeholder="pkt_0001")

    step_btn = gr.Button("Execute Action")

    result_display = gr.Markdown("")

    run_btn.click(reset_env, task_select, [output_text, packet_display])
    step_btn.click(
        step,
        [action_type, packet_id, packet_ids, session_name, pattern_type, claimed_entry_point],
        [output_text, result_display],
    )

demo.launch(server_port=7860, server_name="0.0.0.0")


if __name__ == "__main__":
    demo.launch(server_port=7860, server_name="0.0.0.0")
