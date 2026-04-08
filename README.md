---
title: Network Forensics Environment
emoji: "🛰️"
colorFrom: red
colorTo: blue
sdk: docker
sdk_version: "1.0.0"
pinned: false
app_port: 8000
base_path: /
tags:
  - openenv
  - rl-environment
  - network-security
---

# Network Forensics Environment

`network_forensics` is an OpenEnv benchmark for packet triage and intrusion investigation. It simulates a real analyst workflow: inspect traffic, flag suspicious packets, group related activity into sessions, classify attack patterns, identify the likely entry point, and submit a final report.

The environment is backed by generated PCAP traces and deterministic JSON answer keys, so agents can be evaluated consistently while still solving a real-world security analysis task.

## Motivation

Security analysts routinely ask:

- Which packets are suspicious?
- Which packets belong to the same malicious session?
- What kind of attack is this?
- Which packet looks like the initial compromise or entry point?

This environment turns that workflow into a reproducible benchmark for LLM and RL-style agents.

## Tasks

The benchmark includes three deterministic tasks with increasing difficulty.

### Easy

- Files: `pcaps/easy_task.pcap`, `pcaps/easy_task.json`
- Theme: DDoS-heavy traffic mixed with benign flows
- Goal: recover the main malicious traffic and dominant attack sessions

### Medium

- Files: `pcaps/medium_task.pcap`, `pcaps/medium_task.json`
- Theme: mixed web attacks
- Attack families: `web_bruteforce`, `web_xss`, `web_sql_injection`
- Goal: separate multiple web attack sessions and tag them correctly

### Hard

- Files: `pcaps/hard_task.pcap`, `pcaps/hard_task.json`
- Theme: noisy denial-of-service and exploitation traffic
- Attack families: `dos_hulk`, `dos_goldeneye`, `dos_slowloris`, `dos_slowhttptest`, `heartbleed`
- Goal: recover multiple malicious sessions, avoid false positives, and identify the root cause accurately

## Action Space

The environment uses the `NetworkForensicsAction` Pydantic model:

```python
class NetworkForensicsAction(Action):
    action_type: str
    packet_id: Optional[str] = None
    packet_ids: Optional[List[str]] = None
    session_name: Optional[str] = None
    pattern_type: Optional[str] = None
    claimed_entry_point: Optional[str] = None
```

Supported actions:

- `inspect_packet`: reveal the payload of `packet_id`
- `flag_as_suspicious`: mark `packet_id` as suspicious
- `group_into_session`: group `packet_ids` under `session_name`
- `tag_pattern`: assign an attack label to a session
- `identify_entry_point`: claim the likely first malicious packet
- `submit_report`: end the episode and trigger deterministic final grading

## Observation Space

The environment returns `NetworkForensicsObservation`:

```python
class NetworkForensicsObservation(Observation):
    step_number: int
    steps_remaining: int
    total_packets: int
    visible_packets: List[PacketRecord]
    flagged_packet_ids: List[str]
    grouped_sessions: Dict[str, List[str]]
    tagged_patterns: Dict[str, str]
    claimed_entry_point: Optional[str]
    connection_graph_summary: Dict[str, Any]
    current_score_estimate: float
```

Each `PacketRecord` includes fields such as:

- `packet_id`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `ttl`
- `payload_size`
- `payload_preview`
- `full_payload` once revealed

## Reward and Grading

The environment uses two complementary signals.

### Shaped Step Reward

Dense reward is provided across the trajectory instead of only at the end.

Higher reward is given for:

- first-time malicious packet inspection
- correct suspicious flags
- high-overlap session grouping
- correct pattern tagging
- correct entry-point identification

Lower reward is given for undesirable behavior such as:

- repeated inspection
- duplicate flags
- poor grouping recall
- low-quality or incorrect actions

Both step reward and running score are normalized into `[0.0, 1.0]`.

### Deterministic Final Grader

The final `submit_report` action runs a deterministic audit against the task JSON answer key.

The final score is:

```text
0.3 * precision + 0.4 * recall + 0.3 * logic
```

Where:

- `precision`: how cleanly the agent flagged malicious packets
- `recall`: how much malicious traffic the agent actually recovered
- `logic`: whether the agent linked sessions, tags, and entry point correctly for the task difficulty

Difficulty-specific success rules are enforced:

- `easy`: strong malicious-packet recall
- `medium`: strong recall plus meaningful session overlap and acceptable precision
- `hard`: all of the above plus correct root-cause identification

Ground truth comes from the JSON files in `pcaps/`, including:

- `malicious_packets`
- `packet_roles`
- `sessions`
- `session_roles`
- `entry_point`

Core implementation lives in:

- `src/reward.py`
- `src/pcap_generator.py`
- `server/network_forensics_environment.py`

## Baseline Inference

The baseline runner is `inference.py`.

It:

- uses the OpenAI-compatible client for model calls
- supports `server` and `docker` execution modes
- prints `[START]`, `[STEP]`, and `[END]` logs
- runs `easy`, `medium`, and `hard` sequentially

Important environment variables:

- `API_BASE_URL`
- `MODEL_NAME`
- `OPENAI_API_KEY`, `API_KEY`, or `HF_TOKEN`
- `NETWORK_FORENSICS_ENV_MODE`
- `ENV_BASE_URL`
- `LOCAL_IMAGE_NAME`

### Example Baseline Results

Observed recent runs:

- `openai/gpt-oss-120b`
  - `easy`: success `true`, score `0.64`
  - `medium`: success `false`, score `0.55`
  - `hard`: success `true`, score `0.63`
- `mistralai/mistral-small-4-119b-2603`
  - `easy`: success `false`, score `0.46`
  - `medium`: success `false`, score `0.57`
  - `hard`: success `true`, score `0.60`

These examples show that the environment and final grader are sensitive to model behavior rather than returning a constant score.

## Setup and Local Usage

Install dependencies:

```bash
uv sync
```

Start the server:

```bash
uv run server
```

Or with uvicorn directly:

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Useful endpoints:

- `/` for the custom Gradio analyst UI
- `/web` redirects to `/`
- `/health`
- `/docs`
- `/reset`
- `/step`
- `/state`
- `/schema`
- `/ws`

Run the baseline against the local server:

```bash
NETWORK_FORENSICS_ENV_MODE=server ENV_BASE_URL=http://localhost:8000 python inference.py
```

On Windows PowerShell:

```powershell
$env:NETWORK_FORENSICS_ENV_MODE="server"
$env:ENV_BASE_URL="http://localhost:8000"
py .\inference.py
```

## Docker

The deployment Dockerfile is:

- `server/Dockerfile`

From the cloned `network_forensics` repository root:

```bash
docker build -t network-forensics-env -f server/Dockerfile .
docker run -p 8000:8000 network-forensics-env
```

This is the canonical OpenEnv and Hugging Face Space deployment path.

## Hugging Face Space Deployment

This project is configured as a Docker-based OpenEnv Space through `openenv.yaml`.

Validate locally:

```bash
openenv validate
```

Push to Hugging Face using the custom UI rather than the default OpenEnv web interface:

```bash
openenv push --no-interface
```

On the deployed Space:

- `/` serves the custom Gradio analyst console
- `/web` redirects to `/`
- the OpenEnv API remains available for agent evaluation

## Connecting From Python

Connect to a running local or remote server:

```python
from network_forensics import NetworkForensicsAction, NetworkForensicsEnv

with NetworkForensicsEnv(base_url="http://localhost:8000") as env:
    result = env.reset(task_id="easy")
    result = env.step(
        NetworkForensicsAction(
            action_type="inspect_packet",
            packet_id="pkt_0008",
        )
    )
```

Connect to a deployed Hugging Face Space:

```python
from network_forensics import NetworkForensicsAction, NetworkForensicsEnv

with NetworkForensicsEnv.from_env("<hf-username>/<hf-repo-name>") as env:
    result = env.reset(task_id="medium")
    result = env.step(
        NetworkForensicsAction(
            action_type="flag_as_suspicious",
            packet_id="pkt_0008",
        )
    )
```

## Dataset Build Pipeline

Task PCAPs and answer keys are generated from labeled flow data using:

- `scripts/build_task_pcaps.py`

That script writes:

- `pcaps/easy_task.pcap`
- `pcaps/easy_task.json`
- `pcaps/medium_task.pcap`
- `pcaps/medium_task.json`
- `pcaps/hard_task.pcap`
- `pcaps/hard_task.json`

## Repository Structure

```text
network_forensics/
├── .dockerignore
├── .gitignore
├── __init__.py
├── client.py
├── inference.py
├── models.py
├── openenv.yaml
├── pcaps/
├── pyproject.toml
├── README.md
├── scripts/
│   └── build_task_pcaps.py
├── server/
│   ├── app.py
│   ├── Dockerfile
│   ├── gradio_ui.py
│   └── network_forensics_environment.py
└── src/
    ├── pcap_generator.py
    ├── reward.py
    └── tasks/
        ├── easy.py
        ├── medium.py
        └── hard.py
```
