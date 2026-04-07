---
title: Network Forensics Environment Server
emoji: "🛰️"
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# Network Forensics Environment

`network_forensics` is an OpenEnv environment for packet-triage and intrusion-investigation workflows. It simulates a real network forensics task that human analysts perform: inspect suspicious traffic, flag malicious packets, group related activity into sessions, classify attack patterns, identify the likely entry point, and submit a final investigation report.

The environment is designed for agent evaluation rather than toy gameplay. Episodes are built from packet traces derived from labeled intrusion-detection data, with deterministic JSON answer keys used for grading and shaped rewards.

## Motivation

Security analysts routinely inspect packet captures and network telemetry to answer questions like:

- Which packets are malicious?
- Which packets belong to the same attack session?
- What type of attack is this?
- Where did the intrusion start?

This environment turns that workflow into a reproducible benchmark for LLM and RL agents.

## What The Environment Does

Each episode exposes up to 100 visible packets at a time. The agent must:

1. inspect packets to reveal payloads
2. flag suspicious packets
3. group malicious packets into sessions
4. tag each session with an attack type
5. identify the likely entry point
6. submit the report or reach episode end

Ground truth lives in task-specific JSON files under `pcaps/`, and rewards are computed by comparing the agent’s actions against those answer keys.

## Tasks

The environment includes three deterministic tasks with increasing difficulty.

### Easy

- Source: DDoS-heavy traffic mixed with benign flows
- Files: `pcaps/easy_task.pcap`, `pcaps/easy_task.json`
- Expected challenge: identify a single dominant attack family with relatively low ambiguity

### Medium

- Source: web attack traffic
- Attack families: `web_bruteforce`, `web_xss`, `web_sql_injection`
- Files: `pcaps/medium_task.pcap`, `pcaps/medium_task.json`
- Expected challenge: distinguish multiple web attack behaviors and group them correctly

### Hard

- Source: high-noise denial-of-service traffic
- Attack families: `dos_hulk`, `dos_goldeneye`, `dos_slowloris`, `dos_slowhttptest`, `heartbleed`
- Files: `pcaps/hard_task.pcap`, `pcaps/hard_task.json`
- Expected challenge: operate in heavy noise, recover multiple malicious sessions, and avoid incorrect tags

## Action Space

The environment uses the `NetworkForensicsAction` model.

```python
class NetworkForensicsAction(Action):
    action_type: str
    packet_id: Optional[str] = None
    packet_ids: Optional[List[str]] = None
    session_name: Optional[str] = None
    pattern_type: Optional[str] = None
    claimed_entry_point: Optional[str] = None
```

Supported `action_type` values:

- `inspect_packet`
  Reveals the payload for `packet_id`
- `flag_as_suspicious`
  Marks `packet_id` as suspicious
- `group_into_session`
  Groups `packet_ids` into a named session
- `tag_pattern`
  Labels a grouped session with a pattern such as `ddos` or `web_xss`
- `identify_entry_point`
  Claims the first malicious packet
- `submit_report`
  Ends the investigation and triggers final scoring

## Observation Space

The environment returns `NetworkForensicsObservation`.

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
- `payload_size`
- `ttl`
- `flags`
- `payload_preview`
- `full_payload` when revealed

## Reward Function

Rewards provide signal across the full trajectory.

- positive reward for first-time malicious inspections
- positive reward for correct suspicious flags
- positive reward for correct session grouping overlap
- positive reward for correct entry-point identification
- moderate final report bonus based on precision, recall, session recovery, and tagging quality
- penalties for repeated inspection, duplicate flagging, false positives, and invalid/low-quality actions

This reward shaping is implemented in `src/reward.py`.

## Grading

Task grading is deterministic and driven by the JSON answer keys in `pcaps/`.

Each answer key includes:

- `malicious_packets`
- `packet_roles`
- `sessions`
- `session_roles`
- `entry_point`

These are used both for shaped rewards during the episode and for final success scoring.

## Baseline Inference

The baseline runner is `inference.py`. It:

- uses the OpenAI client for all model calls
- reads endpoint and auth configuration from environment variables
- prints `[START]`, `[STEP]`, and `[END]` lines in benchmark-friendly format
- runs the `easy`, `medium`, and `hard` tasks sequentially

Observed baseline behavior in the current local setup:

- `easy`: completes successfully
- `medium`: completes successfully
- `hard`: completes successfully

Because the baseline depends on the configured model endpoint, exact scores may vary across providers and model versions.

## Running Locally

### Python Environment

```bash
uv sync
```

### Run The OpenEnv Server

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Available endpoints:

- `/health`
- `/docs`
- `/ws`
- `/web` when the web interface is enabled

### Run The Baseline

Set these variables first:

- `API_BASE_URL`
- `MODEL_NAME`
- `API_KEY` or `HF_TOKEN`

Then run:

```bash
python inference.py
```

## Docker

The deployment Dockerfile for OpenEnv and Hugging Face Spaces is:

- `server/Dockerfile`

Build and run from the repository root:

```bash
docker build -t network-forensics-env -f network_forensics/server/Dockerfile network_forensics
docker run -p 8000:8000 network-forensics-env
```

The current container path has been verified to:

- build successfully
- start successfully
- return `200 OK` from `/health`

## Hugging Face Space Deployment

This project is configured as a Docker-based OpenEnv Space via `openenv.yaml`.

Push with:

```bash
openenv validate
openenv push
```

The Space is expected to expose:

- `/health`
- `/docs`
- `/ws`
- `/web`

## Connecting From Python

Connect directly to a running server:

```python
from network_forensics import NetworkForensicsAction, NetworkForensicsEnv

with NetworkForensicsEnv(base_url="http://localhost:8000") as env:
    result = env.reset()
    result = env.step(
        NetworkForensicsAction(
            action_type="inspect_packet",
            packet_id="pkt_0008",
        )
    )
```

Or connect to a deployed environment:

```python
from network_forensics import NetworkForensicsAction, NetworkForensicsEnv

with NetworkForensicsEnv.from_env("<hf-username>/<hf-repo-name>") as env:
    result = env.reset()
    result = env.step(
        NetworkForensicsAction(
            action_type="flag_as_suspicious",
            packet_id="pkt_0008",
        )
    )
```

## Dataset Build Pipeline

Task PCAPs and answer keys are generated from labeled flow CSVs using:

- `scripts/build_task_pcaps.py`

This script writes:

- `pcaps/easy_task.pcap` and `pcaps/easy_task.json`
- `pcaps/medium_task.pcap` and `pcaps/medium_task.json`
- `pcaps/hard_task.pcap` and `pcaps/hard_task.json`

## Project Structure

```text
network_forensics/
├── .dockerignore
├── __init__.py
├── app.py
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
│   └── network_forensics_environment.py
└── src/
    ├── pcap_generator.py
    ├── reward.py
    └── tasks/
        ├── easy.py
        ├── medium.py
        └── hard.py
```
