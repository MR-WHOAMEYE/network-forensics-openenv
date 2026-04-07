
# Network Forensics Environment

`network_forensics` is an OpenEnv benchmark for packet triage and intrusion investigation. It simulates a real analyst workflow: inspect traffic, flag malicious packets, group related activity into sessions, classify attack patterns, identify the likely entry point, and finish with a final report.

This is not a toy environment. Episodes are backed by generated PCAP traces and deterministic JSON answer keys, so agents can be evaluated consistently across runs.

## Why This Environment Exists

Security analysts regularly work through packet captures and network telemetry to answer questions such as:

- Which packets are suspicious?
- Which packets belong to the same attack session?
- What kind of attack is occurring?
- Where did the intrusion begin?

This environment turns that process into a reproducible benchmark for LLM and RL agents.

## Core Workflow

At each episode, the agent receives a visible packet window and must make investigation decisions step by step.

Typical flow:

1. inspect packets to reveal payloads
2. flag suspicious packets
3. group related packets into sessions
4. tag sessions with attack types
5. identify the likely entry point
6. submit a report

Ground truth is stored in per-task JSON files under `pcaps/`, and grading is deterministic.

## Tasks

The benchmark ships with three tasks of increasing difficulty.

### Easy

- Dataset flavor: DDoS-heavy traffic mixed with benign flows
- Files: `pcaps/easy_task.pcap`, `pcaps/easy_task.json`
- Goal: find the dominant attack traffic and recover the main malicious session

### Medium

- Dataset flavor: web attack traffic
- Attack families: `web_bruteforce`, `web_xss`, `web_sql_injection`
- Files: `pcaps/medium_task.pcap`, `pcaps/medium_task.json`
- Goal: distinguish multiple web attack behaviors and group them correctly

### Hard

- Dataset flavor: high-noise denial-of-service traffic
- Attack families: `dos_hulk`, `dos_goldeneye`, `dos_slowloris`, `dos_slowhttptest`, `heartbleed`
- Files: `pcaps/hard_task.pcap`, `pcaps/hard_task.json`
- Goal: recover multiple malicious sessions in noisy traffic and avoid incorrect tagging

## Action Space

The environment uses the `NetworkForensicsAction` model:

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

- `inspect_packet`
  Reveal the payload of `packet_id`.
- `flag_as_suspicious`
  Mark `packet_id` as suspicious.
- `group_into_session`
  Group `packet_ids` into `session_name`.
- `tag_pattern`
  Assign an attack label to a session.
- `identify_entry_point`
  Claim the first malicious packet.
- `submit_report`
  End the episode and trigger final report scoring.

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

Each `PacketRecord` contains fields such as:

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

## Reward and Grading

The reward function is shaped across the trajectory instead of only rewarding the final step.

Positive signal is given for:

- first-time malicious packet inspection
- correct suspicious flags
- good session grouping overlap
- correct entry-point identification
- correct final report outcomes

Penalties are applied for:

- repeated inspection
- duplicate flagging
- false positives
- invalid or low-quality actions

Both step reward and score stay in the `[0.0, 1.0]` range.

Deterministic grading is driven by the JSON answer keys in `pcaps/`, which include:

- `malicious_packets`
- `packet_roles`
- `sessions`
- `session_roles`
- `entry_point`

The main logic lives in:

- `src/reward.py`
- `src/pcap_generator.py`
- `server/network_forensics_environment.py`

## Baseline Inference

The baseline runner is `inference.py`.

It:

- uses the OpenAI client for all model calls
- supports `local`, `server`, and `docker` execution modes
- prints `[START]`, `[STEP]`, and `[END]` lines in benchmark-friendly format
- runs `easy`, `medium`, and `hard` sequentially

Environment variables commonly used by the baseline:

- `API_BASE_URL`
- `MODEL_NAME`
- `API_KEY` or `HF_TOKEN`
- `NETWORK_FORENSICS_ENV_MODE`
- `ENV_BASE_URL`
- `LOCAL_IMAGE_NAME`

### Baseline Status

Current local checks confirm:

- task enumeration works
- reward and score stay in `[0.0, 1.0]`
- `easy`, `medium`, and `hard` all execute end to end

Exact scores depend on the configured model endpoint.

## Running Locally

Install dependencies:

```bash
uv sync
```

Run the OpenEnv server:

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Available endpoints:

- `/health`
- `/docs`
- `/ws`
- `/web`

Run the baseline:

```bash
python inference.py
```

## Docker

The deployment Dockerfile is:

- `server/Dockerfile`

Build and run from the repository root:

```bash
docker build -t network-forensics-env -f network_forensics/server/Dockerfile network_forensics
docker run -p 8000:8000 network-forensics-env
```

This container path has been verified to:

- build successfully
- start successfully
- return `200 OK` from `/health`

## Hugging Face Space Deployment

This project is configured as a Docker-based OpenEnv Space through `openenv.yaml`.

Deploy with:

```bash
openenv validate
openenv push
```

Expected Space endpoints:

- `/health`
- `/docs`
- `/ws`
- `/web`

## Connecting From Python

Connect to a running server:

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

Connect to a deployed environment:

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
│   └── network_forensics_environment.py
└── src/
    ├── pcap_generator.py
    ├── reward.py
    └── tasks/
        ├── easy.py
        ├── medium.py
        └── hard.py
```
