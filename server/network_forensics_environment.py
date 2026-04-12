import sys
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parent.parent))

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from models import (
    NetworkForensicsAction,
    NetworkForensicsObservation,
    PacketRecord,
    Reward,
    TaskConfig,
    GroundTruth,
)
from src.pcap_generator import PCAPGenerator
from src.tasks.easy import EasyTask
from src.reward import compute_reward
from src.graph import ConnectionGraph


class NetworkForensicsEnvironment(Environment):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, task_id: str = "easy"):
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task_id = task_id
        self._packets: list[PacketRecord] = []
        self._ground_truth: Optional[GroundTruth] = None
        self._flagged_packets: set = set()
        self._grouped_sessions: Dict[str, list] = {}
        self._tagged_patterns: Dict[str, str] = {}
        self._claimed_entry_point: Optional[str] = None
        self._reward_state: Dict[str, Any] = {}
        self._current_score: float = 0.0
        self._reward_history: list[float] = []
        self._max_steps: int = 50
        self._connection_graph: ConnectionGraph = ConnectionGraph()

    def config(self) -> Dict[str, Any]:
        return {"task_id": self._task_id, "max_steps": self._max_steps}

    def _build_graph(self) -> None:
        """Build the connection graph from all packets."""
        self._connection_graph = ConnectionGraph()
        for packet in self._packets:
            self._connection_graph.add_packet(packet)

    def _get_graph_summary(self) -> Dict[str, Any]:
        """Return a compact graph summary for the observation."""
        full_summary = self._connection_graph.get_summary()
        # Include top-level stats and top-N nodes/edges to keep payload manageable
        top_nodes = sorted(
            full_summary.get("nodes", []),
            key=lambda n: n.get("packet_count", 0),
            reverse=True,
        )[:15]
        top_edges = sorted(
            full_summary.get("edges", []),
            key=lambda e: e.get("packet_count", 0),
            reverse=True,
        )[:20]
        return {
            "node_count": full_summary.get("node_count", 0),
            "edge_count": full_summary.get("edge_count", 0),
            "top_talkers": top_nodes,
            "top_flows": top_edges,
        }

    def reset(
        self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs: Any
    ) -> NetworkForensicsObservation:
        requested_task = kwargs.get("task_id")
        if requested_task in {"easy", "medium", "hard"}:
            self._task_id = requested_task

        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
        )

        if self._task_id == "medium":
            from src.tasks.medium import MediumTask
            task = MediumTask()
        elif self._task_id == "hard":
            from src.tasks.hard import HardTask
            task = HardTask()
        else:
            task = EasyTask()
        config = task.get_config()
        if hasattr(task, 'get_annotation'):
            self._annotation = task.get_annotation()
            generator = PCAPGenerator(config, self._annotation)
        else:
            self._annotation = {}
            generator = PCAPGenerator(config)
        self._packets, self._ground_truth = generator.generate(seed=seed or config.seed)
        self._flagged_packets = set()
        self._grouped_sessions = {}
        self._tagged_patterns = {}
        self._claimed_entry_point = None
        self._reward_state = {}
        self._current_score = 0.0
        self._reward_history = []
        self._max_steps = config.max_steps

        # Build the connection graph from all packets
        self._build_graph()

        visible = [
            PacketRecord(
                packet_id=p.packet_id,
                timestamp=p.timestamp,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol=p.protocol,
                payload_size=p.payload_size,
                ttl=p.ttl,
                flags=p.flags,
                is_revealed=False,
                payload_preview=p.payload_preview,
                full_payload=p.full_payload if p.is_revealed else None,
            )
            for p in self._packets
        ]

        return NetworkForensicsObservation(
            step_number=0,
            steps_remaining=self._max_steps,
            total_packets=len(self._packets),
            visible_packets=visible,
            flagged_packet_ids=[],
            grouped_sessions={},
            tagged_patterns={},
            claimed_entry_point=None,
            connection_graph_summary=self._get_graph_summary(),
            current_score_estimate=0.0,
            final_metrics={},
            done=False,
            reward=0.0,
        )

    def step(
        self, action: NetworkForensicsAction, timeout_s: Optional[float] = None, **kwargs: Any
    ) -> NetworkForensicsObservation:
        self._state.step_count += 1

        action_result = compute_reward(
            action=action,
            packets=self._packets,
            ground_truth=self._ground_truth,
            flagged_packets=self._flagged_packets,
            grouped_sessions=self._grouped_sessions,
            tagged_patterns=self._tagged_patterns,
            reward_state=self._reward_state,
            task_id=self._task_id,
        )

        if action.action_type == "flag_as_suspicious" and action.packet_id:
            self._flagged_packets.add(action.packet_id)
            # Mark the node as flagged in the connection graph
            packet_map = {p.packet_id: p for p in self._packets}
            pkt = packet_map.get(action.packet_id)
            if pkt:
                for ip in (pkt.src_ip, pkt.dst_ip):
                    if ip in self._connection_graph._node_attributes:
                        self._connection_graph._node_attributes[ip]["flagged"] = True
        elif action.action_type == "group_into_session":
            if action.session_name and action.packet_ids:
                self._grouped_sessions[action.session_name] = action.packet_ids
        elif action.action_type == "tag_pattern":
            if action.session_name and action.pattern_type:
                self._tagged_patterns[action.session_name] = action.pattern_type
        elif action.action_type == "identify_entry_point":
            self._claimed_entry_point = action.claimed_entry_point

        self._reward_history.append(action_result.step_reward)
        self._current_score = sum(self._reward_history) / len(self._reward_history)

        visible = [
            PacketRecord(
                packet_id=p.packet_id,
                timestamp=p.timestamp,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol=p.protocol,
                payload_size=p.payload_size,
                ttl=p.ttl,
                flags=p.flags,
                is_revealed=p.is_revealed,
                payload_preview=p.payload_preview,
                full_payload=p.full_payload if p.is_revealed else None,
            )
            for p in self._packets
        ]

        done = (
            action.action_type == "submit_report"
            or self._state.step_count >= self._max_steps
        )

        return NetworkForensicsObservation(
            step_number=self._state.step_count,
            steps_remaining=max(0, self._max_steps - self._state.step_count),
            total_packets=len(self._packets),
            visible_packets=visible,
            flagged_packet_ids=list(self._flagged_packets),
            grouped_sessions=self._grouped_sessions,
            tagged_patterns=self._tagged_patterns,
            claimed_entry_point=self._claimed_entry_point,
            connection_graph_summary=self._get_graph_summary(),
            current_score_estimate=self._current_score,
            final_metrics=action_result.breakdown,
            done=done,
            reward=action_result.step_reward,
            metadata=action_result.breakdown,
        )

    @property
    def state(self) -> State:
        return self._state
