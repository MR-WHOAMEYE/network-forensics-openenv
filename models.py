from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator
from openenv.core.env_server.types import Action, Observation


class PacketRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    packet_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    ttl: int
    flags: List[str] = Field(default_factory=list)
    is_revealed: bool = False
    payload_preview: str = ""
    full_payload: Optional[str] = None
    is_malicious: bool = False
    attack_role: Optional[str] = None


class NetworkForensicsAction(Action):
    model_config = ConfigDict(extra="allow")

    action_type: str = Field(description="Type of action to perform")
    packet_id: Optional[str] = Field(default=None, description="Packet ID for packet-specific actions")
    packet_ids: Optional[List[str]] = Field(default=None, description="List of packet IDs for grouping")
    session_name: Optional[str] = Field(default=None, description="Name for the session group")
    pattern_type: Optional[str] = Field(default=None, description="Pattern type: c2, exfil, scan, lateral")
    claimed_entry_point: Optional[str] = Field(default=None, description="Packet ID claimed as entry point")
    incident_summary: Optional[str] = Field(default=None, description="Free-text incident report for LLM-as-a-Judge evaluation on submit_report")

    @field_validator("packet_ids", mode="before")
    @classmethod
    def coerce_packet_ids(cls, value: Any) -> Any:
        if value is None or value == "":
            return None
        if isinstance(value, str):
            parts = [part.strip() for part in value.split(",") if part.strip()]
            return parts or None
        return value


class NetworkForensicsObservation(Observation):
    model_config = ConfigDict(extra="allow")

    step_number: int = Field(default=0, description="Current step number")
    steps_remaining: int = Field(default=0, description="Steps remaining in episode")
    total_packets: int = Field(default=0, description="Total packets in stream")
    visible_packets: List[PacketRecord] = Field(default_factory=list, description="Packets with previews")
    flagged_packet_ids: List[str] = Field(default_factory=list, description="IDs of flagged packets")
    grouped_sessions: Dict[str, List[str]] = Field(default_factory=dict, description="Session name to packet IDs")
    tagged_patterns: Dict[str, str] = Field(default_factory=dict, description="Session/pattern to attack role")
    claimed_entry_point: Optional[str] = Field(default=None, description="Agent's identified entry point")
    connection_graph_summary: Dict[str, Any] = Field(default_factory=dict, description="Graph topology summary")
    current_score_estimate: float = Field(default=0.0, description="Running score estimate")
    final_metrics: Dict[str, Any] = Field(default_factory=dict, description="Final/report scoring metrics")
    reward: float = Field(default=0.0, description="Step reward")
    done: bool = Field(default=False, description="Whether the episode is finished")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Step metadata (final scores, breakdown)")


class Reward(BaseModel):
    model_config = ConfigDict(extra="allow")

    step_reward: float = 0.0
    cumulative_reward: float = 0.0
    done: bool = False
    success: bool = False
    breakdown: Dict[str, float] = Field(default_factory=dict)
    message: str = ""


class TaskConfig(BaseModel):
    task_id: str
    difficulty: str
    max_steps: int
    total_packets: int
    attack_templates: List[str] = Field(default_factory=list)
    noise_ratio: float
    seed: int
    pcap_file: str = ""


class GroundTruth(BaseModel):
    malicious_packets: List[str] = Field(default_factory=list)
    packet_roles: Dict[str, str] = Field(default_factory=dict)
    sessions: Dict[str, List[str]] = Field(default_factory=dict)
    session_roles: Dict[str, str] = Field(default_factory=dict)
    entry_point: Optional[str] = None
    c2_sessions: Dict[str, List[str]] = Field(default_factory=dict)
    scan_packets: List[str] = Field(default_factory=list)
    exfil_packets: List[str] = Field(default_factory=list)
    lateral_packets: List[str] = Field(default_factory=list)
