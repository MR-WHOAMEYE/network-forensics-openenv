"""
MCP-enabled Network Forensics Environment.

This module provides a NetworkForensicsMCPEnv that extends MCPEnvironment,
wrapping the existing NetworkForensicsEnvironment and exposing all forensics
actions as MCP tools. This enables any MCP-compatible AI agent (Claude Desktop,
Cursor, LangChain, etc.) to connect and investigate network traffic via the
standard Model Context Protocol.

Both simulation mode (/reset, /step, /ws) and MCP mode (/mcp) coexist on the
same server. The MCP tools delegate to the inner simulation environment, so
reward computation, state tracking, and scoring all work identically.

Architecture:
    MCPToolClient  ────▶  /mcp (HTTP POST / WebSocket)
                                │
                    NetworkForensicsMCPEnv (MCPEnvironment)
                        │ tools/call ──▶ FastMCP ──▶ tool closures
                        │ step()    ──▶ _step_impl() ──▶ inner.step()
                        │ reset()   ──▶ inner.reset()
                                │
                    NetworkForensicsEnvironment (inner)
                        │ reward computation, graph, state
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastmcp import FastMCP

from openenv.core.env_server.mcp_environment import MCPEnvironment
from openenv.core.env_server.types import State

from models import (
    NetworkForensicsAction,
    NetworkForensicsObservation,
)
from server.network_forensics_environment import NetworkForensicsEnvironment


class NetworkForensicsMCPEnv(MCPEnvironment):
    """
    MCP-enabled wrapper around NetworkForensicsEnvironment.

    Registers all 6 forensics actions as MCP tools, plus utility tools
    for environment reset and status inspection. The underlying simulation
    environment handles all reward computation, graph updates, and state
    management.

    MCP Tools:
        - reset_env: Start a new investigation episode
        - get_status: Get current investigation status and score
        - inspect_packet: Reveal a packet's full payload for analysis
        - flag_as_suspicious: Flag a packet as malicious traffic
        - group_into_session: Group related packets into a named session
        - tag_pattern: Tag a session with an attack family classification
        - identify_entry_point: Identify the initial compromise packet
        - submit_report: Submit final incident report for scoring
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, task_id: str = "easy"):
        mcp = FastMCP("network-forensics")

        # Create the inner simulation environment
        self._inner = NetworkForensicsEnvironment(task_id=task_id)

        # Track whether we've been reset (tools need packets loaded)
        self._is_reset = False

        # -----------------------------------------------------------------
        # MCP Tool Registration
        # -----------------------------------------------------------------
        # Each tool is a closure capturing `self`, so it has access to the
        # inner environment. Tools create a NetworkForensicsAction, call
        # inner.step(), and return a focused result dict.
        # -----------------------------------------------------------------

        @mcp.tool()
        def reset_env(task_id: str = "easy") -> dict:
            """Start a new investigation episode.

            Generates fresh network traffic with embedded attack patterns.
            Call this before using any other tools.

            Args:
                task_id: Difficulty level — "easy" (DDoS), "medium" (web attacks),
                         or "hard" (multi-vector APT with Heartbleed).

            Returns:
                Summary of the new episode: total packets, max steps, task info.
            """
            obs = self._inner.reset(task_id=task_id)
            self._is_reset = True
            packets = obs.visible_packets
            return {
                "task_id": task_id,
                "total_packets": obs.total_packets,
                "max_steps": obs.steps_remaining,
                "sample_packets": [
                    {
                        "id": p.packet_id,
                        "src": f"{p.src_ip}:{p.src_port}",
                        "dst": f"{p.dst_ip}:{p.dst_port}",
                        "protocol": p.protocol,
                        "size": p.payload_size,
                        "flags": p.flags,
                        "preview": p.payload_preview[:80] if p.payload_preview else "",
                    }
                    for p in packets[:20]
                ],
                "connection_graph": obs.connection_graph_summary,
                "message": f"Episode started. {obs.total_packets} packets to investigate. "
                           f"You have {obs.steps_remaining} steps.",
            }

        @mcp.tool()
        def get_status() -> dict:
            """Get current investigation status.

            Returns the agent's progress: step count, score estimate,
            flagged packets, grouped sessions, tagged patterns, and
            connection graph summary.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            state = self._inner.state
            return {
                "step_count": state.step_count,
                "max_steps": self._inner._max_steps,
                "steps_remaining": max(0, self._inner._max_steps - state.step_count),
                "current_score": self._inner._current_score,
                "flagged_packet_count": len(self._inner._flagged_packets),
                "flagged_packet_ids": list(self._inner._flagged_packets),
                "grouped_sessions": {
                    name: ids for name, ids in self._inner._grouped_sessions.items()
                },
                "tagged_patterns": dict(self._inner._tagged_patterns),
                "claimed_entry_point": self._inner._claimed_entry_point,
                "connection_graph": self._inner._get_graph_summary(),
            }

        @mcp.tool()
        def inspect_packet(packet_id: str) -> dict:
            """Reveal the full payload of a packet for deep analysis.

            This costs one step. Use it selectively on suspicious packets
            to uncover attack signatures, C2 beacons, or exfiltration markers.

            Args:
                packet_id: The packet ID to inspect (e.g., "pkt_0008").

            Returns:
                The packet's full details including revealed payload, plus
                the reward earned for this action.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="inspect_packet", packet_id=packet_id
            )
            obs = self._inner.step(action)
            # Find the inspected packet in the observation
            pkt_data = None
            for p in obs.visible_packets:
                if p.packet_id == packet_id:
                    pkt_data = p.model_dump()
                    break
            return {
                "packet": pkt_data,
                "reward": obs.reward,
                "step": obs.step_number,
                "steps_remaining": obs.steps_remaining,
            }

        @mcp.tool()
        def flag_as_suspicious(packet_id: str) -> dict:
            """Flag a packet as malicious traffic.

            Marks a packet as part of an attack. Correct flags increase
            precision/recall metrics. Flagging benign traffic hurts precision.

            Args:
                packet_id: The packet ID to flag (e.g., "pkt_0008").

            Returns:
                Confirmation of the flag, reward, and total flagged count.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="flag_as_suspicious", packet_id=packet_id
            )
            obs = self._inner.step(action)
            return {
                "flagged": packet_id,
                "reward": obs.reward,
                "total_flagged": len(obs.flagged_packet_ids),
                "step": obs.step_number,
                "steps_remaining": obs.steps_remaining,
            }

        @mcp.tool()
        def group_into_session(session_name: str, packet_ids: list[str]) -> dict:
            """Group related packets into a named attack session.

            Clustering packets by attack campaign demonstrates analytical
            reasoning. Sessions should reflect actual attack flows (e.g.,
            "ddos_from_203.0.113.52", "xss_session_1").

            Args:
                session_name: A descriptive name for the session.
                packet_ids: List of packet IDs belonging to this session.

            Returns:
                Confirmation of the grouping, reward, and session summary.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="group_into_session",
                session_name=session_name,
                packet_ids=packet_ids,
            )
            obs = self._inner.step(action)
            return {
                "session": session_name,
                "packet_count": len(packet_ids),
                "reward": obs.reward,
                "total_sessions": len(obs.grouped_sessions),
                "step": obs.step_number,
                "steps_remaining": obs.steps_remaining,
            }

        @mcp.tool()
        def tag_pattern(session_name: str, pattern_type: str) -> dict:
            """Tag a session with an attack family classification.

            After grouping packets into sessions, classify each session's
            attack type. Common patterns: "dos_hulk", "dos_slowloris",
            "dos_goldeneye", "heartbleed", "sql_injection", "xss",
            "brute_force", "c2", "exfiltration", "scan", "lateral".

            Args:
                session_name: Name of a previously created session.
                pattern_type: The attack family classification.

            Returns:
                Confirmation of the tag, reward, and all tagged patterns.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="tag_pattern",
                session_name=session_name,
                pattern_type=pattern_type,
            )
            obs = self._inner.step(action)
            return {
                "session": session_name,
                "pattern": pattern_type,
                "reward": obs.reward,
                "all_tags": obs.tagged_patterns,
                "step": obs.step_number,
                "steps_remaining": obs.steps_remaining,
            }

        @mcp.tool()
        def identify_entry_point(claimed_entry_point: str) -> dict:
            """Identify the initial compromise packet.

            Pinpoints the first packet that initiated the attack chain.
            This tests root-cause analysis skills.

            Args:
                claimed_entry_point: Packet ID of the suspected entry point.

            Returns:
                Confirmation, reward, and current score estimate.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="identify_entry_point",
                claimed_entry_point=claimed_entry_point,
            )
            obs = self._inner.step(action)
            return {
                "entry_point": claimed_entry_point,
                "reward": obs.reward,
                "current_score": obs.current_score_estimate,
                "step": obs.step_number,
                "steps_remaining": obs.steps_remaining,
            }

        @mcp.tool()
        def submit_report(
            incident_summary: str,
            claimed_entry_point: Optional[str] = None,
        ) -> dict:
            """Submit the final incident report for scoring.

            This ends the episode. The summary is evaluated by LLM-as-a-Judge
            on accuracy, logic, completeness, and analytical insight.

            Write a comprehensive report covering:
            - Attack types identified and their indicators
            - Session groupings and their patterns
            - The root cause / entry point
            - Affected hosts and attacker IPs
            - Recommended mitigation steps

            Args:
                incident_summary: Free-text incident report.
                claimed_entry_point: Optional packet ID for the suspected entry point.

            Returns:
                Final scoring breakdown including precision, recall,
                logic score, and LLM judge score.
            """
            if not self._is_reset:
                return {"error": "Environment not initialized. Call reset_env() first."}
            action = NetworkForensicsAction(
                action_type="submit_report",
                incident_summary=incident_summary,
                claimed_entry_point=claimed_entry_point,
            )
            obs = self._inner.step(action)
            metrics = obs.final_metrics or obs.metadata
            return {
                "done": obs.done,
                "reward": obs.reward,
                "final_score": metrics.get("final_score", obs.current_score_estimate),
                "success": bool(metrics.get("success_threshold_met", 0.0)),
                "breakdown": metrics,
                "step": obs.step_number,
                "message": "Investigation complete. Report submitted for evaluation.",
            }

        # -----------------------------------------------------------------
        # Initialize MCPEnvironment with the FastMCP server
        # -----------------------------------------------------------------
        super().__init__(mcp)

        # Auto-reset so the environment is immediately usable
        self._inner.reset()
        self._is_reset = True

    # -----------------------------------------------------------------
    # Required abstract method implementations
    # -----------------------------------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> NetworkForensicsObservation:
        """Reset the environment — delegates to the inner simulation env."""
        obs = self._inner.reset(seed=seed, episode_id=episode_id, **kwargs)
        self._is_reset = True
        return obs

    def _step_impl(
        self,
        action: Any,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> NetworkForensicsObservation:
        """Handle non-MCP actions — delegates to the inner simulation env.

        This is called by MCPEnvironment.step() for any action that is not
        a ListToolsAction or CallToolAction (i.e., regular simulation actions
        from /step or /ws endpoints).
        """
        return self._inner.step(action, timeout_s=timeout_s, **kwargs)

    @property
    def state(self) -> State:
        """Return the inner environment's state."""
        return self._inner.state

    def close(self) -> None:
        """Clean up both the MCP server and the inner environment."""
        super().close()
        if hasattr(self, "_inner") and self._inner is not None:
            self._inner.close()
