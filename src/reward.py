from typing import Any, Dict, List, Set
from models import NetworkForensicsAction, PacketRecord, GroundTruth, Reward

STEP_REWARD_MIN = -0.12
STEP_REWARD_MAX = 0.30


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _normalize_step_reward(raw_reward: float) -> float:
    scaled = (raw_reward - STEP_REWARD_MIN) / (STEP_REWARD_MAX - STEP_REWARD_MIN)
    return round(_clamp01(scaled), 4)


def _best_matching_session(
    submitted: Set[str],
    sessions: Dict[str, List[str]],
) -> tuple[str | None, float]:
    best_session = None
    best_overlap = 0.0
    for session_name, session_packets in sessions.items():
        truth = set(session_packets)
        union = submitted | truth
        overlap = (len(submitted & truth) / len(union)) if union else 0.0
        if overlap > best_overlap:
            best_overlap = overlap
            best_session = session_name
    return best_session, best_overlap


def compute_reward(
    action: NetworkForensicsAction,
    packets: List[PacketRecord],
    ground_truth: GroundTruth,
    flagged_packets: Set[str],
    grouped_sessions: Dict[str, List[str]],
    tagged_patterns: Dict[str, str],
    reward_state: Dict[str, Any],
) -> Reward:
    raw_step_reward = -0.005
    breakdown = {"step_cost_raw": -0.005}
    done = action.action_type == "submit_report"
    message = ""

    packet_map = {p.packet_id: p for p in packets}
    malicious_set = set(ground_truth.malicious_packets)
    sessions = ground_truth.sessions or {}
    session_roles = ground_truth.session_roles or {}
    inspected_malicious = reward_state.setdefault("inspected_malicious", set())
    flagged_malicious = reward_state.setdefault("flagged_malicious", set())
    rewarded_sessions = reward_state.setdefault("rewarded_sessions", set())
    rewarded_tags = reward_state.setdefault("rewarded_tags", set())
    reward_state.setdefault("entry_point_rewarded", False)

    if action.action_type == "inspect_packet" and action.packet_id:
        if action.packet_id in packet_map:
            pkt = packet_map[action.packet_id]
            if action.packet_id in malicious_set and not pkt.is_revealed:
                delta = 0.08
                if action.packet_id not in inspected_malicious:
                    delta += 0.04
                    inspected_malicious.add(action.packet_id)
                    breakdown["inspect_progress_raw"] = 0.04
                raw_step_reward += delta
                breakdown["malicious_inspect_raw"] = round(delta, 4)
            elif action.packet_id not in malicious_set and not pkt.is_revealed:
                raw_step_reward -= 0.02
                breakdown["benign_inspect_raw"] = -0.02
            else:
                raw_step_reward -= 0.06
                breakdown["repeat_inspect_raw"] = -0.06
            pkt.is_revealed = True
        else:
            raw_step_reward -= 0.03
            breakdown["invalid_packet_raw"] = -0.03

    elif action.action_type == "flag_as_suspicious" and action.packet_id:
        if action.packet_id in flagged_packets:
            raw_step_reward -= 0.08
            breakdown["already_flagged_raw"] = -0.08
        elif action.packet_id in packet_map:
            if action.packet_id in malicious_set:
                delta = 0.12
                if action.packet_id not in flagged_malicious:
                    delta += 0.05
                    flagged_malicious.add(action.packet_id)
                    breakdown["flag_progress_raw"] = 0.05
                raw_step_reward += delta
                breakdown["correct_flag_raw"] = round(delta, 4)
            else:
                raw_step_reward -= 0.10
                breakdown["false_positive_raw"] = -0.10
        else:
            raw_step_reward -= 0.04
            breakdown["invalid_packet_raw"] = -0.04

    elif action.action_type == "group_into_session" and action.session_name and action.packet_ids:
        submitted = {pid for pid in action.packet_ids if pid in packet_map}
        best_session, best_overlap = _best_matching_session(submitted, sessions)

        if best_session and best_overlap > 0:
            truth = set(sessions[best_session])
            precision = len(submitted & truth) / max(1, len(submitted))
            recall = len(submitted & truth) / max(1, len(truth))
            group_score = (precision + recall) / 2
            delta = round(group_score * 0.18 - 0.04, 4)
            if group_score >= 0.6 and best_session not in rewarded_sessions:
                delta += 0.12
                rewarded_sessions.add(best_session)
                breakdown["session_progress_raw"] = 0.12
            raw_step_reward += delta
            breakdown["group_overlap_raw"] = delta
            message = f"Matched session {best_session} with score {group_score:.2f}"
        else:
            correct = sum(1 for pid in submitted if pid in malicious_set)
            wrong = len(submitted) - correct
            delta = round(correct * 0.03 - wrong * 0.05, 4)
            raw_step_reward += delta
            breakdown["group_fallback_raw"] = delta

    elif action.action_type == "tag_pattern" and action.session_name and action.pattern_type:
        if action.session_name in grouped_sessions:
            pattern = action.pattern_type.strip().lower()
            expected_role = session_roles.get(action.session_name)
            matched_truth_session = action.session_name if expected_role else None
            if not expected_role:
                submitted = set(grouped_sessions[action.session_name])
                matched_truth_session, overlap = _best_matching_session(submitted, sessions)
                if matched_truth_session and overlap >= 0.6:
                    expected_role = session_roles.get(matched_truth_session)
            if expected_role and pattern == expected_role.lower():
                delta = 0.10
                if matched_truth_session and matched_truth_session not in rewarded_tags:
                    delta += 0.06
                    rewarded_tags.add(matched_truth_session)
                    breakdown["tag_progress_raw"] = 0.06
                raw_step_reward += delta
                breakdown["correct_tag_raw"] = round(delta, 4)
            else:
                raw_step_reward -= 0.08
                breakdown["wrong_tag_raw"] = -0.08
        else:
            raw_step_reward -= 0.05
            breakdown["unknown_session_raw"] = -0.05

    elif action.action_type == "identify_entry_point" and action.claimed_entry_point:
        if ground_truth.entry_point and action.claimed_entry_point == ground_truth.entry_point:
            delta = 0.12
            if not reward_state["entry_point_rewarded"]:
                delta += 0.08
                reward_state["entry_point_rewarded"] = True
                breakdown["entry_progress_raw"] = 0.08
            raw_step_reward += delta
            breakdown["correct_entry_point_raw"] = round(delta, 4)
        else:
            raw_step_reward -= 0.10
            breakdown["wrong_entry_point_raw"] = -0.10

    elif action.action_type == "submit_report":
        flagged = set(flagged_packets)
        true_positive = len(flagged & malicious_set)
        precision = true_positive / max(1, len(flagged))
        recall = true_positive / max(1, len(malicious_set))
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        session_hits = 0
        for session_name, truth_packets in sessions.items():
            truth = set(truth_packets)
            for grouped in grouped_sessions.values():
                if truth == set(grouped):
                    session_hits += 1
                    break
        session_score = session_hits / max(1, len(sessions))
        tag_hits = 0
        for submitted_name, submitted_packets in grouped_sessions.items():
            matched_truth_session, overlap = _best_matching_session(set(submitted_packets), sessions)
            if matched_truth_session and overlap >= 0.8:
                expected_role = session_roles.get(matched_truth_session, "").lower()
                if tagged_patterns.get(submitted_name, "").lower() == expected_role:
                    tag_hits += 1
        tag_score = tag_hits / max(1, len(session_roles))
        entry_score = 1.0 if reward_state.get("entry_point_rewarded") else 0.0
        final_score = round(f1 * 0.45 + session_score * 0.25 + tag_score * 0.20 + entry_score * 0.10, 4)
        final_bonus = round(final_score * 0.45, 4)
        raw_step_reward += final_bonus
        breakdown["final_f1"] = round(f1, 4)
        breakdown["final_session_score"] = round(session_score, 4)
        breakdown["final_tag_score"] = round(tag_score, 4)
        breakdown["final_entry_score"] = round(entry_score, 4)
        breakdown["final_score"] = final_score
        breakdown["final_bonus_raw"] = final_bonus
        message = f"Report precision={precision:.2f} recall={recall:.2f} score={final_score:.2f}"

    success = done and breakdown.get("final_score", 0.0) >= 0.6
    step_reward = _normalize_step_reward(raw_step_reward)
    breakdown["raw_step_reward"] = round(raw_step_reward, 4)
    breakdown["normalized_step_reward"] = step_reward

    return Reward(
        step_reward=step_reward,
        cumulative_reward=step_reward,
        done=done,
        success=success,
        breakdown=breakdown,
        message=message or f"Action: {action.action_type}",
    )
