from models import TaskConfig, GroundTruth


class HardTask:
    def get_config(self) -> TaskConfig:
        return TaskConfig(
            task_id="hard",
            difficulty="hard",
            max_steps=100,
            total_packets=520,
            attack_templates=["dos_hulk", "dos_goldeneye", "dos_slowloris", "dos_slowhttptest", "heartbleed"],
            noise_ratio=0.8,
            seed=456,
            pcap_file="hard_task",
        )

    def get_annotation(self) -> dict:
        return {
            "pcap_file": "hard_task.pcap",
        }

    def get_ground_truth(self) -> GroundTruth:
        return GroundTruth(
            malicious_packets=[],
            attack_roles={},
            entry_point=None,
        )

    def describe(self) -> str:
        return "High-noise denial-of-service dataset with multiple attack families and a rare Heartbleed trace"
