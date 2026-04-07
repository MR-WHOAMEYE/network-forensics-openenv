from models import TaskConfig, GroundTruth


class EasyTask:
    def get_config(self) -> TaskConfig:
        return TaskConfig(
            task_id="easy",
            difficulty="easy",
            max_steps=40,
            total_packets=220,
            attack_templates=["ddos"],
            noise_ratio=0.5,
            seed=42,
            pcap_file="easy_task",
        )

    def get_annotation(self) -> dict:
        return {
            "pcap_file": "easy_task.pcap",
        }

    def get_ground_truth(self) -> GroundTruth:
        return GroundTruth(
            malicious_packets=[],
            attack_roles={},
            entry_point=None,
        )

    def describe(self) -> str:
        return "DDoS-heavy traffic with a single malicious campaign hidden among benign flows"
