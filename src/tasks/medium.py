from models import TaskConfig, GroundTruth


class MediumTask:
    def get_config(self) -> TaskConfig:
        return TaskConfig(
            task_id="medium",
            difficulty="medium",
            max_steps=70,
            total_packets=360,
            attack_templates=["web_bruteforce", "web_xss", "web_sql_injection"],
            noise_ratio=0.65,
            seed=123,
            pcap_file="medium_task",
        )

    def get_annotation(self) -> dict:
        return {
            "pcap_file": "medium_task.pcap",
        }

    def get_ground_truth(self) -> GroundTruth:
        return GroundTruth(
            malicious_packets=[],
            attack_roles={},
            entry_point=None,
        )

    def describe(self) -> str:
        return "Web attack traffic containing brute force, XSS, and SQL injection sessions"
