from collections import defaultdict
import json

DATA_EXFILTRATION_THRESHOLD = 10

class DataExfiltrationDetector:
    """Detects N+ successful or failed attempts to download a file from an external IP address."""

    def __init__(self, threshold=DATA_EXFILTRATION_THRESHOLD):
        self.threshold = threshold

    def is_external_ip(self, ip: str) -> bool:
        return not ip.startswith("10.0")

    def scan(self, logs: list[dict]) -> list:
        total_atks = list()

        # Group download attempts by source_ip by (user_id, session_id, source_ip)
        by_group = defaultdict(list)
        for log in logs:
            if log["action"] == "file_download" and self.is_external_ip(log["source_ip"]):
                key = (log["user_id"], log["session_id"], log["source_ip"])
                by_group[key].append(log)

        for (user_id, session_id, external_ip), attempts in by_group.items():
            if len(attempts) >= self.threshold:
                total_atks.append(json.dumps({
                    "attack_type": "DATA_EXFILTRATION",
                    "iocs": {
                        "event_ids": {e["event_id"] + ", " + e["status"]: e["timestamp"] for e in attempts},
                        "user_id": user_id,
                        "session_id": session_id,
                        "ip_address": external_ip,
                        "affected_assets": list(dict.fromkeys([e["resource"] for e in attempts]).keys()),
                        "download_attempt_count": len(attempts)
                    }
                }, indent = 2) + "\n\nEnd of Attack\n\n")

        return total_atks
