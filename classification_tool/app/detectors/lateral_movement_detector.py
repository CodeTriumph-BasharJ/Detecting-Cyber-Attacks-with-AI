from collections import defaultdict
import json

LATERAL_MOVEMENT_THRESHOLD = 5


class LateralMovementDetector:
    """Detects SSH chains across multiple internal hosts in the same session."""

    def __init__(self, threshold=LATERAL_MOVEMENT_THRESHOLD):
        self.threshold = threshold

    def is_internal_host(self, resource: str) -> bool:
        return resource.startswith("10.0.")

    def scan(self, logs: list[dict]) -> list:
        total_atks = list()

        by_session = defaultdict(list)
        for log in logs:
            if log.get("action") == "ssh_connect" and log.get("status") == "success" and self.is_internal_host(log.get("resource", "")):
                by_session[log["session_id"]].append(log)

        for session_id, attempts in by_session.items():
            if len({event["resource"] for event in attempts}) >= self.threshold:
                sorted_attempts = sorted(attempts, key=lambda event: event["timestamp"])
                total_atks.append(json.dumps({
                    "attack_type": "LATERAL_MOVEMENT",
                    "iocs": {
                        "event_ids": {f'{event["event_id"]}, {event["status"]}': event["timestamp"] for event in sorted_attempts},
                        "user_id": sorted_attempts[0]["user_id"],
                        "session_id": session_id,
                        "source_ip": sorted_attempts[0]["source_ip"],
                        "hosts_traversed": [event["resource"] for event in sorted_attempts],
                        "host_count": len({event["resource"] for event in attempts}),
                    }
                }, indent=2) + "\n\nEnd of Attack\n\n")

        return total_atks