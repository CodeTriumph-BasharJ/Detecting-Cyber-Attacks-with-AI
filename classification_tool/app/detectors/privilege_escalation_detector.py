from collections import defaultdict
import json
from datetime import datetime

PRIVILEGE_ESCALATION_THRESHOLD = 2


class PrivilegeEscalationDetector:
    """Detects repeated privilege escalation actions within the same session."""

    def __init__(self, threshold=PRIVILEGE_ESCALATION_THRESHOLD):
        self.threshold = threshold

    def parse(self, timestamp: str) -> datetime:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    def scan(self, logs: list[dict]) -> list:
        total_atks = list()

        sudo_logs = [log for log in logs if log.get("action") == "sudo_exec"]
        if not sudo_logs:
            return total_atks

        by_session = defaultdict(list)
        for log in sudo_logs:
            by_session[log["session_id"]].append(log)

        sessions_in_time_order = sorted(
            by_session.items(),
            key=lambda item: self.parse(min(event["timestamp"] for event in item[1])),
        )

        sudo_history_by_user: dict[str, int] = defaultdict(int)

        for session_id, attempts in sessions_in_time_order:
            attempts.sort(key=lambda event: self.parse(event["timestamp"]))
            user_id = attempts[0]["user_id"]

            if sudo_history_by_user[user_id] > 0:
                sudo_history_by_user[user_id] += len(attempts)
                continue

            if len(attempts) >= self.threshold:
                sorted_attempts = attempts
                total_atks.append(json.dumps({
                    "attack_type": "PRIVILEGE_ESCALATION",
                    "iocs": {
                        "event_ids": {f'{event["event_id"]}, {event["status"]}': event["timestamp"] for event in sorted_attempts},
                        "user_id": user_id,
                        "session_id": session_id,
                        "source_ip": sorted_attempts[0]["source_ip"],
                        "privileged_actions": [event["action"] for event in sorted_attempts],
                        "privileged_action_count": len(sorted_attempts),
                        "prior_sudo_history_count": 0,
                    }
                }, indent=2) + "\n\nEnd of Attack\n\n")

            sudo_history_by_user[user_id] += len(attempts)

        return total_atks