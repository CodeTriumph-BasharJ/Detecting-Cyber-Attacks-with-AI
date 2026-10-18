from datetime import timedelta, datetime
from collections import defaultdict
import json

BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 5

class BruteForceDetector:
    """Detects N+ failed logins from same (user ID, session ID, IP address) within T minutes followed by a successful login."""

    def __init__(self, threshold=BRUTE_FORCE_THRESHOLD, window_minutes=BRUTE_FORCE_WINDOW_MINUTES):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def parse(self, timestamp: str) -> datetime:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    def scan(self, logs: list[dict]) -> list:
        total_atks = list()

        # Group logins by (user_id, session_id, source_ip)
        by_group = defaultdict(list)
        for log in logs:
            if log["action"] == "login":
                key = (log["user_id"], log["session_id"], log["source_ip"])
                by_group[key].append(log)

        for (user_id, session_id, ip), attempts in by_group.items():
            attempts.sort(key=lambda e: self.parse(e["timestamp"]))

            failed_logins = [
                a for a in attempts
                if a["status"] == "failure"
            ]

            # Sliding window
            for i in range(len(failed_logins)):
                window_end_time = self.parse(failed_logins[i]["timestamp"]) + self.window
                in_window = [
                    a for a in failed_logins[i:]
                    if self.parse(a["timestamp"]) <= window_end_time
                ]

                if len(in_window) >= self.threshold:
                    last_failed_login_time = self.parse(in_window[-1]["timestamp"])

                    successful_login = next(
                        (
                            a for a in attempts
                            if (
                                a["status"] == "success"
                                and self.parse(a["timestamp"]) > last_failed_login_time
                            )
                        ),
                        None
                    )
                    
                    if successful_login:
                        event_ids = {
                            e["event_id"] +  ", " + e["status"] : e["timestamp"]
                            for e in in_window
                        }
                        event_ids[successful_login["event_id"] + ", success"] = successful_login["timestamp"]

                        total_atks.append(json.dumps({
                            "attack_type": "BRUTE_FORCE",
                            "iocs": {
                                "event_ids": event_ids,
                                "user_id": user_id,
                                "session_id": session_id,
                                "ip_address": ip,
                                "failed_attempt_count": len(in_window)
                            }
                        }, indent=2) + "\n\nEnd of Attack\n\n")

                        break  # One alert per (user_id, session_id, source_ip) group

        return total_atks
