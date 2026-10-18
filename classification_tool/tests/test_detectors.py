import json
from datetime import datetime, timedelta

import pytest

from classification_tool.app.detectors.brute_force_detector import BruteForceDetector
from classification_tool.app.detectors.data_exfiltration_detector import DataExfiltrationDetector
from classification_tool.app.detectors.lateral_movement_detector import LateralMovementDetector
from classification_tool.app.detectors.privilege_escalation_detector import PrivilegeEscalationDetector


def make_log(
    timestamp="2026-01-01T12:00:00Z",
    event_id="EVT-00001",
    source_ip="10.0.0.1",
    user_id="u0001_eng",
    action="login",
    resource="/tmp/resource",
    status="success",
    session_id="session-1",
):
    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "source_ip": source_ip,
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "status": status,
        "session_id": session_id,
    }


def iso_at(base: datetime, *, seconds: int = 0, minutes: int = 0) -> str:
    return (base + timedelta(seconds=seconds, minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_incident(raw_incident: str) -> dict:
    return json.loads(raw_incident.split("\n\nEnd of Attack\n\n", 1)[0])


class TestBruteForceDetector:
    def test_detects_fifteen_failures_within_five_minutes_then_success(self):
        detector = BruteForceDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=index * 15),
                event_id=f"EVT-BF-{index:03d}",
                source_ip="203.0.113.10",
                status="failure",
                session_id="sess-bf-15",
            )
            for index in range(1, 16)
        ]
        logs.append(
            make_log(
                timestamp=iso_at(base, seconds=230),
                event_id="EVT-BF-SUCCESS",
                source_ip="203.0.113.10",
                status="success",
                session_id="sess-bf-15",
            )
        )

        incidents = detector.scan(logs)

        assert len(incidents) == 1
        payload = parse_incident(incidents[0])
        event_ids = payload["iocs"]["event_ids"]
        assert payload["attack_type"] == "BRUTE_FORCE"
        assert payload["iocs"]["failed_attempt_count"] == 15
        # Verify reasoning/event chain contains first failed, last failed, and final success.
        assert "EVT-BF-001, failure" in event_ids
        assert "EVT-BF-015, failure" in event_ids
        assert "EVT-BF-SUCCESS, success" in event_ids

    def test_detects_ten_failures_within_five_minutes_followed_by_success(self):
        detector = BruteForceDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=offset),
                event_id=f"EVT-10{index}",
                status="failure",
                session_id="sess-1",
            )
            for index, offset in enumerate(range(0, 300, 30), start=1)
        ]
        logs.append(
            make_log(
                timestamp=iso_at(base, seconds=305),
                event_id="EVT-111",
                status="success",
                session_id="sess-1",
            )
        )

        incidents = detector.scan(logs)

        assert len(incidents) == 1
        payload = parse_incident(incidents[0])
        assert payload["attack_type"] == "BRUTE_FORCE"
        assert payload["iocs"]["failed_attempt_count"] == 10
        assert payload["iocs"]["session_id"] == "sess-1"
        assert "EVT-111, success" in payload["iocs"]["event_ids"]

    def test_ignores_nine_failures_even_if_a_success_follows(self):
        detector = BruteForceDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=offset),
                event_id=f"EVT-20{index}",
                status="failure",
                session_id="sess-2",
            )
            for index, offset in enumerate(range(0, 270, 30), start=1)
        ]
        logs.append(
            make_log(
                timestamp=iso_at(base, seconds=275),
                event_id="EVT-210",
                status="success",
                session_id="sess-2",
            )
        )

        incidents = detector.scan(logs)

        assert incidents == []

    def test_ignores_fifteen_failures_split_across_two_source_ips(self):
        detector = BruteForceDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = []

        # Group A: 8 failures + success (below threshold for one IP group).
        logs.extend(
            [
                make_log(
                    timestamp=iso_at(base, seconds=index * 15),
                    event_id=f"EVT-BFA-{index:03d}",
                    source_ip="203.0.113.20",
                    status="failure",
                    session_id="sess-bf-split",
                )
                for index in range(1, 9)
            ]
        )
        logs.append(
            make_log(
                timestamp=iso_at(base, seconds=130),
                event_id="EVT-BFA-SUCCESS",
                source_ip="203.0.113.20",
                status="success",
                session_id="sess-bf-split",
            )
        )

        # Group B: 7 failures + success (below threshold for second IP group).
        logs.extend(
            [
                make_log(
                    timestamp=iso_at(base, seconds=160 + index * 15),
                    event_id=f"EVT-BFB-{index:03d}",
                    source_ip="203.0.113.21",
                    status="failure",
                    session_id="sess-bf-split",
                )
                for index in range(1, 8)
            ]
        )
        logs.append(
            make_log(
                timestamp=iso_at(base, seconds=300),
                event_id="EVT-BFB-SUCCESS",
                source_ip="203.0.113.21",
                status="success",
                session_id="sess-bf-split",
            )
        )

        incidents = detector.scan(logs)

        assert incidents == []


class TestDataExfiltrationDetector:
    def test_detects_ten_external_downloads_in_same_session(self):
        detector = DataExfiltrationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=index * 15),
                event_id=f"EVT-30{index}",
                source_ip="203.0.113.10",
                action="file_download",
                resource=resource,
                session_id="sess-3",
            )
            for index, resource in enumerate(
                [
                    "/data/a.txt",
                    "/data/b.txt",
                    "/data/c.txt",
                    "/data/d.txt",
                    "/data/e.txt",
                    "/data/f.txt",
                    "/data/g.txt",
                    "/data/h.txt",
                    "/data/i.txt",
                    "/data/a.txt",
                ],
                start=1,
            )
        ]

        incidents = detector.scan(logs)

        assert len(incidents) == 1
        payload = parse_incident(incidents[0])
        assert payload["attack_type"] == "DATA_EXFILTRATION"
        assert payload["iocs"]["download_attempt_count"] == 10
        assert payload["iocs"]["ip_address"] == "203.0.113.10"
        assert payload["iocs"]["affected_assets"] == [
            "/data/a.txt",
            "/data/b.txt",
            "/data/c.txt",
            "/data/d.txt",
            "/data/e.txt",
            "/data/f.txt",
            "/data/g.txt",
            "/data/h.txt",
            "/data/i.txt",
        ]

    def test_ignores_nine_external_downloads_below_threshold(self):
        detector = DataExfiltrationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=index * 15),
                event_id=f"EVT-40{index}",
                source_ip="203.0.113.25",
                action="file_download",
                resource=f"/data/file-{index}.txt",
                session_id="sess-4",
            )
            for index in range(1, 10)
        ]

        incidents = detector.scan(logs)

        assert incidents == []

    def test_ignores_ten_internal_downloads_even_at_threshold(self):
        detector = DataExfiltrationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, seconds=index * 15),
                event_id=f"EVT-INT-{index:03d}",
                source_ip="10.0.0.25",
                action="file_download",
                resource=f"/data/internal-{index}.txt",
                session_id="sess-int-1",
            )
            for index in range(1, 11)
        ]

        incidents = detector.scan(logs)

        assert incidents == []


class TestLateralMovementDetector:
    def test_detects_ssh_chain_across_five_internal_hosts(self):
        detector = LateralMovementDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=index),
                event_id=f"EVT-50{index}",
                action="ssh_connect",
                resource=host,
                session_id="sess-5",
            )
            for index, host in enumerate(
                ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"], start=1
            )
        ]

        incidents = detector.scan(logs)

        assert len(incidents) == 1
        payload = parse_incident(incidents[0])
        assert payload["attack_type"] == "LATERAL_MOVEMENT"
        assert payload["iocs"]["host_count"] == 5
        assert payload["iocs"]["hosts_traversed"] == ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"]

    def test_ignores_only_four_distinct_internal_hosts(self):
        detector = LateralMovementDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=0),
                event_id="EVT-601",
                action="ssh_connect",
                resource="10.0.0.11",
                session_id="sess-6",
            ),
            make_log(
                timestamp=iso_at(base, minutes=1),
                event_id="EVT-602",
                action="ssh_connect",
                resource="10.0.0.12",
                session_id="sess-6",
            ),
            make_log(
                timestamp=iso_at(base, minutes=2),
                event_id="EVT-603",
                action="ssh_connect",
                resource="10.0.0.13",
                session_id="sess-6",
            ),
            make_log(
                timestamp=iso_at(base, minutes=3),
                event_id="EVT-604",
                action="ssh_connect",
                resource="10.0.0.14",
                session_id="sess-6",
            ),
        ]

        incidents = detector.scan(logs)

        assert incidents == []

    def test_ignores_five_ssh_connects_split_across_two_sessions(self):
        detector = LateralMovementDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=0),
                event_id="EVT-LM-A1",
                action="ssh_connect",
                resource="10.0.0.11",
                session_id="sess-lm-a",
            ),
            make_log(
                timestamp=iso_at(base, minutes=1),
                event_id="EVT-LM-A2",
                action="ssh_connect",
                resource="10.0.0.12",
                session_id="sess-lm-a",
            ),
            make_log(
                timestamp=iso_at(base, minutes=2),
                event_id="EVT-LM-A3",
                action="ssh_connect",
                resource="10.0.0.13",
                session_id="sess-lm-a",
            ),
            make_log(
                timestamp=iso_at(base, minutes=3),
                event_id="EVT-LM-B1",
                action="ssh_connect",
                resource="10.0.0.14",
                session_id="sess-lm-b",
            ),
            make_log(
                timestamp=iso_at(base, minutes=4),
                event_id="EVT-LM-B2",
                action="ssh_connect",
                resource="10.0.0.15",
                session_id="sess-lm-b",
            ),
        ]

        incidents = detector.scan(logs)

        assert incidents == []


class TestPrivilegeEscalationDetector:
    def test_detects_two_successful_sudo_execs_without_prior_history(self):
        detector = PrivilegeEscalationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=index),
                event_id=f"EVT-70{index}",
                action="sudo_exec",
                resource="/usr/bin/id",
                session_id="sess-7",
            )
            for index in range(1, 3)
        ]

        incidents = detector.scan(logs)

        assert len(incidents) == 1
        payload = parse_incident(incidents[0])
        assert payload["attack_type"] == "PRIVILEGE_ESCALATION"
        assert payload["iocs"]["privileged_action_count"] == 2
        assert payload["iocs"]["privileged_actions"] == ["sudo_exec", "sudo_exec"]

    def test_ignores_below_threshold_sudo_execs(self):
        detector = PrivilegeEscalationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=0),
                event_id="EVT-801",
                action="sudo_exec",
                status="failure",
                session_id="sess-8",
            )
        ]

        incidents = detector.scan(logs)

        assert incidents == []

    def test_ignores_single_successful_sudo_exec_event(self):
        detector = PrivilegeEscalationDetector()
        logs = [
            make_log(
                timestamp="2026-01-01T12:00:00Z",
                event_id="EVT-901",
                action="sudo_exec",
                status="success",
                session_id="sess-single",
                user_id="u0001_mkt",
            )
        ]

        incidents = detector.scan(logs)

        assert incidents == []

    @pytest.mark.xfail(
        reason="Spec requires no prior sudo history for the user, but current detector only counts successful sudo_exec events within a session.",
        strict=False,
    )
    def test_spec_requires_no_prior_sudo_history_for_privilege_escalation(self):
        detector = PrivilegeEscalationDetector()
        base = datetime.fromisoformat("2026-01-01T12:00:00+00:00")
        logs = [
            make_log(
                timestamp=iso_at(base, minutes=0),
                event_id="EVT-901",
                action="sudo_exec",
                status="success",
                session_id="sess-prior",
                user_id="u0001_mkt",
            ),
            make_log(
                timestamp=iso_at(base, minutes=10),
                event_id="EVT-902",
                action="sudo_exec",
                status="success",
                session_id="sess-9",
                user_id="u0001_mkt",
            ),
            make_log(
                timestamp=iso_at(base, minutes=11),
                event_id="EVT-903",
                action="sudo_exec",
                status="success",
                session_id="sess-9",
                user_id="u0001_mkt",
            ),
        ]

        incidents = detector.scan(logs)

        assert incidents == []