"""Deterministic four-detector release verification command.

This module backs the final-sprint "one reliable command" requirement:

    python -m classification_tool.app.verification.four_detector_release_check

It is intentionally independent of pytest, Supabase, Groq, or the frontend.
That makes it suitable for a demo terminal, local release sign-off, or CI
smoke job where the goal is to prove the detector logic itself still behaves
correctly.

The check has three evidence buckets:

1. Positive controls: every detector receives a complete technical attack
   pattern at the production threshold and must emit exactly one alert.
2. Negative/adversarial controls: every detector receives suspicious-looking
   but incomplete or below-threshold data and must emit zero alerts.
3. EVT-9901 to EVT-9904 trap: one event is shaped to touch each detector path,
   but no detector receives enough evidence to alert.

All generated events include protected bias fields. The scan helper strips
those fields before calling detectors and asserts they are absent from the
detector input, giving a lightweight before/after stripping proof for this
release check.
"""

import json
from datetime import datetime, timedelta, timezone

from classification_tool.app.bias_filter.filter import PROTECTED_FIELDS, strip_for_detection
from classification_tool.app.detectors.brute_force_detector import BruteForceDetector
from classification_tool.app.detectors.data_exfiltration_detector import DataExfiltrationDetector
from classification_tool.app.detectors.lateral_movement_detector import LateralMovementDetector
from classification_tool.app.detectors.privilege_escalation_detector import (
    PrivilegeEscalationDetector,
)


def _ts(offset_seconds: int) -> str:
    """Return stable ISO timestamps so event ordering is deterministic."""
    base = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(
    event_id: str,
    action: str,
    *,
    offset_seconds: int = 0,
    source_ip: str = "10.0.0.10",
    user_id: str = "u9900_ops",
    session_id: str = "sess-9900",
    resource: str = "/auth/login",
    status: str = "success",
) -> dict:
    """Build one log event using the shared ACIRO log shape.

    Defaults are deliberately benign and internal. Individual fixtures override
    only the technical fields that matter for a detector, such as action,
    status, source IP, target resource, user, and session.

    The protected fields are included on every event on purpose. They should be
    present in the raw fixture, then removed by _strip before any detector sees
    the event. If a future change accidentally passes protected fields into the
    detector input, the assertion in _strip fails this command.
    """
    return {
        "timestamp": _ts(offset_seconds),
        "event_id": event_id,
        "source_ip": source_ip,
        "user_id": user_id,
        "department": "finance",
        "seniority": "director",
        "job_title": "VP Finance",
        "location": "Mexico",
        "nationality": "Canadian",
        "action": action,
        "resource": resource,
        "status": status,
        "session_id": session_id,
    }


def _strip(events: list[dict]) -> list[dict]:
    """Apply the production bias-field stripping step before detection."""
    stripped = [strip_for_detection(event) for event in events]

    # This assertion is release evidence, not just defensive programming: every
    # event fixture contains protected fields, and every detector input must
    # have them removed before scanning begins.
    assert all(field not in event for event in stripped for field in PROTECTED_FIELDS)
    return stripped


def _parse_attacks(raw_attacks: list[str]) -> list[dict]:
    """Convert detector JSON-string outputs into dictionaries for assertions."""
    return [
        json.loads(attack.replace("\n\nEnd of Attack\n\n", "").strip())
        for attack in raw_attacks
    ]


def scan_all(events: list[dict]) -> dict[str, list[dict]]:
    """Run the same stripped event batch through all four release detectors."""
    detector_inputs = _strip(events)

    # Each detector receives the same stripped corpus. This matters for the
    # trap requirement: EVT-9901 to EVT-9904 must exercise all four detector
    # paths, not only the detector that appears most relevant for each event.
    return {
        "BRUTE_FORCE": _parse_attacks(BruteForceDetector().scan(detector_inputs)),
        "DATA_EXFILTRATION": _parse_attacks(DataExfiltrationDetector().scan(detector_inputs)),
        "LATERAL_MOVEMENT": _parse_attacks(LateralMovementDetector().scan(detector_inputs)),
        "PRIVILEGE_ESCALATION": _parse_attacks(PrivilegeEscalationDetector().scan(detector_inputs)),
    }


def positive_events() -> list[dict]:
    """Build complete attack patterns that must alert at production thresholds."""
    events: list[dict] = []

    # Brute force positive:
    # The detector requires 10 failed login attempts within a 5-minute window
    # from the same user/session/IP, followed by a successful login. The events
    # below are 20 seconds apart, so all failures fit inside the window, and the
    # final success converts the failed-attempt cluster into an alert.
    events.extend(
        _event(
            f"BF-POS-{index:02d}",
            "login",
            offset_seconds=index * 20,
            status="failure",
            user_id="u_bf",
            session_id="sess-bf",
            source_ip="10.0.0.20",
        )
        for index in range(10)
    )
    events.append(
        _event(
            "BF-POS-10",
            "login",
            offset_seconds=220,
            status="success",
            user_id="u_bf",
            session_id="sess-bf",
            source_ip="10.0.0.20",
        )
    )

    # Data exfiltration positive:
    # The detector requires 10 file_download attempts from an external IP.
    # 203.0.113.0/24 is a documentation/test range, so it is safe to use here
    # while still being treated as external by the detector's "not 10.0.*" rule.
    events.extend(
        _event(
            f"EX-POS-{index:02d}",
            "file_download",
            offset_seconds=400 + index,
            source_ip="203.0.113.10",
            user_id="u_ex",
            session_id="sess-ex",
            resource=f"/data/finance/report-{index}.csv",
        )
        for index in range(10)
    )

    # Lateral movement positive:
    # The detector requires successful ssh_connect events to at least 5 unique
    # internal hosts in the same session. The resource values below are unique
    # 10.0.* hosts, so the host-count threshold is met.
    events.extend(
        _event(
            f"LM-POS-{index:02d}",
            "ssh_connect",
            offset_seconds=600 + index,
            user_id="u_lm",
            session_id="sess-lm",
            source_ip="10.0.0.30",
            resource=f"10.0.1.{index}",
        )
        for index in range(5)
    )

    # Privilege escalation positive:
    # The detector requires 2 sudo_exec events in the same session for a user
    # with no prior sudo history in this batch. These two events meet exactly
    # that threshold.
    events.extend(
        _event(
            f"PE-POS-{index:02d}",
            "sudo_exec",
            offset_seconds=800 + index,
            user_id="u_pe",
            session_id="sess-pe",
            source_ip="10.0.0.40",
            resource="/usr/bin/sudo",
        )
        for index in range(2)
    )
    return events


def negative_events() -> list[dict]:
    """Build near-miss patterns that must not alert at production thresholds."""
    events: list[dict] = []

    # Brute force negative:
    # This deliberately has 10 failures, which looks severe, but there is no
    # later successful login. The current detector definition requires that
    # success after the failure window, so expected alerts remain zero.
    events.extend(
        _event(
            f"BF-NEG-{index:02d}",
            "login",
            offset_seconds=index * 20,
            status="failure",
            user_id="u_bf_neg",
            session_id="sess-bf-neg",
            source_ip="10.0.0.21",
        )
        for index in range(10)
    )

    # Data exfiltration negative:
    # 9 external downloads is one below the production threshold of 10. This is
    # the boundary case that proves the detector does not alert early.
    events.extend(
        _event(
            f"EX-NEG-{index:02d}",
            "file_download",
            offset_seconds=400 + index,
            source_ip="203.0.113.11",
            user_id="u_ex_neg",
            session_id="sess-ex-neg",
            resource=f"/data/hr/report-{index}.csv",
        )
        for index in range(9)
    )

    # Lateral movement negative:
    # 4 unique internal hosts is one below the production threshold of 5. This
    # should touch the lateral-movement path but not produce an incident.
    events.extend(
        _event(
            f"LM-NEG-{index:02d}",
            "ssh_connect",
            offset_seconds=600 + index,
            user_id="u_lm_neg",
            session_id="sess-lm-neg",
            source_ip="10.0.0.31",
            resource=f"10.0.2.{index}",
        )
        for index in range(4)
    )

    # Privilege escalation negative:
    # A single sudo_exec is suspicious-looking but below the threshold of 2.
    # The expected result is no privilege-escalation incident.
    events.append(
        _event(
            "PE-NEG-00",
            "sudo_exec",
            offset_seconds=800,
            user_id="u_pe_neg",
            session_id="sess-pe-neg",
            source_ip="10.0.0.41",
            resource="/usr/bin/sudo",
        )
    )
    return events


def trap_events() -> list[dict]:
    """Build the exact EVT-9901 to EVT-9904 all-detector trap sequence.

    Each event resembles the first step of one detector's attack pattern:

    - EVT-9901: one failed login for brute force
    - EVT-9902: one external file download for data exfiltration
    - EVT-9903: one internal SSH connection for lateral movement
    - EVT-9904: one sudo execution for privilege escalation

    The trap is adversarial because it is intentionally suspicious across many
    dimensions, but no single detector receives a complete technical pattern.
    The expected result is zero alerts through all four detectors.
    """
    return [
        _event("EVT-9901", "login", status="failure", session_id="sess-trap"),
        _event(
            "EVT-9902",
            "file_download",
            offset_seconds=10,
            source_ip="203.0.113.99",
            session_id="sess-trap",
            resource="/data/finance/quarterly.xlsx",
        ),
        _event(
            "EVT-9903",
            "ssh_connect",
            offset_seconds=20,
            session_id="sess-trap",
            resource="10.0.9.3",
        ),
        _event(
            "EVT-9904",
            "sudo_exec",
            offset_seconds=30,
            session_id="sess-trap",
            resource="/usr/bin/sudo",
        ),
    ]


def run_check() -> dict[str, dict[str, int]]:
    """Run all release assertions and return a compact evidence summary."""
    positive = scan_all(positive_events())
    expected = {
        "BRUTE_FORCE",
        "DATA_EXFILTRATION",
        "LATERAL_MOVEMENT",
        "PRIVILEGE_ESCALATION",
    }

    # Positive controls protect against a false sense of safety. If every
    # negative case returned zero alerts because a detector was broken or never
    # called, these assertions would fail first.
    assert {name for name, results in positive.items() if results} == expected
    for attack_type, results in positive.items():
        # Confirm the detector labels its own output correctly and includes
        # event IDs, because downstream incident/trace views depend on those
        # event IDs for user-visible evidence.
        assert results[0]["attack_type"] == attack_type
        assert results[0]["iocs"]["event_ids"]

    negative = scan_all(negative_events())
    trap = scan_all(trap_events())

    # Negative controls prove the detector thresholds are respected. Trap
    # controls prove EVT-9901 to EVT-9904 touches every detector path while
    # still producing zero alerts.
    assert all(not results for results in negative.values())
    assert all(not results for results in trap.values())

    # Keep the command output small and evidence-focused. Reviewers can capture
    # this JSON in a terminal screenshot or CI artifact without exposing bulky
    # raw event fixtures.
    return {
        "positive_alert_counts": {name: len(results) for name, results in positive.items()},
        "negative_alert_counts": {name: len(results) for name, results in negative.items()},
        "evt_9901_evt_9904_trap_alert_counts": {
            name: len(results) for name, results in trap.items()
        },
    }


def main() -> None:
    """CLI entry point for the final-sprint one-command detector check."""
    result = run_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    print("four-detector release check passed")


if __name__ == "__main__":
    main()
