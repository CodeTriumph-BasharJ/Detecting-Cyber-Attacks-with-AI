from classification_tool.app.verification.four_detector_release_check import (
    negative_events,
    positive_events,
    run_check,
    scan_all,
    trap_events,
)


def test_four_detector_positive_cases_at_production_thresholds() -> None:
    attacks = scan_all(positive_events())

    assert {name for name, results in attacks.items() if results} == {
        "BRUTE_FORCE",
        "DATA_EXFILTRATION",
        "LATERAL_MOVEMENT",
        "PRIVILEGE_ESCALATION",
    }
    for attack_type, results in attacks.items():
        assert results[0]["attack_type"] == attack_type
        assert results[0]["iocs"]["event_ids"]


def test_four_detector_negative_cases_at_production_thresholds() -> None:
    assert scan_all(negative_events()) == {
        "BRUTE_FORCE": [],
        "DATA_EXFILTRATION": [],
        "LATERAL_MOVEMENT": [],
        "PRIVILEGE_ESCALATION": [],
    }


def test_evt_9901_to_evt_9904_trap_exercises_all_detectors_with_zero_alerts() -> None:
    assert scan_all(trap_events()) == {
        "BRUTE_FORCE": [],
        "DATA_EXFILTRATION": [],
        "LATERAL_MOVEMENT": [],
        "PRIVILEGE_ESCALATION": [],
    }


def test_standalone_release_check_summary() -> None:
    assert run_check()["evt_9901_evt_9904_trap_alert_counts"] == {
        "BRUTE_FORCE": 0,
        "DATA_EXFILTRATION": 0,
        "LATERAL_MOVEMENT": 0,
        "PRIVILEGE_ESCALATION": 0,
    }
