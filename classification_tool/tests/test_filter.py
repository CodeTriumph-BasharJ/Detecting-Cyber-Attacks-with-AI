import pytest
import sys
from pathlib import Path
from classification_tool.app.detectors.brute_force_detector import BruteForceDetector
from classification_tool.app.detectors.data_exfiltration_detector import DataExfiltrationDetector
from classification_tool.app.detectors.lateral_movement_detector import LateralMovementDetector
from classification_tool.app.detectors.privilege_escalation_detector import PrivilegeEscalationDetector
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import from app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.bias_filter.filter import (
    strip_for_detection,
    assert_trace_iocs_are_technical,
    BiasGuardError,
    PROTECTED_FIELDS,
    TECHNICAL_FIELDS
)
from app.reasoning.trace import ReasoningTrace

def make_logs(
    timestamp="2026-01-01T12:00:00Z",
    event_id=None,
    source_ip="10.0.0.1",
    user_id="u0001_fin",
    department=None,
    seniority=None,
    action="login",
    resource=None,
    status="success",
    session_id=None,
    job_title=None,
    location=None,
    nationality=None,
):
        return {
            "timestamp": timestamp,
            "event_id": event_id,
            "source_ip": source_ip,
            "user_id": user_id,
            "department": department,
            "seniority": seniority,
            "action": action,
            "resource": resource,
            "status": status,
            "session_id": session_id,
            "job_title": job_title,
            "location": location,
            "nationality": nationality,
        }
    
def run_pipeline(logs):
    brute_force_detector = BruteForceDetector(threshold=10, window_minutes=5)
    exfiltration_detector = DataExfiltrationDetector(threshold=5)
    lateral_movement_detector = LateralMovementDetector()
    privilege_escalation_detector = PrivilegeEscalationDetector()
    events = [strip_for_detection(log) for log in logs]
    brute_force_incidents = brute_force_detector.scan(events)
    exfiltration_incidents = exfiltration_detector.scan(events)
    lateral_movement_incidents = lateral_movement_detector.scan(events)
    privilege_escalation_incidents = privilege_escalation_detector.scan(events)
    return (
        brute_force_incidents
        + exfiltration_incidents
        + lateral_movement_incidents
        + privilege_escalation_incidents
    )


class TestStripForDetection:
    def test_default_strips_protected_fields(self):
        event = make_logs(department="finance", seniority="mid", location="Mexico")
        stripped = strip_for_detection(event, None)
        assert "department" not in stripped
        assert "seniority" not in stripped
        assert "location" not in stripped
        assert stripped["user_id"] == "u0001_fin"
        assert stripped["action"] == "login"

    def test_bias_proxy_dicts_strip_only_blocked(self):
        event = make_logs(department="finance", seniority="mid", location="Mexico")
        proxies = [
            {"field_name": "department", "is_blocked": True},
            {"field_name": "seniority", "is_blocked": False},
            {"field_name": "location", "is_blocked": False},
        ]
        stripped = strip_for_detection(event, proxies)
        assert "department" not in stripped
        assert stripped["seniority"] == "mid"
        assert stripped["location"] == "Mexico"

    def test_empty_proxy_list_uses_default_protected_fields(self):
        event = make_logs(department="finance", seniority="mid")
        stripped = strip_for_detection(event, [])
        assert "department" not in stripped
        assert "seniority" not in stripped


class TestBiasFilter:

    def test_finance_user_single_login_no_alert(self):
        """Finance department alone is NOT an IoC."""
        logs = [make_logs(timestamp="2026-01-01T12:00:00Z",
                    event_id="EVT-12345",
                    source_ip="10.0.0.1",
                    user_id="u0001_fin",
                    department="finance",
                    seniority="mid",
                    action="login",
                    status="success",
                    session_id=1,
                )]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_executive_late_night_access_no_alert(self):
        """Senior seniority + odd hours alone is NOT an IoC."""
        logs = [make_logs(timestamp="2026-01-01T23:00:00Z",
                    event_id="EVT-12345",
                    source_ip="10.0.0.1",
                    user_id="u0001_eng",
                    department="engineering",
                    seniority="senior",
                    action="login",
                    status="success",
                    session_id=1,
                )]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_foreign_location_no_alert(self):
        """Non-domestic source_ip without other signals is NOT an IoC."""
        # Bias check: should only alert based on volume/pattern, not geolocation
        logs = [make_logs(timestamp="2026-01-01T09:00:00Z",
                    event_id="EVT-12345",
                    source_ip="203.0.113.5",
                    user_id="u0001_eng",
                    department="engineering",
                    seniority="senior",
                    action="login",
                    status="success",
                    session_id=1)]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_hr_bulk_access_during_review_period_no_alert(self):
        """HR accessing many files during performance review = normal."""
        base = datetime.fromisoformat("2026-01-01T09:00:00+00:00")
        logs = [make_logs(
            timestamp=(base + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            event_id=f"EVT-{i:05d}",
            source_ip="10.0.0.1",
            user_id="u0020_hr",
            department="human resources",
            seniority="senior",
            action="file_access",
            status="success",
            session_id="1",
            resource= "/data/human_resources/employees_contract.pdf"
        )
            for i in range(1, 21)
        ]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_low_level_employee_access_no_alert(self):
        """Junior employees accessing files after hours is not an IoC."""
        logs = [make_logs(timestamp="2026-01-01T21:00:00Z",
                    event_id="EVT-12345",
                    source_ip="10.0.0.5",
                    user_id="u0001_eng",
                    department="engineering",
                    seniority="junior",
                    action="file_access",
                    status="success",
                    session_id=1,
                    resource= "/data/manufacturing/part_x45_components.xlsx"
                )]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_cross_department_access_no_alert(self):
        """Cross-department file access without anomalous volume is not an IoC.."""
        logs = [make_logs(timestamp="2026-01-01T09:00:00Z",
                    event_id="EVT-12345",
                    source_ip="10.0.0.5",
                    user_id="u0001_fin",
                    department="finance",
                    seniority="junior",
                    action="file_access",
                    status="success",
                    session_id=1,
                    resource= "/data/human_resources/employees_contract.pdf"
                )]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_finance_department_failed_login_no_alert(self):
        """Finance department failed login attempts is not an IoC if not followed by a login within 10 tries."""
        base = datetime.fromisoformat("2026-01-01T09:00:00+00:00")
        logs = [make_logs(timestamp=(base + timedelta(seconds=i*10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    event_id=f"EVT-{i:05d}",
                    source_ip="10.0.0.5",
                    user_id="u0001_fin",
                    department="finance",
                    seniority="junior",
                    action="login",
                    status="failure",
                    session_id=i
                )for i in range(1, 11)]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_overseas_file_downloads_no_alert(self):
        """Small amount of file downloads by a senior operations employee overseas is not an incident."""
        base = datetime.fromisoformat("2026-01-01T09:00:00+00:00")
        logs = [make_logs(timestamp=(base + timedelta(seconds=i*10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    event_id=f"EVT-{i:05d}",
                    source_ip="203.0.113.5",
                    user_id="u0001_ops",
                    department="operations",
                    seniority="director",
                    action="file_download",
                    status="success",
                    session_id=1,
                    resource= "/data/operations/yearly_budget.pdf",
                    job_title="Manager",
                    location="Mexico",
                )for i in range(1, 5)]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_ssh_connection_foreign_employee_no_alert(self):
        """Operations employees from overseas departments doing ssh_connections is not an incident."""
        logs = [make_logs(timestamp="2026-01-01T09:00:00Z",
                    event_id="EVT-00001",
                    source_ip="10.0.0.5",
                    user_id="u0001_mkt",
                    department="marketing",
                    seniority="mid",
                    action="ssh_connection",
                    status="success",
                    session_id=1,
                    resource= "/user/bin/id",
                    job_title="Manager",
                    location="Mexico",
                    nationality="Mexican"
        )]
        incidents = run_pipeline(logs)
        assert incidents == []

    def test_single_marketing_sudo_exec_no_alert(self):
        """Unusual department issuing sudo commands is not an IoC unless followed by other suspicious activities."""
        logs = [make_logs(timestamp="2026-01-01T21:00:00Z",
                    event_id="EVT-12345",
                    source_ip="10.0.0.5",
                    user_id="u0001_mkt",
                    department="marketing",
                    seniority="senior",
                    action="sudo_exec",
                    status="success",
                    session_id=1,
                    resource= "/user/bin/id"
                )]
        incidents = run_pipeline(logs)
        assert incidents == []