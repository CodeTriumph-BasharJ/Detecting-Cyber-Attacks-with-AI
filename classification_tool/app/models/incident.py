import uuid
from datetime import datetime, UTC


BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 5
DATA_EXFILTRATION_THRESHOLD = 10


class IoC():
  description: str
  value: list[str] | str | int

  def __init__(self, description, value):
    self.description = description
    self.value = value


class CandidateIncident():
  incident_id: str
  timestamp: str
  attack_type: str
  iocs: list[IoC]

  def __init__(self, attack_type, iocs):
    self.incident_id = str(uuid.uuid4())
    self.timestamp=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    self.attack_type=attack_type
    self.iocs = iocs