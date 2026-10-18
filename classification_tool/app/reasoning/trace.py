from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ReasoningTrace:
    triggering_iocs: list[dict]    # each has event_id + field + value
    playbook_citation: dict        # {section: "3.2.1", page: 14, title: "..."}
    recommended_action: str        # from spec's 4-action enum
    plain_language_summary: str   # 2-3 sentences
    ignored_fields: dict     # {field_name: [event_id1, event_id2, ...]} for any fields removed by the bias filter