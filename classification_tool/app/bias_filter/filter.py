from __future__ import annotations

from ..reasoning.trace import ReasoningTrace

PROTECTED_FIELDS = {"department", "seniority", "job_title", "location", "nationality"}

TECHNICAL_FIELDS = {"action", "status", "source_ip", "timestamp",
                        "session_id", "resource", "event_id"}

BiasGuardError = Exception


def _fields_to_strip(protected_fields: list | None) -> set[str]:
    """
    Resolve which log fields to remove before detection.

    - Empty / None → default PROTECTED_FIELDS (safe when caller omits config).
    - BiasProxyConfig dicts / objects → strip only entries with is_blocked=True.
    - Plain field-name strings → strip those names.
    """
    if not protected_fields:
        return set(PROTECTED_FIELDS)

    names: set[str] = set()
    for item in protected_fields:
        if item is None:
            continue
        if isinstance(item, str):
            names.add(item)
            continue
        if isinstance(item, dict):
            field_name = item.get("field_name")
            if field_name and item.get("is_blocked", True):
                names.add(str(field_name))
            continue
        field_name = getattr(item, "field_name", None)
        is_blocked = getattr(item, "is_blocked", True)
        if field_name and is_blocked:
            names.add(str(field_name))

    return names


def strip_for_detection(log_event: dict, protected_fields: list | None = None) -> dict:
    """Returns a copy with protected / blocked bias-proxy fields removed.
    The original is preserved separately for reasoning-trace metadata only."""
    fields = _fields_to_strip(protected_fields if protected_fields is not None else [])
    return {k: v for k, v in log_event.items() if k not in fields}


def assert_trace_iocs_are_technical(trace: ReasoningTrace) -> bool:
    """Refuses to emit alerts whose IoCs cite only protected fields."""
    cited_fields = {ioc["field"] for ioc in trace.triggering_iocs}
    if not (cited_fields & TECHNICAL_FIELDS):
        raise BiasGuardError(
            f"Alert trace cites only non-technical fields: {cited_fields}"
        )
    return True


def get_ignored_fields(original_log_event: dict, processed_log_event: dict) -> set:
    """Returns a set of any detected protected fields that were removed by the bias filter."""
    return {field for field in PROTECTED_FIELDS if field in original_log_event and field not in processed_log_event}
