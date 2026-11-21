"""Formatting and counting helpers for ``--explain`` and ``--stats``.

``--explain`` shows, per input line, how the line was parsed, which
mapping was applied, the fields available to mapping templates, and the
resulting CEF record. ``--stats`` summarizes a whole run: lines per
parser, lines per msg pattern, and the lines no specific parser matched.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from . import custom
from .mappings import CISCO_ASA, CISCO_IOS, F5, FORTINET, LINUX, SOPHOS, VMWARE

MAX_VALUE_LEN = 200
MAX_SAMPLES = 5

# Source hints for lines no specific parser recognized.
UNMATCHED_HINTS = frozenset({"adaptive", "unknown"})

# Bundled mappings, compared by identity with what the auto-detection
# returned, so the label names the mapping actually used.
_BUNDLED = (
    (CISCO_ASA, "cisco_asa"),
    (CISCO_IOS, "cisco_ios"),
    (F5, "f5"),
    (FORTINET, "fortinet"),
    (LINUX, "linux"),
    (SOPHOS, "sophos"),
    (VMWARE, "vmware"),
)


def truncate(text: str, limit: int = MAX_VALUE_LEN) -> str:
    """Return *text* cut to *limit* characters, marked with "..." when cut."""
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def bundled_name(mapping: Any) -> Optional[str]:
    """Return the bundled mapping name for *mapping* (by identity), else None."""
    for candidate, name in _BUNDLED:
        if mapping is candidate:
            return name
    return None


def mapping_label(event: Any, explicit_mapping: Optional[Mapping[str, Any]] = None) -> str:
    """Describe which mapping ``to_cef`` selects for *event*.

    Mirrors the selection order: an explicit ``--mapping`` always wins,
    then a mapping attached to the matching pattern, then auto-detection.
    """
    if explicit_mapping is not None:
        return "--mapping"
    mapping_for = getattr(custom, "mapping_for", None)
    if mapping_for is not None:
        found = mapping_for(event)
        if found is not None:
            return f"pattern {found[0]}"
    from .api import _guess_mapping

    guessed = _guess_mapping(event)
    return f"auto {bundled_name(guessed) or 'custom'}"


def format_explain(index: int, event: Any, cef: str, label: str) -> str:
    """Render the ``--explain`` block for one converted line (no trailing newline)."""
    lines = [
        f"--- line {index}",
        f"raw:     {event.raw}",
        f"parser:  {event.source_hint}",
        f"pattern: {getattr(event, 'pattern', None) or '-'}",
        f"msg pattern: {getattr(event, 'msg_pattern', None) or '-'}",
        f"mapping: {label}",
        "fields:",
    ]
    fields = event.as_field_dict()
    for key in sorted(fields):
        if key == "raw":
            continue
        lines.append(f"  {key} = {truncate(str(fields[key]))}")
    lines.append(f"cef:     {cef}")
    return "\n".join(lines)


class Stats:
    """Per-run counters for ``--stats``."""

    def __init__(self) -> None:
        self.total = 0
        self.by_parser: Dict[str, int] = {}
        self.by_msg_pattern: Dict[str, int] = {}
        self.unmatched = 0
        self.samples: List[str] = []

    def add(self, event: Any) -> None:
        self.total += 1
        hint = event.source_hint or "unknown"
        self.by_parser[hint] = self.by_parser.get(hint, 0) + 1
        msg_pattern = getattr(event, "msg_pattern", None)
        if msg_pattern:
            self.by_msg_pattern[msg_pattern] = self.by_msg_pattern.get(msg_pattern, 0) + 1
        if hint in UNMATCHED_HINTS:
            self.unmatched += 1
            if len(self.samples) < MAX_SAMPLES:
                self.samples.append(truncate(event.raw))

    def format(self) -> str:
        """Render the summary (no trailing newline)."""
        lines = [f"syslogcef: {self.total} lines", "  by parser:"]
        lines.extend(f"    {name}  {count}" for name, count in _sorted_counts(self.by_parser))
        if self.by_msg_pattern:
            lines.append("  by msg pattern:")
            lines.extend(f"    {name}  {count}" for name, count in _sorted_counts(self.by_msg_pattern))
        lines.append(f"  unmatched (adaptive or unknown): {self.unmatched}")
        lines.extend(f"    {sample}" for sample in self.samples)
        return "\n".join(lines)


def _sorted_counts(counts: Mapping[str, int]) -> List[tuple]:
    # Count descending, then name ascending for a stable order.
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))
