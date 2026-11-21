"""User-defined parsers: declarative pattern files and a registration API.

Two ways to teach syslogcef a format it does not know (issue #67):

1. **Pattern files** — ``--patterns file.json`` (or ``load_patterns()``
   from Python) loads named regexes whose named groups map to event
   fields, the same way ``--mapping`` supplies CEF mappings::

       {
         "patterns": [
           {
             "name": "acme_fw",
             "regex": "^(?P<ts>\\\\d{4}-\\\\d{2}-\\\\d{2} \\\\d{2}:\\\\d{2}:\\\\d{2}) (?P<host>\\\\S+) (?P<app>\\\\w+): (?P<msg>.*)$",
             "timestamp_format": "%Y-%m-%d %H:%M:%S",
             "priority": "after",
             "mapping": "linux"
           },
           {
             "name": "sshd_failed",
             "match": "msg",
             "app": "sshd",
             "regex": "Failed password for (?P<suser>\\\\S+) from (?P<src>[\\\\d.]+) port (?P<spt>\\\\d+)",
             "examples": [
               {"line": "<38>Jan  2 03:04:05 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
                "expect": {"src": "10.0.0.1"}}
             ]
           }
         ]
       }

   Entry keys:

   ``name`` (required)
       Unique name; may not shadow a built-in parser. Line pattern names
       are also accepted by ``--mode``.
   ``regex`` (required)
       The regular expression. ``%{NAME}`` and ``%{NAME:field}`` tokens
       expand to the shorthands in :mod:`syslogcef.shorthands` (e.g.
       ``%{IP:src}``); an unknown NAME is a load error.
   ``match``
       ``"line"`` (default) applies the regex to the whole raw line with
       ``re.match``: it is a full parser. ``"msg"`` applies it with
       ``re.search`` to the message of an event that something else
       (a built-in parser, a line pattern, the adaptive parser, or a
       forced ``--mode``) already parsed; the first matching msg pattern
       in load order wins.
   ``timestamp_format`` / ``priority`` (line patterns only)
       ``timestamp_format`` is required iff the regex has a ``ts`` group:
       a strptime format, ``iso8601``, or ``epoch``. ``priority`` decides
       whether the pattern is tried ``"before"`` the built-in parsers or
       ``"after"`` them (the default — still ahead of the adaptive
       fallback).
   ``app`` (msg patterns only)
       A string or list of strings; the msg pattern only applies to
       events whose ``app`` equals one of them, case-insensitively.
   ``mapping``
       A bundled mapping name (``cisco_asa``, ``cisco_ios``, ``f5``,
       ``fortinet``, ``linux``, ``sophos``, ``vmware``) or a path to a
       mapping JSON file (relative paths resolve against the pattern
       file's directory). Used for events this pattern matched when no
       explicit ``--mapping`` is given; a msg pattern's mapping wins over
       a line pattern's.
   ``examples``
       A list of ``{"line": str, "expect": {field: value}, "matches":
       bool}`` objects, checked by ``--check-patterns``.
   ``description``
       Free text for humans; ignored by the converter.

   Any other key in an entry or an example (typically a typo such as
   ``"exmaples"``) does not fail loading: it is ignored, logged as a
   warning on the ``syslogcef.custom`` logger naming the file, pattern
   and key, recorded in ``CustomPattern.warnings``, and reported as a
   failure by ``--check-patterns``.

   Named groups: in a line pattern, ``pri``, ``host``, ``app``, ``pid``,
   ``msgid``, ``msg`` and ``ts`` fill the event envelope; every other
   named group is a captured field. In a msg pattern every named group is
   a captured field and the envelope names are not allowed. Captured
   fields land in ``ParsedEvent.fields`` and are merged into the
   normalized key/value fields (winning over key=value text in the
   message), so mapping templates reference them as ``%(name)s`` and
   aliases such as ``src_ip`` gain their canonical CEF name. Derived
   field names (``facility``, ``severity``, ``timestamp``, ``ts_orig``,
   ``source_hint``, ``raw``, ``raw_kv``, ``rt``, ``message_length``,
   ``message_short``, ``dvcpid``) cannot be captured.

2. **``register_parser(name, fn)``** — register a full parser function
   ``fn(line) -> ParsedEvent | None`` programmatically; the name becomes
   a valid ``--mode`` value.

Files are validated eagerly at load time — regex syntax, group names,
timestamp formats, duplicate names, mappings, example structure — so a typo fails at startup with a clear message instead of
mid-stream. User regexes run against untrusted log content: keep them
anchored and free of nested quantifiers (ReDoS), as they enjoy the same
time budget as everything else, i.e. none.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from .parsers import PARSERS, ParsedEvent
from .shorthands import expand as _expand_shorthands
from .utils import convert_pri, latest_past_occurrence, parse_iso8601

# Groups that fill the ParsedEvent envelope of a line pattern.
_EVENT_GROUPS = {"pri", "host", "app", "pid", "msgid", "msg"}
_ENVELOPE_GROUPS = frozenset(_EVENT_GROUPS | {"ts"})
# Derived during normalization; a capture with one of these names would be
# shadowed or would shadow the derived value, so it is rejected outright.
_RESERVED_GROUPS = frozenset(
    {
        "facility", "severity", "timestamp", "ts_orig", "source_hint", "raw",
        "raw_kv", "rt", "message_length", "message_short", "dvcpid",
    }
)
_TS_SPECIAL_FORMATS = {"iso8601", "epoch"}
_PRIORITIES = {"before", "after"}
_MATCH_KINDS = ("line", "msg")
_ENTRY_KEYS = frozenset(
    {
        "name", "regex", "match", "timestamp_format", "priority", "app", "mapping",
        "examples", "description",
    }
)
_LINE_ONLY_KEYS = ("timestamp_format", "priority")
_EXAMPLE_KEYS = frozenset({"line", "expect", "matches"})

logger = logging.getLogger(__name__)
_BUNDLED_MAPPINGS = ("cisco_asa", "cisco_ios", "f5", "fortinet", "linux", "sophos", "vmware")


class PatternFileError(ValueError):
    """A pattern file failed validation; the message names the pattern."""


@dataclass
class CustomPattern:
    name: str
    regex: "re.Pattern[str]"
    timestamp_format: Optional[str]
    priority: str
    match: str = "line"
    # Lowercased app filter for msg patterns; empty means any app.
    apps: Tuple[str, ...] = ()
    # The 'mapping' value as written in the pattern file.
    mapping_ref: Optional[str] = None
    examples: List[dict] = field(default_factory=list)
    # Path of the pattern file this pattern came from.
    source: str = ""
    # The optional free-text 'description'.
    description: Optional[str] = None
    # Load-time problems that did not fail loading, e.g. "unknown key
    # 'exmaples'"; --check-patterns reports each one as a failure.
    warnings: List[str] = field(default_factory=list)

    def parse(self, line: str, *, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
        if self.match != "line":
            return None
        match = self.regex.match(line)
        if match is None:
            return None
        groups = {k: v for k, v in match.groupdict().items() if v is not None}

        pri = int(groups["pri"]) if groups.get("pri", "").isdigit() else None
        facility, severity = convert_pri(pri)

        ts = None
        ts_orig = groups.get("ts", "")
        if ts_orig and self.timestamp_format:
            try:
                ts = _parse_timestamp(ts_orig, self.timestamp_format, now=now)
            except (ValueError, OverflowError, OSError):
                # OverflowError/OSError: out-of-range epoch values. A bad
                # timestamp never drops the line, in any mode.
                ts = None

        return ParsedEvent(
            pri=pri,
            facility=facility,
            severity=severity,
            ts=ts,
            ts_orig=ts_orig,
            host=groups.get("host"),
            app=groups.get("app"),
            pid=groups.get("pid"),
            msgid=groups.get("msgid"),
            msg=groups.get("msg", line),
            raw=line,
            source_hint=f"custom:{self.name}",
            fields={k: v for k, v in groups.items() if k not in _ENVELOPE_GROUPS},
            pattern=self.name,
        )

    def match_msg(self, event: ParsedEvent) -> Optional[Dict[str, str]]:
        """Return the captures of this msg pattern on *event*, or None."""
        if self.match != "msg":
            return None
        if self.apps and str(event.app or "").lower() not in self.apps:
            return None
        msg = event.msg
        if not isinstance(msg, str):
            return None
        found = self.regex.search(msg)
        if found is None:
            return None
        return {k: v for k, v in found.groupdict().items() if v is not None}


# Directives datetime.strptime accepts on every platform. Validated at
# load time so a typo like %Q fails at startup, not silently mid-stream.
_STRPTIME_DIRECTIVES = frozenset("aAbBcdfGHIjmMpSuUVwWxXyYzZ%")


def _validate_strptime_format(fmt: str) -> bool:
    """Return True if *fmt* contains a year directive; raise on invalid."""
    has_year, has_directive, i = False, False, 0
    while i < len(fmt):
        if fmt[i] == "%":
            if i + 1 >= len(fmt):
                raise ValueError("trailing '%' in timestamp_format")
            nxt = fmt[i + 1]
            if nxt not in _STRPTIME_DIRECTIVES:
                raise ValueError(f"unsupported strptime directive '%{nxt}'")
            if nxt != "%":
                has_directive = True
            if nxt in "YyG":
                has_year = True
            i += 2
        else:
            i += 1
    if not has_directive:
        raise ValueError("timestamp_format contains no strptime directives")
    return has_year


def _year_with_rollover(parsed: datetime, ref: datetime) -> datetime:
    """Assign the year to a yearless timestamp, as the built-in parsers do.

    Keeps every parsed component (tz offset, microseconds); see
    :func:`syslogcef.utils.latest_past_occurrence` for the rule.
    """

    def with_year(year: int) -> Optional[datetime]:
        try:
            return parsed.replace(year=year)
        except ValueError:  # Feb 29 in a non-leap year
            return None

    return latest_past_occurrence(with_year, ref) or parsed


def _parse_timestamp(text: str, fmt: str, *, now: Optional[datetime] = None) -> datetime:
    if fmt == "iso8601":
        return parse_iso8601(text)
    if fmt == "epoch":
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    has_year = "%Y" in fmt or "%y" in fmt or "%G" in fmt
    if has_year:
        parsed = datetime.strptime(text, fmt)
    else:
        # Parse against leap year 2000 so Feb 29 survives strptime (the
        # implicit 1900 default is not a leap year), then infer the real
        # year with the same rollover logic as the built-in parsers.
        parsed = datetime.strptime(f"2000 {text}", f"%Y {fmt}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if not has_year:
        ref = now or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        parsed = _year_with_rollover(parsed, ref)
    return parsed


_registered: Dict[str, Callable] = {}
_before: List[CustomPattern] = []
_after: List[CustomPattern] = []
_msg_patterns: List[CustomPattern] = []
# Every pattern loaded from a file, line and msg kind, in load order.
_loaded: List[CustomPattern] = []
# Pattern name -> validated CEF mapping, for patterns with a 'mapping' key.
_pattern_mappings: Dict[str, Mapping[str, Any]] = {}


def register_parser(name: str, parser: Callable, *, replace: bool = False) -> None:
    """Register ``parser(line) -> ParsedEvent | None`` under ``name``.

    The name becomes a valid ``--mode`` value. Built-in parser names are
    reserved; re-registering an existing custom name requires
    ``replace=True``.
    """
    if name in PARSERS:
        raise ValueError(f"'{name}' is a built-in parser name")
    if any(p.name == name for p in _msg_patterns):
        raise ValueError(f"'{name}' is the name of a loaded msg pattern")
    if name in _registered and not replace:
        raise ValueError(f"parser '{name}' is already registered")
    _registered[name] = parser


def get_registered(name: str) -> Optional[Callable]:
    return _registered.get(name)


def custom_parse(line: str, stage: str, *, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
    """Try every loaded line pattern of the given stage ("before"/"after")."""
    for pattern in _before if stage == "before" else _after:
        try:
            result = pattern.parse(line, now=now)
        except Exception:  # a broken user regex must never abort a stream
            continue
        if result is not None:
            return result
    return None


def apply_msg_patterns(event: ParsedEvent) -> ParsedEvent:
    """Run the loaded msg patterns over ``event.msg``; first match wins.

    The winning pattern's captures are merged over any fields a line
    pattern captured and ``event.msg_pattern`` is set. Mutates and returns
    *event*; never raises.
    """
    if not _msg_patterns:
        return event
    try:
        for pattern in _msg_patterns:
            try:
                captured = pattern.match_msg(event)
            except Exception:  # a broken user regex must never abort a stream
                continue
            if captured is None:
                continue
            fields = getattr(event, "fields", None)
            merged = dict(fields) if isinstance(fields, dict) else {}
            merged.update(captured)
            event.fields = merged
            event.msg_pattern = pattern.name
            break
    except Exception:
        pass
    return event


def loaded_patterns() -> List[CustomPattern]:
    """All patterns loaded from pattern files (line and msg), in load order."""
    return list(_loaded)


def mapping_for(event: Any) -> Optional[Tuple[str, Mapping[str, Any]]]:
    """Return ``(pattern_name, mapping)`` for the event's pattern mapping.

    A matching msg pattern's mapping wins over the line pattern's; None
    when neither pattern declared a mapping.
    """
    for name in (getattr(event, "msg_pattern", None), getattr(event, "pattern", None)):
        if name is None:
            continue
        mapping = _pattern_mappings.get(name)
        if mapping is not None:
            return name, mapping
    return None


def clear_registry() -> None:
    """Forget all registered parsers and loaded patterns (for tests)."""
    _registered.clear()
    del _before[:]
    del _after[:]
    del _msg_patterns[:]
    del _loaded[:]
    _pattern_mappings.clear()


def _resolve_mapping(ref: Any, base_dir: Path, where: str) -> Mapping[str, Any]:
    if not isinstance(ref, str) or not ref.strip():
        raise PatternFileError(
            f"{where}: 'mapping' must be a bundled mapping name or a path to a mapping JSON file"
        )
    # Imported lazily: api imports this module, so a top-level import cycles.
    from .api import _load_mapping
    from .mappings import load_mapping

    if ref in _BUNDLED_MAPPINGS:
        source: Any = load_mapping(ref)
    else:
        path = Path(ref)
        source = path if path.is_absolute() else base_dir / path
    try:
        return _load_mapping(source)
    except OSError as exc:
        raise PatternFileError(
            f"{where}: 'mapping' {ref!r} is not a bundled mapping "
            f"({', '.join(_BUNDLED_MAPPINGS)}) and cannot be read: {exc}"
        ) from exc
    except ValueError as exc:  # includes json.JSONDecodeError
        raise PatternFileError(f"{where}: invalid 'mapping' {ref!r}: {exc}") from exc


def _validate_examples(raw: Any, where: str, warnings: List[str]) -> List[dict]:
    """Validate the 'examples' list; unknown example keys go to *warnings*."""
    if not isinstance(raw, list):
        raise PatternFileError(f"{where}: 'examples' must be a list of objects")
    examples: List[dict] = []
    for index, example in enumerate(raw):
        at = f"{where}: examples[{index}]"
        if not isinstance(example, dict):
            raise PatternFileError(f"{at}: must be an object")
        for key in sorted(set(example) - _EXAMPLE_KEYS, key=str):
            # Numbered from 1, as --check-patterns numbers examples.
            warnings.append(f"unknown key {key!r} in example {index + 1}")
        line = example.get("line")
        if not isinstance(line, str) or not line:
            raise PatternFileError(f"{at}: 'line' is required and must be a non-empty string")
        copy: Dict[str, Any] = {"line": line}
        if "expect" in example:
            expect = example["expect"]
            if not isinstance(expect, dict):
                raise PatternFileError(f"{at}: 'expect' must be an object of field: value")
            for key, value in expect.items():
                if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                    raise PatternFileError(
                        f"{at}: 'expect' value for {key!r} must be a string or a number"
                    )
            copy["expect"] = dict(expect)
        if "matches" in example:
            if not isinstance(example["matches"], bool):
                raise PatternFileError(f"{at}: 'matches' must be true or false")
            copy["matches"] = example["matches"]
        examples.append(copy)
    return examples


def _parse_apps(raw: Any, where: str) -> Tuple[str, ...]:
    items = [raw] if isinstance(raw, str) else raw
    if (
        not isinstance(items, list)
        or not items
        or any(not isinstance(item, str) or not item.strip() for item in items)
    ):
        raise PatternFileError(
            f"{where}: 'app' must be a non-empty string or a non-empty list of strings"
        )
    return tuple(dict.fromkeys(item.lower() for item in items))


def load_patterns(path: Union[str, Path]) -> int:
    """Load and validate a pattern file; returns the number of patterns.

    Raises :class:`PatternFileError` naming the offending pattern on any
    validation problem, so services fail at startup rather than
    mid-stream. Nothing from the file is registered unless every entry
    validates.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PatternFileError(f"cannot read pattern file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PatternFileError(f"invalid JSON in pattern file {path}: {exc}") from exc

    entries = data.get("patterns") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise PatternFileError(
            f"{path}: expected an object with a non-empty 'patterns' list"
        )

    loaded: List[CustomPattern] = []
    mappings: Dict[str, Mapping[str, Any]] = {}
    for index, entry in enumerate(entries):
        where = f"{path}: patterns[{index}]"
        if not isinstance(entry, dict):
            raise PatternFileError(f"{where}: entry must be an object")
        name = entry.get("name")
        if not name or not isinstance(name, str):
            raise PatternFileError(f"{where}: missing 'name'")
        where = f"{path}: pattern '{name}'"
        # Unknown keys (usually typos) are reported, not fatal: a newer
        # pattern file still loads on an older syslogcef.
        warnings = [f"unknown key {key!r}" for key in sorted(set(entry) - _ENTRY_KEYS, key=str)]
        description = entry.get("description")
        if description is not None and not isinstance(description, str):
            raise PatternFileError(f"{where}: 'description' must be a string")
        if name in PARSERS:
            raise PatternFileError(f"{where}: shadows a built-in parser name")
        if (
            name in _registered
            or any(p.name == name for p in _msg_patterns)
            or any(p.name == name for p in loaded)
        ):
            raise PatternFileError(f"{where}: duplicate name")

        kind = entry.get("match", "line")
        if not isinstance(kind, str) or kind not in _MATCH_KINDS:
            raise PatternFileError(f"{where}: 'match' must be 'line' or 'msg' (got {kind!r})")

        regex_src = entry.get("regex")
        if not regex_src or not isinstance(regex_src, str):
            raise PatternFileError(f"{where}: missing 'regex'")
        try:
            regex_src = _expand_shorthands(regex_src)
        except ValueError as exc:
            raise PatternFileError(f"{where}: {exc}") from exc
        try:
            regex = re.compile(regex_src)
        except re.error as exc:
            raise PatternFileError(f"{where}: invalid regex: {exc}") from exc

        groups = set(regex.groupindex)
        reserved = sorted(groups & _RESERVED_GROUPS)
        if reserved:
            raise PatternFileError(
                f"{where}: capture group name(s) {reserved} are reserved for derived fields"
            )

        ts_format: Optional[str] = None
        priority = "after"
        apps: Tuple[str, ...] = ()
        if kind == "msg":
            envelope = sorted(groups & _ENVELOPE_GROUPS)
            if envelope:
                raise PatternFileError(
                    f"{where}: envelope group name(s) {envelope} are not allowed in a "
                    f"msg pattern (it matches the already parsed message)"
                )
            for key in _LINE_ONLY_KEYS:
                if key in entry:
                    raise PatternFileError(
                        f"{where}: '{key}' only applies to line patterns, not 'match': 'msg'"
                    )
            if "app" in entry:
                apps = _parse_apps(entry["app"], where)
        else:
            if "app" in entry:
                raise PatternFileError(
                    f"{where}: 'app' only applies to 'match': 'msg' patterns; "
                    f"capture the app with an (?P<app>...) group instead"
                )
            ts_format = entry.get("timestamp_format")
            if ts_format is not None and not isinstance(ts_format, str):
                raise PatternFileError(f"{where}: 'timestamp_format' must be a string")
            if "ts" in groups:
                if not ts_format:
                    raise PatternFileError(
                        f"{where}: a 'ts' group requires 'timestamp_format' "
                        f"(a strptime format, 'iso8601', or 'epoch')"
                    )
                if ts_format not in _TS_SPECIAL_FORMATS:
                    try:
                        _validate_strptime_format(ts_format)
                    except ValueError as exc:
                        raise PatternFileError(
                            f"{where}: 'timestamp_format' must be a strptime format, "
                            f"'iso8601', or 'epoch': {exc}"
                        ) from exc
            elif ts_format:
                raise PatternFileError(
                    f"{where}: 'timestamp_format' given but the regex has no 'ts' group"
                )

            priority = entry.get("priority", "after")
            if not isinstance(priority, str) or priority not in _PRIORITIES:
                raise PatternFileError(
                    f"{where}: 'priority' must be 'before' or 'after' (got {priority!r})"
                )

        mapping_ref = None
        if "mapping" in entry:
            mapping_ref = entry["mapping"]
            mappings[name] = _resolve_mapping(mapping_ref, path.parent, where)

        examples: List[dict] = []
        if "examples" in entry:
            examples = _validate_examples(entry["examples"], where, warnings)

        loaded.append(
            CustomPattern(
                name=name,
                regex=regex,
                timestamp_format=ts_format,
                priority=priority,
                match=kind,
                apps=apps,
                mapping_ref=mapping_ref,
                examples=examples,
                source=str(path),
                description=description,
                warnings=warnings,
            )
        )

    for pattern in loaded:
        if pattern.match == "msg":
            _msg_patterns.append(pattern)
        else:
            (_before if pattern.priority == "before" else _after).append(pattern)
            _registered[pattern.name] = pattern.parse
        _loaded.append(pattern)
        for warning in pattern.warnings:
            logger.warning("%s: pattern '%s': %s (ignored)", pattern.source, pattern.name, warning)
    _pattern_mappings.update(mappings)
    return len(loaded)
