"""Run the ``examples`` embedded in pattern files (``--check-patterns``).

Each pattern may carry example lines with the fields they should
produce. :func:`run_examples` converts every example line and checks
that the expected pattern matched and the expected fields came out, so
a pattern file can be tested without writing Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, List


@dataclass
class ExampleResult:
    """Outcome of one example. ``index`` is 1-based, as in the report."""

    pattern: str
    index: int
    line: str
    passed: bool
    problems: List[str] = field(default_factory=list)


def _matched_name(event: Any, kind: str) -> Any:
    attr = "msg_pattern" if kind == "msg" else "pattern"
    return getattr(event, attr, None)


def _check_example(pattern: Any, kind: str, example: dict, event: Any) -> List[str]:
    problems: List[str] = []
    name = pattern.name
    matched = _matched_name(event, kind)
    label = "msg pattern" if kind == "msg" else "pattern"

    if not example.get("matches", True):
        if matched == name:
            problems.append(f"expected no match, but {label} {name!r} matched")
        return problems

    if matched != name:
        if matched is None:
            parser = getattr(event, "source_hint", None) or "unknown"
            problems.append(f"{label} {name!r} did not match (no {label} matched; parser: {parser})")
        else:
            problems.append(f"{label} {name!r} did not match ({label} {matched!r} matched instead)")

    expect = example.get("expect") or {}
    if expect:
        fields = event.as_field_dict()
        for key in sorted(expect):
            want = str(expect[key])
            if key not in fields or fields[key] is None:
                problems.append(f"field {key}: expected {want!r}, but it is missing")
                continue
            got = str(fields[key])
            if got != want:
                problems.append(f"field {key}: expected {want!r}, got {got!r}")
    return problems


def run_examples(patterns: Iterable[Any], convert: Callable[[str], Any]) -> List[ExampleResult]:
    """Run every example of every pattern through ``convert``.

    ``patterns`` is any iterable of objects with ``name``, ``match``
    (``"line"`` or ``"msg"``) and ``examples`` (a list of dicts with
    ``line``, optional ``expect`` and optional ``matches``).
    ``convert(line)`` returns a normalized event. An exception from
    ``convert`` fails that example instead of aborting the run.
    """
    results: List[ExampleResult] = []
    for pattern in patterns:
        kind = getattr(pattern, "match", "line") or "line"
        for index, example in enumerate(getattr(pattern, "examples", None) or [], start=1):
            line = example.get("line", "")
            try:
                event = convert(line)
                problems = _check_example(pattern, kind, example, event)
            except Exception as exc:  # report, never crash the run
                problems = [f"conversion error: {type(exc).__name__}: {exc}"]
            results.append(
                ExampleResult(
                    pattern=pattern.name,
                    index=index,
                    line=line,
                    passed=not problems,
                    problems=problems,
                )
            )
    return results


def format_report(results: Iterable[ExampleResult]) -> str:
    """Render results as PASS/FAIL lines plus a totals line (no trailing newline)."""
    results = list(results)
    if not results:
        return "no examples defined"
    lines = []
    for result in results:
        if result.passed:
            lines.append(f"PASS {result.pattern} example {result.index}")
        else:
            lines.append(
                f"FAIL {result.pattern} example {result.index}: {'; '.join(result.problems)}"
            )
    passed = sum(1 for r in results if r.passed)
    lines.append(f"{passed}/{len(results)} examples passed")
    return "\n".join(lines)
