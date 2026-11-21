"""Named regex shorthands for custom pattern files.

Pattern authors can write ``%{NAME}`` in a regex to insert the regex for a
common token, or ``%{NAME:field}`` to insert it as a named capture group::

    from [%{IP:src}] port %{PORT:spt}

``%{NAME}`` expands to a non-capturing group ``(?:...)`` so it never adds a
group of its own. ``%{NAME:field}`` expands to ``(?P<field>...)``. Every
shorthand regex is free of capturing groups and avoids nested unbounded
quantifiers, so expansion does not introduce catastrophic backtracking.
"""

from __future__ import annotations

import re
from typing import Dict

__all__ = ["SHORTHANDS", "expand"]

_IPV4 = (
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
)
# The IPv4-suffix alternative comes first: with re.search nothing forces
# the whole address to be consumed, so trying the hex group first would
# capture "::ffff:192" out of "::ffff:192.168.1.1".
_IPV6 = r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?"

SHORTHANDS: Dict[str, str] = {
    "IPV4": _IPV4,
    "IPV6": _IPV6,
    "IP": "(?:" + _IPV4 + "|" + _IPV6 + ")",
    "INT": r"[+-]?\d+",
    "NUMBER": r"[+-]?\d+(?:\.\d+)?",
    "PORT": r"\d{1,5}",
    "WORD": r"\w+",
    "NOTSPACE": r"\S+",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "HOSTNAME": r"[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*\.?",
    "USER": r"[A-Za-z0-9._@-]+",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    "SYSLOGTIMESTAMP": r"[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}",
    "TIMESTAMP_ISO8601": (
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    "QUOTEDSTRING": r'"(?:[^"\\]|\\.)*"',
    "PATH": r"(?:/[^/\s]*)+",
    "LOGLEVEL": (
        r"(?i:emerg|alert|crit(?:ical)?|err(?:or)?|warn(?:ing)?|notice|info|debug)"
    ),
}

_TOKEN = re.compile(r"%\{([A-Z][A-Z0-9_]*)(?::([A-Za-z_][A-Za-z0-9_]*))?\}")


def expand(regex: str) -> str:
    """Replace ``%{NAME}`` and ``%{NAME:field}`` tokens in *regex*.

    Text that is not a token is returned unchanged. Raises ``ValueError``
    for an unknown shorthand name.
    """

    def _replace(match: "re.Match[str]") -> str:
        name, field = match.group(1), match.group(2)
        if name not in SHORTHANDS:
            raise ValueError(
                "unknown shorthand %{"
                + name
                + "}; known: "
                + ", ".join(sorted(SHORTHANDS))
            )
        body = SHORTHANDS[name]
        if field is None:
            return "(?:" + body + ")"
        return "(?P<" + field + ">" + body + ")"

    return _TOKEN.sub(_replace, regex)
