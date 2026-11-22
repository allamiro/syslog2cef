from __future__ import annotations

import argparse
import logging
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from ._version import __author__, __copyright__, __email__, __license__, __version__
from .api import StreamConverter, _convert_forced_fallback, _log_rejected_line

logger = logging.getLogger(__name__)


def iter_lines_from_sources(paths: Iterable[Path] | None, *, tag_sources: bool = False) -> Iterator[Any]:
    """Yield lines from stdin or the given files.

    With ``tag_sources`` each item is ``(source, line)`` so downstream
    continuation handling can keep per-file context instead of letting
    an indented line at the top of one file inherit the previous file's
    host and timestamp.
    """
    if not paths:
        for line in sys.stdin:
            line = line.rstrip("\n")
            yield ("stdin", line) if tag_sources else line
        return

    for path in paths:
        source = str(path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                yield (source, line) if tag_sources else line


def tail_file(path: Path, *, follow: bool = False) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            line = handle.readline()
            if not line:
                if not follow:
                    break
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


class _Follower:
    """One tailed path, surviving rotation (rename, replace, truncate)."""

    _FINGERPRINT_LEN = 256

    def __init__(self, path: Path):
        from collections import deque

        self.path = path
        self.handle = path.open("r", encoding="utf-8", errors="replace")
        self.signature = self._fsignature()
        # Fingerprint of the *already-consumed* head of the file. Those
        # bytes are stable across appends (which only add data past our
        # offset) but change when a copy-truncate rewrites the file in
        # place, so comparing them detects rewrites the size/inode check
        # misses. Length is bounded by both _FINGERPRINT_LEN and our read
        # offset, so a plain append to a short file is never mistaken for
        # a rewrite.
        self.fp_len = 0
        self.fingerprint = b""
        self.pending = deque()
        # Start of a line whose newline has not been written yet.
        self.partial = ""

    def _fsignature(self):
        import os

        st = os.fstat(self.handle.fileno())
        return (st.st_dev, st.st_ino)

    def _read_head(self, length: int) -> bytes:
        # Positional read so the follow position is untouched.
        import os

        if self.handle is None or length <= 0:
            return b""
        try:
            return os.pread(self.handle.fileno(), length, 0)
        except (OSError, AttributeError):
            return b""

    def _capture_fingerprint(self) -> None:
        if self.handle is None:
            self.fp_len, self.fingerprint = 0, b""
            return
        self.fp_len = min(self._FINGERPRINT_LEN, self.handle.tell())
        self.fingerprint = self._read_head(self.fp_len)

    def read_lines(self, limit: Optional[int] = None) -> Iterator[str]:
        """Yield available lines, at most ``limit`` of them when given."""
        count = 0
        while self.pending and (limit is None or count < limit):
            count += 1
            yield self.pending.popleft()
        if self.handle is None:
            return
        while limit is None or count < limit:
            chunk = self.handle.readline()
            if not chunk:
                break
            if not chunk.endswith("\n"):
                # The writer is mid-line: hold the fragment until the
                # newline arrives instead of emitting the line in pieces.
                self.partial += chunk
                break
            line, self.partial = self.partial + chunk, ""
            count += 1
            yield line.rstrip("\n")
        # Record the consumed-head fingerprint so the next rotation check
        # can tell an append from an in-place rewrite. Also done when the
        # limit stops us short of EOF, so a file that never goes idle still
        # gets one.
        self._capture_fingerprint()

    def check_rotation(self) -> bool:
        """Reattach after rotation events. Returns True if a replacement
        file was (re)opened or the file was rewound.

        Runs every pass, not only when idle: a file that is renamed away
        while still being written keeps this follower producing from the
        stale descriptor forever, so a replacement at the original path
        would never be picked up if rotation were checked only on idle
        polls.

        - rename-and-recreate: the path's dev/inode changes; drain any
          remaining lines from the old descriptor, then open the new
          file from the start.
        - copy-truncate: same inode but size below our offset; rewind.
        - temporary disappearance mid-rotation: keep the old descriptor
          (it stays readable) and retry until a replacement appears.
        """
        if self.handle is None:
            try:
                self.handle = self.path.open("r", encoding="utf-8", errors="replace")
                self.signature = self._fsignature()
                self.fp_len, self.fingerprint = 0, b""
                return True
            except OSError:
                return False
        try:
            st = self.path.stat()
        except OSError:
            return False
        if (st.st_dev, st.st_ino) != self.signature:
            for line in self.handle:
                self.pending.append((self.partial + line).rstrip("\n"))
                self.partial = ""
            # The old file is finished, so an unterminated last line is
            # as complete as it will get.
            if self.partial:
                self.pending.append(self.partial)
                self.partial = ""
            self.handle.close()
            self.handle = None
            return self.check_rotation()  # open the replacement immediately
        # Copy-truncate: same inode, but either the file shrank below our
        # offset, or the already-consumed head changed (an in-place rewrite
        # that regrew past our offset). Comparing only the consumed prefix
        # means a plain append — which never touches those bytes — is not
        # mistaken for a rewrite, even for a file shorter than the cap.
        offset = self.handle.tell()
        rewound = False
        if offset > 0:
            if st.st_size < offset:
                rewound = True
            elif self.fp_len and self._read_head(self.fp_len) != self.fingerprint:
                rewound = True
        if rewound:
            # The rest of a held fragment went to the rotated copy; emit
            # what we have rather than drop it.
            if self.partial:
                self.pending.append(self.partial)
                self.partial = ""
            self.handle.seek(0)
            self.fp_len, self.fingerprint = 0, b""
        return rewound

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


_LINES_PER_PASS = 100


def follow_files(
    paths: Iterable[Path],
    *,
    poll_interval: float = 0.5,
    max_idle_polls: Optional[int] = None,
    tag_sources: bool = False,
) -> Iterator[Any]:
    """Tail several files at once, round-robin, yielding lines as they appear.

    Survives log rotation on every path independently: renamed-and-
    recreated files are reopened from the start (after draining the old
    descriptor), copy-truncated files are rewound, and paths that
    disappear mid-rotation are retried until a replacement appears.

    ``max_idle_polls`` bounds how many consecutive empty polls are allowed
    before the generator stops; ``None`` follows forever.

    With ``tag_sources`` each item is ``(path, line)``: the round-robin
    interleaves files, so continuation context downstream must be keyed
    per file rather than shared across them.
    """

    followers = [_Follower(path) for path in paths]
    idle_polls = 0
    try:
        while True:
            any_line = False
            for follower in followers:
                # Rotation is checked for every follower on every pass —
                # including busy ones — so a file renamed away while still
                # being written cannot pin this follower to the stale
                # descriptor and starve the replacement at the origin path.
                # It runs before the read: a copy-truncate that happened
                # during the sleep and regrew past our offset must be
                # detected before reading resumes at the stale offset and
                # refreshes the fingerprint from the rewritten head.
                follower.check_rotation()
                source = str(follower.path)
                # Bounded per pass: a file that is written as fast as we
                # read never reaches EOF and would otherwise starve the
                # files after it.
                for line in follower.read_lines(limit=_LINES_PER_PASS):
                    any_line = True
                    yield (source, line) if tag_sources else line
            if any_line:
                idle_polls = 0
                continue
            idle_polls += 1
            if max_idle_polls is not None and idle_polls >= max_idle_polls:
                return
            time.sleep(poll_interval)
    finally:
        for follower in followers:
            follower.close()


# Portable strftime codes with at-coarsest one-second granularity.
# %f (microseconds) is excluded so a rendered path can only change once
# per second; platform extensions (%e, %s, %-d, ...) are excluded so
# templates behave identically on glibc and musl.
_STRFTIME_CODES = frozenset("aAbBcdGHIjmMpSuUVwWxXyYzZ")


def template_has_codes(text: str) -> bool:
    """Return True if *text* contains supported strftime codes.

    ``%%`` is a literal percent. Any other ``%`` sequence, including a
    trailing ``%``, raises ValueError so typos like ``%Q`` fail at
    startup instead of silently producing a literal filename (glibc
    passes unknown codes through rather than raising).
    """
    templated = False
    i = 0
    while i < len(text):
        if text[i] == "%":
            if i + 1 >= len(text):
                raise ValueError("trailing '%' (use '%%' for a literal percent)")
            nxt = text[i + 1]
            if nxt in _STRFTIME_CODES:
                templated = True
            elif nxt != "%":
                raise ValueError(f"unsupported strftime code '%{nxt}' (use '%%' for a literal percent)")
            i += 2
        else:
            i += 1
    return templated


def write_lines(
    outputs: Iterable[str],
    template: Path,
    *,
    append: bool,
    stream_flush: bool,
    sender=None,
) -> None:
    """Write CEF lines to ``template``.

    A path containing strftime codes is re-rendered as time passes and
    the file is reopened whenever the rendered path changes, e.g.
    ``/var/log/syslogcef/%Y-%m-%d/events-%H.cef`` starts a new file each
    hour. Templated paths are always opened in append mode and their
    parent directories are created; paths without codes (``%%`` renders
    as a literal percent) keep the truncate/append behaviour selected by
    ``append``.
    """
    text = str(template)
    if not template_has_codes(text):
        if "%" in text:
            # Rendered (%%-escaped) paths get the same parent-creation
            # guarantee as templated ones; untouched paths keep the old
            # fail-if-missing behaviour.
            path = Path(datetime.now().astimezone().strftime(text))
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path = template
        with path.open("a" if append else "w", encoding="utf-8") as fp:
            for cef in outputs:
                fp.write(cef + "\n")
                if stream_flush:
                    fp.flush()
                if sender:
                    sender.send(cef)
        return

    fp = None
    current = None
    last_tick = None
    try:
        for cef in outputs:
            # Aware local datetime so %z/%Z render the real offset/name
            # instead of the empty string a naive datetime produces.
            now = datetime.now().astimezone()
            tick = now.replace(microsecond=0)
            if tick != last_tick:
                last_tick = tick
                rendered = now.strftime(text)
                if rendered != current:
                    if fp:
                        fp.close()
                    path = Path(rendered)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    fp = path.open("a", encoding="utf-8")
                    current = rendered
            fp.write(cef + "\n")
            if stream_flush:
                fp.flush()
            if sender:
                sender.send(cef)
    finally:
        if fp:
            fp.close()


def _convert_line_mp(line: str, mode: Optional[str], mapping: Any, validate: bool = False, strict: bool = False) -> tuple:
    """Convert one line in a pool worker; returns ``(cef, rejected_line)``.

    A line a forced ``--mode`` rejects is converted as a raw-message event,
    as in the single-process path, so one malformed line cannot stop the
    run. ``rejected_line`` is that line (else None): the parent logs it, so
    the first-line warning appears once rather than once per worker.
    """
    cef, rejected = _convert_forced_fallback(line, mode=mode, mapping=mapping, now=None, validate=validate, strict=strict)
    return cef, (line if rejected else None)


def _mp_load_patterns(pattern_files: list) -> None:
    import signal

    from .custom import clear_patterns, load_patterns

    # Ctrl-C reaches the whole process group; the parent handles it and
    # tears the pool down, so workers must not print tracebacks of their own.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # The parent already logged any pattern file warnings at startup;
    # don't repeat them once per worker.
    logging.getLogger("syslogcef.custom").setLevel(logging.ERROR)
    # Reload pattern files in each pool worker so --patterns works with
    # --multiprocess. Clear first: under the fork start method workers
    # inherit the parent's already-populated registry, and reloading into
    # it would fail every worker with duplicate-name errors. Parsers from
    # register_parser() are kept: a worker cannot recreate them.
    clear_patterns()
    for path in pattern_files:
        load_patterns(path)


def _split_item(item: Any) -> tuple:
    # Line iterators may tag items as (source, line); untagged plain
    # strings share the "" source.
    if isinstance(item, tuple):
        return item
    return ("", item)


def _convert_chunk_mp(lines: list, mode: Optional[str], mapping: Any, validate: bool = False, strict: bool = False) -> tuple:
    """Convert a chunk of lines in a pool worker; returns ``(results, error)``.

    ``results`` holds one :func:`_convert_line_mp` tuple per line converted.
    A line that raises (e.g. ``--strict`` validation) ends the chunk: the
    exception is returned as ``error`` so the parent can emit the records
    before it, in order, and then raise it, as a per-line ``imap`` would.
    """
    results = []
    try:
        for line in lines:
            results.append(_convert_line_mp(line, mode, mapping, validate=validate, strict=strict))
    except Exception as exc:
        return results, exc
    return results, None


# Lines per pool task under --multiprocess, and pool tasks in flight per
# worker. A chunk is only as large as the input already waiting, so a
# --tail or --listen line is converted as soon as it arrives.
_MP_CHUNK = 256
_MP_TASKS_PER_WORKER = 4
# Seconds between checks for Ctrl-C while blocked (lock waits are not
# interruptible on every platform).
_MP_POLL = 0.5

_INPUT_END = object()


class _InputFailed:
    """Carries an exception raised by the input iterator to the consumer."""

    __slots__ = ("exc",)

    def __init__(self, exc: BaseException):
        self.exc = exc


def _read_input(lines: Iterable[Any], feed: queue.Queue, stop: threading.Event) -> None:
    """Move lines from ``lines`` to ``feed`` until the input ends or ``stop`` is set.

    Runs in a daemon thread: ``--tail`` and ``--listen`` inputs block
    forever waiting for data, so the thread that waits on them must not
    be one the process has to join to exit (it would be the pool's task
    handler if ``lines`` went to ``imap`` directly).
    """

    def put(item: Any) -> bool:
        while not stop.is_set():
            try:
                feed.put(item, timeout=_MP_POLL)
                return True
            except queue.Full:
                pass
        return False

    iterator = iter(lines)
    try:
        for item in iterator:
            if not put(_split_item(item)[1]):
                return
    except BaseException as exc:  # re-raised by the consuming thread
        put(_InputFailed(exc))
    else:
        put(_INPUT_END)
    finally:
        close = getattr(iterator, "close", None)
        if close is not None:
            close()


def _take_chunk(feed: queue.Queue, *, block: bool) -> tuple:
    """Return ``(lines, end)``: up to ``_MP_CHUNK`` waiting lines and the end marker, if reached.

    With ``block`` waits for the first line; otherwise takes only what is
    already queued.
    """
    lines: list = []
    while len(lines) < _MP_CHUNK:
        try:
            if block and not lines:
                item = feed.get(timeout=_MP_POLL)
            else:
                item = feed.get_nowait()
        except queue.Empty:
            if block and not lines:
                continue
            break
        if item is _INPUT_END or isinstance(item, _InputFailed):
            return lines, item
        lines.append(item)
    return lines, None


def _process_lines_mp(lines: Iterable[Any], *, mode: Optional[str], mapping: Any, pool_size: Optional[int], validate: bool, strict: bool, pattern_files: Optional[list]) -> Iterator[str]:
    """Convert lines in a process pool, yielding CEF records in input order.

    A daemon thread reads the input into a bounded queue; this thread is
    the only one that feeds the pool, a chunk of already-waiting lines at
    a time, and it never hands the pool an input that can block. So
    Ctrl-C reaches it directly and the pool shuts down at once, even when
    ``lines`` never ends (``--tail``, ``--listen``).
    """
    size = pool_size or max(1, cpu_count() - 1)
    max_pending = size * _MP_TASKS_PER_WORKER
    feed: queue.Queue = queue.Queue(maxsize=_MP_CHUNK * max_pending)
    stop = threading.Event()
    with Pool(size, initializer=_mp_load_patterns, initargs=(pattern_files or [],)) as pool:
        convert = partial(_convert_chunk_mp, mode=mode, mapping=mapping, validate=validate, strict=strict)
        reader = threading.Thread(target=_read_input, args=(lines, feed, stop), name="syslogcef-input", daemon=True)
        reader.start()
        try:
            pending: deque = deque()
            end = None
            rejected_lines = 0
            while True:
                # Submit what input is waiting; block for more only when
                # nothing is in flight, so finished records are never held
                # back waiting for the next line to arrive.
                while end is None and len(pending) < max_pending:
                    chunk, end = _take_chunk(feed, block=not pending)
                    if not chunk:
                        break
                    pending.append(pool.apply_async(convert, (chunk,)))
                if not pending:
                    break
                task = pending.popleft()
                while not task.ready():
                    task.wait(_MP_POLL)
                results, error = task.get()
                for cef, rejected_line in results:
                    if rejected_line is not None:
                        rejected_lines += 1
                        _log_rejected_line(mode, rejected_line, first=rejected_lines == 1)
                    yield cef
                if error is not None:
                    raise error
            if isinstance(end, _InputFailed):
                raise end.exc
        finally:
            stop.set()


def process_lines(
    lines: Iterable[Any],
    *,
    mode: Optional[str],
    mapping: Any,
    use_multiprocessing: bool,
    pool_size: Optional[int],
    validate: bool = False,
    strict: bool = False,
    pattern_files: Optional[list] = None,
    explain: bool = False,
    stats: Any = None,
) -> Iterator[str]:
    """Convert lines to CEF records.

    With ``explain`` each item is an ``--explain`` block instead of a bare
    CEF record (blocks after the first start with a blank line). With
    ``stats`` (a :class:`syslogcef.explain.Stats`) every converted event is
    counted. Neither is available with ``use_multiprocessing``.
    """
    if use_multiprocessing:
        yield from _process_lines_mp(lines, mode=mode, mapping=mapping, pool_size=pool_size, validate=validate, strict=strict, pattern_files=pattern_files)
    else:
        # Stateful conversion so whitespace-indented continuation lines
        # inherit host/app/timestamp from the preceding event, keyed by
        # source so interleaved files never cross-inherit. Unavailable
        # under --multiprocess, where workers cannot share line order.
        # A line a forced --mode rejects is converted raw with a warning
        # rather than raised: one malformed datagram must not stop a
        # --listen receiver (or a --tail/file run).
        converter = StreamConverter(mode=mode, mapping=mapping, validate=validate, strict=strict, on_parse_error="raw")
        if not (explain or stats is not None):
            for item in lines:
                source, line = _split_item(item)
                yield converter.convert(line, source=source)
            return

        from .explain import format_explain, mapping_label

        for index, item in enumerate(lines, start=1):
            source, line = _split_item(item)
            cef, event = converter.convert_event(line, source=source)
            if stats is not None:
                stats.add(event)
            if explain:
                block = format_explain(index, event, cef, mapping_label(event, converter.mapping))
                yield block if index == 1 else "\n" + block
            else:
                yield cef


def _optional_path(value: str) -> Optional[Path]:
    # An empty --output (e.g. OUTPUT_FILE= left blank in the service
    # environment file) means stdout, not a file named "".
    return Path(value) if value else None


# GNU-style --version text: name and version first (scripts parse it),
# then copyright, license, and authorship.
VERSION_TEXT = (
    f"syslogcef {__version__}\n"
    f"{__copyright__}\n"
    f"License {__license__}: <https://opensource.org/licenses/{__license__}>\n"
    "This is free software: you are free to change and redistribute it.\n"
    "There is NO WARRANTY, to the extent permitted by law.\n"
    "\n"
    f"Written by {__author__} <{__email__}>."
)


# Exit status for a run stopped with Ctrl-C (SIGINT), as shells report it.
EXIT_INTERRUPTED = 130


def main(argv: Optional[list[str]] = None) -> int:
    """Run the command line; returns the exit status.

    Ctrl-C (KeyboardInterrupt) ends ``--tail`` and ``--listen`` runs, so
    it exits with status 130 and no traceback. Any ``--stats`` summary is
    printed before that, while the interrupt unwinds the conversion loop.
    """
    try:
        return _main(argv)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


def _main(argv: Optional[list[str]] = None) -> int:
    # prog is explicit so "python -m syslogcef --help" reports the command
    # name rather than "__main__.py". RawDescriptionHelpFormatter keeps
    # VERSION_TEXT's line breaks; argparse otherwise reflows the version
    # string onto one line. Option help is still wrapped as before.
    parser = argparse.ArgumentParser(
        prog="syslogcef",
        description="Convert syslog lines to ArcSight CEF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", type=Path, help="Input files (defaults to stdin)")
    parser.add_argument("-o", "--output", type=_optional_path, help="Output file; strftime codes such as %%Y-%%m-%%d or %%H start a new file when the rendered path changes (templated paths always append and parent directories are created). Use %%%% for a literal percent; unsupported codes are rejected. An empty value means stdout.")
    parser.add_argument("-a", "--append", action="store_true", help="Append to --output instead of truncating it (implied for templated paths)")
    parser.add_argument("--mode", help="Parser mode override: rfc3164, rfc5424, rsyslog_json, rsyslog_file, journald_json, journald_short, journald_iso, cisco_seq, iso_syslog, kv, or a name from --patterns")
    parser.add_argument("--mapping", type=str, help="Mapping JSON file")
    parser.add_argument("--patterns", action="append", metavar="FILE", help="JSON file of custom parser patterns (named regexes); may be given multiple times. See the man page for the format.")
    parser.add_argument("--tail", action="store_true", help="Follow file like tail -f")
    parser.add_argument("--check-patterns", action="store_true", help="Run the examples in the --patterns files, print PASS/FAIL per example and a total, then exit (status 1 if any fail); reads no input")
    parser.add_argument("--listen", metavar="PROTO:PORT", help="Receive syslog over the network instead of reading files/stdin, e.g. udp:514, tcp:5514, or udp:10.0.0.5:514")
    parser.add_argument("--send", metavar="URL", help="Forward CEF records to udp://HOST:PORT, tcp://HOST:PORT (newline-delimited, with reconnect), or kafka://BROKER:PORT/TOPIC (requires the kafka extra)")
    parser.add_argument("--eps", type=float, help="Rate-limit --send to at most this many events per second")
    parser.add_argument("--multiprocess", action="store_true", help="Process lines using a process pool")
    parser.add_argument("--pool-size", type=int, help="Number of worker processes for --multiprocess")
    parser.add_argument("--validate", action="store_true", help="Validate CEF extensions against the ArcSight dictionary; violations are logged as warnings")
    parser.add_argument("--strict", action="store_true", help="Like --validate, but exit with an error on type/length violations")
    parser.add_argument("--explain", action="store_true", help="Instead of bare CEF, print one block per input line showing the parser, matching patterns, mapping, extracted fields and the CEF record (not with --send, --output or --multiprocess)")
    parser.add_argument("--stats", action="store_true", help="When input ends (or on interrupt), print to stderr how many lines each parser and msg pattern matched, plus samples of unmatched lines (not with --multiprocess)")
    parser.add_argument("--log-level", default="WARNING", help="Logging level")
    parser.add_argument(
        "--version",
        action="version",
        version=VERSION_TEXT,
        help="Show the version, license and author, then exit",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING))

    # Reject invalid option combinations before any file, socket, or
    # pool side effects (#89): mistakes in service environment files
    # must fail with a clear message, not a traceback or silence.
    if args.pool_size is not None and not args.multiprocess:
        parser.error("--pool-size requires --multiprocess")
    if args.multiprocess and args.pool_size is not None and args.pool_size < 1:
        parser.error(f"--pool-size must be a positive integer (got {args.pool_size})")
    if args.eps is not None and not args.send:
        parser.error("--eps requires --send")
    if args.listen and args.paths:
        parser.error("--listen replaces file input; remove the positional paths")
    if args.tail and not args.paths:
        parser.error("--tail requires input file paths")
    if args.explain:
        for flag, given in (("--send", args.send), ("--output", args.output), ("--multiprocess", args.multiprocess)):
            if given:
                parser.error(f"--explain cannot be combined with {flag}")
    if args.stats and args.multiprocess:
        parser.error("--stats cannot be combined with --multiprocess")

    if args.output:
        try:
            template_has_codes(str(args.output))
        except ValueError as exc:
            parser.error(f"invalid --output template: {exc}")

    if args.patterns:
        from .custom import PatternFileError, load_patterns

        for pattern_file in args.patterns:
            try:
                load_patterns(pattern_file)
            except PatternFileError as exc:
                parser.error(str(exc))

    if args.check_patterns:
        if not args.patterns:
            parser.error("--check-patterns requires at least one --patterns FILE")
        given = [opt for opt, on in (("PATHS", args.paths), ("--listen", args.listen), ("--tail", args.tail)) if on]
        if given:
            parser.error(f"--check-patterns reads no input; remove {', '.join(given)}")
        from .api import normalize_event, parse_syslog
        from .custom import loaded_patterns
        from .pattern_check import format_report, run_examples

        results = run_examples(loaded_patterns(), lambda line: normalize_event(parse_syslog(line)))
        print(format_report(results))
        return 0 if all(result.passed for result in results) else 1

    if args.mode:
        from .custom import get_registered
        from .parsers import PARSERS

        if args.mode not in PARSERS and get_registered(args.mode) is None:
            parser.error(f"unknown --mode '{args.mode}' (not a built-in parser or a loaded pattern name)")

    # Load and validate the mapping eagerly (#84): a missing or malformed
    # file must fail before the output is opened — a truncate-mode open
    # would destroy an existing archive before the lazy first-event load
    # ever ran. Loading once here also avoids re-reading the JSON file
    # for every converted line.
    mapping = None
    if args.mapping is not None:
        # An explicitly empty --mapping (e.g. MAPPING= blank in a service
        # environment file) is a misconfiguration, not "use the default":
        # silently proceeding would truncate an existing --output with an
        # unintended mapping. Fail before any file is opened.
        if not args.mapping.strip():
            parser.error("--mapping was given an empty value")
        from .api import _load_mapping

        try:
            mapping = _load_mapping(args.mapping)
        except (OSError, ValueError) as exc:
            parser.error(f"invalid --mapping: {exc}")

    stats = None
    if args.stats:
        from .explain import Stats

        stats = Stats()

    outputs: Iterator[str]
    if args.listen:
        from .net import listen_lines, parse_endpoint

        try:
            proto, host, port = parse_endpoint(args.listen)
        except ValueError as exc:
            parser.error(str(exc))
        lines = listen_lines(proto, host, port)
        outputs = process_lines(lines, mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns, explain=args.explain, stats=stats)
    elif args.tail and args.paths:
        outputs = process_lines(follow_files(args.paths, tag_sources=True), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns, explain=args.explain, stats=stats)
    else:
        outputs = process_lines(iter_lines_from_sources(args.paths, tag_sources=True), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns, explain=args.explain, stats=stats)

    sender = None
    if args.send:
        from .net import create_sender

        try:
            sender = create_sender(args.send, eps=args.eps)
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))

    from .validation import CEFValidationError

    try:
        if args.output:
            write_lines(
                outputs,
                args.output,
                append=args.append,
                stream_flush=bool(args.tail or args.listen),
                sender=sender,
            )
        elif sender:
            for cef in outputs:
                sender.send(cef)
        else:
            stream_flush = bool(args.tail or args.listen)
            for cef in outputs:
                print(cef, flush=stream_flush)
    except CEFValidationError as exc:
        print(f"syslogcef: strict validation failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if sender:
            sender.close()
        if stats is not None:
            # Also reached on KeyboardInterrupt, so --tail/--listen runs
            # report their counts when stopped.
            print(stats.format(), file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
