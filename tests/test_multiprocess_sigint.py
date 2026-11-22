"""--multiprocess input handling: Ctrl-C on never-ending input, order, errors.

The process pool must not be left waiting on an input that never ends:
SIGINT exits with status 130, without a traceback, and takes every
worker process with it.
"""

from __future__ import annotations

import os
import queue
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

needs_sigint = pytest.mark.skipif(sys.platform == "win32", reason="needs SIGINT and process groups")

REPO_ROOT = Path(__file__).resolve().parent.parent
RFC3164 = "<34>Oct 11 22:14:15 mymachine su[123]: user=alice action=login"

# Seconds the CLI may take to exit after SIGINT before the test calls it hung.
EXIT_TIMEOUT = 10


def _children(pid: int) -> list | None:
    """Direct children of *pid*, or None when they cannot be listed."""
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        psutil = None
    if psutil is not None:
        try:
            return [child.pid for child in psutil.Process(pid).children()]
        except psutil.NoSuchProcess:
            return []
    pgrep = shutil.which("pgrep")
    if pgrep is None:
        return None
    result = subprocess.run([pgrep, "-P", str(pid)], capture_output=True, text=True)
    if result.returncode not in (0, 1):  # 1 means no match
        return None
    return [int(token) for token in result.stdout.split()]


def _descendants(pid: int) -> list | None:
    """All descendants of *pid* (pool workers may sit under a forkserver)."""
    found = []
    pending = [pid]
    while pending:
        children = _children(pending.pop())
        if children is None:
            return None
        found.extend(children)
        pending.extend(children)
    return found


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _Cli:
    """The CLI in its own process group, with its pipes drained by threads.

    Reader threads feed a queue instead of select() on the buffered text
    pipe, which can miss lines already pulled into the buffer.
    """

    def __init__(self, argv):
        # An ignored SIGINT is inherited across exec: the CLI would never
        # see the Ctrl-C and the test would report a false hang.
        assert signal.getsignal(signal.SIGINT) is not signal.SIG_IGN, "SIGINT is ignored in the test process"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "syslogcef", *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO_ROOT,
            start_new_session=True,
        )
        self.lines: queue.Queue = queue.Queue()
        self.err: list = []
        self._threads = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, self.lines.put), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, self.err.append), daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    @staticmethod
    def _pump(pipe, sink):
        for line in pipe:
            sink(line)
        sink(None)

    def wait_for_output(self, feed, timeout: float = 30) -> str:
        """Call *feed* until the first stdout line arrives; return it."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            feed()
            try:
                line = self.lines.get(timeout=0.2)
            except queue.Empty:
                continue
            assert line is not None, "syslogcef exited early: " + "".join(filter(None, self.err))
            return line
        pytest.fail("no output from syslogcef")

    def wait_until_quiet(self, quiet: float = 1.5, timeout: float = 30) -> None:
        """Read stdout until no line arrives for *quiet* seconds.

        Every line fed so far has then been converted and the input is
        idle, blocked waiting for more: the state Ctrl-C must handle.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=quiet)
            except queue.Empty:
                return
            assert line is not None, "syslogcef exited early: " + "".join(filter(None, self.err))
        pytest.fail("syslogcef output never went quiet")

    def interrupt(self):
        """Ctrl-C as a terminal sends it: SIGINT to the whole process group."""
        os.killpg(self.proc.pid, signal.SIGINT)
        try:
            status = self.proc.wait(timeout=EXIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            pytest.fail(f"syslogcef did not exit within {EXIT_TIMEOUT}s of SIGINT")
        for thread in self._threads:
            thread.join(timeout=5)
        return status, "".join(filter(None, self.err))

    def kill(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # macOS reports EPERM for a group left with only zombies.
                pass
            self.proc.wait()
        for pipe in (self.proc.stdout, self.proc.stderr):
            pipe.close()


def _assert_interrupted_cleanly(cli: _Cli, feed):
    assert cli.wait_for_output(feed).startswith("CEF:0|")
    cli.wait_until_quiet()
    workers = _descendants(cli.proc.pid)
    status, err = cli.interrupt()

    assert status == 130, err
    assert "Traceback" not in err
    assert "KeyboardInterrupt" not in err
    if workers is None:
        return  # no psutil or pgrep: cannot look for orphans
    assert workers, "expected pool worker processes"
    # Orphans would be reparented and keep running; give init a moment to
    # reap workers that exited along with the parent.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(_alive(pid) for pid in workers):
        time.sleep(0.1)
    assert not [pid for pid in workers if _alive(pid)], "worker processes left running"


@needs_sigint
def test_tail_multiprocess_interrupt_exits_130(tmp_path: Path):
    log = tmp_path / "in.log"
    log.write_text("", encoding="utf-8")

    def feed():
        with log.open("a", encoding="utf-8") as fp:
            fp.write(RFC3164 + "\n")

    cli = _Cli(["--tail", "--multiprocess", "--pool-size", "2", str(log)])
    try:
        _assert_interrupted_cleanly(cli, feed)
    finally:
        cli.kill()


@needs_sigint
def test_listen_multiprocess_interrupt_exits_130():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def feed():
        sender.sendto(RFC3164.encode("utf-8"), ("127.0.0.1", port))

    cli = _Cli(["--listen", f"udp:127.0.0.1:{port}", "--multiprocess", "--pool-size", "2"])
    try:
        _assert_interrupted_cleanly(cli, feed)
    finally:
        cli.kill()
        sender.close()


def test_multiprocess_keeps_input_order_across_chunks():
    from syslogcef.cli import process_lines

    # Several pool tasks' worth of distinct lines, so out-of-order results
    # would show.
    lines = [f"<34>Oct 11 22:14:15 host{i} su[{i}]: user=u{i} action=login" for i in range(2000)]
    kwargs = dict(mode=None, mapping=None, pool_size=2)

    expected = list(process_lines(lines, use_multiprocessing=False, **kwargs))
    assert list(process_lines(lines, use_multiprocessing=True, **kwargs)) == expected


def test_multiprocess_input_error_after_earlier_records():
    from syslogcef.cli import process_lines

    def lines():
        yield RFC3164
        yield RFC3164
        raise OSError("input failed")

    out = []
    with pytest.raises(OSError, match="input failed"):
        for cef in process_lines(lines(), mode=None, mapping=None, use_multiprocessing=True, pool_size=1):
            out.append(cef)
    assert len(out) == 2
    assert all(cef.startswith("CEF:0|") for cef in out)


def test_multiprocess_strict_failure_after_earlier_records():
    from syslogcef.cli import process_lines
    from syslogcef.validation import CEFValidationError

    good = "<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: Built inbound src=10.0.0.1 dst=10.0.0.2"
    bad = "<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: x src=notanip"
    # One pool task: the records before the failing line still come out,
    # in order, as they did when every line was its own task.
    lines = [good] * 5 + [bad] + [good] * 3

    out = []
    with pytest.raises(CEFValidationError):
        for cef in process_lines(lines, mode=None, mapping=None, use_multiprocessing=True, pool_size=1, validate=True, strict=True):
            out.append(cef)
    assert len(out) == 5
