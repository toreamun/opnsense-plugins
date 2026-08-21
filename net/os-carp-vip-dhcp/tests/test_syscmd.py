"""Unit tests for syscmd, the daemon's single system-command boundary.

run() (synchronous, None on launch failure) and spawn() (fire-and-forget, RAISES
on launch failure) have opposite failure contracts on purpose; the callers depend
on the difference (route/status branch on None; FollowPolicy re-drives on a raise),
so both are pinned here alongside the ifconfig() helper. Comments over docstrings.
"""
# pylint: disable=missing-function-docstring
import subprocess
import types

import pytest

from leasekeeper import syscmd  # sys.path via conftest  # type: ignore


def _cp(returncode=0, stdout=""):
    # Stand-in for subprocess.run's CompletedProcess (only the fields syscmd reads).
    return types.SimpleNamespace(returncode=returncode, stdout=stdout)


def test_run_returns_completedprocess_on_success(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run", lambda *a, **k: _cp(0, "ok"))
    res = syscmd.run(["/bin/true"])
    assert res is not None and res.returncode == 0 and res.stdout == "ok"


def test_run_returns_completedprocess_on_nonzero(monkeypatch):
    # A non-zero exit is NOT a launch failure: the caller still gets the object
    # so it can read the code and output.
    monkeypatch.setattr(syscmd.subprocess, "run", lambda *a, **k: _cp(1, "boom"))
    res = syscmd.run(["/bin/false"])
    assert res is not None and res.returncode == 1


def test_run_returns_none_on_launch_failure_and_warns(monkeypatch, caplog):
    def boom(*_a, **_k):
        raise OSError("no such binary")
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    with caplog.at_level("WARNING", logger=syscmd.LOG.name):
        assert syscmd.run(["/nope"]) is None
    assert any("command failed to run" in r.getMessage() for r in caplog.records)


def test_run_none_on_timeout(monkeypatch):
    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=5)
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    assert syscmd.run(["/slow"]) is None


def test_run_quiet_suppresses_the_warning(monkeypatch, caplog):
    def boom(*_a, **_k):
        raise OSError("nope")
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    with caplog.at_level("WARNING", logger=syscmd.LOG.name):
        assert syscmd.run(["/nope"], quiet=True) is None
    assert not caplog.records


def test_run_arms_timeout_and_captures_text(monkeypatch):
    # The timeout bound is the anti-hang safety property (a stuck ifconfig/route/
    # sysctl must not wedge the maintain loop); capture_output + text give callers
    # str. A regression dropping any of these would otherwise pass every other test.
    seen = {}

    def capture(cmd, **kw):
        seen["cmd"] = cmd
        seen["kw"] = kw
        return _cp(0, "")
    monkeypatch.setattr(syscmd.subprocess, "run", capture)
    syscmd.run(["/sbin/route", "-n", "get", "default"])
    assert seen["cmd"] == ["/sbin/route", "-n", "get", "default"]
    assert seen["kw"]["timeout"] == syscmd.SUBPROC_TIMEOUT
    assert seen["kw"]["capture_output"] is True
    assert seen["kw"]["text"] is True
    assert seen["kw"]["check"] is False
    assert seen["kw"]["errors"] == "replace"   # non-UTF-8 output must not raise into the loop
    syscmd.run(["/x"], timeout=2)
    assert seen["kw"]["timeout"] == 2   # caller override is honoured


def test_spawn_launches_detached_with_devnull_stdio(monkeypatch):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        seen["kw"] = kw
    monkeypatch.setattr(syscmd.subprocess, "Popen", fake_popen)
    syscmd.spawn(["/usr/local/sbin/configctl", "x"])
    assert seen["cmd"] == ["/usr/local/sbin/configctl", "x"]
    # Detached into its own session, all stdio to /dev/null: the follow dispatch
    # must survive this daemon's own restart and leak nothing into the log.
    assert seen["kw"]["start_new_session"] is True
    assert seen["kw"]["stdin"] == subprocess.DEVNULL
    assert seen["kw"]["stdout"] == subprocess.DEVNULL
    assert seen["kw"]["stderr"] == subprocess.DEVNULL


def test_spawn_raises_on_launch_failure(monkeypatch):
    # Unlike run's None, a spawn launch failure RAISES so the caller owns the
    # retry policy (a follow that could not be dispatched must be re-driven).
    def boom(*_a, **_k):
        raise OSError("cannot exec")
    monkeypatch.setattr(syscmd.subprocess, "Popen", boom)
    with pytest.raises(OSError):
        syscmd.spawn(["/nope"])


def test_ifconfig_builds_argv(monkeypatch):
    # No arg -> all interfaces; an iface -> that iface only (the per-interface CARP
    # probe depends on the passthrough). Every other fake ignores argv, so pin it.
    seen = {}

    def capture(cmd, **_k):
        seen["cmd"] = cmd
        return _cp(0, "out")
    monkeypatch.setattr(syscmd.subprocess, "run", capture)
    syscmd.ifconfig()
    assert seen["cmd"] == ["/sbin/ifconfig"]
    syscmd.ifconfig("igb0")
    assert seen["cmd"] == ["/sbin/ifconfig", "igb0"]


def test_ifconfig_returns_stdout_on_success(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run", lambda *a, **k: _cp(0, "igb0: flags\n"))
    assert syscmd.ifconfig("igb0") == "igb0: flags\n"


def test_ifconfig_none_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run", lambda *a, **k: _cp(1, ""))
    assert syscmd.ifconfig("nope0") is None


def test_ifconfig_none_on_launch_failure(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("no ifconfig")
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    assert syscmd.ifconfig() is None
