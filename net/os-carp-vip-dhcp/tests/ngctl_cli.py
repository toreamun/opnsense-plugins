"""Command-line front of FakeNgctl for the shell tests (tests/test_vmac_shell.py).

    python ngctl_cli.py <state.json> <ngctl|kldstat> [args...]

Loads the netgraph state and the failure knobs (NgKnobs) from the JSON file, runs one
command through FakeNgctl (the
same oracle the Python tests use, printing what FreeBSD prints), saves the state and
appends the argv to the file's call log, then prints stdout and stderr and exits with
the command's exit status. Keeps shell and Python tests on one model of ngctl.
"""
import dataclasses
import importlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [_HERE, os.path.join(_HERE, "..", "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp")]
fakes = importlib.import_module("fakes")   # after the path set-up above


def _tuples(value):
    """JSON lists back to the nested tuples FakeNgctl keeps."""
    return tuple(_tuples(v) for v in value) if isinstance(value, list) else value


def load(path):
    """The FakeNgctl a state file describes."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    fake = fakes.FakeNgctl(ifaces=(), knobs=fakes.NgKnobs(**data.get("knobs", {})))
    fake.nodes = {name: fakes.NgNode(n["type"], {k: tuple(p) for k, p in n["hooks"].items()},
                                     _tuples(n["config"]), id=n.get("id", 0))
                  for name, n in data["nodes"].items()}
    fake.calls = data.get("calls", [])
    return fake


def save(path, fake):
    """Write a FakeNgctl's nodes, knobs and call log to a state file."""
    data = {"knobs": dataclasses.asdict(fake.knobs), "calls": fake.calls,
            "nodes": {name: {"type": n.type, "hooks": n.hooks, "config": n.config, "id": n.id}
                      for name, n in fake.nodes.items()}}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def main():
    """Run one command against the state file; mirror its output and exit status."""
    path, prog, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    fake = load(path)
    res = fake.run([f"/fake/{prog}", *args])
    save(path, fake)
    if res is None:
        return 127
    sys.stdout.write(res.stdout)
    sys.stderr.write(res.stderr)
    return res.returncode


if __name__ == "__main__":
    sys.exit(main())
