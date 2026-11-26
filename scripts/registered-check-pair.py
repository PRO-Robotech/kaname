#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent 45-minute registered Check diagnostics (never a CI verdict).

From a clean committed checkout, initialize a fresh absolute output directory:
  python3 scripts/registered-check-pair.py init /tmp/check-attempt
Under the existing heavy slot run one command at a time, in either order:
  python3 scripts/registered-check-pair.py lawful /tmp/check-attempt
  python3 scripts/registered-check-pair.py missing_row /tmp/check-attempt
Then validate both full raw logs and the checkout:
  python3 scripts/registered-check-pair.py compare /tmp/check-attempt

An interrupted/failed attempt keeps its logs. Start a new pair to retry.
"""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/PRO-Robotech/kaname"
PACKAGE = MODULE + "/internal/check"
TOP = "TestCallerIdentityRegisteredCheckFullTraversal"
RPC = MODULE + "/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check"
PRODUCER = MODULE + "/internal/moduleidentity.Roster.FromContext"
HANDLER = "(*" + MODULE + "/internal/apps/kaname/api/internal_iam.Handler).Check"
HANDLER_SOURCE = "internal/apps/kaname/api/internal_iam/handler.go"
TABLE = "internal/authzguard/front_admission.go"
ROW = b"\tinternalCheckMethod: {moduleidentity.ProfileDataPlane},\n"
CALL = b"h.modules.FromContext(ctx)"
PHASES = ("lawful", "missing_row")
ADMISSION = "TestHopAdmits_FollowsTheNarrowingDeclaration"
FRONT = "TestInternalFront_CheckLaneIsNoWiderThanGRPC"
FRONT_CASES = (
    "плоскость_данных_registry_о_чужом_типе",
    "лист_вне_перечня",
    "плоскость_данных_registry_о_своём_типе",
    "близнец:_край_о_том_же_чужом_объекте",
)
MARKER = "REGISTERED_CHECK_OBSERVATION "
CI_KEYS = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
GO_KEYS = ("GOFLAGS", "GOWORK", "GOPACKAGESDRIVER", "GOENV", "GOTOOLCHAIN",
           "GOMAXPROCS", "CGO_ENABLED", "GOEXPERIMENT", "GOOS", "GOARCH")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def source():
    """Derive both exact manifests independently from verified HEAD files."""
    head, tree = git("rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
    require(not git("ls-files", "--others", "-z"), "untracked files in input")
    require(not git("status", "--porcelain", "--untracked-files=no"), "dirty input")
    manifests = {phase: hashlib.sha256() for phase in PHASES}
    blobs = {}
    coordinate = None
    entries = []
    for record in git("ls-tree", "-rz", "HEAD").split(b"\0")[:-1]:
        meta, path = record.split(b"\t", 1)
        mode, kind, oid = meta.split()
        require(kind == b"blob", f"unsupported tree entry {path!r}")
        entries.append((path, mode, oid))
    for path, mode, oid in sorted(entries):
        file = ROOT / os.fsdecode(path)
        actual = file.lstat().st_mode
        if stat.S_ISLNK(actual):
            data, actual_mode = os.fsencode(os.readlink(file)), b"120000"
        else:
            require(stat.S_ISREG(actual), f"unsupported file {path!r}")
            data = file.read_bytes()
            actual_mode = b"100755" if actual & stat.S_IXUSR else b"100644"
        blob = b"blob " + str(len(data)).encode() + b"\0" + data
        obj_hash = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
        require(actual_mode == mode and obj_hash(blob).hexdigest().encode() == oid,
                f"checkout differs from HEAD at {path!r}")
        original = injected = sha(data)
        if path == os.fsencode(TABLE):
            require(data.count(ROW) == 1, "expected exactly one Check row in source")
            injected = sha(data.replace(ROW, b"", 1))
            blobs = {"lawful": original, "missing_row": injected}
        elif path == os.fsencode(HANDLER_SOURCE):
            require(data.count(CALL) == 1, "expected exactly one handler call")
            prefix = data[:data.index(CALL)]
            line_number = prefix.count(b"\n") + 1
            column = len(prefix.rsplit(b"\n", 1)[-1]) + 1
            coordinate = f"{HANDLER_SOURCE}:{line_number}:{column}"
        for phase, digest in (("lawful", original), ("missing_row", injected)):
            manifests[phase].update(path + b"\0" + mode + b"\0" + digest.encode() + b"\n")
    require(blobs and coordinate, "required fixture files absent")
    return {"head": head, "tree": tree, "coordinate": coordinate, "table_sha256": blobs,
            "fixture_sha256": {p: m.hexdigest() for p, m in manifests.items()}}


def environment(keys):
    return {key: os.getenv(key) for key in keys}


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    with path.open("x") as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def command(phase):
    return ["go", "test", "-race", "-short", "-count=1", "-timeout=45m", "-json",
            "-run", f"^{TOP}$/^{phase}$", "./internal/check"]


def package_events(events, package, names):
    actions = collections.defaultdict(list)
    active = set()
    for event in events:
        require(event.get("Package") == package, "unexpected Go package")
        action = event["Action"]
        name = event.get("Test", "")
        if action == "output":
            continue
        if action in ("start", "run"):
            parent = name.rpartition("/")[0]
            require(name not in active and (not name or parent in active),
                    f"misordered start: {package} {name}")
            active.add(name)
        elif action == "pass":
            require(name in active and not any(n != name and (not name or n.startswith(name + "/"))
                                               for n in active), f"misordered pass: {package} {name}")
            active.remove(name)
        actions[name].append(action)
    expected = {"": ["start", "pass"], **{name: ["run", "pass"] for name in names}}
    require(dict(actions) == expected, f"incomplete/unexpected Go lifecycle for {package}: {actions}")


def observation(log, phase, pair):
    child = TOP + "/" + phase
    events = []
    for line in log.splitlines():
        event = json.loads(line)
        if event.get("Action") == "build-output":
            continue
        events.append(event)
    package_events(events, PACKAGE, [TOP, child])
    # Go splits long -json output lines into chunks. Restore the entire child's
    # stream before decoding either the report or the nested control events.
    out = "".join(e["Output"] for e in events if e.get("Test") == child and e["Action"] == "output")
    reports = []
    controls = collections.defaultdict(list)
    for line in out.splitlines():
        if match := re.search(r"\b" + MARKER + r"(.*)$", line):
            reports.append(json.loads(match[1]))
        if line.lstrip().startswith("{"):
            e = json.loads(line.strip())
            if e.get("Action") != "build-output":
                controls[e["Package"]].append(e)
    require(len(reports) == 1, f"expected exactly one observed report in {phase}")
    if phase == "lawful":
        admission, front = MODULE + "/internal/authzguard", MODULE + "/internal/restfront"
        require(set(controls) == {admission, front}, "required real controls missing or extra")
        package_events(controls[admission], admission, [ADMISSION])
        package_events(controls[front], front, [FRONT, *(FRONT + "/" + n for n in FRONT_CASES)])
    else:
        require(not controls, "unexpected nested controls")
    report = reports[0]
    src = pair["source"]
    expected = {"Schema": 1, "Phase": phase, "Pair": pair["id"], "RPC": RPC, "Producer": PRODUCER,
                "Coordinate": src["coordinate"], "FixtureSHA256": src["fixture_sha256"][phase],
                "TableSHA256": src["table_sha256"][phase]}
    require(set(report) == set(expected) | {"Reads", "Findings"}, "invalid observation fields")
    require(all(report[k] == v for k, v in expected.items()), "observation identity/fixture mismatch")
    require(isinstance(report["Reads"], list) and isinstance(report["Findings"], list)
            and all(isinstance(x, str) and x for x in report["Findings"]), "malformed full witness")
    for row in report["Reads"]:
        require(isinstance(row, dict) and set(row) == {"RPC", "Producer", "Site", "Coordinate"}
                and all(isinstance(v, str) and v for v in row.values())
                and row["RPC"] == RPC, "invalid registered RPC read tuple")
    return report


def expected_findings(lawful):
    require(not lawful["Findings"], "lawful twin has findings")
    reads = [row for row in lawful["Reads"] if row["Producer"] == PRODUCER]
    require(any(row["Site"] == HANDLER and row["Coordinate"] == lawful["Coordinate"] for row in reads),
            "lawful twin missing actual handler read at source coordinate")
    return sorted(row["Coordinate"] + ": чтение личности без объявления " + RPC
                  + " -> " + PRODUCER + " @ " + row["Site"] for row in reads)


def load_leg(out, phase, pair):
    directory = out / phase
    receipt = read(directory / "completed.json")
    log = (directory / "go.jsonl").read_bytes()
    go_environment = receipt.get("go_environment", {})
    require(set(go_environment) == set(GO_KEYS) and
            all(v is None or isinstance(v, str) for v in go_environment.values()), "invalid Go environment")
    expected = {"phase": phase, "pair": pair, "command": command(phase), "go_exit": 0,
                "log_sha256": sha(log), "go_environment": go_environment}
    require(receipt == expected, f"{phase}: identity, exit code or log digest mismatch")
    return observation(log, phase, pair), receipt


def compare(out, pair):
    (lawful, a), (missing, b) = (load_leg(out, phase, pair) for phase in PHASES)
    require(a["go_environment"] == b["go_environment"], "Go environments differ")
    expected = expected_findings(lawful)
    require(missing["Findings"] == expected,
            f"missing-row findings differ: expected {expected!r}, got {missing['Findings']!r}")
    return {"kind": "paired registered Check diagnostic", "pair": pair,
            "lawful": lawful, "missing_row": missing, "expected_findings": expected,
            "go_environment": a["go_environment"],
            "log_sha256": {phase: r["log_sha256"] for phase, r in zip(PHASES, (a, b))}}


def run_leg(out, phase, pair):
    require(environment(CI_KEYS) == pair["ci"], "run/attempt changed")
    go_environment = environment(GO_KEYS)
    directory = out / phase
    directory.mkdir()  # Exclusive. Never overwrite a failed or partial observation.
    cmd = command(phase)
    env = dict(os.environ, KANAME_REGISTERED_CHECK_PHASE=phase, KANAME_REGISTERED_CHECK_PAIR=pair["id"])
    with (directory / "go.jsonl").open("xb") as log, (directory / "stderr.log").open("xb") as err:
        result = subprocess.run(cmd, stdout=log, stderr=err, cwd=ROOT, env=env)
    if result.returncode == 0:
        require(source() == pair["source"], "checkout changed while test ran")
    receipt = {"phase": phase, "pair": pair, "command": cmd, "go_exit": result.returncode,
               "go_environment": go_environment, "log_sha256": sha((directory / "go.jsonl").read_bytes())}
    write(directory / "completed.json", receipt)
    require(result.returncode == 0, f"{phase} Go exit {result.returncode}; logs in {directory}")
    evidence, _ = load_leg(out, phase, pair)
    if phase == "lawful":
        expected_findings(evidence)
    print(json.dumps(evidence, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("init", *PHASES, "compare"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    require(not out.is_relative_to(ROOT), "output must be outside the source checkout")
    current = source()
    if args.action == "init":
        out.mkdir()
        ci = environment(CI_KEYS)
        require(all(not v for v in ci.values()) or all(ci.values()) and ci["GITHUB_SHA"] == current["head"],
                "incomplete or conflicting CI identity")
        write(out / "pair.json", {"schema": 1, "id": uuid.uuid4().hex, "source": current, "ci": ci})
        return
    pair = read(out / "pair.json")
    require(pair["schema"] == 1 and re.fullmatch("[0-9a-f]{32}", pair["id"])
            and pair["source"] == current, "pair does not match checkout HEAD, tree or files")
    if args.action == "compare":
        print(json.dumps(compare(out, pair), ensure_ascii=False, indent=2))
    else:
        run_leg(out, args.action, pair)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as err:
        sys.exit(f"registered Check diagnostic incomplete: {err}")
