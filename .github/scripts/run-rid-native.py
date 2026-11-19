#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Штатный производитель нативных RID. Сводка не содержит закрытые данные прогона."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "github.com/PRO-Robotech/kaname/cmd/kaname"
# Имена прямых подтестов после замены пробелов на подчёркивания в testing.T.Run.
CASES = {
    "registry-installation-rid01": ("TestRID_01_CleanInstallAndRenewal", frozenset({
        "real_standalone_F0_->_verified_O_->_standing_C_->_full_serve_delivery",
        "exact_creator_and_axes;_C_I_A_distinct;_I_not_admin",
        "actual_token_expiry_renewal_with_same_live_key_and_unchanged_IDs_createdAt_counts",
        "expired_standing_key_refusal_and_valid-time-only_twin",
        "pace1_and_pace5_large_repeated_concurrent_authentication_and_cancellation",
    }), 8),
    "registry-installation-rid04": ("TestRID_04_CreatorRetirement", frozenset({
        "independent_verified_O_gateway_RevokeAdmin_materialized_before_I_grant_and_apply",
        "new_grant_and_apply_denied;_old_G_and_GD_ACTIVE_and_no_self-restoration",
        "O_explicit_GrantAdmin_only_->_same_request_succeeds_with_same_delegationId",
    }), 14),
}
# Исходный бюджет полных RID-01 и RID-04 сохраняется.
TEST_SECONDS = 1200
OUTER_SECONDS = 1320


class Rejected(Exception):
    pass


def need(value):
    if not value:
        raise Rejected()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def tree_sha(root):
    # Каноническая внешняя фиксация rid-tool-tree-v1 до первого запуска Node.
    root = root.resolve(strict=True)
    records, files, total = [], 0, 0

    def safe(value):
        need(0 < len(value) <= 4096 and all(32 <= ord(c) <= 126 for c in value))

    def visit(directory, depth):
        nonlocal files, total
        need(depth <= 128)
        for path in directory.iterdir():
            need(len(records) < 32768)
            rel = path.relative_to(root).as_posix()
            safe(rel)
            st = path.lstat()
            mode = format(stat.S_IMODE(st.st_mode) & 0o777, "03o")
            if path.is_symlink():
                value = path.resolve(strict=True).relative_to(root).as_posix()
                safe(value)
                kind = "S"
            elif stat.S_ISDIR(st.st_mode):
                kind, value = "D", "-"
            else:
                need(stat.S_ISREG(st.st_mode) and st.st_size <= 32 * 1048576)
                files += 1
                total += st.st_size
                need(total <= 256 * 1048576)
                kind, value = "F", sha(path)
                need(path.stat().st_size == st.st_size)
            records.append(f"{kind}\t{rel}\t{mode}\t{value}\n")
            if kind == "D":
                visit(path, depth + 1)
    visit(root, 0)
    need(files > 0)
    return hashlib.sha256("".join(sorted(records)).encode("ascii")).hexdigest()


def command(argv, env, log, cwd=ROOT, timeout=900):
    # Вывод компилятора, Docker и теста всегда остаётся в закрытом каталоге.
    with log.open("xb") as stream:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return child.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
            raise


def docker(argv, env):
    result = subprocess.run(["docker", *argv], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False)
    need(result.returncode == 0)
    return result.stdout.decode("utf-8").splitlines()


def descendants():
    # subreaper удерживает осиротевших потомков, включая отдельные setsid-группы.
    rows = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            rows[int(path.parent.name)] = (int(fields[1]), fields[19], fields[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    owned = {os.getpid()}
    while True:
        found = {pid for pid, (ppid, _, _) in rows.items() if ppid in owned}
        if found <= owned:
            break
        owned |= found
    return {pid: rows[pid] for pid in owned if pid != os.getpid()}


def cleanup(evidence, env, before, root_test):
    result = {"ok": False, "processesRemaining": 0, "forcedProcesses": 0,
              "containers": 0, "volumes": 0, "containersRemaining": 0,
              "volumesRemaining": 0, "fallbackContainers": 0}
    initial = descendants()
    result["forcedProcesses"] = sum(row[2] != "Z" for row in initial.values())
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, (_, start, state) in descendants().items():
            if state != "Z":
                try:
                    # Владение и время рождения сверяются непосредственно перед сигналом.
                    if descendants().get(pid, (None, None, None))[1] == start:
                        os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        until = time.monotonic() + 5
        while time.monotonic() < until:
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            if not descendants():
                break
            time.sleep(0.1)
    result["processesRemaining"] = len(descendants())
    # Без начального снимка Docker никакое удаление не разрешено.
    need(before is not None)
    ownerships = sorted(evidence.glob("*/pg-ownership.json"))
    need(ownerships)
    containers, volumes, mounts_by_container = set(), set(), {}
    natural = True

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def read_receipt(path):
        need(path.is_file() and not path.is_symlink() and not path.parent.is_symlink())
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_fields)
        need(type(value) is dict)
        return value

    def mount_ids(mounts):
        need(type(mounts) is list and mounts)
        found = set()
        for mount in mounts:
            need(type(mount) is dict and mount.get("Type") == "volume")
            name, destination = mount.get("Name"), mount.get("Destination")
            need(isinstance(name, str) and re.fullmatch(r"[a-f0-9]{64}", name))
            need(destination == "/var/lib/postgresql/data")
            need((name, destination) not in found and name not in before["volumes"])
            found.add((name, destination))
        return found

    # Сначала проверяем ВСЮ ведомость владения. Без неё удаление запрещено.
    # Отсутствующий terminal после аварии допускает только scoped cleanup, никогда PASS.
    for path in ownerships:
        identity = read_receipt(path.parent / "test-identity.json")
        name = identity.get("testIdentity")
        need(set(identity) == {"testIdentity"} and isinstance(name, str) and name.startswith(root_test + "/"))
        need(path.parent.name == "case-" + hashlib.sha256(name.encode()).hexdigest())
        owned = read_receipt(path)
        need(set(owned) == {"containerId", "mounts"})
        cid = owned["containerId"]
        need(isinstance(cid, str) and re.fullmatch(r"[a-f0-9]{64}", cid))
        need(cid not in before["containers"] and cid not in containers)
        expected_mounts = mount_ids(owned["mounts"])
        need(not (volumes & {name for name, _ in expected_mounts}))
        containers.add(cid)
        volumes.update(name for name, _ in expected_mounts)
        mounts_by_container[cid] = expected_mounts
        def optional_receipt(name):
            receipt_path = path.parent / name
            # Повреждённый существующий файл (включая dangling symlink) не является отсутствующим.
            if not receipt_path.exists() and not receipt_path.is_symlink():
                return None
            return read_receipt(receipt_path)

        pg = optional_receipt("pg-cleanup.json")
        mail = optional_receipt("mailbox-cleanup.json")
        process = optional_receipt("mailbox-process.json")
        if pg is not None:
            need(set(pg) == {"containerId", "terminateSucceeded"} and pg["containerId"] == cid)
            need(type(pg["terminateSucceeded"]) is bool)
        if mail is not None:
            need(set(mail) == {"pid", "forced", "exited"} and type(mail["pid"]) is int and mail["pid"] > 0)
            need(type(mail["forced"]) is bool and type(mail["exited"]) is bool)
        if process is not None:
            need(set(process) == {"name", "pid"} and process["name"] == "mailbox")
            need(type(process["pid"]) is int and process["pid"] > 0)
        if mail is not None and process is not None:
            need(process["pid"] == mail["pid"])
        # PID из квитанции не используется для сигналов: выше действует проверка потомков/starttime.
        natural &= bool(pg is not None and mail is not None and process is not None and
                        pg["terminateSucceeded"] and mail["exited"] and not mail["forced"])
    current = set(docker(["ps", "-aq", "--no-trunc"], env))
    for cid in sorted(containers & current):
        inspected = json.loads("\n".join(docker(["inspect", "--type=container", cid], env)))
        need(type(inspected) is list and len(inspected) == 1 and inspected[0].get("Id") == cid)
        need(mount_ids(inspected[0].get("Mounts")) == mounts_by_container[cid])
    current_volumes = set(docker(["volume", "ls", "-q"], env))
    for volume in sorted(volumes & current_volumes):
        # Даже новый том нельзя удалить, если его уже использует чужой контейнер.
        users = set(docker(["ps", "-aq", "--no-trunc", "--filter", "volume=" + volume], env))
        need(users <= containers)
    for cid in sorted(containers & current):
        result["fallbackContainers"] += 1
        # Без -v: Docker не получает права неявно удалить неучтённый том.
        docker(["rm", "-f", cid], env)
    for volume in sorted(volumes & set(docker(["volume", "ls", "-q"], env))):
        need(not docker(["ps", "-aq", "--no-trunc", "--filter", "volume=" + volume], env))
        docker(["volume", "rm", volume], env)
    result.update(containers=len(containers), volumes=len(volumes),
                  containersRemaining=len(containers & set(docker(["ps", "-aq", "--no-trunc"], env))),
                  volumesRemaining=len(volumes & set(docker(["volume", "ls", "-q"], env))))
    result["ok"] = bool(natural and not any(result[key] for key in
        ("processesRemaining", "forcedProcesses", "containersRemaining", "volumesRemaining", "fallbackContainers")))
    return result


def judge_test(path, root_test, predicates):
    running, passed, terminal = set(), set(), []
    with path.open() as stream:
        for line in stream:
            event = json.loads(line)
            need(event.get("Package") == PACKAGE)
            name, action = event.get("Test"), event.get("Action")
            need(action not in ("fail", "skip"))
            if name:
                need(name == root_test or name.startswith(root_test + "/"))
                if action == "run":
                    need(name not in running)
                    running.add(name)
                if action == "pass":
                    need(name in running and name not in passed)
                    passed.add(name)
            elif action in ("pass", "fail"):
                terminal.append(action)
    need(root_test in passed and passed == running and terminal == ["pass"])
    direct = {name.split("/", 1)[1] for name in passed if name.count("/") == 1}
    need(direct == predicates)
    return {"ok": True, "passedTests": len(passed), "skippedTests": 0, "failedTests": 0,
            "directPredicates": sorted(direct)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=CASES, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root_test, predicates, phase_count = CASES[args.suite]
    summary = {"schemaVersion": 1, "ok": False, "suite": args.suite, "status": "precondition-failed"}
    need(args.private_dir.is_absolute() and args.out.is_absolute())
    private, output = args.private_dir.resolve(), args.out.resolve()
    # Свежий закрытый каталог исключает смешивание доказательств разных вызовов.
    need(private.is_absolute() and output != private and private not in output.parents)
    need(ROOT != private and ROOT not in private.parents)
    need(ROOT != output and ROOT not in output.parents)
    need(not private.exists() and not output.exists())
    private.mkdir(mode=0o700, parents=True)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence = private / "evidence"
    evidence.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith("KANAME_")}
    env.pop("NODE_OPTIONS", None)
    env.pop("NODE_PATH", None)
    started = False
    before = None
    try:
        need(sys.platform == "linux" and ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0)
        started = True
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        for tool in ("go", "docker", "bash", "openssl", "python3"):
            need(shutil.which(tool))
        node = Path(os.environ["KANAME_RID_NODE_BINARY"])
        module = Path(os.environ["KANAME_RID_NEWMAN_MODULE"])
        need(node.is_absolute() and module.is_absolute())
        node, module = node.resolve(strict=True), module.resolve(strict=True)
        need(json.loads((module / "package.json").read_bytes())["version"] == "6.2.2")
        # Пользовательские NODE_OPTIONS и отключение штатного сборщика контейнеров не наследуются.
        env.pop("TESTCONTAINERS_RYUK_DISABLED", None)
        env.update(GOMAXPROCS="2", GOMEMLIMIT="3GiB", CGO_ENABLED="0")
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
        need(re.fullmatch(r"[a-f0-9]{40}", source))
        need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                         cwd=ROOT, stderr=subprocess.DEVNULL))
        source_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                              stderr=subprocess.DEVNULL).decode().strip()
        need(re.fullmatch(r"[a-f0-9]{40}", source_tree))
        summary["sourceTree"] = source_tree
        summary["sourceRevision"] = source
        summary["status"] = "build-failed"
        bins = private / "bin"
        bins.mkdir(mode=0o700)
        for name, package, test in (("kaname", "./cmd/kaname", False),
                                    ("kaname-migrator", "./cmd/migrator", False),
                                    ("rid-tests", "./cmd/kaname", True)):
            argv = ["go", "test", "-c"] if test else ["go", "build"]
            need(command([*argv, "-p=1", "-o", str(bins / name), package], env,
                         private / (name + "-build.log")) == 0)
        runner = ROOT / "tests/newman/scripts/run-rid-native.cjs"
        collection = ROOT / "tests/newman/collections" / (args.suite + ".postman_collection.json")
        collector = ROOT / "tests/newman/scripts/collect-rid-native.py"
        expected = {"nodeSHA256": sha(node), "runnerSHA256": sha(runner),
                    "toolTreeSHA256": tree_sha(module), "collectionSHA256": sha(collection),
                    "testExecutableSHA256": sha(bins / "rid-tests")}
        artifact_hashes = {name: sha(bins / name) for name in ("kaname", "kaname-migrator", "rid-tests")}
        collector_sha = sha(collector)
        identity_file = private / "expected-identities.json"
        write_json(identity_file, expected)
        run_id = args.suite.removeprefix("registry-installation-") + "-ci-" + uuid.uuid4().hex
        env.update(KANAME_RID_ACCEPTANCE="1", KANAME_RID_NEWMAN="1",
                   KANAME_RID_NODE_BINARY=str(node), KANAME_RID_NEWMAN_MODULE=str(module),
                   KANAME_RID_EXPECTED_IDENTITIES_FILE=str(identity_file), KANAME_RID_RUN_ID=run_id,
                   KANAME_RID_EVIDENCE=str(evidence), KANAME_RID_BINARY=str(bins / "kaname"),
                   KANAME_RID_BINARY_SHA256=artifact_hashes["kaname"],
                   KANAME_RID_MIGRATOR=str(bins / "kaname-migrator"))
        summary.update(status="native-test-failed", expectedIdentities=expected, artifactSHA256=artifact_hashes,
                       collectorSHA256=collector_sha, runIdSHA256=hashlib.sha256(run_id.encode()).hexdigest(),
                       testDeadlineSeconds=TEST_SECONDS, outerDeadlineSeconds=OUTER_SECONDS)
        before = {"containers": frozenset(docker(["ps", "-aq", "--no-trunc"], env)),
                  "volumes": frozenset(docker(["volume", "ls", "-q"], env))}
        need(all(re.fullmatch(r"[a-f0-9]{64}", cid) for cid in before["containers"]))
        write_json(private / "docker-before.json", {key: sorted(value) for key, value in before.items()})
        rc = command(["go", "tool", "test2json", "-t", "-p", PACKAGE, str(bins / "rid-tests"),
                      "-test.v=test2json", "-test.parallel=1", "-test.run=^" + root_test + "$",
                      "-test.count=1", "-test.timeout=20m"], env, private / "test.jsonl",
                     cwd=ROOT / "cmd/kaname", timeout=OUTER_SECONDS)
        need(rc == 0)
        summary["test"] = judge_test(private / "test.jsonl", root_test, predicates)
        summary["status"] = "receipt-proof-failed"
        need(sha(node) == expected["nodeSHA256"] and tree_sha(module) == expected["toolTreeSHA256"])
        need(sha(runner) == expected["runnerSHA256"] and sha(collector) == collector_sha)
        need(all(sha(bins / name) == value for name, value in artifact_hashes.items()))
        spec = importlib.util.spec_from_file_location("rid_native_collector", collector)
        impl = importlib.util.module_from_spec(spec)
        sys.dont_write_bytecode = True
        spec.loader.exec_module(impl)
        reports = sorted(evidence.glob("**/newman/stdout"))
        need(len(reports) == phase_count)
        merged = impl.combine(collection, reports, run_id, expected["testExecutableSHA256"], expected)
        need(len(merged["sources"]) == phase_count)
        write_json(private / "combined.json", merged)
        # Проецируются только проверенные числовые поля и хеши, ни один HTTP-запрос/ответ.
        summary["phases"] = [{"phaseSHA256": hashlib.sha256(row["phase"].encode()).hexdigest(),
                              "reportSHA256": row["reportSHA256"], "requests": row["requests"],
                              "uniqueRequests": row["uniqueRequests"], "assertions": row["assertions"]}
                             for row in merged["sources"]]
        summary["counts"] = {"phases": phase_count, "requests": merged["run"]["stats"]["requests"]["total"],
                             "assertions": merged["run"]["stats"]["assertions"]["total"]}
        need(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source)
        need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                         cwd=ROOT, stderr=subprocess.DEVNULL))
        need(subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source_tree)
        summary["status"] = "cleanup-proof-failed"
        summary["cleanup"] = cleanup(evidence, env, before, root_test)
        need(summary["cleanup"]["ok"])
        need(subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source_tree)
        summary.update(ok=True, status="passed")
    except (Exception, KeyboardInterrupt):
        # Исключения могут содержать закрытые пути/ответы: наружу идёт только стадия отказа.
        if started and "cleanup" not in summary:
            try:
                summary["cleanup"] = cleanup(evidence, env, before, root_test)
            except Exception:
                summary["cleanup"] = {"ok": False}
    finally:
        write_json(output, summary)
    print(json.dumps({"ok": summary["ok"], "status": summary["status"]}))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"ok": False, "status": "invalid-or-unavailable-output"}))
        sys.exit(1)
