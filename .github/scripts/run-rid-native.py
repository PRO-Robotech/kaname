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
    "registry-installation-rid02": ("TestRID_02_ConcurrentAndRepeat", frozenset({
        "axis_reorder_sequential_repeat_preserves_IDs_and_createdAt",
        "two_real_absent-pair_arrivals_->_one_GD_and_two_successful_Operations",
        "raw_Any_metadata_index_and_response_identities_agree_on_both_Operations",
        "stop_before_writer_before_commit_after_commit_before_terminal;_primary_recovery",
        "cancellation_and_reconciler_overlap_preserve_terminal_refusal",
    }), 4),
    "registry-installation-rid04": ("TestRID_04_CreatorRetirement", frozenset({
        "independent_verified_O_gateway_RevokeAdmin_materialized_before_I_grant_and_apply",
        "new_grant_and_apply_denied;_old_G_and_GD_ACTIVE_and_no_self-restoration",
        "O_explicit_GrantAdmin_only_->_same_request_succeeds_with_same_delegationId",
    }), 14),
    "registry-installation-rid10": ("TestRID_10_MidRunFaultAndRetirement", frozenset({
        "first_pair_committed_observed;_unknown_Writer_BeginTx_only_after_normal_second_Operation_Create",
        "second_Operation_done_INTERNAL_internal_error;_first_kept;_no_later_pairs",
        "independent_O_RevokeAdmin_at_same_boundary;_denial_before_next_Operation",
        "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins",
    }), 6),
    'registry-installation-rid07': ('TestRID_07_ExistingPairConflict', frozenset({
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION',
        'each_failure_preserves_complete_pair_and_grants_without_update_or_revoke',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match',
    }), 32),
    'registry-installation-rid09': ('TestRID_09_WholeDeliveryPreflight', frozenset({
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate',
        'every_invalid_axis_preserves_catalog_roles_own_seed_SA_groups_joins_grants_GD_snapshots',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair',
    }), 32),
}
# Все шесть вложенных узлов обязательны в полном RID10.
RID10_NESTED = frozenset({
    "first_pair_committed_observed;_unknown_Writer_BeginTx_only_after_normal_second_Operation_Create/fault",
    "independent_O_RevokeAdmin_at_same_boundary;_denial_before_next_Operation/retirement",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/fault-independent-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/fault-independent-twin/fault-lawful-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/retirement-independent-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/retirement-independent-twin/retirement-lawful-twin",
})

# Полные матрицы существующих фикстур: slash в t.Run не создаёт промежуточных узлов.
RID_MATRIX_NESTED = {
    'TestRID_07_ExistingPairConflict': frozenset({
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/role/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/role/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/target/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/target/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/subject/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/subject/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/creator/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/creator/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/role/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/role/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/target/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/target/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/subject/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/subject/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/creator/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/creator/S2',
    }),
    'TestRID_09_WholeDeliveryPreflight': frozenset({
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/roleIds/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/targetTypes/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/subjectTypes/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/delegate/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/roleIds/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/targetTypes/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/subjectTypes/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/delegate/M2-M1/negative',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/roleIds/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/targetTypes/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/subjectTypes/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/delegate/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/roleIds/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/targetTypes/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/subjectTypes/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/delegate/M2-M1/lawful-twin',
    }),
}

# Исходный бюджет полного нативного теста сохраняется.
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


# Только публичные исходники существующих native fixture/bridge, не пути из Output.
ASSERTION_FILES = (
    "cmd/kaname/installation_native_fixture_test.go",
    "cmd/kaname/installation_native_baseline_test.go",
    "cmd/kaname/installation_native_stock_premise_test.go",
    "cmd/kaname/installation_public_lifecycle_fixture_test.go",
    "cmd/kaname/installation_native_renewal_test.go",
    "cmd/kaname/installation_newman_install_test.go",
    "cmd/kaname/installation_creator_retirement_native_test.go",
    "cmd/kaname/installation_newman_retirement_test.go",
    "cmd/kaname/installation_newman_bridge_test.go",
    "cmd/kaname/installation_owned_child_driver_test.go",
    "internal/testsupport/installruntime/stand.go",
)


def test_diagnostics(path, root_test, predicates):
    # Только имена из CASES и известные режимы RID-04; строки Output не проецируются.
    names = {root_test, *(root_test + "/" + name for name in predicates)}
    if root_test == CASES["registry-installation-rid04"][0]:
        names.update(root_test + "/" + name + "/" + mode
                     for name in predicates for mode in ("S1", "S2"))
    if root_test == CASES["registry-installation-rid10"][0]:
        names.update(root_test + "/" + name for name in RID10_NESTED)
    names.update(root_test + "/" + name for name in RID_MATRIX_NESTED.get(root_test, frozenset()))
    known = {name: name for name in names}
    actions = {action: action for action in ("run", "pass", "fail", "skip")}
    result = {"status": "complete", "events": []}
    seen, fragmented, sites = set(), set(), {}
    bounds = {}
    for relative in ASSERTION_FILES:
        try:
            bounds[relative] = len((ROOT / relative).read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError):
            continue
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                line = stream.readline(1048577)
                if not line:
                    break
                total += len(line)
                if len(line) > 1048576 or total > 64 * 1048576:
                    result["status"] = "limit-exceeded"
                    break
                event = json.loads(line)
                if not isinstance(event, dict) or event.get("Package") != PACKAGE:
                    continue
                name, action = event.get("Test"), event.get("Action")
                if (action == "output" and isinstance(name, str) and name in known and name not in sites
                        and (name, "run") in seen
                        and not any((name, end) in seen for end in ("pass", "fail", "skip"))):
                    output = event.get("Output")
                    # Никакой сборки фрагментов: потеря координаты безопаснее ложной склейки.
                    if not isinstance(output, str) or output.count("\n") != 1 or not output.endswith("\n"):
                        fragmented.add(name)
                    elif re.match(r"^[ \t]*Error Trace:", output):
                        sites[name] = {"status": "unrecognized-trace"}
                        for relative, limit in bounds.items():
                            match = re.fullmatch(r"[ \t]*Error Trace:[ \t]+" +
                                re.escape(str(ROOT / relative)) + r":([1-9][0-9]{0,6})\n", output)
                            if match and int(match[1]) <= limit:
                                sites[name] = {"status": "matched", "file": relative, "line": int(match[1])}
                                break
                if not isinstance(action, str) or action not in actions:
                    continue
                if name is None:
                    if action == "run":
                        continue
                    key = (None, action)
                    row = {"scope": "package", "action": actions[action]}
                elif isinstance(name, str) and name in known:
                    key = (name, action)
                    row = {"scope": "test", "test": known[name], "action": actions[action]}
                else:
                    continue
                if key not in seen:
                    seen.add(key)
                    result["events"].append(row)
    except (ValueError, RecursionError):
        result["status"] = "malformed"
    except OSError:
        result["status"] = "unavailable"
    first = next((row["test"] for row in result["events"]
                  if row["scope"] == "test" and row["action"] == "fail"), None)
    if first is not None:
        if result["status"] != "complete":
            site = {"status": "incomplete-scan"}
        elif first in fragmented:
            site = {"status": "fragmented-output"}
        else:
            site = sites.get(first, {"status": "not-observed"})
        result["firstFailureSite"] = {"test": first, **site}
    return result


def startup_diagnostics(evidence, root_test, predicates, diagnostics, binary_sha):
    # Только первый fail, уже связанный с точным require.NoError после StartBase.
    site = diagnostics.get("firstFailureSite", {})
    fixture_source = "cmd/kaname/installation_native_fixture_test.go"
    names = {root_test + "/" + name for name in predicates}
    if root_test == CASES["registry-installation-rid04"][0]:
        names = {name + "/" + mode for name in names for mode in ("S1", "S2")}
    if (diagnostics.get("status") != "complete" or site.get("status") != "matched"
            or site.get("file") != fixture_source or site.get("test") not in names):
        return {"status": "not-first-startbase-failure"}
    try:
        source_lines = (ROOT / fixture_source).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {"status": "unavailable-fixture-source"}
    location = site.get("line")
    if (type(location) is not int or not 2 <= location <= len(source_lines)
            or source_lines[location - 2].strip() != "base, err := session.StartBase(ctx, f.writerPlan)"
            or source_lines[location - 1].strip() != "require.NoError(t, err)"):
        return {"status": "not-first-startbase-failure"}
    name = site["test"]
    events = diagnostics.get("events", [])
    first = next((i for i, row in enumerate(events) if row.get("action") == "fail"), None)
    if (first is None or events[first].get("test") != name
            or not any(row.get("test") == name and row.get("action") == "run" for row in events[:first])
            or any(row.get("test") == name and row.get("action") in ("pass", "skip") for row in events[:first])):
        return {"status": "unbound-failure"}
    fixture = "case-" + hashlib.sha256(name.encode()).hexdigest()

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def read(parts, limit):
        # Каждый каталог и файл открывается относительно fd без следования ссылкам.
        fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in (fixture, *parts[:-1]):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(leaf, "rb") as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_size <= limit)
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
                need(len(raw) <= limit and len(raw) == before.st_size == after.st_size)
                need(before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns)
                return raw
        except FileNotFoundError:
            return None
        finally:
            os.close(fd)

    def receipt(parts):
        raw = read(parts, 4096)
        return None if raw is None else json.loads(raw, object_pairs_hook=unique)

    try:
        need(receipt(("test-identity.json",)) == {"testIdentity": name})
        process = receipt(("serve-001", "process", "process.json"))
        terminal = receipt(("serve-001", "process", "terminal.json"))
        result = {"status": "observed", "process": "receipt-absent", "terminal": "receipt-absent"}
        if process is None:
            need(terminal is None)
            return result  # Не утверждаем, что exec точно не происходил без process receipt.
        need(type(process) is dict and set(process) == {"pid", "binarySHA256", "configSHA256"})
        need(type(process["pid"]) is int and 0 < process["pid"] <= 2147483647)
        need(isinstance(binary_sha, str) and re.fullmatch(r"[a-f0-9]{64}", binary_sha))
        need(process["binarySHA256"] == binary_sha)
        need(isinstance(process["configSHA256"], str) and re.fullmatch(r"[a-f0-9]{64}", process["configSHA256"]))
        config = read(("serve-001", "config.yaml"), 65536)
        need(config is not None and hashlib.sha256(config).hexdigest() == process["configSHA256"])
        result["process"] = "matched-binary-and-config"
        if terminal is not None:
            need(type(terminal) is dict and set(terminal) == {"pid", "exited", "exitCode"})
            need(type(terminal["pid"]) is int and terminal["pid"] == process["pid"] and terminal["exited"] is True)
            need(type(terminal["exitCode"]) is int and -1 <= terminal["exitCode"] <= 255)
            result.update(terminal="matched-process", exitCode=terminal["exitCode"])
        # main.go bootstrap logger пишет эти четыре сообщения только в stderr.
        messages = {"refusal domain declaration failed": "refusal-domain",
                    "config load failed": "config-load", "config validation failed": "config-validation",
                    "kaname exited with error": "serve"}
        # Только фиксированные префиксы ошибок запуска. Суффикс не выходит наружу.
        prefixes = {"registration-account-writers: ": "registration-writer-plan",
                    "module identities: ": "module-identities", "refusal domain: ": "refusal-domain",
                    "посадка процесса: ": "process-posture",
                    "sign-in lane: authn.login.verifier-capacity: предел памяти средой не наложен": "sign-in-memory-limit-missing",
                    "sign-in lane: authn.login.verifier-capacity =": "sign-in-memory-budget",
                    "предел соединений базы не прочитан: ": "database-connection-limit-read",
                    "KANAME_REPOSITORY__POSTGRES__MAX_CONNS / KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET: ": "database-connection-budget",
                    "состояние схем базы не прочитано: ": "database-schema-read",
                    "load server mTLS config: ": "server-mtls",
                    "public listener mTLS creds: ": "public-listener-mtls",
                    "internal listener mTLS creds: ": "internal-listener-mtls",
                    "metrics listener mTLS config: ": "metrics-listener-mtls"}
        try:
            raw = read(("serve-001", "process", "stderr.jsonl"), 262144)
            if raw is None:
                result["bootstrap"] = {"status": "log-absent"}
                return result
            need(not raw or raw.endswith(b"\n"))  # Фрагменты не склеиваются и не признаются событием.
            lines = raw.splitlines(keepends=True)
            need(len(lines) <= 1024)
            found = []
            origins = []
            origin_message = "kaname startup error origin"
            origin_source = "cmd/kaname/serve.go"
            origin_classes = {"other", "context-canceled", "context-deadline", "address-in-use",
                              "connection-refused", "permission", "not-exist", "file", "database", "network"}
            for event_index, line in enumerate(lines):
                need(len(line) <= 32768 and line.endswith(b"\n"))
                event = json.loads(line, object_pairs_hook=unique)
                need(type(event) is dict)
                message = event.get("msg")
                if message == origin_message:
                    need(set(event) == {"time", "level", "msg", "source", "line", "class"})
                    need(isinstance(event["time"], str) and event["level"] == "ERROR")
                    need(event["source"] == origin_source and type(event["line"]) is int)
                    need(isinstance(event["class"], str) and event["class"] in origin_classes)
                    source_lines = (ROOT / origin_source).read_text(encoding="utf-8").splitlines()
                    need(1 <= event["line"] <= len(source_lines))
                    need(re.fullmatch(r"\s*return startupFailureAt\(.+", source_lines[event["line"] - 1]))
                    origins.append(({"source": origin_source, "line": event["line"],
                                     "class": event["class"]}, event_index))
                    continue
                if not isinstance(message, str) or message not in messages:
                    continue
                need(set(event) == {"time", "level", "msg", "err"})
                need(isinstance(event["time"], str) and event["level"] == "ERROR" and isinstance(event["err"], str))
                cause = "unclassified"
                if messages[message] == "serve":
                    for prefix, value in prefixes.items():
                        if event["err"].startswith(prefix):
                            cause = value
                            break
                elif messages[message] == "config-validation" and event["err"] in (
                    "registration-account-writers must be explicitly declared",
                    "registration-account-writers.assignments must be explicitly declared (an empty list disables registrars)",
                ):
                    cause = "registration-writer-declaration"
                found.append({"stage": messages[message], "cause": cause})
                fatal_index = event_index
            need(len(found) <= 1 and len(origins) <= 1)
            if origins:
                need(found and found[0]["stage"] == "serve" and origins[0][1] < fatal_index)
            if found and terminal is not None and terminal["exitCode"] == 1:
                result["bootstrap"] = {"status": "fatal-exit-matched", **found[0]}
                result["startupOrigin"] = ({"status": "matched-return", **origins[0][0]}
                                           if origins else {"status": "not-observed"})
            elif found:
                result["bootstrap"] = {"status": "event-without-matching-exit"}
            else:
                # terminal после cleanup сам по себе не отличает ранний выход от остановки по readiness timeout.
                result["bootstrap"] = {"status": "no-known-fatal-event"}
        except (OSError, ValueError, TypeError, Rejected, RecursionError):
            result["bootstrap"] = {"status": "invalid-or-unavailable"}
        return result
    except (OSError, ValueError, TypeError, Rejected, RecursionError):
        return {"status": "invalid-or-unavailable"}


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
    if root_test == CASES["registry-installation-rid10"][0]:
        expected = {root_test, *(root_test + "/" + name for name in predicates | RID10_NESTED)}
        need(running == expected)
    if root_test in RID_MATRIX_NESTED:
        expected = {root_test, *(root_test + "/" + name for name in predicates | RID_MATRIX_NESTED[root_test])}
        need(running == expected)
    return {"ok": True, "passedTests": len(passed), "skippedTests": 0, "failedTests": 0,
            "directPredicates": sorted(direct)}


def hosted_memory_scope():
    # Читаем предел области процесса из ядра. GOMEMLIMIT не ограничивает RSS
    # и не подтверждает условие запуска полосы входа.
    need(os.geteuid() != 0)
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    memberships = [row.removeprefix("0::") for row in rows if row.startswith("0::")]
    need(len(memberships) == 1)
    member = Path(memberships[0])
    need(member.is_absolute() and member.as_posix() == memberships[0]
         and member != Path("/") and ".." not in member.parts)
    group = Path("/sys/fs/cgroup").joinpath(*member.parts[1:])
    memory = (group / "memory.max").read_text().strip()
    swap = (group / "memory.swap.max").read_text().strip()
    need(memory == "4294967296" and swap == "0")
    return {"memoryMaxBytes": int(memory), "memorySwapMaxBytes": int(swap), "unprivileged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=CASES, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-hosted-memory-scope", action="store_true")
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
        if args.require_hosted_memory_scope:
            summary["status"] = "hosted-memory-scope-invalid"
            summary["nativeProcessScope"] = hosted_memory_scope()
            summary["status"] = "precondition-failed"
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
        summary["status"] = "native-test-command-failed"
        rc = command(["go", "tool", "test2json", "-t", "-p", PACKAGE, str(bins / "rid-tests"),
                      "-test.v=test2json", "-test.parallel=1", "-test.run=^" + root_test + "$",
                      "-test.count=1", "-test.timeout=20m"], env, private / "test.jsonl",
                     cwd=ROOT / "cmd/kaname", timeout=OUTER_SECONDS)
        summary["testExitCode"] = rc if type(rc) is int and -255 <= rc <= 255 else None
        if rc != 0:
            summary["testDiagnostics"] = test_diagnostics(private / "test.jsonl", root_test, predicates)
        need(rc == 0)
        summary["status"] = "native-test-verdict-failed"
        try:
            summary["test"] = judge_test(private / "test.jsonl", root_test, predicates)
        except (Rejected, ValueError, OSError, TypeError, RecursionError):
            summary["testDiagnostics"] = test_diagnostics(private / "test.jsonl", root_test, predicates)
            raise
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
        if not summary["ok"] and "testDiagnostics" in summary:
            summary["startupDiagnostics"] = startup_diagnostics(
                evidence, root_test, predicates, summary["testDiagnostics"], summary["artifactSHA256"]["kaname"])
        write_json(output, summary)
    print(json.dumps({"ok": summary["ok"], "status": summary["status"]}))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"ok": False, "status": "invalid-or-unavailable-output"}))
        sys.exit(1)
