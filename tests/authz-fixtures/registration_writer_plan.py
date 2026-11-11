#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Конечный план registry для accountAId и, после ceremony, ceremonyAccountId."""
import argparse
import hashlib
import stat
import uuid
import json
import os
from pathlib import Path
import re


def owned_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("не owned regular generation state")
        return json.load(source)


def write_exclusive(path, doc):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(doc, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def generation(run_dir, bin_dir, identity, begin=False):
    # Identity приходит только после подтверждённого старта PG/pod. Одинаковая
    # identity сохраняет фазу; service-only restart никогда не сбрасывает план.
    if not re.fullmatch(r"(?:docker:[0-9a-f]{64}|pod:[0-9a-f-]{36})", identity):
        raise ValueError("нет immutable PG/pod identity")
    run_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    lock = run_dir / "registration-generation.lock"
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        state_path = run_dir / "registration-generation.json"
        current = owned_json(state_path) if state_path.exists() or state_path.is_symlink() else None
        config = bin_dir / "registration-writers.json"
        if current is not None and current.get("identity") == identity:
            owned_json(config)
            return
        if not begin:
            raise ValueError("план относится к другому поколению PG/pod")
        # Предыдущая фаза сохраняется дословно, даже после неуспешного перехода.
        paths = [state_path, config, bin_dir / "registration-writers.next.json",
                 run_dir / "registration-plan.attempt", run_dir / "registration-stop.rc",
                 run_dir / "registration-stop.stderr", run_dir / "kaname.bootstrap.log",
                 run_dir / "kaname.bootstrap.cid"]
        present = [path for path in paths if path.exists() or path.is_symlink()]
        # Validate the whole archive set before the first rename. A foreign
        # path must not leave half of the previous evidence moved away.
        for source in present:
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("generation evidence не является owned regular файлом")
        if present:
            archive = run_dir / ("registration-history-" + uuid.uuid4().hex)
            archive.mkdir(mode=0o700)
            for source in present:
                source.rename(archive / source.name)
        write_exclusive(config, {"registration-account-writers": {
            "assignments": [], "disabled": [], "retire-cluster-writer": False}})
        write_exclusive(state_path, {"identity": identity,
            "generation": hashlib.sha256(identity.encode()).hexdigest()})
    finally:
        os.close(descriptor)
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--begin-generation")
    modes.add_argument("--verify-generation")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--bin-dir", type=Path)
    args = parser.parse_args()
    identity = args.begin_generation or args.verify_generation
    if identity:
        if args.run_dir is None or args.bin_dir is None:
            parser.error("generation требует run-dir и bin-dir")
        generation(args.run_dir, args.bin_dir, identity, begin=bool(args.begin_generation))
        return
    if args.env_file is None or args.output is None:
        parser.error("план требует env-file и output")
    values = json.loads(args.env_file.read_text())["values"]
    # Два именованных производителя; произвольный набор аккаунтов и wildcard
    # не принимаются. При старом машинном посеве байты первого assignment прежние.
    keys = ["accountAId"]
    if any(row.get("key") == "ceremonyAccountId" and row.get("enabled", True)
           and row.get("value") for row in values):
        keys.append("ceremonyAccountId")
    accounts = []
    for key in keys:
        found = [row.get("value") for row in values
                 if row.get("key") == key and row.get("enabled", True)]
        if (len(found) != 1 or not isinstance(found[0], str)
                or not re.fullmatch(r"acc[0-9a-hjkmnp-tv-z]{17}", found[0])):
            raise ValueError("требуется ровно один actual " + key + " штатного посева")
        if found[0] not in accounts:
            accounts.append(found[0])
    plan = {"registration-account-writers": {
        "assignments": [{"assignment_id": "stand-registry-" + account,
                         "account_id": account, "module": "registry"} for account in accounts],
        "disabled": [], "retire-cluster-writer": False}}
    # Файл новый и закрытый; повтор не переписывает чужую/непринятую фазу.
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(plan, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    main()
