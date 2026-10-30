#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#1033: ресурс registry через владельца модуля; делегирование не создаётся."""
from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess

import seed_own_stand as own

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS = ("gdRegistryId", "gdRegistryProjectId")
PROTO = "kaname/cloud/iam/v1/internal_iam_service.proto"
SERVICE = "kaname.cloud.iam.v1.InternalIAMService/"


def required(values, key):
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise own.Unmet("нет условия машинного посева: " + key)
    return value


def intent(values):
    account, project = required(values, "accountAId"), required(values, "projectA1Id")
    for prefix, value in (("acc", account), ("prj", project)):
        if not re.fullmatch(prefix + r"[0-9a-hjkmnp-tv-z]{17}", value):
            raise own.Finding("неверная форма идентификатора родителя")
    # Идентификатор выдаёт сам владелец фикстуры и сохраняет ДО отправки.
    # Повтор читает то же намерение, а не подставляет случайный объект при отказе.
    rid = "reg" + "".join(secrets.choice("0123456789abcdefghjkmnpqrstvwxyz") for _ in range(17))
    return {"subjectId": "project:" + project, "relation": "parent",
            "object": "registry_registry:" + rid, "parentProjectId": project,
            "parentAccountId": account,
            "parentChain": ["project:" + project, "account:" + account, "cluster:cluster_root"],
            "sourceVersion": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}


def validate_intent(row, values):
    expected = intent(values)
    for key in ("subjectId", "relation", "parentProjectId", "parentAccountId", "parentChain"):
        if row.get(key) != expected[key]:
            raise own.Finding("сохранённое намерение расходится с родителями: " + key)
    if not re.fullmatch(r"registry_registry:reg[0-9a-hjkmnp-tv-z]{17}", row.get("object", "")):
        raise own.Finding("сохранённое намерение не содержит идентификатор владельца")
    try:
        stamp = datetime.datetime.fromisoformat(row["sourceVersion"].replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.timestamp() <= 0:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise own.Finding("сохранённое намерение не содержит sourceVersion") from None


class Registrar:
    def __init__(self, pki, address):
        if not shutil.which("grpcurl"):
            raise own.Unmet("нет grpcurl")
        for name in ("ca.crt", "registry.crt", "registry.key"):
            if not (pki / name).is_file():
                raise own.Unmet("нет листа владельца registry: " + name)
        self.args = ["grpcurl", "-cacert", str(pki / "ca.crt"),
                     "-cert", str(pki / "registry.crt"), "-key", str(pki / "registry.key"),
                     "-max-time", "20", "-import-path", str(ROOT / "proto"),
                     "-import-path", str(own.module_proto_root()), "-proto", PROTO]
        self.address = address

    def call(self, method, body):
        try:
            proc = subprocess.run(self.args + ["-d", json.dumps(body), self.address, SERVICE + method],
                                  capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise own.Unmet("внутренний слушатель не ответил") from None
        if proc.returncode:
            error = proc.stderr.lower()
            if any(word in error for word in ("connection refused", "no such host", "context deadline")):
                raise own.Unmet("внутренний слушатель недостижим")
            # Не печатаем сырой ответ, ключи или адреса.
            raise own.Finding(method + ": отказ владельцу registry, grpcurl rc=" + str(proc.returncode))
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise own.Finding(method + ": ответ не JSON") from None


def prove(registrar, row):
    # Повтор того же intent обязан быть идемпотентным.
    for _ in range(2):
        registrar.call("RegisterResource", row)
    for subject, allowed in ((row["subjectId"], True),
                             ("project:prj" + "0" * 17, False)):
        response = registrar.call("Check", {"subjectId": subject, "relation": "parent",
                                            "object": row["object"], "consistency": "HIGHER_CONSISTENCY"})
        if response.get("allowed", False) is not allowed:
            raise own.Finding("реестр не доказал точное родительство")
    return {KEYS[0]: row["object"].split(":", 1)[1], KEYS[1]: row["parentProjectId"]}


def run(args):
    env_file, pki, ledger = pathlib.Path(args.env_file), pathlib.Path(args.pki), pathlib.Path(args.ledger)
    if not env_file.is_file():
        raise own.Unmet("машинный посев ещё не записал окружение")
    values = {item["key"]: item.get("value") for item in json.loads(env_file.read_text())["values"]
              if item.get("enabled", True)}
    token, public = required(values, "jwtAccountAdminA"), required(values, "ownRestBaseUrl")
    project = required(values, "projectA1Id")
    code, body = own.Http(pki).json_ask(public + "/iam/v1/projects/" + project, token=token)
    if code != 200 or body.get("accountId") != required(values, "accountAId"):
        raise own.Finding("проект не подтвердил свой аккаунт")
    registrar = Registrar(pki, args.grpc_addr)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(ledger) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise own.Unmet("посев registry уже занят") from None
        if ledger.exists():
            row = json.loads(ledger.read_text())
        else:
            if any(values.get(key) for key in KEYS):
                raise own.Finding("окружение называет registry без намерения владельца")
            row = intent(values)
            fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(row, out)
                out.flush()
                os.fsync(out.fileno())
        validate_intent(row, values)
        patch = prove(registrar, row)
        for key in KEYS:
            if values.get(key) and values[key] != patch[key]:
                raise own.Finding("окружение расходится с ресурсом владельца: " + key)
        own.write_env(patch, env_file, env_file)
    print("registry seed: регистрация и повтор приняты; точное родительство доказано; ключей записано 2")
    return 0


def self_test():
    import yaml

    fixture = yaml.safe_load((ROOT / "tests/authz-fixtures/registry-own-stand-fixture.yaml").read_text())
    assert fixture["module"] == "registry" and fixture["revision"] > 0
    resource = next(item for item in fixture["resources"] if item["name"] == "registries")
    assert resource["objectType"] == "registry_registry"
    assert {"get", "update", "delete"} <= {item["name"] for item in resource["verbs"]}
    assert fixture["seed"]["serviceAccounts"][0]["name"] == "kacho-registry"
    assert fixture["seed"]["joins"][0]["group"]["name"] == "module-relation-writers"
    values = {"accountAId": "acc" + "1" * 17, "projectA1Id": "prj" + "2" * 17}
    row = intent(values)
    validate_intent(row, values)
    count = 2
    for key in ("parentChain", "parentProjectId", "parentAccountId", "object", "sourceVersion"):
        bad = dict(row)
        bad[key] = ""
        try:
            validate_intent(bad, values)
        except own.Finding:
            count += 1
        else:
            raise AssertionError("не замечено повреждение " + key)

    class Fake:
        def __init__(self, failure=""):
            self.failure, self.calls = failure, []

        def call(self, method, body):
            self.calls.append(method)
            if method == "RegisterResource" and self.failure == "registration":
                raise own.Finding("denied")
            if method == "Check":
                return {"allowed": self.failure == "wide" or (self.failure != "absent" and body["subjectId"] == row["subjectId"])}
            return {}

    fake = Fake()
    assert prove(fake, row)[KEYS[1]] == values["projectA1Id"]
    assert fake.calls == ["RegisterResource", "RegisterResource", "Check", "Check"]
    count += 1
    for failure in ("registration", "wide", "absent"):
        try:
            prove(Fake(failure), row)
        except own.Finding:
            count += 1
        else:
            raise AssertionError("ложный proof: " + failure)
    print("registry seed self-test: passed=" + str(count) + " failed=0")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki", default=str(ROOT / ".stand/pki"))
    parser.add_argument("--grpc-addr", default="localhost:9091")
    parser.add_argument("--env-file", default=str(ROOT / "tests/newman/environments/local.postman_environment.json"))
    parser.add_argument("--ledger", default=str(ROOT / ".stand/run/registry-intent.json"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--minted-keys", action="store_true")
    parser.add_argument("--minted-surface", action="store_true")
    args = parser.parse_args()
    if args.minted_keys:
        print("\n".join(KEYS))
        return 0
    if args.minted_surface:
        print(own.MINTED_SURFACE)
        return 0
    try:
        return self_test() if args.self_test else run(args)
    except own.Unmet as error:
        print("УСЛОВИЕ НЕ СОЗДАНО: " + str(error))
        return 75
    except (own.Finding, OSError, ValueError) as error:
        print("НАХОДКА: " + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
