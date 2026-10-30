#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#1033: ресурс registry через владельца модуля; делегирование не создаётся."""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile

import seed_own_stand as own

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS = ("gdRegistryId", "gdRegistryProjectId", "escRoleEdit", "escGroupEdit")
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
    return {"subjectId": "project:" + project, "relation": "project",
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

    def request(self, method, body):
        try:
            proc = subprocess.run(self.args + ["-d", json.dumps(body), self.address, SERVICE + method],
                                  capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise own.Unmet("внутренний слушатель не ответил") from None
        return proc

    def call(self, method, body):
        proc = self.request(method, body)
        if proc.returncode:
            error = proc.stderr.lower()
            if any(word in error for word in ("connection refused", "no such host", "context deadline", "code: unavailable")):
                raise own.Unmet("внутренний слушатель или источник вердикта недоступен")
            # Не печатаем сырой ответ, ключи или адреса.
            raise own.Finding(method + ": отказ владельцу registry, grpcurl rc=" + str(proc.returncode))
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise own.Finding(method + ": ответ не JSON") from None

    def refused(self, row, tls=False):
        proc = self.request("RegisterResource", row)
        message = proc.stderr.lower()
        matches = ("tls" in message and "certificate" in message) if tls else any(
            code in message for code in ("code: permissiondenied", "code: unauthenticated"))
        if proc.returncode == 0 or not matches:
            raise own.Finding("отрицательный контроль регистрации не получил свой отказ")


def live_refusals(registrar, row, pki):
    """Та же цель и исправный близнец до и после каждой отрицательной подачи."""
    def paired(other, body, tls=False):
        prove(registrar, row)
        other.refused(body, tls=tls)
        prove(registrar, row)

    # Доверенный лист службы не является объявленной личностью писателя registry.
    without_identity = Registrar(pki, registrar.address)
    without_identity.args = [str(pki / "srv.crt") if value == str(pki / "registry.crt")
                             else str(pki / "srv.key") if value == str(pki / "registry.key")
                             else value for value in without_identity.args]
    paired(without_identity, row)
    foreign = dict(row, object="vpc_network:net" + row["object"].split(":", 1)[1][3:])
    paired(registrar, foreign)
    # Другая CA действительно подписывает лист с тем же SAN; серверу доверяем
    # по прежней CA. Отказ проверяет клиентского издателя, не серверный TLS.
    with tempfile.TemporaryDirectory(prefix="registry-issuer-") as directory:
        other = pathlib.Path(directory)
        shutil.copyfile(pki / "ca.crt", other / "ca.crt")
        ext = other / "leaf.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       "extendedKeyUsage=clientAuth\nsubjectAltName=URI:spiffe://kaname.local/ns/kaname/sa/kacho-registry\n")
        commands = [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=untrusted-fixture-issuer", "-keyout", str(other / "issuer.key"), "-out", str(other / "issuer.crt")],
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=kacho-registry",
             "-keyout", str(other / "registry.key"), "-out", str(other / "leaf.csr")],
            ["openssl", "x509", "-req", "-in", str(other / "leaf.csr"), "-CA", str(other / "issuer.crt"),
             "-CAkey", str(other / "issuer.key"), "-CAcreateserial", "-days", "1", "-extfile", str(ext),
             "-out", str(other / "registry.crt")],
        ]
        for command in commands:
            result = subprocess.run(command, capture_output=True, timeout=30)
            if result.returncode:
                raise own.Unmet("не удалось выпустить отрицательный клиентский лист")
        paired(Registrar(other, registrar.address), row, tls=True)
    print("registry live negatives: unrecognized identity, foreign module type, wrong issuer refused; paired positives passed")


def prove(registrar, row):
    # Повтор того же intent обязан быть идемпотентным.
    for _ in range(2):
        registrar.call("RegisterResource", row)
    for subject, allowed in ((row["subjectId"], True),
                             ("project:prj" + "0" * 17, False)):
        response = registrar.call("Check", {"subjectId": subject, "relation": row["relation"],
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
    http = own.Http(pki)
    code, body = http.json_ask(public + "/iam/v1/projects/" + project, token=token)
    if code != 200 or body.get("accountId") != required(values, "accountAId"):
        raise own.Finding("проект не подтвердил свой аккаунт")
    registrar = Registrar(pki, args.grpc_addr)
    roles = {}
    for key, name in (("escRoleEdit", "iam.role.edit"), ("escGroupEdit", "iam.group.edit")):
        role_id = own.builtin_role_id(http, public, token, name)
        # Коллекция также вычисляет эти идентификаторы; сверяем с живым каталогом.
        if role_id != "rol" + hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()[:17]:
            raise own.Finding("идентификатор роли коллекции расходится с живым каталогом")
        roles[key] = role_id
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
            if any(values.get(key) for key in KEYS[:2]):
                raise own.Finding("окружение называет registry без намерения владельца")
            row = intent(values)
            fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(row, out)
                out.flush()
                os.fsync(out.fileno())
        validate_intent(row, values)
        live_refusals(registrar, row, pki)
        patch = prove(registrar, row)
        patch.update(roles)
        for key in KEYS:
            if values.get(key) and values[key] != patch[key]:
                raise own.Finding("окружение расходится с ресурсом владельца: " + key)
        own.write_env(patch, env_file, env_file)
    print("registry seed: регистрация и повтор приняты; точное родительство доказано; ключей записано 4")
    return 0


def self_test():
    import yaml
    from types import SimpleNamespace

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
    # Сверяем структурное ребро с канонической моделью, а не с собственным fake.
    model = (ROOT / "internal/authzmodel/fga_model.fga").read_text()
    registry_model = model.split("\ntype registry_registry\n", 1)[1].split("\ntype ", 1)[0]
    assert row["relation"] == "project"
    assert "define " + row["relation"] + ": [project]" in registry_model
    count = 4
    for key in ("relation", "parentChain", "parentProjectId", "parentAccountId", "object", "sourceVersion"):
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
                assert body["relation"] == row["relation"]
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
    for code, message, tls, expected in (
            (1, "Code: PermissionDenied", False, True),
            (1, "remote error: tls: bad certificate", True, True),
            (0, "", False, False),
            (1, "Code: Unavailable", False, False),
            (1, "connection refused", True, False)):
        probe = Registrar.__new__(Registrar)
        probe.request = lambda *_: SimpleNamespace(returncode=code, stderr=message)
        accepted = True
        try:
            probe.refused(row, tls=tls)
        except own.Finding:
            accepted = False
        assert accepted is expected, "не тот класс отрицательного ответа"
        count += 1
    for code, message, expected in (
            (78, "Code: Unavailable", own.Unmet),
            (71, "Code: PermissionDenied", own.Finding)):
        probe = Registrar.__new__(Registrar)
        probe.request = lambda *_: SimpleNamespace(returncode=code, stderr=message, stdout="")
        try:
            probe.call("Check", row)
        except expected:
            count += 1
        else:
            raise AssertionError("не тот класс отказа положительной проверки")
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
