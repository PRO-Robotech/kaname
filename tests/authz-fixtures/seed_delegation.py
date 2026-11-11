#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Обычное Дано делегирования через собственные API Kaname.

Сохраняет прежние GD-E фикстуры и добавляет #1032: настоящий U из ceremony,
отдельные P/X/Y, S/S2/M с обычными ключами/обменами и G={M}. Делегирования
и выдачи создаёт сама коллекция. Штатный seed_ceremony должен завершиться
раньше этого производителя; отсутствие входа не считается RED Update.
"""
from __future__ import annotations

import argparse
import datetime
import time
import hashlib
import json
import os
from pathlib import Path
import secrets

import seed_own_stand as own
import seed_registry_resource as registry

ROOT = Path(__file__).resolve().parents[2]
KEYS = ("gdDelegateSaId", "jwtGDDelegate", "gdGroupDelegateSaId",
        "jwtGDGroupDelegate", "gdRegistryRolesDelivered",
        "gdRolePullerId", "gdRolePusherId", "gdRoleAdminId",
        "gduAccountId", "gduProjectId", "gduRegistryId", "gduRepositoryId",
        "gduSId", "jwtGDUS", "gduS2Id", "jwtGDUS2", "gduMId", "jwtGDUM",
        "gduGroupId", "gduGivenReady", "gduAccountAdminRoleId")


def run(args):
    os.umask(0o077)
    env_file = Path(args.env_file)
    values = {v["key"]: v.get("value") for v in json.loads(env_file.read_text())["values"]
              if v.get("enabled", True)}
    def required(key):
        value = values.get(key)
        if not isinstance(value, str) or not value:
            raise own.Unmet("delegation fixture input missing: " + key)
        return value
    if any(values.get(key) for key in KEYS):
        raise own.Unmet("delegation producer requires a fresh own-stand environment")
    # Реальные люди создаются предшествующей штатной ceremony-полосой.
    for key in ("jwtHumanCeremony", "jwtHumanCeremonyStepUp", "ceremonyUserId",
                "ceremonyAccountId", "jwtHumanEscStepUp", "humanEscUserId",
                "jwtHumanAidAdmSharedStepUp", "humanAidAdmSharedUserId"):
        required(key)
    public = required("ownRestBaseUrl")
    token_url = required("iamRegistryTokenBaseUrl") + "/iam/v1/token"
    account_a, account_b = required("accountAId"), required("accountBId")
    if account_a == account_b:
        raise own.Finding("delegation fixture accounts must be distinct")
    required("gdRegistryId")
    required("gdRegistryProjectId")
    http = own.Http(Path(args.pki))
    admin_a = required("jwtAccountAdminAStepUp")
    admin_b = required("jwtAccountAdminB")
    roles = []
    for name in ("registry.puller", "registry.pusher", "registry.admin"):
        role_id = own.builtin_role_id(http, public, admin_a, name)
        expected = "rol" + hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()[:17]
        code, role = http.json_ask(public + "/iam/v1/roles/" + role_id, token=admin_a)
        rules = role.get("rules") or []
        resources = {resource for rule in rules for resource in rule.get("resources", [])}
        if (code != 200 or role_id != expected or role.get("name") != name or not rules
                or any(rule.get("module") != "registry" for rule in rules)
                or not {"registries", "repositories"}.issubset(resources)
                or role.get("definitionTier") != {"tierType": "iam.cluster", "tierId": "cluster_root"}):
            raise own.Finding("live delivered role does not match the public delegation fixture: " + name)
        roles.append(role_id)
    run_id = secrets.token_hex(5)
    patch = {"gdRegistryRolesDelivered": "true",
             "gdRolePullerId": roles[0], "gdRolePusherId": roles[1], "gdRoleAdminId": roles[2]}
    ledger = {"runId": run_id, "roles": roles, "subjects": []}
    for account, admin, prefix, id_key, token_key in (
        (account_b, admin_b, "gd-edge-delegate", "gdDelegateSaId", "jwtGDDelegate"),
        (account_a, admin_a, "gd-group-delegate", "gdGroupDelegateSaId", "jwtGDGroupDelegate"),
    ):
        subject = own.make_service_account(http, public, admin, account,
                                           prefix + "-" + run_id, run_id, prefix)
        own.assert_no_bindings(http, public, admin, subject)
        code, live = http.json_ask(public + "/iam/v1/serviceAccounts/" + subject, token=admin)
        if code != 200 or live.get("id") != subject or live.get("accountId") != account:
            raise own.Finding("new delegate does not have the required account lineage")
        token = own.sa_token(http, public, token_url, admin, subject, run_id, prefix)
        own.assert_serves(http, public, token, "/iam/v1/me", prefix)
        patch.update({id_key: subject, token_key: token})
        ledger["subjects"].append({"id": subject, "accountId": account, "directBindings": 0})
    seed_update_given(args, http, values, patch, ledger, run_id)
    own.write_env(patch, env_file, env_file)
    Path(args.ledger).write_text(json.dumps(ledger, indent=2) + "\n")
    print("delegation seed: 3 живые роли; 5 непривилегированных SA и обменов; G={M}; X/Y и lineage; selfCheck=false")
    return 0



def seed_update_given(args, http, values, patch, ledger, run_id):
    """Дано #1032: обычные публичные мутации и доставка ресурса владельцем модуля."""
    public = values["ownRestBaseUrl"]
    owner, user = values["jwtHumanCeremonyStepUp"], values["ceremonyUserId"]
    account = values["ceremonyAccountId"]
    code, row = http.json_ask(public + "/iam/v1/accounts/" + account, token=owner)
    if code != 200 or row.get("ownerUserId") != user:
        raise own.Finding("GDU U не подтверждён как Account.ownerUserId")
    # ACR1 и ACR2 — один настоящий человек; C — другой настоящий cloud-admin.
    for token_key, expected, system_admin in (
            ("jwtHumanCeremony", "user:" + user, False),
            ("jwtHumanCeremonyStepUp", "user:" + user, False),
            ("jwtHumanEscStepUp", "user:" + values["humanEscUserId"], False),
            ("jwtHumanAidAdmSharedStepUp", "user:" + values["humanAidAdmSharedUserId"], True)):
        code, me = http.json_ask(public + "/iam/v1/me", token=values[token_key])
        if code != 200 or me.get("subject") != expected or bool(me.get("systemAdmin")) != system_admin:
            raise own.Finding("GDU живая личность/облачное полномочие не совпало: " + token_key)
    if len({user, values["humanEscUserId"], values["humanAidAdmSharedUserId"]}) != 3:
        raise own.Finding("GDU U/E/C должны быть разными людьми")
    project = own.post_operation(http, public, owner, "/iam/v1/projects",
        {"accountId": account, "name": "gdu-" + run_id}, "GDU Project.Create")["id"]
    code, row = http.json_ask(public + "/iam/v1/projects/" + project, token=owner)
    if code != 200 or row.get("accountId") != account:
        raise own.Finding("GDU проект не подтвердил account lineage")
    patch.update({"gduAccountId": account, "gduProjectId": project,
                  "gduAccountAdminRoleId": own.builtin_role_id(http, public, owner, "admin")})
    registrar = registry.Registrar(Path(args.pki), args.grpc_addr)
    x = "reg" + "".join(secrets.choice("0123456789abcdefghjkmnpqrstvwxyz") for _ in range(17))
    y = x + "/gdu-" + run_id
    version = datetime.datetime.now(datetime.timezone.utc)
    lineage = []
    # Версия упорядочивает объект целиком: owner должен быть новее его указателя.
    for offset, (obj, subject, relation, chain) in enumerate((
            ("registry_registry:" + x, "project:" + project, "project", ["project:" + project, "account:" + account]),
            ("registry_registry:" + x, "user:" + user, "owner", ["project:" + project, "account:" + account]),
            ("registry_repository:" + y, "registry_registry:" + x, "parent", ["registry_registry:" + x, "project:" + project, "account:" + account]),
            ("registry_repository:" + y, "user:" + user, "owner", ["registry_registry:" + x, "project:" + project, "account:" + account]))):
        stamp = (version + datetime.timedelta(microseconds=offset)).isoformat().replace("+00:00", "Z")
        intent = {"object": obj, "subjectId": subject, "relation": relation,
                  "parentProjectId": project, "parentAccountId": account,
                  "parentChain": chain, "sourceVersion": stamp}
        registrar.call("RegisterResource", intent)
        got = registrar.call("Check", {"object": obj, "subjectId": subject,
            "relation": relation, "consistency": "HIGHER_CONSISTENCY"})
        if got.get("allowed") is not True:
            raise own.Finding("GDU RegisterResource не подтвердил объявленную связь")
        lineage.append(intent)
    patch.update({"gduRegistryId": x, "gduRepositoryId": y})
    token_url = values["iamRegistryTokenBaseUrl"] + "/iam/v1/token"
    for tag, id_key, token_key in (("s", "gduSId", "jwtGDUS"),
                                  ("s2", "gduS2Id", "jwtGDUS2"),
                                  ("m", "gduMId", "jwtGDUM")):
        subject = own.make_service_account(http, public, owner, account,
            "gdu-" + tag + "-" + run_id, run_id, "GDU " + tag)
        own.assert_no_bindings(http, public, owner, subject)
        code, row = http.json_ask(public + "/iam/v1/serviceAccounts/" + subject, token=owner)
        if code != 200 or row.get("accountId") != account or row.get("id") != subject:
            raise own.Finding("GDU субъект не подтвердил account lineage")
        token = own.sa_token(http, public, token_url, owner, subject, run_id, "GDU " + tag)
        code, me = http.json_ask(public + "/iam/v1/me", token=token)
        if code != 200 or me.get("subject") != "service_account:" + subject or me.get("systemAdmin", False):
            raise own.Finding("GDU машинное удостоверение не подтвердило свой субъект")
        patch.update({id_key: subject, token_key: token})
        ledger["subjects"].append({"id": subject, "accountId": account, "directBindings": 0})
    group = own.post_operation(http, public, owner, "/iam/v1/groups",
        {"accountId": account, "name": "gdu-only-m-" + run_id}, "GDU Group.Create")["id"]
    own.post_operation(http, public, owner, "/iam/v1/groups/" + group + ":addMember",
        {"memberType": "service_account", "memberId": patch["gduMId"]}, "GDU Group.AddMember")
    # Ждём готовность существующего пути чтения, а не угадываем задержку проекции.
    deadline = time.monotonic() + 60
    while True:
        code, decision = http.json_ask(public + "/iam/v1/authorize:check", method="POST", token=owner,
            body={"subject": "user:" + user, "resource": {"type": "iam_group", "id": group},
                  "action": "iam.group_memberses.listMembers", "requiredRelation": "v_list"})
        if code != 200:
            raise own.Finding("GDU готовность Group.ListMembers не дала HTTP 200")
        if decision.get("allowed") is True:
            break
        if time.monotonic() >= deadline:
            raise own.Finding("GDU Group.ListMembers не стал готов за 60 секунд")
        time.sleep(0.25)
    code, members = http.json_ask(public + "/iam/v1/groups/" + group + ":listMembers", token=owner)
    got = [(m.get("memberType"), m.get("memberId")) for m in members.get("members", [])]
    if code != 200 or got != [("service_account", patch["gduMId"])] or members.get("nextPageToken"):
        raise own.Finding("GDU группа должна содержать ровно M")
    patch["gduGroupId"] = group
    for id_key, token_key in (("gduSId", "jwtGDUS"), ("gduS2Id", "jwtGDUS2"), ("gduMId", "jwtGDUM")):
        for typ, ident, resource, verb in (("registry_registry", x, "registries", "get"),
                ("registry_repository", y, "repositories", "get"),
                ("registry_repository", y, "repositories", "update")):
            code, result = http.json_ask(public + "/iam/v1/authorize:check", method="POST", token=patch[token_key],
                body={"subject": "service_account:" + patch[id_key], "resource": {"type": typ, "id": ident},
                      "action": "registry." + resource + "." + verb, "requiredRelation": "v_" + verb})
            if code != 200 or result.get("allowed") is not False:
                raise own.Finding("GDU новый субъект обязан получить HTTP 200 allowed=false")
    patch["gduGivenReady"] = "true"
    ledger["gdu"] = {"ownerUserId": user, "accountId": account, "projectId": project,
                     "lineage": lineage, "groupId": group, "memberId": patch["gduMId"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki", default=str(ROOT / ".stand/pki"))
    parser.add_argument("--grpc-addr", default="localhost:9091")
    parser.add_argument("--ledger", default=str(ROOT / ".stand/run/delegation-subjects.json"))
    parser.add_argument("--env-file", default=str(ROOT / "tests/newman/environments/local.postman_environment.json"))
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
        return run(args)
    except own.Unmet as error:
        print("УСЛОВИЕ НЕ СОЗДАНО: " + str(error))
        return 75
    except (own.Finding, OSError, ValueError) as error:
        print("НАХОДКА: " + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
