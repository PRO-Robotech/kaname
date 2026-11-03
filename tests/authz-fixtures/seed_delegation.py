#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Complete the ordinary own-stand delegation Given through public Kaname APIs.

The existing module/resource producer remains authoritative. This adds only two
unprivileged test SAs and their normally issued/exchanged credentials: the GD-E
delegate in B, and the group-membership twin delegate in A. No delegation or
binding is pre-created; Newman owns those mutations and their assertions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets

import seed_own_stand as own

ROOT = Path(__file__).resolve().parents[2]
KEYS = ("gdDelegateSaId", "jwtGDDelegate", "gdGroupDelegateSaId",
        "jwtGDGroupDelegate", "gdRegistryRolesDelivered",
        "gdRolePullerId", "gdRolePusherId", "gdRoleAdminId")


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
    own.write_env(patch, env_file, env_file)
    Path(args.ledger).write_text(json.dumps(ledger, indent=2) + "\n")
    print("delegation seed: 3 live module roles; 2 distinct unprivileged test SAs; 2 real credential exchanges")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki", default=str(ROOT / ".stand/pki"))
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
