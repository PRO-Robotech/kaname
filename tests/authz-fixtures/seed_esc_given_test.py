#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Дано H после перезапуска: чужая выдача не становится предметом уборки."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import seed_delegation as seed


VALUES = {
    "humanEscUserId": "usr-esc", "ceremonyEscAccountId": "acc-esc",
    "jwtHumanEscStepUp": "human", "jwtHumanAidAdmSharedStepUp": "admin",
    "humanAidAdmSharedUserId": "usr-admin",
}


def owner_binding():
    return {"id": "acb-owner", "subjectType": "user", "subjectId": "usr-esc",
        "subjects": [{"type": "SUBJECT_TYPE_USER", "id": "usr-esc"}],
        "roleId": "rol" + hashlib.md5(b"owner", usedforsecurity=False).hexdigest()[:17],
        "scopeType": "iam.account", "scopeId": "acc-esc", "status": "ACTIVE",
        "grantedByUserId": "system", "deletionProtection": True,
        "target": {"allInScope": {}}, "delegationId": "", "expiresAt": None,
        "revokedAt": None}


class World:
    def __init__(self, rows=None):
        self.rows = [owner_binding()] if rows is None else copy.deepcopy(rows)
        self.mutations = []
        self.operations = {}
        self.next_page = ""
        self.incomplete = []
        self.owner = "usr-esc"
        self.admin_valid = True
        self.right_retained = False
        self.keep_deleted = False
        self.revoked_snapshots = []

    def json_ask(self, url, token=None, method="GET", body=None):
        if url.endswith("/me"):
            return 200, {"subject": "user:usr-esc" if token == "human" else "user:usr-admin",
                         "systemAdmin": token == "admin" and self.admin_valid}
        if url.endswith("/accounts/acc-esc"):
            return 200, {"id": "acc-esc", "ownerUserId": self.owner}
        if "accessBindings:listBySubject" in url:
            return 200, {"accessBindings": copy.deepcopy(self.rows),
                "nextPageToken": self.next_page, "incompleteMembershipGroupIds": self.incomplete}
        if url.endswith("authorize:check"):
            return 200, {"allowed": self.right_retained}
        if "/accessBindings/" in url:
            if method == "GET":
                return (200, copy.deepcopy(self.rows[0])) if self.rows else (404, {"code": 5})
            self.mutations.append(method)
            row = self.rows[0]
            if method == "PATCH":
                row["deletionProtection"] = body["deletionProtection"]
            elif method == "POST" and url.endswith(":revoke"):
                row.update(status="REVOKED", revokedAt="2026-11-12T00:00:00Z")
                self.revoked_snapshots.append(copy.deepcopy(row))
            elif method == "DELETE":
                if not self.keep_deleted:
                    self.rows = []
            else:
                raise AssertionError("неожиданная мутация")
            op = "op-" + str(len(self.mutations))
            self.operations[op] = copy.deepcopy(row)
            return 200, {"id": op}
        raise AssertionError("неожиданный запрос")

    def run(self):
        def await_done(http, public, token, op_id):
            return self.operations[op_id]
        with patch.object(seed.own, "await_operation", side_effect=await_done):
            seed.prepare_esc_given(self, "https://own", VALUES)


class EscGivenTests(unittest.TestCase):
    def test_expected_owner_is_revoked_then_deleted(self):
        world = World()
        world.run()
        self.assertEqual(world.mutations, ["PATCH", "POST", "DELETE"])
        self.assertEqual(world.rows, [])
        self.assertEqual(world.revoked_snapshots[0]["id"], "acb-owner")
        self.assertEqual(world.revoked_snapshots[0]["status"], "REVOKED")
        self.assertEqual(world.owner, VALUES["humanEscUserId"])

    def test_already_empty_given_does_not_mutate(self):
        world = World([])
        world.run()
        self.assertEqual(world.mutations, [])

    def test_foreign_and_unexpected_bindings_refuse_before_mutation(self):
        for field, value in (("scopeId", "acc-other"), ("subjectId", "usr-other"),
                ("roleId", "rol-other"), ("grantedByUserId", "usr-other"),
                ("subjects", [{"type": "SUBJECT_TYPE_USER", "id": "usr-other"}]),
                ("target", {"ids": ["obj-other"]}), ("deletionProtection", False),
                ("status", "REVOKED"), ("delegationId", "gdl-other")):
            with self.subTest(field=field):
                row = owner_binding()
                row[field] = value
                world = World([row])
                with self.assertRaises(seed.own.Finding):
                    world.run()
                self.assertEqual(world.mutations, [])

    def test_second_binding_refuses_before_mutation(self):
        world = World([owner_binding(), dict(owner_binding(), id="acb-second")])
        with self.assertRaises(seed.own.Finding):
            world.run()
        self.assertEqual(world.mutations, [])

    def test_incomplete_or_wrong_identity_refuses_before_mutation(self):
        for field, value in (("next_page", "more"), ("incomplete", ["group"]),
                             ("owner", "usr-other"), ("admin_valid", False)):
            with self.subTest(field=field):
                world = World()
                setattr(world, field, value)
                with self.assertRaises(seed.own.Finding):
                    world.run()
                self.assertEqual(world.mutations, [])

    def test_revoke_with_remaining_right_is_not_hidden_by_delete(self):
        world = World()
        world.right_retained = True
        with self.assertRaises(seed.own.Finding):
            world.run()
        self.assertEqual(world.mutations, ["PATCH", "POST"])

    def test_completed_delete_with_visible_row_is_a_finding(self):
        world = World()
        world.keep_deleted = True
        with self.assertRaises(seed.own.Finding):
            world.run()
        self.assertEqual(world.mutations, ["PATCH", "POST", "DELETE"])


if __name__ == "__main__":
    unittest.main()
