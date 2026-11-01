# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#1037: групповая фикстура доказывает ACTIVE-членство без выдачи ролей."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "authz-fixtures"))
import seed_own_stand as seed


class Front:
    def __init__(self, field=None, read_code=200):
        self.field = field
        self.read_code = read_code
        self.created = []

    def json_ask(self, url, **kw):
        row = {"id": "mbr-fixture", "accountId": "acc-a", "userId": "usr-group", "state": "ACTIVE"}
        if kw.get("method") == "POST":
            self.created.append(kw["body"])
            return 200, {"id": "iop-fixture"}
        if self.field:
            row[self.field] = "PENDING" if self.field == "state" else "wrong"
        if "/operations/" in url:
            return 200, {"done": True, "response": row}
        return self.read_code, row


def test_active_same_account_twin_has_no_role_assignment():
    front = Front()
    seed.active_group_account_member(front, "https://fixture", "token", "acc-a", "group@fixture.invalid", "usr-group")
    assert front.created == [{"accountId": "acc-a", "email": "group@fixture.invalid"}]


@pytest.mark.parametrize("field", ["accountId", "userId", "state"])
def test_one_fact_wrong_membership_is_rejected(field):
    with pytest.raises(seed.Finding, match="ACTIVE"):
        seed.active_group_account_member(Front(field), "https://fixture", "token", "acc-a", "group@fixture.invalid", "usr-group")


def test_unreadable_membership_is_rejected():
    with pytest.raises(seed.Finding, match="чтение"):
        seed.active_group_account_member(Front(read_code=403), "https://fixture", "token", "acc-a", "group@fixture.invalid", "usr-group")
