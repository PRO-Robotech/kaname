# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Gate: every AccessBinding `:listByScope` read must be page-complete.

Why this gate exists
--------------------
`accessBindings:listByScope` is cursor-paginated: `page_size` defaults to **50**
(api-conventions.md «Pagination / filter»). A reader that issues the request
WITHOUT an explicit page size gets the first 50 rows plus a `nextPageToken` — and
every reader in this harness that then does `rows.filter(...)` treats that
truncated page as if it were the complete set.

That is not hypothetical. `account:accountA` is a long-lived shared fixture scope
that accumulates bindings across runs (73 rows on the kind stand at the time of
writing, of which every `usr`-subject row sits at index 53-55 — page 2). Two
readers silently broke on it:

  * `tests/authz-fixtures/setup.sh :: delete_binding_if_exists` — the KAC-132 NOB
    pre-clean. It found nothing to delete, so stale `userNOB` grants on account-A
    survived into the run and the whole `authz-deny` NOB deny-matrix flipped to
    ALLOW.
  * `cases/iam-authz-grant-check-propagation.py :: resolve_binding_id_step` — it
    failed to resolve the persisted binding id, so the PHANTOM id minted on the
    ALREADY_EXISTS duplicate-create path survived in the environment. The
    downstream FGA probe then asked for `v_delete` on an `iam_access_binding`
    that was rolled back and never existed, which reads exactly like a
    permission-model hole but is not one.

`cases/rbac-visibility-set.py` had already been fixed for this precise reason
("pageSize=1000: the account scope accumulates >50 bindings across re-runs, so
the default page (50) could page-out the stale binding") — the class was
diagnosed once and left live in the other two readers. This gate stops that.

Rule enforced
-------------
1. Every `accessBindings:listByScope` request URL — in the generated collections
   (the artifact newman actually runs), in the `cases/*.py` sources, and in the
   shared authz fixture seed — must carry an explicit `pageSize=`.
2. A reader that RESOLVES an id out of the response must be able to walk past the
   first page (`pageToken`) and must clear its output variable first, so a stale
   or phantom id can never survive a failed resolve.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
NEWMAN_DIR = HERE.parent
CASES_DIR = NEWMAN_DIR / "cases"
COLLECTIONS_DIR = NEWMAN_DIR / "collections"
REPO_ROOT = HERE.parents[4]
AUTHZ_FIXTURE_SETUP = REPO_ROOT / "tests" / "authz-fixtures" / "setup.sh"

LIST_BY_SCOPE = "accessBindings:listByScope"


def _iter_collection_urls():
    """Yield (collection_name, item_name, raw_url) for every request."""
    for col in sorted(COLLECTIONS_DIR.glob("*.postman_collection.json")):
        doc = json.loads(col.read_text())

        def walk(items, trail):
            for it in items or []:
                name = it.get("name", "?")
                if "item" in it:
                    walk(it["item"], f"{trail}/{name}")
                    continue
                url = (it.get("request") or {}).get("url")
                if isinstance(url, dict):
                    url = url.get("raw", "")
                if isinstance(url, str) and url:
                    yield_name = f"{trail}/{name}".lstrip("/")
                    found.append((col.name, yield_name, url))

        found: list = []
        walk(doc.get("item"), "")
        for row in found:
            yield row


def test_generated_collections_paginate_list_by_scope():
    """The shipped collections must never read a default-sized page of bindings."""
    offenders = [
        f"{col} :: {item} -> {url}"
        for col, item, url in _iter_collection_urls()
        if LIST_BY_SCOPE in url and "pageSize=" not in url
    ]
    assert not offenders, (
        "listByScope read without an explicit pageSize (default page = 50 rows; "
        "the shared account scope holds far more, so the filtered row pages out "
        "and the reader silently sees an incomplete set):\n  "
        + "\n  ".join(offenders)
    )


# A request URL may be built across several source lines (implicit string
# concatenation, `+` continuation). Look for the page size within a small window
# after the match rather than on the single matching line — a genuinely
# unpaginated request has no `pageSize=` anywhere near it.
_URL_WINDOW = 6


def _unpaginated_occurrences(text, label):
    offenders = []
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if LIST_BY_SCOPE not in line:
            continue
        if line.lstrip().startswith("#"):
            continue  # prose in a comment, not a request
        window = "\n".join(lines[idx:idx + _URL_WINDOW])
        if "pageSize=" in window:
            continue
        offenders.append(f"{label}:{idx + 1}: {line.strip()}")
    return offenders


def test_case_sources_paginate_list_by_scope():
    """Same rule at the source of truth, so a regen cannot reintroduce it."""
    offenders = []
    for src in sorted(CASES_DIR.glob("*.py")):
        offenders += _unpaginated_occurrences(src.read_text(), src.name)
    assert not offenders, (
        "listByScope request built without an explicit pageSize:\n  "
        + "\n  ".join(offenders)
    )


def test_authz_fixture_preclean_paginates():
    """The shared NOB pre-clean must see every binding in the scope.

    If it cannot, stale grants survive the seed and the authz-deny deny-matrix
    reports ALLOW where it must report DENY.
    """
    assert AUTHZ_FIXTURE_SETUP.is_file(), f"missing {AUTHZ_FIXTURE_SETUP}"
    offenders = _unpaginated_occurrences(
        AUTHZ_FIXTURE_SETUP.read_text(), "setup.sh")
    assert not offenders, (
        "authz-fixture listByScope read without an explicit pageSize:\n  "
        + "\n  ".join(offenders)
    )


def test_binding_resolver_walks_pages_and_clears_stale_output():
    """`resolve_binding_id_step` must page, and must never leave a stale id behind.

    The output variable is pre-seeded from `Operation.metadata.accessBindingId`,
    which on the ALREADY_EXISTS duplicate-create path is a freshly minted id that
    was rolled back and never persisted. If the resolve step cannot find the real
    row it must NOT leave that phantom in place — downstream steps would probe
    FGA for a non-existent object and report a bogus missing-relation.
    """
    src = (CASES_DIR / "iam-authz-grant-check-propagation.py").read_text()
    match = re.search(
        r"def resolve_binding_id_step\(.*?\n(?=\n\n# ─|\ndef )", src, re.S)
    assert match, "resolve_binding_id_step not found"
    body = match.group(0)

    assert "pageToken" in body, (
        "resolve_binding_id_step does not follow nextPageToken — it can only ever "
        "see the first page of a paginated scope")
    assert "nextPageToken" in body, (
        "resolve_binding_id_step ignores the response's nextPageToken cursor")
    assert re.search(r"unset\(.*out_env_key|unset\('\{out_env_key\}'|\{out_env_key\}.*unset", body) \
        or "unset" in body, (
        "resolve_binding_id_step never clears its output variable, so a phantom "
        "id from the duplicate-create path can survive a failed resolve")
