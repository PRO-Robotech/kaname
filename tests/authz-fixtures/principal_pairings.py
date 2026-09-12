#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1
"""Which emitted id is the principal of which emitted Bearer — declared, then checked.

WHY THIS IS ITS OWN MODULE. `prodseed_matrix` mints the bootstrap Bearer at IMPORT time,
so importing it dials the stand. A self-test that cannot be run without a cluster is a
self-test nobody runs, and these functions are exactly the part that must be provable
offline. Nothing here touches a network, a file or a clock.

WHAT IT IS FOR. A suite that binds a role to `{{<id>}}` and then reads with
`{{<token>}}` depends on the two naming the SAME principal. That is the one fixture
property such a suite cannot check for itself: from inside the case, a mismatch is
indistinguishable from a grant that has not materialised yet, so it presents as a
timeout — in the wrong place, with the wrong explanation, six steps later.

It is not hypothetical. One channel's subject id was discarded at creation, and the
nearest-looking id in the env — an unrelated user row — got bound instead. The relation
then named a `user` while every request authenticated as a `service_account`, so it could
not resolve at any budget. The invariant had been written down for the neighbouring
channel, as a comment, and honoured there; what was missing was making it DATA, so that
honouring it is checked rather than remembered.
"""
from __future__ import annotations

import base64
import json
import re

# `<id-key>: <token-key>` — the id-key must be the id of the principal the token-key
# authenticates as.
#
# NOT EVERY EMITTED ID BELONGS HERE, AND THE ABSENCE IS MEANINGFUL. `userAAAId` /
# `userAABId` / `userNOBId` / `userINVId` / `userPA1Id` / `userPureNoBindingsId` are
# BINDING TARGETS only — real user rows so the subject-exists trigger resolves. No
# emitted token authenticates as any of them, and none can: a machine harness obtains
# `client_credentials`, i.e. a service account (mint_rs256 says why — a user token needs
# an interactive login to carry `acr`, and the issued one is scoped to an internal
# audience the edge does not accept). Pairing one of them with a `jwt*` key is the defect
# described above, not a gap in this table.
# Имя утверждения о принципале — ОДНО объявление на модуль. Три литерала в
# трёх местах разошлись бы молча, и разошлись бы там, где это не видно.
_PRINCIPAL_CLAIM = "kaname_principal_id"

# BINDING_TARGET_ONLY_IDS — та же врезка выше, но ДАННЫМИ (задача #1441, п.5).
#
# ПОЧЕМУ ДАННЫМИ, А НЕ ПРОЗОЙ. Урок этого модуля записан в его собственной шапке:
# инвариант «id и токен называют одного принципала» БЫЛ записан — комментарием у
# соседнего канала — и там соблюдался; не хватало ровно того, чтобы соблюдение
# ПРОВЕРЯЛОСЬ, а не помнилось. Врезка про «не всякий id сюда попадает» осталась
# прозой и повторила судьбу того комментария: шесть шапок кейсов iam утверждали
# ровно то, что она запрещает.
#
# ЧТО ЭТО ЗА НАБОР. Строки пользователей, заведённые ЦЕЛЯМИ ПРИВЯЗКИ — чтобы
# триггер существования субъекта разрешился. Ни один выдаваемый предъявитель не
# аутентифицируется ни одним из них, и не может: машинный харнесс получает
# `client_credentials`, то есть служебную учётку.
#
# ЧЕГО НАБОР НЕ ОЗНАЧАЕТ. Он НЕ перечисляет «все идентификаторы людей»: человек
# церемонии (`ceremonyUserId`) добывается настоящим входом паролем и своим
# предъявителем аутентифицируется законно. Сюда попадает только то, у чего
# предъявителя нет by construction.
BINDING_TARGET_ONLY_IDS = frozenset({
    "userAAAId",
    "userAABId",
    "userNOBId",
    "userINVId",
    "userPA1Id",
    "userPureNoBindingsId",
})

# Две ФОРМЫ ЗАПИСИ пары в шапке кейса — блок «CRUD fixture dependency».
#
# ОБЕ, А НЕ ОДНА: перепись по дереву (2026-08-31, 38 шапок) нашла прямую запись
# «<слот> — JWT for <id>» и обратную «<id> — User.id of <слот> principal», и
# распознаватель, знающий одну, оставил бы вторую вне наблюдения — не находкой,
# а невидимостью.
#
# ЧЕГО ЭТИ ОБРАЗЦЫ НЕ ЧИТАЮТ, и это объявленный предел, а не упущение: свободную
# прозу («Happy: <слот> → 200, subject == "user:<id>"»). Отличить в прозе
# УТВЕРЖДЕНИЕ от ПРЕДОСТЕРЕЖЕНИЯ («субъект выдачи — svaInviteeId, А НЕ userINVId»)
# и от ПЕРЕЧИСЛЕНИЯ переменных нечем: замер по тому же дереву дал 23 кандидата на
# 15 нарушений, то есть каждая третья находка была бы ложной. Прибор, у которого
# треть находок ложна, перестают читать — и вместе с ним перестают читать
# настоящую. Поэтому образцы держатся СТРУКТУРНОГО блока зависимостей фикстуры,
# где форма записи табличная; на нём ложных находок ноль (13 из 13 разобраны).
_CLAIM_FORWARD = re.compile(
    r"\b(jwt[A-Za-z0-9]+)\s+[\u2014-]+\s+(?:JWT|Bearer|bearer)\s+for\b([^\n]*)")
_CLAIM_REVERSE = re.compile(
    r"\b([A-Za-z0-9]+Id)\s+[\u2014-]+\s+User\.id of\s+(jwt[A-Za-z0-9]+)\b")
_ID_TOKEN = re.compile(r"\b([A-Za-z0-9]+Id)\b")


def header_principal_claims(doc: str) -> list[tuple[int, str, str]]:
    """Пары «предъявитель ↔ id», объявленные шапкой и НЕВОЗМОЖНЫЕ by construction.

    Возвращает `(номер строки шапки, слот-предъявитель, id)` по каждой находке.
    Пустой список — шапка не утверждает ни одной такой пары.

    Ничего не читает с диска и не ходит в сеть: на вход — текст шапки, на выход —
    разбор. Это то же требование, что у остального модуля, и оно тут не ради
    аккуратности — самопроверка, которую нельзя прогнать без стенда, это
    самопроверка, которую никто не гоняет.
    """
    out: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(doc.splitlines(), 1):
        for m in _CLAIM_FORWARD.finditer(line):
            for ident in _ID_TOKEN.findall(m.group(2)):
                if ident in BINDING_TARGET_ONLY_IDS:
                    out.append((lineno, m.group(1), ident))
        for m in _CLAIM_REVERSE.finditer(line):
            if m.group(1) in BINDING_TARGET_ONLY_IDS:
                out.append((lineno, m.group(2), m.group(1)))
    return out

PRINCIPAL_PAIRINGS = {
    "svaAId": "jwtSAA",
    "svaInviteeId": "jwtInvitee",
    "svaNoGrantId": "jwtSANoGrant",
    "svaPureNoGrantId": "jwtPureNoBindings",
    "svaStorageCreateListOnlyId": "jwtStorageCreateListOnlyA",
}


def token_principal_id(token: str) -> str:
    """Principal id a Bearer authenticates as, or "" if it carries none.

    READS THE SAME SHAPES THE EDGE READS, IN THE SAME ORDER — top level first,
    then the nested `ext_claims` map. Not a nicety: this function exists to
    predict what the edge will make of a token, so any shape the edge honours
    and this one does not turns a SOUND channel into a seed abort, and the abort
    lands on the whole run (measured: run 32669585825, four shards, 0 of 18
    collections executed, five sound service-account channels condemned).

    WHY BOTH SHAPES ARE REAL, i.e. why this is not defensive coding. The platform
    issues principal Bearers by two lanes, and they place the enrichment claims
    differently BY CONSTRUCTION:

      * our own issuer signs them FLAT at the top level — `tokensigner.Sign`
        copies the composed claim map straight into the payload, which is the
        placement the product's own test asserts
        (`TestClaimsComeFromTheSingleDeclarationAndCarryTheClientIdentifier`);
      * the external provider nests them, because the only place in the tree that
        wraps the map under `ext_claims` is the provider's token/refresh hook
        handler, and the provider then carries that map as its own `ext` claim.

    The edge already treats the two as equivalent (`verifiedClaim` in
    gateway/internal/middleware/auth.go: "preferring the top-level claim, then the
    nested ext_claims map"). This function is the harness-side mirror of that rule.

    Deliberately NOT `sub`: on a client_credentials token that is the OAuth client
    id and equals no kacho id at all, so a comparison against it reports EVERY
    pairing broken, the sound ones included. (Measured: the first version of this
    check did exactly that and would have condemned a channel that was correct.)
    """
    if not isinstance(token, str) or token.count(".") < 2:
        return ""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return ""
    if not isinstance(claims, dict):
        return ""
    # 1. Top level — where OUR issuer states it, and what the edge prefers.
    got = claims.get(_PRINCIPAL_CLAIM, "")
    if isinstance(got, str) and got:
        return got
    # 2. Nested `ext_claims`, either bare or under the provider's `ext` envelope.
    ext = claims.get("ext_claims")
    if not isinstance(ext, dict):
        outer = claims.get("ext")
        ext = outer.get("ext_claims") if isinstance(outer, dict) else None
    if not isinstance(ext, dict):
        return ""
    got = ext.get(_PRINCIPAL_CLAIM, "")
    return got if isinstance(got, str) else ""


def unpaired_principals(fixtures: dict, pairings: dict | None = None) -> list[str]:
    """Declared pairings that do NOT hold — one human-readable line each.

    A declared pair whose BOTH keys are absent is not a finding: that profile simply did
    not emit the channel. A pair with one side present and the other missing IS one —
    half a channel is precisely how the original defect looked from outside.
    """
    table = PRINCIPAL_PAIRINGS if pairings is None else pairings
    broken: list[str] = []
    for id_key, tok_key in table.items():
        have_id, have_tok = id_key in fixtures, tok_key in fixtures
        if not have_id and not have_tok:
            continue
        if not have_id or not have_tok:
            broken.append(
                f"{id_key} ↔ {tok_key}: only {id_key if have_id else tok_key} was emitted")
            continue
        want, got = fixtures[id_key], token_principal_id(fixtures[tok_key])
        if not got:
            broken.append(
                f"{id_key} ↔ {tok_key}: the token carries no principal id (expected {want})")
        elif got != want:
            broken.append(
                f"{id_key} ↔ {tok_key}: bound subject is {want}, "
                f"but the token authenticates as {got}")
    return broken


def make_token(principal_id: str, *, nest: bool = False) -> str:
    """Unsigned JWS-shaped string carrying `principal_id` — for self-tests ONLY.

    Signature segment is the literal `not-a-signature`, which no verifier accepts. The
    point is to keep test fixtures visibly NOT credentials: a realistic-looking token in
    a fixture is how a substitution starts reading like a correct hand-off.
    """
    inner = {_PRINCIPAL_CLAIM: principal_id, "kaname_principal_type": "service_account"}
    claims = {"ext": {"ext_claims": inner}} if nest else {"ext_claims": inner}
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + body + ".not-a-signature"
