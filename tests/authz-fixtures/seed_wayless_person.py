#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ЛИЧНОСТЕЙ `ACTIVE` БЕЗ СПОСОБА ВХОДА на стенде посадки `own` (kaname#468).

ПРЕДМЕТ. «Дано» полосы «личность без способа входа» приёмки восстановления доступа
(`docs/engineering/acceptance/recovery-of-access.md`, редакция 9: Ф5-29, Ф5-30,
Ф5-34) и AWI-12 приёмки пары (`active-identity-has-a-way-in.md`): действующая
личность, у которой строк способов входа нет НИ ОДНОЙ, в форме «после переноса» —
с отметкой открытого пути восстановления. Продукт такую личность не производит ни
одним глаголом (Ф5 §5.6 (8)); приёмка строит её посевом (§5.5 (6)): заведение
регистрацией полосы и одна транзакция прямой записи. Набор
`kaname-recovery-lane` читает адреса этих личностей из окружения и дальше ходит
только глаголами продукта.

ЛИЧНОСТЕЙ ПЯТЬ, У КАЖДОЙ — СВОЙ КЕЙС, И НИ ОДНА НЕ ДЕЛИТСЯ (`PREFIXES`):

  · `wayN`   — адрес подтверждён · Ф5-34 (а): завершение заводит первую строку;
  · `wayNB`  — адрес подтверждён · Ф5-34 (в): кейс сам блокирует её надзором облака,
               поэтому посев отдаёт и идентификатор (`wayNBUserId`);
  · `wayA`   — адрес НЕ подтверждён · Ф5-29: код выдаётся и такому адресу;
  · `wayA30` — адрес НЕ подтверждён · Ф5-30 и AWI-12: предъявление кода подтверждает
               адрес и заводит первый пароль;
  · `wayN30` — адрес подтверждён · Ф5-30 (б), близнец по одному факту.

Кейс завершения тратит личность (после него у неё есть пароль), поэтому одна
личность на два кейса дала бы второму не тот мир.

ЧТО ДЕЛАЕТСЯ ЗАПИСЬЮ — РОВНО ОДНО, И ЭТО ТА ЖЕ ФОРМА, ЧТО У ПОСЕВА ЛИЧНОСТИ С КЛЮЧОМ
(`seed_key_person.drop_password_sql`): отметка открытого пути и снятие строки
пароля одной транзакцией — `ACTIVE` без строки законна только с отметкой
(`users_active_has_a_way_in_fk`). Оператор и проверка его возврата — общие с тем
посевом, второй копии нет. Всё остальное — глаголы полосы:

  1. регистрация; письмо регистрации дожидается приёмник стенда;
  2. у подтверждённых — предъявление кода письма регистрации (`seed_login_lane.seed`);
     у неподтверждённых — ничего: вход после регистрации обязан назвать
     `session.emailVerified: false`, иначе мир кейса не тот (находка);
  3. запись; утверждение — вход прежним паролем отвергнут (`401`): способа входа
     у личности больше нет.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — личности лежат, окружение записано;
    1  — НАХОДКА: глагол полосы ответил не по контракту там, где посев предъявил
         всё требуемое (регистрация, подтверждение, положение сессии, вход после
         снятия строки, возврат оператора записи);
   75  — УСЛОВИЕ НЕ СОЗДАНО: полоса, приёмник писем либо исполнитель записи
         недостижимы. Вердикта о дереве нет.

ПАРОЛЬ НЕ ПЕЧАТАЕТСЯ И В ОКРУЖЕНИЕ НЕ УЕЗЖАЕТ: у личности его нет по построению.

САМОПРОВЕРКА — `--self-test`: законный мир и по одному изменённому факту — оператор
вернул не ту форму, вход после снятия проходит, неподтверждённая регистрация
назвала адрес подтверждённым, полоса недостижима; сходимость ключей и поверхности
против переписи долга.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import secrets
import shlex
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

sys.path.insert(0, str(HERE))
from seed_ceremony import human_session  # noqa: E402
from seed_key_person import MINTED_SURFACE, drop_password  # noqa: E402
from seed_login_lane import (Finding, LaneHttp, login, register,  # noqa: E402
                             seed as seed_verified)
from seed_own_stand import Mailbox, Unmet, await_code, write_env  # noqa: E402
from seed_stored_value import PsqlStore  # noqa: E402

RC_FINDING = 1
RC_UNMET = 75

DOMAIN = "kaname.local"

# Приставка → подтверждён ли адрес. Порядок — порядок посева и печати.
PREFIXES: tuple[tuple[str, bool], ...] = (
    ("wayN", True), ("wayNB", True), ("wayA", False), ("wayA30", False), ("wayN30", True))
# Кому посев отдаёт идентификатор: блокирует личность сам кейс.
WITH_USER_ID = ("wayNB",)
MINTED_KEYS = tuple(p + "Email" for p, _ in PREFIXES) + tuple(p + "UserId" for p in WITH_USER_ID)


def say(msg: str) -> None:
    print(msg, flush=True)


def seed_one(lane, mailbox, store, prefix: str, verified: bool, sleep=time.sleep) -> dict:
    email = f"wayless-{prefix.lower()}-{secrets.token_hex(6)}@{DOMAIN}"
    password = "Way-" + secrets.token_hex(12)
    if verified:
        seed_verified(lane, mailbox, email, password, sleep)
    else:
        register(lane, email, password)
        # Письмо регистрации ставится тем же исходом глагола: дождаться его здесь,
        # чтобы оно не пришло посреди кейса и не легло в его счёт писем.
        if await_code(mailbox, email, 0, sleep) is None:
            raise Finding("письмо регистрации не дошло до приёмника стенда — служба не сдала "
                          "его узлу, названному посадкой стенда")
    session = login(lane, email, password)
    if session is None:
        raise Finding("регистрация ответила 200, а вход тем же паролем отвергнут (401) — "
                      "личность заведена без способа войти ещё до записи")
    if session["verified"] is not verified:
        raise Finding(f"положение сессии после регистрации: emailVerified={session['verified']}, "
                      f"а мир личности «{prefix}» требует {verified} — кейсу достался бы не тот мир")
    patch = {prefix + "Email": email}
    if prefix in WITH_USER_ID:
        _cookie, user = human_session(lane, email, password)
        patch[prefix + "UserId"] = user
    drop_password(store, email)
    if login(lane, email, password) is not None:
        raise Finding("строка способа «пароль» снята, а вход прежним паролем проходит — у личности "
                      "остался способ, которого в хранилище нет")
    say(f"  ok   личность «{prefix}» (адрес {'подтверждён' if verified else 'не подтверждён'}) "
        f"положена: способов входа нет, отметка открытого пути стоит")
    return patch


def seed_all(lane, mailbox, store, sleep=time.sleep) -> dict:
    patch: dict = {}
    for prefix, verified in PREFIXES:
        patch.update(seed_one(lane, mailbox, store, prefix, verified, sleep))
    return patch


def run(args: argparse.Namespace) -> int:
    patch = seed_all(LaneHttp(args.base_url, pathlib.Path(args.pki)), Mailbox(args.mailbox_url),
                     PsqlStore(shlex.split(args.store_exec)))
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев личностей без способа входа: ключей записано {len(patch)} (заменено {replaced}) "
        f"в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


def _fakes():
    from seed_login_lane import LOGIN, _FakeLane, _FakeMailbox  # noqa: PLC0415 — только самопроверке

    class Lane(_FakeLane):
        """Подставная полоса, чей вход называет человека (`user.id`) и чья строка
        пароля снимается подставным оператором."""

        def __init__(self, *, unverified_says_verified=False, login_survives_drop=False, **kw):
            super().__init__(**kw)
            self.unverified_says_verified = unverified_says_verified
            self.login_survives_drop = login_survives_drop
            self.dropped: set[str] = set()

        def ask(self, method, path, body=None, cookies=None):
            if path == LOGIN and body and body.get("email") in self.dropped and not self.login_survives_drop:
                return 401, [], '{"code":16,"message":"authentication failed"}'
            code, sc, text = super().ask(method, path, body, cookies)
            if path == LOGIN and code == 200:
                doc = json.loads(text)
                doc["user"] = {"id": "usr" + str(abs(hash(body["email"])) % 10 ** 17).zfill(17)}
                if self.unverified_says_verified:
                    doc["session"]["emailVerified"] = True
                text = json.dumps(doc)
            return code, sc, text

    class Store:
        def __init__(self, lane, rows=("opened", "password")):
            self.lane, self.rows = lane, list(rows)
            self.sql: list[str] = []

        def run(self, sql):
            self.sql.append(sql)
            email = sql.split("WHERE email = '", 1)[1].split("'", 1)[0]
            self.lane.dropped.add(email)
            return self.rows

    def world(**kw):
        store_rows = kw.pop("store_rows", ("opened", "password"))
        mailbox = _FakeMailbox(down=kw.pop("mailbox_down", False))
        lane = Lane(mailbox=mailbox, **kw)
        return lane, mailbox, Store(lane, store_rows)

    return world


def _outcome(fn) -> tuple[str, str]:
    try:
        return "ok", str(fn())
    except Finding as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)
    except Exception as e:  # noqa: BLE001 — сбой пробы назван, а не проглочен
        return "crash", f"{type(e).__name__}: {e}"


def _census_surface() -> str | None:
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_probe_wp", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"loginLaneBaseUrl"})


def self_test() -> int:
    world = _fakes()
    nap = lambda _s: None  # noqa: E731 — подставные часы

    lane, mailbox, store = world()
    got: dict = {}
    kind, out = _outcome(lambda: got.update(seed_all(lane, mailbox, store, nap)))
    patch = got
    _c("законный мир: посев проходит", kind == "ok", f"{kind}: {out}")
    _c("законный мир: ключей ровно столько, сколько объявлено", set(patch) == set(MINTED_KEYS),
       f"{sorted(patch)} против {sorted(MINTED_KEYS)}")
    _c("законный мир: адреса личностей различны", len({v for k, v in patch.items() if k.endswith('Email')})
       == len(PREFIXES), str(patch))
    _c("законный мир: запись — по одной на личность, и каждая снимает строку пароля и ставит отметку",
       len(store.sql) == len(PREFIXES) and all("recovery_path_opened_at" in q and "DELETE" in q for q in store.sql),
       f"записей {len(store.sql)}")
    _c("законный мир: подтверждённых личностей столько, сколько объявлено",
       lane.confirmed == sum(1 for _, v in PREFIXES if v), f"подтверждено {lane.confirmed}")

    for label, kw, want in (
        ("оператор вернул не форму «после переноса» → находка", {"store_rows": ("opened",)}, "finding"),
        ("вход прежним паролем после снятия строки проходит → находка", {"login_survives_drop": True}, "finding"),
        ("неподтверждённая регистрация названа подтверждённой → находка", {"unverified_says_verified": True}, "finding"),
        ("полоса недостижима → условие не создано", {"down": True}, "unmet"),
        ("приёмник писем недостижим → условие не создано", {"mailbox_down": True}, "unmet"),
    ):
        lane, mailbox, store = world(**kw)
        kind, out = _outcome(lambda: seed_all(lane, mailbox, store, nap))
        _c(label, kind == want, f"{kind}: {out}")

    try:
        census = _census_surface()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        census = f"<перепись не прочитана: {e}>"
    _c("поверхность посева = поверхность, которую перепись выводит из loginLaneBaseUrl",
       census == MINTED_SURFACE, f"перепись {census!r}, посев {MINTED_SURFACE!r}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: личности заводятся глаголами полосы в объявленном положении адреса, строка "
          "пароля снимается одной записью формы «после переноса» и утверждается отказом входа, "
          "отказ продукта отличим от несозданного условия.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="", help="адрес полосы входа (слушатель формы)")
    ap.add_argument("--pki", default="", help="каталог с edge.crt, edge.key и ca.crt")
    ap.add_argument("--mailbox-url", default="")
    ap.add_argument("--store-exec", default="", help="команда до psql включительно")
    ap.add_argument("--env-file",
                    default=str(ROOT / "tests" / "newman" / "environments" / "local.postman_environment.json"))
    ap.add_argument("--env-template",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.template.json"))
    ap.add_argument("--minted-keys", action="store_true")
    ap.add_argument("--minted-surface", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.minted_keys:
        for k in MINTED_KEYS:
            print(k)
        return 0
    if args.minted_surface:
        print(MINTED_SURFACE)
        return 0
    if args.self_test:
        return self_test()
    try:
        if not all((args.base_url, args.pki, args.mailbox_url, args.store_exec)):
            raise Unmet("не названы --base-url, --pki, --mailbox-url и --store-exec — сеять нечем")
        return run(args)
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}", file=sys.stderr)
        print("Посев не состоялся по причине, не относящейся к дереву: вердикта о продукте нет "
              "НИ ОДНОГО.", file=sys.stderr)
        return RC_UNMET
    except Finding as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
