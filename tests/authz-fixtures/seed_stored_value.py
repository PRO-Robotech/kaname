#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ХРАНИМЫХ ЗНАЧЕНИЙ ПАРОЛЯ ФОРМАТОВ A И B на стенде посадки `own`.

ПРЕДМЕТ. «Дано» сквозных позиций PWV-01 и PWV-02 приёмки ID-PW-1 (редакция 5,
`docs/engineering/acceptance/password-verifier-follows-the-stored-value.md`, Д-01):
человек, чьё проверочное значение положено ПОСЕВОМ и несёт признак формата A
(bcrypt `2a`) либо формата B (argon2id), и пароль его с посева не менялся. Кейсы
`IAM-LOGINLANE-OK-STORED-FORMAT-A` и `IAM-LOGINLANE-OK-STORED-FORMAT-B` набора
`kaname-login-lane` читают из окружения почту и пароль каждого (`MINTED_KEYS`);
пока их не пишет никто, каждый шаг уходит в «условие не создано».

ПОЧЕМУ ЗАПИСЬ В ХРАНИЛИЩЕ, А НЕ ГЛАГОЛ. Значения формата A продукт не пишет вовсе,
формата B — только с параметрами ручки «что писать» (ID-PW-1 Р2, PWV-16): глагола,
который положил бы «Дано», у продукта нет by construction, и приёмка называет
конструктором посев (Д-01, Ф1-04 редакции 14). Значение строит СТОРОННЯЯ
БИБЛИОТЕКА (`tests/newman/scripts/storedvaluemint`, `golang.org/x/crypto`), а не
хешер продукта: хешер продукта доказывал бы, что продукт читает написанное им же.
Что построенное читается проверяющим продукта, держит Go-проба той программы.

ЧТО ДЕЛАЕТСЯ ГЛАГОЛОМ, А ЧТО ЗАПИСЬЮ. Человек и его строка способа входа —
глаголом продукта: регистрация паролем (`POST /iam/v1/auth/register`) на той же
двери, которую судит набор. Записью — ТОЛЬКО материал этой строки
(`kaname.user_login_methods.verifier`), одним оператором с возвратом: признак
формата и равенство положенному читаются тем же оператором, и посев утверждает
именно это — «у этого человека лежит ровно построенное значение формата A (B)».

ВХОДА ПОСЕВ НЕ ДЕЛАЕТ. Успешный вход переписывает значение формата A (Р5,
PWV-08): посев, доказавший способность входом, отдал бы набору уже не «Дано».
Поэтому способность здесь — это значение в хранилище, прочитанное оператором
записи, а вход — предмет кейса. Люди свежие на каждый посев (Д-03: значение
расходуется успешным входом и заводится заново на каждый прогон).

Параметры формата B — ВЫШЕ ручки по проходам (`t=4` против ручки `t=3`,
`deploy/values.prod.yaml`, `authn.login.hasherIterations`): проверяющий, читающий
параметры ручки, а не значения, на нём бы отказал (Р1). Такое значение
переписыванию не подлежит (оно не ниже ручки, Р5), и формат его до кейса и после
один.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — значения обоих форматов лежат у своих людей, окружение записано;
    1  — НАХОДКА: регистрация отвергнута, у заведённого человека нет строки
         способа входа паролем, либо оператор записи вернул не то значение, что
         положено, — вердикт о дереве;
   75  — УСЛОВИЕ НЕ СОЗДАНО: полоса недостижима, листа нет, построитель значений
         либо исполнитель записи в хранилище не запустился. Вердикта о дереве нет.

ПАРОЛИ И ЗНАЧЕНИЯ НЕ ПЕЧАТАЮТСЯ НИКОГДА, почта — тоже: журнал прогона публичного
репозитория читает кто угодно. Пароль уходит построителю стандартным вводом, а
оператор записи — исполнителю стандартным вводом, не аргументами.

САМОПРОВЕРКА — `--self-test`: законный мир (оба формата, ни одного входа), и по
одному изменённому факту — регистрация отвергнута, 200 без носителя, полоса
молчит, строки способа входа нет, признак не тот, значение не то, исполнитель не
запустился, построитель не запустился, значение вне безопасного алфавита; сходимость
объявленных ключей с записью и поверхность против переписи долга.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import secrets
import shlex
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

sys.path.insert(0, str(HERE))
from seed_login_lane import (  # noqa: E402
    CSRF, FORM_COOKIE, LOGIN, REGISTER, SESSION_COOKIE, Finding, LaneHttp, register)
from seed_own_stand import Unmet, write_env  # noqa: E402

RC_FINDING = 1
RC_UNMET = 75

# Ключи окружения, которые пишет посев. Перепись долга спрашивает их у посева
# флагом `--minted-keys`; сходимость объявления с записью держит самопроверка.
MINTED_KEYS = ("storedValueAEmail", "storedValueAPassword",
               "storedValueBEmail", "storedValueBPassword")

# Поверхность — та же, что у посева полосы входа: кейсы стоят на слушателе формы
# службы и адресуются `loginLaneBaseUrl`.
MINTED_SURFACE = "служба (собственный REST-фронт)"

# Форматы «Дано». Аргументы построителя — величины, а не умолчания программы:
# умолчание, поменявшееся там, молча сменило бы «Дано» здесь.
FORMATS = (
    # A — стоимость, которой писал прежний поставщик (ID-PW-1 §1.6).
    ("A", "2a", ("-format", "2a", "-cost", "12")),
    # B — параметры источника §1.2, проходов на один больше ручки.
    ("B", "argon2id", ("-format", "argon2id", "-m", "65536", "-t", "4", "-p", "4")),
)

# Буквы, которые попадают в оператор записи литералом. Значение bcrypt и
# разметка PHC их не выходят; почту строит сам посев. Выход за алфавит — отказ
# писать, а не экранирование: экранирование — второй разбор, и он разошёлся бы.
EMAIL_RE = re.compile(r"^[a-z0-9.-]+@[a-z0-9.-]+$")
VERIFIER_RE = re.compile(r"^\$[A-Za-z0-9$./=,+]+$")

DOMAIN = "kaname.local"


def say(msg: str) -> None:
    print(msg, flush=True)


# ─────────────────────────── построитель и хранилище ─────────────────────────


def go_mint(args: tuple[str, ...], password: str) -> str:
    """Значение, построенное библиотекой; пароль — стандартным вводом."""
    cmd = ["go", "-C", str(ROOT), "run", "./tests/newman/scripts/storedvaluemint", *args]
    try:
        proc = subprocess.run(cmd, input=password, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as e:
        raise Unmet(f"построитель значений не запустился ({e})") from None
    if proc.returncode != 0:
        raise Unmet(f"построитель значений отказал (код {proc.returncode}): "
                    f"{proc.stderr.strip()[-300:]}")
    return proc.stdout.strip()


class PsqlStore:
    """Исполнитель записи: команда до `psql` включительно; оператор — вводом."""

    def __init__(self, argv: list[str]):
        if not argv:
            raise Unmet("исполнитель записи в хранилище не назван (--store-exec)")
        self.argv = argv

    def run(self, sql: str) -> list[str]:
        try:
            proc = subprocess.run([*self.argv, "-qtAX", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                                  input=sql, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            raise Unmet(f"исполнитель записи не запустился ({e})") from None
        if proc.returncode != 0:
            # Сообщение psql не несёт значения: оператор с ним уходит вводом, а
            # отказ называет оператор, а не его литералы.
            raise Unmet(f"исполнитель записи отказал (код {proc.returncode}): "
                        f"{proc.stderr.strip()[-300:]}")
        return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def put_sql(email: str, verifier: str) -> str:
    """Оператор записи материала с возвратом признака и равенства положенному."""
    if not EMAIL_RE.match(email):
        raise Unmet("почта вне безопасного алфавита оператора — посев не пишет")
    if not VERIFIER_RE.match(verifier):
        raise Unmet("значение вне безопасного алфавита оператора — построитель "
                    "выдал не разметку bcrypt и не PHC")
    return ("UPDATE kaname.user_login_methods m SET verifier = '" + verifier + "'\n"
            "  FROM kaname.users u\n"
            " WHERE u.id = m.user_id AND u.email = '" + email + "' AND m.kind = 'password'\n"
            "RETURNING split_part(m.verifier, '$', 2) || '|' || (m.verifier = '" + verifier + "')::text;\n")


def put(store, email: str, verifier: str, marker: str) -> None:
    rows = store.run(put_sql(email, verifier))
    if len(rows) != 1:
        raise Finding(f"запись материала: строк способа входа паролем у заведённого "
                      f"регистрацией человека {len(rows)}, ждали ровно одну — регистрация "
                      f"ответила 200, а способа входа паролем не завела")
    got_marker, _, equal = rows[0].partition("|")
    if got_marker != marker:
        raise Finding(f"запись материала: признак лежащего значения {got_marker!r}, "
                      f"положен {marker!r}")
    if equal != "true":
        raise Finding("запись материала: лежащее значение не равно положенному — "
                      "запись замещена на пути в хранилище")


# ─────────────────────────── посев ───────────────────────────────────────────


def seed(http, store, mint) -> dict:
    """Окружение по обоим форматам; утверждение — значение в хранилище."""
    patch: dict[str, str] = {}
    for letter, marker, mint_args in FORMATS:
        email = f"stored-{letter.lower()}-{secrets.token_hex(6)}@{DOMAIN}"
        password = "Stored-" + secrets.token_hex(12)
        register(http, email, password)
        verifier = mint(mint_args, password)
        put(store, email, verifier, marker)
        say(f"  ok   формат {letter}: человек заведён регистрацией, у него лежит значение "
            f"признака {marker}, построенное библиотекой")
        patch[f"storedValue{letter}Email"] = email
        patch[f"storedValue{letter}Password"] = password
    return patch


def run(args: argparse.Namespace) -> int:
    http = LaneHttp(args.base_url, pathlib.Path(args.pki))
    store = PsqlStore(shlex.split(args.store_exec))
    patch = seed(http, store, go_mint)
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев хранимых значений: ключей записано {len(patch)} (заменено {replaced}) "
        f"в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


class _FakeLane:
    """Подставная полоса: регистрация и признак формы; вход только считается."""

    def __init__(self, register_code=200, register_cookie=True, down=False):
        self.register_code, self.register_cookie, self.down = register_code, register_cookie, down
        self.registered: list[str] = []
        self.logins = 0

    def ask(self, method, path, body=None, cookies=None):
        if self.down:
            raise Unmet("полоса недостижима: connection refused")
        if path.startswith(CSRF):
            return 200, [f"{FORM_COOKIE}=ctx; Path=/; HttpOnly"], '{"csrfToken":"t"}'
        if path == LOGIN:
            self.logins += 1
            return 401, [], '{"code":16,"message":"authentication failed"}'
        if path == REGISTER:
            if self.register_code != 200:
                return self.register_code, [], '{"code":6,"message":"request not performed"}'
            self.registered.append(body["email"])
            sc = [f"{SESSION_COOKIE}=s; Path=/"] if self.register_cookie else []
            return 200, sc, json.dumps({"session": {"emailVerified": False}})
        return 404, [], "{}"


class _FakeStore:
    """Подставное хранилище: строка способа входа на каждого заведённого."""

    def __init__(self, lane, rows=True, rewrite_to=None, unequal=False, down=False):
        self.lane, self.rows, self.rewrite_to = lane, rows, rewrite_to
        self.unequal, self.down = unequal, down
        self.stored: dict[str, str] = {}

    def run(self, sql: str) -> list[str]:
        if self.down:
            raise Unmet("исполнитель записи не запустился (kubectl: not found)")
        email = re.search(r"u\.email = '([^']*)'", sql).group(1)
        verifier = re.search(r"SET verifier = '([^']*)'", sql).group(1)
        if not self.rows or email not in self.lane.registered:
            return []
        self.stored[email] = verifier
        marker = self.rewrite_to or verifier.split("$")[1]
        return [f"{marker}|{'false' if self.unequal else 'true'}"]


def _fake_mint(args, password):
    fmt = args[1]
    return ("$2a$12$" + "a" * 53) if fmt == "2a" else (
        "$argon2id$v=19$m=65536,t=4,p=4$c2FsdHNhbHRzYWx0c2FsdA$" + "b" * 43)


def _outcome(fn) -> tuple[str, str]:
    try:
        return "ok", str(fn())
    except Finding as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)
    except Exception as e:  # noqa: BLE001 — сбой пробы назван, а не проглочен
        return "crash", f"{type(e).__name__}: {e}"


def _census_surface_for_lane_address() -> str | None:
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_probe_sv", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"loginLaneBaseUrl"})


def self_test() -> int:
    import tempfile

    print("=== посев хранимых значений: различение исходов ===")

    def sow(lane, store=None, mint=_fake_mint):
        store = store if store is not None else _FakeStore(lane)
        return _outcome(lambda: seed(lane, store, mint)), store

    lane = _FakeLane()
    (kind, _), store = sow(lane)
    _c("законный мир — оба формата лежат у своих людей, вход не сделан ни разу",
       kind == "ok" and len(lane.registered) == 2 and lane.logins == 0
       and sorted(v.split("$")[1] for v in store.stored.values()) == ["2a", "argon2id"],
       f"{kind}, регистраций {len(lane.registered)}, входов {lane.logins}, лежит {store.stored}")
    lane = _FakeLane()
    patch = seed(lane, _FakeStore(lane), _fake_mint)
    _c("объявленные ключи = записываемые (в обе стороны)",
       set(patch) == set(MINTED_KEYS), f"{sorted(patch)} против {sorted(MINTED_KEYS)}")
    _c("почты двух форматов различны и свежи",
       patch["storedValueAEmail"] != patch["storedValueBEmail"], f"{patch}")

    axes = [
        ("регистрация отвергнута — находка", _FakeLane(register_code=409), None, "finding"),
        ("регистрация 200 без носителя — находка", _FakeLane(register_cookie=False), None, "finding"),
        ("полоса молчит — условие не создано", _FakeLane(down=True), None, "unmet"),
    ]
    for label, ln, st, want in axes:
        (kind, text), _ = sow(ln, st)
        _c(label, kind == want, f"{kind}: {text}")

    for label, mk, want in [
        ("строки способа входа нет — находка", lambda ln: _FakeStore(ln, rows=False), "finding"),
        ("признак лежащего не тот (запись замещена форматом ручки) — находка",
         lambda ln: _FakeStore(ln, rewrite_to="argon2id"), "finding"),
        ("лежит не то значение — находка", lambda ln: _FakeStore(ln, unequal=True), "finding"),
        ("исполнитель записи не запустился — условие не создано",
         lambda ln: _FakeStore(ln, down=True), "unmet"),
    ]:
        ln = _FakeLane()
        (kind, text), _ = sow(ln, mk(ln))
        _c(label, kind == want, f"{kind}: {text}")

    def broken_mint(args, password):
        raise Unmet("построитель значений не запустился (go: not found)")

    ln = _FakeLane()
    (kind, text), _ = sow(ln, mint=broken_mint)
    _c("построитель не запустился — условие не создано", kind == "unmet", f"{kind}: {text}")

    ln = _FakeLane()
    (kind, text), st = sow(ln, mint=lambda a, p: "$2a$12$x'; DROP TABLE x; --")
    _c("значение вне алфавита оператора — отказ писать, хранилище не тронуто",
       kind == "unmet" and not st.stored, f"{kind}: {text}, лежит {st.stored}")

    with tempfile.TemporaryDirectory() as tmp:
        got = _outcome(lambda: LaneHttp("https://127.0.0.1:1", pathlib.Path(tmp)))
        _c("листа края нет — условие не создано", got[0] == "unmet", f"{got}")
        env, tmpl = pathlib.Path(tmp) / "env.json", pathlib.Path(tmp) / "tmpl.json"
        tmpl.write_text(json.dumps({"values": [
            {"key": "storedValueAPassword", "value": "", "type": "secret"},
            {"key": "storedValueAEmail", "value": ""}]}), encoding="utf-8")
        write_env(patch, env, tmpl)
        doc = {v["key"]: v for v in json.loads(env.read_text(encoding="utf-8"))["values"]}
        _c("запись доезжает всеми ключами, тип secret у пароля сохранён",
           all(doc.get(k, {}).get("value") for k in MINTED_KEYS)
           and doc["storedValueAPassword"].get("type") == "secret", f"{sorted(doc)}")

    try:
        census = _census_surface_for_lane_address()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        census = f"<перепись не прочитана: {e}>"
    _c("поверхность посева = поверхность, которую перепись выводит из loginLaneBaseUrl",
       census == MINTED_SURFACE, f"перепись {census!r}, посев {MINTED_SURFACE!r}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: «Дано» утверждается значением в хранилище без единого входа, отказ "
          "продукта отличим от несозданного условия кодом, литерал вне алфавита не "
          "доезжает до оператора, объявленные ключи сходятся с записью, поверхность — с "
          "переписью долга.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="", help="адрес полосы входа (слушатель формы)")
    ap.add_argument("--pki", default="", help="каталог с edge.crt, edge.key и ca.crt")
    ap.add_argument("--store-exec", default="",
                    help="команда до psql включительно, которой исполняется запись "
                         "в базу службы стенда (оператор уходит вводом)")
    ap.add_argument("--env-file",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.json"))
    ap.add_argument("--env-template",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.template.json"))
    ap.add_argument("--minted-keys", action="store_true",
                    help="напечатать ключи окружения, которые пишет посев, и выйти")
    ap.add_argument("--minted-surface", action="store_true",
                    help="напечатать поверхность, для которой посев куёт, и выйти")
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
        if not args.base_url or not args.pki or not args.store_exec:
            raise Unmet("не названы --base-url, --pki и --store-exec — полосы либо "
                        "хранилища, которое сеять, нет")
        return run(args)
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}", file=sys.stderr)
        print("Посев не состоялся по причине, не относящейся к дереву: вердикта о "
              "продукте нет НИ ОДНОГО.", file=sys.stderr)
        return RC_UNMET
    except Finding as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
