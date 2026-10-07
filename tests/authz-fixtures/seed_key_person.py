#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ЛИЧНОСТЕЙ БЕЗ ПАРОЛЯ С КЛЮЧОМ ДОСТУПА на стенде посадки `own`.

ПРЕДМЕТ. «Дано» позиции FP-12 приёмки заведения первого пароля
(`docs/engineering/acceptance/first-password-from-a-live-session.md`, kaname#213):
«личность без пароля с ключом и фикстурой-аутентификатором, вошедшая ключом».
Кейс `IAM-LOGINLANE-OK-FP12-KEY-PERSON-ENROLLS-PASSWORD` набора
`kaname-login-lane` входит ключом сам — посев кладёт ему человека и ключ и
больше ничего (`MINTED_KEYS`).

ЛИЧНОСТЕЙ ДВЕ, И КАЖДАЯ — СВОЕГО НАБОРА (kaname#643). Вторая — «Дано» полосы
«личность без пароля» приёмки входа ключом (`passwordless-login-with-access-key.md`,
§5 преамбула: «записью»): Ф13-19, Ф13-22, Ф13-23 и Ф13-25 набора ключей доступа
(`kaname-access-keys`). Одной личности на оба набора не хватает by construction:
FP-12 заводит ей пароль, и после прогона полосы входа она уже не «без пароля», а
Ф13-25 заводит пароль восстановлением. Набор ключей доступа идёт после полосы
входа, поэтому у каждого своя личность, свои ключи окружения — по приставке
(`PREFIXES`), — и посев одной не трогает другую.

ПОЧЕМУ ЧАСТЬ — ЗАПИСЬЮ. Личность без строки способа «пароль» продукт не
производит ни одним глаголом: регистрация пишет строку, а регистрации ключом без
сессии не будет (Ф13, §0.2). Приёмка FP поэтому строит «Дано» уровня I вставкой
пробы мимо продукта (§4.0, «единственный шаг посева мимо продукта, и он
вынужден»), и здесь тот же единственный шаг: строка способа «пароль» снимается
одной транзакцией вместе с отметкой открытого пути восстановления — в той же
форме, которую кладёт миграция переноса для личностей без пароля
(`users_active_has_a_way_in_fk`: `ACTIVE` без строки пароля законна только с
отметкой). Утверждаются обе записи оператором с возвратом. Всё остальное — глаголами продукта на тех же
дверях, что судит набор:

  1. человек заводится регистрацией и подтверждает адрес кодом письма
     (посев полосы входа, `seed_login_lane.seed`);
  2. входит паролем и куёт токен НАШЕЙ церемонией (точка авторизации → обмен
     кода секретом клиента, которого завёл посев церемонии); окно свежести
     открыто этим входом;
  3. регистрирует ключ доступа на собственном фронте: испытание →
     результат церемонии подставного аутентификатора (аттестация `none`) →
     операция без ошибки. Материал ключа — тот же, что у подставного
     аутентификатора набора (`tests/newman/cases/kaname-access-keys.py`,
     `_KEYS`): кейс подписывает утверждение тем же ключом, и второй копии
     материала в дереве нет — посев читает литерал оттуда разбором;
  4. строка способа «пароль» снимается записью; утверждение — следующий вход
     прежним паролем отвергнут (`401`): у человека остался только ключ.

Порядок несущий: ключ заводится ДО снятия пароля — иначе у живой личности не
осталось бы способа входа, а это законным состоянием не является
(`active-identity-has-a-way-in.md`).

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — человек с ключом и без пароля лежит, окружение записано;
    1  — НАХОДКА: глагол ответил не по контракту там, где посев предъявил всё
         требуемое (регистрация ключа, операция, снятие строки, вход после
         снятия);
   75  — УСЛОВИЕ НЕ СОЗДАНО: двери стенда, приёмник писем либо исполнитель
         записи недостижимы; клиента церемонии в окружении нет. Вердикта о
         дереве нет.

ПАРОЛЬ, ТОКЕН И ПОЧТА НЕ ПЕЧАТАЮТСЯ.

САМОПРОВЕРКА — `--self-test`: кодирование аттестации (CBOR, ключ COSE RS256) и
по одному изменённому факту — клиента церемонии нет, испытание без рукоятки,
имя доверяющей стороны чужое, операция с ошибкой, строки пароля не было, вход
после снятия проходит; сходимость ключей и поверхность против переписи долга.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import pathlib
import re
import secrets
import shlex
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

sys.path.insert(0, str(HERE))
from seed_ceremony import authorize, exchange, human_session  # noqa: E402
from seed_login_lane import Finding, LaneHttp, login, message_of, seed as seed_person  # noqa: E402
from seed_own_stand import Mailbox, Unmet, write_env  # noqa: E402
from seed_stored_value import EMAIL_RE, PsqlStore  # noqa: E402

RC_FINDING = 1
RC_UNMET = 75

# Приставка — чья личность: `keyPerson` — FP-12 полосы входа, `f13Person` — полоса
# «личность без пароля» Ф13 набора ключей доступа.
PREFIXES = ("keyPerson", "f13Person")
FIELDS = ("Email", "CredentialId", "UserHandle", "Origin")
MINTED_KEYS = tuple(prefix + field for prefix in PREFIXES for field in FIELDS)
MINTED_SURFACE = "служба (собственный REST-фронт)"

DOMAIN = "kaname.local"

# Индекс материала подставного аутентификатора (`_KEYS` модуля ключей доступа),
# которым подписывает кейс FP-12. Тот же индекс кейс читает отсюда.
KEY_SLOT = 0

AUTHENTICATOR = ROOT / "tests" / "newman" / "cases" / "kaname-access-keys.py"
PROFILE = ROOT / "deploy" / "values.prod.yaml"

OP_BUDGET_S, OP_STEP_S = 30.0, 0.5

# Флаги данных аутентификатора (WebAuthn L2 §6.1): присутствие, проверка, данные удостоверения.
FLAGS_REGISTER = 0x01 | 0x04 | 0x40
COSE_RS256 = -257


def say(msg: str) -> None:
    print(msg, flush=True)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(s: str) -> bytes:
    s = (s or "").replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


# ─────────────────────────── материал и профиль ──────────────────────────────


def authenticator_keys(path: pathlib.Path = AUTHENTICATOR) -> list[dict]:
    """`_KEYS` модуля ключей доступа — литерал, прочитанный разбором, не копией."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_KEYS"
                                                for t in node.targets):
            keys = ast.literal_eval(node.value)
            if not keys or not all({"n", "e"} <= set(k) for k in keys):
                raise Finding(f"{path.name}: _KEYS без n и e — подписывать кейсу нечем")
            return keys
    raise Finding(f"{path.name}: присваивания _KEYS нет — материал подставного аутентификатора пропал")


def profile_binding(path: pathlib.Path = PROFILE) -> tuple[str, str]:
    """Имя доверяющей стороны и первое происхождение блока `authn.accessKeys`."""
    found = re.findall(r"^  accessKeys:\n    rpId: (\S+)\n    origins:\n      - (\S+)\n",
                       path.read_text(encoding="utf-8"), re.M)
    if len(found) != 1:
        raise Finding(f"{path.name}: блок authn.accessKeys найден {len(found)} раз — ждали ровно один")
    return found[0]


# ─────────────────────────── результат церемонии регистрации ─────────────────


def cbor(v) -> bytes:
    """Минимальный CBOR: целые, байты, строки, отображения — то, что нужно аттестации."""
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([(major << 5) | n])
        if n < 256:
            return bytes([(major << 5) | 24, n])
        if n < 65536:
            return bytes([(major << 5) | 25]) + struct.pack(">H", n)
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)

    if isinstance(v, bool):
        raise TypeError("cbor: логических значений аттестация не несёт")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        raw = v.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(v, list):  # отображение — перечнем пар, порядок сохраняется
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v)
    raise TypeError(f"cbor: тип {type(v).__name__} не нужен аттестации")


def registration_result(key: dict, challenge: bytes, rp_id: str, origin: str, cred_id: bytes) -> dict:
    client_data = json.dumps({"type": "webauthn.create", "challenge": b64u(challenge), "origin": origin,
                              "crossOrigin": False}, separators=(",", ":")).encode("utf-8")
    cose = cbor([(1, 3), (3, COSE_RS256), (-1, bytes.fromhex(key["n"])), (-2, bytes.fromhex(key["e"]))])
    auth_data = (hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([FLAGS_REGISTER])
                 + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", len(cred_id)) + cred_id + cose)
    att = cbor([("fmt", "none"), ("attStmt", []), ("authData", auth_data)])
    return {"id": b64(cred_id), "clientDataJson": b64(client_data), "attestationObject": b64(att),
            "discoverable": True}


# ─────────────────────────── двери ───────────────────────────────────────────


class Doors:
    """Поверхность выдачи и собственный фронт: TLS листом стенда, имя проверяется."""

    def __init__(self, pki: pathlib.Path, issuance: str, own: str):
        ca = pki / "ca.crt"
        if not ca.is_file():
            raise Unmet(f"нет {ca} — якоря стенда не вынесено")
        self.issuance, self.own = issuance.rstrip("/"), own.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=str(ca))

    def http(self, url: str, *, method: str = "GET", headers: dict | None = None,
             form: dict | None = None, body: dict | None = None) -> tuple[int, dict, str]:
        data, hdrs = None, dict(headers or {})
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
                return None

        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx), _NoRedirect)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with opener.open(req, timeout=30) as r:
                return r.status, dict(r.headers.items()), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()), e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, ssl.SSLError, OSError, socket.timeout) as e:
            raise Unmet(f"{url.split('?')[0]} недостижим: {e}") from None


def _json(text: str) -> dict:
    try:
        doc = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {}
    return doc if isinstance(doc, dict) else {}


def register_key(doors, token: str, user: str, key: dict, rp_id: str, origin: str,
                 sleep=time.sleep) -> tuple[bytes, bytes]:
    """Испытание → результат → операция без ошибки: (идентификатор удостоверения, рукоятка)."""
    auth = {"Authorization": "Bearer " + token}
    base = f"{doors.own}/iam/v1/users/{urllib.parse.quote(user, safe='')}/accessKeys"
    code, _, text = doors.http(base + ":beginRegistration", method="POST", headers=auth, body={})
    ch = _json(text)
    if code != 200:
        raise Finding(f"испытание регистрации ключа: ждали 200, получили {code} ({message_of(text)!r})")
    challenge, handle = unb64(ch.get("challenge", "")), unb64((ch.get("user") or {}).get("id", ""))
    if not challenge or not handle:
        raise Finding("испытание регистрации ключа без challenge либо без рукоятки user.id")
    if (ch.get("rp") or {}).get("id") != rp_id:
        raise Finding("испытание называет доверяющую сторону, которой профиль не объявляет")
    cred_id = secrets.token_bytes(16)
    code, _, text = doors.http(base, method="POST", headers=auth, body={
        "name": "", "description": "", "credential": registration_result(key, challenge, rp_id, origin, cred_id)})
    op = _json(text)
    if code != 200 or not op.get("id"):
        raise Finding(f"результат регистрации ключа: ждали 200 с операцией, получили {code} "
                      f"({message_of(text)!r})")
    waited = 0.0
    while not op.get("done"):
        if waited >= OP_BUDGET_S:
            raise Finding(f"операция регистрации ключа не завершилась за {OP_BUDGET_S:.0f} с")
        sleep(OP_STEP_S)
        waited += OP_STEP_S
        code, _, text = doors.http(f"{doors.own}/operations/{op['id']}", headers=auth)
        if code != 200:
            raise Finding(f"опрос операции регистрации ключа: ждали 200, получили {code}")
        op = _json(text)
    if op.get("error") or not ((op.get("response") or {}).get("accessKey") or {}).get("id"):
        raise Finding(f"операция регистрации ключа завершилась без ключа: error={op.get('error')!r}")
    return cred_id, handle


# ─────────────────────────── снятие строки пароля ────────────────────────────


def drop_password_sql(email: str) -> str:
    """Форма «после переноса» одной транзакцией: отметка открытого пути и снятие строки.

    `ACTIVE` без строки пароля законна в продукте ровно в одной форме — с отметкой
    `recovery_path_opened_at` (миграция `20261005030000_active_identity_has_a_way_in`,
    ключ `users_active_has_a_way_in_fk` отложен до конца транзакции). Посев кладёт
    ту же форму, что кладёт перенос, а не обходит ключ."""
    if not EMAIL_RE.match(email):
        raise Unmet("почта вне безопасного алфавита оператора — посев не пишет")
    return ("BEGIN;\n"
            "UPDATE kaname.users SET recovery_path_opened_at = now()\n"
            f" WHERE email = '{email}' AND recovery_path_opened_at IS NULL\n"
            "RETURNING 'opened';\n"
            "DELETE FROM kaname.user_login_methods m USING kaname.users u\n"
            f" WHERE u.id = m.user_id AND u.email = '{email}' AND m.kind = 'password'\n"
            "RETURNING m.kind;\n"
            "COMMIT;\n")


def drop_password(store, email: str) -> None:
    rows = store.run(drop_password_sql(email))
    if rows != ["opened", "password"]:
        raise Finding(f"форма «после переноса» не положена: операторы вернули {rows!r:.80}, ждали отметку "
                      f"открытого пути и одну снятую строку пароля")


# ─────────────────────────── посев ───────────────────────────────────────────


def client_of(env_file: pathlib.Path) -> tuple[str, str, str]:
    try:
        doc = json.loads(env_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise Unmet(f"окружения набора нет ({env_file}): {e}") from None
    vals = {v.get("key"): v.get("value") for v in doc.get("values", []) if isinstance(v, dict)}
    cid, sec, red = (vals.get(k) or "" for k in ("oauthClientId", "oauthClientSecret", "oauthRedirectUri"))
    if not (cid and sec and red):
        raise Unmet("клиента церемонии в окружении нет — посев церемонии (`seed-ceremony`) не исполнялся")
    return cid, sec, red


def seed(lane, mailbox, doors, store, client: tuple[str, str, str], *, keys=None, binding=None,
         sleep=time.sleep, prefix: str = PREFIXES[0]) -> dict:
    key = (keys or authenticator_keys())[KEY_SLOT]
    rp_id, origin = binding or profile_binding()
    email = f"key-person-{secrets.token_hex(6)}@{DOMAIN}"
    password = "Key-" + secrets.token_hex(12)
    seed_person(lane, mailbox, email, password, sleep)
    session, user = human_session(lane, email, password)
    cid, sec, redirect = client
    code, verifier = authorize(doors, cid, redirect, session)
    token = exchange(doors, cid, sec, code, verifier, redirect)
    say("  ok   человек заведён и подтверждён глаголами полосы, токен выкован нашей церемонией")
    cred_id, handle = register_key(doors, token, user, key, rp_id, origin, sleep)
    say("  ok   ключ доступа заведён глаголом собственного фронта (операция без ошибки)")
    drop_password(store, email)
    if login(lane, email, password) is not None:
        raise Finding("строка способа «пароль» снята, а вход прежним паролем проходит — у человека "
                      "остался способ, которого в хранилище нет")
    say("  ok   строка способа «пароль» снята записью; вход прежним паролем отвергнут — остался ключ")
    # Происхождение уезжает тем же посевом, что доказал по нему регистрацию: кейс
    # собирает утверждение с ним же, и второго разбора профиля у кейса нет.
    return {prefix + "Email": email, prefix + "CredentialId": b64u(cred_id),
            prefix + "UserHandle": b64u(handle), prefix + "Origin": origin}


def seed_all(lane, mailbox, doors, store, client: tuple[str, str, str], *, keys=None, binding=None,
             sleep=time.sleep) -> dict:
    """Обе личности, каждая под своей приставкой: свежая почта, свой ключ, своя рукоятка."""
    patch: dict = {}
    for prefix in PREFIXES:
        patch.update(seed(lane, mailbox, doors, store, client, keys=keys, binding=binding,
                          sleep=sleep, prefix=prefix))
        say(f"  ok   личность «{prefix}» положена")
    return patch


def run(args: argparse.Namespace) -> int:
    pki = pathlib.Path(args.pki)
    patch = seed_all(LaneHttp(args.base_url, pki), Mailbox(args.mailbox_url),
                 Doors(pki, args.issuance_url, args.own_url), PsqlStore(shlex.split(args.store_exec)),
                 client_of(pathlib.Path(args.env_file)))
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев личности с ключом: ключей записано {len(patch)} (заменено {replaced}) в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


class _FakeDoors:
    issuance, own = "https://iss", "https://own"

    def __init__(self, handle=True, rp="kaname.local", op_error=None):
        self.handle, self.rp, self.op_error = handle, rp, op_error
        self.finished: list[dict] = []

    def http(self, url, *, method="GET", headers=None, form=None, body=None):
        if url.endswith(":beginRegistration"):
            ch = {"challenge": b64(b"c" * 32), "rp": {"id": self.rp}}
            if self.handle:
                ch["user"] = {"id": b64(b"h" * 64)}
            return 200, {}, json.dumps(ch)
        if url.endswith("/accessKeys"):
            self.finished.append(body)
            return 200, {}, json.dumps({"id": "iopx", "done": False})
        if "/operations/" in url:
            if self.op_error:
                return 200, {}, json.dumps({"id": "iopx", "done": True, "error": self.op_error})
            return 200, {}, json.dumps({"id": "iopx", "done": True, "response": {"accessKey": {"id": "ak-x"}}})
        return 404, {}, "{}"


class _FakeStore:
    def __init__(self, rows=("opened", "password")):
        self.rows = list(rows)
        self.sql: list[str] = []

    def run(self, sql):
        self.sql.append(sql)
        return self.rows


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
    spec = importlib.util.spec_from_file_location("newman_suite_debt_probe_kp", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"loginLaneBaseUrl"})


def self_test() -> int:
    import tempfile

    global seed_person, human_session, authorize, exchange, login
    saved = (seed_person, human_session, authorize, exchange, login)
    login_answer = {"value": None}
    seed_person = lambda *a, **k: "заведён"  # noqa: E731
    human_session = lambda lane, e, p: ("s", "usr-x")  # noqa: E731
    authorize = lambda d, c, r, s: ("code", "verifier")  # noqa: E731
    exchange = lambda d, c, s, code, v, r: "tok"  # noqa: E731
    login = lambda lane, e, p: login_answer["value"]  # noqa: E731
    try:
        print("=== посев личности с ключом: различение исходов ===")
        keys = authenticator_keys()
        _c("материал подставного аутентификатора читается разбором модуля ключей доступа",
           len(keys) >= 1 and all(re.fullmatch(r"[0-9a-f]+", k["n"]) for k in keys), f"{len(keys)}")
        rp, origin = profile_binding()
        _c("имя доверяющей стороны и происхождение — из профиля поставки", bool(rp) and origin.startswith("https://"),
           f"{rp} {origin}")

        res = registration_result({"n": "c0ffee", "e": "010001"}, b"\x01" * 4, "kaname.local",
                                  "https://kaname.local", b"\x02" * 16)
        att = base64.b64decode(res["attestationObject"])
        _c("аттестация — отображение трёх ключей fmt none, attStmt пуст, authData байтами",
           att[:1] == b"\xa3" and b"\x63fmt\x64none" in att and b"\x67attStmt\xa0" in att, att[:24].hex())
        ad = att[att.index(b"\x68authData") + 9:]
        ad = ad[2:] if ad[:1] == b"\x58" else ad[3:]
        _c("authData: хэш имени, флаги UP|UV|AT, счёт 0, удостоверение и ключ COSE RS256",
           ad[:32] == hashlib.sha256(b"kaname.local").digest() and ad[32] == FLAGS_REGISTER
           and ad[33:37] == b"\x00\x00\x00\x00" and ad[53:55] == b"\x00\x10" and ad[55:71] == b"\x02" * 16
           and ad[71:] == bytes.fromhex("a401030339010020" + "43c0ffee" + "2143010001"), ad.hex())
        cd = json.loads(base64.b64decode(res["clientDataJson"]))
        _c("данные клиента: вид webauthn.create, испытание base64url, происхождение",
           cd == {"type": "webauthn.create", "challenge": "AQEBAQ", "origin": "https://kaname.local",
                  "crossOrigin": False}, f"{cd}")

        def sow(doors=None, store=None, after_login=None):
            login_answer["value"] = after_login
            d, s = doors or _FakeDoors(rp=rp), store or _FakeStore()
            return _outcome(lambda: seed_all(None, None, d, s, ("c", "s", "r"), sleep=lambda _: None)), d, s

        (kind, text), d, s = sow()
        _c("законный мир — у каждой из двух личностей ключ заведён, затем строка пароля снята, вход "
           "паролем отвергнут",
           kind == "ok" and len(d.finished) == len(PREFIXES) == 2 and len(s.sql) == 2
           and all("DELETE" in q for q in s.sql) and s.sql[0] != s.sql[1], f"{kind}: {text}")
        patch = json.loads(text.replace("'", '"')) if kind == "ok" else {}
        _c("объявленные ключи = записываемые (в обе стороны)", set(patch) == set(MINTED_KEYS), f"{patch}")
        _c("рукоятка и удостоверение — base64url без выравнивания (форма полосы входа ключом) у обеих",
           kind == "ok" and all("=" not in patch[p + "UserHandle"] and len(unb64(patch[p + "UserHandle"])) == 64
                                and len(unb64(patch[p + "CredentialId"])) == 16 for p in PREFIXES), f"{patch}")
        _c("личности разные: своя почта и своё удостоверение у каждой приставки",
           kind == "ok" and patch["keyPersonEmail"] != patch["f13PersonEmail"]
           and patch["keyPersonCredentialId"] != patch["f13PersonCredentialId"], f"{patch}")
        for label, kw, want in [
            ("испытание без рукоятки — находка", {"doors": _FakeDoors(handle=False, rp=rp)}, "finding"),
            ("доверяющая сторона чужая — находка", {"doors": _FakeDoors(rp="elsewhere")}, "finding"),
            ("операция регистрации с ошибкой — находка",
             {"doors": _FakeDoors(rp=rp, op_error={"code": 9, "message": "x"})}, "finding"),
            ("строки пароля не было — находка", {"store": _FakeStore(rows=("opened",))}, "finding"),
            ("отметка открытого пути не легла — находка", {"store": _FakeStore(rows=("password",))}, "finding"),
            ("вход прежним паролем после снятия проходит — находка",
             {"after_login": {"bearer": "b", "verified": True}}, "finding"),
        ]:
            (kind, text), _, _ = sow(**kw)
            _c(label, kind == want, f"{kind}: {text}")
        got = _outcome(lambda: drop_password_sql("x'; DROP TABLE x; --@a"))
        _c("почта вне алфавита оператора — отказ писать", got[0] == "unmet", f"{got}")
        with tempfile.TemporaryDirectory() as tmp:
            env = pathlib.Path(tmp) / "env.json"
            env.write_text(json.dumps({"values": [{"key": "oauthClientId", "value": ""}]}), encoding="utf-8")
            got = _outcome(lambda: client_of(env))
            _c("клиента церемонии нет — условие не создано", got[0] == "unmet", f"{got}")
            got = _outcome(lambda: Doors(pathlib.Path(tmp), "https://a", "https://b"))
            _c("якоря стенда нет — условие не создано", got[0] == "unmet", f"{got}")
    finally:
        seed_person, human_session, authorize, exchange, login = saved

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
    print("ДОКАЗАНО: ключ заводится глаголом до снятия пароля, снятие утверждается оператором и "
          "отказом входа, аттестация собрана по форме, отказ продукта отличим от несозданного условия.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="", help="адрес полосы входа (слушатель формы)")
    ap.add_argument("--pki", default="", help="каталог с edge.crt, edge.key и ca.crt")
    ap.add_argument("--mailbox-url", default="")
    ap.add_argument("--issuance-url", default="", help="поверхность выдачи (точка авторизации, токен)")
    ap.add_argument("--own-url", default="", help="собственный публичный фронт")
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
        if not all((args.base_url, args.pki, args.mailbox_url, args.issuance_url, args.own_url,
                    args.store_exec)):
            raise Unmet("не названы --base-url, --pki, --mailbox-url, --issuance-url, --own-url и "
                        "--store-exec — сеять нечем")
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
