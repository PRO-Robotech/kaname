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
  2. входит паролем (сессия «1»), заводит второй фактор и подтверждает его
     кодом по времени — подтверждение перевыпускает сессию уровнем «2»
     (Ф12-02); под ней куёт токен НАШЕЙ церемонией (точка авторизации → обмен
     кода секретом клиента, которого завёл посев церемонии), уровень токена
     утверждается по его составу. Ключ доступа — способ, чьё предъявление ОДНО
     даёт «2», и заводится он только сессией «2» (приёмка
     `level-two-is-enrolled-at-level-two.md`, Р1, Р3; там же Р2 — путь
     человека, заводящего первый ключ: сперва код, затем ключ). Окно свежести
     открыто этим же входом;
  3. регистрирует ключ доступа на собственном фронте: испытание →
     результат церемонии подставного аутентификатора (аттестация `none`) →
     операция без ошибки. Материал ключа — тот же, что у подставного
     аутентификатора набора (`tests/newman/cases/kaname-access-keys.py`,
     `_KEYS`): кейс подписывает утверждение тем же ключом, и второй копии
     материала в дереве нет — посев читает литерал оттуда разбором;
  4. снимает второй фактор глаголом полосы (Ф12-28) запасным кодом, который
     показало подтверждение: «Дано» обоих наборов — личность, у которой
     остаётся ОДИН ключ, а код по времени перевёл бы её вход паролем и
     восстановление на ветвь второго фактора;
  5. строка способа «пароль» снимается записью; утверждение — следующий вход
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

ПРИВЯЗКА СТЕНДА (kaname#684). Имя доверяющей стороны и происхождение консоли —
величины установки: посев берёт их из переменных `KANAME_STAND_ACCESS_KEYS_RP_ID`
и `KANAME_STAND_ACCESS_KEYS_ORIGIN` (обе либо ни одной), а без них — из профиля
поставки (`deploy/values.prod.yaml`, `authn.accessKeys`, первое происхождение).
Разрешённая привязка уезжает в окружение ключами `accessKeysRpId` и
`accessKeysOrigin`: набор `kaname-access-keys` собирает церемонии под неё же.

ПОТОЛОК СТЕНДА (kaname#699). Потолок ключей человека — тоже величина установки:
посев берёт его из `KANAME_STAND_ACCESS_KEYS_CEILING`, а без неё — из профиля
(`ownCeilings.accessKeysPerUser`), и пишет ключом `accessKeysCeiling`. Не число,
ниже трёх либо выше предела повтора набора — условие не создано (код 75).

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
import os
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
from seed_ceremony import (  # noqa: E402
    SECOND_FACTOR_FORM, authorize, enroll_second_factor_with_codes, exchange, human_session, token_claims)
from seed_login_lane import Finding, LaneHttp, form_token, login, message_of, seed as seed_person  # noqa: E402
from seed_own_stand import Mailbox, Unmet, write_env  # noqa: E402
from seed_stored_value import EMAIL_RE, PsqlStore  # noqa: E402

RC_FINDING = 1
RC_UNMET = 75

# Приставка — чья личность: `keyPerson` — FP-12 полосы входа, `f13Person` — полоса
# «личность без пароля» Ф13 набора ключей доступа.
PREFIXES = ("keyPerson", "f13Person")
FIELDS = ("Email", "CredentialId", "UserHandle", "Origin")
# Привязка ключей доступа СТЕНДА — имя доверяющей стороны и происхождение консоли,
# под которыми посев доказал регистрацию. Набор `kaname-access-keys` собирает
# церемонии под них же (ключ окружения, иначе величина профиля), поэтому они
# уезжают в окружение тем же посевом, а не выписываются в наборе второй раз.
BINDING_KEYS = ("accessKeysRpId", "accessKeysOrigin")
# Потолок ключей человека СТЕНДА (kaname#699): набор заполняет его до конца и
# судит отказ сверх него, поэтому читает величину стенда, а не профиля.
CEILING_KEY = "accessKeysCeiling"
MINTED_KEYS = tuple(prefix + field for prefix in PREFIXES for field in FIELDS) + BINDING_KEYS + (CEILING_KEY,)
MINTED_SURFACE = "служба (собственный REST-фронт)"

DOMAIN = "kaname.local"

# Индекс материала подставного аутентификатора (`_KEYS` модуля ключей доступа),
# которым подписывает кейс FP-12. Тот же индекс кейс читает отсюда.
KEY_SLOT = 0

AUTHENTICATOR = ROOT / "tests" / "newman" / "cases" / "kaname-access-keys.py"
PROFILE = ROOT / "deploy" / "values.prod.yaml"

# Ручки стенда (kaname#684): имя доверяющей стороны и происхождение консоли,
# которые объявляет СТЕНД. Автономный стенд службы их не называет — тогда
# величины профиля поставки; стенд платформы объявляет свои (происхождение — из
# адреса консоли своего пространства) и называет их здесь. Обе или ни одной.
ENV_RP_ID = "KANAME_STAND_ACCESS_KEYS_RP_ID"
ENV_ORIGIN = "KANAME_STAND_ACCESS_KEYS_ORIGIN"
# Потолок ключей человека, который объявляет СТЕНД (kaname#699). Автономный стенд
# службы его не называет — тогда `ownCeilings.accessKeysPerUser` профиля; стенд
# платформы объявляет свой (чарт платформы ставит службе другую величину).
ENV_CEILING = "KANAME_STAND_ACCESS_KEYS_CEILING"
# Набор заводит до потолка два ключа сам и судит отказ сверх него: ниже трёх
# «Дано» кейса потолка не строится. Выше предела повтора набора заполнение не
# дошло бы до потолка — это тоже несозданное условие, а не величина продукта.
CEILING_MIN, CEILING_MAX = 3, 32
_RP_ID_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_ORIGIN_RE = re.compile(r"^https://([a-z0-9.-]+)(:[0-9]{1,5})?$")

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


def profile_ceiling(path: pathlib.Path = PROFILE) -> int:
    """`ownCeilings.accessKeysPerUser` профиля — ровно одно вхождение."""
    found = re.findall(r"^  accessKeysPerUser: (\d+)\s*$", path.read_text(encoding="utf-8"), re.M)
    if len(found) != 1:
        raise Finding(f"{path.name}: ownCeilings.accessKeysPerUser найден {len(found)} раз — ждали ровно один")
    return int(found[0])


def stand_ceiling(environ) -> int:
    """Потолок стенда: переменная `KANAME_STAND_ACCESS_KEYS_CEILING`, без неё — профиль.

    Величина не той формы — условие не создано, а не молчаливая подстановка
    профиля: набор заполнил бы чужой потолок, и отказ продукта на «лишнем» ключе
    читался бы дефектом."""
    raw = (environ.get(ENV_CEILING) or "").strip()
    if not raw:
        return profile_ceiling()
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise Unmet(f"{ENV_CEILING}: ждали целое положительное число без знака и пробелов")
    n = int(raw)
    if not CEILING_MIN <= n <= CEILING_MAX:
        raise Unmet(f"{ENV_CEILING}: набор судит потолок от {CEILING_MIN} до {CEILING_MAX} — "
                    f"ниже «Дано» кейса потолка не строится, выше заполнение не дойдёт до него")
    return n


def stand_binding(environ) -> tuple[str, str]:
    """Привязка стенда: переменные `KANAME_STAND_ACCESS_KEYS_*`, без них — профиль.

    Названа одна из двух — условие не создано: половина привязки стенда с
    половиной профиля дала бы церемонию, которую продукт честно отвергнет, и
    отказ читался бы дефектом. По той же причине отвергается величина, под
    которой аутентификатор церемонию не собрал бы: имя со схемой, портом либо
    заглавными; происхождение не `https://хост[:порт]` либо вне имени доверяющей
    стороны; происхождение, совпавшее с «чужим» набора (`https://elsewhere.<имя>`)."""
    rp_id = (environ.get(ENV_RP_ID) or "").strip()
    origin = (environ.get(ENV_ORIGIN) or "").strip()
    if not rp_id and not origin:
        return profile_binding()
    if not (rp_id and origin):
        raise Unmet(f"названа одна из двух ручек привязки стенда ({ENV_RP_ID}, {ENV_ORIGIN}) — "
                    "нужны обе либо ни одной")
    if not _RP_ID_RE.match(rp_id):
        raise Unmet(f"{ENV_RP_ID}: ждали доменное имя строчными без схемы и порта")
    m = _ORIGIN_RE.match(origin)
    if not m:
        raise Unmet(f"{ENV_ORIGIN}: ждали https://хост[:порт] без пути")
    host = m.group(1)
    if host != rp_id and not host.endswith("." + rp_id):
        raise Unmet(f"{ENV_ORIGIN}: хост происхождения не лежит под именем доверяющей стороны "
                    f"из {ENV_RP_ID}")
    if origin == "https://elsewhere." + rp_id:
        raise Unmet(f"{ENV_ORIGIN} совпадает с «чужим» происхождением набора — отрицательные кейсы "
                    "перестанут быть отрицательными")
    return rp_id, origin


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
        raise Finding("испытание называет доверяющую сторону, отличную от привязки посева — стенд "
                      f"объявляет своё имя, а {ENV_RP_ID} и {ENV_ORIGIN} его не называют либо называют "
                      "не то")
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


# ─────────────────────────── снятие второго фактора ──────────────────────────

SECOND_FACTOR_REMOVE = "/iam/v1/auth/second-factor/remove"
# Способ предъявления при снятии — запасной код (`assurance.MethodLookupSecret`).
LOOKUP_SECRET = "lookup_secret"


def remove_second_factor(lane, session: str, code: str) -> None:
    """Снятие второго фактора глаголом полосы (Ф12-28) под сессией «2»,
    подтверждённое запасным кодом. Утверждается ответ: `200` и тело ровно
    `session`, `assurance` — набора после снятия нет, и сводки набора в ответе
    нет (kaname#297 BCS-11)."""
    token, ctx = form_token(lane, SECOND_FACTOR_FORM, {"kaname_session": session})
    status, _, text = lane.ask("POST", SECOND_FACTOR_REMOVE,
                               body={"method": LOOKUP_SECRET, "code": code, "csrfToken": token},
                               cookies={"kaname_form": ctx, "kaname_session": session})
    if status != 200:
        raise Finding(f"снятие второго фактора запасным кодом: ждали 200, получили {status} "
                      f"({message_of(text)!r})")
    extra = sorted(set(_json(text)) - {"session", "assurance"})
    if extra:
        raise Finding(f"снятие второго фактора ответило 200, а тело несёт ещё {extra} — набор "
                      "запасных кодов назван после снятия, фактор снят не целиком")


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
    rp_id, origin = binding or stand_binding(os.environ)
    email = f"key-person-{secrets.token_hex(6)}@{DOMAIN}"
    password = "Key-" + secrets.token_hex(12)
    seed_person(lane, mailbox, email, password, sleep)
    session, user = human_session(lane, email, password)
    raised, _, backup = enroll_second_factor_with_codes(lane, session)
    if not backup:
        raise Finding("подтверждение второго фактора не показало запасных кодов — снять фактор "
                      "глаголом полосы нечем (Ф12-02)")
    cid, sec, redirect = client
    code, verifier = authorize(doors, cid, redirect, raised)
    token = exchange(doors, cid, sec, code, verifier, redirect)
    if str(token_claims(token).get("acr")) != "2":
        raise Finding(f"церемония под сессией «2» выдала токен уровня {token_claims(token).get('acr')!r} — "
                      "уровень токена обязан быть уровнем сессии")
    say("  ok   человек заведён глаголами полосы, второй фактор поднял сессию до «2», токен уровня «2» "
        "выкован нашей церемонией")
    cred_id, handle = register_key(doors, token, user, key, rp_id, origin, sleep)
    say("  ok   ключ доступа заведён глаголом собственного фронта (операция без ошибки)")
    remove_second_factor(lane, raised, backup[0])
    say("  ok   второй фактор снят глаголом полосы запасным кодом — из способов «2» остался ключ")
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
             ceiling=None, sleep=time.sleep, prefixes=PREFIXES) -> dict:
    """Личности названных приставок (умолчание — обе): свежая почта, свой ключ, своя рукоятка.

    Привязка разрешается ОДИН раз и уезжает в окружение рядом с личностями: набор
    ключей доступа собирает церемонии под ту же привязку, под которой посев
    доказал регистрацию.

    ПОДМНОЖЕСТВО ПРИСТАВОК — ПЕРЕПОСЕВ ОДНОРАЗОВОЙ ЛИЧНОСТИ (kaname#860). Личность
    без пароля прогон расходует: Ф13-25 заводит ей пароль восстановлением, а вход
    ключом двигает счётчик подписи. Второй прогон на той же строке получает единый
    отказ входа ключом. Поэтому прогонщик перед набором ключей доступа сеет одну
    приставку `f13Person` заново, а прочие строки окружения не трогает."""
    unknown = [p for p in prefixes if p not in PREFIXES]
    if unknown or not prefixes:
        raise Unmet(f"приставки {list(prefixes)} вне объявленных {list(PREFIXES)} — сеять некого")
    binding = binding or stand_binding(os.environ)
    ceiling = stand_ceiling(os.environ) if ceiling is None else ceiling
    patch: dict = {}
    for prefix in prefixes:
        patch.update(seed(lane, mailbox, doors, store, client, keys=keys, binding=binding,
                          sleep=sleep, prefix=prefix))
        say(f"  ok   личность «{prefix}» положена")
    patch.update(dict(zip(BINDING_KEYS, binding)))
    patch[CEILING_KEY] = str(ceiling)
    return patch


def run(args: argparse.Namespace) -> int:
    pki = pathlib.Path(args.pki)
    patch = seed_all(LaneHttp(args.base_url, pki), Mailbox(args.mailbox_url),
                 Doors(pki, args.issuance_url, args.own_url), PsqlStore(shlex.split(args.store_exec)),
                 client_of(pathlib.Path(args.env_file)), prefixes=tuple(args.prefix or PREFIXES))
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев личности с ключом: ключей записано {len(patch)} (заменено {replaced}) в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


def _step_up_text(path: pathlib.Path = ROOT / "internal" / "errors" / "step_up.go") -> str:
    """Текст указания повысить уровень — у производителя (`TextStepUpRequired`),
    а не копией: двойник отказывает тем же текстом, что служба, и правка текста
    в службе доезжает до двойника без второй записи."""
    m = re.search(r'^const TextStepUpRequired = "([^"\\]+)"$', path.read_text(encoding="utf-8"), re.M)
    if not m:
        raise SystemExit(f"seed_key_person: в {path} нет константы TextStepUpRequired строкой — сверить разбор")
    return m.group(1)



def _fake_token(session: str) -> str:
    """Токен двойника выдачи: уровень токена — уровень сессии, под которой шла
    церемония (как у продукта, `ceremony_bearer`). Сессия «2» двойника — `s2`."""
    claims = {"sub": "usr-x", "acr": "2" if session == "s2" else "1"}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return "e30." + payload + ".sig"


class _FakeDoors:
    issuance, own = "https://iss", "https://own"

    def __init__(self, handle=True, rp="kaname.local", op_error=None):
        self.handle, self.rp, self.op_error = handle, rp, op_error
        self.finished: list[dict] = []

    def http(self, url, *, method="GET", headers=None, form=None, body=None):
        if url.endswith(":beginRegistration") or url.endswith("/accessKeys"):
            # Пол «2» трёх глаголов ключа (kaname#747, Р3): двойник держит его тем
            # же исходом, что служба, — иначе он глотал бы то, на чём настоящий
            # отказывает.
            bearer = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
            parts = bearer.split(".")
            try:
                acr = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))).get("acr")
            except (IndexError, ValueError):
                acr = None
            if acr != "2":
                return 401, {}, json.dumps({"code": 16, "message": _step_up_text()})
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


class _FakeLane:
    """Двойник полосы для снятия второго фактора: признак формы и сам глагол.
    Отказ и лишняя сводка набора в ответе — изменяемые факты."""

    def __init__(self, remove_status=200, leftover=None):
        self.remove_status, self.leftover = remove_status, leftover
        self.removed: list[dict] = []

    def ask(self, method, path, body=None, cookies=None):
        if method == "GET" and path.startswith("/iam/v1/auth/csrf"):
            return 200, ["kaname_form=ctx; Path=/"], json.dumps({"csrfToken": "t"})
        if method == "POST" and path == SECOND_FACTOR_REMOVE:
            # Снятие судится под сессией «2» с запасным кодом, который показало подтверждение.
            if (cookies or {}).get("kaname_session") != "s2" or body.get("method") != LOOKUP_SECRET \
                    or body.get("code") != "backup-1":
                return 403, [], json.dumps({"message": "refused"})
            self.removed.append(body)
            if self.remove_status != 200:
                return self.remove_status, [], json.dumps({"message": "refused"})
            body = {"session": {"assuranceLevel": "2"}, "assurance": {"level": "2"}}
            if self.leftover is not None:
                body["backupCodeSet"] = self.leftover
            return 200, ["kaname_session=s3; Path=/"], json.dumps(body)
        return 404, [], "{}"


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

    global seed_person, human_session, authorize, exchange, login, enroll_second_factor_with_codes
    saved = (seed_person, human_session, authorize, exchange, login, enroll_second_factor_with_codes)
    login_answer = {"value": None}
    codes_answer = {"value": ["backup-1", "backup-2"]}
    enroll_second_factor_with_codes = lambda lane, s: ("s2" if s == "s1" else s, "secret",  # noqa: E731
                                                       codes_answer["value"])
    seed_person = lambda *a, **k: "заведён"  # noqa: E731
    human_session = lambda lane, e, p: ("s1", "usr-x")  # noqa: E731
    authorize = lambda d, c, r, s: (s, "verifier")  # noqa: E731
    exchange = lambda d, c, s, code, v, r: _fake_token(code)  # noqa: E731
    login = lambda lane, e, p: login_answer["value"]  # noqa: E731
    try:
        print("=== посев личности с ключом: различение исходов ===")
        keys = authenticator_keys()
        _c("материал подставного аутентификатора читается разбором модуля ключей доступа",
           len(keys) >= 1 and all(re.fullmatch(r"[0-9a-f]+", k["n"]) for k in keys), f"{len(keys)}")
        rp, origin = profile_binding()
        _c("имя доверяющей стороны и происхождение — из профиля поставки", bool(rp) and origin.startswith("https://"),
           f"{rp} {origin}")
        stand_rp, stand_origin = "stand.example.invalid", "https://console.stand.example.invalid:20001"
        for label, env, want in [
            ("переменных стенда нет — величины профиля", {}, ("ok", str((rp, origin)))),
            ("переменные пусты — величины профиля", {ENV_RP_ID: "", ENV_ORIGIN: " "}, ("ok", str((rp, origin)))),
            ("обе переменные названы — величины стенда",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: stand_origin}, ("ok", str((stand_rp, stand_origin)))),
            ("происхождение — само имя без поддомена — законно",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: "https://" + stand_rp}, ("ok", str((stand_rp, "https://" + stand_rp)))),
            ("названо одно имя — условие не создано", {ENV_RP_ID: stand_rp}, ("unmet", None)),
            ("названо одно происхождение — условие не создано", {ENV_ORIGIN: stand_origin}, ("unmet", None)),
            ("имя со схемой — условие не создано", {ENV_RP_ID: "https://" + stand_rp, ENV_ORIGIN: stand_origin},
             ("unmet", None)),
            ("имя заглавными — условие не создано", {ENV_RP_ID: stand_rp.upper(), ENV_ORIGIN: stand_origin},
             ("unmet", None)),
            ("происхождение без https — условие не создано",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: "http://console." + stand_rp}, ("unmet", None)),
            ("происхождение с путём — условие не создано",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: stand_origin + "/"}, ("unmet", None)),
            ("происхождение вне имени доверяющей стороны — условие не создано",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: "https://console.other.example.invalid"}, ("unmet", None)),
            ("хвост имени без точки не делает происхождение своим — условие не создано",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: "https://evil" + stand_rp}, ("unmet", None)),
            ("происхождение совпало с «чужим» набора — условие не создано",
             {ENV_RP_ID: stand_rp, ENV_ORIGIN: "https://elsewhere." + stand_rp}, ("unmet", None)),
        ]:
            got = _outcome(lambda env=env: stand_binding(env))
            _c(label, got[0] == want[0] and (want[1] is None or got[1] == want[1]), f"{got}")

        prof_ceiling = profile_ceiling()
        for label, env, want in [
            ("потолок: переменной стенда нет — величина профиля", {}, ("ok", str(prof_ceiling))),
            ("потолок: переменная пуста — величина профиля", {ENV_CEILING: " "}, ("ok", str(prof_ceiling))),
            ("потолок: переменная названа — величина стенда", {ENV_CEILING: "8"}, ("ok", "8")),
            ("потолок: на границе предела повтора — величина стенда", {ENV_CEILING: str(CEILING_MAX)},
             ("ok", str(CEILING_MAX))),
            ("потолок: не число — условие не создано", {ENV_CEILING: "восемь"}, ("unmet", None)),
            ("потолок: со знаком — условие не создано", {ENV_CEILING: "+8"}, ("unmet", None)),
            ("потолок: с ведущим нулём — условие не создано", {ENV_CEILING: "08"}, ("unmet", None)),
            ("потолок: ниже трёх — условие не создано", {ENV_CEILING: "2"}, ("unmet", None)),
            ("потолок: выше предела повтора — условие не создано", {ENV_CEILING: str(CEILING_MAX + 1)},
             ("unmet", None)),
        ]:
            got = _outcome(lambda env=env: stand_ceiling(env))
            _c(label, got[0] == want[0] and (want[1] is None or got[1] == want[1]), f"{got}")

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

        def sow(doors=None, store=None, after_login=None, lane=None, codes=("backup-1", "backup-2")):
            login_answer["value"], codes_answer["value"] = after_login, list(codes)
            d, s = doors or _FakeDoors(rp=rp), store or _FakeStore()
            ln = lane or _FakeLane()
            return _outcome(lambda: seed_all(ln, None, d, s, ("c", "s", "r"), binding=(rp, origin),
                                             sleep=lambda _: None)), d, s, ln

        (kind, text), d, s, ln = sow()
        _c("законный мир — у каждой из двух личностей ключ заведён сессией «2», второй фактор снят "
           "запасным кодом, затем строка пароля снята, вход паролем отвергнут",
           kind == "ok" and len(d.finished) == len(PREFIXES) == 2 and len(ln.removed) == 2
           and len(s.sql) == 2 and all("DELETE" in q for q in s.sql) and s.sql[0] != s.sql[1],
           f"{kind}: {text}")
        patch = json.loads(text.replace("'", '"')) if kind == "ok" else {}
        _c("объявленные ключи = записываемые (в обе стороны)", set(patch) == set(MINTED_KEYS), f"{patch}")
        _c("рукоятка и удостоверение — base64url без выравнивания (форма полосы входа ключом) у обеих",
           kind == "ok" and all("=" not in patch[p + "UserHandle"] and len(unb64(patch[p + "UserHandle"])) == 64
                                and len(unb64(patch[p + "CredentialId"])) == 16 for p in PREFIXES), f"{patch}")
        _c("личности разные: своя почта и своё удостоверение у каждой приставки",
           kind == "ok" and patch["keyPersonEmail"] != patch["f13PersonEmail"]
           and patch["keyPersonCredentialId"] != patch["f13PersonCredentialId"], f"{patch}")
        # Перепосев одноразовой личности (kaname#860): одна приставка — одна личность,
        # чужие ключи окружения не пишутся; близнец — умолчание выше (обе).
        lane_one, doors_one = _FakeLane(), _FakeDoors(rp=rp)
        kind_o, text_o = _outcome(lambda: seed_all(lane_one, None, doors_one, _FakeStore(), ("c", "s", "r"),
                                                   binding=(rp, origin), sleep=lambda _: None,
                                                   prefixes=("f13Person",)))
        patch_o = json.loads(text_o.replace("'", '"')) if kind_o == "ok" else {}
        _c("одна приставка — заведена одна личность, записаны только её ключи, привязка и потолок",
           kind_o == "ok" and len(doors_one.finished) == 1 and len(lane_one.removed) == 1
           and set(patch_o) == {"f13Person" + f for f in FIELDS} | set(BINDING_KEYS) | {CEILING_KEY},
           f"{kind_o}: {text_o}")
        kind_u, text_u = _outcome(lambda: seed_all(_FakeLane(), None, _FakeDoors(rp=rp), _FakeStore(),
                                                   ("c", "s", "r"), binding=(rp, origin),
                                                   sleep=lambda _: None, prefixes=("nobody",)))
        _c("приставка вне объявленных — условие не создано, а не тихий пустой посев",
           kind_u == "unmet" and "nobody" in text_u, f"{kind_u}: {text_u}")
        _c("привязка профиля уезжает в окружение рядом с личностями",
           kind == "ok" and (patch["accessKeysRpId"], patch["accessKeysOrigin"]) == (rp, origin), f"{patch}")
        _c("потолок уезжает в окружение тем же посевом",
           kind == "ok" and patch.get(CEILING_KEY) == str(stand_ceiling(os.environ)), f"{patch}")
        kind_c, text_c = _outcome(lambda: seed_all(_FakeLane(), None, _FakeDoors(rp=rp), _FakeStore(), ("c", "s", "r"),
                                                   binding=(rp, origin), ceiling=stand_ceiling({ENV_CEILING: "8"}),
                                                   sleep=lambda _: None))
        patch_c = json.loads(text_c.replace("'", '"')) if kind_c == "ok" else {}
        _c("потолок стенда уезжает в окружение величиной стенда, а не профиля",
           kind_c == "ok" and patch_c.get(CEILING_KEY) == "8", f"{kind_c}: {text_c}")

        login_answer["value"] = None
        d_st = _FakeDoors(rp=stand_rp)
        kind_st, text_st = _outcome(lambda: seed_all(_FakeLane(), None, d_st, _FakeStore(), ("c", "s", "r"),
                                                     binding=stand_binding({ENV_RP_ID: stand_rp,
                                                                            ENV_ORIGIN: stand_origin}),
                                                     sleep=lambda _: None))
        patch_st = json.loads(text_st.replace("'", '"')) if kind_st == "ok" else {}
        origins_st = {json.loads(base64.b64decode(f["credential"]["clientDataJson"]))["origin"]
                      for f in d_st.finished}
        _c("привязка стенда: испытание под его имя проходит, регистрация собрана с его происхождением, "
           "она же уезжает в окружение",
           kind_st == "ok" and origins_st == {stand_origin}
           and (patch_st["accessKeysRpId"], patch_st["accessKeysOrigin"]) == (stand_rp, stand_origin)
           and patch_st["f13PersonOrigin"] == stand_origin, f"{kind_st}: {text_st} {origins_st}")
        for label, kw, want in [
            ("испытание без рукоятки — находка", {"doors": _FakeDoors(handle=False, rp=rp)}, "finding"),
            ("доверяющая сторона чужая — находка", {"doors": _FakeDoors(rp="elsewhere")}, "finding"),
            ("операция регистрации с ошибкой — находка",
             {"doors": _FakeDoors(rp=rp, op_error={"code": 9, "message": "x"})}, "finding"),
            ("строки пароля не было — находка", {"store": _FakeStore(rows=("opened",))}, "finding"),
            ("отметка открытого пути не легла — находка", {"store": _FakeStore(rows=("password",))}, "finding"),
            ("вход прежним паролем после снятия проходит — находка",
             {"after_login": {"bearer": "b", "verified": True}}, "finding"),
            ("подтверждение второго фактора без запасных кодов — находка", {"codes": ()}, "finding"),
            ("снятие второго фактора отвергнуто — находка", {"lane": _FakeLane(remove_status=409)}, "finding"),
            ("снятие второго фактора назвало набор запасных кодов — находка",
             {"lane": _FakeLane(leftover={"remaining": 10, "total": 10, "issuedAt": "2026-10-19T00:00:00Z"})},
             "finding"),
        ]:
            (kind, text), _, _, _ = sow(**kw)
            _c(label, kind == want, f"{kind}: {text}")
        # Близнецы красного kaname#768, по одному изменённому факту. (а) Сессия не
        # поднята до «2» — посев называет причину сам, до глагола ключа. (б) Глагол
        # ключа под токеном «1» — двойник отказывает дословным текстом службы (пол
        # «2», kaname#747 Р3), и посев несёт этот текст в находке; под токеном «2»
        # тот же вызов проходит.
        enroll_second_factor_with_codes = lambda lane, s: (s, "secret", ["backup-1"])  # noqa: E731
        (kind, text), _, _, _ = sow()
        _c("сессия не поднята до «2» — находка называет уровень токена",
           kind == "finding" and "уровня '1'" in text, f"{kind}: {text}")
        enroll_second_factor_with_codes = lambda lane, s: ("s2" if s == "s1" else s, "secret",  # noqa: E731
                                                           codes_answer["value"])
        key0 = authenticator_keys()[KEY_SLOT]
        for label, tok, want in [
            ("ключ под токеном «1» — указание повысить уровень дословно", _fake_token("s1"), "finding"),
            ("ключ под токеном «2» — заведён", _fake_token("s2"), "ok"),
        ]:
            got = _outcome(lambda tok=tok: register_key(_FakeDoors(rp=rp), tok, "usr-x", key0, rp, origin,
                                                        lambda _: None))
            _c(label, got[0] == want and (want == "ok" or _step_up_text() in got[1]), f"{got}")
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
        seed_person, human_session, authorize, exchange, login, enroll_second_factor_with_codes = saved

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
    ap.add_argument("--prefix", action="append", choices=PREFIXES,
                    help="сеять только эту приставку (повторяемо); умолчание — все")
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
