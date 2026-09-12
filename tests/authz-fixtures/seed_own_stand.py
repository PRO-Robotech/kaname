#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""МАШИННЫЙ ПОСЕВ для АВТОНОМНОГО стенда службы: удостоверения своей чеканки.

ПРЕДМЕТ. На автономном стенде нет ни края платформы, ни внешнего поставщика
личности. Сквозной набор при этом читает из окружения четыре предъявителя и два
адреса, и пока их не пишет никто, коллекция `kaname-own-rest-front` — та
единственная, чья поверхность принадлежит САМОЙ службе, — не гоняется ни разу.
Это не «нет покрытия», а покрытие ОБЪЯВЛЕННОЕ И НЕИСПОЛНИМОЕ.

ВСЁ, ЧТО ЗДЕСЬ ДЕЛАЕТСЯ, ДЕЛАЕТСЯ ЕДИНСТВЕННЫМ ГЛАГОЛОМ ПРОДУКТА. Ни одной
записи в базу, ни одной подписи чужим ключом, ни одного обхода рубежа:

  1. чеканка бутстрап-удостоверения — `InternalBootstrapTokenService` на :9091,
     gRPC поверх взаимного TLS. Круг вызывающих задан ИМЕНАМИ сертификатов, и
     стенд предъявляет своё; REST-маршрута у этой чеканки нет нигде;
  2. провизия личности — `POST /iam/v1/hooks/provision` на :9092 с секретом
     `X-Kacho-Hook-Token`. Это ТОТ ЖЕ обработчик, что обслуживает
     `InternalUserService/UpsertFromIdentity`, и он заводит человека, его личный
     аккаунт, проект по умолчанию и выдачу владельца — то есть АРЕНДАТОРА;
  3. выпуск удостоверения субъекта — `UserTokenService/Issue` и
     `SAKeyService/Issue`. Приватный ключ показывается ОДИН раз;
  4. обмен — `POST /iam/v1/token` на :9096: подписанное утверждение клиента
     (RFC 7521/7523) у НАШЕГО издателя. Адресат утверждения — идентификатор
     издателя, а не адрес эндпоинта.

ПОЧЕМУ ВТОРОЙ ВХОД (ХУК) ЗАКОНЕН, И ГДЕ ЕГО ГРАНИЦА — СКАЗАНО ПРЯМО. Аккаунт
принадлежит ЧЕЛОВЕКУ by construction: `CreateAccount` от служебной учётки
отвергается синхронно («an Account is owned by a user; principal type is
service_account»), а единственный человек свежего стенда несёт
`invite_status=PENDING` и пустой внешний идентификатор, то есть токен ему не
выпускается («is not active»). Машинных дверей к активному человеку ровно две:
gRPC `UpsertFromIdentity`, доступный в боевой посадке ТОЛЬКО учётной записи
края, и этот хук, доступный держателю общего секрета. Края на автономном стенде
нет by construction — значит остаётся хук, и предъявляем мы НАСТОЯЩИЙ секрет
посадки, а не обходим проверку. Отсюда и граница: посев не вправе выпустить себе
сертификат с именем края — это была бы личность отсутствующего звена.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — посев состоялся, окружение записано;
    1  — НАХОДКА: продукт отказал там, где посев предъявил всё, чего требует
         контракт. Это вердикт о дереве;
   75  — УСЛОВИЕ НЕ СОЗДАНО: стенда нет (нет слушателя, нет сертификатов, нет
         `grpcurl`). Вердикта о дереве нет НИ ОДНОГО.

КАЖДЫЙ СОЗДАЮЩИЙ ШАГ УТВЕРЖДАЕТ И СТАТУС, И ЗАХВАТ. Шаг, проверивший только
код, оставляет переменную пустой, кейс уезжает дальше и падает через три шага,
называя виновником невиновного.

САМОПРОВЕРКА — `--self-test`: доказывает инъекцией, что «нет слушателя» отличимо
от находки КОДОМ, что успешный статус с пустым захватом даёт находку, и что
объявленный перечень записываемых ключей сходится с тем, что запись
действительно производит, — в обе стороны.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RC_FINDING = 1
RC_UNMET = 75

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Издатель и адресат стенда. Величины объявлены ОДИН раз и совпадают с посадкой
# (`.github/scripts/stand-own.sh`): расхождение здесь дало бы отказ обмена с
# текстом про несовпадение адресата, то есть находку о дереве на месте опечатки.
STAND_ISSUER = "https://kaname.local"

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Заголовочный `typ` утверждения. НАШ проверяющий его ТРЕБУЕТ: без него обмен
# отвергается до сверки подписи, и отказ выглядит как неверный клиент.
ASSERTION_TOKEN_TYPE = "client-authentication+jwt"

HOOK_HEADER = "X-Kacho-Hook-Token"
BOOTSTRAP_METHOD = (
    "kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken")
BOOTSTRAP_PROTO = "kaname/cloud/iam/v1/internal_bootstrap_token_service.proto"

# ─────────────────────────────────────────────────────────────────────────────
# КЛЮЧИ ОКРУЖЕНИЯ, КОТОРЫЕ ЭТОТ ПОСЕВ ПИШЕТ
#
# Перечень объявлен ЗДЕСЬ и выдаётся флагом `--minted-keys`: перепись долга
# (`.github/scripts/newman-suite-debt.py`) спрашивает его у САМОГО посева, а не
# держит вторую копию. Копия разошлась бы молча и разошлась бы в одну сторону:
# новый ключ в неё просто не попал бы.
#
# Сходимость объявления с записью держится не этой строкой, а самопроверкой
# ниже: она сравнивает перечень с тем, что производит `env_patch`, в обе стороны.
# ─────────────────────────────────────────────────────────────────────────────

# Предъявители: пусты в шаблоне, и пока их не напишет посев, шаги с ними
# отказывают меткой «условие не создано».
MINTED_CREDENTIALS = (
    "jwtAccountAdminA",
    "jwtAccountAdminB",
    "jwtPureNoBindings",
    "jwtSAA",
)
# Адреса собственных фронтов: их производит САМ стенд, и удостоверениями они не
# являются. Названы отдельной группой намеренно — перепись долга считала все
# шесть пустых ключей «удостоверениями», и два из шести ими не были никогда.
MINTED_ADDRESSES = (
    "ownRestBaseUrl",
    "ownInternalRestBaseUrl",
)
# Идентификаторы, которые в шаблоне стоят ПРАВДОПОДОБНЫМИ ЛИТЕРАЛАМИ с чужого
# стенда. Они непусты, поэтому перепись долга их препятствием не считает, — а
# указывают они в пустоту: аккаунта `accmnkdsy70pyn7qbm12` на этом стенде нет.
# Посев заменяет их теми, которые ВЕРНУЛ продукт.
MINTED_IDENTIFIERS = (
    "accountAId",
    "accountBId",
    "existingAccountId",
    "existingProjectId",
    "existingProjectCrossId",
    "svaAId",
    "runId",
)


def minted_keys() -> tuple[str, ...]:
    return MINTED_ADDRESSES + MINTED_CREDENTIALS + MINTED_IDENTIFIERS


# ─────────────────────────── исходы и учёт ───────────────────────────────────

findings: list[str] = []
unmet_reasons: list[str] = []
steps_done = 0


class Unmet(Exception):
    """Условие не создано: вердикта о дереве нет."""


class Finding(Exception):
    """Продукт отказал там, где посев предъявил требуемое контрактом."""


def say(msg: str) -> None:
    print(msg, flush=True)


def step(label: str) -> None:
    global steps_done
    steps_done += 1
    print(f"  ok   {label}", flush=True)


# ─────────────────────────── транспорт ───────────────────────────────────────


class Http:
    """Клиент собственных фронтов стенда: взаимный TLS и проверка имени.

    Имя сервера ПРОВЕРЯЕТСЯ: снять проверку значило бы перестать проверять то,
    ради чего взаимный TLS и включён на этой посадке.
    """

    def __init__(self, pki: pathlib.Path):
        ca, cert, key = pki / "ca.crt", pki / "srv.crt", pki / "srv.key"
        for f in (ca, cert, key):
            if not f.is_file():
                raise Unmet(f"нет {f} — стенд не поднимался")
        self.ctx = ssl.create_default_context(cafile=str(ca))
        self.ctx.load_cert_chain(str(cert), str(key))

    def ask(self, url: str, *, method: str = "GET", token: str | None = None,
            body: dict | None = None, form: dict | None = None,
            headers: dict | None = None,
            timeout: float = 30.0) -> tuple[int | None, str]:
        data, hdrs = None, dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            hdrs["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, ssl.SSLError, OSError, socket.timeout) as e:
            # Соединение не состоялось — это НЕ вердикт о дереве.
            raise Unmet(f"{url} недостижим: {e}") from None

    def json_ask(self, url: str, **kw) -> tuple[int | None, dict]:
        code, text = self.ask(url, **kw)
        try:
            return code, json.loads(text or "{}")
        except json.JSONDecodeError:
            raise Finding(
                f"{url} ответил кодом {code} и НЕ-JSON телом: {text[:200]!r}. "
                f"Разобрать ответ нечем, а молчаливое продолжение оставило бы "
                f"переменную пустой") from None


def require_listener(host: str, port: int, what: str) -> None:
    try:
        with socket.create_connection((host, port), timeout=5):
            return
    except OSError as e:
        raise Unmet(f":{port} ({what}) не слушает: {e} — стенд не поднят") from None


# ─────────────────────── подпись утверждения клиента ─────────────────────────


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_client_assertion(client_id: str, private_key_pem: str, key_id: str,
                          audience: str, ttl_s: int = 120) -> str:
    """Подписать `client_assertion` выданным приватным ключом (ES256).

    Подписывается ИМЕНЕМ СТРОКИ РЕЕСТРА: проверяющий разрешает клиента по своей
    таблице, и утверждение, назвавшееся иначе, отвергается как неверный клиент.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric import utils as ecutils
    except ImportError as e:
        raise Unmet(f"нет библиотеки подписи (cryptography): {e} — "
                    f"утверждение не собрать, вердикта о дереве нет") from None
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"),
                                             password=None)
    now = int(time.time())
    header = {"alg": "ES256", "kid": key_id, "typ": ASSERTION_TOKEN_TYPE}
    payload = {"iss": client_id, "sub": client_id, "aud": audience,
               "iat": now, "exp": now + ttl_s, "jti": secrets.token_hex(16)}
    signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode())
                     + "." + b64u(json.dumps(payload, separators=(",", ":")).encode()))
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = ecutils.decode_dss_signature(der)
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# ─────────────────────────── шаги посева ─────────────────────────────────────


def mint_bootstrap(pki: pathlib.Path, host: str, grpc_port: int) -> str:
    """Бутстрап-удостоверение: ЕДИНСТВЕННЫЙ вход на дерево без личностей."""
    if not shutil.which("grpcurl"):
        raise Unmet("нет grpcurl — у чеканки бутстрапа REST-маршрута не "
                    "существует НИГДЕ, и позвать её больше нечем")
    proto_root = module_proto_root()
    args = ["grpcurl", "-insecure", "-max-time", "20",
            "-cert", str(pki / "srv.crt"), "-key", str(pki / "srv.key"),
            "-import-path", str(proto_root), "-proto", BOOTSTRAP_PROTO,
            "-d", "{}", f"{host}:{grpc_port}", BOOTSTRAP_METHOD]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise Finding(
            f"чеканка бутстрап-удостоверения отказала (grpcurl rc="
            f"{proc.returncode}): {(proc.stderr or proc.stdout).strip()[:400]}. "
            f"Круг вызывающих задан ИМЕНАМИ сертификатов "
            f"(authn.bootstrap-mint.allowed-client-sans) и ключ чеканки — "
            f"KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM")
    try:
        body = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise Finding(f"чеканка ответила НЕ-JSON: {proc.stdout[:200]!r}") from None
    token = body.get("accessToken") or ""
    if not token:
        raise Finding(f"чеканка ответила без accessToken: ключи {list(body)}")
    return token


def module_proto_root() -> pathlib.Path:
    """Каталог контрактов — из МОДУЛЯ-пина, а не из чужой рабочей копии."""
    env = os.environ.get("KANAME_STAND_PROTO_ROOT", "").strip()
    if env:
        p = pathlib.Path(env)
        if not (p / BOOTSTRAP_PROTO).is_file():
            raise Unmet(f"KANAME_STAND_PROTO_ROOT={p} не несёт {BOOTSTRAP_PROTO}")
        return p
    if not shutil.which("go"):
        raise Unmet("нет go — каталог контрактов модуля-пина назвать нечем")
    proc = subprocess.run(["go", "list", "-m", "-f", "{{.Dir}}",
                           "github.com/PRO-Robotech/kacho"],
                          capture_output=True, text=True, cwd=str(ROOT), timeout=120)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise Unmet("модуль-пин платформы не скачан (`go mod download`): "
                    f"{(proc.stderr or '').strip()[:200]}")
    root = pathlib.Path(proc.stdout.strip()) / "proto"
    if not (root / BOOTSTRAP_PROTO).is_file():
        raise Unmet(f"{root} не несёт {BOOTSTRAP_PROTO}")
    return root


def assert_bootstrap_accepted(http: Http, public: str, token: str) -> None:
    """Удостоверение, которое фронт отверг, неотличимо от невыпущенного.

    По всему, что можно спросить у службы, токен выдан: подпись стоит, срок
    идёт. Различает их только предъявление, поэтому шаг, создающий ПРЕДМЕТ всего
    посева, несёт собственное утверждение.
    """
    code, body = http.json_ask(f"{public}/iam/v1/accounts?pageSize=1", token=token)
    if code != 200 or "accounts" not in body:
        raise Finding(
            f"собственный фронт НЕ ПРИНЯЛ бутстрап-удостоверение: код {code}, "
            f"тело {json.dumps(body, ensure_ascii=False)[:300]}. Дальше идти "
            f"нельзя: всякий следующий отказ назвал бы виновником невиновного")


def provision_identity(http: Http, hooks: str, secret: str, external_id: str) -> None:
    """Провизия личности через хук поставщика — НАСТОЯЩИМ секретом посадки."""
    code, text = http.ask(f"{hooks}/iam/v1/hooks/provision", method="POST",
                          headers={HOOK_HEADER: secret},
                          body={"external_id": external_id, "email": external_id,
                                "display_name": external_id})
    if code == 500 and "hook_secret_not_configured" in text:
        raise Unmet("секрет хука не задан на посадке (KANAME_HOOK_TOKEN) — "
                    "провизия невозможна, вердикта о дереве нет")
    if code != 200:
        raise Finding(
            f"хук провизии отказал на {external_id}: код {code}, тело "
            f"{text[:300]!r}. Секрет предъявлен заголовком {HOOK_HEADER}")


def resolve_tenant(http: Http, public: str, token: str, external_id: str,
                   budget_s: float = 60.0) -> dict:
    """Личность → её аккаунт → её проект по умолчанию. ЖДЁТ, а не спрашивает раз.

    Хук отвечает 200 синхронно, а строка личности, её аккаунт и проект приезжают
    своим путём. Единственный ответ «ещё нет» здесь неотличим от «не будет»,
    поэтому ожидание идёт до ПРЕДМЕТА, а не до кода ответа.
    """
    deadline = time.time() + budget_s
    seen = {"user": False, "active": False, "account": False}
    while time.time() < deadline:
        code, body = http.json_ask(f"{public}/iam/v1/users?pageSize=1000", token=token)
        if code != 200:
            raise Finding(f"перечень людей не читается: код {code}")
        user = next((u for u in body.get("users", [])
                     if u.get("externalId") == external_id), None)
        if user:
            seen["user"] = True
            if user.get("inviteStatus") == "ACTIVE":
                seen["active"] = True
                code, accs = http.json_ask(f"{public}/iam/v1/accounts?pageSize=1000",
                                           token=token)
                acc = next((a for a in accs.get("accounts", [])
                            if a.get("ownerUserId") == user["id"]), None)
                if acc:
                    seen["account"] = True
                    code, prjs = http.json_ask(
                        f"{public}/iam/v1/projects?accountId={acc['id']}&pageSize=100",
                        token=token)
                    prj = next((p for p in prjs.get("projects", [])), None)
                    if prj:
                        return {"userId": user["id"], "accountId": acc["id"],
                                "projectId": prj["id"]}
        time.sleep(1)
    raise Finding(
        f"личность {external_id} не стала арендатором за {budget_s:.0f} с: "
        f"строка есть={seen['user']}, активна={seen['active']}, "
        f"аккаунт есть={seen['account']}. Хук ответил 200, значит отказ "
        f"наступил ПОСЛЕ него — смотреть журнал службы, а не вызов")


def await_operation(http: Http, public: str, token: str, op_id: str,
                    budget_s: float = 60.0) -> dict:
    """Дождаться завершения операции и ВЕРНУТЬ её ответ.

    Идентификатор ресурса в `metadata` предвыделен и приходит даже у операции,
    которая кончится ошибкой, — поэтому читается только `response`, и только
    после `done` без `error`.
    """
    deadline = time.time() + budget_s
    last: dict = {}
    while time.time() < deadline:
        code, last = http.json_ask(f"{public}/operations/{op_id}", token=token)
        if code != 200:
            raise Finding(f"операция {op_id} не читается: код {code}, "
                          f"тело {json.dumps(last, ensure_ascii=False)[:200]}")
        if last.get("done"):
            if last.get("error"):
                raise Finding(f"операция {op_id} завершилась отказом: "
                              f"{json.dumps(last['error'], ensure_ascii=False)[:300]}")
            resp = last.get("response") or {}
            if not resp:
                raise Finding(f"операция {op_id} завершена БЕЗ ответа — "
                              f"захватывать нечего")
            return resp
        time.sleep(1)
    raise Finding(f"операция {op_id} не завершилась за {budget_s:.0f} с: "
                  f"{json.dumps(last, ensure_ascii=False)[:300]}")


def post_operation(http: Http, public: str, token: str, path: str,
                   body: dict, what: str) -> dict:
    """Мутация → операция → её ответ. Утверждается И статус, И захват."""
    code, resp = http.json_ask(public + path, method="POST", token=token, body=body)
    if code != 200:
        raise Finding(f"{what}: код {code}, тело "
                      f"{json.dumps(resp, ensure_ascii=False)[:300]}")
    op_id = resp.get("id") or ""
    if not op_id:
        raise Finding(f"{what}: ответ 200 БЕЗ идентификатора операции — "
                      f"ждать нечего, и молчание здесь оставило бы переменную "
                      f"пустой: {json.dumps(resp, ensure_ascii=False)[:300]}")
    return await_operation(http, public, token, op_id)


def exchange(http: Http, token_url: str, client_id: str, key_pem: str,
             key_id: str, what: str) -> str:
    """Подписанное утверждение → токен НАШЕЙ чеканки."""
    assertion = sign_client_assertion(client_id, key_pem, key_id, STAND_ISSUER)
    code, body = http.json_ask(token_url, method="POST", form={
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
        "audience": STAND_ISSUER,
    })
    access = body.get("access_token") or ""
    if code != 200 or not access:
        raise Finding(
            f"обмен утверждения у нашего издателя не состоялся ({what}): код "
            f"{code}, тело {json.dumps(body, ensure_ascii=False)[:300]}. Полоса "
            f"включается authn.client-token.enabled, а адресат утверждения — "
            f"идентификатор издателя ({STAND_ISSUER})")
    return access


def key_material(resp: dict, what: str) -> tuple[str, str, str]:
    """Из ответа выдачи — (client_id, private_key_pem, key_id), все три непусты."""
    client_id = resp.get("clientId") or ""
    key_pem = resp.get("privateKeyPem") or ""
    key_id = resp.get("keyId") or ""
    missing = [n for n, v in (("clientId", client_id), ("privateKeyPem", key_pem),
                              ("keyId", key_id)) if not v]
    if missing:
        raise Finding(
            f"{what}: выдача прошла, но ответ не несёт {', '.join(missing)} — "
            f"приватный ключ показывается ОДИН раз, и повторить выдачу нечем")
    if client_id != key_id:
        raise Finding(
            f"{what}: выдача вернула ДВА имени — clientId={client_id!r} против "
            f"keyId={key_id!r}. Наш издатель разрешает клиента по строке "
            f"реестра, поэтому первое имя не годится для обмена ни при каком входе")
    return client_id, key_pem, key_id


def builtin_role_id(http: Http, public: str, token: str, name: str) -> str:
    """Идентификатор ВСТРОЕННОЙ роли по её имени — спрошенный у продукта.

    Выписанный идентификатор роли был бы правдоподобным литералом: он выводится
    из имени и потому выглядит настоящим на любом стенде, а совпасть обязан с
    тем, что лежит в ЭТОЙ базе. Спрашиваем перечень и отбираем по имени и по
    пустому аккаунту — встроенная роль арендатору не принадлежит.
    """
    code, body = http.json_ask(f"{public}/iam/v1/roles?pageSize=1000", token=token)
    if code != 200:
        raise Finding(f"перечень ролей не читается: код {code}")
    roles = [r for r in body.get("roles", [])
             if r.get("name") == name and not r.get("accountId")]
    if len(roles) != 1:
        raise Finding(
            f"встроенная роль {name!r} найдена {len(roles)} раз(а) среди "
            f"{len(body.get('roles', []))} — выдавать нечем, а выписанный "
            f"идентификатор совпал бы с базой лишь по совпадению")
    return roles[0]["id"]


def grant_account_admin(http: Http, public: str, token: str, sva_id: str,
                        role_id: str, account_id: str) -> str:
    """Выдача: служебная учётка получает роль на СВОЁМ аккаунте.

    Отказ ГРОМКИЙ. Посев без выдачи готовит субъекта БЕЗ ПРАВА, и всякое
    утверждение о доступе после этого проверяет не продукт, а собственную
    поломку: отказ придёт там, где кейс ждёт ответа, и виновником назовут
    невиновного.
    """
    resp = post_operation(
        http, public, token, "/iam/v1/accessBindings",
        {"subjectType": "service_account", "subjectId": sva_id,
         "roleId": role_id, "scopeType": "iam.account", "scopeId": account_id,
         "target": {"allInScope": {}}},
        f"выдача роли {role_id} учётке {sva_id} на аккаунте {account_id}")
    binding_id = resp.get("id") or ""
    if not binding_id:
        raise Finding(f"выдача учётке {sva_id} прошла без идентификатора привязки: "
                      f"{json.dumps(resp, ensure_ascii=False)[:300]}")
    if resp.get("status") != "ACTIVE":
        raise Finding(f"выдача {binding_id} создана в состоянии "
                      f"{resp.get('status')!r}, а не ACTIVE — права она не даёт")
    return binding_id


def make_service_account(http: Http, public: str, token: str, account_id: str,
                         name: str, run_id: str, what: str) -> str:
    """Служебная учётка в названном аккаунте. Идентификатор — от продукта."""
    resp = post_operation(
        http, public, token, "/iam/v1/serviceAccounts",
        {"accountId": account_id, "name": name,
         "description": f"посев автономного стенда, прогон {run_id}"},
        what)
    sva = resp.get("id") or ""
    if not sva:
        raise Finding(f"{what}: учётка создана, а идентификатора в ответе "
                      f"операции нет: {json.dumps(resp, ensure_ascii=False)[:300]}")
    return sva


def sa_token(http: Http, public: str, token_url: str, token: str, sva_id: str,
             run_id: str, what: str) -> str:
    """Ключ служебной учётки → подписанное утверждение → токен нашей чеканки."""
    resp = post_operation(
        http, public, token, f"/iam/v1/serviceAccounts/{sva_id}/keys",
        {"description": f"посев автономного стенда, прогон {run_id}"},
        f"выпуск ключа {what}")
    client_id, key_pem, key_id = key_material(resp, f"ключ {what}")
    return exchange(http, token_url, client_id, key_pem, key_id, what)


def assert_serves(http: Http, public: str, token: str, path: str,
                  what: str) -> None:
    """Предъявитель, которого фронт не принял, неотличим от невыпущенного.

    Шаг выпуска отвечает 200 и тому, чей доступ ничего не откроет: подпись
    стоит, срок идёт, а первый же кейс получает отказ и называет виновником
    продукт. Поэтому каждый выпущенный предъявитель ПРЕДЪЯВЛЯЕТСЯ здесь.
    """
    code, body = http.json_ask(public + path, token=token)
    if code != 200:
        raise Finding(
            f"{what}: предъявитель выпущен, а фронт ответил {code} на {path} — "
            f"{json.dumps(body, ensure_ascii=False)[:300]}. Выдача без права "
            f"готовит субъекта, на котором кейсы падали бы, называя виновником "
            f"невиновного")



def assert_no_bindings(http: Http, public: str, token: str, subject_id: str) -> None:
    """У «чистого» субъекта выдач НЕТ — и это утверждается, а не предполагается.

    Кейсы про него проверяют ответ тому, кому не выдано НИЧЕГО. Субъект, которому
    что-то выдано, оставил бы их зелёными по неверной причине.
    """
    code, body = http.json_ask(
        f"{public}/iam/v1/accessBindings:listBySubject"
        f"?subjectType=service_account&subjectId={subject_id}&pageSize=100",
        token=token)
    if code != 200:
        raise Finding(f"выдачи субъекта {subject_id} не читаются: код {code}, "
                      f"тело {json.dumps(body, ensure_ascii=False)[:200]}")
    items = body.get("accessBindings") or []
    if items:
        raise Finding(
            f"субъект {subject_id} заведён как «без выдач», а их у него "
            f"{len(items)} — кейсы про непривилегированного вызывающего зеленели "
            f"бы по неверной причине")


# ─────────────────────────── запись окружения ────────────────────────────────


def env_patch(fixtures: dict) -> dict:
    """Что именно посев пишет в окружение. ЧИСТАЯ функция — её судит самопроверка.

    Ключи берутся из объявления, а значения из результата посева: расхождение
    объявления и записи здесь невозможно by construction, и это проверяется в
    обе стороны.
    """
    out = {k: fixtures[k] for k in minted_keys()}
    return out


def write_env(patch: dict, env_file: pathlib.Path, template: pathlib.Path) -> int:
    """Записать значения в файл окружения, создав его из шаблона при отсутствии.

    Возвращает число ЗАМЕНЁННЫХ ключей. Ключ, которого в шаблоне нет, ДОБАВЛЯЕТСЯ
    записью — молча потерянный ключ дал бы шаг, падающий на пустой переменной.
    """
    if not env_file.is_file():
        if not template.is_file():
            raise Unmet(f"нет ни {env_file}, ни шаблона {template}")
        env_file.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    doc = json.loads(env_file.read_text(encoding="utf-8"))
    values = doc.setdefault("values", [])
    index = {v["key"]: v for v in values}
    replaced = 0
    for key, val in patch.items():
        if key in index:
            index[key]["value"] = val
            index[key]["enabled"] = True
            replaced += 1
        else:
            values.append({"key": key, "value": val, "type": "default",
                           "enabled": True})
    env_file.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    return replaced


# ─────────────────────────── прогон посева ───────────────────────────────────


def run(args: argparse.Namespace) -> int:
    pki = pathlib.Path(args.pki)
    host = args.host
    public = f"https://{host}:{args.port_public}"
    internal = f"https://{host}:{args.port_internal}"
    hooks = f"https://{host}:{args.port_hooks}"
    token_url = f"https://{host}:{args.port_token}/iam/v1/token"

    # Признак прогона: он уезжает в ИМЕНА заводимых предметов, поэтому повторный
    # прогон не встречает 409 — и заодно по нему видно, какой прогон что завёл.
    run_id = args.run_id or f"s{secrets.token_hex(4)}"

    for port, what in ((args.port_public, "собственный публичный REST"),
                       (args.port_internal, "собственный внутренний REST"),
                       (args.port_hooks, "хуки поставщика"),
                       (args.port_token, "выдача токенов"),
                       (args.port_grpc, "внутренний gRPC")):
        require_listener(host, port, what)

    hook_secret = os.environ.get("KANAME_HOOK_TOKEN", "").strip()
    if not hook_secret:
        raise Unmet("KANAME_HOOK_TOKEN не задан в окружении посева — тем же "
                    "секретом посадка принимает хук поставщика; без него "
                    "провизия личности невозможна")

    http = Http(pki)

    say(f"===== машинный посев автономного стенда (прогон {run_id}) =====")

    say("── вход: бутстрап-удостоверение своей чеканки ────────────────────────")
    boot = mint_bootstrap(pki, host, args.port_grpc)
    step("бутстрап-удостоверение выпущено (gRPC :%d, круг по имени сертификата)"
         % args.port_grpc)
    assert_bootstrap_accepted(http, public, boot)
    step("и собственный публичный фронт его ПРИНЯЛ (200 на перечне аккаунтов)")

    say("── два арендатора: личность → аккаунт → проект ───────────────────────")
    tenants = {}
    for lane in ("a", "b"):
        external_id = f"seed-{run_id}-{lane}@kaname.local"
        provision_identity(http, hooks, hook_secret, external_id)
        step(f"личность {lane.upper()} провизирована хуком поставщика")
        tenants[lane] = resolve_tenant(http, public, boot, external_id)
        t = tenants[lane]
        step(f"и стала арендатором: человек {t['userId']}, аккаунт "
             f"{t['accountId']}, проект {t['projectId']}")
    if tenants["a"]["accountId"] == tenants["b"]["accountId"]:
        raise Finding(
            "оба арендатора получили ОДИН аккаунт — кейсы про чужого арендатора "
            "проверяли бы своего, и «неотличимо от нет-такой» стало бы истинно "
            "тривиально")

    say("── предъявители арендаторов: служебная учётка с выдачей на аккаунте ──")
    #
    # ПРЕДЪЯВИТЕЛЬ ЗДЕСЬ — МАШИНА, А НЕ ЧЕЛОВЕК, И ЭТО ЗАМЕР, А НЕ УДОБСТВО.
    #
    # Токен человека, выпущенный машинно, приезжает с ПУСТЫМ уровнем
    # подтверждения личности (`kaname_acr`), а ручки собственного фронта
    # объявляют порог `required_acr_min=1`. Замер однофакторный, и он в отчёте
    # этой полосы: при ОДНОЙ И ТОЙ ЖЕ выдаче на аккаунте служебная учётка читает
    # аккаунт (200), а человек получает отказ (403) — уровень поднимается только
    # интерактивным входом, которого на автономном стенде нет вовсе.
    #
    # Люди выше заведены поэтому не ради предъявления, а ради того, чего без них
    # не существует: аккаунт принадлежит ЧЕЛОВЕКУ by construction, и второго
    # арендатора без второго человека не создать.
    role_admin = builtin_role_id(http, public, boot, "admin")
    step(f"встроенная роль admin спрошена у продукта: {role_admin}")
    creds: dict[str, str] = {}
    for lane, var in (("a", "jwtAccountAdminA"), ("b", "jwtAccountAdminB")):
        account_id = tenants[lane]["accountId"]
        sva = make_service_account(http, public, boot, account_id,
                                   f"seed-{run_id}-adm-{lane}", run_id,
                                   f"создание распорядителя аккаунта {lane.upper()}")
        grant_account_admin(http, public, boot, sva, role_admin, account_id)
        step(f"распорядитель аккаунта {lane.upper()} заведён и получил роль: {sva}")
        creds[var] = sa_token(http, public, token_url, boot, sva, run_id,
                              f"распорядитель аккаунта {lane.upper()}")
        assert_serves(http, public, creds[var], f"/iam/v1/accounts/{account_id}",
                      f"{var} (чтение СВОЕГО аккаунта)")
        step(f"{var} получен обменом и ПРИНЯТ фронтом на своём аккаунте")

    say("── служебная учётка A: субъект, который называет себя на /iam/v1/me ──")
    sva_a = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                 f"seed-{run_id}-sa-a", run_id,
                                 "создание служебной учётки A")
    step(f"служебная учётка A создана: {sva_a}")
    creds["jwtSAA"] = sa_token(http, public, token_url, boot, sva_a, run_id,
                               "служебная учётка A")
    assert_serves(http, public, creds["jwtSAA"], "/iam/v1/me",
                  "jwtSAA (называет себя на /iam/v1/me)")
    step("jwtSAA получен обменом и ПРИНЯТ фронтом на /iam/v1/me")

    say("── субъект БЕЗ выдач: тот, кому не выдано ничего ─────────────────────")
    sva_pure = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                    f"seed-{run_id}-pure", run_id,
                                    "создание служебной учётки без выдач")
    assert_no_bindings(http, public, boot, sva_pure)
    step(f"учётка без выдач заведена, и её перечень выдач ПУСТ: {sva_pure}")
    creds["jwtPureNoBindings"] = sa_token(http, public, token_url, boot, sva_pure,
                                          run_id, "субъект без выдач")
    assert_serves(http, public, creds["jwtPureNoBindings"], "/iam/v1/me",
                  "jwtPureNoBindings (рубеж проходит, права не имеет)")
    step("jwtPureNoBindings получен обменом и ПРИНЯТ рубежом (права при этом нет)")

    fixtures = {
        "ownRestBaseUrl": public,
        "ownInternalRestBaseUrl": internal,
        "accountAId": tenants["a"]["accountId"],
        "accountBId": tenants["b"]["accountId"],
        "existingAccountId": tenants["a"]["accountId"],
        "existingProjectId": tenants["a"]["projectId"],
        "existingProjectCrossId": tenants["b"]["projectId"],
        "svaAId": sva_a,
        "runId": run_id,
        **creds,
    }
    patch = env_patch(fixtures)
    env_file = pathlib.Path(args.env_file)
    replaced = write_env(patch, env_file, pathlib.Path(args.env_template))
    step(f"окружение записано: {env_file} — ключей {len(patch)}, из них "
         f"заменено в шаблоне {replaced}")

    say("")
    say(f"перепись: шагов с утверждённым исходом {steps_done} · "
         f"ключей записано {len(patch)} · предъявителей {len(creds)} · "
         f"арендаторов {len(tenants)}")
    say("ПОСЕЯНО. Всё выдано глаголами продукта: чеканка бутстрапа, хук "
        "провизии, выпуск удостоверения, обмен подписанного утверждения.")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _SELF.append(label)
        if detail:
            print(f"       {detail}")


def self_test() -> int:
    print("seed_own_stand: доказательство способности упасть")

    # Ось 1: объявление записываемых ключей сходится с записью — В ОБЕ СТОРОНЫ.
    declared = set(minted_keys())
    fixtures = {k: f"v-{k}" for k in declared}
    produced = set(env_patch(fixtures))
    _c("объявленный перечень ключей равен тому, что пишет env_patch",
       produced == declared, f"лишние {produced - declared}, "
                             f"недостающие {declared - produced}")
    missing_one = dict(fixtures)
    missing_one.pop("jwtSAA")
    try:
        env_patch(missing_one)
        _c("ключ, объявленный и НЕ добытый, роняет запись", False,
           "env_patch промолчал — переменная уехала бы в окружение пустой")
    except KeyError:
        _c("ключ, объявленный и НЕ добытый, роняет запись", True)

    # Ось 2: «нет слушателя» — код 75, а НЕ находка и не ноль.
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    _, closed_port = free.getsockname()
    free.close()
    env = dict(os.environ, KANAME_HOOK_TOKEN="selftest-secret")
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve()),
         "--host", "127.0.0.1", "--pki", "/nonexistent-pki-for-selftest",
         "--port-public", str(closed_port), "--port-internal", str(closed_port),
         "--port-hooks", str(closed_port), "--port-token", str(closed_port),
         "--port-grpc", str(closed_port)],
        capture_output=True, text=True, env=env, timeout=120)
    _c("нет слушателя — код 75, а НЕ 1 и не 0", proc.returncode == RC_UNMET,
       f"код {proc.returncode}, вывод {(proc.stdout + proc.stderr)[-300:]!r}")
    _c("и текст называет несозданное условие, а не находку",
       "УСЛОВИЕ НЕ СОЗДАНО" in (proc.stdout + proc.stderr)
       and "НАХОДКА" not in (proc.stdout + proc.stderr),
       (proc.stdout + proc.stderr)[-300:])

    # Ось 3: успешный статус с ПУСТЫМ захватом — находка, а не проход.
    # Законный близнец рядом: тот же код, но захват на месте — молчит.
    class _Fake:
        def __init__(self, resp):
            self.resp = resp

        def json_ask(self, url, **kw):
            if "/operations/" in url:
                return 200, {"done": True, "response": self.resp}
            return 200, {"id": "iopselftest00000000"}

    for label, resp, must_fail in (
            ("операция 200 с ответом БЕЗ ключа — находка", {"clientId": "c1"}, True),
            ("тот же 200 с полным ответом — молчит",
             {"clientId": "c1", "privateKeyPem": "pem", "keyId": "c1"}, False)):
        fake = _Fake(resp)
        try:
            out = post_operation(fake, "https://x", "t", "/p", {}, "проба")
            key_material(out, "проба")
            failed = False
        except Finding:
            failed = True
        _c(label, failed == must_fail,
           f"ожидалось падение={must_fail}, получено={failed}")

    # Ось 4: два имени в ответе выдачи — находка (обмен невозможен ни при каком входе).
    try:
        key_material({"clientId": "one", "privateKeyPem": "pem", "keyId": "two"}, "проба")
        _c("clientId != keyId — находка", False, "прошло молча")
    except Finding:
        _c("clientId != keyId — находка", True)

    # Ось 5: непустой перечень выдач у «чистого» субъекта — находка;
    # пустой — молчит. Один факт против близнеца.
    class _Bindings:
        def __init__(self, items):
            self.items = items

        def json_ask(self, url, **kw):
            return 200, {"accessBindings": self.items}

    for label, items, must_fail in (
            ("у «чистого» субъекта есть выдача — находка", [{"id": "ab1"}], True),
            ("у «чистого» субъекта выдач нет — молчит", [], False)):
        try:
            assert_no_bindings(_Bindings(items), "https://x", "t", "svaX")
            failed = False
        except Finding:
            failed = True
        _c(label, failed == must_fail, f"ожидалось={must_fail}, получено={failed}")

    # Ось 6: запись окружения ДОБАВЛЯЕТ ключ, которого в шаблоне нет.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="seed-selftest-") as td:
        tmp = pathlib.Path(td)
        tmpl = tmp / "t.json"
        tmpl.write_text(json.dumps({"values": [{"key": "jwtSAA", "value": ""}]}),
                        encoding="utf-8")
        envf = tmp / "e.json"
        replaced = write_env({"jwtSAA": "x", "ownRestBaseUrl": "https://y"},
                             envf, tmpl)
        doc = json.loads(envf.read_text(encoding="utf-8"))
        got = {v["key"]: v["value"] for v in doc["values"]}
        _c("запись заменяет известный ключ и ДОБАВЛЯЕТ неизвестный",
           replaced == 1 and got == {"jwtSAA": "x", "ownRestBaseUrl": "https://y"},
           f"заменено {replaced}, получено {got}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}",
              file=sys.stderr)
        return 1
    print("ДОКАЗАНО: объявление ключей сходится с записью в обе стороны, "
          "«нет слушателя» отличимо от находки КОДОМ и ТЕКСТОМ, успешный статус "
          "с пустым захватом роняет посев, а законный близнец рядом молчит.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--pki", default=str(ROOT / ".stand" / "pki"))
    ap.add_argument("--port-public", type=int, default=9098)
    ap.add_argument("--port-internal", type=int, default=9099)
    ap.add_argument("--port-hooks", type=int, default=9092)
    ap.add_argument("--port-token", type=int, default=9096)
    ap.add_argument("--port-grpc", type=int, default=9091)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--env-file",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.json"))
    ap.add_argument("--env-template",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.template.json"))
    ap.add_argument("--minted-keys", action="store_true",
                    help="напечатать ключи окружения, которые пишет этот посев, "
                         "по одному в строке, и выйти")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.minted_keys:
        for k in minted_keys():
            print(k)
        return 0
    if args.self_test:
        return self_test()
    try:
        return run(args)
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}", file=sys.stderr)
        print("Посев не состоялся по причине, не относящейся к дереву: "
              "вердикта о продукте нет НИ ОДНОГО.", file=sys.stderr)
        return RC_UNMET
    except Finding as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
