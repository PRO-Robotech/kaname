#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""МАШИННЫЙ ПОСЕВ для АВТОНОМНОГО стенда службы: удостоверения своей чеканки.

ПРЕДМЕТ. На автономном стенде нет ни края платформы, ни внешнего поставщика
личности. Сквозной набор при этом читает из окружения предъявителей, адреса и
идентификаторы субъектов, и пока их не пишет никто, коллекция
`kaname-own-rest-front` — та единственная, чья поверхность принадлежит САМОЙ
службе, — не гоняется ни разу. Это не «нет покрытия», а покрытие ОБЪЯВЛЕННОЕ И
НЕИСПОЛНИМОЕ.

ЧТО ЗДЕСЬ ЧЕКАНИТСЯ И ЧЕГО ЗДЕСЬ НЕ ЧЕКАНИТСЯ — СКАЗАНО ЧИСЛОМ. Посев пишет 23
ключа окружения: восемь предъявителей, одно удостоверение в ЗАКОННО-ДЕФЕКТНОМ
состоянии (отозванное), три адреса собственных поверхностей и одиннадцать
идентификаторов, которые вернул продукт. Не чеканится ничего из трёх других
природ, и каждая названа отказом, а не обойдена:

  · ЦЕРЕМОНИЯ ЧЕЛОВЕКА — `jwtHuman*`, `ceremony*` и идентификаторы человека
    церемонии (`humanAcc*UserId`). Полоса личности `own` не поднимается вовсе
    (врезка в `.github/scripts/stand-own.sh`), а машинно выпущенный токен человека
    приезжает с ПУСТЫМ уровнем подтверждения при пороге `required_acr_min>=1` —
    и поднять его нечем: `acr` приходит только из сессии поставщика, службой он
    лишь читается. То же и про `*StepUp`: набор сам объявляет их неподделываемыми;
  · АДРЕС НЕДОСТИЖИМОГО СОСЕДА — `providerPublicBaseUrl`: внешнего поставщика на
    этом стенде нет ВООБЩЕ, и адрес, назначенный на собственный слушатель, был бы
    ложью о том, чей ответ проверяется;
  · ИСТЁКШЕЕ и ПОВРЕЖДЁННОЕ удостоверения — причины у самого шага отзыва ниже.

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
от находки КОДОМ, что успешный статус с пустым захватом даёт находку, что
объявленный перечень записываемых ключей сходится с тем, что запись действительно
производит (в обе стороны), что `--minted-surface` отвечает ровно одной строкой,
что 401 `invalid_hook_token` — код 75, а не находка, при живом законном близнеце
рядом (409 от того же хука обязан остаться находкой), что ни одна объявленная пара
«идентификатор ↔ предъявитель» не покрыта ПОЛОВИНОЙ, что фронт, который после
отзыва всё ещё принимает предъявителя, даёт находку, и что пустой набор ключей
собственной чеканки даёт находку.
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

# АВТОРИТЕТ ПАР «идентификатор ↔ предъявитель» лежит РЯДОМ и ничего не сеет
# (`paginated_binding_reads_test.py`, `_AUTHORITY_ONLY`). Импорт по каталогу файла,
# а не по пакету: каталог фикстур пакетом не является, и посев зовётся из разных
# рабочих каталогов. Модуль не трогает ни сети, ни файла, ни часов — это условие
# его собственной шапки, и потому его можно звать и в самопроверке.
sys.path.insert(0, str(HERE))
import principal_pairings  # noqa: E402

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

# Путь набора ключей СОБСТВЕННОЙ чеканки на слушателе :9097. Дефолт посадки —
# `authn.token-signing.key-set-path` (`internal/apps/kaname/config/token_signing.go`).
# Зеркало прежнего издателя (`/.well-known/jwks.json`) лежит на том же слушателе и
# на автономном стенде отвечать не может: поставщика нет ВООБЩЕ.
OWN_JWKS_PATH = "/.well-known/kaname/jwks.json"

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
    "jwtBootstrap",
    "jwtInvitee",
    "jwtProjectAdminA1",
    "jwtPureNoBindings",
    "jwtSAA",
    "jwtSANoGrant",
)
# Удостоверение в ЗАКОННО-ДЕФЕКТНОМ состоянии. Названо отдельной группой, потому
# что у него ДВА утверждения вместо одного: выпущенное настоящим глаголом принято
# фронтом ДО приведения в состояние и отвергнуто ПОСЛЕ. Одного «отозвали» мало —
# отозванное удостоверение, которое фронт всё ещё принимает, не отозвано.
MINTED_DEFECTIVE = (
    "apiTokenRevoked",
)
# Адреса собственных фронтов: их производит САМ стенд, и удостоверениями они не
# являются. Названы отдельной группой намеренно — перепись долга считала все
# шесть пустых ключей «удостоверениями», и два из шести ими не были никогда.
MINTED_ADDRESSES = (
    "ownRestBaseUrl",
    "ownInternalRestBaseUrl",
    "iamJwksBaseUrl",
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
    "projectA1Id",
    "svaAId",
    "svaInviteeId",
    "svaNoGrantId",
    "svaPureNoGrantId",
    "runId",
)


# ПОВЕРХНОСТЬ, ДЛЯ КОТОРОЙ ЭТОТ ПОСЕВ КУЁТ. Величина выдаётся флагом
# `--minted-surface`, и перепись долга зачитывает ключи ТОЛЬКО коллекциям этой
# поверхности.
#
# ПОЧЕМУ НЕДОСТАТОЧНО ПЕРЕЧНЯ ИМЁН — ЗАМЕРЕНО. Учёт по одним именам снял
# препятствие машинного посева у ВОСЬМИ коллекций, и СЕМЬ из восьми —
# коллекции КРАЯ платформы: их `jwtAccountAdminA`/`jwtAccountAdminB` производит
# чужой посев чужого стенда, а совпало только ИМЯ ключа. Предъявитель этой чеканки
# краю не годится ничем: другой издатель, другой адресат, другой арендатор.
#
# Строка сверяется с тем, что перепись выводит из коллекции (`surface_of` в
# `.github/scripts/newman-suite-debt.py`). Расхождение — не молчаливое: посев с
# неизвестной поверхностью не зачитывается НИКОМУ, и держатель согласованности
# (`tests/newman/scripts/pipeline_claims_test.py`) краснеет, потому что конвейер
# гоняет коллекцию, которую перепись при этом считает заблокированной.
MINTED_SURFACE = "служба (собственный REST-фронт)"


def minted_keys() -> tuple[str, ...]:
    return (MINTED_ADDRESSES + MINTED_CREDENTIALS + MINTED_DEFECTIVE
            + MINTED_IDENTIFIERS)


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
    # 401 `invalid_hook_token` — УСЛОВИЕ НЕ СОЗДАНО, а НЕ находка, и это следует
    # из устройства продукта, а не из снисходительности.
    #
    # `writeHookAuthRefusal` — единственный производитель этого отказа, и он
    # отвечает ПОБАЙТОВО ОДИНАКОВО на «заголовка нет» и на «величина не та»:
    # различимый снаружи отказ был бы ОРАКУЛОМ по стерегомому секрету. Значит из
    # 401 вердикт о дереве НЕ ВЫВОДИМ ни при каком чтении ответа: он говорит ровно
    # то, что секрет посева и секрет посадки — две копии одной величины — разошлись
    # либо заголовок не дошёл. И то и другое — несозданное условие.
    #
    # Цена прежнего чтения: конвейер на rc≠75 печатал «Посев отвергнут продуктом»
    # и посылал читателя чинить рубеж хука, который работал правильно.
    if code == 401 and "invalid_hook_token" in text:
        raise Unmet(
            f"хук провизии отверг секрет ({HOOK_HEADER}): 401 invalid_hook_token. "
            f"Отказ ЕДИН намеренно — «заголовка нет» и «величина не та» побайтово "
            f"одинаковы, чтобы не давать оракула по секрету, — поэтому вердикта о "
            f"дереве из него нет НИ ОДНОГО. Сверьте KANAME_HOOK_TOKEN у посева и у "
            f"посадки: это ДВЕ копии одной величины")
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


def grant_role(http: Http, public: str, token: str, sva_id: str, role_id: str,
               scope_type: str, scope_id: str) -> str:
    """Выдача: служебная учётка получает роль на НАЗВАННОЙ области.

    ОБЛАСТЬ — ПАРАМЕТР, А НЕ ЛИТЕРАЛ, и это не обобщение ради обобщения: словарь
    якорей ровно трёхчленный (`iam.cluster` · `iam.account` · `iam.project`,
    `internal/domain/access_binding_scope.go`), и посев заводит субъектов и на
    аккаунте, и на проекте. Вторая копия этой функции с другим литералом
    разошлась бы с первой молча — в утверждении о статусе, например.

    Отказ ГРОМКИЙ. Посев без выдачи готовит субъекта БЕЗ ПРАВА, и всякое
    утверждение о доступе после этого проверяет не продукт, а собственную
    поломку: отказ придёт там, где кейс ждёт ответа, и виновником назовут
    невиновного.
    """
    resp = post_operation(
        http, public, token, "/iam/v1/accessBindings",
        {"subjectType": "service_account", "subjectId": sva_id,
         "roleId": role_id, "scopeType": scope_type, "scopeId": scope_id,
         "target": {"allInScope": {}}},
        f"выдача роли {role_id} учётке {sva_id} на {scope_type}:{scope_id}")
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



def assert_refused(http: Http, public: str, token: str, path: str,
                   what: str) -> None:
    """Фронт обязан ОТВЕРГНУТЬ этого предъявителя на этом пути.

    Утверждение об отказе стоит рядом с утверждением о доступе и по той же
    причине. Выдача, оказавшаяся ШИРЕ объявленной, готовит субъекта, на котором
    отрицательный кейс зеленеет по неверной причине: он ждёт отказа, а получил бы
    его и от опечатки в пути. Различает их только пара «здесь принят — там
    отвергнут», и обе половины утверждаются.
    """
    code, body = http.json_ask(public + path, token=token)
    if code == 200:
        raise Finding(
            f"{what}: фронт ОТВЕТИЛ 200 на {path}, а выдача этого не давала — "
            f"значит область выдачи шире объявленной: "
            f"{json.dumps(body, ensure_ascii=False)[:300]}")


def await_refusal(http: Http, public: str, token: str, path: str, what: str,
                  budget_s: float = 90.0) -> None:
    """ДОЖДАТЬСЯ отказа фронта — доказательство, что состояние ДОСТИГНУТО.

    ЖДЁТ, а не спрашивает раз, и это свойство посадки, а не осторожность:
    `authn.presented-credential.revocation-cache-ttl` объявлен 30 с
    (`.github/scripts/stand-own.sh`), поэтому отзыв доходит до читателя
    предъявленного удостоверения не мгновенно. Единственный ответ «ещё принимает»
    неотличим от «принимать не перестанет», поэтому ожидание идёт до ПРЕДМЕТА.

    Исчерпанный бюджет — НАХОДКА, а не несозданное условие: удостоверение выпущено
    настоящим глаголом, отозвано настоящим глаголом, и то, что фронт его всё ещё
    принимает, есть вердикт о дереве.
    """
    deadline = time.time() + budget_s
    last_code, last_body = None, {}
    while True:
        last_code, last_body = http.json_ask(public + path, token=token)
        if last_code != 200:
            return
        if time.time() >= deadline:
            break
        time.sleep(1)
    raise Finding(
        f"{what}: фронт ПРИНИМАЕТ предъявителя спустя {budget_s:.0f} с после "
        f"приведения в дефектное состояние (код {last_code} на {path}, тело "
        f"{json.dumps(last_body, ensure_ascii=False)[:200]}). Кэш отзыва посадки — "
        f"30 с, то есть бюджет исчерпан с запасом: состояние НЕ ДОСТИГНУТО, а "
        f"кейс про отозванное удостоверение зеленел бы на живом токене")


def assert_own_jwks(http: Http, jwks_base: str) -> dict:
    """Набор ключей СВОЕЙ чеканки не пуст — и это утверждается, а не адресуется.

    Адрес, за которым лежит ПУСТОЙ перечень, от ненаписанного адреса не отличается
    ничем: сверяющий подпись сосед получит 200 и не найдёт ключа, то есть отказ
    приедет как «подпись не сверяется», а не как «ключей нет».

    ПУТЬ — НАШ, А НЕ ЗЕРКАЛО. На слушателе :9097 их два: зеркало прежнего издателя
    (`/.well-known/jwks.json`) и набор собственной чеканки
    (`authn.token-signing.key-set-path`, по умолчанию
    `/.well-known/kaname/jwks.json`). На автономном стенде внешнего поставщика нет
    ВООБЩЕ, поэтому зеркало отвечать не может by construction, а собственный набор
    обязан: своя чеканка на этой посадке включена, и ею подписаны все
    предъявители, которые посев выдаёт.
    """
    code, body = http.json_ask(jwks_base + OWN_JWKS_PATH)
    keys = body.get("keys") if isinstance(body, dict) else None
    if code != 200 or not isinstance(keys, list) or not keys:
        raise Finding(
            f"набор ключей собственной чеканки не отдан: код {code}, ключей "
            f"{len(keys) if isinstance(keys, list) else 'нет поля'} на "
            f"{jwks_base}{OWN_JWKS_PATH}. Служба — ЕДИНСТВЕННЫЙ фасад к поставщику, "
            f"и подписи её предъявителей сверять нечем: "
            f"{json.dumps(body, ensure_ascii=False)[:200]}")
    return body


def assert_binding_scopes(http: Http, public: str, token: str, subject_id: str,
                          want: set[tuple[str, str]]) -> None:
    """У субъекта РОВНО названные области выдач — спрошено у продукта.

    Утверждается перечень, а не число: субъект, у которого две выдачи, но обе в
    домашнем аккаунте, от объявленного отличается ровно тем свойством, ради
    которого он и заводится, — и по счёту это не видно.
    """
    code, body = http.json_ask(
        f"{public}/iam/v1/accessBindings:listBySubject"
        f"?subjectType=service_account&subjectId={subject_id}&pageSize=100",
        token=token)
    if code != 200:
        raise Finding(f"выдачи субъекта {subject_id} не читаются: код {code}, "
                      f"тело {json.dumps(body, ensure_ascii=False)[:200]}")
    got = {(b.get("scopeType") or "", b.get("scopeId") or "")
           for b in (body.get("accessBindings") or [])}
    if got != want:
        raise Finding(
            f"субъект {subject_id} заведён с выдачами {sorted(want)}, а продукт "
            f"вернул {sorted(got)} — кейсы про сужение страницы по ДОМАШНЕМУ "
            f"аккаунту проверяли бы другую форму субъекта")


def revoke_sa_key(http: Http, public: str, token: str, sva_id: str,
                  key_id: str) -> None:
    """Отзыв ключа — настоящим глаголом службы (`SAKeyService/Revoke`).

    Отзыв идемпотентен НАМЕРЕННО: чужой и несуществующий ключ дают тот же успех,
    чтобы не давать оракула по чужим ключам. Значит из успеха отзыва СОСТОЯНИЕ НЕ
    ВЫВОДИМО — его доказывает только отказ фронта, и он утверждается отдельно.
    """
    code, resp = http.json_ask(
        f"{public}/iam/v1/serviceAccounts/{sva_id}/keys/{key_id}",
        method="DELETE", token=token)
    if code != 200:
        raise Finding(f"отзыв ключа {key_id} учётки {sva_id} отказал: код {code}, "
                      f"тело {json.dumps(resp, ensure_ascii=False)[:300]}")
    op_id = resp.get("id") or ""
    if op_id:
        await_operation(http, public, token, op_id)


def revoked_sa_token(http: Http, public: str, token_url: str, token: str,
                     sva_id: str, run_id: str) -> str:
    """Удостоверение в состоянии ОТОЗВАНО — заведённое настоящим путём.

    ТРИ ШАГА, И НИ ОДИН НЕ ЛИШНИЙ: выпуск ключа, обмен в предъявителя, отзыв
    ключа, — а между вторым и третьим утверждение, что фронт его ПРИНИМАЛ. Без
    этого утверждения отказ после отзыва неотличим от отказа по любой другой
    причине (негодный обмен, неверный адресат, опечатка в пути), и кейс про
    отозванное удостоверение проверял бы что угодно.
    """
    resp = post_operation(
        http, public, token, f"/iam/v1/serviceAccounts/{sva_id}/keys",
        {"description": f"посев автономного стенда, под отзыв, прогон {run_id}"},
        "выпуск ключа под отзыв")
    client_id, key_pem, key_id = key_material(resp, "ключ под отзыв")
    access = exchange(http, token_url, client_id, key_pem, key_id,
                      "удостоверение под отзыв")
    assert_serves(http, public, access, "/iam/v1/me",
                  "удостоверение ДО отзыва (иначе отказ после ничего не значит)")
    revoke_sa_key(http, public, token, sva_id, key_id)
    await_refusal(http, public, access, "/iam/v1/me",
                  "удостоверение ПОСЛЕ отзыва")
    return access


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
    jwks_base = f"https://{host}:{args.port_jwks}"

    # Признак прогона: он уезжает в ИМЕНА заводимых предметов, поэтому повторный
    # прогон не встречает 409 — и заодно по нему видно, какой прогон что завёл.
    run_id = args.run_id or f"s{secrets.token_hex(4)}"

    for port, what in ((args.port_public, "собственный публичный REST"),
                       (args.port_internal, "собственный внутренний REST"),
                       (args.port_hooks, "хуки поставщика"),
                       (args.port_token, "выдача токенов"),
                       (args.port_jwks, "публикатор набора ключей"),
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
        grant_role(http, public, boot, sva, role_admin, "iam.account", account_id)
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

    say("── бутстрап-предъявитель: тот, кем посев и работал всё это время ─────")
    #
    # ПОЧЕМУ ОН ЗАПИСЫВАЕТСЯ, А НЕ ВЫБРАСЫВАЕТСЯ. Посев чеканил его настоящим
    # глаголом на первом шаге и там же УТВЕРДИЛ, что собственный фронт его
    # принимает (200 на перечне аккаунтов), — то есть самое доказанное
    # удостоверение всего прогона уезжало в мусор, а ключ окружения того же
    # предмета стоял пустым. Своего шага здесь нет намеренно: второй выпуск дал бы
    # ВТОРОЕ удостоверение, и утверждение первого шага относилось бы не к нему.
    creds["jwtBootstrap"] = boot
    step("jwtBootstrap — удостоверение шага 1, уже предъявленное фронту")

    say("── набор ключей: его публикует САМА служба, поставщика нет ВООБЩЕ ─────")
    jwks = assert_own_jwks(http, jwks_base)
    step(f"собственный набор ключей отдан и НЕ ПУСТ: ключей "
         f"{len(jwks.get('keys', []))} на {jwks_base}{OWN_JWKS_PATH}")

    say("── вторая учётка БЕЗ выдач: своя у каждого объявленного слота ─────────")
    #
    # ПОЧЕМУ ВТОРАЯ, А НЕ ПЕРЕИСПОЛЬЗОВАНИЕ ПЕРВОЙ. Набор объявляет ДВА слота
    # «никогда не грантится», и у них разные владельцы:
    # `svaPureNoGrantId`/`jwtPureNoBindings` — выделенный субъект leak-guard'ов
    # (шапка `cases/iam-subject-privileges-read.py`: «никогда не грантится»), а
    # `svaNoGrantId`/`jwtSANoGrant` — непривилегированная учётка набора
    # эквивалентности каналов. Один субъект на два слота сделал бы свойство
    # «никогда не грантится» ЗАВИСИМЫМ от того, что делает соседний набор.
    sva_nogrant = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                       f"seed-{run_id}-nogrant", run_id,
                                       "создание учётки без выдач (слот канала)")
    assert_no_bindings(http, public, boot, sva_nogrant)
    step(f"учётка без выдач (слот канала) заведена, перечень выдач ПУСТ: "
         f"{sva_nogrant}")
    creds["jwtSANoGrant"] = sa_token(http, public, token_url, boot, sva_nogrant,
                                     run_id, "учётка без выдач (слот канала)")
    assert_serves(http, public, creds["jwtSANoGrant"], "/iam/v1/me",
                  "jwtSANoGrant (рубеж проходит, права не имеет)")
    step("jwtSANoGrant получен обменом и ПРИНЯТ рубежом")

    say("── распорядитель ПРОЕКТА: допуск в проекте есть, на аккаунте НЕТ ──────")
    #
    # ОБЕ ПОЛОВИНЫ УТВЕРЖДАЮТСЯ. Кейсы про него (`AUTHZ-ACCT-GT-OWN-PA1` и
    # соседние) ждут ОТКАЗА на аккаунте — то есть проверяют ровно то, что выдача
    # проектная, а не аккаунтная. Субъект, которому выдали шире, оставил бы их
    # зелёными по неверной причине: 403 они ждут и получили бы его от чего угодно.
    role_prj_admin = builtin_role_id(http, public, boot, "iam.project.admin")
    step(f"встроенная роль iam.project.admin спрошена у продукта: {role_prj_admin}")
    sva_pa1 = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                   f"seed-{run_id}-pa1", run_id,
                                   "создание распорядителя проекта A1")
    grant_role(http, public, boot, sva_pa1, role_prj_admin, "iam.project",
               tenants["a"]["projectId"])
    step(f"распорядитель проекта A1 заведён и получил роль на проекте: {sva_pa1}")
    creds["jwtProjectAdminA1"] = sa_token(http, public, token_url, boot, sva_pa1,
                                          run_id, "распорядитель проекта A1")
    assert_serves(http, public, creds["jwtProjectAdminA1"],
                  f"/iam/v1/projects/{tenants['a']['projectId']}",
                  "jwtProjectAdminA1 (читает СВОЙ проект)")
    assert_refused(http, public, creds["jwtProjectAdminA1"],
                   f"/iam/v1/accounts/{tenants['a']['accountId']}",
                   "jwtProjectAdminA1 (аккаунт ему НЕ выдавали)")
    step("jwtProjectAdminA1 принят на своём проекте и ОТВЕРГНУТ на аккаунте")

    say("── субъект с выдачами в ДВУХ аккаунтах: домашний A, чужой B ───────────")
    #
    # ФОРМА ОБЪЯВЛЕНА НАБОРОМ, А НЕ ВЫБРАНА ЗДЕСЬ. Шапка
    # `cases/iam-subject-privileges-read.py` называет её дословно: служебная
    # учётка, домашний аккаунт которой — A, а выдачи лежат в ДВУХ аккаунтах —
    # `edit` на проекте A1 (внутри A) и `admin` на АККАУНТЕ B (снаружи). Ради неё
    # сужение страницы и заведено: допуск решается по ДОМАШНЕМУ аккаунту, а строки
    # называют область каждой выдачи.
    #
    # ОТКАЗ ПРОДУКТА НА ВЫДАЧЕ В ЧУЖОМ АККАУНТЕ БУДЕТ НАХОДКОЙ, И ЭТО СКАЗАНО
    # ПРЯМО: посев предъявляет бутстрап-удостоверение, которому открыто дерево, и
    # форму, которую набор объявляет своей фикстурой. Если такая выдача не
    # создаётся, расходятся набор и продукт — вердикт о дереве, а не о посеве.
    role_prj_edit = builtin_role_id(http, public, boot, "iam.project.edit")
    step(f"встроенная роль iam.project.edit спрошена у продукта: {role_prj_edit}")
    sva_inv = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                   f"seed-{run_id}-inv", run_id,
                                   "создание субъекта с выдачами в двух аккаунтах")
    grant_role(http, public, boot, sva_inv, role_prj_edit, "iam.project",
               tenants["a"]["projectId"])
    grant_role(http, public, boot, sva_inv, role_admin, "iam.account",
               tenants["b"]["accountId"])
    assert_binding_scopes(http, public, boot, sva_inv, {
        ("iam.project", tenants["a"]["projectId"]),
        ("iam.account", tenants["b"]["accountId"])})
    step(f"субъект заведён, и продукт вернул РОВНО две области выдач: {sva_inv}")
    creds["jwtInvitee"] = sa_token(http, public, token_url, boot, sva_inv, run_id,
                                   "субъект с выдачами в двух аккаунтах")
    assert_serves(http, public, creds["jwtInvitee"],
                  f"/iam/v1/projects/{tenants['a']['projectId']}",
                  "jwtInvitee (читает проект своей выдачи)")
    step("jwtInvitee получен обменом и ПРИНЯТ на проекте своей выдачи")

    say("── ОТОЗВАННОЕ удостоверение: принято ДО отзыва, отвергнуто ПОСЛЕ ──────")
    #
    # ЕДИНСТВЕННОЕ ДЕФЕКТНОЕ СОСТОЯНИЕ, КОТОРОЕ ЭТОТ СТЕНД ДОКАЗЫВАЕТ, И ОСТАЛЬНЫЕ
    # НАЗВАНЫ ОТКАЗОМ, А НЕ ОБОЙДЕНЫ:
    #
    #   · ИСТЁКШЕЕ — `IssueSAKeyRequest.ttl_seconds` принимает только `>= 0`
    #     (`internal/apps/kaname/api/sa_keys/usecases.go`, отказ
    #     «ttl_seconds must be >= 0»), абсолютного `expires_at` в запросе нет, а
    #     срок САМОГО предъявителя назначает издатель. Значит истёкшего
    #     предъявителя настоящим глаголом не родить, а подписать его самим —
    #     подделка, которую кейс и проверил бы;
    #   · ПОВРЕЖДЁННОЕ — по определению не выпускается никем: «не JWS, 2 сегмента»
    #     (шапка `cases/authz-sa-apitoken.py`). Это ВХОД, а не удостоверение, и
    #     производителя у него нет — ни у посева, ни у службы;
    #   · ГОДНОЕ В ОБЛАСТИ (`apiTokenValid`) — объявлено как «in-scope vpc.* на
    #     проекте A1». Выдачу такой формы iam создаёт, а УПРАЖНЯТЬ её здесь нечем:
    #     соседа vpc на автономном стенде нет, и предъявитель, чьё свойство ни один
    #     шаг не трогает, доказан ровно наполовину.
    sva_rvk = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                   f"seed-{run_id}-rvk", run_id,
                                   "создание учётки под отзыв удостоверения")
    step(f"учётка под отзыв заведена (своя, чтобы отзыв не задел соседей): "
         f"{sva_rvk}")
    creds["apiTokenRevoked"] = revoked_sa_token(http, public, token_url, boot,
                                                sva_rvk, run_id)
    step("apiTokenRevoked: принят фронтом ДО отзыва и ОТВЕРГНУТ после — "
         "состояние достигнуто, а не объявлено")

    fixtures = {
        "ownRestBaseUrl": public,
        "ownInternalRestBaseUrl": internal,
        "accountAId": tenants["a"]["accountId"],
        "accountBId": tenants["b"]["accountId"],
        "existingAccountId": tenants["a"]["accountId"],
        "existingProjectId": tenants["a"]["projectId"],
        "existingProjectCrossId": tenants["b"]["projectId"],
        "iamJwksBaseUrl": jwks_base,
        "projectA1Id": tenants["a"]["projectId"],
        "svaAId": sva_a,
        "svaInviteeId": sva_inv,
        "svaNoGrantId": sva_nogrant,
        "svaPureNoGrantId": sva_pure,
        "runId": run_id,
        **creds,
    }
    # ОБЪЯВЛЕННЫЕ ПАРЫ ПРОВЕРЯЮТСЯ ЗДЕСЬ — В ЕДИНСТВЕННОМ МЕСТЕ, ГДЕ ФИКСТУРЫ
    # СУЩЕСТВУЮТ. `principal_pairings` объявляет данными, чей идентификатор
    # аутентифицирует какой предъявитель, и до этой правки его `unpaired_principals`
    # не звал НИКТО: проверка без вызывающего от ненаписанной не отличается ничем.
    # Вердикт при этом читается из САМОГО предъявителя — из claim
    # `kaname_principal_id`, который кладёт наш издатель, — а не из того, что посев
    # о нём думает.
    broken = principal_pairings.unpaired_principals(fixtures)
    if broken:
        raise Finding(
            "объявленные пары «идентификатор ↔ предъявитель» НЕ ДЕРЖАТСЯ: "
            + "; ".join(broken)
            + ". Набор привязывает роль к идентификатору и читает под "
              "предъявителем, поэтому расхождение здесь приезжает в кейс "
              "таймаутом на шесть шагов позже причины")
    covered = sum(1 for i, t in principal_pairings.PRINCIPAL_PAIRINGS.items()
                  if i in fixtures and t in fixtures)
    step(f"объявленные пары проверены по claim предъявителя: покрыто этим посевом "
         f"{covered} из {len(principal_pairings.PRINCIPAL_PAIRINGS)}, расхождений нет")
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

    # Ось 1б: ПОСЕВ ОБЪЯВЛЯЕТ ПОВЕРХНОСТЬ, ДЛЯ КОТОРОЙ КУЁТ.
    #
    # Перечня ключей НЕДОСТАТОЧНО, и это замер: восемь коллекций потеряли
    # препятствие машинного посева от одного этого посева, и СЕМЬ из восьми
    # — коллекции КРАЯ платформы, чьих предъявителей производит чужой посев чужого
    # стенда. Совпало только ИМЯ ключа. Поэтому посев называет и поверхность, а
    # перепись зачитывает его ключи ТОЛЬКО коллекциям этой поверхности.
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--minted-surface"],
        capture_output=True, text=True, timeout=60)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    _c("`--minted-surface` отвечает кодом 0 и ровно одной непустой строкой",
       proc.returncode == 0 and len(lines) == 1,
       f"код {proc.returncode}, строк {len(lines)}: {lines!r} "
       f"{(proc.stderr or '')[-200:]!r}")
    _c("и названная поверхность — собственный фронт службы, а не край платформы",
       bool(lines) and lines[0] == MINTED_SURFACE,
       f"объявлено {lines[0] if lines else None!r}, ожидалось {MINTED_SURFACE!r}")

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

    # Ось 2б: РАСХОЖДЕНИЕ СЕКРЕТА ХУКА — «условие не создано», а НЕ находка.
    #
    # Отказ хука един намеренно: `writeHookAuthRefusal` отвечает побайтово
    # одинаково и на «заголовка нет», и на «величина не та» — различимый снаружи
    # отказ был бы ОРАКУЛОМ по стерегомому секрету. Отсюда следствие для посева:
    # из 401 `invalid_hook_token` вердикт о дереве НЕ ВЫВОДИМ ни при каком чтении.
    # Он означает ровно то, что секрет посева и секрет посадки — две копии одной
    # величины — разошлись; это код 75, и конвейер обязан прочесть его как «нет
    # вердикта», а не как дефект продукта.
    #
    # Законный близнец рядом и отличается ОДНИМ фактом: тот же не-200, но отказ НЕ
    # про аутентификацию хука — это находка, и она обязана остаться находкой.
    class _Hook:
        def __init__(self, code, text):
            self.code, self.text = code, text

        def ask(self, url, **kw):
            return self.code, self.text

    for label, code, text, want in (
            ("401 invalid_hook_token — УСЛОВИЕ НЕ СОЗДАНО (75), а не находка",
             401, '{"error":"invalid_hook_token"}', Unmet),
            ("500 hook_secret_not_configured — тоже условие не создано",
             500, '{"error":"hook_secret_not_configured"}', Unmet),
            ("409 при живом хуке — НАХОДКА (вердикт о дереве)",
             409, '{"error":"user_already_exists"}', Finding),
            ("200 — молчит", 200, "{}", None)):
        try:
            provision_identity(_Hook(code, text), "https://h", "s", "who@x")
            got = None
        except Unmet:
            got = Unmet
        except Finding:
            got = Finding
        _c(label, got is want,
           f"ожидалось {want.__name__ if want else 'молчание'}, "
           f"получено {got.__name__ if got else 'молчание'}")

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

    # ── Ось 7: ОБЪЯВЛЕННАЯ ПАРА «ИДЕНТИФИКАТОР ↔ ПРЕДЪЯВИТЕЛЬ» ДЕРЖИТСЯ ────
    #
    # ПРЕДМЕТ. `tests/authz-fixtures/principal_pairings.py` объявляет ДАННЫМИ, чей
    # идентификатор аутентифицирует какой предъявитель, и его собственная шапка
    # называет цену несоблюдения: набор привязывает роль к `{{<id>}}`, читает под
    # `{{<token>}}`, и при расхождении отказ неотличим от «выдача ещё не
    # материализовалась» — то есть приезжает таймаутом, не там, где причина, и на
    # шесть шагов позже.
    #
    # ПОЧЕМУ ЭТО ОСЬ ПОСЕВА, А НЕ АВТОРИТЕТА. У `unpaired_principals` в этом
    # репозитории НЕТ НИ ОДНОГО вызывающего: `git grep -n unpaired_principals`
    # находит только объявление. Проверка, которую никто не зовёт, отличается от
    # ненаписанной ровно ничем, а единственное место, где фикстуры существуют, —
    # посев. Шапка кейсов при этом утверждает «и там же проверяется»
    # (`cases/iam-subject-privileges-read.py`) — то есть два места об одном
    # предмете, и верно одно.
    #
    # ПОЛОВИНА КАНАЛА — НАХОДКА, И ОНА В ДЕРЕВЕ СЕЙЧАС: посев пишет
    # `jwtPureNoBindings` и НЕ пишет `svaPureNoGrantId`, с которым тот объявлен в
    # паре. Это ровно та форма, из-за которой авторитет и написан.
    declared_pairs = principal_pairings.PRINCIPAL_PAIRINGS
    keys_declared = set(minted_keys())
    half = sorted(f"{i} ↔ {t}" for i, t in declared_pairs.items()
                  if (i in keys_declared) != (t in keys_declared))
    _c("ни одна объявленная пара не покрыта ПОЛОВИНОЙ", not half,
       f"половин {len(half)}: {', '.join(half)}")

    # Ось 7б: ВЕРДИКТ ПАРЫ НАСТОЯЩИЙ — инъекция в обе стороны на одном факте.
    # Предъявитель, назвавший ЧУЖОГО принципала, обязан дать находку; тот же
    # предъявитель, назвавший своего, обязан молчать.
    table = {"svaXId": "jwtX"}
    for label, claimed, must_break in (
            ("предъявитель называет ЧУЖОГО принципала — расхождение", "svaOther", True),
            ("тот же предъявитель называет своего — молчит", "svaXId-value", False)):
        got = principal_pairings.unpaired_principals(
            {"svaXId": "svaXId-value",
             "jwtX": principal_pairings.make_token(claimed)}, table)
        _c(label, bool(got) == must_break, f"получено {got}")

    # ── Ось 8: ДЕФЕКТНОЕ СОСТОЯНИЕ ДОКАЗАНО, А НЕ ОБЪЯВЛЕНО ──────────────────
    #
    # ПРЕДМЕТ. Отозванное удостоверение, у которого фронт по-прежнему принимает
    # предъявителя, — не отозванное. Кейс про него («[UNAUTH] … revoked token»)
    # тогда зеленеет на живом токене по неверной причине, и отличить это снаружи
    # нельзя: ответ 401 он и ждёт, а получил бы его от любой опечатки в пути.
    #
    # Отзыв на этой посадке доходит НЕ МГНОВЕННО: `presented-credential`
    # объявляет кэш отзыва 30 с (`stand-own.sh`), поэтому утверждение обязано
    # ЖДАТЬ отказа, а не спрашивать один раз. Ждать при этом до ПРЕДМЕТА:
    # единственный ответ «ещё принимает» неотличим от «принимать не перестанет».
    #
    # Инъекция в обе стороны на одном факте: фронт, который после отзыва отвечает
    # 200, обязан дать находку; тот же фронт с 401 — молчать.
    await_refusal = globals().get("await_refusal")
    if await_refusal is None:
        _c("отозванное удостоверение: отказ фронта ДОЖИДАЕТСЯ, а не объявляется",
           False, "в посеве нет шага, утверждающего отказ после отзыва — "
                  "предмета у оси не существует")
    else:
        class _Front:
            def __init__(self, code):
                self.code = code

            def json_ask(self, url, **kw):
                return self.code, {"error": "x"} if self.code != 200 else {"ok": 1}

        for label, code, must_fail in (
                ("после отзыва фронт всё ещё принимает — находка", 200, True),
                ("после отзыва фронт отвергает — молчит", 401, False)):
            try:
                await_refusal(_Front(code), "https://x", "t", "/iam/v1/me",
                              "проба", budget_s=0.5)
                failed = False
            except Finding:
                failed = True
            _c(label, failed == must_fail,
               f"ожидалось падение={must_fail}, получено={failed}")

    # ── Ось 9: НАБОР КЛЮЧЕЙ ПУБЛИКУЕТ САМА СЛУЖБА, И ОН НЕ ПУСТ ──────────────
    #
    # ПРЕДМЕТ. `iamJwksBaseUrl` — АДРЕС, а не удостоверение: его называет посадка.
    # Но адрес, за которым лежит ПУСТОЙ набор ключей, от ненаписанного адреса не
    # отличается ничем: проверяющий подпись сосед получит 200 и не найдёт ключа,
    # то есть отказ приедет как «подпись не сверяется», а не как «ключей нет».
    #
    # Инъекция в обе стороны на одном факте: пустой перечень — находка, непустой —
    # молчание.
    assert_own_jwks = globals().get("assert_own_jwks")
    if assert_own_jwks is None:
        _c("набор ключей собственной чеканки НЕ ПУСТ — утверждается", False,
           "в посеве нет шага, утверждающего набор ключей — предмета у оси нет")
    else:
        class _Jwks:
            def __init__(self, doc):
                self.doc = doc

            def json_ask(self, url, **kw):
                return 200, self.doc

        for label, doc, must_fail in (
                ("набор ключей ПУСТ — находка", {"keys": []}, True),
                ("набор ключей несёт ключ — молчит",
                 {"keys": [{"kty": "RSA", "kid": "k1"}]}, False)):
            try:
                assert_own_jwks(_Jwks(doc), "https://x")
                failed = False
            except Finding:
                failed = True
            _c(label, failed == must_fail,
               f"ожидалось падение={must_fail}, получено={failed}")

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
    ap.add_argument("--port-jwks", type=int, default=9097)
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
    ap.add_argument("--minted-surface", action="store_true",
                    help="напечатать ПОВЕРХНОСТЬ, для которой этот посев куёт, "
                         "и выйти: имя ключа совпадает через разные стенды, "
                         "а предъявитель не переносится")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.minted_keys:
        for k in minted_keys():
            print(k)
        return 0
    if args.minted_surface:
        print(MINTED_SURFACE)
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
