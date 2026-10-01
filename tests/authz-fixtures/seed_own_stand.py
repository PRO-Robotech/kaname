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

ЧТО ЗДЕСЬ ЧЕКАНИТСЯ И ЧЕГО ЗДЕСЬ НЕ ЧЕКАНИТСЯ. Посев пишет ключи окружения
четырёх природ: предъявителей, одно удостоверение в ЗАКОННО-ДЕФЕКТНОМ состоянии
(отозванное), адреса собственных поверхностей и идентификаторы, которые вернул
продукт. Число здесь не выписано — оно меняется с каждым ключом, а выписанное
расходилось с деревом: его печатает `--minted-keys | wc -l`. Не чеканится
ничего из двух других природ, и каждая названа отказом, а не обойдена (третья —
адрес публичного эндпоинта поставщика — снята вместе с сверкой зеркала набора
ключей, которая его читала, kaname#361):

  · ЦЕРЕМОНИЯ ЧЕЛОВЕКА — `jwtHuman*`, `ceremony*` и идентификаторы человека
    церемонии (`humanAcc*UserId`). Машинно выпущенный токен человека приезжает с
    ПУСТЫМ уровнем подтверждения при пороге `required_acr_min>=1`, а уровень
    приходит только из сессии входа. Их куёт посев церемонии
    (`seed_ceremony.py --wave`) входом человека через свою церемонию службы на
    этом же стенде; повышенный уровень человека (`jwtHuman*StepUp`) — вторым
    фактором. Слот повышенного уровня МАШИННОГО распорядителя
    (`jwtAccountAdminAStepUp`) — иное дело: у машины уровня нет, и слот несёт
    того же распорядителя (см. `MINTED_CREDENTIALS`);
  · ИСТЁКШЕЕ и ПОВРЕЖДЁННОЕ удостоверения — причины у самого шага отзыва ниже.

ВСЁ, ЧТО ЗДЕСЬ ДЕЛАЕТСЯ, ДЕЛАЕТСЯ ЕДИНСТВЕННЫМ ГЛАГОЛОМ ПРОДУКТА. Ни одной
записи в базу, ни одной подписи чужим ключом, ни одного обхода рубежа:

  1. чеканка бутстрап-удостоверения — `InternalBootstrapTokenService` на :9091,
     gRPC поверх взаимного TLS. Круг вызывающих задан ИМЕНАМИ сертификатов, и
     стенд предъявляет своё; REST-маршрута у этой чеканки нет нигде;
  2. регистрация человека — `POST /iam/v1/auth/register` на слушателе полосы
     входа :9100, признаком формы от `GET /iam/v1/auth/csrf`. Глагол заводит
     человека, его личный аккаунт, проект по умолчанию и выдачу владельца — то
     есть АРЕНДАТОРА. Адрес заведённого подтверждается тем же путём, что у
     человека (kaname#456): код из письма регистрации, которое служба сдала
     приёмнику писем стенда (`.github/scripts/stand-mailbox.py`), предъявляется
     `POST /iam/v1/auth/verify-email/confirm` под сессией регистрации — иначе
     выдачи на человека не действуют и раскрытие отношений его не называет;
  3. выпуск удостоверения субъекта — `UserTokenService/Issue` и
     `SAKeyService/Issue`. Приватный ключ показывается ОДИН раз;
  4. обмен — `POST /iam/v1/token` на :9096: подписанное утверждение клиента
     (RFC 7521/7523) у НАШЕГО издателя. Адресат утверждения — идентификатор
     издателя, а не адрес эндпоинта.

ПОЧЕМУ ВТОРОЙ ВХОД (ПОЛОСА ВХОДА) ЗАКОНЕН, И ГДЕ ЕГО ГРАНИЦА — СКАЗАНО ПРЯМО.
Аккаунт принадлежит ЧЕЛОВЕКУ by construction: `CreateAccount` от служебной
учётки отвергается синхронно («an Account is owned by a user; principal type is
service_account»). Под посадкой `own` — единственной у службы (kaname#424) —
человека заводит только полоса входа: хука поставщика нет (kaname#360), а gRPC
`UpsertFromIdentity` в боевой посадке доступен ТОЛЬКО учётной записи края.
Полоса допускает РОВНО край по SAN проверенного клиентского листа, края на
стенде нет, и его место у полосы занимает посев — листом с именем края,
выписанным УЦ стенда (`stand-own.sh`, `edge.crt`), как у стенда чарта. Граница:
лист края посев предъявляет ТОЛЬКО полосе входа, ни одной другой поверхности
службы; остальные шаги идут листом самой службы.

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
что отказ полосы входа (403 листу не края, регистрация без печенья сессии,
регистрация не 200) — находка, а 200 с печеньем — молчание, что подтверждение адреса
кодом письма регистрации молчит на законном мире и различает недошедшее письмо,
молчащий приёмник, отвергнутый код и 200 без отметки, что ни одна объявленная пара
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
try:
    import principal_pairings  # noqa: E402
except ImportError as e:
    # НЕПРОЧИТАННЫЙ АВТОРИТЕТ — «условие не создано», А НЕ ОТКАЗ ПРОДУКТА, и это
    # различие ценой одной строки. Непокрытый `import` уронил бы посев кодом 1, а
    # конвейер печатает на rc≠75 «Посев отвергнут продуктом» и посылает читателя
    # чинить службу, которая ни при чём: предмет отказа — рабочая копия.
    principal_pairings = None
    PAIRINGS_IMPORT_ERROR = str(e)
else:
    PAIRINGS_IMPORT_ERROR = ""


def require_pairings():
    """Авторитет пар или «условие не создано» с названной причиной."""
    if principal_pairings is None:
        raise Unmet(
            f"модуль-авторитет пар не прочитан ({PAIRINGS_IMPORT_ERROR}) — "
            f"объявленные пары «идентификатор ↔ предъявитель» проверить нечем, "
            f"и вердикта о продукте здесь нет НИ ОДНОГО")
    return principal_pairings

# Издатель и адресат стенда. Величины объявлены ОДИН раз и совпадают с посадкой
# (`.github/scripts/stand-own.sh`): расхождение здесь дало бы отказ обмена с
# текстом про несовпадение адресата, то есть находку о дереве на месте опечатки.
STAND_ISSUER = "https://kaname.local"

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Заголовочный `typ` утверждения. НАШ проверяющий его ТРЕБУЕТ: без него обмен
# отвергается до сверки подписи, и отказ выглядит как неверный клиент.
ASSERTION_TOKEN_TYPE = "client-authentication+jwt"

BOOTSTRAP_METHOD = (
    "kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken")
BOOTSTRAP_PROTO = "kaname/cloud/iam/v1/internal_bootstrap_token_service.proto"

# Путь набора ключей СОБСТВЕННОЙ чеканки на слушателе :9097. Дефолт посадки —
# `authn.token-signing.key-set-path` (`internal/apps/kaname/config/token_signing.go`).
# Запись у публикатора одна — эта: зеркало прежнего издателя по каноническому
# `/.well-known/jwks.json` снято вместе с ним (kaname#361).
OWN_JWKS_PATH = "/.well-known/kaname/jwks.json"

# Полоса входа: признак формы, регистрация и носители. Адрес источника — свой,
# отличный от посева стенда чарта и от набора: счёт частоты по источнику у
# каждого раздельный, и попытки посева не съедают окно прогона.
LANE_CSRF = "/iam/v1/auth/csrf"
LANE_REGISTER = "/iam/v1/auth/register"
LANE_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
LANE_SESSION_COOKIE = "kaname_session"
LANE_FORM_COOKIE = "kaname_form"
LANE_SOURCE = "203.0.113.12"

# Адрес чтения приёмника писем автономного стенда (`stand-own.sh`,
# `KANAME_STAND_MAIL_HTTP_PORT`, умолчание то же).
DEFAULT_MAILBOX_URL = "http://127.0.0.1:18025"

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
    # ТОТ ЖЕ предъявитель распорядителя аккаунта A — слот «повышенного уровня»
    # (kaname#398). Кейсы читают его как вариант ТОГО ЖЕ принципала: выпускают
    # под ним и опрашивают операцию под `jwtAccountAdminA`. Распорядитель здесь —
    # служебная учётка, а у машинного принципала уровня нет: общее правило
    # повышения (`grpcsrv.EvaluateStepUp`) освобождает его ПЕРВОЙ ветвью, до
    # всякого сравнения `acr`. Значит поднимать нечего, и слот несёт то же
    # удостоверение; человек под этим именем был бы ДРУГИМ принципалом, и его
    # операция не читалась бы соседним шагом.
    "jwtAccountAdminAStepUp",
    "jwtAccountAdminB",
    "jwtBootstrap",
    "jwtInvitee",
    "jwtProjectAdminA1",
    "jwtNoBindings",
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
    # Ручка докер-токена. Того же рода, что и остальные три: её НАЗЫВАЕТ посадка,
    # и ни один подписант её не выпускает. В шаблоне окружения строки под неё не
    # было ВОВСЕ — то есть ключ читался кейсом и не объявлялся нигде, и перепись
    # долга его не видела, пока не научилась третьему состоянию (kaname#122).
    "iamRegistryTokenBaseUrl",
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
    "projectB1Id",
    "userAAAId",
    "userAABId",
    "userNOBId",
    "userINVId",
    # Цели привязки матрицы отказов (`cases/authz-deny.py`): строки людей, на
    # которые субъекты матрицы пробуют выдать себе права и чью запись читают.
    # Предъявителя у них нет (`principal_pairings.BINDING_TARGET_ONLY_IDS`), и
    # литерал чужого стенда на их месте называл бы несуществующую строку —
    # отказ по нему пришёл бы и при исправном рубеже.
    "userPA1Id",
    "userPureNoBindingsId",
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
    """Каталог контрактов — из СВОЕГО дерева.

    ЗДЕСЬ БРАЛСЯ КАТАЛОГ МОДУЛЯ-ПИНА ПЛАТФОРМЫ (`go list -m -f '{{.Dir}}'`), и
    это было верно ровно пока контракты службы публиковала платформа. Ступень
    S0a (kacho#2617, исход C) перенесла их дом сюда и сняла ребро
    `kaname → kacho` целиком, поэтому запрос к `go list -m` стал НЕИСПОЛНИМ by
    construction: «module github.com/PRO-Robotech/kacho: not a known dependency».
    Посев выходил третьим исходом («условие не создано») на каждом прогоне —
    наблюдалось в конвейере, задание «автономный стенд».

    Что это меняет в посеве — ничего: `proto/kaname/` этого дерева несёт тот же
    контракт, и от копии платформы он отличается РОВНО строкой `option
    go_package`, которую разбор дескриптора для чеканки не читает.

    Переопределение средой сохранено: стенд могут поднимать над деревом,
    собранным иначе.
    """
    env = os.environ.get("KANAME_STAND_PROTO_ROOT", "").strip()
    if env:
        p = pathlib.Path(env)
        if not (p / BOOTSTRAP_PROTO).is_file():
            raise Unmet(f"KANAME_STAND_PROTO_ROOT={p} не несёт {BOOTSTRAP_PROTO}")
        return p
    root = ROOT / "proto"
    if not (root / BOOTSTRAP_PROTO).is_file():
        raise Unmet(f"{root} не несёт {BOOTSTRAP_PROTO} — контракты службы лежат в её "
                    "дереве (proto/kaname/), и назвать их больше нечем: ребро к модулю "
                    "платформы снято ступенью S0a")
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


class LaneHttp:
    """Клиент полосы входа: взаимный TLS ЛИСТОМ КРАЯ и проверка имени сервера.

    Лист края предъявляется ТОЛЬКО здесь: полоса допускает ровно край, и другой
    двери к регистрации человека под `own` у продукта нет.
    """

    def __init__(self, base_url: str, pki: pathlib.Path):
        ca, cert, key = pki / "ca.crt", pki / "edge.crt", pki / "edge.key"
        for f in (ca, cert, key):
            if not f.is_file():
                raise Unmet(f"нет {f} — лист края стенд не выписывал")
        self.base = base_url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=str(ca))
        self.ctx.load_cert_chain(str(cert), str(key))

    def ask(self, method: str, path: str, body: dict | None = None,
            cookies: dict | None = None) -> tuple[int, list[str], str]:
        """(код, значения `Set-Cookie`, тело)."""
        hdrs = {"X-Forwarded-For": LANE_SOURCE, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=hdrs)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                return (r.status, r.headers.get_all("Set-Cookie") or [],
                        r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return (e.code, e.headers.get_all("Set-Cookie") or [],
                    e.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, ssl.SSLError, OSError, socket.timeout) as e:
            raise Unmet(f"полоса входа {self.base} недостижима: {e}") from None


def lane_cookie(set_cookies: list[str], name: str) -> str | None:
    for sc in set_cookies:
        head = sc.split(";", 1)[0]
        if head.startswith(name + "="):
            return head[len(name) + 1:]
    return None


def person_password() -> str:
    """Пароль заводимого человека: случайный, у каждого свой, нигде не печатается.

    Входить под ним посеву незачем — человек нужен как ВЛАДЕЛЕЦ аккаунта, а
    предъявители аккаунтов — служебные учётки (см. «ПРЕДЪЯВИТЕЛЬ ЗДЕСЬ —
    МАШИНА»). Длина выше минимума профиля (`authn.login.password-min-length`).
    """
    return secrets.token_urlsafe(24)


def register_person(lane, email: str, password: str) -> str:
    """Регистрация человека полосой входа. Утверждается и статус, и носитель.

    Пароль и почта в текст отказа НЕ попадают: журнал прогона публичного
    репозитория читает кто угодно.
    """
    code, sc, text = lane.ask("GET", f"{LANE_CSRF}?form=register")
    if code == 403:
        raise Finding(
            f"признак формы регистрации: полоса ответила 403 ({text[:200]!r}) — "
            f"лист края стенда не принят как край. Полоса допускает РОВНО край по "
            f"SAN клиентского листа; отказ обвиняет либо имя листа, либо сужение "
            f"круга у службы")
    try:
        token = json.loads(text or "{}").get("csrfToken") if code == 200 else None
    except json.JSONDecodeError:
        token = None
    ctx = lane_cookie(sc, LANE_FORM_COOKIE)
    if code != 200 or not isinstance(token, str) or not token or not ctx:
        raise Finding(
            f"признак формы регистрации: код {code}, признак строкой "
            f"{isinstance(token, str) and bool(token)}, печенье {LANE_FORM_COOKIE} "
            f"{bool(ctx)} — форму отправить нечем")
    code, sc, text = lane.ask("POST", LANE_REGISTER,
                              body={"email": email, "password": password,
                                    "csrfToken": token},
                              cookies={LANE_FORM_COOKIE: ctx})
    if code != 200:
        raise Finding(f"регистрация человека: ждали 200, получили {code} "
                      f"({text[:200]!r})")
    bearer = lane_cookie(sc, LANE_SESSION_COOKIE)
    if not bearer:
        raise Finding(f"регистрация ответила 200 без печенья {LANE_SESSION_COOKIE} — "
                      f"следствия регистрации одним исходом не наступили")
    return bearer


# ─── ПОДТВЕРЖДЕНИЕ АДРЕСА ЗАВЕДЁННОГО ЧЕЛОВЕКА (kaname#456) ──────────────────
#
# Человек, чей адрес не подтверждён, дальше входа не проходит, и выдачи на него
# не действуют: дверь решения отвечает ему `email_not_verified`, раскрытие
# отношений его не называет. Люди стенда — владельцы аккаунтов и цели выдач
# наборов, поэтому каждый заведённый доводится до подтверждённого адреса ТЕМ ЖЕ
# глаголом, что человек: код из письма регистрации, которое служба сдала
# приёмнику писем стенда (`.github/scripts/stand-mailbox.py`), предъявляется
# полосе под сессией регистрации. Отметку в базу посев не пишет.
#
# Приёмник и разбор кода — ОДНИ на оба посева (посев стенда чарта их отсюда
# импортирует): вторая копия разошлась бы с первой молча.

# Сколько ждать письма в приёмнике и с какой паузой спрашивать. Письмо
# регистрации ставится той же транзакцией, что заводит человека, и дренаж
# очереди отдаёт его узлу за секунды; предел — с запасом на повтор отправки.
LETTER_BUDGET_S = 90
LETTER_POLL_S = 2


class Mailbox:
    """Приёмник писем стенда: `GET /messages?to=<адрес>` — письма по порядку."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")

    def letters(self, to: str) -> list[str]:
        url = f"{self.base}/messages?" + urllib.parse.urlencode({"to": to})
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                doc = json.loads(r.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, socket.timeout,
                json.JSONDecodeError) as e:
            raise Unmet(f"приёмник писем стенда по адресу {self.base} недостижим "
                        f"либо ответил не перечнем: {e}") from None
        msgs = doc.get("messages") if isinstance(doc, dict) else None
        if not isinstance(msgs, list):
            raise Unmet(f"приёмник писем стенда ответил без перечня messages: {doc!r:.200}")
        return [m.get("data", "") for m in msgs if isinstance(m, dict)]


def code_of(letter: str) -> str | None:
    """Код из письма подтверждения: первая непустая строка после строки
    «Код подтверждения:» (`internal/clients/invite_mail.go`,
    RenderVerificationMail). Письмо без неё кода не несёт."""
    lines = letter.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if line.strip() == "Код подтверждения:":
            for nxt in lines[i + 1:]:
                if nxt.strip():
                    return nxt.strip()
            return None
    return None


def await_code(mailbox, email: str, seen: int, sleep) -> str | None:
    """Код ПОСЛЕДНЕГО письма, пришедшего сверх `seen` уже прочитанных. None —
    за предел письма не пришло."""
    for _ in range(max(1, LETTER_BUDGET_S // LETTER_POLL_S)):
        letters = mailbox.letters(email)
        if len(letters) > seen:
            return code_of(letters[-1])
        sleep(LETTER_POLL_S)
    return None


def confirm_person(lane, mailbox, email: str, bearer: str, sleep=time.sleep) -> None:
    """Код письма регистрации предъявляется полосе под сессией регистрации;
    утверждается `session.emailVerified: true` ответа."""
    code_value = await_code(mailbox, email, 0, sleep)
    if code_value is None:
        raise Finding(f"письмо подтверждения адреса заведённому человеку не дошло до "
                      f"приёмника писем стенда за {LETTER_BUDGET_S} с (либо пришло без "
                      f"строки кода) — служба не сдала его узлу, названному посадкой "
                      f"стенда")
    code, sc, text = lane.ask("GET", f"{LANE_CSRF}?form=verify-email-confirm",
                              cookies={LANE_SESSION_COOKIE: bearer})
    try:
        token = json.loads(text or "{}").get("csrfToken") if code == 200 else None
    except json.JSONDecodeError:
        token = None
    ctx = lane_cookie(sc, LANE_FORM_COOKIE)
    if code != 200 or not isinstance(token, str) or not token or not ctx:
        raise Finding(f"признак формы подтверждения: код {code} — форму отправить нечем")
    code, _sc, text = lane.ask("POST", LANE_VERIFY_CONFIRM,
                               body={"code": code_value, "csrfToken": token},
                               cookies={LANE_FORM_COOKIE: ctx, LANE_SESSION_COOKIE: bearer})
    if code != 200:
        raise Finding(f"предъявление кода подтверждения из письма: ждали 200, получили "
                      f"{code} ({text[:200]!r})")
    try:
        view = json.loads(text or "{}").get("session")
    except (json.JSONDecodeError, AttributeError):
        view = None
    if not isinstance(view, dict) or view.get("emailVerified") is not True:
        raise Finding("предъявление кода ответило 200, а session.emailVerified не true — "
                      "отметка не поставлена, а успех объявлен")


def resolve_tenant(http: Http, public: str, token: str, email: str,
                   budget_s: float = 60.0) -> dict:
    """Личность → её аккаунт → её проект по умолчанию. ЖДЁТ, а не спрашивает раз.

    Регистрация отвечает 200 синхронно, а аккаунт и проект могут приезжать
    своим путём. Единственный ответ «ещё нет» здесь неотличим от «не будет»,
    поэтому ожидание идёт до ПРЕДМЕТА, а не до кода ответа. Человек ищется по
    почте: внешний идентификатор под `own` — случайное имя субъекта полосы.
    """
    deadline = time.time() + budget_s
    seen = {"user": False, "active": False, "account": False}
    while time.time() < deadline:
        code, body = http.json_ask(f"{public}/iam/v1/users?pageSize=1000", token=token)
        if code != 200:
            raise Finding(f"перечень людей не читается: код {code}")
        user = next((u for u in body.get("users", [])
                     if u.get("email") == email), None)
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
        f"зарегистрированный человек не стал арендатором за {budget_s:.0f} с: "
        f"строка есть={seen['user']}, активна={seen['active']}, "
        f"аккаунт есть={seen['account']}. Регистрация ответила 200, значит отказ "
        f"наступил ПОСЛЕ неё — смотреть журнал службы, а не вызов")


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

    ПУТЬ — НАШ. Запись у публикатора :9097 одна — набор собственной чеканки
    (`authn.token-signing.key-set-path`, по умолчанию
    `/.well-known/kaname/jwks.json`); зеркало прежнего издателя по каноническому
    `/.well-known/jwks.json` снято вместе с ним (kaname#361). Набор обязан
    отвечать: своя чеканка на этой посадке включена, и ею подписаны все
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
    lane_url = f"https://{host}:{args.port_lane}"
    token_base = f"https://{host}:{args.port_token}"
    token_url = f"{token_base}/iam/v1/token"
    jwks_base = f"https://{host}:{args.port_jwks}"

    # Признак прогона: он уезжает в ИМЕНА заводимых предметов, поэтому повторный
    # прогон не встречает 409 — и заодно по нему видно, какой прогон что завёл.
    run_id = args.run_id or f"s{secrets.token_hex(4)}"

    for port, what in ((args.port_public, "собственный публичный REST"),
                       (args.port_internal, "собственный внутренний REST"),
                       (args.port_lane, "полоса входа"),
                       (args.port_token, "выдача токенов"),
                       (args.port_jwks, "публикатор набора ключей"),
                       (args.port_grpc, "внутренний gRPC")):
        require_listener(host, port, what)

    http = Http(pki)
    lane_http = LaneHttp(lane_url, pki)
    mailbox = Mailbox(args.mailbox_url)

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
        email = f"seed-{run_id}-{lane}@kaname.local"
        bearer = register_person(lane_http, email, person_password())
        step(f"человек {lane.upper()} зарегистрирован полосой входа")
        confirm_person(lane_http, mailbox, email, bearer)
        step(f"и подтвердил адрес кодом письма регистрации (приёмник писем стенда)")
        tenants[lane] = resolve_tenant(http, public, boot, email)
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
    # Слот повышенного уровня — ТОТ ЖЕ принципал (см. `MINTED_CREDENTIALS`):
    # машинный распорядитель освобождён от порога уровня, и второе удостоверение
    # ничего не подняло бы.
    creds["jwtAccountAdminAStepUp"] = creds["jwtAccountAdminA"]
    step("jwtAccountAdminAStepUp — тот же распорядитель аккаунта A (машинный "
         "принципал порогу уровня не подлежит)")

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

    say("── ВТОРОЙ субъект без выдач: у каждого слота своя учётка ──────────────")
    #
    # ПОЧЕМУ ОТДЕЛЬНАЯ УЧЁТКА, А НЕ ТА ЖЕ САМАЯ. `jwtNoBindings` и
    # `jwtPureNoBindings` — два слота «кому не выдано ничего», и наборы читают их
    # порознь. Сведи их в одну учётку — и выдача, сделанная одной коллекцией на
    # первый слот, молча снимет предмет у второго: отрицание «не имеет прав»
    # стало бы функцией порядка прогонов. Класс измерен на общем стенде
    # (`testing-newman.md` §4а, общий субъект без выдач, который грант-суиты
    # реально гранят) и здесь не воспроизводится.
    sva_nob = make_service_account(http, public, boot, tenants["a"]["accountId"],
                                   f"seed-{run_id}-nob", run_id,
                                   "создание второй учётки без выдач")
    assert_no_bindings(http, public, boot, sva_nob)
    step(f"вторая учётка без выдач заведена, её перечень выдач ПУСТ: {sva_nob}")
    creds["jwtNoBindings"] = sa_token(http, public, token_url, boot, sva_nob,
                                      run_id, "второй субъект без выдач")
    assert_serves(http, public, creds["jwtNoBindings"], "/iam/v1/me",
                  "jwtNoBindings (рубеж проходит, права не имеет)")
    step("jwtNoBindings получен обменом и ПРИНЯТ рубежом (права при этом нет)")

    say("── ЧЕЛОВЕК, которому не выдано ничего: назначенный субъект без грантов ─")
    #
    # ЭТО ЧЕЛОВЕК, А НЕ СЛУЖЕБНАЯ УЧЁТКА, И ПОДМЕНА ЗДЕСЬ НЕ ПРОХОДИТ. Кейсы
    # читают его как `"subjectId": "{{userNOBId}}"` и `subject="user:{{userNOBId}}"`
    # — то есть предмет утверждения есть ТИП субъекта, и учётка с префиксом `sva`
    # дала бы кейс, проверивший подстановку. Человека производит только провизия
    # личности, поэтому заводится третья полоса арендатора.
    #
    # ПРЕДЪЯВИТЕЛЯ У НЕГО НЕТ НАМЕРЕННО: наборы называют его только КАК ЦЕЛЬ
    # выдачи и ни разу не ходят под ним. Выпустить токен человека машинно значило
    # бы дать предъявителя с пустым уровнем подтверждения личности — тот самый
    # случай, который эта же полоса измерила выше.
    nob_email = f"seed-{run_id}-nob@kaname.local"
    bearer = register_person(lane_http, nob_email, person_password())
    step("человек БЕЗ ВЫДАЧ зарегистрирован полосой входа")
    confirm_person(lane_http, mailbox, nob_email, bearer)
    step("и подтвердил адрес кодом письма регистрации")
    tenants["nob"] = resolve_tenant(http, public, boot, nob_email)
    user_nob = tenants["nob"]["userId"]
    if tenants["nob"]["accountId"] in (tenants["a"]["accountId"],
                                       tenants["b"]["accountId"]):
        raise Finding(
            "человек без выдач получил аккаунт одного из арендаторов — тогда "
            "«ему не выдано ничего» перестаёт быть верным: владелец аккаунта "
            "имеет права на нём структурно")
    step(f"и стал арендатором своего аккаунта: человек {user_nob}, аккаунт "
         f"{tenants['nob']['accountId']}")

    say("── ЧЕЛОВЕК — ЦЕЛЬ ПРИВЯЗКИ ЧЛЕНСТВА: отдельный от человека без выдач ───")
    #
    # `userINVId` набор группы (`cases/iam-group.py`) называет ЦЕЛЬЮ ПРИВЯЗКИ:
    # его добавляют в группу и снимают из неё, и предметом утверждения служит
    # набор членов. Второй слот, а не `userNOBId`: «человеку не выдано ничего»
    # у соседних наборов не должно зависеть от того, чьим членом его сделала
    # группа. Предъявителя у него нет по той же причине, что у `userNOBId`.
    inv_email = f"seed-{run_id}-inv@kaname.local"
    bearer = register_person(lane_http, inv_email, person_password())
    step("человек — цель привязки членства — зарегистрирован полосой входа")
    confirm_person(lane_http, mailbox, inv_email, bearer)
    step("и подтвердил адрес кодом письма регистрации")
    tenants["inv"] = resolve_tenant(http, public, boot, inv_email)
    user_inv = tenants["inv"]["userId"]
    if user_inv in (user_nob, tenants["a"]["userId"], tenants["b"]["userId"]):
        raise Finding(
            "цель привязки членства совпала с уже заведённым человеком — слоты "
            "набора перестали быть независимы")
    step(f"и стала строкой человека: {user_inv}")

    say("── ЦЕЛИ ПРИВЯЗКИ МАТРИЦЫ ОТКАЗОВ: строки людей без предъявителя ───────")
    #
    # `userPureNoBindingsId` — цель, которой в дереве не выдаётся НИЧЕГО и никем;
    # `userPA1Id` — строка человека, на которую распорядитель проекта A1 пробует
    # выдать себе права. Свой слот у каждой: общий слот сделал бы «никому не
    # выдано» функцией порядка коллекций.
    targets: dict[str, str] = {}
    for slot in ("pa1", "pure"):
        t_email = f"seed-{run_id}-{slot}@kaname.local"
        bearer = register_person(lane_http, t_email, person_password())
        confirm_person(lane_http, mailbox, t_email, bearer)
        targets[slot] = resolve_tenant(http, public, boot, t_email)["userId"]
        if targets[slot] in (user_nob, user_inv, tenants["a"]["userId"],
                             tenants["b"]["userId"], *[v for k, v in targets.items()
                                                       if k != slot]):
            raise Finding(
                f"цель привязки «{slot}» совпала с уже заведённым человеком — слоты "
                f"матрицы перестали быть независимы")
        step(f"цель привязки «{slot}» заведена полосой входа, адрес подтверждён: "
             f"{targets[slot]}")

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
    #     (шапка набора `authz-sa-apitoken`, ныне в доме платформы —
    #     `PRO-Robotech/kacho:services/vpc/tests/newman/cases/authz-sa-apitoken.py`).
    #     Это ВХОД, а не удостоверение, и
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
        "iamRegistryTokenBaseUrl": token_base,
        "projectA1Id": tenants["a"]["projectId"],
        # Проект на стороне ЧУЖОГО арендатора. Совпадает с
        # `existingProjectCrossId` не случайно и не временно: у арендатора `b`
        # проект по умолчанию один, и оба ключа называют именно его. Два имени
        # остались оттого, что наборы пришли из разных фикстур; сводить их —
        # ломающая правка кейсов, и она не предмет этой полосы.
        "projectB1Id": tenants["b"]["projectId"],
        # Собственные строки арендаторов. Кейсы читают их как ЧЕЛОВЕКА-владельца
        # своего аккаунта (`ownerUserId`, пол видимости перечня людей), и
        # производит их провизия личности, а не создание учётки.
        "userAAAId": tenants["a"]["userId"],
        "userAABId": tenants["b"]["userId"],
        # Назначенный субъект БЕЗ выдач — человек своего аккаунта и никого
        # больше. Предъявителя у него нет: наборы называют его целью выдачи.
        "userNOBId": user_nob,
        # Цель привязки членства группы — человек, и только цель.
        "userINVId": user_inv,
        # Цели привязки матрицы отказов — люди, и только цели.
        "userPA1Id": targets["pa1"],
        "userPureNoBindingsId": targets["pure"],
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
    pairings = require_pairings()
    broken = pairings.unpaired_principals(fixtures)
    if broken:
        raise Finding(
            "объявленные пары «идентификатор ↔ предъявитель» НЕ ДЕРЖАТСЯ: "
            + "; ".join(broken)
            + ". Набор привязывает роль к идентификатору и читает под "
              "предъявителем, поэтому расхождение здесь приезжает в кейс "
              "таймаутом на шесть шагов позже причины")
    covered = sum(1 for i, t in pairings.PRINCIPAL_PAIRINGS.items()
                  if i in fixtures and t in fixtures)
    step(f"объявленные пары проверены по claim предъявителя: покрыто этим посевом "
         f"{covered} из {len(pairings.PRINCIPAL_PAIRINGS)}, расхождений нет")
    patch = env_patch(fixtures)
    env_file = pathlib.Path(args.env_file)
    replaced = write_env(patch, env_file, pathlib.Path(args.env_template))
    step(f"окружение записано: {env_file} — ключей {len(patch)}, из них "
         f"заменено в шаблоне {replaced}")

    say("")
    say(f"перепись: шагов с утверждённым исходом {steps_done} · "
         f"ключей записано {len(patch)} · предъявителей {len(creds)} · "
         f"арендаторов {len(tenants)}")
    say("ПОСЕЯНО. Всё выдано глаголами продукта: чеканка бутстрапа, регистрация "
        "полосой входа, выпуск удостоверения, обмен подписанного утверждения.")
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
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve()),
         "--host", "127.0.0.1", "--pki", "/nonexistent-pki-for-selftest",
         "--port-public", str(closed_port), "--port-internal", str(closed_port),
         "--port-lane", str(closed_port), "--port-token", str(closed_port),
         "--port-grpc", str(closed_port)],
        capture_output=True, text=True, env=env, timeout=120)
    _c("нет слушателя — код 75, а НЕ 1 и не 0", proc.returncode == RC_UNMET,
       f"код {proc.returncode}, вывод {(proc.stdout + proc.stderr)[-300:]!r}")
    _c("и текст называет несозданное условие, а не находку",
       "УСЛОВИЕ НЕ СОЗДАНО" in (proc.stdout + proc.stderr)
       and "НАХОДКА" not in (proc.stdout + proc.stderr),
       (proc.stdout + proc.stderr)[-300:])

    # Ось 2б: РЕГИСТРАЦИЯ ПОЛОСОЙ ВХОДА — отказ полосы есть находка, успех молчит.
    #
    # Каждый мир отличается от законного близнеца (последняя строка) ОДНИМ
    # фактом: признак формы отвергнут листу (403), регистрация не 200,
    # регистрация 200 без печенья сессии. Близнец — 200 с печеньем — обязан
    # молчать: иначе проба падала бы на чём угодно.
    class _Lane:
        def __init__(self, csrf_code=200, register_code=200, session=True):
            self.csrf_code, self.register_code = csrf_code, register_code
            self.session = session

        def ask(self, method, path, body=None, cookies=None):
            if path.startswith(LANE_CSRF):
                if self.csrf_code != 200:
                    return self.csrf_code, [], '{"code":7,"message":"edge only"}'
                return 200, [f"{LANE_FORM_COOKIE}=f; Path=/"], '{"csrfToken":"t"}'
            if self.register_code != 200:
                return self.register_code, [], '{"code":3,"message":"bad form"}'
            sc = [f"{LANE_SESSION_COOKIE}=s; Path=/"] if self.session else []
            return 200, sc, "{}"

    for label, lane_world, want in (
            ("признак формы отвергнут листу (403) — НАХОДКА", _Lane(csrf_code=403), Finding),
            ("регистрация ответила 400 — НАХОДКА", _Lane(register_code=400), Finding),
            ("регистрация 200 без печенья сессии — НАХОДКА", _Lane(session=False), Finding),
            ("регистрация 200 с печеньем — молчит", _Lane(), None)):
        try:
            register_person(lane_world, "who@x", "pw-selftest")
            got = None
        except Unmet:
            got = Unmet
        except Finding:
            got = Finding
        _c(label, got is want,
           f"ожидалось {want.__name__ if want else 'молчание'}, "
           f"получено {got.__name__ if got else 'молчание'}")

    # Ось 2в: ПОДТВЕРЖДЕНИЕ АДРЕСА заведённого человека (kaname#456). Человек с
    # неподтверждённым адресом дальше входа не проходит, и выдачи на него не
    # действуют: посев доводит каждого заведённого до подтверждённого адреса
    # кодом из письма регистрации в приёмнике писем стенда. Каждый мир меняет
    # ОДИН факт против законного близнеца (первая строка).
    class _Box:
        def __init__(self, letters=None, down=False):
            self.letters_by, self.down = dict(letters or {}), down

        def letters(self, to):
            if self.down:
                raise Unmet("приёмник писем стенда недостижим: connection refused")
            return list(self.letters_by.get(to, []))

    def _letter(code):
        return ("Subject: x\r\n\r\nКод подтверждения:\r\n\r\n    " + code
                + "\r\n\r\nКод действует 30 мин.\r\n")

    class _VLane:
        def __init__(self, code=200, verifies=True):
            self.code, self.verifies, self.seen = code, verifies, []

        def ask(self, method, path, body=None, cookies=None):
            if path.startswith(LANE_CSRF):
                return 200, [f"{LANE_FORM_COOKIE}=f; Path=/"], '{"csrfToken":"t"}'
            if path == LANE_VERIFY_CONFIRM:
                self.seen.append((body or {}).get("code"))
                if (cookies or {}).get(LANE_SESSION_COOKIE) != "s":
                    return 401, [], '{"code":16,"message":"authentication failed"}'
                if self.code != 200 or (body or {}).get("code") != "ABCDE-FGHIJ":
                    return 401, [], '{"code":16,"message":"authentication failed"}'
                return (200, [f"{LANE_SESSION_COOKIE}=s2; Path=/"],
                        json.dumps({"session": {"emailVerified": self.verifies}}))
            return 404, [], "{}"

    who = "who@stand.invalid"
    for label, lane_world, box, want in (
            ("код письма регистрации принят — молчит", _VLane(),
             _Box({who: [_letter("ABCDE-FGHIJ")]}), None),
            ("письмо не дошло до приёмника — НАХОДКА", _VLane(), _Box(), Finding),
            ("приёмник писем молчит — УСЛОВИЕ НЕ СОЗДАНО", _VLane(), _Box(down=True), Unmet),
            ("код отвергнут полосой (401) — НАХОДКА", _VLane(code=401),
             _Box({who: [_letter("ABCDE-FGHIJ")]}), Finding),
            ("200 без emailVerified: true — НАХОДКА", _VLane(verifies=False),
             _Box({who: [_letter("ABCDE-FGHIJ")]}), Finding)):
        try:
            confirm_person(lane_world, box, who, "s", sleep=lambda _s: None)
            got = None
        except Unmet:
            got = Unmet
        except Finding:
            got = Finding
        except Exception as e:  # noqa: BLE001 — сбой пробы назван, а не проглочен
            got = type(e)
        _c("подтверждение адреса: " + label, got is want,
           f"ожидалось {want.__name__ if want else 'молчание'}, "
           f"получено {got.__name__ if got else 'молчание'}")

    _c("код разбирается из письма той формы, что собирает служба",
       code_of(_letter("ABCDE-FGHIJ")) == "ABCDE-FGHIJ", f"{code_of(_letter('ABCDE-FGHIJ'))!r}")
    _c("ЗАКОННЫЙ БЛИЗНЕЦ: письмо без строки кода — кода нет",
       code_of("Subject: x\r\n\r\nПодтвердите адрес.\r\n") is None, "")

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
    if principal_pairings is None:
        _c("ни одна объявленная пара не покрыта ПОЛОВИНОЙ", False,
           f"модуль-авторитет не прочитан ({PAIRINGS_IMPORT_ERROR}) — "
           f"предпосылки у оси нет, и молчание здесь объявило бы её проверенной")
        _c("предъявитель называет ЧУЖОГО принципала — расхождение", False,
           "тот же непрочитанный авторитет")
        return _finish_self_test()
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

    return _finish_self_test()


def _finish_self_test() -> int:
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
    ap.add_argument("--port-lane", type=int, default=9100)
    ap.add_argument("--port-token", type=int, default=9096)
    ap.add_argument("--port-jwks", type=int, default=9097)
    ap.add_argument("--port-grpc", type=int, default=9091)
    ap.add_argument("--mailbox-url", default=DEFAULT_MAILBOX_URL,
                    help="адрес чтения приёмника писем стенда: из него берётся код "
                         "подтверждения адреса заведённых людей")
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
