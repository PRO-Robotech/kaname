#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ЦЕРЕМОНИИ: человеческий предъявитель своей церемонией службы (kaname#398).

ПРЕДМЕТ. Объявление волны церемонии (`ceremony_credentials.py`) называет этот
файл ПРОИЗВОДИТЕЛЕМ условия «предъявитель принадлежит человеку». Машинный посев
такого предъявителя не выковывает ни при каком устройстве: аккаунт принадлежит
человеку by construction, а уровень аутентификации приходит только из сессии
входа. Пока файла не было, прогонщик набора печатал «УСЛОВИЕ НЕ СОЗДАНО: …
посева церемонии нет» на каждом запуске.

ГДЕ ОН ИСПОЛНЯЕТСЯ — ДВА РЕЖИМА.

  * Стенд чарта посадки `own` (`.github/scripts/stand-chart.sh`, задание
    `chart-own`): зовёт его подкоманда
    `seed-ceremony` того же скрипта ПОСЛЕ `seed-login-lane`. Подкоманда выносит из
    Secret стенда листы, человека и поднимает переадресации поверхностей; адреса,
    по которым посев доказал способность, уезжают в окружение.
  * ВОЛНА (`--wave`) на автономном стенде (`.github/scripts/stand-own.sh`, задание
    `stand-ceremony`, после машинного посева): людей посев заводит сам —
    регистрацией полосой, подтверждением адреса кодом письма из приёмника писем
    стенда и входом, — куёт каждому предъявителя уровня «1» той же церемонией, а
    повышенный уровень — вторым фактором (заведение, подтверждение кодом по
    времени, Ф12): подтверждение перевыпускает сессию уровнем «2», и церемония
    под ней выдаёт токен уровня «2». Уровень и субъект каждого токена
    утверждаются по его составу. Собственные фронты этого стенда держат взаимный
    TLS, поэтому посев предъявляет им лист службы.

ВСЁ ДЕЛАЕТСЯ ГЛАГОЛАМИ ПРОДУКТА — СЕМЬ ШАГОВ, И КАЖДЫЙ УТВЕРЖДАЕТ СВОЙ ИСХОД:

  1. чеканка бутстрап-удостоверения (`InternalBootstrapTokenService`, :9091,
     лист службы из круга чеканки) — машинный `system_admin` кластера. Его
     принимает собственный публичный фронт (`GET /iam/v1/accounts`) — иначе
     «выдано» было бы неотличимо от «выдано и негодно»;
  2. заведение ДВУХ конфиденциальных интерактивных клиентов глаголом `Create`
     (`InternalInteractiveClientService`, :9091). Глагол фронтируется краем
     (`GatewayFrontedInternalRPCs`): собственный внутренний фронт его не
     проходит by construction, и дверь у него одна — край. Края на стенде нет,
     его место занимает прогонщик, как и у полосы входа: предъявляет лист с
     именем края и пересылает принципал ТОГО машинного удостоверения, которое
     шаг 1 выковал и фронт принял. Круг вызывающих, пол подтверждения и
     проверка `system_admin` у глагола остаются продуктовыми — посев их не
     обходит, а проходит. Утверждается способ `client_secret_basic` и непустой
     секрет в ответе вызова (Р3 и Р4 приёмки секрета клиента, kaname#405);
  3. вход человека паролем через полосу (лист края) — сессия уровня 1;
  4. запрос авторизации (`GET /iam/v1/authorize`, PKCE S256) с печеньем
     сессии — `302` на адрес возврата с ровно одним кодом и `state` дословно;
  5. обмен кода (`POST /iam/v1/token`, секрет клиента схемой Basic) — токен
     доступа;
  6. рутинный глагол собственного публичного фронта (`GET /iam/v1/me`) под
     выданным токеном: субъект — ТОТ человек, что вошёл. Иначе «токен выдан» не
     значило бы «предъявитель человека есть».

ЧТО ПИШЕТСЯ — объявлено ниже и выдаётся флагом `--minted-keys` (всё, что посев
умеет писать): адреса двух поверхностей, по которым шаги доказаны; два
конфиденциальных клиента с адресами возврата (их читает набор
`kaname-authorization-code`); предъявитель человека уровня «1», его идентификатор
и почта. Режим стенда чарта на этом останавливается: человек стенда там один, и
второй фактор ему заводит и снимает набор `kaname-second-factor`. Волна пишет
сверх того `MINTED_WAVE`: тот же человек уровня «2» и его личный аккаунт, второй
человек без выдач, приглашаемый человек и слоты заведения аккаунта. Чего не
пишет ни один режим: слот повышенного уровня машинного распорядителя
(`jwtAccountAdminAStepUp`) — его пишет машинный посев.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — предъявители людей выкованы и приняты фронтом, окружение записано;
    1  — НАХОДКА: продукт ответил не по контракту там, где посев предъявил всё,
         чего контракт требует. Вердикт о дереве;
   75  — УСЛОВИЕ НЕ СОЗДАНО: поверхность недостижима, листа нет, нет `grpcurl`,
         стенд не передал человека либо (волна) не назван приёмник писем.
         Вердикта о дереве нет НИ ОДНОГО.

СЕКРЕТЫ НЕ ПЕЧАТАЮТСЯ НИКОГДА — ни пароль, ни секрет клиента, ни токен: журнал
прогона публичного репозитория читает кто угодно. Пароль и почта приходят
переменными окружения процесса, а не аргументами; пароли людей волны случайны,
у каждого свой, и из процесса посева не выходят.

САМОПРОВЕРКА — `--self-test`: подставной стенд по каждой оси, где каждая
инъекция меняет ОДИН факт против законного мира — в обоих режимах; код по
времени — по вектору RFC 6238; сходимость объявленных ключей с записью в обе
стороны; поверхность и природа ключей — те, что выводит перепись долга. Мир
волны не снисходительнее стенда: письмо приходит позже ответа глагола, второе
раньше интервала Р9 отвергается `429`, а ожидание идёт по часам мира.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
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

# Запись окружения и исход «условие не создано» — ОДНИ на все посевы: копия
# разошлась бы с первой молча.
sys.path.insert(0, str(HERE))
import seed_login_lane as lane_seed  # noqa: E402
import seed_own_stand as own_seed  # noqa: E402
from seed_own_stand import Unmet, write_env  # noqa: E402
from seed_login_lane import LaneHttp, cookie_value, form_token, message_of  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# КЛЮЧИ ОКРУЖЕНИЯ, КОТОРЫЕ ЭТОТ ПОСЕВ ПИШЕТ. Перепись долга спрашивает их у
# САМОГО посева (`--minted-keys`); сходимость объявления с записью держит
# самопроверка, в обе стороны.
# ─────────────────────────────────────────────────────────────────────────────
MINTED_ADDRESSES = ("iamRegistryTokenBaseUrl", "ownRestBaseUrl")
MINTED_CLIENTS = ("oauthClientId", "oauthClientSecret", "oauthRedirectUri",
                  "oauthRedirectUriAlt", "oauthOtherClientId", "oauthOtherClientSecret")
# Предъявитель человека и его идентичность — ключи ЦЕРЕМОНИИ
# (`newman-suite-debt.py`, `is_ceremony_key`): их производит только вход человека.
MINTED_CEREMONY = ("jwtHumanCeremony", "ceremonyUserId", "ceremonyEmail")

# ─── ВОЛНА ЦЕРЕМОНИИ (`--wave`): люди, которых ждут коллекции волны ─────────
#
# Объявление волны (`ceremony_credentials.py --stems`) выводит из дерева
# коллекции, которым нужен человеческий предъявитель, и ключи, которых каждая
# ждёт. Здесь — ПРОИЗВОДИТЕЛЬ этих ключей: каждый человек заводится глаголами
# продукта (регистрация полосой, подтверждение адреса кодом письма, вход), его
# предъявитель куётся своей церемонией службы, а повышенный уровень — вторым
# фактором (заведение и подтверждение кодом по времени, Ф12): подтверждение
# перевыпускает сессию уровнем «2», и церемония под ней выдаёт токен того же
# уровня. Уровень токена УТВЕРЖДАЕТСЯ по его составу (`acr`), а не
# предполагается: токен «повышенного» уровня, выданный уровнем «1», дал бы
# кейс, проверивший не порог, а подстановку.
#
# СЛОТЫ ЗАВЕДЕНИЯ АККАУНТА: одна личность — один аккаунт волны. Заведение
# списывается с темпа личности (`authn.registration.admissions-per-window`), а
# регистрация уже занимает у человека одно место — личный аккаунт. Поэтому
# кейс, заводящий аккаунт, приводит СВОЮ личность; складывать заведения разных
# кейсов в одного человека значит воспроизводить сценарий, который продукт
# отвергает. Имена слотов — те, что читают кейсы (`cases/iam-account.py`,
# `cases/iam-account-redesign.py`, `cases/rbac-visibility-set.py`).
ADMISSION_SLOTS = ("AccCrud", "AccBvaMin", "AccBvaMax", "AccLsop",
                   "AccRdDerive", "AccRdSaga", "AccRdRestrict", "RbacVisSet")


def slot_keys(slot: str) -> tuple[str, str, str]:
    """Ключи слота: предъявитель уровня «1», уровня «2» и идентификатор человека."""
    return f"jwtHuman{slot}", f"jwtHuman{slot}StepUp", f"human{slot}UserId"


MINTED_WAVE = (
    # Тот же человек церемонии — повышенным уровнем, и аккаунт, которым он владеет
    # (личный аккаунт регистрации: известный id, не зависящий от порядка коллекций).
    "jwtHumanCeremonyStepUp", "ceremonyAccountId",
    # ВТОРОЙ человек, которому на арендаторах посева не выдано ничего.
    "jwtHumanCeremonyNoBindings", "ceremonyNoBindingsUserId",
    # Человек, которого кейс ПРИГЛАШАЕТ (`iam-user.py`,
    # IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS): с kaname#456 выдачи действуют только
    # на человека с подтверждённым адресом, и приглашённый, ни разу не входивший,
    # права не держит by construction. Предъявитель ему не нужен — доступ судит
    # проба модели прав, — нужны адрес и строка, которую приглашение обязано найти.
    "ceremonyInviteeEmail", "ceremonyInviteeUserId",
) + tuple(k for s in ADMISSION_SLOTS for k in slot_keys(s))
# Чего волна НЕ пишет, хотя имя похоже: `jwtAccountAdminAStepUp`. Это слот ТОГО
# ЖЕ машинного распорядителя, что `jwtAccountAdminA` (кейсы выпускают под одним и
# опрашивают под другим), а машине уровень не поднимается и не нужен — его пишет
# машинный посев (`seed_own_stand.py`, `MINTED_CREDENTIALS`).

MINTED_KEYS = MINTED_ADDRESSES + MINTED_CLIENTS + MINTED_CEREMONY + MINTED_WAVE

# Поверхность, которой зачитываются эти ключи: у собственных HTTP-дверей службы
# ярлык переписи один. Самопроверка сверяет строку с выводом переписи.
MINTED_SURFACE = "служба (собственный REST-фронт)"

ENV_EMAIL = "KANAME_STAND_LANE_EMAIL"
ENV_PASSWORD = "KANAME_STAND_LANE_PASSWORD"

# Адреса возврата — значения, которыми клиентов заводил прежний набор
# интерактивного клиента этого дерева; набор переехал к краю платформы
# (`PRO-Robotech/kacho:gateway/tests/newman/cases/iam-interactive-client.py`, первый
# адрес там тот же). Слушать по ним не нужно: предмет — куда служба СОГЛАСНА
# доставить код.
REDIRECT = "https://api.kacho.local/auth/callback"
REDIRECT_ALT = "https://api.kacho.local/auth/callback2"

PRINCIPAL_TYPE_MD = "x-kacho-principal-type"
PRINCIPAL_ID_MD = "x-kacho-principal-id"
BOOTSTRAP_METHOD = "kaname.cloud.iam.v1.InternalBootstrapTokenService/MintBootstrapToken"
BOOTSTRAP_PROTO = "kaname/cloud/iam/v1/internal_bootstrap_token_service.proto"
CREATE_METHOD = "kaname.cloud.iam.v1.InternalInteractiveClientService/Create"
CREATE_PROTO = "kaname/cloud/iam/v1/internal_interactive_client_service.proto"
SECRET_METHOD = "client_secret_basic"
STATE_BYTES = 32


class Finding(Exception):
    """Продукт ответил не по контракту там, где посев предъявил требуемое."""


# Находка любого из трёх посевов, чьи глаголы здесь зовутся, — одна категория
# исхода: отказ продукта там, где посев предъявил требуемое. Непойманная находка
# соседа вышла бы трассировкой, и код 1 совпал бы с находкой лишь случайно.
FINDINGS = (Finding, lane_seed.Finding, own_seed.Finding)


def say(msg: str) -> None:
    print(msg, flush=True)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ─────────────────────────── транспорт ───────────────────────────────────────


class Surfaces:
    """Настоящие поверхности стенда: gRPC :9091 через `grpcurl`, HTTP — urllib.

    Имя сервера ПРОВЕРЯЕТСЯ у каждой HTTP-поверхности (лист стенда выписан и на
    127.0.0.1): снять проверку значило бы перестать проверять то, ради чего TLS
    на этой посадке и включён.
    """

    def __init__(self, pki: pathlib.Path, grpc_addr: str, issuance: str, own: str,
                 proto_root: pathlib.Path, present_service_leaf: bool = False):
        for f in ("ca.crt", "srv.crt", "srv.key", "edge.crt", "edge.key"):
            if not (pki / f).is_file():
                raise Unmet(f"нет {pki / f} — стенд не выносил листы")
        if not shutil.which("grpcurl"):
            raise Unmet("нет grpcurl — у чеканки бутстрапа и заведения клиента REST-двери, "
                        "которую посев вправе пройти, нет")
        if not (proto_root / CREATE_PROTO).is_file():
            raise Unmet(f"{proto_root} не несёт {CREATE_PROTO}")
        self.pki, self.grpc, self.proto = pki, grpc_addr, proto_root
        self.issuance, self.own = issuance.rstrip("/"), own.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
        # ЛИСТ СЛУЖБЫ НА HTTP-ДВЕРЯХ — ПО ПОСАДКЕ, А НЕ ВСЕГДА. Автономный стенд
        # (`stand-own.sh`) держит собственные фронты во взаимном TLS (`mutual`), и
        # без клиентского листа рукопожатие обрывается раньше всякого ответа; его
        # прогонщик набора предъявляет тот же лист службы. Стенд чарта листа от
        # этих дверей не требует, и его лист службы выписан для роли сервера:
        # предъявлять его там значило бы менять условие, при котором посев доказан.
        if present_service_leaf:
            self.ctx.load_cert_chain(str(pki / "srv.crt"), str(pki / "srv.key"))

    def _grpcurl(self, leaf: str, proto: str, method: str, body: dict,
                 headers: tuple[str, ...] = ()) -> tuple[int, str]:
        args = ["grpcurl", "-insecure", "-max-time", "20",
                "-cert", str(self.pki / f"{leaf}.crt"), "-key", str(self.pki / f"{leaf}.key"),
                "-import-path", str(self.proto), "-proto", proto]
        for h in headers:
            args += ["-H", h]
        args += ["-d", json.dumps(body), self.grpc, method]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            raise Unmet(f"{self.grpc} не ответил за 60 с ({method})") from None
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0 and ("connection refused" in out or "context deadline" in out
                                     or "no such host" in out):
            raise Unmet(f"{self.grpc} недостижим: {out.strip()[:200]}")
        return proc.returncode, proc.stdout if proc.returncode == 0 else out

    def mint(self) -> dict:
        rc, out = self._grpcurl("srv", BOOTSTRAP_PROTO, BOOTSTRAP_METHOD, {})
        if rc != 0:
            raise Finding(f"чеканка бутстрапа отказала (grpcurl rc={rc}): {out.strip()[:300]}")
        return json.loads(out or "{}")

    def create_client(self, principal_id: str, name: str, redirects: list[str]) -> tuple[int, str]:
        return self._grpcurl(
            "edge", CREATE_PROTO, CREATE_METHOD,
            {"name": name, "redirect_uris": redirects},
            (f"{PRINCIPAL_TYPE_MD}: service_account", f"{PRINCIPAL_ID_MD}: {principal_id}"))

    def http(self, url: str, *, method: str = "GET", headers: dict | None = None,
             form: dict | None = None) -> tuple[int, dict, str]:
        """(код, заголовки, тело). Перенаправлению НЕ следуем: предмет — сам `302`."""
        data = None
        hdrs = dict(headers or {})
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
                return None

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ctx), _NoRedirect)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with opener.open(req, timeout=30) as r:
                return r.status, dict(r.headers.items()), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()), e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, ssl.SSLError, OSError, socket.timeout) as e:
            raise Unmet(f"{url.split('?')[0]} недостижим: {e}") from None


# ─────────────────────────── шаги посева ─────────────────────────────────────


def bootstrap(stand) -> tuple[str, str]:
    """Машинный `system_admin`, которого фронт ПРИНЯЛ: (токен, идентификатор)."""
    body = stand.mint()
    token, principal = body.get("accessToken") or "", body.get("principalId") or ""
    if not token or not principal:
        raise Finding(f"чеканка ответила без accessToken либо principalId: ключи {sorted(body)}")
    code, _, text = stand.http(f"{stand.own}/iam/v1/accounts?pageSize=1",
                               headers={"Authorization": "Bearer " + token})
    if code != 200:
        raise Finding(f"собственный фронт НЕ ПРИНЯЛ бутстрап-удостоверение: код {code} "
                      f"({message_of(text)!r}) — пересылать принципал, которого фронт не "
                      f"признаёт, посев не вправе")
    return token, principal


def create_confidential(stand, principal: str, name: str, redirects: list[str]) -> tuple[str, str]:
    """Конфиденциальный клиент глаголом `Create`: (clientId, секрет)."""
    rc, out = stand.create_client(principal, name, redirects)
    if rc != 0:
        raise Finding(f"Create {name}: глагол отказал (grpcurl rc={rc}): {out.strip()[:300]}")
    try:
        op = json.loads(out or "{}")
    except json.JSONDecodeError:
        raise Finding(f"Create {name}: ответ не JSON") from None
    if not op.get("done") or op.get("error"):
        raise Finding(f"Create {name}: операция не завершилась успехом синхронно "
                      f"(done={op.get('done')!r}, error={op.get('error')!r}) — секрет "
                      f"показывается ТОЛЬКО ответом вызова, и опрашивать его нечем")
    resp = op.get("response") or {}
    client = resp.get("interactiveClient") or {}
    method = client.get("tokenEndpointAuthMethod", "")
    secret, client_id = resp.get("clientSecret") or "", client.get("clientId") or ""
    if method != SECRET_METHOD:
        raise Finding(f"Create {name}: способ {method!r}, а посадка own заводит клиента "
                      f"конфиденциальным ({SECRET_METHOD}, Р3) — церемонии нечем доказать клиента")
    if not secret or not client_id:
        raise Finding(f"Create {name}: способ секретом, а {'секрета' if not secret else 'clientId'} "
                      f"в ответе вызова нет (Р4: непуст ровно тогда, когда способ — секретом)")
    if sorted(client.get("redirectUris") or []) != sorted(redirects):
        raise Finding(f"Create {name}: адреса возврата не совпали с заведёнными")
    return client_id, secret


def human_session(lane, email: str, password: str) -> tuple[str, str]:
    """Вход паролем через полосу: (печенье сессии, идентификатор человека)."""
    token, ctx = form_token(lane, "login")
    code, sc, text = lane.ask("POST", "/iam/v1/auth/login",
                              body={"email": email, "password": password, "csrfToken": token},
                              cookies={"kaname_form": ctx})
    if code != 200:
        raise Finding(f"вход человека стенда: ждали 200, получили {code} ({message_of(text)!r}) — "
                      f"посев полосы входа (`seed-login-lane`) доказал этот же вход раньше")
    session = cookie_value(sc, "kaname_session")
    try:
        body = json.loads(text or "{}")
    except json.JSONDecodeError:
        body = {}
    user = (body.get("user") or {}).get("id") or ""
    if not session or not user:
        raise Finding("вход ответил 200 без печенья kaname_session либо без user.id")
    return session, user


def authorize(stand, client_id: str, redirect: str, session: str) -> tuple[str, str]:
    """Код авторизации: (код, code_verifier). `302` на адрес возврата, `state` дословно."""
    verifier = b64u(secrets.token_bytes(32))
    state = b64u(secrets.token_bytes(STATE_BYTES))
    challenge = b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "scope": "openid", "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256"})
    code, hdrs, text = stand.http(f"{stand.issuance}/iam/v1/authorize?{q}",
                                  headers={"Cookie": "kaname_session=" + session})
    loc = next((v for k, v in hdrs.items() if k.lower() == "location"), "")
    if code != 302 or not loc:
        raise Finding(f"авторизация: ждали 302 с Location, получили {code} "
                      f"({message_of(text)!r})")
    base, _, query = loc.partition("?")
    got = urllib.parse.parse_qs(query.split("#")[0])
    if base != redirect or got.get("state") != [state] or len(got.get("code", [])) != 1:
        raise Finding(f"авторизация: перенаправление не на адрес возврата, без ровно одного "
                      f"кода либо без state дословно (error={got.get('error')})")
    return got["code"][0], verifier


def exchange(stand, client_id: str, secret: str, code: str, verifier: str,
             redirect: str) -> str:
    """Обмен кода секретом клиента схемой Basic (RFC 6749 §2.3.1): токен доступа."""
    basic = base64.b64encode((urllib.parse.quote(client_id, safe="") + ":"
                              + urllib.parse.quote(secret, safe="")).encode()).decode()
    status, _, text = stand.http(
        f"{stand.issuance}/iam/v1/token", method="POST",
        headers={"Authorization": "Basic " + basic, "Accept": "application/json"},
        form={"grant_type": "authorization_code", "code": code,
              "redirect_uri": redirect, "code_verifier": verifier})
    if status != 200:
        raise Finding(f"обмен кода: ждали 200, получили {status} ({message_of(text)!r})")
    try:
        token = json.loads(text or "{}").get("access_token") or ""
    except json.JSONDecodeError:
        token = ""
    if not token:
        raise Finding("обмен кода ответил 200 без access_token")
    return token


def assert_human(stand, token: str, user: str) -> str:
    """Фронт принимает токен, и субъект — ТОТ человек. Возвращает почту."""
    code, _, text = stand.http(f"{stand.own}/iam/v1/me",
                               headers={"Authorization": "Bearer " + token})
    if code != 200:
        raise Finding(f"собственный фронт НЕ ПРИНЯЛ токен церемонии: код {code} "
                      f"({message_of(text)!r})")
    try:
        me = json.loads(text or "{}")
    except json.JSONDecodeError:
        me = {}
    if me.get("subject") != "user:" + user or me.get("userId") != user:
        raise Finding(f"токен церемонии принят, а субъект — не вошедший человек "
                      f"(subject={me.get('subject')!r})")
    return str(me.get("email") or "")


def seed(stand, lane, email: str, password: str, suffix: str) -> dict:
    """Семь шагов; результат — значения ключей (секреты в журнал не уезжают)."""
    _, principal = bootstrap(stand)
    say("  ok   машинный system_admin выкован чеканкой и принят фронтом")
    cid, csec = create_confidential(stand, principal, f"ceremony-a-{suffix}",
                                    [REDIRECT, REDIRECT_ALT])
    oid, osec = create_confidential(stand, principal, f"ceremony-b-{suffix}", [REDIRECT])
    say("  ok   два конфиденциальных клиента заведены глаголом Create (способ секретом)")
    session, user = human_session(lane, email, password)
    say("  ok   человек вошёл паролем через полосу")
    code, verifier = authorize(stand, cid, REDIRECT, session)
    say("  ok   точка авторизации выдала код перенаправлением")
    token = exchange(stand, cid, csec, code, verifier, REDIRECT)
    say("  ok   код обменян секретом клиента на токен")
    shown = assert_human(stand, token, user)
    say("  ok   собственный фронт принял токен, субъект — вошедший человек")
    return {"iamRegistryTokenBaseUrl": stand.issuance, "ownRestBaseUrl": stand.own,
            "oauthClientId": cid, "oauthClientSecret": csec,
            "oauthRedirectUri": REDIRECT, "oauthRedirectUriAlt": REDIRECT_ALT,
            "oauthOtherClientId": oid, "oauthOtherClientSecret": osec,
            "jwtHumanCeremony": token, "ceremonyUserId": user,
            "ceremonyEmail": shown or email}


# ─────────────────────────── волна церемонии ─────────────────────────────────


TOTP_STEP_S = 30
TOTP_DIGITS = 6
SECOND_FACTOR_FORM = "second-factor"
ENROLL = "/iam/v1/auth/second-factor/enroll"
CONFIRM = "/iam/v1/auth/second-factor/confirm"


def totp(secret_b32: str, step: int) -> str:
    """Код по времени RFC 6238: HMAC-SHA1, шесть цифр, шаг 30 с (Ф12-08)."""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    value = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(value).zfill(TOTP_DIGITS)


def token_claims(token: str) -> dict:
    """Состав выданного токена — без проверки подписи: подпись проверяет фронт,
    которому токен предъявляется (`assert_human`), а здесь читается только то,
    что выдача назначила."""
    parts = token.split(".")
    if len(parts) != 3:
        raise Finding("выданный токен — не JWT из трёх частей: уровень и субъект "
                      "прочесть не из чего")
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        raise Finding("состав выданного токена не разбирается") from None
    if not isinstance(claims, dict):
        raise Finding("состав выданного токена — не объект")
    return claims


def new_human(lane, mailbox, email: str, password: str,
              sleep=time.sleep) -> tuple[str, str]:
    """Человек заводится глаголами полосы: регистрация → подтверждение адреса
    кодом письма → вход. Возвращает (носитель сессии уровня «1», id человека).

    Письмо регистрации ставится тем же исходом глагола, а в приёмник приходит
    позже ответа: его ЖДУТ здесь, а не просят второе. Второе письмо раньше
    интервала Р9 служба отвергает (`429`), и посев, прочитавший приёмник один
    раз, падал бы по жребию доставки. Форма — та же, что у полосы входа
    (`seed_login_lane.seed`)."""
    lane_seed.register(lane, email, password)
    own_seed.await_code(mailbox, email, 0, sleep)
    first = lane_seed.login(lane, email, password)
    if first is None:
        raise Finding("вход сразу после регистрации отвергнут (401) — человек, "
                      "которого продукт только что завёл, не входит своим паролем")
    if not first["verified"]:
        lane_seed.verify_address(lane, mailbox, email, first["bearer"], sleep)
    return human_session(lane, email, password)


def level2_session(lane, session: str) -> str:
    """Второй фактор: заведение → подтверждение кодом по времени. Подтверждение
    перевыпускает сессию уровнем «2» (Ф12-02) — её носитель и возвращается."""
    token, ctx = form_token(lane, SECOND_FACTOR_FORM, {"kaname_session": session})
    cookies = {"kaname_form": ctx, "kaname_session": session}
    code, _, text = lane.ask("POST", ENROLL, body={"csrfToken": token}, cookies=cookies)
    if code != 200:
        raise Finding(f"заведение второго фактора: ждали 200, получили {code} "
                      f"({message_of(text)!r})")
    try:
        secret = json.loads(text or "{}").get("secret") or ""
    except json.JSONDecodeError:
        secret = ""
    if not isinstance(secret, str) or not secret:
        raise Finding("заведение второго фактора ответило 200 без секрета — "
                      "кода по времени вычислить не из чего")
    code, sc, text = lane.ask("POST", CONFIRM,
                              body={"code": totp(secret, int(time.time()) // TOTP_STEP_S),
                                    "csrfToken": token},
                              cookies=cookies)
    if code != 200:
        raise Finding(f"подтверждение второго фактора кодом по времени: ждали 200, "
                      f"получили {code} ({message_of(text)!r})")
    try:
        level = (json.loads(text or "{}").get("session") or {}).get("assuranceLevel")
    except (json.JSONDecodeError, AttributeError):
        level = None
    raised = cookie_value(sc, "kaname_session")
    if level != "2" or not raised:
        raise Finding(f"подтверждение второго фактора: уровень сессии {level!r} и "
                      f"носитель {'перевыпущен' if raised else 'НЕ перевыпущен'} — "
                      f"уровня «2» подтверждение не дало (Ф12-02)")
    return raised


def ceremony_bearer(stand, client: tuple[str, str], session: str, user: str,
                    level: str) -> tuple[str, str]:
    """Церемония под сессией: код → обмен → приём фронтом. Уровень и субъект
    токена утверждаются по его составу. → (токен, почта по фронту)."""
    cid, csec = client
    code, verifier = authorize(stand, cid, REDIRECT, session)
    token = exchange(stand, cid, csec, code, verifier, REDIRECT)
    claims = token_claims(token)
    if str(claims.get("acr")) != level:
        raise Finding(f"церемония под сессией уровня «{level}» выдала токен уровня "
                      f"{claims.get('acr')!r} — уровень токена обязан быть уровнем сессии")
    if claims.get("sub") != user or claims.get("kaname_principal_type") != "user":
        raise Finding("церемония выдала токен не того субъекта либо не человеку")
    return token, assert_human(stand, token, user)


def slot_slug(slot: str) -> str:
    """Слот → часть адреса почты: `AccRdDerive` → `acc-rd-derive`."""
    out = []
    for ch in slot:
        if ch.isupper() and out:
            out.append("-")
        out.append(ch.lower())
    return "".join(out)


def seed_wave(stand, lane, http, mailbox, suffix: str, domain: str,
              sleep=time.sleep) -> dict:
    """Волна церемонии: клиенты, люди и их предъявители обоих уровней. `sleep` —
    паузы ожидания письма; самопроверка подаёт часы подставного мира."""
    boot, principal = bootstrap(stand)
    say("  ok   машинный system_admin выкован чеканкой и принят фронтом")
    cid, csec = create_confidential(stand, principal, f"ceremony-a-{suffix}",
                                    [REDIRECT, REDIRECT_ALT])
    oid, osec = create_confidential(stand, principal, f"ceremony-b-{suffix}", [REDIRECT])
    say("  ok   два конфиденциальных клиента заведены глаголом Create (способ секретом)")
    client = (cid, csec)
    values = {"iamRegistryTokenBaseUrl": stand.issuance, "ownRestBaseUrl": stand.own,
              "oauthClientId": cid, "oauthClientSecret": csec,
              "oauthRedirectUri": REDIRECT, "oauthRedirectUriAlt": REDIRECT_ALT,
              "oauthOtherClientId": oid, "oauthOtherClientSecret": osec}
    people: dict[str, str] = {}

    def person(tag: str) -> tuple[str, str, str]:
        email = f"ceremony-{tag}-{suffix}@{domain}"
        session, user = new_human(lane, mailbox, email, secrets.token_urlsafe(24), sleep)
        if user in people.values():
            raise Finding(f"человек «{tag}» получил идентификатор уже заведённого — "
                          f"слоты волны перестали быть разными людьми")
        people[tag] = user
        return email, session, user

    email, s1, user = person("main")
    l1, shown = ceremony_bearer(stand, client, s1, user, "1")
    l2, _ = ceremony_bearer(stand, client, level2_session(lane, s1), user, "2")
    tenant = own_seed.resolve_tenant(http, stand.own, boot, email)
    if tenant["userId"] != user:
        raise Finding("личный аккаунт найден у другого человека, чем вошедший")
    values.update({"jwtHumanCeremony": l1, "jwtHumanCeremonyStepUp": l2,
                   "ceremonyUserId": user, "ceremonyEmail": shown or email,
                   "ceremonyAccountId": tenant["accountId"]})
    say("  ok   человек церемонии: предъявители уровней «1» и «2», личный аккаунт")

    _, sn, nob = person("nobind")
    values["jwtHumanCeremonyNoBindings"], _ = ceremony_bearer(stand, client, sn, nob, "1")
    values["ceremonyNoBindingsUserId"] = nob
    say("  ok   второй человек — без выдач на арендаторах посева")

    values["ceremonyInviteeEmail"], _, values["ceremonyInviteeUserId"] = person("invitee")
    say("  ok   человек для приглашения — адрес подтверждён, выдач нет")

    for slot in ADMISSION_SLOTS:
        _, ss, su = person(slot_slug(slot))
        k1, k2, kid = slot_keys(slot)
        values[k1], _ = ceremony_bearer(stand, client, ss, su, "1")
        values[k2], _ = ceremony_bearer(stand, client, level2_session(lane, ss), su, "2")
        values[kid] = su
    say(f"  ok   слоты заведения аккаунта: {len(ADMISSION_SLOTS)} людей, у каждого "
        f"предъявители уровней «1» и «2»")
    say(f"  ok   людей заведено {len(people)}, все разные")
    return values


BASE_KEYS = MINTED_ADDRESSES + MINTED_CLIENTS + MINTED_CEREMONY


def env_patch(values: dict, keys: tuple[str, ...] = BASE_KEYS) -> dict:
    """ЧИСТАЯ функция — что уезжает в окружение; её судит самопроверка."""
    return {k: values[k] for k in keys}


def credentials() -> tuple[str, str]:
    email, password = os.environ.get(ENV_EMAIL, ""), os.environ.get(ENV_PASSWORD, "")
    if not email or not password:
        raise Unmet(f"стенд не передал человека: {ENV_EMAIL} и {ENV_PASSWORD} обязаны быть "
                    f"непусты (их выносит из Secret стенда `stand-chart.sh seed-ceremony`)")
    return email, password


def run(args: argparse.Namespace) -> int:
    for name in ("lane_url", "issuance_url", "own_url", "grpc_addr", "pki"):
        if not getattr(args, name):
            raise Unmet(f"не назван --{name.replace('_', '-')} — поверхности, которую сеять, нет")
    pki = pathlib.Path(args.pki)
    env_file = pathlib.Path(args.env_file)
    stand = Surfaces(pki, args.grpc_addr, args.issuance_url, args.own_url, ROOT / "proto",
                     present_service_leaf=args.wave)
    # Полоса — тем же клиентом, что у посева полосы входа, и с ТЕМ ЖЕ адресом
    # источника: оба — посевы, а не наборы, и окно частоты наборов они не трогают.
    lane = LaneHttp(args.lane_url, pki)

    if args.wave:
        if not args.mailbox_url:
            raise Unmet("не назван --mailbox-url — код подтверждения адреса заводимых "
                        "людей читать неоткуда")
        values = seed_wave(stand, lane, own_seed.Http(pki), own_seed.Mailbox(args.mailbox_url),
                           secrets.token_hex(4), args.email_domain)
        keys = MINTED_KEYS
    else:
        email, password = credentials()
        values = seed(stand, lane, email, password, secrets.token_hex(4))
        keys = BASE_KEYS
    patch = env_patch(values, keys)
    replaced = write_env(patch, env_file, pathlib.Path(args.env_template))
    say(f"посев церемонии: ключей записано {len(patch)} (заменено {replaced}) в {env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


class _FakeStand:
    """Подставной стенд: законный мир, в котором каждая инъекция меняет ОДИН факт."""

    issuance, own = "https://127.0.0.1:1", "https://127.0.0.1:2"

    def __init__(self, **inject):
        self.inj = inject
        self.clients: dict[str, tuple[str, list[str]]] = {}
        self.codes: dict[str, str] = {}

    def mint(self):
        if self.inj.get("mint_down"):
            raise Unmet("127.0.0.1:3 недостижим: connection refused")
        return {"accessToken": "boot", "principalId": "svaboot"}

    def create_client(self, principal, name, redirects):
        n = len(self.clients) + 1
        method = self.inj.get("method", SECRET_METHOD)
        secret = "" if self.inj.get("no_secret") else f"sec{n}"
        self.clients[f"oic{n}"] = (secret, list(redirects))
        op = {"done": not self.inj.get("not_done"), "response": {
            "interactiveClient": {"clientId": f"oic{n}", "tokenEndpointAuthMethod": method,
                                  "redirectUris": list(redirects)},
            "clientSecret": secret}}
        if self.inj.get("op_error"):
            op = {"done": True, "error": {"code": 6, "message": "already exists"}}
        return 0, json.dumps(op)

    def http(self, url, *, method="GET", headers=None, form=None):
        headers = headers or {}
        if url.startswith(self.own + "/iam/v1/accounts"):
            ok = headers.get("Authorization") == "Bearer boot" and not self.inj.get("boot_refused")
            return (200, {}, '{"accounts":[]}') if ok else (401, {}, '{"message":"unauth"}')
        if url.startswith(self.issuance + "/iam/v1/authorize"):
            q = urllib.parse.parse_qs(url.split("?", 1)[1])
            if self.inj.get("no_redirect"):
                return 400, {}, '{"message":"invalid_request"}'
            code = "code1"
            self.codes[code] = q["client_id"][0]
            state = "wrong" if self.inj.get("state_changed") else q["state"][0]
            loc = f"{q['redirect_uri'][0]}?code={code}&state={state}"
            return 302, {"Location": loc}, ""
        if url == self.issuance + "/iam/v1/token":
            raw = base64.b64decode(headers["Authorization"].split()[1]).decode()
            cid, sec = (urllib.parse.unquote(x) for x in raw.split(":", 1))
            if self.inj.get("exchange_refused") or self.clients.get(cid, ("",))[0] != sec:
                return 401, {}, '{"error":"invalid_client"}'
            return 200, {}, '{"access_token":"human"}'
        if url == self.own + "/iam/v1/me":
            if self.inj.get("me_refused"):
                return 401, {}, '{"message":"unauthenticated"}'
            uid = "usrother" if self.inj.get("other_subject") else "usrhuman"
            return 200, {}, json.dumps({"subject": "user:" + uid, "userId": uid,
                                        "email": "h@stand.invalid"})
        return 404, {}, "{}"


class _FakeLane:
    def __init__(self, login_code=200):
        self.login_code = login_code

    def ask(self, method, path, body=None, cookies=None):
        if path.startswith("/iam/v1/auth/csrf"):
            return 200, ["kaname_form=ctx; Path=/"], '{"csrfToken":"t"}'
        if path == "/iam/v1/auth/login":
            if self.login_code != 200:
                return self.login_code, [], '{"message":"credentials are not accepted"}'
            return 200, ["kaname_session=s; Path=/"], '{"user":{"id":"usrhuman"}}'
        return 404, [], "{}"


def _outcome(fn) -> tuple[str, str]:
    try:
        return "ok", json.dumps(fn())
    except FINDINGS as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)


# ─── подставной мир волны: полоса, приёмник писем, стенд и фронт одной памятью ─


def _fake_jwt(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return "e30." + body + ".sig"


class _WaveWorld:
    """Законный мир волны: люди заводятся регистрацией, адрес подтверждается кодом
    письма, второй фактор — кодом по времени; уровень сессии уезжает в токен.
    Каждая инъекция меняет ОДИН факт.

    ПИСЬМО — НЕ СИНХРОННО, И ВТОРОЕ РАНЬШЕ ИНТЕРВАЛА НЕ ВЫДАЁТСЯ, как на стенде.
    Служба сдаёт письмо узлу после ответа глагола, и в приёмнике оно появляется
    позже (`letter_lag` секунд часов мира; по умолчанию — меньше одного шага
    опроса письма, законно — любое в пределах бюджета ожидания). Запрос письма раньше `RESEND_S` после предыдущего отвечает
    `429 too many attempts; try again later` (Р9, kaname#456; величина — та, что
    ставит стенд: `stand-own.sh`, VERIFICATION_RESEND_INTERVAL). Мир, кладущий
    письмо в тот же миг, снисходительнее продукта: посев, просящий второе письмо
    раньше срока, проходил бы здесь и падал бы на стенде по жребию доставки.
    Часы — свои (`sleep` двигает `now`): ожидание по ним не стоит настоящего
    времени и не зависит от него."""

    SECRET = "JBSWY3DPEHPK3PXP"
    RESEND_S = 60

    def __init__(self, **inject):
        self.inj = inject
        self.now = 0.0
        self.lag = float(inject.get("letter_lag", 1))
        self.people: dict[str, dict] = {}
        self.letters: dict[str, list[tuple[float, str]]] = {}
        self.sent_at: dict[str, float] = {}
        self.requests = 0
        self.codes: dict[str, tuple[str, str]] = {}
        self.base = _FakeStand()
        self.issuance, self.own = self.base.issuance, self.base.own

    # часы мира
    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def _send(self, email: str) -> None:
        self.sent_at[email] = self.now
        if not self.inj.get("no_letter"):
            self.letters.setdefault(email, []).append(
                (self.now + self.lag, "Код подтверждения:\n4242\n"))

    # полоса
    def _uid(self, n: int) -> str:
        return "usr" + ("same" if self.inj.get("same_id") and n > 1 else f"{n:04d}")

    def ask(self, method, path, body=None, cookies=None):
        cookies = cookies or {}
        sess = cookies.get("kaname_session", "")
        if path.startswith("/iam/v1/auth/csrf"):
            return 200, ["kaname_form=ctx; Path=/"], '{"csrfToken":"t"}'
        if path == "/iam/v1/auth/register":
            uid = self._uid(len(self.people) + 1)
            self.people[body["email"]] = {"id": uid, "pw": body["password"], "verified": False}
            self._send(body["email"])
            return 200, [f"kaname_session=s1-{uid}; Path=/"], "{}"
        if path == "/iam/v1/auth/login":
            who = self.people.get(body["email"])
            if not who or who["pw"] != body["password"]:
                return 401, [], '{"message":"credentials are not accepted"}'
            return 200, [f"kaname_session=s1-{who['id']}; Path=/"], json.dumps(
                {"user": {"id": who["id"]}, "session": {"emailVerified": who["verified"]}})
        if path == "/iam/v1/auth/verify-email":
            self.requests += 1
            email = next(e for e, w in self.people.items() if sess.endswith("-" + w["id"]))
            if self.now - self.sent_at[email] < self.RESEND_S:
                return 429, [], '{"message":"too many attempts; try again later"}'
            self._send(email)
            return 200, [], "{}"
        if path == "/iam/v1/auth/verify-email/confirm":
            for who in self.people.values():
                if sess.endswith("-" + who["id"]) and body.get("code") == "4242":
                    who["verified"] = True
                    return 200, [], '{"session":{"emailVerified":true}}'
            return 401, [], '{"message":"authentication failed"}'
        if path == ENROLL:
            if self.inj.get("no_secret"):
                return 200, [], '{"otpauthUri":"otpauth://totp/x"}'
            return 200, [], json.dumps({"secret": self.SECRET, "expiresAt": "2099-01-01T00:00:00Z"})
        if path == CONFIRM:
            step = int(time.time()) // TOTP_STEP_S
            if body.get("code") not in {totp(self.SECRET, step + d) for d in (-1, 0, 1)}:
                return 401, [], '{"message":"authentication failed"}'
            level = "1" if self.inj.get("confirm_level_1") else "2"
            return 200, [f"kaname_session=s{level}-{sess.split('-', 1)[1]}; Path=/"], json.dumps(
                {"session": {"assuranceLevel": level}, "backupCodes": ["A"] * 10})
        return 404, [], "{}"

    # приёмник писем
    def mailbox_letters(self, to):
        return [text for at, text in self.letters.get(to, []) if at <= self.now]

    # стенд: чеканка и клиенты — законные, у подставного стенда базового режима
    def mint(self):
        return self.base.mint()

    def create_client(self, principal, name, redirects):
        return self.base.create_client(principal, name, redirects)

    def http(self, url, *, method="GET", headers=None, form=None):
        headers = headers or {}
        if url.startswith(self.issuance + "/iam/v1/authorize"):
            q = urllib.parse.parse_qs(url.split("?", 1)[1])
            sess = headers.get("Cookie", "").split("kaname_session=", 1)[-1]
            level, uid = sess.split("-", 1)[0][1:], sess.split("-", 1)[1]
            code = f"code{len(self.codes) + 1}"
            self.codes[code] = (uid, level)
            return 302, {"Location": f"{q['redirect_uri'][0]}?code={code}&state={q['state'][0]}"}, ""
        if url == self.issuance + "/iam/v1/token":
            uid, level = self.codes.pop(form["code"])
            if self.inj.get("acr_stuck"):
                level = "1"
            return 200, {}, json.dumps({"access_token": _fake_jwt(
                {"acr": level, "sub": uid, "kaname_principal_type": "user"})})
        if url == self.own + "/iam/v1/me":
            claims = token_claims(headers["Authorization"].split()[1])
            email = next(e for e, w in self.people.items() if w["id"] == claims["sub"])
            return 200, {}, json.dumps({"subject": "user:" + claims["sub"],
                                        "userId": claims["sub"], "email": email})
        return self.base.http(url, method=method, headers=headers, form=form)

    # фронт под бутстрапом (перечни для разрешения арендатора)
    def json_ask(self, url, **kw):
        # Инъекция `foreign_owner`: строка человека по адресу и её личный аккаунт —
        # у ДРУГОГО идентификатора, чем назвал вход.
        row = (lambda w: "usrforeign" if self.inj.get("foreign_owner") else w["id"])
        if "/iam/v1/users?" in url:
            users = [{"id": row(w), "email": e, "inviteStatus": "ACTIVE"}
                     for e, w in self.people.items()]
            return 200, {"users": users}
        if "/iam/v1/accounts?" in url:
            return 200, {"accounts": [{"id": "acc" + w["id"][3:], "ownerUserId": row(w)}
                                      for w in self.people.values()]}
        if "/iam/v1/projects?" in url:
            return 200, {"projects": [{"id": "prj1"}]}
        return 404, {}


class _Mail:
    def __init__(self, world):
        self.world = world

    def letters(self, to):
        return self.world.mailbox_letters(to)


def _census_surface() -> str | None:
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_ceremony_seed", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"iamRegistryTokenBaseUrl", "ownRestBaseUrl"}), mod


def self_test() -> int:
    import tempfile

    print("=== посев церемонии: различение исходов ===")
    E, P = "h@stand.invalid", "correct-horse"

    def go(stand=None, lane=None):
        return _outcome(lambda: seed(stand or _FakeStand(), lane or _FakeLane(), E, P, "t"))

    got = go()
    vals = json.loads(got[1]) if got[0] == "ok" else {}
    _c("(−) законный мир — предъявитель человека выкован, клиенты разные",
       got[0] == "ok" and vals.get("jwtHumanCeremony") == "human"
       and vals.get("oauthClientId") != vals.get("oauthOtherClientId"), f"{got}")
    for label, inj, needle in (
        ("фронт не принял бутстрап", {"boot_refused": True}, "НЕ ПРИНЯЛ бутстрап"),
        ("Create отказал операцией", {"op_error": True}, "не завершилась успехом"),
        ("Create не завершился синхронно", {"not_done": True}, "не завершилась успехом"),
        ("клиент заведён публичным (способ none)", {"method": "none"}, "конфиденциальным"),
        ("способ секретом, секрета в ответе нет", {"no_secret": True}, "Р4"),
        ("авторизация без перенаправления", {"no_redirect": True}, "ждали 302"),
        ("state не возвращён дословно", {"state_changed": True}, "state"),
        ("обмен отвергнут", {"exchange_refused": True}, "обмен кода"),
        ("фронт не принял токен церемонии", {"me_refused": True}, "НЕ ПРИНЯЛ токен"),
        ("субъект токена — другой человек", {"other_subject": True}, "субъект"),
    ):
        got = go(stand=_FakeStand(**inj))
        _c(f"(+) {label} — находка, причина названа", got[0] == "finding" and needle in got[1],
           f"{got}")
    got = go(lane=_FakeLane(login_code=401))
    _c("(+) вход человека отвергнут — находка", got[0] == "finding" and "401" in got[1], f"{got}")
    got = go(stand=_FakeStand(mint_down=True))
    _c("(+) :9091 молчит — условие не создано, а не находка", got[0] == "unmet", f"{got}")

    saved = {k: os.environ.pop(k, None) for k in (ENV_EMAIL, ENV_PASSWORD)}
    got = _outcome(credentials)
    _c("(+) стенд не передал человека — условие не создано", got[0] == "unmet", f"{got}")
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v

    with tempfile.TemporaryDirectory() as tmp:
        got = _outcome(lambda: Surfaces(pathlib.Path(tmp), "127.0.0.1:1", "https://x",
                                        "https://y", ROOT / "proto"))
        _c("(+) листов нет — условие не создано", got[0] == "unmet", f"{got}")

        ok = go()
        patch = env_patch(json.loads(ok[1])) if ok[0] == "ok" else {}
        _c("режим стенда чарта: объявленные ключи = записываемые (в обе стороны)",
           set(patch) == set(BASE_KEYS), f"{sorted(patch)} против {sorted(BASE_KEYS)}")
        env, tmpl = pathlib.Path(tmp) / "env.json", pathlib.Path(tmp) / "tmpl.json"
        tmpl.write_text(json.dumps({"values": [
            {"key": "oauthClientSecret", "value": "", "type": "secret"},
            {"key": "jwtHumanCeremony", "value": "", "type": "secret"}]}), encoding="utf-8")
        write_env(patch, env, tmpl)
        doc = {v["key"]: v for v in json.loads(env.read_text(encoding="utf-8"))["values"]}
        _c("запись доезжает всеми ключами, тип secret у секретов сохранён",
           all(doc.get(k, {}).get("value") for k in BASE_KEYS)
           and doc["oauthClientSecret"].get("type") == "secret"
           and doc["jwtHumanCeremony"].get("type") == "secret", f"{sorted(doc)}")

    print("=== волна церемонии (--wave): различение исходов ===")
    _c("код по времени — вектор RFC 6238 (шаг 1, SHA-1): 287082",
       totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1) == "287082",
       totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1))

    def wave(**inj):
        w = _WaveWorld(**inj)
        return _outcome(lambda: seed_wave(w, w, w, _Mail(w), "t", "stand.invalid",
                                          sleep=w.sleep)), w

    # Предпосылка подставного мира: Р9 в нём ЕСТЬ и различает обе стороны
    # интервала. Без неё проверки ниже зеленели бы и на мире, где второго письма
    # не отвергает никто, — то есть на том, где дефект ненаблюдаем.
    pw = _WaveWorld()
    pw.ask("POST", "/iam/v1/auth/register", body={"email": "p@stand.invalid", "password": "x"})
    early = pw.ask("POST", "/iam/v1/auth/verify-email", body={},
                   cookies={"kaname_session": "s1-usr0001"})
    pw.sleep(_WaveWorld.RESEND_S)
    late = pw.ask("POST", "/iam/v1/auth/verify-email", body={},
                  cookies={"kaname_session": "s1-usr0001"})
    _c("предпосылка мира: письмо раньше интервала Р9 — 429, после интервала — 200",
       early[0] == 429 and "too many attempts" in early[2] and late[0] == 200,
       f"раньше {early[0]}, после {late[0]}")
    lw = _WaveWorld()
    lw.ask("POST", "/iam/v1/auth/register", body={"email": "p@stand.invalid", "password": "x"})
    in_flight = lw.mailbox_letters("p@stand.invalid")
    lw.sleep(own_seed.LETTER_POLL_S)
    arrived = lw.mailbox_letters("p@stand.invalid")
    _c("предпосылка мира: письмо регистрации к первому чтению в пути, через шаг опроса — в приёмнике",
       in_flight == [] and len(arrived) == 1,
       f"к первому чтению {len(in_flight)}, через шаг {len(arrived)}")

    got, world = wave()
    vals = json.loads(got[1]) if got[0] == "ok" else {}
    levels = {k: token_claims(v).get("acr") for k, v in vals.items() if k.startswith("jwt")}
    _c("(−) законный мир волны — записываемые ключи = объявленные (в обе стороны)",
       got[0] == "ok" and set(env_patch(vals, MINTED_KEYS)) == set(MINTED_KEYS)
       and set(vals) == set(MINTED_KEYS), f"{got[0]}: {sorted(set(vals) ^ set(MINTED_KEYS))}")
    _c("(−) уровень каждого предъявителя — по имени слота: `…StepUp` — «2», прочие — «1»",
       bool(levels) and all(lv == ("2" if k.endswith("StepUp") else "1")
                            for k, lv in levels.items()), f"{levels}")
    _c("(−) люди волны разные, и каждый подтвердил адрес",
       len({w["id"] for w in world.people.values()}) == len(world.people) >= 11
       and all(w["verified"] for w in world.people.values()), f"{world.people}")
    _c("(−) письмо регистрации дождано, второго не запрошено ни разу",
       got[0] == "ok" and world.requests == 0, f"запросов письма {world.requests}: {got}")
    # Ось запаздывания письма: обе законные стороны — письмо уже лежит к первому
    # чтению и письмо идёт дольше десятка шагов опроса (в пределах бюджета).
    for label, lag in (("письмо регистрации уже в приёмнике к первому чтению", 0),
                       ("письмо регистрации идёт 30 с", 30)):
        got, world = wave(letter_lag=lag)
        _c(f"(−) {label} — посев молчит, второго письма не просит",
           got[0] == "ok" and world.requests == 0, f"запросов письма {world.requests}: {got}")
    for label, inj, needle in (
        ("подтверждение второго фактора не подняло уровень", {"confirm_level_1": True},
         "уровня «2» подтверждение не дало"),
        ("сессия «2», а токен выдан уровнем «1»", {"acr_stuck": True},
         "уровень токена обязан быть уровнем сессии"),
        ("два человека получили один идентификатор", {"same_id": True},
         "перестали быть разными людьми"),
        ("заведение фактора без секрета", {"no_secret": True}, "без секрета"),
        # Причина — «не дошло», а не отказ Р9: запрос второго письма раньше срока
        # тоже упоминает письмо подтверждения, и по одному слову их не различить.
        ("письмо подтверждения не дошло", {"no_letter": True}, "не дошло до приёмника"),
        ("личный аккаунт у другого человека", {"foreign_owner": True}, "у другого человека"),
    ):
        got, _ = wave(**inj)
        _c(f"(+) {label} — находка, причина названа",
           got[0] == "finding" and needle in got[1], f"{got}")

    try:
        surface, census = _census_surface()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        surface, census = f"<перепись не прочитана: {e}>", None
    _c("поверхность посева = поверхность, которую перепись выводит из адресов посева",
       surface == MINTED_SURFACE, f"перепись {surface!r}, посев {MINTED_SURFACE!r}")
    if census is not None:
        _c("ключи церемонии распознаны переписью как ключи ЦЕРЕМОНИИ, прочие — нет",
           all(census.is_ceremony_key(k) for k in MINTED_CEREMONY + MINTED_WAVE)
           and not any(census.is_ceremony_key(k) for k in MINTED_ADDRESSES + MINTED_CLIENTS),
           f"{[(k, census.is_ceremony_key(k)) for k in MINTED_KEYS]}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: предъявитель человека утверждается исходом каждого из семи шагов, "
          "«поверхность молчит» и «листов нет» отличимы от находки кодом; волна различает "
          "уровень сессии и уровень токена, разных людей и подтверждённый адрес, а письмо "
          "регистрации дожидается, не прося второго раньше интервала Р9; объявленные "
          "ключи сходятся с записью в обоих режимах, а поверхность и природа ключей — с "
          "переписью долга.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    env = os.environ.get
    ap.add_argument("--lane-url", default=env("KANAME_CEREMONY_LANE_URL", ""),
                    help="адрес полосы входа (лист края)")
    ap.add_argument("--issuance-url", default=env("KANAME_CEREMONY_ISSUANCE_URL", ""),
                    help="адрес поверхности выдачи (:9096): авторизация и токен-эндпоинт")
    ap.add_argument("--own-url", default=env("KANAME_CEREMONY_OWN_URL", ""),
                    help="адрес собственного публичного фронта (:9098)")
    ap.add_argument("--grpc-addr", default=env("KANAME_CEREMONY_GRPC_ADDR", ""),
                    help="host:port внутреннего gRPC (:9091)")
    ap.add_argument("--pki", default=env("KANAME_CEREMONY_PKI", ""),
                    help="каталог с ca.crt, srv.crt/.key (лист службы) и edge.crt/.key (лист края)")
    ap.add_argument("--env-file",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.json"))
    ap.add_argument("--env-template",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.template.json"))
    ap.add_argument("--wave", action="store_true",
                    help="волна церемонии автономного стенда: посев сам заводит людей "
                         "(регистрация, подтверждение адреса, второй фактор) и пишет все "
                         "ключи волны; без флага — человек стенда чарта из окружения")
    ap.add_argument("--mailbox-url", default=env("KANAME_CEREMONY_MAILBOX_URL", ""),
                    help="адрес чтения приёмника писем стенда (для --wave)")
    ap.add_argument("--email-domain", default="kaname.local",
                    help="домен адресов заводимых людей (для --wave)")
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
        return run(args)
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}", file=sys.stderr)
        print("Посев не состоялся по причине, не относящейся к дереву: вердикта о продукте "
              "нет НИ ОДНОГО.", file=sys.stderr)
        return RC_UNMET
    except FINDINGS as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
