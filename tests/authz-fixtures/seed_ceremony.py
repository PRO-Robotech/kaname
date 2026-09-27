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

ГДЕ ОН ИСПОЛНЯЕТСЯ. На стенде чарта посадки `own`
(`KANAME_STAND_IDENTITY_PROVIDER=own .github/scripts/stand-chart.sh`): зовёт его
подкоманда `seed-ceremony` того же скрипта ПОСЛЕ `seed-login-lane`. Подкоманда
выносит из Secret стенда листы, человека и поднимает переадресации поверхностей;
адреса, по которым посев доказал способность, уезжают в окружение.

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

ЧТО ПИШЕТСЯ — объявлено ниже и выдаётся флагом `--minted-keys`: адреса двух
поверхностей, по которым шаги доказаны; два конфиденциальных клиента с адресами
возврата (их читает набор `kaname-authorization-code`); предъявитель человека
уровня 1 и его идентификатор и почта (ключи волны церемонии). Чего НЕ пишется и
почему: предъявителей повышенного уровня (`*StepUp`) — второй фактор посевом не
проходится; второго человека без выдач — у стенда один человек полосы.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — предъявитель человека выкован и принят фронтом, окружение записано;
    1  — НАХОДКА: продукт ответил не по контракту там, где посев предъявил всё,
         чего контракт требует. Вердикт о дереве;
   75  — УСЛОВИЕ НЕ СОЗДАНО: поверхность недостижима, листа нет, нет `grpcurl`,
         стенд не передал человека. Вердикта о дереве нет НИ ОДНОГО.

СЕКРЕТЫ НЕ ПЕЧАТАЮТСЯ НИКОГДА — ни пароль, ни секрет клиента, ни токен: журнал
прогона публичного репозитория читает кто угодно. Пароль и почта приходят
переменными окружения процесса, а не аргументами.

САМОПРОВЕРКА — `--self-test`: подставной стенд по каждой оси, где каждая
инъекция меняет ОДИН факт против законного мира; сходимость объявленных ключей
с записью в обе стороны; поверхность — та, что выводит перепись долга.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
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
MINTED_KEYS = MINTED_ADDRESSES + MINTED_CLIENTS + MINTED_CEREMONY

# Поверхность, которой зачитываются эти ключи: у собственных HTTP-дверей службы
# ярлык переписи один. Самопроверка сверяет строку с выводом переписи.
MINTED_SURFACE = "служба (собственный REST-фронт)"

ENV_EMAIL = "KANAME_STAND_LANE_EMAIL"
ENV_PASSWORD = "KANAME_STAND_LANE_PASSWORD"

# Адреса возврата — те же значения, что у набора интерактивного клиента
# (`cases/iam-interactive-client.py`, GOOD_REDIRECT и GOOD_REDIRECT_2). Слушать по
# ним не нужно: предмет — куда служба СОГЛАСНА доставить код.
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
                 proto_root: pathlib.Path):
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


def env_patch(values: dict) -> dict:
    """ЧИСТАЯ функция — что уезжает в окружение; её судит самопроверка."""
    return {k: values[k] for k in MINTED_KEYS}


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
    email, password = credentials()
    pki = pathlib.Path(args.pki)
    stand = Surfaces(pki, args.grpc_addr, args.issuance_url, args.own_url, ROOT / "proto")
    # Полоса — тем же клиентом, что у посева полосы входа, и с ТЕМ ЖЕ адресом
    # источника: оба — посевы, а не наборы, и окно частоты наборов они не трогают.
    lane = LaneHttp(args.lane_url, pki)

    values = seed(stand, lane, email, password, secrets.token_hex(4))
    patch = env_patch(values)
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев церемонии: ключей записано {len(patch)} (заменено {replaced}) в {args.env_file}")
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
    except Finding as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)


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
        _c("объявленные ключи = записываемые (в обе стороны)", set(patch) == set(MINTED_KEYS),
           f"{sorted(patch)} против {sorted(MINTED_KEYS)}")
        env, tmpl = pathlib.Path(tmp) / "env.json", pathlib.Path(tmp) / "tmpl.json"
        tmpl.write_text(json.dumps({"values": [
            {"key": "oauthClientSecret", "value": "", "type": "secret"},
            {"key": "jwtHumanCeremony", "value": "", "type": "secret"}]}), encoding="utf-8")
        write_env(patch, env, tmpl)
        doc = {v["key"]: v for v in json.loads(env.read_text(encoding="utf-8"))["values"]}
        _c("запись доезжает всеми ключами, тип secret у секретов сохранён",
           all(doc.get(k, {}).get("value") for k in MINTED_KEYS)
           and doc["oauthClientSecret"].get("type") == "secret"
           and doc["jwtHumanCeremony"].get("type") == "secret", f"{sorted(doc)}")

    try:
        surface, census = _census_surface()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        surface, census = f"<перепись не прочитана: {e}>", None
    _c("поверхность посева = поверхность, которую перепись выводит из адресов посева",
       surface == MINTED_SURFACE, f"перепись {surface!r}, посев {MINTED_SURFACE!r}")
    if census is not None:
        _c("ключи церемонии распознаны переписью как ключи ЦЕРЕМОНИИ, прочие — нет",
           all(census.is_ceremony_key(k) for k in MINTED_CEREMONY)
           and not any(census.is_ceremony_key(k) for k in MINTED_ADDRESSES + MINTED_CLIENTS),
           f"{[(k, census.is_ceremony_key(k)) for k in MINTED_KEYS]}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: предъявитель человека утверждается исходом каждого из семи шагов, "
          "«поверхность молчит» и «листов нет» отличимы от находки кодом, объявленные ключи "
          "сходятся с записью, а поверхность и природа ключей — с переписью долга.")
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
    except Finding as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
