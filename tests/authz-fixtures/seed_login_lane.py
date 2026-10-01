#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ЧЕЛОВЕКА ДЛЯ ПОЛОСЫ ВХОДА ПАРОЛЕМ на стенде посадки `own`.

ПРЕДМЕТ. Набор `kaname-login-lane` читает из окружения адрес слушателя формы
(`loginLaneBaseUrl`) и человека со способом входа паролем (`loginLaneEmail`,
`loginLanePassword`). Пока их не пишет никто, каждый шаг набора уходит в
«условие не создано» помеченным утверждением — набор исполняется и не утверждает
ничего. Этот посев пишет все три и четвёртым — адрес чтения приёмника писем
стенда (`standMailboxUrl`), по которому сам доказал код подтверждения: из него
набор восстановления (`kaname-recovery-lane`) читает код письма своих людей.
Больше он не пишет ничего (`MINTED_KEYS`).

ГДЕ ОН ИСПОЛНЯЕТСЯ. На стенде чарта посадки `own`
(`.github/scripts/stand-chart.sh`): зовёт его подкоманда `seed-login-lane` того
же скрипта. Она же выносит из Secret стенда
клиентский лист с именем края и учётные данные человека, поднимает переадресацию
порта полосы и передаёт посеву адрес, по которому посев доказал способность, —
этот адрес и уезжает в окружение.

ВСЁ ДЕЛАЕТСЯ ГЛАГОЛАМИ ПРОДУКТА НА ТОЙ ЖЕ ДВЕРИ, КОТОРУЮ СУДИТ НАБОР. Ни записи в
базу, ни подписи, ни второй поверхности:

  1. вход паролем (`POST /iam/v1/auth/login`) учётными данными из Secret стенда.
     Вошёл — человек уже есть, и посев на этом кончается: повторный прогон на
     том же стенде не заводит второго человека;
  2. иначе регистрация паролем (`POST /iam/v1/auth/register`) — строка личности,
     способ входа и сессия одним исходом глагола;
  3. снова вход — это и есть утверждение посева. Утверждается СПОСОБНОСТЬ
     («этот человек входит этим паролем»), а не наличие строки: регистрация,
     ответившая 200, после которой вход отвергнут, — находка, а не успех;
  4. вход в положении подтверждения (`session.emailVerified: false`,
     kaname#456) — подтверждение адреса глаголом полосы: код из письма, которое
     служба сдала приёмнику писем стенда (`.github/scripts/stand-mailbox.py`),
     предъявляется `POST /iam/v1/auth/verify-email/confirm`; письма в приёмнике
     нет — оно запрашивается `POST /iam/v1/auth/verify-email`. Утверждение —
     следующий вход в ОБЫЧНОМ положении: без него церемония отвечает
     `access_denied`, а второй фактор — отказом положения. Отметку в базу посев
     не пишет.

ПОЧЕМУ ЛИСТ С ИМЕНЕМ КРАЯ ЗАКОНЕН ЗДЕСЬ. Слушатель полосы допускает РОВНО край —
по короткому имени службы из SAN проверенного клиентского листа (Р7, Р16), и
другой двери к форме человека у продукта нет. Прогонщик набора стоит на месте
края: ретранслирует форму и ставит адрес источника. Лист выписывает УЦ стенда, и
посев предъявляет его ТОЛЬКО этой двери — ни одной другой поверхности службы он
не зовёт. Машинный посев автономного стенда (`seed_own_stand.py`) предъявляет
такой же лист по той же причине: под `own` человека заводит только полоса входа,
и лист края он несёт ТОЛЬКО к ней.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — человек входит паролем, окружение записано;
    1  — НАХОДКА: полоса ответила не так, как обещает контракт, на запрос, где
         посев предъявил всё, чего контракт требует. Вердикт о дереве — о службе
         либо о стенде, выписавшем лист;
   75  — УСЛОВИЕ НЕ СОЗДАНО: полоса недостижима, листа нет, стенд не передал
         учётных данных. Вердикта о дереве нет НИ ОДНОГО.

ПАРОЛЬ НЕ ПЕЧАТАЕТСЯ НИКОГДА, почта — тоже: журнал прогона публичного
репозитория читает кто угодно. Оба приходят переменными окружения процесса, а не
аргументами (аргументы видны в перечне процессов машины).

САМОПРОВЕРКА — `--self-test`: подставная полоса по каждой оси — человек есть,
человека нет, лист не края (403), регистрация без носителя, отказ регистрации,
отказ входа после регистрации, полоса молчит, учётных данных нет, ответ 5xx на
входе; подтверждение адреса — код письма регистрации, письмо запрошено, письмо не
дошло, приёмник молчит, код отвергнут, 200 без отметки, вход после кода снова в
положении подтверждения, ответ без положения, и разбор кода из письма с законным
близнецом без строки кода; и сходимость объявленных ключей с записью в обе
стороны, и поверхность, которую выводит перепись долга из самой переменной адреса.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RC_FINDING = 1
RC_UNMET = 75

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Запись окружения — ОДНА на оба посева, а не вторая копия рядом: копия
# разошлась бы с первой молча (иной порядок, иной тип добавленного ключа).
sys.path.insert(0, str(HERE))
from seed_own_stand import (  # noqa: E402
    LETTER_BUDGET_S, Mailbox, Unmet, await_code, code_of, write_env)

# Ключи окружения, которые пишет этот посев. Перепись долга
# (`.github/scripts/newman-suite-debt.py`) спрашивает их у САМОГО посева флагом
# `--minted-keys`; сходимость объявления с записью держит самопроверка.
MINTED_KEYS = ("loginLaneBaseUrl", "loginLaneEmail", "loginLanePassword", "standMailboxUrl")

# Поверхность, которой зачитываются эти ключи. Перепись выводит её у коллекции из
# переменной адреса (`surface_of`), и у всех трёх адресов собственных HTTP-дверей
# службы ярлык один; самопроверка сверяет строку с тем, что выводит перепись.
MINTED_SURFACE = "служба (собственный REST-фронт)"

# Переменные окружения, которыми стенд передаёт человека. Имена — контракт с
# `.github/scripts/stand-chart.sh seed-login-lane`.
ENV_EMAIL = "KANAME_STAND_LANE_EMAIL"
ENV_PASSWORD = "KANAME_STAND_LANE_PASSWORD"

# Адрес источника, который на живом проводе ставит край (Р10). Свой, а не тот,
# что ставит набор (`203.0.113.10`): счёт частоты по источнику у посева и у
# прогона раздельный, и попытки посева не съедают окно набора.
SOURCE = "203.0.113.11"

CSRF = "/iam/v1/auth/csrf"
LOGIN = "/iam/v1/auth/login"
REGISTER = "/iam/v1/auth/register"
VERIFY = "/iam/v1/auth/verify-email"
VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
SESSION_COOKIE = "kaname_session"
FORM_COOKIE = "kaname_form"


class Finding(Exception):
    """Полоса ответила не по контракту там, где посев предъявил требуемое."""


def say(msg: str) -> None:
    print(msg, flush=True)


# ─────────────────────────── транспорт ───────────────────────────────────────


class LaneHttp:
    """Клиент полосы: взаимный TLS листом края и проверка имени сервера.

    Имя сервера ПРОВЕРЯЕТСЯ: снять проверку значило бы перестать проверять то,
    ради чего взаимный TLS на этой посадке и включён.
    """

    def __init__(self, base_url: str, pki: pathlib.Path):
        ca, cert, key = pki / "ca.crt", pki / "edge.crt", pki / "edge.key"
        for f in (ca, cert, key):
            if not f.is_file():
                raise Unmet(f"нет {f} — лист края стенд не выносил")
        self.base = base_url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=str(ca))
        self.ctx.load_cert_chain(str(cert), str(key))

    def ask(self, method: str, path: str, body: dict | None = None,
            cookies: dict | None = None) -> tuple[int, list[str], str]:
        """(код, значения `Set-Cookie`, тело)."""
        hdrs = {"X-Forwarded-For": SOURCE, "Accept": "application/json"}
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
            # Соединение не состоялось — вердикта о дереве нет.
            raise Unmet(f"полоса по адресу {self.base} недостижима: {e}") from None


def cookie_value(set_cookies: list[str], name: str) -> str | None:
    for sc in set_cookies:
        head = sc.split(";", 1)[0]
        if head.startswith(name + "="):
            return head[len(name) + 1:]
    return None


def message_of(text: str) -> str:
    try:
        return str(json.loads(text or "{}").get("message", ""))[:200]
    except (json.JSONDecodeError, AttributeError):
        return text[:200]


# ─────────────────────────── глаголы полосы ──────────────────────────────────


def form_token(http, form: str, cookies: dict | None = None) -> tuple[str, str]:
    """Признак формы и контекст формы (печенье), под которым он выдан."""
    code, sc, text = http.ask("GET", f"{CSRF}?form={form}", cookies=cookies)
    if code == 403:
        raise Finding(
            f"признак формы {form!r}: полоса ответила 403 ({message_of(text)!r}) — "
            f"предъявленный лист не принят как край. Слушатель допускает РОВНО край "
            f"по SAN клиентского листа; лист выписан стендом, и отказ обвиняет либо "
            f"его имя, либо сужение круга у службы")
    if code != 200:
        raise Finding(f"признак формы {form!r}: ждали 200, получили {code} "
                      f"({message_of(text)!r})")
    try:
        token = json.loads(text or "{}").get("csrfToken")
    except json.JSONDecodeError:
        token = None
    ctx = cookie_value(sc, FORM_COOKIE)
    if not isinstance(token, str) or not token or not ctx:
        raise Finding(f"признак формы {form!r}: 200 без признака строкой либо без "
                      f"печенья {FORM_COOKIE} — форму отправить нечем")
    return token, ctx


def position_of(text: str, what: str) -> bool:
    """`session.emailVerified` ответа — положение сессии (kaname#456, Р5).

    Поле обязано быть логическим: ответ, который положения не называет, не
    отличает «подтверждён» от «неизвестно», и посев на нём решал бы наугад.
    """
    try:
        view = json.loads(text or "{}").get("session")
    except (json.JSONDecodeError, AttributeError):
        view = None
    verified = view.get("emailVerified") if isinstance(view, dict) else None
    if not isinstance(verified, bool):
        raise Finding(f"{what}: ответ 200 не называет положение сессии "
                      f"(session.emailVerified логическим значением нет) — "
                      f"подтверждён ли адрес, не сказано")
    return verified


def login(http, email: str, password: str) -> dict | None:
    """Вход. None — 401 («нет», исход контракта); иначе носитель сессии и её
    положение. Прочее не-200 — находка."""
    token, ctx = form_token(http, "login")
    code, sc, text = http.ask("POST", LOGIN,
                              body={"email": email, "password": password,
                                    "csrfToken": token},
                              cookies={FORM_COOKIE: ctx})
    if code == 401:
        return None
    if code != 200:
        raise Finding(f"вход: ждали 200 либо 401, получили {code} "
                      f"({message_of(text)!r})")
    bearer = cookie_value(sc, SESSION_COOKIE)
    if not bearer:
        raise Finding(f"вход ответил 200 без печенья {SESSION_COOKIE} — "
                      f"сессия не выдана, а успех объявлен")
    return {"bearer": bearer, "verified": position_of(text, "вход")}


def register(http, email: str, password: str) -> None:
    token, ctx = form_token(http, "register")
    code, sc, text = http.ask("POST", REGISTER,
                              body={"email": email, "password": password,
                                    "csrfToken": token},
                              cookies={FORM_COOKIE: ctx})
    if code != 200:
        raise Finding(f"регистрация: ждали 200, получили {code} "
                      f"({message_of(text)!r}); вход этими учётными данными "
                      f"перед ней отвергнут — человека на стенде нет и завести его "
                      f"не вышло")
    if not cookie_value(sc, SESSION_COOKIE):
        raise Finding(f"регистрация ответила 200 без печенья {SESSION_COOKIE} — "
                      f"три следствия одним исходом не наступили")


# ─────────────────────────── подтверждение адреса ────────────────────────────
#
# С kaname#456 сессия человека, чей адрес не подтверждён, стоит в ПОЛОЖЕНИИ
# ПОДТВЕРЖДЕНИЯ: дальше входа и экрана подтверждения ей не открыто ничего —
# церемония отвечает `access_denied`, второй фактор и смена пароля — отказом
# положения. Человек стенда, заведённый регистрацией, поэтому доводится до
# подтверждённого адреса ТЕМ ЖЕ глаголом, которым это делает человек: код берётся
# из письма, которое служба сдала почтовому узлу стенда (приёмник писем —
# `.github/scripts/stand-mailbox.py`), и предъявляется полосе. Обратного
# заполнения отметки нет: запись в базу закрыла бы именно то, что судит набор.

# Приёмник писем стенда, разбор кода и ожидание письма — те же, что у
# машинного посева (`seed_own_stand.py`, импорт выше): одна реализация на оба.


def request_letter(http, bearer: str) -> None:
    token, ctx = form_token(http, "verify-email", {SESSION_COOKIE: bearer})
    code, _sc, text = http.ask("POST", VERIFY, body={"csrfToken": token},
                               cookies={FORM_COOKIE: ctx, SESSION_COOKIE: bearer})
    if code != 200:
        raise Finding(f"запрос письма подтверждения: ждали 200, получили {code} "
                      f"({message_of(text)!r})")


def confirm(http, bearer: str, code_value: str) -> None:
    token, ctx = form_token(http, "verify-email-confirm", {SESSION_COOKIE: bearer})
    code, _sc, text = http.ask("POST", VERIFY_CONFIRM,
                               body={"code": code_value, "csrfToken": token},
                               cookies={FORM_COOKIE: ctx, SESSION_COOKIE: bearer})
    if code != 200:
        raise Finding(f"предъявление кода подтверждения из письма: ждали 200, "
                      f"получили {code} ({message_of(text)!r})")
    if position_of(text, "предъявление кода") is not True:
        raise Finding("предъявление кода ответило 200, а session.emailVerified "
                      "не true — отметка не поставлена, а успех объявлен")


def verify_address(http, mailbox, email: str, bearer: str, sleep) -> None:
    """Код из письма, уже лежащего в приёмнике (письмо регистрации), иначе из
    письма, запрошенного глаголом; предъявляется полосе."""
    letters = mailbox.letters(email)
    code_value = code_of(letters[-1]) if letters else None
    if code_value is None:
        request_letter(http, bearer)
        code_value = await_code(mailbox, email, len(letters), sleep)
    if code_value is None:
        raise Finding(f"письмо подтверждения адреса человеку стенда не дошло до "
                      f"приёмника писем стенда за {LETTER_BUDGET_S} с (либо пришло "
                      f"без строки кода) — служба не сдала его узлу, названному "
                      f"посадкой стенда")
    confirm(http, bearer, code_value)


def seed(http, mailbox, email: str, password: str, sleep=time.sleep) -> str:
    """«есть» либо «заведён» (и «адрес подтверждён», если подтверждал посев);
    утверждение — способность войти в обычном положении."""
    session = login(http, email, password)
    state = "есть"
    if session is None:
        register(http, email, password)
        # Письмо регистрации ставится тем же исходом глагола: ждать его здесь,
        # а не запрашивать второе, — иначе промежуток между письмами отвечал бы
        # отказом по частоте.
        await_code(mailbox, email, 0, sleep)
        session = login(http, email, password)
        if session is None:
            raise Finding("регистрация ответила 200, а вход тем же паролем отвергнут "
                          "(401) — человек заведён без способа войти")
        state = "заведён"
    if session["verified"]:
        return state
    verify_address(http, mailbox, email, session["bearer"], sleep)
    session = login(http, email, password)
    if session is None or not session["verified"]:
        raise Finding("код подтверждения принят, а следующий вход снова в положении "
                      "подтверждения (session.emailVerified false) — отметка не "
                      "действует на следующем запросе")
    return state + " · адрес подтверждён"


def env_patch(base_url: str, email: str, password: str, mailbox_url: str) -> dict:
    """ЧИСТАЯ функция — что уезжает в окружение; её судит самопроверка.

    Адрес приёмника писем стенда уезжает ТЕМ ЖЕ посевом, что доказал по нему
    код подтверждения: набор восстановления читает из него код письма
    (`GET /codes`, `.github/scripts/stand-mailbox.py`), и адрес, по которому
    посев не читал, был бы адресом без доказанной способности."""
    return {"loginLaneBaseUrl": base_url.rstrip("/"),
            "loginLaneEmail": email,
            "loginLanePassword": password,
            "standMailboxUrl": mailbox_url.rstrip("/")}


def credentials() -> tuple[str, str]:
    email, password = os.environ.get(ENV_EMAIL, ""), os.environ.get(ENV_PASSWORD, "")
    if not email or not password:
        raise Unmet(f"стенд не передал человека: {ENV_EMAIL} и {ENV_PASSWORD} "
                    f"обязаны быть непусты (их выносит из Secret стенда "
                    f"`stand-chart.sh seed-login-lane`)")
    return email, password


def run(args: argparse.Namespace) -> int:
    email, password = credentials()
    http = LaneHttp(args.base_url, pathlib.Path(args.pki))
    state = seed(http, Mailbox(args.mailbox_url), email, password)
    say(f"  ok   человек стенда {state} и входит паролем через полосу {http.base} "
        f"в обычном положении")
    patch = env_patch(http.base, email, password, args.mailbox_url)
    replaced = write_env(patch, pathlib.Path(args.env_file),
                         pathlib.Path(args.env_template))
    say(f"посев полосы входа: ключей записано {len(patch)} (заменено {replaced}) "
        f"в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


class _FakeLane:
    """Подставная полоса: состояние — кто заведён; ответы — по контракту.

    Каждая инъекция меняет ОДИН факт против законного мира.
    """

    def __init__(self, humans=None, csrf_code=200, register_code=200,
                 register_cookie=True, login_after_register=True, login_code=None,
                 down=False, verified=None, mailbox=None, confirm_code=200,
                 confirm_verifies=True, position_named=True, letter_on_register=True,
                 stays_unverified=False):
        self.humans = dict(humans or {})
        self.csrf_code, self.register_code = csrf_code, register_code
        self.register_cookie = register_cookie
        self.login_after_register = login_after_register
        self.login_code, self.down = login_code, down
        # Отметка адреса — по человеку; письма с кодом — в подставной приёмник
        # стенда, как это делает служба: письмо регистрации ставится тем же
        # исходом, что заводит человека, и жив последний выданный код.
        self.verified = set(verified or ())
        self.mailbox = mailbox if mailbox is not None else _FakeMailbox()
        self.confirm_code, self.confirm_verifies = confirm_code, confirm_verifies
        self.position_named, self.letter_on_register = position_named, letter_on_register
        self.stays_unverified = stays_unverified
        self.live_code: dict[str, str] = {}
        self.registered = self.requested = self.confirmed = 0
        self.base = "https://127.0.0.1:1"

    def _letter(self, email: str) -> None:
        code = f"K{len(self.live_code) + self.requested + 1:04d}-STAND"
        self.live_code[email] = code
        self.mailbox.deliver(email, _letter_text(code))

    def _session(self, email: str) -> tuple[list[str], str]:
        view = {"expiresAt": "2026-01-01T00:00:00Z", "assuranceLevel": 1}
        if self.position_named:
            view["emailVerified"] = email in self.verified
        return [f"{SESSION_COOKIE}=s-{email}; Path=/"], json.dumps({"session": view})

    def ask(self, method, path, body=None, cookies=None):
        if self.down:
            raise Unmet("полоса недостижима: connection refused")
        if path.startswith(CSRF):
            if self.csrf_code != 200:
                return self.csrf_code, [], '{"code":7,"message":"permission denied"}'
            return 200, [f"{FORM_COOKIE}=ctx; Path=/; HttpOnly"], '{"csrfToken":"t"}'
        owner = ((cookies or {}).get(SESSION_COOKIE) or "")[2:]
        if path == LOGIN:
            if self.login_code is not None:
                return self.login_code, [], '{"code":13,"message":"internal"}'
            ok = self.humans.get(body["email"]) == body["password"]
            if ok and (self.registered == 0 or self.login_after_register):
                return (200, *self._session(body["email"]))
            return 401, [], '{"code":16,"message":"credentials are not accepted"}'
        if path == REGISTER:
            self.registered += 1
            if self.register_code != 200:
                return self.register_code, [], '{"code":3,"message":"request not performed"}'
            self.humans[body["email"]] = body["password"]
            if self.letter_on_register:
                self._letter(body["email"])
            sc, text = self._session(body["email"])
            return 200, (sc if self.register_cookie else []), text
        if path == VERIFY:
            if owner not in self.humans:
                return 401, [], '{"code":16,"message":"authentication failed"}'
            self.requested += 1
            self._letter(owner)
            return 200, [], "{}"
        if path == VERIFY_CONFIRM:
            if owner not in self.humans:
                return 401, [], '{"code":16,"message":"authentication failed"}'
            if self.confirm_code != 200:
                return self.confirm_code, [], '{"code":9,"message":"email address is already verified"}'
            if body.get("code") != self.live_code.get(owner):
                return 401, [], '{"code":16,"message":"authentication failed"}'
            self.confirmed += 1
            if self.confirm_verifies and not self.stays_unverified:
                self.verified.add(owner)
            view = {"emailVerified": self.confirm_verifies}
            return 200, [f"{SESSION_COOKIE}=s-{owner}; Path=/"], json.dumps({"session": view})
        return 404, [], "{}"


class _FakeMailbox:
    """Подставной приёмник писем стенда: письма по адресату, по порядку."""

    def __init__(self, down=False, drops=False):
        self.down, self.drops = down, drops
        self.box: dict[str, list[str]] = {}
        self.reads = 0

    def deliver(self, to: str, text: str) -> None:
        if not self.drops:
            self.box.setdefault(to, []).append(text)

    def letters(self, to: str) -> list[str]:
        self.reads += 1
        if self.down:
            raise Unmet("приёмник писем стенда недостижим: connection refused")
        return list(self.box.get(to, []))


def _letter_text(code: str) -> str:
    """Тело письма подтверждения той формы, что собирает служба
    (`internal/clients/invite_mail.go`, RenderVerificationMail)."""
    return ("From: kaname@kaname.local\r\nTo: human@stand.invalid\r\n"
            "Subject: =?UTF-8?B?0JrQvtC0?=\r\n\r\n"
            "Подтвердите адрес почты, чтобы продолжить работу.\r\n\r\n"
            "Код подтверждения:\r\n\r\n"
            f"    {code}\r\n\r\n"
            "Код действует 30 мин. с момента отправки и применяется один раз.\r\n")


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
    """Поверхность, которую перепись долга выводит из переменной адреса полосы."""
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_probe", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"loginLaneBaseUrl"})


def self_test() -> int:
    import tempfile

    E, P = "human@stand.invalid", "correct-horse"
    print("=== посев полосы входа: различение исходов ===")

    def sow(lane, box=None):
        return _outcome(lambda: seed(lane, lane.mailbox if box is None else box, E, P,
                                     sleep=lambda _s: None))

    lane = _FakeLane()
    got = sow(lane)
    _c("(−) человека нет — заведён, адрес подтверждён кодом письма регистрации, и "
       "вход им доказан",
       got == ("ok", "заведён · адрес подтверждён") and lane.registered == 1
       and lane.confirmed == 1 and lane.requested == 0 and E in lane.verified,
       f"{got}, регистраций {lane.registered}, подтверждений {lane.confirmed}, "
       f"запросов письма {lane.requested}")

    lane = _FakeLane(humans={E: P}, verified={E})
    got = sow(lane)
    _c("(−) человек есть и подтверждён — ни регистрации, ни письма, ни кода",
       got == ("ok", "есть") and lane.registered == 0 and lane.confirmed == 0
       and lane.requested == 0 and lane.mailbox.reads == 0,
       f"{got}, регистраций {lane.registered}, подтверждений {lane.confirmed}, "
       f"чтений приёмника {lane.mailbox.reads}")

    print("=== подтверждение адреса человека стенда ===")
    lane = _FakeLane(humans={E: P})
    got = sow(lane)
    _c("(−) человек есть, адрес не подтверждён, письма нет — письмо запрошено "
       "глаголом, код из него принят",
       got == ("ok", "есть · адрес подтверждён") and lane.requested == 1
       and lane.confirmed == 1, f"{got}, запросов {lane.requested}, "
       f"подтверждений {lane.confirmed}")

    got = sow(_FakeLane(mailbox=_FakeMailbox(drops=True)))
    _c("(+) письмо не дошло до приёмника стенда — находка, названы письмо и приёмник",
       got[0] == "finding" and "письм" in got[1] and "приёмник" in got[1], f"{got}")

    got = sow(_FakeLane(mailbox=_FakeMailbox(down=True)))
    _c("(+) приёмник писем стенда молчит — условие не создано, а не находка",
       got[0] == "unmet", f"{got}")

    got = sow(_FakeLane(confirm_code=400))
    _c("(+) предъявление кода отвергнуто — находка с кодом ответа",
       got[0] == "finding" and "400" in got[1], f"{got}")

    got = sow(_FakeLane(confirm_verifies=False))
    _c("(+) код принят (200), а ответ не несёт emailVerified: true — находка",
       got[0] == "finding" and "emailVerified" in got[1], f"{got}")

    got = sow(_FakeLane(stays_unverified=True))
    _c("(+) код принят, а следующий вход снова в положении подтверждения — находка",
       got[0] == "finding" and "положени" in got[1], f"{got}")

    got = sow(_FakeLane(position_named=False))
    _c("(+) вход не называет положение (нет session.emailVerified) — находка",
       got[0] == "finding" and "emailVerified" in got[1], f"{got}")

    got = _outcome(lambda: code_of(_letter_text("ABCDE-FGHIJ")))
    _c("код разбирается из письма той формы, что собирает служба",
       got == ("ok", "ABCDE-FGHIJ"), f"{got}")
    got = _outcome(lambda: code_of("Subject: x\r\n\r\nПодтвердите адрес.\r\n"))
    _c("ЗАКОННЫЙ БЛИЗНЕЦ: письмо без строки кода — кода нет, а не первая строка тела",
       got == ("ok", "None"), f"{got}")

    got = sow(_FakeLane(csrf_code=403))
    _c("(+) лист не края — 403 на признаке формы — находка, названа причина",
       got[0] == "finding" and "край" in got[1], f"{got}")

    got = sow(_FakeLane(register_cookie=False))
    _c("(+) регистрация 200 без носителя сессии — находка",
       got[0] == "finding" and SESSION_COOKIE in got[1], f"{got}")

    got = sow(_FakeLane(register_code=400))
    _c("(+) регистрация отвергнута — находка с кодом ответа",
       got[0] == "finding" and "400" in got[1], f"{got}")

    got = sow(_FakeLane(login_after_register=False))
    _c("(+) заведён, а войти не может — находка, а не успех",
       got[0] == "finding" and "вход тем же паролем" in got[1], f"{got}")

    got = sow(_FakeLane(login_code=500))
    _c("(+) вход 5xx — находка, а не «человека нет»",
       got[0] == "finding" and "500" in got[1], f"{got}")

    got = sow(_FakeLane(down=True))
    _c("(+) полоса молчит — условие не создано, а не находка", got[0] == "unmet",
       f"{got}")

    saved = {k: os.environ.pop(k, None) for k in (ENV_EMAIL, ENV_PASSWORD)}
    got = _outcome(credentials)
    _c("(+) стенд не передал человека — условие не создано", got[0] == "unmet",
       f"{got}")
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v

    with tempfile.TemporaryDirectory() as tmp:
        got = _outcome(lambda: LaneHttp("https://127.0.0.1:1", pathlib.Path(tmp)))
        _c("(+) листа края нет — условие не создано", got[0] == "unmet", f"{got}")

        patch = env_patch("https://127.0.0.1:1/", E, P, "http://127.0.0.1:2/")
        _c("объявленные ключи = записываемые (в обе стороны)",
           set(patch) == set(MINTED_KEYS), f"{sorted(patch)} против {sorted(MINTED_KEYS)}")
        env = pathlib.Path(tmp) / "env.json"
        tmpl = pathlib.Path(tmp) / "tmpl.json"
        tmpl.write_text(json.dumps({"values": [
            {"key": "loginLanePassword", "value": "", "type": "secret"},
            {"key": "loginLaneEmail", "value": ""}]}), encoding="utf-8")
        write_env(patch, env, tmpl)
        doc = {v["key"]: v for v in json.loads(env.read_text(encoding="utf-8"))["values"]}
        _c("запись доезжает всеми ключами, тип secret у пароля сохранён",
           all(doc.get(k, {}).get("value") for k in MINTED_KEYS)
           and doc["loginLanePassword"].get("type") == "secret"
           and doc["loginLaneBaseUrl"]["value"] == "https://127.0.0.1:1"
           and doc["standMailboxUrl"]["value"] == "http://127.0.0.1:2", f"{doc}")

    try:
        census = _census_surface_for_lane_address()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        census = f"<перепись не прочитана: {e}>"
    _c("поверхность посева = поверхность, которую перепись выводит из loginLaneBaseUrl",
       census == MINTED_SURFACE, f"перепись {census!r}, посев {MINTED_SURFACE!r}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}",
              file=sys.stderr)
        return 1
    print("ДОКАЗАНО: способность входа в обычном положении утверждается исходом, "
          "код подтверждения берётся из письма приёмника стенда, «полоса молчит», "
          "«приёмник молчит» и «листа нет» отличимы от находки кодом, объявленные "
          "ключи сходятся с записью, а поверхность — с переписью долга.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="",
                    help="адрес полосы, по которому посев доказывает способность; "
                         "он же уезжает в окружение")
    ap.add_argument("--pki", default="",
                    help="каталог с edge.crt, edge.key и ca.crt")
    ap.add_argument("--mailbox-url", default="",
                    help="адрес чтения приёмника писем стенда (stand-mailbox.py): "
                         "из него берётся код подтверждения адреса")
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
        if not args.base_url or not args.pki or not args.mailbox_url:
            raise Unmet("не названы --base-url, --pki и --mailbox-url — полосы, "
                        "которую сеять, либо приёмника писем стенда нет")
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
