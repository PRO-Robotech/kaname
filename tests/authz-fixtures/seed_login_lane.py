#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ ЧЕЛОВЕКА ДЛЯ ПОЛОСЫ ВХОДА ПАРОЛЕМ на стенде посадки `own`.

ПРЕДМЕТ. Набор `kaname-login-lane` читает из окружения адрес слушателя формы
(`loginLaneBaseUrl`) и человека со способом входа паролем (`loginLaneEmail`,
`loginLanePassword`). Пока их не пишет никто, каждый шаг набора уходит в
«условие не создано» помеченным утверждением — набор исполняется и не утверждает
ничего. Этот посев пишет все три, и пишет только их.

ГДЕ ОН ИСПОЛНЯЕТСЯ. На стенде чарта посадки `own`
(`KANAME_STAND_IDENTITY_PROVIDER=own .github/scripts/stand-chart.sh`): зовёт его
подкоманда `seed-login-lane` того же скрипта. Она же выносит из Secret стенда
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
     ответившая 200, после которой вход отвергнут, — находка, а не успех.

ПОЧЕМУ ЛИСТ С ИМЕНЕМ КРАЯ ЗАКОНЕН ЗДЕСЬ. Слушатель полосы допускает РОВНО край —
по короткому имени службы из SAN проверенного клиентского листа (Р7, Р16), и
другой двери к форме человека у продукта нет. Прогонщик набора стоит на месте
края: ретранслирует форму и ставит адрес источника. Лист выписывает УЦ стенда, и
посев предъявляет его ТОЛЬКО этой двери — ни одной другой поверхности службы он
не зовёт. Машинный посев автономного стенда (`seed_own_stand.py`) такого листа не
выписывает и не вправе: его предмет — служба без края, и там лист края был бы
личностью отсутствующего звена.

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
входе; и сходимость объявленных ключей с записью в обе стороны, и поверхность,
которую выводит перепись долга из самой переменной адреса.
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
from seed_own_stand import Unmet, write_env  # noqa: E402

# Ключи окружения, которые пишет этот посев. Перепись долга
# (`.github/scripts/newman-suite-debt.py`) спрашивает их у САМОГО посева флагом
# `--minted-keys`; сходимость объявления с записью держит самопроверка.
MINTED_KEYS = ("loginLaneBaseUrl", "loginLaneEmail", "loginLanePassword")

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


def form_token(http, form: str) -> tuple[str, str]:
    """Признак формы и контекст формы (печенье), под которым он выдан."""
    code, sc, text = http.ask("GET", f"{CSRF}?form={form}")
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


def login(http, email: str, password: str) -> bool:
    """Вошёл ли человек. 401 — «нет» (исход контракта), прочее не-200 — находка."""
    token, ctx = form_token(http, "login")
    code, sc, text = http.ask("POST", LOGIN,
                              body={"email": email, "password": password,
                                    "csrfToken": token},
                              cookies={FORM_COOKIE: ctx})
    if code == 401:
        return False
    if code != 200:
        raise Finding(f"вход: ждали 200 либо 401, получили {code} "
                      f"({message_of(text)!r})")
    if not cookie_value(sc, SESSION_COOKIE):
        raise Finding(f"вход ответил 200 без печенья {SESSION_COOKIE} — "
                      f"сессия не выдана, а успех объявлен")
    return True


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


def seed(http, email: str, password: str) -> str:
    """«есть» либо «заведён»; утверждение — способность войти."""
    if login(http, email, password):
        return "есть"
    register(http, email, password)
    if not login(http, email, password):
        raise Finding("регистрация ответила 200, а вход тем же паролем отвергнут "
                      "(401) — человек заведён без способа войти")
    return "заведён"


def env_patch(base_url: str, email: str, password: str) -> dict:
    """ЧИСТАЯ функция — что уезжает в окружение; её судит самопроверка."""
    return {"loginLaneBaseUrl": base_url.rstrip("/"),
            "loginLaneEmail": email,
            "loginLanePassword": password}


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
    state = seed(http, email, password)
    say(f"  ok   человек стенда {state} и входит паролем через полосу {http.base}")
    patch = env_patch(http.base, email, password)
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
                 down=False):
        self.humans = dict(humans or {})
        self.csrf_code, self.register_code = csrf_code, register_code
        self.register_cookie = register_cookie
        self.login_after_register = login_after_register
        self.login_code, self.down = login_code, down
        self.registered = 0
        self.base = "https://127.0.0.1:1"

    def ask(self, method, path, body=None, cookies=None):
        if self.down:
            raise Unmet("полоса недостижима: connection refused")
        if path.startswith(CSRF):
            if self.csrf_code != 200:
                return self.csrf_code, [], '{"code":7,"message":"permission denied"}'
            return 200, [f"{FORM_COOKIE}=ctx; Path=/; HttpOnly"], '{"csrfToken":"t"}'
        if path == LOGIN:
            if self.login_code is not None:
                return self.login_code, [], '{"code":13,"message":"internal"}'
            ok = self.humans.get(body["email"]) == body["password"]
            if ok and (self.registered == 0 or self.login_after_register):
                return 200, [f"{SESSION_COOKIE}=s; Path=/"], '{"user":{}}'
            return 401, [], '{"code":16,"message":"credentials are not accepted"}'
        if path == REGISTER:
            self.registered += 1
            if self.register_code != 200:
                return self.register_code, [], '{"code":3,"message":"request not performed"}'
            self.humans[body["email"]] = body["password"]
            sc = [f"{SESSION_COOKIE}=s; Path=/"] if self.register_cookie else []
            return 200, sc, '{"user":{}}'
        return 404, [], "{}"


def _outcome(fn) -> tuple[str, str]:
    try:
        return "ok", str(fn())
    except Finding as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)


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

    lane = _FakeLane()
    got = _outcome(lambda: seed(lane, E, P))
    _c("(−) человека нет — заведён, и вход им доказан", got == ("ok", "заведён")
       and lane.registered == 1, f"{got}, регистраций {lane.registered}")

    lane = _FakeLane(humans={E: P})
    got = _outcome(lambda: seed(lane, E, P))
    _c("(−) человек есть — второй регистрации нет", got == ("ok", "есть")
       and lane.registered == 0, f"{got}, регистраций {lane.registered}")

    got = _outcome(lambda: seed(_FakeLane(csrf_code=403), E, P))
    _c("(+) лист не края — 403 на признаке формы — находка, названа причина",
       got[0] == "finding" and "край" in got[1], f"{got}")

    got = _outcome(lambda: seed(_FakeLane(register_cookie=False), E, P))
    _c("(+) регистрация 200 без носителя сессии — находка",
       got[0] == "finding" and SESSION_COOKIE in got[1], f"{got}")

    got = _outcome(lambda: seed(_FakeLane(register_code=400), E, P))
    _c("(+) регистрация отвергнута — находка с кодом ответа",
       got[0] == "finding" and "400" in got[1], f"{got}")

    got = _outcome(lambda: seed(_FakeLane(login_after_register=False), E, P))
    _c("(+) заведён, а войти не может — находка, а не успех",
       got[0] == "finding" and "вход тем же паролем" in got[1], f"{got}")

    got = _outcome(lambda: seed(_FakeLane(login_code=500), E, P))
    _c("(+) вход 5xx — находка, а не «человека нет»",
       got[0] == "finding" and "500" in got[1], f"{got}")

    got = _outcome(lambda: seed(_FakeLane(down=True), E, P))
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

        patch = env_patch("https://127.0.0.1:1/", E, P)
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
           and doc["loginLaneBaseUrl"]["value"] == "https://127.0.0.1:1", f"{doc}")

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
    print("ДОКАЗАНО: способность входа утверждается исходом, «полоса молчит» и "
          "«листа нет» отличимы от находки кодом, объявленные ключи сходятся с "
          "записью, а поверхность — с переписью долга.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="",
                    help="адрес полосы, по которому посев доказывает способность; "
                         "он же уезжает в окружение")
    ap.add_argument("--pki", default="",
                    help="каталог с edge.crt, edge.key и ca.crt")
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
        if not args.base_url or not args.pki:
            raise Unmet("не названы --base-url и --pki — полосы, которую сеять, нет")
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
