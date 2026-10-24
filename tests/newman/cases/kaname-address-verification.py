# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set подтверждения адреса и положения подтверждения (kaname#456).

Предмет — приёмка `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
позиции уровня E: сессия, которую получает человек с неподтверждённым адресом, и
то, что ему в ней доступно, — на СОБСТВЕННОМ слушателе формы службы, той же
полосе, что вход (Ф3): поднимается только посадкой `authn.identityProvider: own`
и допускает РОВНО край по SAN клиентского сертификата. Переменные:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека посева: из неё берётся ДОМЕН адреса,
                           сам человек посева набором не трогается
  {{standMailboxUrl}}    — чтение приёмника писем стенда (`stand-mailbox.py`; посев)

Кейс Ф4-27 сверх того ходит на две поверхности службы и читает ключи посева
церемонии стенда чарта (`seed_ceremony.py`):

  {{iamRegistryTokenBaseUrl}} — поверхность выдачи: точка авторизации и обмен кода
  {{ownRestBaseUrl}}          — собственный публичный фронт: приглашение, опрос его
                                операции, снимок «кто я» (`GET /iam/v1/me`)
  {{oauthClientId}} {{oauthClientSecret}} {{oauthRedirectUri}} — клиент церемонии
  {{cloudSupervisorEmail}} {{cloudSupervisorPassword}} {{cloudSupervisorTotpSecret}}
                              — надзор облака: единственный человек стенда с
                                уровнем «2», которого требует приглашение

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора входа: на автономном стенде
службы посадка `own` не поднята, `loginLaneBaseUrl` пуст, и каждый шаг уходит в
«условие не создано» помеченным утверждением, а не в зелёное и не в красное.

СВОИ ЛЮДИ У КАЖДОГО КЕЙСА. Предмет — человек, чей адрес ещё не подтверждён, а
человек посева подтверждён посевом. Поэтому каждый кейс заводит людей сам —
регистрацией, со своим адресом (`{{runId}}` и случайная добавка) и своим
источником: окно писем подтверждения (`verificationResendInterval`) и окно
регистраций источника успехом не обнуляются, и повторный прогон на том же стенде
заводит других людей.

КОД БЕРЁТСЯ ИЗ ПИСЬМА У ПРИЁМНИКА СТЕНДА — той же дверью, что у набора
восстановления (`GET /codes?to=<адрес>&after=<строка>`): по письму на элемент в
порядке приёма, код — строка после заголовка письма. Отчёт прогона выкладывается
артефактом публичного репозитория, поэтому код лежит в переменных с последним
словом `Code`, пароли — в переменных со словом `Password`, печенья и признаки
формы — со словами `Cookie` и `Csrf`: чистка отчёта режет их именем. Утверждения
значений удостоверений не получают — сообщение литерал, предмет булев или число.

ОТСУТСТВИЕ ПИСЬМА СУДИТСЯ БАРЬЕРОМ, А НЕ ПАУЗОЙ. «Письма нет» после отказа
регистрации, после входа и после отказа запроса нельзя утверждать ожиданием:
письмо сдаётся узлу асинхронно, и пустота через N секунд значит только «пока не
дошло». Барьер — письмо, которое ТОТ ЖЕ человек законно попросил позже: письма
одному человеку уходят в том порядке, в котором их поставили (ключ партиции
очереди — идентификатор человека, `internal/repo/kaname/pg/invite_mail_outbox/outbox.go`,
`EmitTx`). Когда код запрошенного письма прочитан у приёмника и принят службой,
каждое письмо, поставленное раньше, уже сдано узлу, и число писем человеку —
окончательное.

ИНТЕРВАЛ МЕЖДУ ПИСЬМАМИ ЖДЁТСЯ ПО ОТВЕТУ ПРОДУКТА. Запрос внутри интервала
отвечает `429` и называет в `Retry-After`, сколько секунд осталось; следующий
шаг опрашивает признак формы с настоящей паузой, пока названный момент (с
запасом в секунду) не наступит. Величина — ответ службы, а не литерал набора;
предел опросов выведен из интервала профиля (`deploy/values.prod.yaml`,
`verificationResendInterval`). Одной паузой ждать нельзя: песочница прогонщика
обрывает скрипт на 30 с.

Coverage (техники: классы эквивалентности сессии — неподтверждённая · подтверждённая ·
снятая · отсутствующая; переходы состояния сессии — положение подтверждения →
обычное положение; угадывание ошибок — вытесненный код, неверный код той же формы;
положительный близнец у каждого отказа):
  IAM-ADDRVERIFY-OK-REGISTRATION-OPENS-THE-POSITION — EV-01: регистрация — 200,
                                          сессия в положении подтверждения, носитель
                                          выдан; путь положения узнаёт носитель и
                                          называет положение (Resolve: found,
                                          email_verified false); одно письмо
                                          подтверждения с кодом дошло до приёмника;
                                          что оно ОДНО, судит барьер следующего
                                          кейса (ожидание здесь дало бы «пока одно»)
  IAM-ADDRVERIFY-OK-LETTER-ONLY-ON-REQUEST — EV-20: запрос под сессией в положении
                                          подтверждения после интервала — 200 {} без
                                          печений, одно новое письмо, прежний код
                                          вытеснен, новый принят; EV-21: запрос без
                                          носителя и носителем снятой сессии — 401;
                                          EV-01 (близнец): отказ регистрации письма не
                                          ставит; EV-02: вход неподтверждённого — 200,
                                          emailVerified false, письма не ставит;
                                          близнец — тот же человек после
                                          подтверждения входит с emailVerified true.
                                          Число писем человеку после барьера — ровно два
  IAM-ADDRVERIFY-OK-LOGOUT-FOR-BOTH       — EV-10: выход неподтверждённого и
                                          подтверждённого — 200 {}, носитель снят,
                                          сессия снятого носителя не узнаётся
  IAM-ADDRVERIFY-NEG-PASSWORD-CHANGE-REFUSED — EV-11: смена пароля неподтверждённым —
                                          403 дословно (код 7, текст, ErrorInfo
                                          EMAIL_NOT_VERIFIED с доменом службы) без
                                          печений, пароль не сменён; близнец —
                                          подтверждённый: 200, пароль сменён
  IAM-ADDRVERIFY-OK-CORRECT-CODE-IN-TIME  — EV-30: верный код в срок — 200, тело
                                          `session` с emailVerified true, новый
                                          носитель; прежний носитель не узнаётся,
                                          новый узнан в обычном положении; смена
                                          пароля новым носителем проходит без
                                          повторного входа
  IAM-ADDRVERIFY-NEG-WRONG-CODE           — EV-32: неверный код той же длины и
                                          алфавита — 401 одним текстом, details
                                          пусты, без печений; положение прежнее,
                                          носитель жив; близнец — верный код: 200
  IAM-ADDRVERIFY-OK-INVITEE-SNAPSHOT-NAMES-TWO-ACCOUNTS — Ф4-27 (приёмка Ф4,
                                          `registration-and-its-three-consequences.md`,
                                          редакция 7): приглашённый без выдачи роли
                                          регистрируется той же полосой и подтверждает
                                          адрес; снимок «кто я» под токеном его
                                          церемонии — ровно две записи: личный
                                          аккаунт с owner (заведён активацией) и
                                          аккаунт пригласившего без owner; отрицание
                                          стоит в паре с положительным близнецом в
                                          том же ответе. Пригласивший — надзор облака
                                          (уровень «2» глагола приглашения), адреса
                                          выдачи и фронта, клиент церемонии и ключи
                                          надзора пишет посев церемонии стенда чарта
  IAM-ADDRVERIFY-OK-REFUSAL-NAMES-THE-STEP-THAT-LIFTS-IT — EV-14 (редакция 5,
                                          kaname#526): смена пароля носителем N1 в
                                          положении подтверждения — 403, тело Р3
                                          дословно, путь из текста — путь
                                          предъявления кода (вырез печатается); тем
                                          же N1 код принят, выдан N2; то же
                                          обращение носителем N2 — 200, пароль
                                          сменён
  IAM-ADDRVERIFY-OK-REGISTRATION-HAS-FOUR-CONSEQUENCES — Ф4-01, Ф4-13, Ф4-26
                                          (kaname#925): свободный адрес свежего
                                          носителя — зеркало, адрес не подтверждён и
                                          письмо поставлено, сессия узнана сразу;
                                          после подтверждения снимок «кто я» ОДНИМ
                                          чтением — тот же userId, одна запись с owner
  IAM-ADDRVERIFY-OK-FIRST-ACTION-IN-OWN-ACCOUNT — Ф4-21, Ф4-22: первое действие в
                                          своём аккаунте той же сессией — проходит
                                          либо отказ называет повтор; в пределах окна
                                          — проходит
  IAM-ADDRVERIFY-NEG-REGISTRATION-REFUSAL-HIDES-OCCUPANCY-AND-PACE — Ф4-11, Ф4-12:
                                          занятый адрес и свободный адрес носителя с
                                          полным окном (ушёл с адреса сменой) — один
                                          отказ побайтово; у владельца по-прежнему
                                          один личный аккаунт; близнец — носитель с
                                          неполным окном регистрируется
  IAM-ADDRVERIFY-OK-INVITEE-REGISTERS-BY-THE-SAME-LANE — Ф4-23: строка приглашения
                                          сохранила id, она и членство ожидают,
                                          личных аккаунтов ноль; после подтверждения —
                                          действующие, личный аккаунт один с одним
                                          проектом
  IAM-ADDRVERIFY-OK-OWN-SESSIONS-LISTED-AND-ENDED — OS-16 (приёмка kaname#634,
                                          `own-sessions-are-listed-and-ended-by-their-owner.md`):
                                          свежий человек с подтверждённым адресом
                                          входит трижды; перечень носителем N1 —
                                          200, ≥ 3 записей, current ровно у N1;
                                          выход из выбранной (N2) — 200, перечень
                                          носителем N2 — 401; выход из всех, кроме
                                          текущей, — 200, ended ≥ 1; последний
                                          перечень — одна запись, текущая. Служба
                                          стенда без путей своих сессий (404 на
                                          перечень) — «условие не создано»
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — идентификаторы КОММЕНТАРИЕМ, а не строкой: перепись
# долга считает позицию несомой по строковому литералу модуля.
#   · строки очереди, события `iam.user.email_verified`, причина конца сессии и
#     счёт темпа входа при отказе положения (EV-01, EV-11, EV-30, EV-31) — это
#     внутреннее состояние службы; снаружи слушателя формы оно наблюдается только
#     следствием — письмом, носителем, ответом пути. Их держит уровень I
#     (`internal/handler/loginlanehttp/address_verification_*_integration_test.go`);
#   · ответ краю `Resolve` — глагол внутреннего слушателя без HTTP-привязки
#     (`proto/kaname/cloud/iam/v1/human_session_service.proto`); набор судит его
#     следствие на полосе: носитель узнан и назван положением (403
#     EMAIL_NOT_VERIFIED) либо узнан в обычном положении (200), либо не узнан
#     (401), — то есть ровно три ответа `Resolve`, которые различает край.

import json as _json
import pathlib as _pathlib
import re as _re
import urllib.parse as _urlparse

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это не отказ продукта, а условие, "
             "которого стенд не создал")
_MAILBOX_WHY = ("чтение приёмника писем стенда посадки `own`; адрес пишет посев "
                "полосы входа — вне стенда `own` приёмника нет, и это условие, "
                "которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_REGISTER = "/iam/v1/auth/register"
_LOGIN = "/iam/v1/auth/login"
_LOGOUT = "/iam/v1/auth/logout"
_PASSWORD = "/iam/v1/auth/password"
_VERIFY = "/iam/v1/auth/verify-email"
_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
# Чтение под сессией, ничего не меняющее: состояние второго фактора. Три ответа —
# три ответа `Resolve`: подтверждённая живая — 200, живая в положении
# подтверждения — 403 EMAIL_NOT_VERIFIED, не узнанная — 401.
_PROBE = "/iam/v1/auth/second-factor"

_HEAD_VERIFY = "Код подтверждения:"
_REFUSED = "authentication failed"
_NOT_VERIFIED = "email address is not verified: confirm it with the code from the letter (POST /iam/v1/auth/verify-email/confirm)"
_NOT_VERIFIED_REASON = "EMAIL_NOT_VERIFIED"
# Домен отказов службы — константа продукта (`internal/refusaldomain`,
# `ProductSuffix` и `ServiceIAM`), а не величина посадки.
_REFUSAL_DOMAIN = "iam.kaname.cloud"
_TOO_MANY = "too many attempts; try again later"
# Единый отказ регистрации — текст Ф4 Р3, редакция 8 (kaname#211): называет шаг,
# не называя причины.
_REG_REFUSED = ("registration refused; if this address is already yours, sign in or recover access; "
                "if you were invited, ask an account administrator to invite again; otherwise try again later")

# Величины профиля, с которыми стенд поднят: стенд `chart-own` ставит
# `deploy/values.prod.yaml` как есть (накладка несёт координаты и посадку, не
# величины полосы), поэтому интервал писем, который кейс ждёт, — ровно тот, с
# которым служба поднята. Ключ узла `authn.login` в профиле единственный; второе
# вхождение — отказ генерации с именем ключа.
_PROFILE = _pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _profile_login(key):
    found = _re.findall(rf"^    {key}: (\S+)\s*$", _PROFILE.read_text(encoding="utf-8"), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-address-verification: ключ профиля authn.login.{key} найден "
                         f"{len(found)} раз в {_PROFILE} — ждали ровно один")
    return found[0]


def _seconds(duration):
    m = _re.fullmatch(r"(\d+)([smh])", duration)
    if m is None:
        raise SystemExit(f"kaname-address-verification: срок {duration!r} не в форме <число><s|m|h>")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


_RESEND_INTERVAL = _seconds(_profile_login("verificationResendInterval"))

# Предел ожидания письма у приёмника: попыток и пауза между ними (мс). Замер на
# стенде kind посадки `own` (набор восстановления, kaname#468): письмо доходит за
# ~1 с; предел — с запасом на загруженный раннер.
_MAIL_WAIT_CAP = 90
_MAIL_WAIT_MS = 1000


def _v(p, name):
    return p + name


def _src_pre(p):
    return [f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: pm.environment.get({js_str(_v(p, 'Src'))}) || ''}});"]


def _with_cookies(*vars_):
    parts = " + ".join(
        f"(pm.environment.get({js_str(v)}) ? {js_str(name)} + '=' + pm.environment.get({js_str(v)}) + '; ' : '')"
        for name, v in vars_)
    return [
        f"const __cookie = ({parts}).replace(/; $/, '');",
        "if (__cookie) { pm.request.headers.upsert({key: 'Cookie', value: __cookie}); }",
    ]


def _person_init(p, tag):
    """Адрес, пароли и источник человека кейса — один раз, первым шагом."""
    return [
        "{",
        "  const __nonce = () => Math.floor(Math.random() * 2176782336).toString(36);",
        "  const __domain = String(pm.environment.get('loginLaneEmail') || '').split('@')[1] || 'kaname.local';",
        f"  pm.environment.set({js_str(_v(p, 'Email'))}, ({js_str('av-' + tag + '-')} + pm.environment.get('runId') + '-' + __nonce() + '@' + __domain).toLowerCase());",
        f"  pm.environment.set({js_str(_v(p, 'Password'))}, 'Pw-' + __nonce() + __nonce() + '-first');",
        f"  pm.environment.set({js_str(_v(p, 'NewPassword'))}, 'Pw-' + __nonce() + __nonce() + '-renewed');",
        f"  pm.environment.set({js_str(_v(p, 'Src'))}, '198.19.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
        f"  pm.environment.set({js_str(_v(p, 'MailSeen'))}, '0');",
        *(f"  pm.environment.unset({js_str(_v(p, n))});" for n in (
            "FormCookie", "SessionCookie", "OldSessionCookie", "LoginSessionCookie", "Csrf",
            "FirstCode", "Code", "IntervalUntil")),
        "}",
    ]


def _status_is(code, label):
    return [f"pm.test({js_str(label + f': ответ {code}')}, () => pm.expect(pm.response.code).to.eql({code}));"]


def _no_session_issued(label):
    return [f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
            "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
            "&& h.value.startsWith('kaname_session=')).length).to.eql(0));"]


def _no_cookies(label):
    return [f"pm.test({js_str(label + ': печений не пишет')}, () => "
            "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length).to.eql(0));"]


def _refused(status, grpc, text, label, reason=None, empty_details=False):
    """Отказ полосы: статус, код и текст порознь; значений удостоверений нет."""
    out = [
        *_status_is(status, label),
        "let __r = {}; try { __r = pm.response.json(); } catch (e) { __r = {}; }",
        f"pm.test({js_str(label + f': код отказа {grpc}')}, () => pm.expect(__r.code).to.eql({grpc}));",
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => pm.expect(__r.message).to.eql({js_str(text)}));",
        *_no_session_issued(label),
    ]
    if reason:
        out += [
            "const __info = (Array.isArray(__r.details) ? __r.details : [])"
            ".filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            f"pm.test({js_str(label + ': признак отказа ' + reason)}, () => pm.expect(__info.reason).to.eql({js_str(reason)}));",
        ]
    if empty_details:
        out.append(f"pm.test({js_str(label + ': details пусты')}, () => "
                   "pm.expect(Array.isArray(__r.details) && __r.details.length === 0).to.eql(true));")
    return out


def _position_refused(label):
    """Отказ положения (Р3) дословно: 403, код 7, текст, ErrorInfo с доменом службы."""
    return [
        *_refused(403, 7, _NOT_VERIFIED, label, reason=_NOT_VERIFIED_REASON),
        f"pm.test({js_str(label + ': домен признака — домен отказов службы')}, () => "
        f"pm.expect(__info.domain).to.eql({js_str(_REFUSAL_DOMAIN)}));",
    ]


def _capture(p, cookie, var, label, required=True):
    """Печенье из `Set-Cookie`; обязательное — утверждается числом, без значений."""
    lines = [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(cookie + '=')}));",
    ]
    if required:
        lines.append(f"  pm.test({js_str(label + ': ответ ставит печенье ' + cookie)}, () => pm.expect(__sc.length).to.eql(1));")
    lines += [
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(_v(p, var))}, __sc[0].value.split(';')[0].slice({len(cookie) + 1})); }}",
        "}",
    ]
    return lines


def _csrf_step(p, name, form, *, init=None, with_session="SessionCookie"):
    path = f"{_CSRF}?form={form}"
    cookies = [("kaname_form", _v(p, "FormCookie"))]
    if with_session:
        cookies.append(("kaname_session", _v(p, with_session)))
    label = name.upper()
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*(init or []), *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
                    *_src_pre(p), *_with_cookies(*cookies)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_status_is(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(label + ': признак формы выдан строкой')}, () => "
            "pm.expect(typeof __j.csrfToken === 'string' && __j.csrfToken.length > 0).to.eql(true));",
            f"pm.environment.set({js_str(_v(p, 'Csrf'))}, __j.csrfToken || '');",
            *_capture(p, "kaname_form", "FormCookie", label, required=False),
        ],
    )


def _post(p, name, path, body, *, with_session=None, test_script=(), extra_pre=()):
    cookies = [("kaname_form", _v(p, "FormCookie"))]
    if with_session:
        cookies.append(("kaname_session", _v(p, with_session)))
    return Step(
        name=name, method="POST", path=path, body=body,
        pre_script=[*extra_pre, *require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_src_pre(p),
                    *_with_cookies(*cookies)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=list(test_script),
    )


def _session_probe(p, name, cookie_var, outcome):
    """Что служба знает о носителе — чтением под сессией, ничего не меняющим.

    `outcome`: `alive` — узнан в обычном положении (200); `position` — узнан и
    назван положением подтверждения (403 EMAIL_NOT_VERIFIED); `gone` — не узнан
    (401, как несуществующий)."""
    label = name.upper()
    tests = {
        "alive": _status_is(200, label + " (узнан в обычном положении)"),
        "position": _position_refused(label + " (узнан в положении подтверждения)"),
        "gone": _refused(401, 16, _REFUSED, label + " (не узнан)"),
    }[outcome]
    return Step(
        name=name, method="GET", path=_PROBE,
        pre_script=[*require_env_url("loginLaneBaseUrl", _PROBE, _LANE_WHY), *_src_pre(p),
                    f"pm.test({js_str(label + ': предъявляемый носитель был выдан (контроль непустоты)')}, () => "
                    f"pm.expect(!!pm.environment.get({js_str(_v(p, cookie_var))})).to.eql(true));",
                    *_with_cookies(("kaname_session", _v(p, cookie_var)))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=tests,
    )


def _mail_path(p):
    return f"/codes?to={{{{{_v(p, 'Email')}}}}}&after={_urlparse.quote(_HEAD_VERIFY)}"


def _await_letter(p, name, into="Code"):
    """Письмо подтверждения СВЕРХ уже прочитанных: петля с настоящей паузой.

    Код последнего письма — в `<p><into>`, число писем человеку — в `<p>MailSeen`.

    Ждём письмо С КОДОМ, а не любое новое: приглашённому до письма подтверждения
    приходит письмо приглашения, в котором строки кода нет (элемент `null`), и оно
    само по себе условием ожидания не служит (kaname#468, разбор F427). Письмо
    подтверждения без кода по-прежнему краснит кейс — по исчерпании ожидания."""
    path = _mail_path(p)
    counter, started = f"_avmb_{p}_{name}".replace("-", "_"), f"_avmbs_{p}_{name}".replace("-", "_")
    seen, label = _v(p, "MailSeen"), name.upper()
    return Step(
        name=name, method="GET", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[
            *require_env_url("standMailboxUrl", path, _MAILBOX_WHY),
            f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter)}, '0');",
            f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
        ],
        test_script=[
            f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
            f"const __seen = parseInt(pm.environment.get({js_str(seen)}) || '0', 10);",
            "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
            "const __all = Array.isArray(__codes) ? __codes : [];",
            "const __fresh = __all.slice(__seen).filter((c) => typeof c === 'string');",
            f"if (pm.response.code === 200 && __fresh.length === 0 && __n < {_MAIL_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _avd = Date.now(); while (Date.now() - _avd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': письмо дошло до приёмника стенда в пределе ожидания')}, () => "
            "pm.expect(__all.length > __seen).to.eql(true));",
            "const __last = __fresh.length > 0 ? __fresh[__fresh.length - 1] : (__all.length > __seen ? __all[__all.length - 1] : null);",
            f"pm.test({js_str(label + ': письмо — подтверждения адреса и несёт код формы XXXXX-XXXXX')}, () => "
            "pm.expect(typeof __last === 'string' && /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(__last)).to.eql(true));",
            "if (__all.length > __seen) {",
            f"  pm.environment.set({js_str(_v(p, into))}, typeof __last === 'string' ? __last : '');",
            f"  pm.environment.set({js_str(seen)}, String(__all.length));",
            "}",
        ],
    )


def _letters_total(p, name, expected, why):
    """Число писем человеку — ОДНИМ чтением, после барьера (см. шапку)."""
    path = _mail_path(p)
    label = name.upper()
    return Step(
        name=name, method="GET", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[*require_env_url("standMailboxUrl", path, _MAILBOX_WHY)],
        test_script=[
            *_status_is(200, label),
            "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
            f"pm.test({js_str(label + ': писем человеку ровно ' + str(expected) + ' — ' + why)}, () => "
            f"pm.expect(Array.isArray(__codes) ? __codes.length : -1).to.eql({expected}));",
        ],
    )


def _register(p, tag, *, label=None, extra_tests=()):
    label = label or f"{tag.upper()}-REGISTER"
    return [
        _csrf_step(p, f"{tag}-csrf-register", "register", init=_person_init(p, tag), with_session=None),
        _post(p, f"{tag}-register", _REGISTER,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, label),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(label + ': сессия в положении подтверждения — emailVerified false')}, () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === false).to.eql(true));",
                  *_capture(p, "kaname_session", "SessionCookie", label),
                  *_capture(p, "kaname_form", "FormCookie", label, required=False),
                  *extra_tests,
              ]),
    ]


def _confirm(p, name, code_var, *, with_session="SessionCookie", test_script=()):
    return [
        _csrf_step(p, f"{name}-csrf", "verify-email-confirm", with_session=with_session),
        _post(p, name, _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(p, code_var)}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session=with_session, test_script=test_script),
    ]


def _confirmed(p, label, into="SessionCookie"):
    """Успех предъявления кода: 200, тело `session` с emailVerified true, новый носитель."""
    return [
        *_status_is(200, label),
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        f"pm.test({js_str(label + ': адрес подтверждён — emailVerified true')}, () => "
        "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
        *_capture(p, "kaname_session", into, label),
    ]


def _verified_person(p, tag):
    """Человек с подтверждённым адресом: регистрация → код письма → подтверждение.

    Носитель обычного положения — в `<p>SessionCookie`."""
    return [
        *_register(p, tag),
        _await_letter(p, f"{tag}-letter"),
        *_confirm(p, f"{tag}-verify", "Code", test_script=_confirmed(p, f"{tag.upper()}-VERIFY")),
    ]


def _login(p, name, password_var, *, verified, into="LoginSessionCookie"):
    label = name.upper()
    return [
        _csrf_step(p, f"{name}-csrf", "login", with_session=None),
        _post(p, name, _LOGIN,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, password_var)}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, label),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(label + ': emailVerified ' + ('true' if verified else 'false'))}, () => "
                  f"pm.expect(!!__j.session && __j.session.emailVerified === {'true' if verified else 'false'}).to.eql(true));",
                  *_capture(p, "kaname_session", into, label),
                  *_capture(p, "kaname_form", "FormCookie", label, required=False),
              ]),
    ]


def _login_refused(p, name, password_var):
    return [
        _csrf_step(p, f"{name}-csrf", "login", with_session=None),
        _post(p, name, _LOGIN,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, password_var)}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=_refused(401, 16, _REFUSED, name.upper())),
    ]


def _logout(p, name, session_var):
    label = name.upper()
    return [
        _csrf_step(p, f"{name}-csrf", "logout", with_session=session_var),
        _post(p, name, _LOGOUT, {"csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"}, with_session=session_var,
              test_script=[
                  *_status_is(200, label),
                  f"pm.test({js_str(label + ': тело — пустой объект')}, () => pm.expect(pm.response.text()).to.eql('{{}}'));",
                  f"pm.test({js_str(label + ': носитель снят — печенье сессии пустым значением с Max-Age=0')}, () => "
                  "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
                  "&& /^kaname_session=;/.test(h.value) && /Max-Age=0/.test(h.value)).length).to.eql(1));",
              ]),
    ]


def _password_change(p, name, session_var, test_script):
    return [
        _csrf_step(p, f"{name}-csrf", "password", with_session=session_var),
        _post(p, name, _PASSWORD,
              {"currentPassword": f"{{{{{_v(p, 'Password')}}}}}", "newPassword": f"{{{{{_v(p, 'NewPassword')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session=session_var, test_script=test_script),
    ]


# ───────────────────────────────────────────────────────────────────────────
# EV-01: регистрация даёт сессию в положении подтверждения и ставит письмо.
# ───────────────────────────────────────────────────────────────────────────
_P01 = "avR"
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-REGISTRATION-OPENS-THE-POSITION",
    title="Регистрация — 200, сессия в положении подтверждения узнаётся и называется положением, одно письмо подтверждения с кодом (EV-01)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_register(_P01, "ev01"),
        _session_probe(_P01, "ev01-position-recognized", "SessionCookie", "position"),
        _await_letter(_P01, "ev01-letter"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-20, EV-21, EV-02, EV-01 (близнец): письмо ставят регистрация и запрос — и
# больше ничего. Барьер — запрошенное письмо (шапка модуля).
# ───────────────────────────────────────────────────────────────────────────
_P20 = "avQ"
_RETRY_AFTER_OK = [
    f"pm.test({js_str(f'EV20-TOO-EARLY: Retry-After — положительное число секунд не больше интервала профиля ({_RESEND_INTERVAL} с)')}, () => {{",
    "  const ra = pm.response.headers.get('Retry-After');",
    f"  pm.expect(/^[0-9]+$/.test(String(ra)) && Number(ra) >= 1 && Number(ra) <= {_RESEND_INTERVAL}).to.eql(true);",
    "});",
    # Момент, после которого запрос законен: сейчас плюс названное продуктом, с
    # запасом в секунду; без заголовка — интервал профиля.
    "{",
    f"  const __ra = Math.min(parseInt(pm.response.headers.get('Retry-After'), 10) || {_RESEND_INTERVAL}, {_RESEND_INTERVAL});",
    f"  pm.environment.set({js_str(_v(_P20, 'IntervalUntil'))}, String(Date.now() + (__ra + 1) * 1000));",
    "}",
]
# Опросов ожидания интервала: по полсекунды на опрос — интервал профиля с
# запасом вдвое. Предел, в который упёрлась петля, — красное с числом, а не
# молчаливый запрос раньше срока.
_INTERVAL_POLL_CAP = (_RESEND_INTERVAL + 2) * 4


def _await_interval(p, name, form, session_var):
    """Признак формы `form`, запрашиваемый повтором с настоящей паузой, пока не
    наступит момент `<p>IntervalUntil`, названный прошлым шагом по ответу
    продукта. Шаг состояния не меняет; его последний признак нужен следующему."""
    path = f"{_CSRF}?form={form}"
    label, polls = name.upper(), f"_avip_{p}_{name}".replace("-", "_")
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_src_pre(p),
                    *_with_cookies(("kaname_form", _v(p, "FormCookie")), ("kaname_session", _v(p, session_var)))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_status_is(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.environment.set({js_str(_v(p, 'Csrf'))}, __j.csrfToken || '');",
            f"const __until = parseInt(pm.environment.get({js_str(_v(p, 'IntervalUntil'))}) || '0', 10);",
            f"const __polls = parseInt(pm.environment.get({js_str(polls)}) || '0', 10);",
            "const __ready = __until > 0 && Date.now() >= __until;",
            f"pm.test({js_str(label + ': момент, названный продуктом, наступил либо ожидание в пределе')}, () => "
            f"pm.expect(__until > 0 && (__ready || __polls < {_INTERVAL_POLL_CAP})).to.eql(true));",
            f"if (__until > 0 && !__ready && __polls < {_INTERVAL_POLL_CAP}) {{",
            f"  pm.environment.set({js_str(polls)}, String(__polls + 1));",
            "  const _avw = Date.now(); while (Date.now() - _avw < 500) { /* inter-poll delay: the resend interval the product named */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(polls)});",
            "}",
        ],
    )


CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-LETTER-ONLY-ON-REQUEST",
    title="Письмо ставят регистрация и запрос под сессией после интервала — и только они: отказ регистрации, вход, запрос без сессии и внутри интервала писем не ставят (EV-20, EV-21, EV-02, EV-01)",
    classes=["CRUD", "SEC", "NEG"],
    priority="P0",
    steps=[
        *_register(_P20, "ev20"),
        _await_letter(_P20, "ev20-registration-letter", into="FirstCode"),
        # EV-01, близнец: тот же адрес снова — единый отказ регистрации Ф4.
        _csrf_step(_P20, "ev20-csrf-register-again", "register", with_session=None),
        _post(_P20, "ev01-twin-registration-refused", _REGISTER,
              {"email": f"{{{{{_v(_P20, 'Email')}}}}}", "password": f"{{{{{_v(_P20, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              test_script=_refused(400, 9, _REG_REFUSED, "EV01-TWIN", reason="REGISTRATION_REFUSED")),
        # EV-02 (а): вход неподтверждённого — сессия в положении подтверждения.
        *_login(_P20, "ev02-login-unverified", "Password", verified=False),
        # EV-21 (б): носитель снятой сессии.
        *_logout(_P20, "ev20-logout-registration-session", "SessionCookie"),
        _csrf_step(_P20, "ev21-csrf", "verify-email", with_session=None),
        _post(_P20, "ev21-ended-session", _VERIFY, {"csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[*_refused(401, 16, _REFUSED, "EV21-ENDED", empty_details=True),
                           *_no_cookies("EV21-ENDED")]),
        # EV-21 (а): носителя нет вовсе.
        _post(_P20, "ev21-no-carrier", _VERIFY, {"csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              test_script=[*_refused(401, 16, _REFUSED, "EV21-NO-CARRIER", empty_details=True),
                           *_no_cookies("EV21-NO-CARRIER")]),
        # Внутри интервала — отказ по частоте; его Retry-After и есть ожидание.
        _csrf_step(_P20, "ev20-csrf-too-early", "verify-email", with_session="LoginSessionCookie"),
        _post(_P20, "ev20-too-early", _VERIFY, {"csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              with_session="LoginSessionCookie",
              test_script=[*_refused(429, 8, _TOO_MANY, "EV20-TOO-EARLY", reason="TOO_MANY_ATTEMPTS"),
                           *_RETRY_AFTER_OK]),
        # EV-20: после интервала — 200 {}, печений нет.
        _await_interval(_P20, "ev20-await-interval", "verify-email", "LoginSessionCookie"),
        _post(_P20, "ev20-request-after-interval", _VERIFY, {"csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              with_session="LoginSessionCookie",
              test_script=[*_status_is(200, "EV20-REQUEST"),
                           "pm.test('EV20-REQUEST: тело — пустой объект', () => pm.expect(pm.response.text()).to.eql('{}'));",
                           *_no_cookies("EV20-REQUEST")]),
        _await_letter(_P20, "ev20-requested-letter"),
        Step(
            name="ev20-new-code-differs", method="GET", path=_CSRF + "?form=verify-email-confirm",
            pre_script=[*require_env_url("loginLaneBaseUrl", _CSRF + "?form=verify-email-confirm", _LANE_WHY),
                        *_src_pre(_P20),
                        *_with_cookies(("kaname_form", _v(_P20, "FormCookie")),
                                       ("kaname_session", _v(_P20, "LoginSessionCookie")))],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, "EV20-NEW-CODE"),
                "pm.test('EV20-NEW-CODE: код нового письма отличается от кода письма регистрации', () => "
                f"pm.expect(pm.environment.get({js_str(_v(_P20, 'Code'))}) !== pm.environment.get({js_str(_v(_P20, 'FirstCode'))})).to.eql(true));",
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"pm.environment.set({js_str(_v(_P20, 'Csrf'))}, __j.csrfToken || '');",
            ],
        ),
        # K1 вытеснен: код письма регистрации больше не подходит.
        _post(_P20, "ev20-first-code-displaced", _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(_P20, 'FirstCode')}}}}}", "csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              with_session="LoginSessionCookie",
              test_script=_refused(401, 16, _REFUSED, "EV20-K1-DISPLACED")),
        _post(_P20, "ev20-new-code-accepted", _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(_P20, 'Code')}}}}}", "csrfToken": f"{{{{{_v(_P20, 'Csrf')}}}}}"},
              with_session="LoginSessionCookie",
              test_script=_confirmed(_P20, "EV20-K2", into="LoginSessionCookie")),
        # Барьер пройден: всё, что поставлено раньше запрошенного письма, сдано.
        _letters_total(_P20, "ev20-letters-after-barrier", 2,
                       "одно письмо регистрации и одно запрошенное; отказ регистрации, вход, запрос без сессии и внутри интервала писем не ставят"),
        # EV-02 (б): тот же человек с отметкой — вход даёт обычное положение.
        *_login(_P20, "ev02-login-verified-twin", "Password", verified=True, into="VerifiedLoginSessionCookie"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-10: выход доступен обоим.
# ───────────────────────────────────────────────────────────────────────────
_P10U, _P10V = "avLu", "avLv"
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-LOGOUT-FOR-BOTH",
    title="Выход в положении подтверждения и в обычном положении — 200 {}, носитель снят, снятая сессия не узнаётся (EV-10)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_register(_P10U, "ev10-unverified"),
        _session_probe(_P10U, "ev10-unverified-alive-before", "SessionCookie", "position"),
        *_logout(_P10U, "ev10-unverified-logout", "SessionCookie"),
        _session_probe(_P10U, "ev10-unverified-gone-after", "SessionCookie", "gone"),
        *_verified_person(_P10V, "ev10-verified"),
        _session_probe(_P10V, "ev10-verified-alive-before", "SessionCookie", "alive"),
        *_logout(_P10V, "ev10-verified-logout", "SessionCookie"),
        _session_probe(_P10V, "ev10-verified-gone-after", "SessionCookie", "gone"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-11: смена пароля — отказ положения; близнец — подтверждённый.
# ───────────────────────────────────────────────────────────────────────────
_P11U, _P11V = "avPu", "avPv"
CASES.append(Case(
    id="IAM-ADDRVERIFY-NEG-PASSWORD-CHANGE-REFUSED",
    title="Смена пароля в положении подтверждения — 403 EMAIL_NOT_VERIFIED дословно, пароль не сменён; подтверждённому — 200, сменён (EV-11)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_register(_P11U, "ev11-unverified"),
        *_password_change(_P11U, "ev11-unverified-change", "SessionCookie", [
            *_position_refused("EV11-UNVERIFIED"),
            *_no_cookies("EV11-UNVERIFIED"),
        ]),
        _session_probe(_P11U, "ev11-unverified-carrier-alive", "SessionCookie", "position"),
        *_login(_P11U, "ev11-unverified-old-password-still-signs-in", "Password", verified=False),
        *_login_refused(_P11U, "ev11-unverified-new-password-refused", "NewPassword"),
        *_verified_person(_P11V, "ev11-verified"),
        *_password_change(_P11V, "ev11-verified-change", "SessionCookie", [
            *_status_is(200, "EV11-VERIFIED"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "pm.test('EV11-VERIFIED: тело несёт сессию', () => pm.expect(!!(__j.session && __j.session.expiresAt)).to.eql(true));",
        ]),
        *_login(_P11V, "ev11-verified-new-password-signs-in", "NewPassword", verified=True),
        *_login_refused(_P11V, "ev11-verified-old-password-refused", "Password"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-30: верный код в срок.
# ───────────────────────────────────────────────────────────────────────────
_P30 = "avC"
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-CORRECT-CODE-IN-TIME",
    title="Верный код в срок: 200, тело session с emailVerified true, новый носитель; прежний не узнаётся, новый — в обычном положении без повторного входа (EV-30); пароль регистрации входит — ACTIVE с паролем (AWI-08, регистрация)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_register(_P30, "ev30"),
        _await_letter(_P30, "ev30-letter"),
        *_confirm(_P30, "ev30-confirm", "Code", test_script=[
            *_status_is(200, "EV30"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "pm.test('EV30: тело — ровно session с тремя полями', () => "
            "pm.expect(Object.keys(__j).join(',') === 'session' && !!__j.session "
            "&& Object.keys(__j.session).sort().join(',') === 'assuranceLevel,emailVerified,expiresAt').to.eql(true));",
            "pm.test('EV30: emailVerified true', () => pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
            f"pm.environment.set({js_str(_v(_P30, 'OldSessionCookie'))}, pm.environment.get({js_str(_v(_P30, 'SessionCookie'))}));",
            *_capture(_P30, "kaname_session", "SessionCookie", "EV30"),
            "pm.test('EV30: новый носитель отличается от прежнего', () => "
            f"pm.expect(pm.environment.get({js_str(_v(_P30, 'SessionCookie'))}) !== pm.environment.get({js_str(_v(_P30, 'OldSessionCookie'))})).to.eql(true));",
        ]),
        _session_probe(_P30, "ev30-old-carrier-gone", "OldSessionCookie", "gone"),
        _session_probe(_P30, "ev30-new-carrier-verified", "SessionCookie", "alive"),
        # AWI-08 (регистрация): полоса регистрации после инварианта пары даёт ACTIVE
        # С ПАРОЛЕМ — пароль регистрации входит, положение обычное.
        *_login(_P30, "ev30-awi08-login-with-registration-password", "Password", verified=True),
        *_password_change(_P30, "ev30-password-change-without-relogin", "SessionCookie", [
            *_status_is(200, "EV30-PASSWORD"),
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-14 (редакция 5, kaname#526): текст отказа называет шаг, и названный шаг
# снимает отказ. Одна сессия от начала до конца: носитель N1 в положении
# подтверждения получает отказ смены пароля; путь, вырезанный из текста отказа,
# — путь предъявления кода, и он открыт в положении подтверждения: тем же N1
# код из письма принят, выдан N2; то же обращение носителем N2 проходит.
# Близнец (б) отличается от (а) одним фактом — исполнен ли названный шаг.
#
# ЧЕГО КЕЙС НЕ ПЕРЕУТВЕРЖДАЕТ: равенство текста на публичном слушателе gRPC
# (EV-60) и на круге края (EV-62) — последнее «И» позиции; первое держит
# уровень I (`TestEV60_EveryPublicMethodRefusesTheUnverified`), копию края —
# дом платформы. Здесь — текст полосы формы, ровно тот, что видит клиент.
# ───────────────────────────────────────────────────────────────────────────
_P14 = "avN"
# Тело отказа Р3 — целиком: код, текст, единственная запись ErrorInfo с
# признаком и доменом отказов службы (EV-14 (а)).
_EV14_BODY = {"code": 7, "message": _NOT_VERIFIED,
              "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                           "reason": _NOT_VERIFIED_REASON, "domain": _REFUSAL_DOMAIN}]}
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-REFUSAL-NAMES-THE-STEP-THAT-LIFTS-IT",
    title="EV-14: смена пароля носителем в положении подтверждения — 403, тело Р3 целиком, путь из "
          "текста — путь предъявления кода; тем же носителем код принят, выдан новый; то же "
          "обращение новым носителем — 200, пароль сменён (близнец: исполнен ли названный шаг)",
    classes=["NEG", "STATE", "CONF"],
    priority="P0",
    steps=[
        *_register(_P14, "ev14"),
        _await_letter(_P14, "ev14-letter"),
        *_password_change(_P14, "ev14-refused", "SessionCookie", [
            *_position_refused("EV14-A"),
            "let __b = null; try { __b = JSON.parse(pm.response.text()); } catch (e) { __b = null; }",
            f"pm.test('EV14-A: тело отказа — дословно тело Р3 (код, текст, одна запись ErrorInfo)', () => "
            f"pm.expect(pm.response.text()).to.eql({js_str(_json.dumps(_EV14_BODY, ensure_ascii=False, separators=(',', ':')))}));",
            *_no_cookies("EV14-A"),
            # (в): путь — от «POST » до «)» текста отказа. Пустой вырез — отказ
            # пробы, а не зелёное; вырезанное печатается.
            "const __m = String((__b && __b.message) || '');",
            "const __at = __m.indexOf('POST ');",
            "const __end = __at < 0 ? -1 : __m.indexOf(')', __at);",
            "const __cut = (__at < 0 || __end < 0) ? '' : __m.slice(__at + 5, __end);",
            "console.log('[EV-14 (в)] путь шага, вырезанный из текста отказа: «' + __cut + '»');",
            "pm.test('EV14-В: вырез пути из текста отказа непуст', () => pm.expect(__cut.length > 0).to.eql(true));",
            f"pm.test('EV14-В: вырезанный путь — путь предъявления кода полосы формы', () => "
            f"pm.expect(__cut).to.eql({js_str(_VERIFY_CONFIRM)}));",
        ]),
        # Пароль отказом не сменён: прежний входит в том же положении, новый — нет.
        *_login(_P14, "ev14-old-password-still-signs-in", "Password", verified=False),
        *_login_refused(_P14, "ev14-new-password-not-set", "NewPassword"),
        # Названный шаг исполняется ТЕМ ЖЕ носителем N1 — путь доступен в положении
        # подтверждения, и шаг снимает положение.
        *_confirm(_P14, "ev14-named-step", "Code", test_script=[
            f"pm.environment.set({js_str(_v(_P14, 'OldSessionCookie'))}, pm.environment.get({js_str(_v(_P14, 'SessionCookie'))}));",
            *_confirmed(_P14, "EV14-STEP"),
            "pm.test('EV14-STEP: выдан новый носитель N2, отличный от N1', () => "
            f"pm.expect(!!pm.environment.get({js_str(_v(_P14, 'SessionCookie'))}) && pm.environment.get({js_str(_v(_P14, 'SessionCookie'))}) "
            f"!== pm.environment.get({js_str(_v(_P14, 'OldSessionCookie'))})).to.eql(true));",
        ]),
        # (б) близнец: то же обращение с тем же телом — носителем N2.
        *_password_change(_P14, "ev14-same-request-after-the-step", "SessionCookie", [
            *_status_is(200, "EV14-B"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "pm.test('EV14-B: ответ — успех смены с сессией, а не отказ положения', () => "
            "pm.expect([!!(__j.session && __j.session.expiresAt), __j.code === undefined]).to.eql([true, true]));",
            "pm.test('EV14-B: признака EMAIL_NOT_VERIFIED в ответе нет', () => "
            f"pm.expect(pm.response.text().indexOf({js_str(_NOT_VERIFIED_REASON)})).to.eql(-1));",
        ]),
        *_login(_P14, "ev14-new-password-signs-in", "NewPassword", verified=True),
        *_login_refused(_P14, "ev14-old-password-refused", "Password"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EV-32: неверный код; близнец — EV-30 на том же человеке.
# ───────────────────────────────────────────────────────────────────────────
_P32 = "avW"
# Неверный код той же длины и алфавита: первый знак живого кода сдвинут по
# алфавиту Крокфорда (`internal/domain/recovery_code.go`) — годная форма,
# другое значение.
_WRONG_CODE = [
    "{",
    "  const __alpha = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';",
    f"  const __k = String(pm.environment.get({js_str(_v(_P32, 'Code'))}) || '');",
    "  const __i = __alpha.indexOf(__k.charAt(0));",
    f"  pm.environment.set({js_str(_v(_P32, 'WrongCode'))}, __alpha.charAt((__i + 1) % __alpha.length) + __k.slice(1));",
    "}",
]
CASES.append(Case(
    id="IAM-ADDRVERIFY-NEG-WRONG-CODE",
    title="Неверный код той же формы — 401 одним текстом, details пусты, без печений; положение и носитель прежние; верный затем — 200 (EV-32)",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_register(_P32, "ev32"),
        _await_letter(_P32, "ev32-letter"),
        _csrf_step(_P32, "ev32-csrf", "verify-email-confirm"),
        _post(_P32, "ev32-wrong-code", _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(_P32, 'WrongCode')}}}}}", "csrfToken": f"{{{{{_v(_P32, 'Csrf')}}}}}"},
              with_session="SessionCookie", extra_pre=[
                  *_WRONG_CODE,
                  "pm.test('EV32: предъявляемый код — той же формы и не равен живому (контроль)', () => "
                  f"pm.expect(/^[0-9A-HJKMNP-TV-Z]{{5}}-[0-9A-HJKMNP-TV-Z]{{5}}$/.test(String(pm.environment.get({js_str(_v(_P32, 'WrongCode'))}))) "
                  f"&& pm.environment.get({js_str(_v(_P32, 'WrongCode'))}) !== pm.environment.get({js_str(_v(_P32, 'Code'))})).to.eql(true));",
              ],
              test_script=[*_refused(401, 16, _REFUSED, "EV32", empty_details=True), *_no_cookies("EV32")]),
        _session_probe(_P32, "ev32-carrier-alive-still-in-position", "SessionCookie", "position"),
        *_confirm(_P32, "ev32-twin-right-code", "Code", test_script=_confirmed(_P32, "EV32-TWIN")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф4-27 (приёмка Ф4 `registration-and-its-three-consequences.md`, редакция 7):
# у приглашённого после подтверждения адреса снимок «кто я» называет ДВА
# аккаунта, и личный из них — один.
#
# «ДАНО» СТРОИТСЯ ГЛАГОЛАМИ ПРОДУКТА, а не посевом хранилища. Приглашение без
# выдачи роли (`POST /iam/v1/users:invite` без `projectId`/`roleId`) — тот же
# производитель строки приглашения, что у посева, только снаружи; глагол требует
# уровня «2» (`required_acr_min`), и единственный человек стенда `chart-own`, у
# которого он есть, — надзор облака (его адрес, пароль и секрет фактора пишет
# посев церемонии). Пригласивший — сам надзор, аккаунт — его личный: аккаунт,
# которым он владеет, у него один, и это утверждается шагом фикстуры.
#
# СНИМОК — `AuthorizeService.WhoAmI` (`GET /iam/v1/me`) на собственном публичном
# фронте службы. Печенья фронт не разрешает, поэтому сессия, выданная
# подтверждением, предъявляется точке авторизации нашей церемонии, и снимок
# читается токеном, выданным по ней, — тем же путём, каким посев церемонии
# выковывает предъявителя человека (`seed_ceremony.py`, `ceremony_bearer`).
# Функция снимка у Ф4-26 и Ф4-27 одна (приёмка §12 п. 10).
#
# БЛИЗНЕЦ «ДО ПОДТВЕРЖДЕНИЯ» здесь не переутверждается — по приёмке он стоит
# координатой: аккаунтов у приглашённого до подтверждения ноль (Ф4-23), снимок
# той же сессией — отказ положения (EV-60 приёмки `kaname#456`).
#
# СТРАЖ ПРЕДМЕТА. Без производителя (личный аккаунт не заводится активацией)
# снимок называет одну запись — аккаунт пригласившего — и кейс краснеет на
# числе записей и на записи с `owner`; без активации приглашения — на записи
# аккаунта пригласившего. Несозданное «Дано» (ключей надзора либо клиента
# церемонии нет) — третья категория помеченным утверждением, а не зелёное.
# ───────────────────────────────────────────────────────────────────────────
_OWN_WHY = ("собственный публичный фронт службы: приглашение, опрос его операции и "
            "снимок «кто я»; адрес пишет посев церемонии стенда посадки `own`")
_ISSUANCE_WHY = ("поверхность выдачи службы: точка авторизации и обмен кода на токен; "
                 "адрес пишет посев церемонии стенда посадки `own`")
_AUTHORIZE = "/iam/v1/authorize"
_EXCHANGE_PATH = "/iam/v1/token"
_ME = "/iam/v1/me"
_INVITE = "/iam/v1/users:invite"
_SUPERVISOR_KEYS = ("cloudSupervisorEmail", "cloudSupervisorPassword", "cloudSupervisorTotpSecret")
_SUPERVISOR_WHY = ("надзор облака стенда — единственный человек стенда `chart-own` с уровнем "
                   "«2», которого требует глагол приглашения; его адрес, пароль и секрет фактора "
                   "пишет посев церемонии стенда чарта (`stand-chart.sh seed-ceremony`)")
_CLIENT_KEYS = ("oauthClientId", "oauthClientSecret", "oauthRedirectUri")
_CLIENT_WHY = ("посев церемонии стенда посадки own (`stand-chart.sh seed-ceremony`) не завёл "
               "конфиденциального клиента — выковать токен человека нечем")
# Предел опроса операции приглашения и пауза (мс): операция — одна запись строки
# приглашения и членства; предел покрывает загруженный раннер с запасом.
_OP_POLL_CAP = 60
_OP_POLL_MS = 500

# Код по времени в песочнице прогонщика: base32 → HMAC-SHA1 (crypto-js) →
# динамическое усечение → шесть цифр (RFC 6238); то же тело, что у набора
# восстановления, где надзор облака входит тем же способом.
_TOTP_JS = [
    "const __totp = (secretB32, step) => {",
    "  const CryptoJS = require('crypto-js');",
    "  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + '234567';",
    "  let bits = 0, value = 0; const bytes = [];",
    "  for (const ch of String(secretB32 || '').toUpperCase()) {",
    "    const idx = alphabet.indexOf(ch); if (idx < 0) { continue; }",
    "    value = (value << 5) | idx; bits += 5;",
    "    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }",
    "  }",
    "  const toHex = arr => arr.map(b => b.toString(16).padStart(2, '0')).join('');",
    "  const msg = []; let s = step;",
    "  for (let i = 7; i >= 0; i--) { msg[i] = s % 256; s = Math.floor(s / 256); }",
    "  const mac = CryptoJS.HmacSHA1(CryptoJS.enc.Hex.parse(toHex(msg)), CryptoJS.enc.Hex.parse(toHex(bytes)));",
    "  const h = CryptoJS.enc.Hex.stringify(mac);",
    "  const off = parseInt(h.slice(-1), 16);",
    "  const bin = (parseInt(h.slice(off * 2, off * 2 + 8), 16) & 0x7fffffff) % 1000000;",
    "  return String(bin).padStart(6, '0');",
    "};",
]


def _env_ref(key):
    """Подстановка переменной окружения прогона в тело шага: `{{<key>}}`."""
    return "{{" + key + "}}"


def _require_keys(keys, why):
    """Ключи посева заданы — иначе третий исход помеченным утверждением, а не красное."""
    missing = " || ".join(f"!pm.environment.get({js_str(k)})" for k in keys)
    return [
        f"if ({missing}) {{",
        *precondition_not_met("посев стенда: " + ", ".join(keys) + " заданы", why, indent="  "),
        "}",
    ]


def _authorize(p, name):
    """Код церемонии: точка авторизации под сессией `<p>SessionCookie`, PKCE S256."""
    label = name.upper()
    query = _v(p, "Query")
    return Step(
        name=name, method="GET", path=_AUTHORIZE + "?{{" + query + "}}",
        pre_script=[
            *_require_keys(_CLIENT_KEYS, _CLIENT_WHY),
            "const __b64u = (wa) => { let x = CryptoJS.enc.Base64.stringify(wa).split('+').join('-')"
            ".split('/').join('_'); while (x.endsWith('=')) { x = x.slice(0, -1); } return x; };",
            "const __ver = __b64u(CryptoJS.lib.WordArray.random(32));",
            "const __st = __b64u(CryptoJS.lib.WordArray.random(32));",
            f"pm.environment.set({js_str(_v(p, 'Verifier'))}, __ver);",
            f"pm.environment.set({js_str(_v(p, 'State'))}, __st);",
            f"pm.environment.unset({js_str(_v(p, 'OauthCode'))});",
            "const __q = [['response_type', 'code'], ['client_id', pm.environment.get('oauthClientId')],",
            "  ['redirect_uri', pm.environment.get('oauthRedirectUri')], ['scope', 'openid'], ['state', __st],",
            "  ['code_challenge', __b64u(CryptoJS.SHA256(__ver))], ['code_challenge_method', 'S256']]",
            "  .map((kv) => encodeURIComponent(kv[0]) + '=' + encodeURIComponent(kv[1])).join('&');",
            f"pm.environment.set({js_str(query)}, __q);",
            *require_env_url("iamRegistryTokenBaseUrl", _AUTHORIZE + "?{{" + query + "}}", _ISSUANCE_WHY),
            f"if (!pm.environment.get({js_str(_v(p, 'SessionCookie'))})) {{",
            *report_then_skip(f"{label}: сессия не захвачена шагом выше",
                              "вход либо подтверждение выше не выдали kaname_session — точке "
                              "авторизации нечего предъявить; причина — в том шаге, не здесь",
                              indent="  "),
            "} else {",
            f"  pm.request.headers.upsert({{key: 'Cookie', value: 'kaname_session=' + pm.environment.get({js_str(_v(p, 'SessionCookie'))})}});",
            "}",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False, follow_redirects=False,
        test_script=[
            *_status_is(302, label),
            "const __loc = String(pm.response.headers.get('Location') || '');",
            "const __qs = {}; (__loc.split('?')[1] || '').split('#')[0].split('&').forEach((kv) => { const i = kv.indexOf('=');",
            "  if (i > 0) { __qs[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1)); } });",
            f"pm.test({js_str(label + ': перенаправление несёт код и state запроса')}, () => "
            f"pm.expect([typeof __qs.code === 'string' && __qs.code.length > 0, __qs.state === pm.environment.get({js_str(_v(p, 'State'))})]).to.eql([true, true]));",
            f"if (__qs.code) {{ pm.environment.set({js_str(_v(p, 'OauthCode'))}, __qs.code); }}",
        ],
    )


def _exchange(p, name):
    """Обмен кода на токен доступа: `<p>Token`."""
    label = name.upper()
    code_v, redirect_v, verifier_v = f"_{p}FCode", f"_{p}FRedirect", f"_{p}FVerifier"
    return Step(
        name=name, method="POST", path=_EXCHANGE_PATH,
        form=[("grant_type", "authorization_code"), ("code", "{{" + code_v + "}}"),
              ("redirect_uri", "{{" + redirect_v + "}}"), ("code_verifier", "{{" + verifier_v + "}}")],
        pre_script=[
            f"if (!pm.environment.get({js_str(_v(p, 'OauthCode'))})) {{",
            *report_then_skip(f"{label}: код не выдан точкой авторизации",
                              "шаг авторизации выше не выдал code — обменивать нечего; "
                              "причина — в нём, не здесь", indent="  "),
            "}",
            f"pm.variables.set({js_str(code_v)}, encodeURIComponent(pm.environment.get({js_str(_v(p, 'OauthCode'))}) || ''));",
            f"pm.variables.set({js_str(redirect_v)}, encodeURIComponent(pm.environment.get('oauthRedirectUri') || ''));",
            f"pm.variables.set({js_str(verifier_v)}, encodeURIComponent(pm.environment.get({js_str(_v(p, 'Verifier'))}) || ''));",
            *require_env_url("iamRegistryTokenBaseUrl", _EXCHANGE_PATH, _ISSUANCE_WHY),
            "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' + "
            "CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
            "  encodeURIComponent(pm.environment.get('oauthClientId') || '') + ':' + "
            "encodeURIComponent(pm.environment.get('oauthClientSecret') || '')))});",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            f"pm.environment.unset({js_str(_v(p, 'Token'))});",
            *_status_is(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(label + ': выдан токен доступа')}, () => "
            "pm.expect(typeof __j.access_token === 'string' && __j.access_token.length > 0).to.eql(true));",
            f"if (__j.access_token) {{ pm.environment.set({js_str(_v(p, 'Token'))}, __j.access_token); }}",
        ],
    )


def _fresh_totp_step(s, name):
    """Ждёт начала ступени кода по времени, начавшейся ПОСЛЕ входа в шаг.

    Надзор облака входит и в другом наборе того же прогона (восстановление), а
    принятую ступень служба второй раз не принимает (Ф12-15). Коллекции идут одна
    за другой, поэтому ступень, начавшаяся позже первого исполнения этого шага,
    не была предъявлена никем. Ожидание — опросом признака формы входа (чтение,
    ничего не меняющее) с настоящей паузой: одной паузой ждать нельзя, песочница
    прогонщика обрывает скрипт на 30 с. Предел — две ступени."""
    label = name.upper()
    path = f"{_CSRF}?form=login"
    start, count = f"_{s}TotpFrom", f"_{s}TotpWait"
    return Step(
        name=name, method="GET", path=path,
        pre_script=[
            *_require_keys(_SUPERVISOR_KEYS, _SUPERVISOR_WHY),
            *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
            f"if (pm.environment.get({js_str(start + 'Req')}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(start)}, String(Math.floor(Date.now() / 1000 / 30)));",
            f"  pm.environment.set({js_str(count)}, '0');",
            f"  pm.environment.set({js_str(start + 'Req')}, pm.info.requestName);",
            "}",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            f"const __from = parseInt(pm.environment.get({js_str(start)}) || '0', 10);",
            f"const __n = parseInt(pm.environment.get({js_str(count)}) || '0', 10);",
            "if (pm.response.code === 200 && Math.floor(Date.now() / 1000 / 30) <= __from && __n < 70) {",
            f"  pm.environment.set({js_str(count)}, String(__n + 1));",
            "  const _tsd = Date.now(); while (Date.now() - _tsd < 1000) { /* inter-poll delay: next TOTP step not started yet */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(count)});",
            f"pm.environment.unset({js_str(start + 'Req')});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': началась ступень кода, которой до этого набора не было')}, () => "
            "pm.expect(Math.floor(Date.now() / 1000 / 30) > __from).to.eql(true));",
        ],
    )


def _supervisor_bearer(s, tag, *, init=()):
    """Токен надзора облака уровнем «2»: вход со вторым фактором → код → обмен."""
    up = tag.upper()
    return [
        _fresh_totp_step(s, f"{tag}-totp-step-fresh"),
        _csrf_step(s, f"{tag}-csrf-login", "login", with_session=None, init=[
            *_require_keys(_SUPERVISOR_KEYS, _SUPERVISOR_WHY),
            *init,
            f"pm.environment.set({js_str(_v(s, 'Src'))}, '198.18.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
            *(f"pm.environment.unset({js_str(_v(s, n))});" for n in (
                "FormCookie", "SessionCookie", "Csrf", "OauthCode", "Token", "Verifier", "State")),
        ]),
        Step(
            name=f"{tag}-login", method="POST", path=_LOGIN,
            body={"email": _env_ref("cloudSupervisorEmail"), "password": _env_ref("cloudSupervisorPassword"),
                  "secondFactor": {"method": "totp", "code": f"{{{{{_v(s, 'TotpCode')}}}}}"},
                  "csrfToken": f"{{{{{_v(s, 'Csrf')}}}}}"},
            pre_script=[
                *_require_keys(_SUPERVISOR_KEYS, _SUPERVISOR_WHY),
                *_TOTP_JS,
                f"pm.environment.set({js_str(_v(s, 'TotpCode'))}, __totp(pm.environment.get('cloudSupervisorTotpSecret'), Math.floor(Date.now() / 1000 / 30)));",
                *require_env_url("loginLaneBaseUrl", _LOGIN, _LANE_WHY), *_src_pre(s),
                *_with_cookies(("kaname_form", _v(s, "FormCookie"))),
            ],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, f"{up}-LOGIN"),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"pm.test({js_str(up + '-LOGIN: сессия уровня «2» — вход со вторым фактором')}, () => "
                "pm.expect(__j.session && __j.session.assuranceLevel).to.eql('2'));",
                *_capture(s, "kaname_session", "SessionCookie", f"{up}-LOGIN"),
            ],
        ),
        _authorize(s, f"{tag}-authorize"),
        _exchange(s, f"{tag}-exchange"),
    ]


def _me(p, name, test_script, *, retry_predicate=None):
    """Снимок «кто я» под токеном `<p>Token` на собственном публичном фронте.

    `retry_predicate` — только для ПЕРВОГО чтения своего свежего состояния
    (снимок сразу после подтверждения): опрос того же запроса с настоящей паузой,
    предел конечен (`poll_request_until_status`), а по исчерпании исполняются
    настоящие утверждения — ожидание не маскирует отсутствия записи, а лишь не
    принимает за него задержку чтения. Коды отказа не повторяются (`retry_on`
    пуст): отказ на собственном свежем токене — находка, а не окно."""
    label = name.upper()
    guard = [
        *require_env_url("ownRestBaseUrl", _ME, _OWN_WHY),
        f"if (!pm.environment.get({js_str(_v(p, 'Token'))})) {{",
        *report_then_skip(f"{label}: токен не выдан обменом выше",
                          "обмен кода выше не выдал токен — снимок читать нечем; причина — "
                          "в нём, не здесь", indent="  "),
        "}",
    ]
    if retry_predicate is None:
        return Step(name=name, method="GET", path=_ME, auth=_v(p, "Token"), insecure_tls=True,
                    pre_script=guard, test_script=list(test_script))
    step = poll_request_until_status(name, "GET", _ME, list(test_script), auth=_v(p, "Token"),
                                     expect_code=200, retry_on=(), retry_predicate=retry_predicate,
                                     pre_script=guard)
    step.insecure_tls = True
    return step


_PS, _PI = "avS", "avI"
# Записи снимка приглашённого: личная — та, где `roles` содержит `owner`;
# пригласившего — та, чей `accountId` равен аккаунту пригласившего. Пустой
# `roles` в JSON не печатается — его отсутствие читается как пустой перечень.
_F427_ME_JS = [
    "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
    "const __acc = Array.isArray(__j.accounts) ? __j.accounts : [];",
    "const __roles = (a) => Array.isArray(a && a.roles) ? a.roles : [];",
    f"const __inviter = pm.environment.get({js_str(_v(_PS, 'AccountId'))});",
    "const __owned = __acc.filter((a) => __roles(a).includes('owner'));",
    "const __theirs = __acc.filter((a) => a.accountId === __inviter);",
]
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-INVITEE-SNAPSHOT-NAMES-TWO-ACCOUNTS",
    title="Ф4-27: у приглашённого после подтверждения адреса снимок «кто я» называет ровно два "
          "аккаунта — личный с owner, заведённый активацией, и аккаунт пригласившего без owner; "
          "пароль приглашённого входит — ACTIVE с паролем (AWI-08, активация приглашения)",
    classes=["CRUD", "STATE"],
    priority="P1",
    steps=[
        # Пригласивший: надзор облака уровнем «2». Адрес приглашённого назначается
        # здесь же — приглашение заводится раньше его регистрации.
        *_supervisor_bearer(_PS, "f427-inviter", init=_person_init(_PI, "f427")),
        _me(_PS, "f427-inviter-owned-account", [
            *_status_is(200, "F427-INVITER-ME"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "const __own = (Array.isArray(__j.accounts) ? __j.accounts : [])"
            ".filter((a) => Array.isArray(a.roles) && a.roles.includes('owner'));",
            "pm.test('F427-INVITER-ME: аккаунт, которым пригласивший владеет, ровно один (фикстура)', () => "
            "pm.expect(__own.length).to.eql(1));",
            f"if (__own.length === 1) {{ pm.environment.set({js_str(_v(_PS, 'AccountId'))}, __own[0].accountId); }}",
        ]),
        # Приглашение в его аккаунт без выдачи роли.
        Step(
            name="f427-invite", method="POST", path=_INVITE,
            body={"accountId": f"{{{{{_v(_PS, 'AccountId')}}}}}", "email": f"{{{{{_v(_PI, 'Email')}}}}}"},
            auth=_v(_PS, "Token"), insecure_tls=True,
            pre_script=[
                *require_env_url("ownRestBaseUrl", _INVITE, _OWN_WHY),
                f"if (!pm.environment.get({js_str(_v(_PS, 'AccountId'))}) || !pm.environment.get({js_str(_v(_PS, 'Token'))})) {{",
                *report_then_skip("F427-INVITE: аккаунт либо токен пригласившего не захвачен",
                                  "шаги выше не назвали аккаунт пригласившего либо не выдали его "
                                  "токен — приглашать некуда; причина — в них, не здесь", indent="  "),
                "}",
                f"pm.environment.unset({js_str(_v(_PI, 'InviteOp'))});",
            ],
            test_script=[
                *_status_is(200, "F427-INVITE"),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                "pm.test('F427-INVITE: ответ — операция с id', () => "
                "pm.expect(typeof __j.id === 'string' && __j.id.length > 0).to.eql(true));",
                f"if (typeof __j.id === 'string' && __j.id) {{ pm.environment.set({js_str(_v(_PI, 'InviteOp'))}, __j.id); }}",
            ],
        ),
        Step(
            name="f427-invite-op", method="GET", path="/operations/{{" + _v(_PI, "InviteOp") + "}}",
            auth=_v(_PS, "Token"), insecure_tls=True,
            pre_script=[
                *require_env_url("ownRestBaseUrl", "/operations/{{" + _v(_PI, "InviteOp") + "}}", _OWN_WHY),
                f"if (!pm.environment.get({js_str(_v(_PI, 'InviteOp'))})) {{",
                *report_then_skip("F427-INVITE-OP: операция не возвращена шагом выше",
                                  "приглашение выше отвергнуто синхронно либо не вернуло id "
                                  "операции — опрашивать нечего; причина — в нём, не здесь",
                                  indent="  "),
                "}",
                "if (pm.environment.get('_f427opStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_f427opCount', '0');",
                "  pm.environment.set('_f427opStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "const __n = parseInt(pm.environment.get('_f427opCount') || '0', 10);",
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"if (pm.response.code === 200 && !__j.done && __n < {_OP_POLL_CAP}) {{",
                "  pm.environment.set('_f427opCount', String(__n + 1));",
                f"  const _opd = Date.now(); while (Date.now() - _opd < {_OP_POLL_MS}) {{ /* inter-poll delay: operation not done yet */ }}",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_f427opCount');",
                "pm.environment.unset('_f427opStarted');",
                *_status_is(200, "F427-INVITE-OP"),
                "pm.test('F427-INVITE-OP: операция завершена', () => pm.expect(__j.done).to.eql(true));",
                "pm.test('F427-INVITE-OP: операция без ошибки и с ответом', () => "
                "pm.expect([!!__j.error, !!__j.response], JSON.stringify(__j.error || {})).to.eql([false, true]));",
                "pm.test('F427-INVITE-OP: строка приглашения — на адрес приглашённого и ожидает', () => "
                f"pm.expect([__j.response && __j.response.email, __j.response && __j.response.inviteStatus])"
                f".to.eql([pm.environment.get({js_str(_v(_PI, 'Email'))}), 'PENDING']));",
                "if (!__j.error && __j.response && __j.response.id) {",
                f"  pm.environment.set({js_str(_v(_PI, 'InvitedUserId'))}, __j.response.id);",
                "}",
            ],
        ),
        # Приглашённый регистрируется той же полосой, что человек с улицы, и
        # подтверждает адрес выданной регистрацией сессией.
        _csrf_step(_PI, "f427-csrf-register", "register", with_session=None),
        _post(_PI, "f427-register", _REGISTER,
              {"email": f"{{{{{_v(_PI, 'Email')}}}}}", "password": f"{{{{{_v(_PI, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(_PI, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, "F427-REGISTER"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  "pm.test('F427-REGISTER: сессия в положении подтверждения — emailVerified false', () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === false).to.eql(true));",
                  *_capture(_PI, "kaname_session", "SessionCookie", "F427-REGISTER"),
                  *_capture(_PI, "kaname_form", "FormCookie", "F427-REGISTER", required=False),
              ]),
        _await_letter(_PI, "f427-letter"),
        *_confirm(_PI, "f427-verify", "Code", test_script=_confirmed(_PI, "F427-VERIFY")),
        _authorize(_PI, "f427-invitee-authorize"),
        _exchange(_PI, "f427-invitee-exchange"),
        _me(_PI, "f427-invitee-snapshot", [
            *_status_is(200, "F427-ME"),
            *_F427_ME_JS,
            "pm.test('F427-ME: снимок — того, кого приглашали (строка приглашения, контроль)', () => "
            f"pm.expect(!!__j.userId && __j.userId === pm.environment.get({js_str(_v(_PI, 'InvitedUserId'))})).to.eql(true));",
            "pm.test('F427-ME: записей accounts ровно две', () => pm.expect(__acc.length).to.eql(2));",
            "pm.test('F427-ME: запись с owner ровно одна — личный аккаунт', () => pm.expect(__owned.length).to.eql(1));",
            "pm.test('F427-ME: личный аккаунт — не аккаунт пригласившего', () => "
            "pm.expect(__owned.length === 1 && !!__inviter && __owned[0].accountId !== __inviter).to.eql(true));",
            "pm.test('F427-ME: запись аккаунта пригласившего есть и одна', () => pm.expect(__theirs.length).to.eql(1));",
            "pm.test('F427-ME: у аккаунта пригласившего owner нет', () => "
            "pm.expect(__theirs.length === 1 && !__roles(__theirs[0]).includes('owner')).to.eql(true));",
        ], retry_predicate="(() => { let j; try { j = pm.response.json(); } catch (e) { return false; } "
                           "return !Array.isArray(j.accounts) || j.accounts.length < 2; })()"),
        # AWI-08 (активация приглашения): активация в исходе подтверждения адреса даёт
        # ACTIVE С ПАРОЛЕМ — пароль регистрации приглашённого входит, положение обычное.
        *_login(_PI, "f427-awi08-invitee-login-with-password", "Password", verified=True),
    ],
))


# ═══════════════════════════════════════════════════════════════════════════
# ПРИЁМКА Ф4 — ПРОЧИЕ ПОЗИЦИИ УРОВНЯ E (kaname#925).
#
# `docs/engineering/acceptance/registration-and-its-three-consequences.md`.
# Наблюдение исхода — тем же путём, что у Ф4-27 выше: регистрация и подтверждение
# адреса на полосе формы, снимок «кто я» и чтения в аккаунте — токеном нашей
# церемонии на собственном публичном фронте (§7а `e2e-flow.md`: сущности службы
# проверяются в её доме, край службы — её REST-фронт). Печенье регистрации в
# принципала здесь превращает не край, а точка авторизации службы; связку края
# с полосой (форма Ф-ж через край платформы) этот набор не переутверждает.
#
# ЧЕГО ЭТОТ БЛОК НЕ УТВЕРЖДАЕТ — идентификаторы КОММЕНТАРИЕМ, а не строкой:
#   · полоса времени Ф4-14…16 (критерий Ф1-48) — измерительная проба: на стенде
#     `chart-own` (kind на общем ранере) размах выше потолка годности by
#     construction; держатель — уровень I
#     (`internal/apps/kaname/api/registration/timing_probe_test.go`);
#   · проект «по умолчанию» личного аккаунта (форма Ф4-05) у человека с улицы —
#     уровень I; у приглашённого его число читает кейс Ф4-23 ниже, потому что
#     позиция называет его в «Тогда».
# ═══════════════════════════════════════════════════════════════════════════
_ACCOUNTS = "/iam/v1/accounts"
_PROJECTS = "/iam/v1/projects"
_CHANGE = "/iam/v1/auth/email-change"
_CHANGE_CONFIRM = "/iam/v1/auth/email-change/confirm"
_HEAD_CHANGE = "Код подтверждения смены:"
# Потолок темпа заведения аккаунтов одной личностью — величина профиля, с которой
# стенд поднят (`authn.registration.admissionsPerWindow`): регистрация списывает
# первое заведение, прочие — `AccountService.Create`. Ключ узла в профиле один.
_ADMISSIONS = _re.findall(r"^    admissionsPerWindow: (\d+)\s*$", _PROFILE.read_text(encoding="utf-8"), _re.M)
if len(_ADMISSIONS) != 1:
    raise SystemExit(f"kaname-address-verification: ключ профиля authn.registration.admissionsPerWindow "
                     f"найден {len(_ADMISSIONS)} раз в {_PROFILE} — ждали ровно один")
_ADMISSIONS = int(_ADMISSIONS[0])
if _ADMISSIONS < 1:
    raise SystemExit("kaname-address-verification: admissionsPerWindow < 1 — исчерпать окно сверх "
                     "первого заведения нечем, «Дано» Ф4-12 не строится")
# Отрицательный контроль текста единого отказа (Ф4-11, Р3 свойства 2 и 3).
_REG_FORBIDDEN = ("in use", "taken", "exists", "registered", "limit", "rate", "quota", "seconds")


def _token_guard(p, label):
    return [
        f"if (!pm.environment.get({js_str(_v(p, 'Token'))})) {{",
        *report_then_skip(f"{label}: токен не выдан обменом выше",
                          "обмен кода выше не выдал токен — фронту предъявить нечего; причина — "
                          "в нём, не здесь", indent="  "),
        "}",
    ]


def _own(p, name, method, path, test_script, *, body=None, need=()):
    """Обращение к собственному публичному фронту токеном `<p>Token`.

    `need` — переменные пути и тела, захваченные шагами выше: пустая — отказ с
    именем и отмена запроса, а не запрос по адресу с `{{…}}`."""
    label = name.upper()
    guards = []
    for var in need:
        guards += [
            f"if (!pm.environment.get({js_str(var)})) {{",
            *report_then_skip(f"{label}: {var} не захвачен шагом выше",
                              "шаг выше не назвал значение, без которого обращение не "
                              "собрать; причина — в нём, не здесь", indent="  "),
            "}",
        ]
    return Step(name=name, method=method, path=path, body=body, auth=_v(p, "Token"), insecure_tls=True,
                pre_script=[*require_env_url("ownRestBaseUrl", path, _OWN_WHY), *_token_guard(p, label), *guards],
                test_script=list(test_script))


def _with_own_guard(step):
    """Шаг опроса фронта (`poll_request_until_status`): фронт стенда — под своим УЦ."""
    step.insecure_tls = True
    return step


def _op_done(p, name, op_var, tests):
    """Опрос операции до done с настоящей паузой; затем — исход без ошибки и `tests`."""
    label = name.upper()
    path = "/operations/{{" + op_var + "}}"
    counter, started = f"_op925_{name}".replace("-", "_"), f"_op925s_{name}".replace("-", "_")
    return Step(
        name=name, method="GET", path=path, auth=_v(p, "Token"), insecure_tls=True,
        pre_script=[
            *require_env_url("ownRestBaseUrl", path, _OWN_WHY),
            f"if (!pm.environment.get({js_str(op_var)})) {{",
            *report_then_skip(f"{label}: операция не возвращена шагом выше",
                              "мутация выше отвергнута синхронно либо не вернула id операции — "
                              "опрашивать нечего; причина — в ней, не здесь", indent="  "),
            "}",
            f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter)}, '0');",
            f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
        ],
        test_script=[
            f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"if (pm.response.code === 200 && !__j.done && __n < {_OP_POLL_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _o925 = Date.now(); while (Date.now() - _o925 < {_OP_POLL_MS}) {{ /* inter-poll delay: operation not done yet */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': операция завершена')}, () => pm.expect(__j.done).to.eql(true));",
            f"pm.test({js_str(label + ': операция без ошибки и с ответом')}, () => "
            "pm.expect([!!__j.error, !!__j.response], JSON.stringify(__j.error || {})).to.eql([false, true]));",
            *tests,
        ],
    )


def _mutation(p, name, method, path, body, op_var, *, need=()):
    """Мутация фронта: 200 и операция с id в `op_var`."""
    label = name.upper()
    return _own(p, name, method, path, [
        f"pm.environment.unset({js_str(op_var)});",
        *_status_is(200, label),
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        f"pm.test({js_str(label + ': ответ — операция с id')}, () => "
        "pm.expect(typeof __j.id === 'string' && __j.id.length > 0).to.eql(true));",
        f"if (typeof __j.id === 'string' && __j.id) {{ pm.environment.set({js_str(op_var)}, __j.id); }}",
    ], body=body, need=need)


def _token_of(p, tag):
    """Токен человека `<p>` нашей церемонией под его сессией `<p>SessionCookie`."""
    return [_authorize(p, f"{tag}-authorize"), _exchange(p, f"{tag}-exchange")]


def _registration_refused(label, body_var):
    """Единый отказ регистрации (Ф4-11, Р3 редакции 8): 400, code 9, текст дословно,
    REGISTRATION_REFUSED, без Retry-After и носителя; текст не называет ни причины,
    ни величины. Сырое тело — в `body_var` для побайтовой сверки с близнецом."""
    return [
        *_refused(400, 9, _REG_REFUSED, label, reason="REGISTRATION_REFUSED"),
        f"pm.test({js_str(label + ': заголовка Retry-After нет')}, () => "
        "pm.expect(pm.response.headers.has('Retry-After')).to.eql(false));",
        f"pm.test({js_str(label + ': в тексте ни одной цифры')}, () => pm.expect(/[0-9]/.test(String(__r.message))).to.eql(false));",
        *(f"pm.test({js_str(label + ': текст не называет «' + w + '»')}, () => "
          f"pm.expect(String(__r.message).toLowerCase().indexOf({js_str(w)})).to.eql(-1));" for w in _REG_FORBIDDEN),
        f"pm.environment.set({js_str(body_var)}, String(pm.response.code) + ' ' + pm.response.text());",
    ]


def _register_address(p, tag, email_var, tests):
    """Регистрация адресом `email_var` человеком `<p>` (свой источник, свои пароли)."""
    return [
        _csrf_step(p, f"{tag}-csrf-register", "register", init=_person_init(p, tag), with_session=None),
        _post(p, f"{tag}-register", _REGISTER,
              {"email": "{{" + email_var + "}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              extra_pre=[
                  f"if (!pm.environment.get({js_str(email_var)})) {{",
                  *report_then_skip(f"{tag.upper()}-REGISTER: адрес {email_var} не назначен шагом выше",
                                    "адрес, которым регистрируется кейс, назначает шаг выше; "
                                    "причина — в нём, не здесь", indent="  "),
                  "}",
              ],
              test_script=tests),
    ]


def _owned_accounts_js(label, expected, user_var):
    """Снимок «кто я»: записей с `owner` ровно `expected`, и снимок — того человека."""
    return [
        *_status_is(200, label),
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        "const __acc = Array.isArray(__j.accounts) ? __j.accounts : [];",
        "const __owned = __acc.filter((a) => Array.isArray(a.roles) && a.roles.includes('owner'));",
        f"pm.test({js_str(label + ': снимок — того, кто зарегистрировался (userId ответа регистрации)')}, () => "
        f"pm.expect(!!__j.userId && __j.userId === pm.environment.get({js_str(user_var)})).to.eql(true));",
        f"pm.test({js_str(label + f': записей с owner ровно {expected}')}, () => pm.expect(__owned.length).to.eql({expected}));",
    ]


def _user_id_capture(p, label):
    """Ответ регистрации называет `user.id` формы идентификатора — в `<p>UserId`."""
    return [
        f"pm.test({js_str(label + ': ответ называет user.id формы идентификатора человека')}, () => "
        "pm.expect(/^usr[0-9a-z]{17}$/.test(String(__j.user && __j.user.id))).to.eql(true));",
        f"if (__j.user && __j.user.id) {{ pm.environment.set({js_str(_v(p, 'UserId'))}, __j.user.id); }}",
    ]


# ───────────────────────────────────────────────────────────────────────────
# Ф4-01, Ф4-13, Ф4-26: одна регистрация свободным адресом при неисчерпанном пределе
# (свежий носитель) — четыре следствия; четвёртое видит снимок «кто я» сразу после
# подтверждения, без ожидания (Ф-з читает базу службы, а не материализацию прав).
# Ф4-13 — положительный контроль к отказам Ф4-11 и Ф4-12 следующего кейса.
# ───────────────────────────────────────────────────────────────────────────
_P01 = "avR"
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-REGISTRATION-HAS-FOUR-CONSEQUENCES",
    title="Ф4-01, Ф4-13, Ф4-26: регистрация свободным адресом свежего носителя — 200: зеркало (user.id), "
          "адрес не подтверждён и письмо с кодом поставлено, сессия выдана и узнана сразу; после "
          "подтверждения снимок «кто я» без ожидания — тот же userId и ровно одна запись с owner",
    classes=["CRUD", "STATE"],
    priority="P0",
    steps=[
        *_register(_P01, "f401", extra_tests=[
            *_user_id_capture(_P01, "F401-REGISTER"),
            "pm.test('F401-REGISTER: адрес ответа — присланный', () => "
            f"pm.expect(__j.user && __j.user.email).to.eql(pm.environment.get({js_str(_v(_P01, 'Email'))})));",
            "pm.test('F401-REGISTER: сессия уровня «1»', () => pm.expect(__j.session && __j.session.assuranceLevel).to.eql('1'));",
        ]),
        # Сессия годна тем же ответом: носитель узнан — и назван положением.
        _session_probe(_P01, "f401-session-recognized-at-once", "SessionCookie", "position"),
        # Подтверждение затребовано: письмо с кодом дошло до приёмника стенда.
        _await_letter(_P01, "f401-verification-requested"),
        *_confirm(_P01, "f401-verify", "Code", test_script=_confirmed(_P01, "F401-VERIFY")),
        *_token_of(_P01, "f426"),
        # Ф4-26: ОДНО чтение, без опроса — запись снимка не ждёт доставки.
        _me(_P01, "f426-snapshot-at-once", [
            *_owned_accounts_js("F426-ME", 1, _v(_P01, "UserId")),
            "pm.test('F426-ME: записей accounts ровно одна', () => pm.expect(__acc.length).to.eql(1));",
            "pm.test('F426-ME: эта запись — личный аккаунт с owner', () => "
            "pm.expect(__acc.length === 1 && __owned.length === 1 && __acc[0].accountId === __owned[0].accountId).to.eql(true));",
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф4-21, Ф4-22: окно материализации — первое действие в своём аккаунте той же
# сессией (носитель после подтверждения, токен её церемонии).
#
# Ф4-21 по приёмке — ДИЗЪЮНКЦИЯ, и это «Тогда» позиции, а не допуск кейса: либо
# действие проходит, либо отказ называет следующий шаг (повторить) и не выглядит
# как «прав нет». Каждая ветвь утверждается своими условиями, исполненная
# печатается: отказ без названного шага (`AUTHZ_DENIED`, «permission denied») —
# красное. Ф4-22: то же действие, повторённое в пределах окна, проходит — опрос
# первого чтения своего свежего аккаунта с конечным пределом
# (`poll_request_until_status`), по исчерпании судит настоящее утверждение.
# ───────────────────────────────────────────────────────────────────────────
_P21 = "avM"
_F421_PATH = _ACCOUNTS + "/{{" + _v(_P21, "PersonalId") + "}}"
CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-FIRST-ACTION-IN-OWN-ACCOUNT",
    title="Ф4-21, Ф4-22: первое действие в своём аккаунте той же сессией — проходит либо отказ называет "
          "повтор и не выглядит как «прав нет»; повторённое в пределах окна — проходит, аккаунт — его",
    classes=["STATE", "AUTHZ"],
    priority="P1",
    steps=[
        *_register(_P21, "f421", extra_tests=_user_id_capture(_P21, "F421-REGISTER")),
        _await_letter(_P21, "f421-letter"),
        *_confirm(_P21, "f421-verify", "Code", test_script=_confirmed(_P21, "F421-VERIFY")),
        *_token_of(_P21, "f421"),
        _me(_P21, "f421-personal-account", [
            *_owned_accounts_js("F421-ME", 1, _v(_P21, "UserId")),
            f"if (__owned.length === 1) {{ pm.environment.set({js_str(_v(_P21, 'PersonalId'))}, __owned[0].accountId); }}",
        ]),
        _own(_P21, "f421-first-action", "GET", _F421_PATH, [
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "if (pm.response.code === 200) {",
            "  console.log('[Ф4-21] исполнена ветвь «действие проходит»');",
            "  pm.test('F421: действие прошло — ответ называет свой аккаунт и его владельца', () => "
            f"pm.expect([__j.id, __j.ownerUserId]).to.eql([pm.environment.get({js_str(_v(_P21, 'PersonalId'))}), "
            f"pm.environment.get({js_str(_v(_P21, 'UserId'))})]));",
            "} else {",
            "  console.log('[Ф4-21] исполнена ветвь «отказ»: ' + pm.response.code + ' ' + pm.response.text());",
            "  const __why = String(__j.message || '').toLowerCase();",
            "  const __info = (Array.isArray(__j.details) ? __j.details : [])"
            ".filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            "  pm.test('F421: отказ называет следующий шаг — повторить', () => "
            "pm.expect(/try again|retry/.test(__why)).to.eql(true));",
            "  pm.test('F421: отказ не выглядит как «прав нет» (не AUTHZ_DENIED)', () => "
            "pm.expect(__info.reason !== 'AUTHZ_DENIED' && __why.indexOf('permission denied') < 0).to.eql(true));",
            "}",
        ], need=(_v(_P21, "PersonalId"),)),
        _with_own_guard(poll_request_until_status(
            "f422-after-delivery", "GET", _F421_PATH, [
                *_status_is(200, "F422"),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                "pm.test('F422: действие прошло — аккаунт тот, владелец — зарегистрировавшийся', () => "
                f"pm.expect([__j.id, __j.ownerUserId]).to.eql([pm.environment.get({js_str(_v(_P21, 'PersonalId'))}), "
                f"pm.environment.get({js_str(_v(_P21, 'UserId'))})]));",
            ], auth=_v(_P21, "Token"), retry_on=(403, 404, 503),
            pre_script=[*require_env_url("ownRestBaseUrl", _F421_PATH, _OWN_WHY), *_token_guard(_P21, "F422")])),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф4-11, Ф4-12: занятый адрес и исчерпанный предел носителя отвечают ОДНИМ
# отказом — побайтово.
#
# «ДАНО» Ф4-12 — СВОБОДНЫЙ адрес, чей носитель исчерпал окно. Носитель окна —
# адрес в момент чеканки личности, и смена адреса окна не переносит
# (`admission-rate-carrier-is-fixed-at-registration.md`, A197-01). Строится
# глаголами продукта: X регистрируется (первое заведение), заводит ещё
# `admissionsPerWindow − 1` аккаунтов, меняет адрес на X′ — адрес X свободен, а его
# окно полно; регистрация адресом X отвергается.
#
# БЛИЗНЕЦ В ОДИН ФАКТ (отличает его только полнота окна): Y регистрируется, НЕ
# заводит ни одного аккаунта сверх личного, меняет адрес — регистрация адресом Y
# проходит. Без него отказ Ф4-12 был бы неотличим от «адрес, однажды бывший
# занятым, не принимается никогда».
#
# Ф4-11: владелец O, регистрация его адресом — тот же отказ, тело побайтово равно
# отказу Ф4-12; у O по-прежнему ровно один личный аккаунт. Положительный контроль
# обоим — Ф4-13 (кейс выше).
# ───────────────────────────────────────────────────────────────────────────
_PX, _PXR, _PY, _PYR, _PO, _POR = "avX", "avXr", "avY", "avYr", "avO", "avOr"


def _extra_account(p, tag, n):
    """`AccountService.Create` — n-е заведение сверх личного аккаунта, до done без ошибки."""
    op = _v(p, f"AccOp{n}")
    return [
        _mutation(p, f"{tag}-create-account-{n}", "POST", _ACCOUNTS,
                  {"name": f"{{{{{_v(p, f'AccName{n}')}}}}}"}, op),
        _op_done(p, f"{tag}-create-account-{n}-op", op, [
            f"pm.test({js_str(tag.upper() + f'-ACCOUNT-{n}: ответ — аккаунт, которым он владеет')}, () => "
            f"pm.expect(__j.response && __j.response.ownerUserId).to.eql(pm.environment.get({js_str(_v(p, 'UserId'))})));",
        ]),
    ]


def _move_address(p, tag):
    """Смена адреса на `<p>MovedEmail`: запрос, код из письма на новый адрес, предъявление."""
    path = f"/codes?to={{{{{_v(p, 'MovedEmail')}}}}}&after={_urlparse.quote(_HEAD_CHANGE)}"
    counter, started = f"_mv925_{tag}".replace("-", "_"), f"_mv925s_{tag}".replace("-", "_")
    label = f"{tag.upper()}-MOVE"
    return [
        _csrf_step(p, f"{tag}-move-csrf", "email-change", init=[
            f"pm.environment.set({js_str(_v(p, 'MovedEmail'))}, String(pm.environment.get({js_str(_v(p, 'Email'))})).replace('@', '-moved@'));",
            f"pm.environment.set({js_str(_v(p, 'OldEmail'))}, pm.environment.get({js_str(_v(p, 'Email'))}));",
        ]),
        _post(p, f"{tag}-move-request", _CHANGE,
              {"newEmail": f"{{{{{_v(p, 'MovedEmail')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie", test_script=[
                  *_status_is(200, label + "-REQUEST"),
                  f"pm.test({js_str(label + '-REQUEST: тело — пустой объект')}, () => pm.expect(pm.response.text()).to.eql('{{}}'));",
              ]),
        Step(
            name=f"{tag}-move-letter", method="GET", path=path, auth="anonymous", cookie_jar=False,
            pre_script=[
                *require_env_url("standMailboxUrl", path, _MAILBOX_WHY),
                f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
                f"  pm.environment.set({js_str(counter)}, '0');",
                f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
                "}",
            ],
            test_script=[
                f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
                "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
                "const __all = (Array.isArray(__codes) ? __codes : []).filter((c) => typeof c === 'string');",
                f"if (pm.response.code === 200 && __all.length === 0 && __n < {_MAIL_WAIT_CAP}) {{",
                f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
                f"  const _mvd = Date.now(); while (Date.now() - _mvd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                f"pm.environment.unset({js_str(counter)});",
                f"pm.environment.unset({js_str(started)});",
                *_status_is(200, label + "-LETTER"),
                f"pm.test({js_str(label + '-LETTER: письмо смены с кодом формы XXXXX-XXXXX дошло на новый адрес')}, () => "
                "pm.expect(__all.length === 1 && /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(__all[0])).to.eql(true));",
                f"if (__all.length > 0) {{ pm.environment.set({js_str(_v(p, 'ChangeCode'))}, __all[__all.length - 1]); }}",
            ],
        ),
        _csrf_step(p, f"{tag}-move-confirm-csrf", "email-change-confirm"),
        _post(p, f"{tag}-move-confirm", _CHANGE_CONFIRM,
              {"code": f"{{{{{_v(p, 'ChangeCode')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie", test_script=[
                  *_status_is(200, label + "-CONFIRM"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(label + '-CONFIRM: смена принята — session с emailVerified true')}, () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
              ]),
    ]


def _account_names_init(p, count):
    return [
        "{",
        "  const __rn = () => Math.floor(Math.random() * 2176782336).toString(36);",
        *(f"  pm.environment.set({js_str(_v(p, f'AccName{n}'))}, ('f412-' + String(pm.environment.get('runId') || '').slice(0, 12) + '-' + __rn() + {js_str('-' + str(n))}).toLowerCase().replace(/[^a-z0-9-]/g, '-'));"
          for n in range(1, count + 1)),
        "}",
    ]


CASES.append(Case(
    id="IAM-ADDRVERIFY-NEG-REGISTRATION-REFUSAL-HIDES-OCCUPANCY-AND-PACE",
    title="Ф4-11, Ф4-12: занятый адрес и свободный адрес исчерпанного носителя — один отказ регистрации, "
          "побайтово (400, code 9, REGISTRATION_REFUSED, текст Р3, без Retry-After, без цифр и причины); "
          "у владельца адреса по-прежнему один личный аккаунт; близнец — носитель с неполным окном "
          "после смены адреса регистрируется",
    classes=["NEG", "SEC", "BVA"],
    priority="P0",
    steps=[
        # Ф4-12 «Дано»: X исчерпывает окно своего носителя и уходит с адреса.
        *_register(_PX, "f412x", extra_tests=_user_id_capture(_PX, "F412X-REGISTER")),
        _await_letter(_PX, "f412x-letter"),
        *_confirm(_PX, "f412x-verify", "Code", test_script=_confirmed(_PX, "F412X-VERIFY")),
        *_token_of(_PX, "f412x"),
        Step(name="f412x-account-names", method="GET", path=_ME, auth=_v(_PX, "Token"), insecure_tls=True,
             pre_script=[*_account_names_init(_PX, _ADMISSIONS - 1),
                         *require_env_url("ownRestBaseUrl", _ME, _OWN_WHY), *_token_guard(_PX, "F412X-ME")],
             test_script=_owned_accounts_js("F412X-ME", 1, _v(_PX, "UserId"))),
        *(s for n in range(1, _ADMISSIONS) for s in _extra_account(_PX, "f412x", n)),
        *_move_address(_PX, "f412x"),
        *_register_address(_PXR, "f412", _v(_PX, "OldEmail"),
                           _registration_refused("F412", "avF412Refusal")),
        # Близнец: Y — окно не полно (только личный аккаунт), та же смена адреса.
        *_register(_PY, "f412y", extra_tests=_user_id_capture(_PY, "F412Y-REGISTER")),
        _await_letter(_PY, "f412y-letter"),
        *_confirm(_PY, "f412y-verify", "Code", test_script=_confirmed(_PY, "F412Y-VERIFY")),
        *_move_address(_PY, "f412y"),
        *_register_address(_PYR, "f412-twin", _v(_PY, "OldEmail"), [
            *_status_is(200, "F412-TWIN"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "pm.test('F412-TWIN: адрес, с которого ушли при неполном окне, регистрируется — сессия выдана', () => "
            "pm.expect(!!__j.session && __j.session.emailVerified === false).to.eql(true));",
            *_capture(_PYR, "kaname_session", "SessionCookie", "F412-TWIN"),
        ]),
        # Ф4-11: занятый адрес — тот же отказ, у владельца ничего не заведено.
        *_register(_PO, "f411o", extra_tests=_user_id_capture(_PO, "F411O-REGISTER")),
        _await_letter(_PO, "f411o-letter"),
        *_confirm(_PO, "f411o-verify", "Code", test_script=_confirmed(_PO, "F411O-VERIFY")),
        *_register_address(_POR, "f411", _v(_PO, "Email"), [
            *_registration_refused("F411", "avF411Refusal"),
            "pm.test('F411: тело и код побайтово равны отказу Ф4-12', () => "
            "pm.expect(String(pm.environment.get('avF411Refusal'))).to.eql(String(pm.environment.get('avF412Refusal'))));",
        ]),
        *_token_of(_PO, "f411o"),
        _me(_PO, "f411-owner-still-one-personal-account", _owned_accounts_js("F411-OWNER-ME", 1, _v(_PO, "UserId"))),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф4-23 (редакция 6): приглашённый регистрируется той же полосой. До
# подтверждения: строка приглашения сохранила идентификатор, она и членство в
# аккаунте пригласившего ожидают, личных аккаунтов у приглашённого ноль. Близнец
# в один факт (отметка подтверждения) — после подтверждения той же сессией: личный
# аккаунт ровно один, его владелец — приглашённый, в нём один проект; строка и
# членство действующие; аккаунт пригласившего владельца не сменил.
#
# Пригласивший — надзор облака (уровень «2» глагола приглашения), как у Ф4-27.
# Чтения строки, членства и перечня аккаунтов — его токеном (`system_admin`
# кластера). «Ноль личных аккаунтов» читается тем же перечнем, что «ровно один»
# после подтверждения: положительный близнец доказывает, что перечень видит
# аккаунт приглашённого, когда тот есть.
# ───────────────────────────────────────────────────────────────────────────
_P23S, _P23I = "avT", "avJ"
_F423_USER = "/iam/v1/users/{{" + _v(_P23I, "InvitedUserId") + "}}"
_F423_MEMBERS = _ACCOUNTS + "/{{" + _v(_P23S, "AccountId") + "}}/memberships?pageSize=1000"
_F423_ACCOUNTS = _ACCOUNTS + "?pageSize=1000"


def _f423_reads(phase, invite_status, member_state, owned):
    up = phase.upper()
    return [
        _own(_P23S, f"f423-{phase}-invitee-row", "GET", _F423_USER, [
            *_status_is(200, f"F423-{up}-ROW"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(f'F423-{up}-ROW: строка приглашённого — {invite_status}')}, () => "
            f"pm.expect(__j.inviteStatus).to.eql({js_str(invite_status)}));",
        ], need=(_v(_P23I, "InvitedUserId"),)),
        _own(_P23S, f"f423-{phase}-membership", "GET", _F423_MEMBERS, [
            *_status_is(200, f"F423-{up}-MEMBERSHIP"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(f'F423-{up}-MEMBERSHIP: перечень членств — одной страницей')}, () => "
            "pm.expect(String(__j.nextPageToken || '')).to.eql(''));",
            f"const __m = (Array.isArray(__j.memberships) ? __j.memberships : []).filter((m) => m.userId === pm.environment.get({js_str(_v(_P23I, 'InvitedUserId'))}));",
            f"pm.test({js_str(f'F423-{up}-MEMBERSHIP: членство приглашённого одно и {member_state}')}, () => "
            f"pm.expect(__m.map((m) => m.state)).to.eql([{js_str(member_state)}]));",
        ], need=(_v(_P23S, "AccountId"), _v(_P23I, "InvitedUserId"))),
        (_with_own_guard(poll_request_until_status(
            f"f423-{phase}-owned-accounts", "GET", _F423_ACCOUNTS, _f423_owned_js(up, owned),
            auth=_v(_P23S, "Token"), retry_on=(),
            retry_predicate=_f423_owned_short(owned),
            pre_script=[*require_env_url("ownRestBaseUrl", _F423_ACCOUNTS, _OWN_WHY), *_token_guard(_P23S, f"F423-{up}")]))
         if owned else
         _own(_P23S, f"f423-{phase}-owned-accounts", "GET", _F423_ACCOUNTS, _f423_owned_js(up, owned))),
    ]


def _f423_owned_js(up, owned):
    return [
        *_status_is(200, f"F423-{up}-ACCOUNTS"),
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        f"pm.test({js_str(f'F423-{up}-ACCOUNTS: перечень аккаунтов — одной страницей')}, () => "
        "pm.expect(String(__j.nextPageToken || '')).to.eql(''));",
        f"const __o = (Array.isArray(__j.accounts) ? __j.accounts : []).filter((a) => a.ownerUserId === pm.environment.get({js_str(_v(_P23I, 'InvitedUserId'))}));",
        f"pm.test({js_str(f'F423-{up}-ACCOUNTS: аккаунтов, которыми владеет приглашённый, — {owned}')}, () => "
        f"pm.expect(__o.length).to.eql({owned}));",
        f"if (__o.length === 1) {{ pm.environment.set({js_str(_v(_P23I, 'PersonalId'))}, __o[0].id); }}",
        f"pm.test({js_str(f'F423-{up}-ACCOUNTS: аккаунт пригласившего — по-прежнему его')}, () => "
        f"pm.expect((Array.isArray(__j.accounts) ? __j.accounts : []).filter((a) => a.id === pm.environment.get({js_str(_v(_P23S, 'AccountId'))}))"
        ".map((a) => a.ownerUserId)).to.eql([pm.environment.get(" + js_str(_v(_P23S, "UserId")) + ")]));",
    ]


def _f423_owned_short(owned):
    """Первое чтение свежего личного аккаунта: перечень ещё без него — опрос (конечный)."""
    return ("(() => { let j; try { j = pm.response.json(); } catch (e) { return false; } "
            f"return (Array.isArray(j.accounts) ? j.accounts : []).filter((a) => a.ownerUserId === "
            f"pm.environment.get({js_str(_v(_P23I, 'InvitedUserId'))})).length < {owned}; }})()")


CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-INVITEE-REGISTERS-BY-THE-SAME-LANE",
    title="Ф4-23: приглашённый регистрируется той же полосой — строка приглашения сохранила id, она и "
          "членство ожидают, личных аккаунтов ноль; после подтверждения той же сессией — строка и "
          "членство действующие, личный аккаунт ровно один с одним проектом, аккаунт пригласившего — его",
    classes=["CRUD", "STATE"],
    priority="P1",
    steps=[
        *_supervisor_bearer(_P23S, "f423-inviter", init=_person_init(_P23I, "f423")),
        _me(_P23S, "f423-inviter-owned-account", [
            *_status_is(200, "F423-INVITER-ME"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "const __own = (Array.isArray(__j.accounts) ? __j.accounts : [])"
            ".filter((a) => Array.isArray(a.roles) && a.roles.includes('owner'));",
            "pm.test('F423-INVITER-ME: аккаунт, которым пригласивший владеет, ровно один (фикстура)', () => "
            "pm.expect(__own.length).to.eql(1));",
            f"if (__own.length === 1) {{ pm.environment.set({js_str(_v(_P23S, 'AccountId'))}, __own[0].accountId); }}",
            f"if (__j.userId) {{ pm.environment.set({js_str(_v(_P23S, 'UserId'))}, __j.userId); }}",
        ]),
        _mutation(_P23S, "f423-invite", "POST", _INVITE,
                  {"accountId": f"{{{{{_v(_P23S, 'AccountId')}}}}}", "email": f"{{{{{_v(_P23I, 'Email')}}}}}"},
                  _v(_P23I, "InviteOp"), need=(_v(_P23S, "AccountId"),)),
        _op_done(_P23S, "f423-invite-op", _v(_P23I, "InviteOp"), [
            "pm.test('F423-INVITE-OP: строка приглашения — на адрес приглашённого и ожидает', () => "
            f"pm.expect([__j.response && __j.response.email, __j.response && __j.response.inviteStatus])"
            f".to.eql([pm.environment.get({js_str(_v(_P23I, 'Email'))}), 'PENDING']));",
            f"if (!__j.error && __j.response && __j.response.id) {{ pm.environment.set({js_str(_v(_P23I, 'InvitedUserId'))}, __j.response.id); }}",
        ]),
        _csrf_step(_P23I, "f423-csrf-register", "register", with_session=None),
        _post(_P23I, "f423-register", _REGISTER,
              {"email": f"{{{{{_v(_P23I, 'Email')}}}}}", "password": f"{{{{{_v(_P23I, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(_P23I, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, "F423-REGISTER"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  "pm.test('F423-REGISTER: сессия выдана, адрес не подтверждён', () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === false).to.eql(true));",
                  "pm.test('F423-REGISTER: способ входа лёг на строку приглашения — id тот же', () => "
                  f"pm.expect(!!(__j.user && __j.user.id) && __j.user.id === pm.environment.get({js_str(_v(_P23I, 'InvitedUserId'))})).to.eql(true));",
                  *_capture(_P23I, "kaname_session", "SessionCookie", "F423-REGISTER"),
                  *_capture(_P23I, "kaname_form", "FormCookie", "F423-REGISTER", required=False),
              ]),
        *_f423_reads("before", "PENDING", "PENDING", 0),
        _await_letter(_P23I, "f423-letter"),
        *_confirm(_P23I, "f423-verify", "Code", test_script=_confirmed(_P23I, "F423-VERIFY")),
        *_f423_reads("after", "ACTIVE", "ACTIVE", 1),
        _own(_P23S, "f423-after-personal-project", "GET", _PROJECTS + "?accountId={{" + _v(_P23I, "PersonalId") + "}}", [
            *_status_is(200, "F423-AFTER-PROJECTS"),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            "pm.test('F423-AFTER-PROJECTS: в личном аккаунте приглашённого проект ровно один', () => "
            "pm.expect([(Array.isArray(__j.projects) ? __j.projects : []).length, String(__j.nextPageToken || '')]).to.eql([1, '']));",
        ], need=(_v(_P23I, "PersonalId"),)),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# OS-16 (kaname#634): свои сессии сквозь стенд — две и более сессии, перечень,
# выход из выбранной и из всех, кроме текущей. Человек — свой, свежий:
# `end-others` по человеку посева сняло бы сессии кейсов соседних наборов.
# Запись N2 находится в перечне по описанию клиента, которым её назвал вход
# (`User-Agent` запроса выдачи, Р3): так кейс заодно судит, что описание
# доходит до перечня.
# ───────────────────────────────────────────────────────────────────────────
_POS = "avS"
_SESSIONS = "/iam/v1/auth/sessions"
_SESSIONS_END = "/iam/v1/auth/sessions/end"
_SESSIONS_END_OTHERS = "/iam/v1/auth/sessions/end-others"
_OS_AGENT = "kaname-newman-os16-"
_OS_WHY = ("слушатель полосы формы стенда не обслуживает путей своих сессий (перечень отвечает "
           "404): образ службы на стенде старше kaname#634 либо пути не ретранслированы краем — "
           "это условие, которого стенд не создал, а не ответ продукта")


def _os_guard(p):
    """Пути своих сессий есть на стенде — иначе «условие не создано» и шаг не идёт."""
    return [
        f"if (pm.environment.get({js_str(_v(p, 'NoOwnSessions'))}) === '1') {{",
        *precondition_not_met("пути своих сессий обслуживаются слушателем полосы стенда", _OS_WHY, indent="  "),
        "}",
    ]


def _os_login(p, n):
    """Вход той же личности с описанием клиента `<_OS_AGENT><n>`; носитель — в `<p>N<n>Cookie`."""
    name = f"os16-login-{n}"
    label = name.upper()
    return [
        _csrf_step(p, f"{name}-csrf", "login", with_session=None),
        _post(p, name, _LOGIN,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              extra_pre=[f"pm.request.headers.upsert({{key: 'User-Agent', value: {js_str(_OS_AGENT + str(n))}}});"],
              test_script=[
                  *_status_is(200, label),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(label + ': emailVerified true')}, () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
                  *_capture(p, "kaname_session", f"N{n}Cookie", label),
                  *_capture(p, "kaname_form", "FormCookie", label, required=False),
              ]),
    ]


def _os_list(p, name, cookie_var, test_script, *, first=False):
    label = name.upper()
    guard = [] if first else _os_guard(p)
    return Step(
        name=name, method="GET", path=_SESSIONS,
        pre_script=[*guard, *require_env_url("loginLaneBaseUrl", _SESSIONS, _LANE_WHY), *_src_pre(p),
                    f"pm.test({js_str(label + ': предъявляемый носитель был выдан (контроль непустоты)')}, () => "
                    f"pm.expect(!!pm.environment.get({js_str(_v(p, cookie_var))})).to.eql(true));",
                    *_with_cookies(("kaname_session", _v(p, cookie_var)))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=list(test_script),
    )


_OS_PARSE = [
    "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
    "const __s = Array.isArray(__j.sessions) ? __j.sessions : [];",
    "const __cur = __s.filter(x => x.current === true);",
]

CASES.append(Case(
    id="IAM-ADDRVERIFY-OK-OWN-SESSIONS-LISTED-AND-ENDED",
    title="Свои сессии сквозь стенд: перечень — текущая помечена, выход из выбранной снимает её (её носитель — 401), выход из всех, кроме текущей, оставляет одну (OS-16)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_verified_person(_POS, "os16"),
        *_os_login(_POS, 1),
        *_os_login(_POS, 2),
        *_os_login(_POS, 3),
        _os_list(_POS, "os16-list-n1", "N1Cookie", [
            f"if (pm.response.code === 404) {{ pm.environment.set({js_str(_v(_POS, 'NoOwnSessions'))}, '1'); }} else {{",
            f"  pm.environment.unset({js_str(_v(_POS, 'NoOwnSessions'))});",
            *("  " + x for x in _status_is(200, "OS16-LIST-N1")),
            *("  " + x for x in _OS_PARSE),
            "  pm.test('OS16-LIST-N1: записей не меньше трёх', () => pm.expect(__s.length >= 3).to.eql(true));",
            "  pm.test('OS16-LIST-N1: current ровно у одной записи', () => pm.expect(__cur.length).to.eql(1));",
            f"  pm.test('OS16-LIST-N1: текущая — запись N1 (её описание клиента)', () => "
            f"pm.expect(__cur.length === 1 && __cur[0].userAgent === {js_str(_OS_AGENT + '1')}).to.eql(true));",
            f"  const __n2 = __s.filter(x => x.userAgent === {js_str(_OS_AGENT + '2')});",
            "  pm.test('OS16-LIST-N1: запись N2 названа своим описанием клиента ровно один раз', () => "
            "pm.expect(__n2.length).to.eql(1));",
            "  pm.test('OS16-LIST-N1: запись N2 — не текущая', () => "
            "pm.expect(__n2.length === 1 && __n2[0].current === false).to.eql(true));",
            f"  pm.environment.set({js_str(_v(_POS, 'N2Id'))}, __n2.length === 1 ? String(__n2[0].id) : '');",
            "  pm.test('OS16-LIST-N1: nextPageToken — строка', () => pm.expect(typeof __j.nextPageToken).to.eql('string'));",
            "}",
        ], first=True),
        _csrf_step(_POS, "os16-end-csrf", "session-end", init=_os_guard(_POS), with_session="N1Cookie"),
        _post(_POS, "os16-end-n2", _SESSIONS_END,
              {"sessionId": f"{{{{{_v(_POS, 'N2Id')}}}}}", "csrfToken": f"{{{{{_v(_POS, 'Csrf')}}}}}"},
              with_session="N1Cookie", extra_pre=_os_guard(_POS),
              test_script=[
                  *_status_is(200, "OS16-END-N2"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  "pm.test('OS16-END-N2: тело — {\"ended\": true}', () => pm.expect(__j.ended).to.eql(true));",
                  *_no_cookies("OS16-END-N2"),
              ]),
        _os_list(_POS, "os16-list-n2-gone", "N2Cookie", _refused(401, 16, _REFUSED, "OS16-LIST-N2", empty_details=True)),
        _csrf_step(_POS, "os16-end-others-csrf", "session-end", init=_os_guard(_POS), with_session="N1Cookie"),
        _post(_POS, "os16-end-others", _SESSIONS_END_OTHERS,
              {"csrfToken": f"{{{{{_v(_POS, 'Csrf')}}}}}"},
              with_session="N1Cookie", extra_pre=_os_guard(_POS),
              test_script=[
                  *_status_is(200, "OS16-END-OTHERS"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  "pm.test('OS16-END-OTHERS: ended — число не меньше одного', () => "
                  "pm.expect(typeof __j.ended === 'number' && __j.ended >= 1).to.eql(true));",
                  *_no_cookies("OS16-END-OTHERS"),
              ]),
        _os_list(_POS, "os16-list-n1-alone", "N1Cookie", [
            *_status_is(200, "OS16-LIST-ALONE"),
            *_OS_PARSE,
            "pm.test('OS16-LIST-ALONE: запись ровно одна', () => pm.expect(__s.length).to.eql(1));",
            "pm.test('OS16-LIST-ALONE: и она текущая', () => pm.expect(__cur.length).to.eql(1));",
        ]),
    ],
))
