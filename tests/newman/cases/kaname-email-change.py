# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set смены адреса почты с подтверждением с нового адреса (kaname#635).

Предмет — приёмка `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
позиции уровня E — EC-25, EC-26, EC-27: два глагола смены на СОБСТВЕННОМ слушателе
формы службы, той же полосе, что вход (Ф3): поднимается только посадкой
`authn.identityProvider: own` и допускает РОВНО край по SAN клиентского сертификата.
Переменные:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека посева: из неё берётся ДОМЕН адреса,
                           сам человек посева набором не трогается
  {{standMailboxUrl}}    — чтение приёмника писем стенда (`stand-mailbox.py`; посев)

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора подтверждения адреса: без
посадки `own` `loginLaneBaseUrl` пуст, без приёмника писем — `standMailboxUrl`, и
каждый шаг уходит в «условие не создано» помеченным утверждением, а не в зелёное и
не в красное. Доставка писем на стенде платформы — предмет PRO-Robotech/kacho#1773;
на стенде `chart-own` службы приёмник есть, и набор исполняется.

СВОИ ЛЮДИ У КАЖДОГО КЕЙСА: регистрация, подтверждение адреса кодом из письма, вход —
глаголами полосы, адреса — свои у прогона (`{{runId}}` и случайная добавка).

КОД БЕРЁТСЯ ИЗ ПИСЬМА У ПРИЁМНИКА СТЕНДА дверью `GET /codes?to=<адрес>&after=<строка>`:
по элементу на письмо этому адресату в порядке приёма, значение — первая непустая
строка после строки-заголовка, либо null. Код лежит в переменных со словом `Code`,
пароли — `Password`, печенья и признаки формы — `Cookie` и `Csrf`: чистка отчёта
режет их именем. Утверждения значений удостоверений не получают.

ОТСУТСТВИЕ ПИСЬМА СУДИТСЯ БАРЬЕРОМ, А НЕ ПАУЗОЙ (форма набора подтверждения): письма
одному человеку уходят в порядке постановки (ключ партиции очереди — идентификатор
человека). Когда письмо, которое тот же человек законно попросил ПОЗЖЕ, прочитано у
приёмника, всё поставленное раньше уже сдано узлу.

Coverage (техники: классы эквивалентности адреса — свободный · занятый; переходы
состояния — запрос → отложенная смена → смена; пара близнецов у каждого отказа):
  IAM-EMAILCHANGE-OK-CHANGE-END-TO-END    — EC-25: человек заведён регистрацией, адрес
                                          подтверждён кодом из приёмника, сессия
                                          свежая; запрос смены на свободный N — 200 {},
                                          Retry-After — интервал профиля, печений нет;
                                          в приёмнике по N письмо с кодом смены;
                                          предъявление — 200, emailVerified true, новый
                                          носитель; в приёмнике по прежнему адресу —
                                          уведомление о смене; вход адресом N — 200,
                                          прежним адресом — 401 (пара близнецов)
  IAM-EMAILCHANGE-NEG-TAKEN-ADDRESS-INDISTINGUISHABLE — EC-26: первый запрашивает смену
                                          на адрес второго, третий — на свободный N₂;
                                          статус, тело и Retry-After равны; по N₂ письмо
                                          с кодом есть, по занятому адресу — нет (судит
                                          барьер: следующее законное письмо того же
                                          человека прочитано раньше счёта)
  IAM-EMAILCHANGE-NEG-STALE-SESSION-STEP-UP — EC-27: сессия старше окна свежести
                                          профиля — 403 SESSION_NOT_FRESH дословно,
                                          писем нет; повышение паролем — 200; тот же
                                          запрос — 200
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — идентификаторы КОММЕНТАРИЕМ, а не строкой:
#   · чтение строки человека `UserService.Get` после смены (последнее «И» EC-25) —
#     глаголу нужен токен человека, а его выдаёт церемония `authorization_code` с
#     клиентом посева церемонии; набор судит то же следствие на полосе входа:
#     вход адресом N проходит, прежним — нет, и это читает строку человека, а не
#     кэш (Ф3). Чтение строки после смены держит уровень I (EC-02, EC-03:
#     `internal/handler/loginlanehttp/email_change_integration_test.go`);
#   · отсутствие нового адреса в теле уведомления — у двери `codes` нет чтения
#     тела целиком (тело письма с кодом, прочитанное `GET /messages`, ушло бы в
#     публичный отчёт). Его держат уровень I (EC-02: нагрузка строки очереди без N)
#     и сборщик письма (`RenderEmailChangedMail`: новый адрес ему не передаётся);
#   · строки очереди, событие `iam.user.email_changed`, причина конца сессии и
#     строка очереди смены субъекта — внутреннее состояние службы (уровень I).

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
                "которого стенд не создал (доставка на стенде платформы — PRO-Robotech/kacho#1773)")

_CSRF = "/iam/v1/auth/csrf"
_REGISTER = "/iam/v1/auth/register"
_LOGIN = "/iam/v1/auth/login"
_STEP_UP = "/iam/v1/auth/step-up"
_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
_CHANGE = "/iam/v1/auth/email-change"
_CHANGE_CONFIRM = "/iam/v1/auth/email-change/confirm"

# Строки писем службы (`internal/clients/invite_mail.go`): заголовок, после которого
# стоит код, и строка уведомления, после которой стоит строка о действии.
_HEAD_VERIFY = "Код подтверждения:"
_HEAD_CHANGE = "Код подтверждения смены:"
_HEAD_NOTICE = "Этот адрес больше не используется для входа и восстановления доступа."
_NOTICE_NEXT = "Если это были не вы — обратитесь к администратору аккаунта."

_REFUSED = "authentication failed"
_TOO_MANY = "too many attempts; try again later"
_NOT_FRESH = "re-authentication required: present a credential again"

# Величины профиля, с которыми стенд поднят: стенд `chart-own` ставит
# `deploy/values.prod.yaml` как есть, поэтому интервал писем и окно свежести,
# которых кейсы ждут, — ровно те, с которыми служба поднята.
_PROFILE = _pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _profile(indent, key):
    found = _re.findall(rf"^{indent}{key}: (\S+)\s*$", _PROFILE.read_text(encoding="utf-8"), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-email-change: ключ профиля {key} найден "
                         f"{len(found)} раз в {_PROFILE} — ждали ровно один")
    return found[0]


def _seconds(duration):
    m = _re.fullmatch(r"(\d+)([smh])", duration)
    if m is None:
        raise SystemExit(f"kaname-email-change: срок {duration!r} не в форме <число><s|m|h>")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


# Интервал смены — та же ручка, что у писем подтверждения (приёмка Р6).
_RESEND_INTERVAL = _seconds(_profile("    ", "verificationResendInterval"))
# Окно свежести правки своих данных (Р2).
_FRESHNESS = _seconds(_profile("  ", "selfServiceFreshness"))

_MAIL_WAIT_CAP = 90
_MAIL_WAIT_MS = 1000
_INTERVAL_POLL_CAP = (_RESEND_INTERVAL + 2) * 4
# Ожидание окна свежести: опрос с паузой и конечным пределом (форма окна профиля
# набора второго фактора, kaname#480); ε покрывает задержку ответа и округление.
_FRESH_EPS_MS = 5000
_FRESH_POLL_MS = 10000
_FRESH_CAP = -(-((_FRESHNESS + 120) * 1000) // _FRESH_POLL_MS)


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
    """Адрес, новый адрес, пароль и источник человека кейса — первым шагом."""
    return [
        "{",
        "  const __nonce = () => Math.floor(Math.random() * 2176782336).toString(36);",
        "  const __domain = String(pm.environment.get('loginLaneEmail') || '').split('@')[1] || 'kaname.local';",
        f"  pm.environment.set({js_str(_v(p, 'Email'))}, ({js_str('ec-' + tag + '-')} + pm.environment.get('runId') + '-' + __nonce() + '@' + __domain).toLowerCase());",
        f"  pm.environment.set({js_str(_v(p, 'NewEmail'))}, ({js_str('ec-' + tag + '-new-')} + pm.environment.get('runId') + '-' + __nonce() + '@' + __domain).toLowerCase());",
        f"  pm.environment.set({js_str(_v(p, 'Password'))}, 'Pw-' + __nonce() + __nonce() + '-first');",
        f"  pm.environment.set({js_str(_v(p, 'Src'))}, '198.19.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
        f"  pm.environment.set({js_str(_v(p, 'MailSeen'))}, '0');",
        f"  pm.environment.set({js_str(_v(p, 'NewMailSeen'))}, '0');",
        *(f"  pm.environment.unset({js_str(_v(p, n))});" for n in (
            "FormCookie", "SessionCookie", "LoginSessionCookie", "Csrf", "Code", "ChangeCode", "IntervalUntil",
            "FreshUntil")),
        "}",
    ]


def _status_is(code, label):
    return [f"pm.test({js_str(label + f': ответ {code}')}, () => pm.expect(pm.response.code).to.eql({code}));"]


def _no_cookies(label):
    return [f"pm.test({js_str(label + ': печений не пишет')}, () => "
            "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length).to.eql(0));"]


def _refused(status, grpc, text, label, reason=None):
    """Отказ полосы: статус, код, текст и признак порознь; значений удостоверений нет."""
    out = [
        *_status_is(status, label),
        "let __r = {}; try { __r = pm.response.json(); } catch (e) { __r = {}; }",
        f"pm.test({js_str(label + f': код отказа {grpc}')}, () => pm.expect(__r.code).to.eql({grpc}));",
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => pm.expect(__r.message).to.eql({js_str(text)}));",
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length).to.eql(0));",
    ]
    if reason:
        out += [
            "const __info = (Array.isArray(__r.details) ? __r.details : [])"
            ".filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            f"pm.test({js_str(label + ': признак отказа ' + reason)}, () => pm.expect(__info.reason).to.eql({js_str(reason)}));",
        ]
    return out


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


def _mail_path(addr_var, heading):
    return f"/codes?to={{{{{addr_var}}}}}&after={_urlparse.quote(heading)}"


def _await_mail(p, name, *, to="Email", seen="MailSeen", heading=_HEAD_VERIFY, into="Code", expect=None):
    """Письмо адресату `<p><to>` СВЕРХ уже прочитанных: петля с настоящей паузой.

    `expect` пуст — письмо несёт код формы XXXXX-XXXXX, он ложится в `<p><into>`;
    иначе строка после заголовка равна `expect` (письмо без кода)."""
    path = _mail_path(_v(p, to), heading)
    counter, started = f"_ecmb_{p}_{name}".replace("-", "_"), f"_ecmbs_{p}_{name}".replace("-", "_")
    seen_var, label = _v(p, seen), name.upper()
    if expect is None:
        what = [
            f"pm.test({js_str(label + ': письмо несёт код формы XXXXX-XXXXX')}, () => "
            "pm.expect(typeof __last === 'string' && /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(__last)).to.eql(true));",
            "if (__all.length > __seen) {",
            f"  pm.environment.set({js_str(_v(p, into))}, typeof __last === 'string' ? __last : '');",
            "}",
        ]
    else:
        what = [f"pm.test({js_str(label + ': письмо — то, которого ждали (строка после заголовка дословна)')}, () => "
                f"pm.expect(__last).to.eql({js_str(expect)}));"]
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
            f"const __seen = parseInt(pm.environment.get({js_str(seen_var)}) || '0', 10);",
            "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
            "const __all = Array.isArray(__codes) ? __codes : [];",
            f"if (pm.response.code === 200 && __all.length <= __seen && __n < {_MAIL_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _ecd = Date.now(); while (Date.now() - _ecd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': письмо дошло до приёмника стенда в пределе ожидания')}, () => "
            "pm.expect(__all.length > __seen).to.eql(true));",
            "const __last = __all.length > __seen ? __all[__all.length - 1] : null;",
            *what,
            f"if (__all.length > __seen) {{ pm.environment.set({js_str(seen_var)}, String(__all.length)); }}",
        ],
    )


def _verified_person(p, tag):
    """Человек с подтверждённым адресом: регистрация → код письма → подтверждение.

    Носитель обычного положения — в `<p>SessionCookie`; сессия свежая: предъявление
    кода подтверждения сдвигает момент последнего предъявления."""
    label = f"{tag.upper()}-REGISTER"
    return [
        _csrf_step(p, f"{tag}-csrf-register", "register", init=_person_init(p, tag), with_session=None),
        _post(p, f"{tag}-register", _REGISTER,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, label),
                  *_capture(p, "kaname_session", "SessionCookie", label),
                  *_capture(p, "kaname_form", "FormCookie", label, required=False),
              ]),
        _await_mail(p, f"{tag}-verify-letter"),
        _csrf_step(p, f"{tag}-csrf-verify", "verify-email-confirm"),
        _post(p, f"{tag}-verify", _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(p, 'Code')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[
                  *_status_is(200, f"{tag.upper()}-VERIFY"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(tag.upper() + '-VERIFY: адрес подтверждён — emailVerified true')}, () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
                  *_capture(p, "kaname_session", "SessionCookie", f"{tag.upper()}-VERIFY"),
                  # Момент, после которого сессия несвежая (EC-27): ответ + окно + ε.
                  f"if (pm.response.code === 200) {{ pm.environment.set({js_str(_v(p, 'FreshUntil'))}, "
                  f"String(Date.now() + {_FRESHNESS * 1000 + _FRESH_EPS_MS})); }}",
              ]),
    ]


def _request_change(p, name, to_var, *, test_script):
    return [
        _csrf_step(p, f"{name}-csrf", "email-change"),
        _post(p, name, _CHANGE, {"newEmail": f"{{{{{to_var}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie", test_script=test_script),
    ]


def _accepted(label):
    """Принятый запрос смены: 200, тело {}, Retry-After — интервал профиля, печений нет."""
    return [
        *_status_is(200, label),
        f"pm.test({js_str(label + ': тело — пустой объект')}, () => pm.expect(pm.response.text()).to.eql('{{}}'));",
        f"pm.test({js_str(label + f': Retry-After — интервал профиля ({_RESEND_INTERVAL} с)')}, () => "
        f"pm.expect(String(pm.response.headers.get('Retry-After'))).to.eql({js_str(str(_RESEND_INTERVAL))}));",
        *_no_cookies(label),
    ]


def _login(p, name, email_var, *, test_script):
    return [
        _csrf_step(p, f"{name}-csrf", "login", with_session=None),
        _post(p, name, _LOGIN,
              {"email": f"{{{{{_v(p, email_var)}}}}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=test_script),
    ]


# ───────────────────────────────────────────────────────────────────────────
# EC-25: смена целиком на стенде.
# ───────────────────────────────────────────────────────────────────────────
_PA = "ecA"
CASES.append(Case(
    id="IAM-EMAILCHANGE-OK-CHANGE-END-TO-END",
    title="Смена адреса целиком (EC-25): запрос на свободный адрес — 200 {}, код приходит на новый адрес, "
          "предъявление — 200 и новый носитель, прежний адрес получает уведомление; вход новым адресом — 200, прежним — 401",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_verified_person(_PA, "ec25"),
        *_request_change(_PA, "ec25-request", _v(_PA, "NewEmail"), test_script=_accepted("EC25-REQUEST")),
        _await_mail(_PA, "ec25-change-letter", to="NewEmail", seen="NewMailSeen", heading=_HEAD_CHANGE, into="ChangeCode"),
        _csrf_step(_PA, "ec25-csrf-confirm", "email-change-confirm"),
        _post(_PA, "ec25-confirm", _CHANGE_CONFIRM,
              {"code": f"{{{{{_v(_PA, 'ChangeCode')}}}}}", "csrfToken": f"{{{{{_v(_PA, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[
                  *_status_is(200, "EC25-CONFIRM"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  "pm.test('EC25-CONFIRM: тело session с emailVerified true', () => "
                  "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
                  *_capture(_PA, "kaname_session", "SessionCookie", "EC25-CONFIRM"),
              ]),
        _await_mail(_PA, "ec25-notice-to-the-old-address", heading=_HEAD_NOTICE, expect=_NOTICE_NEXT),
        *_login(_PA, "ec25-login-new-address", "NewEmail", test_script=[
            *_status_is(200, "EC25-LOGIN-NEW"),
            *_capture(_PA, "kaname_session", "LoginSessionCookie", "EC25-LOGIN-NEW"),
        ]),
        *_login(_PA, "ec25-login-old-address", "Email",
                test_script=_refused(401, 16, _REFUSED, "EC25-LOGIN-OLD")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EC-26: занятый адрес на стенде неотличим.
# ───────────────────────────────────────────────────────────────────────────
_PB, _PT, _PF = "ecB", "ecT", "ecF"
_TAKEN_STATUS, _TAKEN_BODY, _TAKEN_RA = "ec26TakenStatus", "ec26TakenBody", "ec26TakenRetryAfter"
_RETRY_AFTER_ARM = [
    f"pm.test({js_str(f'EC26-TOO-EARLY: Retry-After — положительное число секунд не больше интервала профиля ({_RESEND_INTERVAL} с)')}, () => {{",
    "  const ra = pm.response.headers.get('Retry-After');",
    f"  pm.expect(/^[0-9]+$/.test(String(ra)) && Number(ra) >= 1 && Number(ra) <= {_RESEND_INTERVAL}).to.eql(true);",
    "});",
    "{",
    f"  const __ra = Math.min(parseInt(pm.response.headers.get('Retry-After'), 10) || {_RESEND_INTERVAL}, {_RESEND_INTERVAL});",
    f"  pm.environment.set({js_str(_v(_PT, 'IntervalUntil'))}, String(Date.now() + (__ra + 1) * 1000));",
    "}",
]


def _await_interval(p, name, form):
    """Признак формы `form`, запрашиваемый повтором с настоящей паузой, пока не
    наступит момент `<p>IntervalUntil`, названный прошлым шагом по ответу продукта."""
    path = f"{_CSRF}?form={form}"
    label, polls = name.upper(), f"_ecip_{p}_{name}".replace("-", "_")
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_src_pre(p),
                    *_with_cookies(("kaname_form", _v(p, "FormCookie")), ("kaname_session", _v(p, "SessionCookie")))],
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
            "  const _ecw = Date.now(); while (Date.now() - _ecw < 500) { /* inter-poll delay: the resend interval the product named */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(polls)});",
            "}",
        ],
    )


CASES.append(Case(
    id="IAM-EMAILCHANGE-NEG-TAKEN-ADDRESS-INDISTINGUISHABLE",
    title="Занятый адрес на запросе смены неотличим (EC-26): ответы на занятый и свободный адрес равны статусом, "
          "телом и Retry-After; письмо с кодом приходит на свободный адрес и не приходит на занятый",
    classes=["SEC", "NEG"],
    priority="P0",
    steps=[
        # Держатель адреса: регистрация глаголом; его письмо подтверждения доходит
        # до приёмника — дверь чтения его адреса исправна (контроль ниже).
        _csrf_step(_PB, "ec26-holder-csrf-register", "register", init=_person_init(_PB, "ec26b"), with_session=None),
        _post(_PB, "ec26-holder-register", _REGISTER,
              {"email": f"{{{{{_v(_PB, 'Email')}}}}}", "password": f"{{{{{_v(_PB, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(_PB, 'Csrf')}}}}}"},
              test_script=[*_status_is(200, "EC26-HOLDER-REGISTER")]),
        _await_mail(_PB, "ec26-holder-verify-letter"),
        # Первый запрашивает смену на адрес держателя.
        *_verified_person(_PT, "ec26t"),
        *_request_change(_PT, "ec26-request-taken", _v(_PB, "Email"), test_script=[
            *_accepted("EC26-TAKEN"),
            f"pm.environment.set({js_str(_TAKEN_STATUS)}, String(pm.response.code));",
            f"pm.environment.set({js_str(_TAKEN_BODY)}, pm.response.text());",
            f"pm.environment.set({js_str(_TAKEN_RA)}, String(pm.response.headers.get('Retry-After')));",
        ]),
        # Третий — на свободный адрес: ответ побайтово тот же.
        *_verified_person(_PF, "ec26f"),
        *_request_change(_PF, "ec26-request-free", _v(_PF, "NewEmail"), test_script=[
            *_accepted("EC26-FREE"),
            f"pm.test('EC26: статусы ответов на занятый и свободный адрес равны', () => "
            f"pm.expect(String(pm.response.code)).to.eql(pm.environment.get({js_str(_TAKEN_STATUS)})));",
            f"pm.test('EC26: тела ответов на занятый и свободный адрес равны побайтово', () => "
            f"pm.expect(pm.response.text()).to.eql(pm.environment.get({js_str(_TAKEN_BODY)})));",
            f"pm.test('EC26: Retry-After ответов на занятый и свободный адрес равны', () => "
            f"pm.expect(String(pm.response.headers.get('Retry-After'))).to.eql(pm.environment.get({js_str(_TAKEN_RA)})));",
        ]),
        _await_mail(_PF, "ec26-free-change-letter", to="NewEmail", seen="NewMailSeen", heading=_HEAD_CHANGE, into="ChangeCode"),
        # Барьер: внутри интервала — отказ по частоте (запрос на занятый адрес
        # расходовал темп, Р6); после интервала тот же человек законно просит
        # смену на свободный адрес, и его письмо прочитано раньше счёта.
        *_request_change(_PT, "ec26-too-early", _v(_PT, "NewEmail"), test_script=[
            *_refused(429, 8, _TOO_MANY, "EC26-TOO-EARLY", reason="TOO_MANY_ATTEMPTS"),
            *_RETRY_AFTER_ARM,
        ]),
        _await_interval(_PT, "ec26-await-interval", "email-change"),
        _post(_PT, "ec26-barrier-request", _CHANGE,
              {"newEmail": f"{{{{{_v(_PT, 'NewEmail')}}}}}", "csrfToken": f"{{{{{_v(_PT, 'Csrf')}}}}}"},
              with_session="SessionCookie", test_script=_accepted("EC26-BARRIER")),
        _await_mail(_PT, "ec26-barrier-letter", to="NewEmail", seen="NewMailSeen", heading=_HEAD_CHANGE, into="ChangeCode"),
        Step(
            name="ec26-no-code-at-the-taken-address", method="GET", path=_mail_path(_v(_PB, "Email"), _HEAD_CHANGE),
            auth="anonymous", cookie_jar=False,
            pre_script=[*require_env_url("standMailboxUrl", _mail_path(_v(_PB, "Email"), _HEAD_CHANGE), _MAILBOX_WHY)],
            test_script=[
                *_status_is(200, "EC26-TAKEN-MAILBOX"),
                "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
                "const __all = Array.isArray(__codes) ? __codes : [];",
                "pm.test('EC26-TAKEN-MAILBOX: письма держателю читаются (контроль: письмо подтверждения дошло)', () => "
                "pm.expect(__all.length >= 1).to.eql(true));",
                "pm.test('EC26-TAKEN-MAILBOX: письма с кодом смены на занятый адрес нет', () => "
                "pm.expect(__all.filter(c => c !== null).length).to.eql(0));",
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# EC-27: несвежая сессия на стенде; после повышения тот же запрос проходит.
# ───────────────────────────────────────────────────────────────────────────
_PS = "ecS"


def _await_staleness(p, name):
    """Ожидание момента `<p>FreshUntil` (окно свежести профиля от ответа, выдавшего
    свежую сессию, плюс ε): опрос признака формы с настоящей паузой и пределом."""
    path = f"{_CSRF}?form=email-change"
    label, polls = name.upper(), f"_ecfp_{p}".replace("-", "_")
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_src_pre(p),
                    *_with_cookies(("kaname_form", _v(p, "FormCookie")), ("kaname_session", _v(p, "SessionCookie")))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_status_is(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.environment.set({js_str(_v(p, 'Csrf'))}, __j.csrfToken || '');",
            f"const __until = parseInt(pm.environment.get({js_str(_v(p, 'FreshUntil'))}) || '0', 10);",
            f"const __polls = parseInt(pm.environment.get({js_str(polls)}) || '0', 10);",
            "const __ready = __until > 0 && Date.now() >= __until;",
            f"pm.test({js_str(label + ': срок свежести взведён шагом подтверждения адреса')}, () => pm.expect(__until > 0).to.eql(true));",
            f"pm.test({js_str(label + f': окно свежести профиля ({_FRESHNESS} с) прошло либо ожидание в пределе {_FRESH_CAP} опросов')}, () => "
            f"pm.expect(__ready || __polls < {_FRESH_CAP}).to.eql(true));",
            f"if (__until > 0 && !__ready && __polls < {_FRESH_CAP}) {{",
            f"  pm.environment.set({js_str(polls)}, String(__polls + 1));",
            f"  const __pause = Math.min({_FRESH_POLL_MS}, Math.max(0, __until - Date.now()));",
            "  const _ecf = Date.now(); while (Date.now() - _ecf < __pause) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(polls)});",
            "}",
        ],
    )


CASES.append(Case(
    id="IAM-EMAILCHANGE-NEG-STALE-SESSION-STEP-UP",
    title="Несвежая сессия на стенде (EC-27): запрос смены — 403 SESSION_NOT_FRESH, письма нет; "
          "после повышения паролем тот же запрос — 200",
    classes=["SEC", "NEG"],
    priority="P1",
    steps=[
        *_verified_person(_PS, "ec27"),
        _await_staleness(_PS, "ec27-await-staleness"),
        _post(_PS, "ec27-request-stale", _CHANGE,
              {"newEmail": f"{{{{{_v(_PS, 'NewEmail')}}}}}", "csrfToken": f"{{{{{_v(_PS, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[*_refused(403, 7, _NOT_FRESH, "EC27-STALE", reason="SESSION_NOT_FRESH"), *_no_cookies("EC27-STALE")]),
        _csrf_step(_PS, "ec27-csrf-step-up", "step-up"),
        _post(_PS, "ec27-step-up", _STEP_UP,
              {"method": "password", "password": f"{{{{{_v(_PS, 'Password')}}}}}", "csrfToken": f"{{{{{_v(_PS, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[*_status_is(200, "EC27-STEP-UP"), *_capture(_PS, "kaname_session", "SessionCookie", "EC27-STEP-UP")]),
        *_request_change(_PS, "ec27-request-after-step-up", _v(_PS, "NewEmail"), test_script=_accepted("EC27-AFTER-STEP-UP")),
        # Письма на новый адрес после отказа свежести нет, после повышения — одно:
        # первое письмо этому адресату и есть письмо после повышения.
        _await_mail(_PS, "ec27-change-letter", to="NewEmail", seen="NewMailSeen", heading=_HEAD_CHANGE, into="ChangeCode"),
        Step(
            name="ec27-one-letter", method="GET", path=_mail_path(_v(_PS, "NewEmail"), _HEAD_CHANGE),
            auth="anonymous", cookie_jar=False,
            pre_script=[*require_env_url("standMailboxUrl", _mail_path(_v(_PS, "NewEmail"), _HEAD_CHANGE), _MAILBOX_WHY)],
            test_script=[
                *_status_is(200, "EC27-LETTERS"),
                "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
                "pm.test('EC27-LETTERS: писем на новый адрес ровно одно — отказ свежести письма не поставил', () => "
                "pm.expect(Array.isArray(__codes) ? __codes.length : -1).to.eql(1));",
            ],
        ),
    ],
))
