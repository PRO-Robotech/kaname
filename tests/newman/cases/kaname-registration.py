# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set регистрации нашей полосой (Ф4, kacho#1270): первая регистрация и её сессия.

Предмет — глагол `POST /iam/v1/auth/register` СОБСТВЕННОГО слушателя формы службы
(та же полоса, что вход: поднимается только посадкой `authn.identityProvider: own`
и допускает РОВНО край по SAN клиентского сертификата) и сессия, которую он
выдаёт. Переменные — те же, что у набора `kaname-login-lane.py`:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека посева: из неё берётся ДОМЕН адреса,
                           сам человек посева набором не трогается

Адрес регистрации свой у каждого прогона (`{{runId}}` в локальной части): набор
заводит человека сам и ни на кого чужого не опирается. Снять заведённого полосой
нечем — глагола удаления человека у неё нет, — поэтому имя несёт прогон, а не
счётчик, и повторный прогон на том же стенде заводит другого.

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора входа: на автономном стенде
службы посадка `own` не поднята, `loginLaneBaseUrl` пуст, и каждый шаг уходит в
«условие не создано» помеченным утверждением, а не в зелёное и не в красное.

ГДЕ НАБОР ГОНЯЕТСЯ. Задание `chart-own` процесса `e2e-newman.yml` — тем же
вызовом прогонщика, что вход, восстановление, церемония и второй фактор.

ПОЛОЖЕНИЕ ПОДТВЕРЖДЕНИЯ (kaname#456). Сессия, выданная регистрацией, годна сразу,
но адрес ещё не подтверждён, и дальше входа и экрана подтверждения полоса её не
пускает: путь, объявленный отказом положения, отвечает `403 EMAIL_NOT_VERIFIED`.
Это и есть «отвечают как вошедшему» для человека в положении подтверждения —
носитель узнан, и отказ называет положение; несуществующему носителю тот же путь
отвечает `401` без положения.

Coverage (техники: классы эквивалентности адреса — свободный · занятый · тот же в
другом регистре; переходы состояния сессии; угадывание ошибок — регистр адреса):
  IAM-REG-OK-FIRST-REGISTRATION-AND-SESSION — Ф4-17: первая регистрация свежего
                                              носителя проходит — зеркало, сессия
                                              «1», адрес не подтверждён, носитель и
                                              контекст формы выданы; Ф4-20: сессия
                                              годна тем же прогоном без ожидания —
                                              путь положения отвечает отказом
                                              положения, а не «сессии нет»;
                                              несуществующему носителю — 401; выход
                                              по носителю регистрации проходит
  IAM-REG-NEG-OCCUPIED-ADDRESS-REFUSED     — отрицательный близнец Ф4-17: тот же
                                              адрес, и тот же в другом регистре, —
                                              единый отказ регистрации без носителя
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — идентификаторы КОММЕНТАРИЕМ, а не строкой: перепись
# долга считает позицию несомой по строковому литералу модуля.
#   · четвёртое следствие и снимок «кто я» (Ф4-01, Ф4-26) — маршрут края; держатель
#     сквозной пробы — дом платформы (приёмка §10а п. 2);
#   · единый отказ побайтово против исчерпанного предела (Ф4-11…16) — «Дано»
#     исчерпанного носителя при свободном адресе;
#   · окно материализации первого действия (Ф4-21, Ф4-22) — «Дано» та же сессия
#     регистрации, а действие в своём аккаунте — глагол API: печенье сессии в
#     принципала превращает край, собственный фронт службы его не разрешает.

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это не отказ продукта, а условие, "
             "которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_REGISTER = "/iam/v1/auth/register"
_LOGOUT = "/iam/v1/auth/logout"
_STATUS = "/iam/v1/auth/second-factor"

# Адрес источника, который на живом проводе ставит край (Р10). Свой у каждого
# прогона: окно регистраций источника (kaname#456) успехом не обнуляется.
_SOURCE_JS = [
    "if (!pm.environment.get('regSource')) {",
    "  pm.environment.set('regSource', '2001:db8:4::' + (Date.now() % 65536).toString(16));",
    "}",
    "pm.request.headers.upsert({key: 'X-Forwarded-For', value: pm.environment.get('regSource')});",
]

# Адрес регистрации — свой у прогона; домен — у адреса человека посева.
_ADDRESS_JS = [
    "{",
    "  const domain = String(pm.environment.get('loginLaneEmail') || '').split('@')[1] || 'stand.invalid';",
    "  pm.environment.set('regEmail', 'reg-' + pm.environment.get('runId') + '@' + domain);",
    "  pm.environment.set('regEmailUpper', ('reg-' + pm.environment.get('runId')).toUpperCase() + '@' + domain);",
    "  pm.environment.set('regPassword', 'reg-pw-' + pm.environment.get('runId') + '-x');",
    "}",
]

_OK = ["pm.test('status 200', () => pm.expect(pm.response.code, 'код ответа').to.eql(200));"]


def _status(status):
    return [f"pm.test({js_str(f'status {status}')}, () => pm.expect(pm.response.code, 'код ответа').to.eql({status}));"]


def _refusal(status, code, text, label, reason=None):
    out = [
        *_status(status),
        f"pm.test({js_str(label + ': код отказа ' + str(code))}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.code, 'код отказа').to.eql({code});",
        "});",
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.message, 'текст отказа').to.eql({js_str(text)});",
        "});",
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, 'печений сессии').to.eql(0));",
    ]
    if reason:
        out += [
            f"pm.test({js_str(label + ': токен отказа ' + reason)}, () => {{",
            "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
            "  const info = (j.details || []).filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0];",
            f"  pm.expect(info && info.reason, 'токен отказа').to.eql({js_str(reason)});",
            "});",
        ]
    return out


def _lane(path):
    return [*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_SOURCE_JS]


def _with_cookies(*vars_):
    parts = " + ".join(
        f"(pm.environment.get({js_str(v)}) ? {js_str(name)} + '=' + pm.environment.get({js_str(v)}) + '; ' : '')"
        for name, v in vars_)
    return [
        f"const __cookie = ({parts}).replace(/; $/, '');",
        "if (__cookie) { pm.request.headers.upsert({key: 'Cookie', value: __cookie}); }",
    ]


def _capture_cookie(name, var, label):
    return [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(name + '=')}));",
        f"  pm.test({js_str(label + ': ответ ставит печенье ' + name)}, () => "
        f"pm.expect(__sc.length, {js_str('печений ' + name)}).to.eql(1));",
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(var)}, __sc[0].value.split(';')[0].slice({len(name) + 1})); }}",
        "}",
    ]


def _csrf_step(name, kind, var, label, extra_pre=None):
    return Step(
        name=name,
        method="GET",
        path=_CSRF + "?form=" + kind,
        pre_script=[*_lane(_CSRF + "?form=" + kind), *_with_cookies(("kaname_form", "regFormCookie")), *(extra_pre or [])],
        insecure_tls=True,
        auth="anonymous",
        test_script=[
            *_OK,
            "const j = pm.response.json();",
            f"pm.test({js_str(label + ': признак выдан')}, () => "
            "pm.expect(typeof j.csrfToken === 'string' && j.csrfToken.length > 0, 'признак формы').to.eql(true));",
            f"pm.environment.set({js_str(var)}, j.csrfToken);",
            "{",
            "  const __sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_form='));",
            "  if (__sc.length === 1) { pm.environment.set('regFormCookie', __sc[0].value.split(';')[0].slice(12)); }",
            "}",
        ],
    )


def _register(name, email_var, label, tests):
    return Step(
        name=name,
        method="POST",
        path=_REGISTER,
        body={"email": "{{" + email_var + "}}", "password": "{{regPassword}}", "csrfToken": "{{regCsrfRegister}}"},
        pre_script=[*_lane(_REGISTER), *_with_cookies(("kaname_form", "regFormCookie"))],
        insecure_tls=True,
        auth="anonymous",
        test_script=tests,
    )


CASES.append(Case(
    id="IAM-REG-OK-FIRST-REGISTRATION-AND-SESSION",
    title="Первая регистрация свежего носителя проходит, и её сессия годна сразу: путь положения узнаёт носитель, несуществующему — 401 (Ф4-17, Ф4-20)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("reg-csrf-register", "register", "regCsrfRegister", "CSRF-REGISTER",
                   extra_pre=["pm.environment.unset('regFormCookie');", *_ADDRESS_JS]),
        _register("reg-register", "regEmail", "REGISTER", [
            *_OK,
            "const j = pm.response.json();",
            "pm.test('REGISTER: заведён человек — идентификатор зеркала, адрес тот, что прислан', () => {",
            "  pm.expect(/^usr[0-9a-z]{17}$/.test(String(j.user && j.user.id)), 'идентификатор человека').to.eql(true);",
            "  pm.expect(j.user && j.user.email, 'адрес человека').to.eql(pm.environment.get('regEmail'));",
            "});",
            "pm.test('REGISTER: сессия «1», адрес не подтверждён, срок до секунды', () => {",
            "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('1');",
            "  pm.expect(j.session && j.session.emailVerified, 'адрес подтверждён').to.eql(false);",
            "  pm.expect(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/.test(String(j.session && j.session.expiresAt)), 'срок до секунды').to.eql(true);",
            "});",
            *_capture_cookie("kaname_session", "regSessionCookie", "REGISTER"),
            *_capture_cookie("kaname_form", "regFormCookie", "REGISTER"),
        ]),
        Step(
            name="reg-session-recognized-at-once",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_with_cookies(("kaname_session", "regSessionCookie"), ("kaname_form", "regFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(403, 7, "email address is not verified: confirm it with the code from the letter (POST /iam/v1/auth/verify-email/confirm)", "REG-POSITION", reason="EMAIL_NOT_VERIFIED"),
        ),
        Step(
            name="reg-no-session-twin",
            method="GET",
            path=_STATUS,
            pre_script=[
                *_lane(_STATUS),
                "pm.request.headers.upsert({key: 'Cookie', value: 'kaname_session=not-a-session-' + pm.environment.get('runId')});",
            ],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(401, 16, "authentication failed", "REG-NO-SESSION"),
        ),
        _csrf_step("reg-csrf-logout", "logout", "regCsrfLogout", "CSRF-LOGOUT"),
        Step(
            name="reg-logout",
            method="POST",
            path=_LOGOUT,
            body={"csrfToken": "{{regCsrfLogout}}"},
            pre_script=[*_lane(_LOGOUT), *_with_cookies(("kaname_session", "regSessionCookie"), ("kaname_form", "regFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[*_OK, "pm.environment.unset('regSessionCookie');"],
        ),
    ],
))

CASES.append(Case(
    id="IAM-REG-NEG-OCCUPIED-ADDRESS-REFUSED",
    title="Отрицательный близнец первой регистрации: занятый адрес и он же в другом регистре — единый отказ регистрации без носителя",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        _csrf_step("reg-csrf-register-again", "register", "regCsrfRegister", "CSRF-REGISTER"),
        _register("reg-register-occupied", "regEmail", "OCCUPIED",
                  _refusal(400, 9, "registration refused", "OCCUPIED", reason="REGISTRATION_REFUSED")),
        _register("reg-register-occupied-other-case", "regEmailUpper", "OCCUPIED-CASE",
                  _refusal(400, 9, "registration refused", "OCCUPIED-CASE", reason="REGISTRATION_REFUSED")),
    ],
))
