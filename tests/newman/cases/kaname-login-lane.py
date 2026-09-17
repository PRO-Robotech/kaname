# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set полосы входа паролем и нашей сессии (Ф3, kacho#1269).

Предмет — СОБСТВЕННЫЙ слушатель формы службы (`/iam/v1/auth/{csrf,login,logout,
password}`), а не край платформы. Слушатель поднимается только посадкой
`authn.identityProvider: own` и допускает РОВНО край — по SAN клиентского
сертификата (Р7, Р16). Поэтому набор адресуется ОТДЕЛЬНОЙ переменной и ждёт от
прогонщика клиентский лист с именем края:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека с заведённым способом входа паролем (посев)
  {{loginLanePassword}}  — его пароль (посев)

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ. Автономный стенд службы сегодня стоит на посадке
`external` (`.github/scripts/stand-own.sh` экспортирует
`KANAME_AUTHN__IDENTITY_PROVIDER=external`), а посадка `own` до Ф12 не
поднимается вовсе: каталог прав требует уровень «2» у части записей, а полоса с
одним паролем предъявляет только «1» (Ф11-27, отказ старта). Значит на
сегодняшнем стенде `loginLaneBaseUrl` не задан, и КАЖДЫЙ шаг ниже уходит в
«условие не создано» — помеченным утверждением, которое вердикт читает своей
строкой и своим кодом, а не в зелёное и не в красное. Клиентский лист стенда
выписан на имя самой службы (`stand-own.sh`, `v3_srv`), а не края: и это второе
условие, которое стенд посадки `own` обязан создать — лист с SAN края.

Test-first: кейсы написаны против слушателя, который на стенде не поднят; прогон
против него — третья категория, не вердикт о дереве.

ПЕЧЕНЬЯ НЕСУТСЯ ЯВНО. Каждый шаг кладёт `Cookie` заголовком из захваченного
предыдущим шагом — потому что предмет набора и есть «предъявить СОХРАНЁННОЕ
печенье после выхода», а банка прогонщика после выхода носитель снимает сама
(`Max-Age=-1`). Банка при этом добавляет свои печенья к явному заголовку; их
значения те же, и служба читает первое совпадение — явное.

Coverage:
  IAM-LOGINLANE-OK-CSRF-ISSUED          — контекст формы выдаётся и признак — строка; повтор
                                          контекст не меняет (Ф3-35)
  IAM-LOGINLANE-NEG-WRONG-PASSWORD      — неверный пароль → 401 code 16 одним текстом, без
                                          носителя (Ф3-03)
  IAM-LOGINLANE-OK-LOGIN-LOGOUT-REPRESENT — вход выдаёт носитель; выход завершает сессию
                                          на стороне службы; СОХРАНЁННЫЙ носитель после выхода
                                          отвергается (Ф3-01, Ф3-15, Ф3-17)
  IAM-LOGINLANE-NEG-CSRF-MISSING        — форма без признака → 400, поле названо (Ф3-36)
"""

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы входа паролем службы; поднимается только посадкой "
             "`own` — на посадке `external` его нет, и это не отказ продукта, а "
             "условие, которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_LOGIN = "/iam/v1/auth/login"
_LOGOUT = "/iam/v1/auth/logout"
_PASSWORD = "/iam/v1/auth/password"

# Адрес источника, который на живом проводе ставит край (Р10). Здесь его нет —
# ставим сами: без него счёт частоты по источнику ведётся на пустом ключе.
_SOURCE = "203.0.113.10"


def _lane(path):
    return [
        *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
        f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: {js_str(_SOURCE)}}});",
    ]


def _with_cookies(*vars_):
    """Явный `Cookie` из захваченных переменных; отсутствующая — не шлётся."""
    parts = " + ".join(
        f"(pm.environment.get({js_str(v)}) ? {js_str(name)} + '=' + pm.environment.get({js_str(v)}) + '; ' : '')"
        for name, v in vars_)
    return [
        f"const __cookie = ({parts}).replace(/; $/, '');",
        "if (__cookie) { pm.request.headers.upsert({key: 'Cookie', value: __cookie}); }",
    ]


def _capture_cookie(name, var, label):
    """Захват значения печенья из `Set-Cookie` ответа; отсутствие — красное."""
    # Блок, а не именованная по переменной константа: имя в скрипт не
    # подставляется, а два захвата в одном шаге не сталкиваются объявлениями.
    return [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(name + '=')}));",
        f"  pm.test({js_str(label + ': ответ ставит печенье ' + name)}, () => "
        "pm.expect(__sc.length, JSON.stringify(pm.response.headers.all())).to.eql(1));",
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(var)}, __sc[0].value.split(';')[0].slice({len(name) + 1})); }}",
        "}",
    ]


def _refusal(status, code, text, label):
    return [
        *assert_status(status),
        *assert_grpc_code(code, {16: "UNAUTHENTICATED", 3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED"}[code]),
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({js_str(text)});",
        "});",
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
    ]


# ───────────────────────────────────────────────────────────────────────────
# КОНТЕКСТ ФОРМЫ. Без него ни одна форма ниже не отправляется; повтор с тем же
# печеньем контекст не меняет (Ф3-35).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-CSRF-ISSUED",
    title="Признак формы выдаётся держателю контекста; повторный запрос контекст не меняет",
    classes=["SEC"],
    priority="P0",
    steps=[
        Step(
            name="csrf-login-first",
            method="GET",
            path=_CSRF + "?form=login",
            pre_script=_lane(_CSRF + "?form=login"),
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CSRF: тело несёт csrfToken строкой', () => pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
                "pm.environment.set('loginLaneCsrfLogin', j.csrfToken);",
                *_capture_cookie("kaname_form", "loginLaneFormCookie", "CSRF"),
                "pm.test('CSRF: печенье контекста — HttpOnly, Secure, SameSite=Lax, без срока', () => {",
                "  const sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_form='))[0];",
                "  pm.expect(sc, 'Set-Cookie kaname_form').to.exist;",
                "  const v = sc.value;",
                "  pm.expect(v, v).to.match(/HttpOnly/i);",
                "  pm.expect(v, v).to.match(/Secure/i);",
                "  pm.expect(v, v).to.match(/SameSite=Lax/i);",
                "  pm.expect(v, v).to.not.match(/Max-Age=|Expires=/i);",
                "});",
            ],
        ),
        Step(
            name="csrf-login-again-same-context",
            method="GET",
            path=_CSRF + "?form=login",
            pre_script=[*_lane(_CSRF + "?form=login"), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CSRF-AGAIN: тот же контекст — тот же признак', () => "
                "pm.expect(j.csrfToken, JSON.stringify(j)).to.eql(pm.environment.get('loginLaneCsrfLogin')));",
                "pm.test('CSRF-AGAIN: контекст не сменён — печенье не переставлено', () => "
                "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
                "&& h.value.startsWith('kaname_form=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ОТРИЦАНИЕ: неверный пароль — один текст, носителя нет (Ф3-03).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-WRONG-PASSWORD",
    title="Неверный пароль: 401 одним текстом, носитель сессии не выдан",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="login-wrong-password",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "not-the-password-{{runId}}",
                  "csrfToken": "{{loginLaneCsrfLogin}}"},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(401, 16, "authentication failed", "WRONG-PW"),
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ХРЕБЕТ Ф3: вход → выход → предъявить сохранённое → отказ.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-LOGIN-LOGOUT-REPRESENT",
    title="Вход выдаёт носитель; выход завершает сессию у службы; сохранённый носитель после выхода отвергается",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="login",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}",
                  "csrfToken": "{{loginLaneCsrfLogin}}"},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('LOGIN: тело несёт человека и сессию', () => {",
                "  pm.expect(j.user, JSON.stringify(j)).to.have.property('id');",
                "  pm.expect(j.session, JSON.stringify(j)).to.have.property('expiresAt');",
                "  pm.expect(j.session.assuranceLevel, JSON.stringify(j)).to.eql('1');",
                "});",
                *_capture_cookie("kaname_session", "loginLaneSessionCookie", "LOGIN"),
                "pm.test('LOGIN: носитель — HttpOnly, Secure, SameSite=Lax, со сроком', () => {",
                "  const sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='))[0];",
                "  pm.expect(sc, 'Set-Cookie kaname_session').to.exist;",
                "  pm.expect(sc.value, sc.value).to.match(/HttpOnly/i).and.match(/Secure/i).and.match(/SameSite=Lax/i).and.match(/Max-Age=[1-9]/);",
                "});",
                # Контекст формы СМЕНЯЕТСЯ выдачей сессии (Р12, Ф3-37): захват нового.
                *_capture_cookie("kaname_form", "loginLaneFormCookie", "LOGIN"),
            ],
        ),
        Step(
            name="csrf-logout",
            method="GET",
            path=_CSRF + "?form=logout",
            pre_script=[*_lane(_CSRF + "?form=logout"), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CSRF-LOGOUT: признак выдан', () => pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
                "pm.environment.set('loginLaneCsrfLogout', j.csrfToken);",
                "pm.test('CSRF-LOGOUT: признак выхода отличается от признака входа — вид формы в него замешан', () => "
                "pm.expect(j.csrfToken).to.not.eql(pm.environment.get('loginLaneCsrfLogin')));",
            ],
        ),
        Step(
            name="logout",
            method="POST",
            path=_LOGOUT,
            body={"csrfToken": "{{loginLaneCsrfLogout}}"},
            pre_script=[*_lane(_LOGOUT), *_with_cookies(("kaname_session", "loginLaneSessionCookie"),
                                                        ("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "pm.test('LOGOUT: ответ снимает носитель у браузера (Max-Age отрицательный либо нулевой)', () => {",
                "  const sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='))[0];",
                "  pm.expect(sc, JSON.stringify(pm.response.headers.all())).to.exist;",
                "  pm.expect(sc.value, sc.value).to.match(/kaname_session=;/).and.match(/Max-Age=(0|-1)/);",
                "});",
            ],
        ),
        Step(
            name="csrf-password-after-logout",
            method="GET",
            path=_CSRF + "?form=password",
            pre_script=[*_lane(_CSRF + "?form=password"), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.environment.set('loginLaneCsrfPassword', j.csrfToken);",
                "pm.test('CSRF-PW: выход контекст формы не трогает — признак выдан на тот же контекст', () => "
                "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
                "&& h.value.startsWith('kaname_form=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
            ],
        ),
        Step(
            # ПРЕДМЕТ НАБОРА: сохранённый до выхода носитель предъявляется глаголу,
            # требующему сессии, — и отвергается СЛУЖБОЙ, не браузером. Пароли
            # годные намеренно: отказ обязан прийти от отсутствия сессии, а не от
            # формы полей, иначе шаг зеленел бы на любом отказе.
            name="represent-ended-session",
            method="POST",
            path=_PASSWORD,
            body={"currentPassword": "{{loginLanePassword}}", "newPassword": "Replaced-{{runId}}-long-enough",
                  "csrfToken": "{{loginLaneCsrfPassword}}"},
            pre_script=[*_lane(_PASSWORD), *_with_cookies(("kaname_session", "loginLaneSessionCookie"),
                                                          ("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                "pm.test('REPRESENT: носитель, сохранённый до выхода, был выдан (контроль непустоты)', () => "
                "pm.expect(pm.environment.get('loginLaneSessionCookie'), 'носитель входа не захвачен').to.be.a('string').and.not.empty);",
                *_refusal(401, 16, "authentication failed", "REPRESENT"),
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ОТРИЦАНИЕ: форма без признака — поле названо, глагол не исполняется (Ф3-36).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-CSRF-MISSING",
    title="Форма входа без признака: 400 с именем поля, глагол не исполняется",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="login-without-csrf",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}"},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "loginLaneFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(400, 3, "Illegal argument csrfToken: required", "NO-CSRF"),
        ),
    ],
))
