# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set восстановления доступа кодом по почте (Ф5, kacho#1271).

Предмет — два глагола на СОБСТВЕННОМ слушателе формы службы
(`/iam/v1/auth/recovery`, `/iam/v1/auth/recovery/complete`), той же полосы, что
вход (Ф3): поднимается только посадкой `authn.identityProvider: own` и допускает
РОВНО край по SAN клиентского сертификата. Переменные те же, что у набора
`kaname-login-lane.py`:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека с подтверждённым адресом (посев)

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора входа: на автономном стенде
службы посадка `own` не поднята, `loginLaneBaseUrl` пуст, и каждый шаг уходит в
«условие не создано» помеченным утверждением, а не в зелёное и не в красное.

ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ. Счастливого завершения с настоящим кодом здесь нет:
код уходит ПИСЬМОМ, и прочитать его через край нельзя by construction — это
предмет Ф5-14 (доставка, `kacho#1773`) и наблюдения письма у приёмника
(ID-MAIL-1 MAIL-04). Здесь утверждается то, что видно на проводе без письма:
ответ на запрос кода один при любом исходе, предъявление неверного кода —
один отказ без носителя, форма без признака — поле названо.

Coverage:
  IAM-RECOVERY-OK-REQUEST-SAME-ANSWER   — запрос кода для существующего и для
                                          несуществующего адреса отвечает 200 {} побайтово
                                          одинаково и не ставит печений (Ф5-01, Ф5-02)
  IAM-RECOVERY-NEG-WRONG-CODE           — неверный код с новым паролем → 401 code 16
                                          одним текстом, носителя нет (Ф5-04/05/07 по форме
                                          отказа; сам код здесь заведомо чужой)
  IAM-RECOVERY-NEG-CSRF-MISSING         — форма предъявления без признака → 400, поле
                                          названо; глагол не исполняется
"""

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это не отказ продукта, а условие, "
             "которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_RECOVERY = "/iam/v1/auth/recovery"
_COMPLETE = "/iam/v1/auth/recovery/complete"

# Адрес источника, который на живом проводе ставит край (Р10).
_SOURCE = "203.0.113.11"


def _lane(path):
    return [
        *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
        f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: {js_str(_SOURCE)}}});",
    ]


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
        "pm.expect(__sc.length, JSON.stringify(pm.response.headers.all())).to.eql(1));",
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(var)}, __sc[0].value.split(';')[0].slice({len(name) + 1})); }}",
        "}",
    ]


def _no_session_cookie(label):
    return [
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
    ]


def _refusal(status, code, text, label):
    return [
        *assert_status(status),
        *assert_grpc_code(code, {16: "UNAUTHENTICATED", 3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED"}[code]),
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({js_str(text)});",
        "});",
        *_no_session_cookie(label),
    ]


# ───────────────────────────────────────────────────────────────────────────
# ЗАПРОС КОДА: ответ один при любом исходе (Ф5-01, Ф5-02).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-RECOVERY-OK-REQUEST-SAME-ANSWER",
    title="Запрос кода восстановления отвечает одинаково для существующего и несуществующего адреса",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="csrf-recovery",
            method="GET",
            path=_CSRF + "?form=recovery",
            pre_script=_lane(_CSRF + "?form=recovery"),
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CSRF-RECOVERY: признак выдан строкой', () => pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
                "pm.environment.set('recoveryCsrfRequest', j.csrfToken);",
                *_capture_cookie("kaname_form", "recoveryFormCookie", "CSRF-RECOVERY"),
            ],
        ),
        Step(
            name="request-existing-address",
            method="POST",
            path=_RECOVERY,
            body={"email": "{{loginLaneEmail}}", "csrfToken": "{{recoveryCsrfRequest}}"},
            pre_script=[*_lane(_RECOVERY), *_with_cookies(("kaname_form", "recoveryFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "pm.test('REQUEST-EXISTING: тело — пустой объект, исход не сообщается', () => "
                "pm.expect(pm.response.json(), pm.response.text()).to.eql({}));",
                "pm.environment.set('recoveryRequestBodyExisting', pm.response.text());",
                *_no_session_cookie("REQUEST-EXISTING"),
                "pm.test('REQUEST-EXISTING: контекст формы не переставлен', () => "
                "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length, "
                "JSON.stringify(pm.response.headers.all())).to.eql(0));",
            ],
        ),
        Step(
            name="request-nobody-address",
            method="POST",
            path=_RECOVERY,
            body={"email": "nobody-{{runId}}@example.invalid", "csrfToken": "{{recoveryCsrfRequest}}"},
            pre_script=[*_lane(_RECOVERY), *_with_cookies(("kaname_form", "recoveryFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "pm.test('REQUEST-NOBODY: тело побайтово равно ответу для существующего адреса (Ф5-02)', () => "
                "pm.expect(pm.response.text()).to.eql(pm.environment.get('recoveryRequestBodyExisting')));",
                *_no_session_cookie("REQUEST-NOBODY"),
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ОТРИЦАНИЕ: неверный код — один текст, носителя нет.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-RECOVERY-NEG-WRONG-CODE",
    title="Неверный код восстановления: 401 одним текстом, носитель сессии не выдан",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        Step(
            name="csrf-recovery-complete",
            method="GET",
            path=_CSRF + "?form=recovery-complete",
            pre_script=[*_lane(_CSRF + "?form=recovery-complete"), *_with_cookies(("kaname_form", "recoveryFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CSRF-COMPLETE: признак выдан строкой', () => pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
                "pm.environment.set('recoveryCsrfComplete', j.csrfToken);",
                "pm.test('CSRF-COMPLETE: признак предъявления отличается от признака запроса — вид формы замешан', () => "
                "pm.expect(j.csrfToken).to.not.eql(pm.environment.get('recoveryCsrfRequest')));",
                "{",
                "  const __sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_form='));",
                "  if (__sc.length === 1) { pm.environment.set('recoveryFormCookie', __sc[0].value.split(';')[0].slice(12)); }",
                "}",
            ],
        ),
        Step(
            # Код заведомо чужой: ни один выданный код не равен своему же
            # написанию из одной буквы, а форма при этом годная — отказ обязан
            # прийти от предъявления, а не от полей.
            name="complete-wrong-code",
            method="POST",
            path=_COMPLETE,
            body={"email": "{{loginLaneEmail}}", "code": "AAAAA-AAAAA",
                  "newPassword": "Recovered-{{runId}}-long-enough", "csrfToken": "{{recoveryCsrfComplete}}"},
            pre_script=[*_lane(_COMPLETE), *_with_cookies(("kaname_form", "recoveryFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(401, 16, "authentication failed", "WRONG-CODE"),
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ОТРИЦАНИЕ: форма предъявления без признака — поле названо.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-RECOVERY-NEG-CSRF-MISSING",
    title="Форма предъявления кода без признака: 400 с именем поля, глагол не исполняется",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="complete-without-csrf",
            method="POST",
            path=_COMPLETE,
            body={"email": "{{loginLaneEmail}}", "code": "AAAAA-AAAAA",
                  "newPassword": "Recovered-{{runId}}-long-enough"},
            pre_script=[*_lane(_COMPLETE), *_with_cookies(("kaname_form", "recoveryFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(400, 3, "Illegal argument csrfToken: required", "NO-CSRF"),
        ),
    ],
))
