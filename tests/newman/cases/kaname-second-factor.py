# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set второго фактора: код по времени и запасные коды (Ф12, kacho#1281).

Предмет — шесть глаголов семейства на СОБСТВЕННОМ слушателе формы службы
(`/iam/v1/auth/second-factor/{enroll,confirm,remove,backup-codes}`,
`GET /iam/v1/auth/second-factor`, `/iam/v1/auth/step-up`) и поле `secondFactor`
формы входа — той же полосы, что вход (Ф3): поднимается только посадкой
`authn.identityProvider: own` и допускает РОВНО край по SAN клиентского
сертификата. Переменные те же, что у набора `kaname-login-lane.py`:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека с заведённым способом входа паролем (посев)
  {{loginLanePassword}}  — его пароль (посев)

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора входа: на автономном стенде
службы посадка `own` не поднята, `loginLaneBaseUrl` пуст, и каждый шаг уходит в
«условие не создано» помеченным утверждением, а не в зелёное и не в красное.

КОД ВЫЧИСЛЯЕТ ПОСЕВ (Ф12-08): из `secret` ответа `enroll` — RFC 6238, SHA-1, шесть
цифр, шаг 30 с. Ступень подтверждения `t₀` запоминается; вход с кодом идёт
ступенью `t₀ + 1` — она в окне ±1 и старше принятого подтверждением шага (Р5).
Посев границы ступени НЕ ждёт, и это сказано здесь, а не оставлено часам: код
той же ступени, что при `confirm`, верный продукт отвергает повтором.

ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ: окно ±1 по краям (Ф12-21 — часы пробы), гонки (Ф12-07,
Ф12-24 — интеграция), счёт частоты (Ф12-31 — N попыток в одном окне сделали бы
следующий прогон красным по частоте).

Coverage:
  IAM-2FA-OK-ENROLL-CONFIRM-LOGIN-LEVEL2  — Ф12-08 цепочка: вход «1» → enroll (секрет один
                                            раз) → confirm кодом (коды один раз, сессия «2»,
                                            носитель перевыпущен) → состояние: заведён, 10 из 10
                                            → выход → вход с кодом t₀+1 — «2» (Ф12-11); без
                                            кода — «1» (Ф12-14); повтор кода — 401 (Ф12-13 г)
  IAM-2FA-OK-BACKUP-CODE-STEP-UP          — Ф12-18: церемония запасным кодом — «2», остаток
                                            9 в ответе; тот же код второй раз — 401 (Ф12-16
                                            форма); состояние — 9 из 10
  IAM-2FA-OK-REMOVE-BY-CODE               — Ф12-28: снятие запасным кодом — сессия «2»,
                                            остаток в ответе; состояние — не заведён; вход с
                                            кодом после снятия — тот же 401, что на неверный
                                            пароль, тело побайтово (Ф12-13 е: состояние наружу
                                            не выходит, kaname#257); без кода — «1»
  IAM-2FA-NEG-FORMS-AND-STATE             — Ф12-06/Ф12-41: `enroll` с чужим признаком — 403
                                            FORM_TOKEN_REJECTED; `confirm` без кода — 400 с
                                            именем поля; `step-up` с `method` вне словаря — 400;
                                            `confirm` без ожидающего заведения — 400
                                            ENROLLMENT_NOT_PENDING (Ф12-04 в)
"""

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это не отказ продукта, а условие, "
             "которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_LOGIN = "/iam/v1/auth/login"
_LOGOUT = "/iam/v1/auth/logout"
_STATUS = "/iam/v1/auth/second-factor"
_ENROLL = "/iam/v1/auth/second-factor/enroll"
_CONFIRM = "/iam/v1/auth/second-factor/confirm"
_REMOVE = "/iam/v1/auth/second-factor/remove"
_BACKUP_CODES = "/iam/v1/auth/second-factor/backup-codes"
_STEP_UP = "/iam/v1/auth/step-up"

# Адрес источника, который на живом проводе ставит край (Р10).
_SOURCE = "203.0.113.12"

# Вычисление кода по времени в песочнице прогонщика: base32 (RFC 4648, без
# дополнения) → HMAC-SHA1 (crypto-js) → динамическое усечение → шесть цифр.
# Объявляется в pre-script каждого шага, которому нужен код, — песочница между
# шагами функции не хранит.
_TOTP_JS = [
    "const __totp = (secretB32, step) => {",
    "  const CryptoJS = require('crypto-js');",
    "  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';",
    "  let bits = 0, value = 0; const bytes = [];",
    "  for (const ch of secretB32.toUpperCase()) {",
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
    "const __stepNow = () => Math.floor(Date.now() / 1000 / 30);",
]


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


def _session_and_form():
    return _with_cookies(("kaname_session", "sfSessionCookie"), ("kaname_form", "sfFormCookie"))


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


def _refusal(status, code, text, label, reason=None):
    names = {16: "UNAUTHENTICATED", 3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED", 9: "FAILED_PRECONDITION", 6: "ALREADY_EXISTS"}
    out = [
        *assert_status(status),
        *assert_grpc_code(code, names[code]),
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({js_str(text)});",
        "});",
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
    ]
    if reason:
        out += [
            f"pm.test({js_str(label + ': токен отказа ' + reason)}, () => {{",
            "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
            "  const info = (j.details || []).filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0];",
            f"  pm.expect(info && info.reason, JSON.stringify(j)).to.eql({js_str(reason)});",
            "});",
        ]
    return out


def _csrf_step(name, kind, var, label):
    return Step(
        name=name,
        method="GET",
        path=_CSRF + "?form=" + kind,
        pre_script=[*_lane(_CSRF + "?form=" + kind), *_with_cookies(("kaname_form", "sfFormCookie"))],
        insecure_tls=True,
        auth="anonymous",
        test_script=[
            *assert_status(200),
            "const j = pm.response.json();",
            f"pm.test({js_str(label + ': признак выдан')}, () => pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
            f"pm.environment.set({js_str(var)}, j.csrfToken);",
            "{",
            "  const __sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_form='));",
            "  if (__sc.length === 1) { pm.environment.set('sfFormCookie', __sc[0].value.split(';')[0].slice(12)); }",
            "}",
        ],
    )


def _login_step(name, label, second_factor=None, level="1"):
    body = {"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{sfCsrfLogin}}"}
    if second_factor is not None:
        body["secondFactor"] = second_factor
    return Step(
        name=name,
        method="POST",
        path=_LOGIN,
        body=body,
        pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie"))],
        insecure_tls=True,
        auth="anonymous",
        test_script=[
            *assert_status(200),
            "const j = pm.response.json();",
            f"pm.test({js_str(label + ': сессия уровня ' + level)}, () => pm.expect(j.session && j.session.assuranceLevel, JSON.stringify(j)).to.eql({js_str(level)}));",
            *_capture_cookie("kaname_session", "sfSessionCookie", label),
            *_capture_cookie("kaname_form", "sfFormCookie", label),
        ],
    )


def _logout_steps(prefix):
    return [
        _csrf_step(prefix + "-csrf-logout", "logout", "sfCsrfLogout", "CSRF-LOGOUT"),
        Step(
            name=prefix + "-logout",
            method="POST",
            path=_LOGOUT,
            body={"csrfToken": "{{sfCsrfLogout}}"},
            pre_script=[*_lane(_LOGOUT), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[*assert_status(200), "pm.environment.unset('sfSessionCookie');"],
        ),
        _csrf_step(prefix + "-csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
    ]


# ───────────────────────────────────────────────────────────────────────────
# ХРЕБЕТ Ф12-08: вход → enroll → confirm → состояние → выход → вход с кодом → «2».
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-ENROLL-CONFIRM-LOGIN-LEVEL2",
    title="Фактор заводится и предъявляется без браузера: enroll → confirm → вход с кодом даёт «2»",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
        _login_step("login-level-1", "LOGIN-1"),
        Step(
            name="status-before-enroll",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STATUS-0: фактор не заведён, набора нет', () => {",
                "  pm.expect(j.totp && j.totp.enrolled, JSON.stringify(j)).to.eql(false);",
                "  pm.expect(j, JSON.stringify(j)).to.not.have.property('backupCodes');",
                "});",
            ],
        ),
        _csrf_step("csrf-second-factor", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        Step(
            name="enroll",
            method="POST",
            path=_ENROLL,
            body={"csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[*_lane(_ENROLL), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('ENROLL: секрет base32 без дополнения (32 знака — 20 байт), адрес otpauth, срок', () => {",
                "  pm.expect(j.secret, JSON.stringify(j)).to.match(/^[A-Z2-7]{32}$/);",
                "  pm.expect(j.otpauthUri, JSON.stringify(j)).to.match(/^otpauth:\\/\\/totp\\/.+\\?secret=[A-Z2-7]{32}&issuer=.+&algorithm=SHA1&digits=6&period=30$/);",
                "  pm.expect(j.expiresAt, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "});",
                "pm.environment.set('sfSecret', j.secret);",
                "pm.test('ENROLL: печений не пишет — сессия и контекст прежние', () => "
                "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
            ],
        ),
        Step(
            name="status-pending",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STATUS-PENDING: не заведён, срок ожидания назван, набора нет', () => {",
                "  pm.expect(j.totp && j.totp.enrolled, JSON.stringify(j)).to.eql(false);",
                "  pm.expect(j.totp && j.totp.pendingUntil, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "  pm.expect(j, JSON.stringify(j)).to.not.have.property('backupCodes');",
                "});",
            ],
        ),
        Step(
            name="confirm",
            method="POST",
            path=_CONFIRM,
            body={"code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[
                *_lane(_CONFIRM), *_session_and_form(), *_TOTP_JS,
                "const __t0 = __stepNow();",
                "pm.environment.set('sfStep0', String(__t0));",
                "pm.environment.set('sfCode', __totp(pm.environment.get('sfSecret'), __t0));",
            ],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('CONFIRM: десять запасных кодов по десять знаков Crockford, сессия «2», assurance', () => {",
                "  pm.expect(j.backupCodes, JSON.stringify(j)).to.be.an('array').with.lengthOf(10);",
                "  j.backupCodes.forEach(c => pm.expect(c, c).to.match(/^[0-9A-HJKMNP-TV-Z]{10}$/));",
                "  pm.expect(j.session && j.session.assuranceLevel, JSON.stringify(j)).to.eql('2');",
                "  pm.expect(j.assurance, JSON.stringify(j)).to.eql({level: '2', level2Reachable: true, missingForLevel2: []});",
                "});",
                "if (j.backupCodes && j.backupCodes.length === 10) {",
                "  pm.environment.set('sfBackup0', j.backupCodes[0]);",
                "  pm.environment.set('sfBackup1', j.backupCodes[1]);",
                "}",
                *_capture_cookie("kaname_session", "sfSessionCookie", "CONFIRM"),
            ],
        ),
        Step(
            name="status-enrolled",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STATUS-ACTIVE: заведён, момент подтверждения, 10 из 10', () => {",
                "  pm.expect(j.totp && j.totp.enrolled, JSON.stringify(j)).to.eql(true);",
                "  pm.expect(j.totp && j.totp.confirmedAt, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "  pm.expect(j.backupCodes, JSON.stringify(j)).to.eql({remaining: 10, total: 10});",
                "});",
                "pm.test('STATUS: ни секрета, ни кодов, ни адреса в ответе (Ф12-27)', () => {",
                "  const t = pm.response.text();",
                "  pm.expect(t).to.not.include('otpauth'); pm.expect(t).to.not.include(pm.environment.get('sfSecret'));",
                "});",
            ],
        ),
        *_logout_steps("after-confirm"),
        Step(
            # Ф12-11 / Ф12-08: ступень t₀ + 1 — в окне ±1 и старше принятого шага.
            name="login-with-totp-level-2",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{sfCsrfLogin}}",
                  "secondFactor": {"method": "totp", "code": "{{sfCode}}"}},
            pre_script=[
                *_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie")), *_TOTP_JS,
                "const __t1 = parseInt(pm.environment.get('sfStep0'), 10) + 1;",
                "pm.environment.set('sfCode', __totp(pm.environment.get('sfSecret'), __t1));",
            ],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('LOGIN-2FA: сессия «2» на исходном носителе (Ф11-02)', () => pm.expect(j.session && j.session.assuranceLevel, JSON.stringify(j)).to.eql('2'));",
                *_capture_cookie("kaname_session", "sfSessionCookie", "LOGIN-2FA"),
                *_capture_cookie("kaname_form", "sfFormCookie", "LOGIN-2FA"),
            ],
        ),
        *_logout_steps("after-level-2"),
        Step(
            # Ф12-13 (г): тот же код — повтор, 401 одним текстом.
            name="login-replayed-code",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{sfCsrfLogin}}",
                  "secondFactor": {"method": "totp", "code": "{{sfCode}}"}},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(401, 16, "authentication failed", "REPLAY"),
        ),
        # Ф12-14: без кода — «1», а не отказ.
        _login_step("login-without-code-level-1", "LOGIN-NO-CODE"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-18: церемония запасным кодом — «2», остаток в ответе; повтор — 401.
# Стоит на фикстуре хребта: сессия «1» и запасные коды захвачены им.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-BACKUP-CODE-STEP-UP",
    title="Церемония запасным кодом поднимает сессию до «2» и называет остаток; тот же код второй раз — 401",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        Step(
            name="step-up-with-backup-code",
            method="POST",
            path=_STEP_UP,
            body={"method": "lookup_secret", "code": "{{sfBackup0}}", "csrfToken": "{{sfCsrfStepUp}}"},
            pre_script=[
                *_lane(_STEP_UP), *_session_and_form(),
                "pm.test('STEP-UP: фикстура хребта на месте — сессия и запасной код захвачены', () => {",
                "  pm.expect(pm.environment.get('sfSessionCookie'), 'носитель').to.be.a('string').and.not.empty;",
                "  pm.expect(pm.environment.get('sfBackup0'), 'запасной код').to.be.a('string').and.not.empty;",
                "});",
            ],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STEP-UP: «2», остаток 9 назван только здесь', () => {",
                "  pm.expect(j.session && j.session.assuranceLevel, JSON.stringify(j)).to.eql('2');",
                "  pm.expect(j.assurance && j.assurance.level, JSON.stringify(j)).to.eql('2');",
                "  pm.expect(j.backupCodesRemaining, JSON.stringify(j)).to.eql(9);",
                "});",
                *_capture_cookie("kaname_session", "sfSessionCookie", "STEP-UP"),
            ],
        ),
        Step(
            name="step-up-same-backup-code-again",
            method="POST",
            path=_STEP_UP,
            body={"method": "lookup_secret", "code": "{{sfBackup0}}", "csrfToken": "{{sfCsrfStepUp}}"},
            pre_script=[*_lane(_STEP_UP), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(401, 16, "authentication failed", "BACKUP-AGAIN"),
        ),
        Step(
            name="status-after-backup-code",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STATUS: 9 из 10', () => pm.expect(j.backupCodes, JSON.stringify(j)).to.eql({remaining: 9, total: 10}));",
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-28: снятие запасным кодом; после — состояние «не заведён», вход с кодом —
# тот же 401 «authentication failed», что на неверный пароль, тело побайтово
# (Ф12-13 е, kaname#257: код при незаведённом факторе не называет совпавшего
# пароля), без кода — «1». Порядок трёх входов несущий: неверный пароль + код
# → верный пароль + код (тело равно первому) → верный пароль без кода (сессия
# «1», положительный близнец). Заодно возвращает посев в исходное: следующий
# прогон снова заводит фактор с нуля.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-REMOVE-BY-CODE",
    title="Снятие фактора запасным кодом: строки сняты, сессия жива на «2», вход с кодом после — тот же 401, что на неверный пароль",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("csrf-second-factor-remove", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        Step(
            name="remove-with-backup-code",
            method="POST",
            path=_REMOVE,
            body={"method": "lookup_secret", "code": "{{sfBackup1}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[*_lane(_REMOVE), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('REMOVE: сессия «2», остаток назван (8: два кода потреблены), путь к «2» закрыт', () => {",
                "  pm.expect(j.session && j.session.assuranceLevel, JSON.stringify(j)).to.eql('2');",
                "  pm.expect(j.backupCodesRemaining, JSON.stringify(j)).to.eql(8);",
                "  pm.expect(j.assurance, JSON.stringify(j)).to.eql({level: '2', level2Reachable: false, missingForLevel2: []});",
                "});",
                *_capture_cookie("kaname_session", "sfSessionCookie", "REMOVE"),
            ],
        ),
        Step(
            name="status-after-remove",
            method="GET",
            path=_STATUS,
            pre_script=[*_lane(_STATUS), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('STATUS: не заведён, набора нет', () => {",
                "  pm.expect(j.totp && j.totp.enrolled, JSON.stringify(j)).to.eql(false);",
                "  pm.expect(j, JSON.stringify(j)).to.not.have.property('backupCodes');",
                "});",
            ],
        ),
        *_logout_steps("after-remove"),
        Step(
            name="login-wrong-password-with-code-after-remove",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "not-the-password-{{runId}}", "csrfToken": "{{sfCsrfLogin}}",
                  "secondFactor": {"method": "totp", "code": "000000"}},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *_refusal(401, 16, "authentication failed", "WRONG-PW-WITH-CODE"),
                # Тело — эталон для следующего шага: сравнение побайтовое, не по полям.
                "pm.environment.set('sfWrongPasswordRefusalBody', pm.response.text());",
            ],
        ),
        Step(
            name="login-with-code-after-remove",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{sfCsrfLogin}}",
                  "secondFactor": {"method": "totp", "code": "000000"}},
            pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie"))],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *_refusal(401, 16, "authentication failed", "NOT-ENROLLED-ON-LOGIN"),
                "pm.test('NOT-ENROLLED-ON-LOGIN: тело побайтово равно отказу на неверный пароль — совпавший пароль не назван', () => "
                "pm.expect(pm.response.text()).to.eql(pm.environment.get('sfWrongPasswordRefusalBody')));",
            ],
        ),
        _login_step("login-plain-after-remove", "LOGIN-PLAIN"),
        *_logout_steps("after-plain"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ОТРИЦАНИЯ формы и состояния (Ф12-06, Ф12-41, Ф12-04 в). Сессия «1» без
# фактора: последним шагом хребта посев вернул её в исходное.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-NEG-FORMS-AND-STATE",
    title="Чужой признак — 403; поле не прислано — 400 с именем; способ вне словаря — 400; confirm без заведения — ENROLLMENT_NOT_PENDING",
    classes=["NEG", "VAL", "SEC"],
    priority="P1",
    steps=[
        _login_step("login-for-negatives", "LOGIN-NEG"),
        _csrf_step("csrf-second-factor-neg", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        _csrf_step("csrf-step-up-neg", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        Step(
            name="enroll-with-step-up-token",
            method="POST",
            path=_ENROLL,
            body={"csrfToken": "{{sfCsrfStepUp}}"},
            pre_script=[*_lane(_ENROLL), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(403, 7, "form token rejected", "FOREIGN-TOKEN", reason="FORM_TOKEN_REJECTED"),
        ),
        Step(
            name="confirm-without-code",
            method="POST",
            path=_CONFIRM,
            body={"csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[*_lane(_CONFIRM), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(400, 3, "Illegal argument code: required", "NO-CODE"),
        ),
        Step(
            name="step-up-method-outside-vocabulary",
            method="POST",
            path=_STEP_UP,
            body={"method": "sms", "code": "123456", "csrfToken": "{{sfCsrfStepUp}}"},
            pre_script=[*_lane(_STEP_UP), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(400, 3, "Illegal argument method: must be one of password|totp|lookup_secret", "BAD-METHOD"),
        ),
        Step(
            name="confirm-without-pending-enrollment",
            method="POST",
            path=_CONFIRM,
            body={"code": "123456", "csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[*_lane(_CONFIRM), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=_refusal(400, 9, "no pending enrollment: begin with enroll", "NOT-PENDING", reason="ENROLLMENT_NOT_PENDING"),
        ),
        *_logout_steps("after-negatives"),
    ],
))
