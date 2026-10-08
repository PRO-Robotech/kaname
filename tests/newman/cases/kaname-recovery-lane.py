# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set восстановления доступа кодом по почте (Ф5, kacho#1271).

Предмет — два глагола на СОБСТВЕННОМ слушателе формы службы
(`/iam/v1/auth/recovery`, `/iam/v1/auth/recovery/complete`), той же полосы, что
вход (Ф3): поднимается только посадкой `authn.identityProvider: own` и допускает
РОВНО край по SAN клиентского сертификата. Переменные:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека с подтверждённым адресом (посев)
  {{standMailboxUrl}}    — чтение приёмника писем стенда (`stand-mailbox.py`; посев) и
                           задержка его приёма (`POST /hold`, `POST /release`; Ф5-14)
  {{standMetricsUrl}}    — слушатель метрик процесса: клетки исходов запроса кода и
                           возраст головы почтовой очереди (посев `seed_mail_pace.py`)
  {{recoveryLettersPerRecipient}} · {{recoveryLetterWindow}} · {{recoverySourceAttempts}}
  · {{recoverySourceWindow}} — величины окон из карты настроек процесса (тот же посев)
  {{paceInviteFullEmail}} — адресат с окном писем приглашения, заполненным до N (тот же посев)
  {{ownRestBaseUrl}}     — собственный публичный фронт: блокировка и опрос операций
  {{iamRegistryTokenBaseUrl}} — поверхность выдачи: код авторизации и обмен на токен
  {{oauthClientId}} · {{oauthClientSecret}} · {{oauthRedirectUri}} — клиент церемонии
                           (посев церемонии), которым кейс куёт предъявителя надзора
  {{cloudSupervisorEmail}} · {{cloudSupervisorPassword}} · {{cloudSupervisorTotpSecret}}
                         — надзор облака стенда: `system_admin` и второй фактор
                           (посев церемонии стенда чарта, kaname#468)

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ — та же, что у набора входа: на автономном стенде
службы посадка `own` не поднята, `loginLaneBaseUrl` пуст, и каждый шаг уходит в
«условие не создано» помеченным утверждением, а не в зелёное и не в красное.

КОД БЕРЁТСЯ ИЗ ПИСЬМА У ПРИЁМНИКА СТЕНДА. Стенд посадки `own` сдаёт письма
своему почтовому узлу (`.github/scripts/stand-mailbox.py`), и набор читает код
тем же путём, что человек, — из письма, а не из базы. Читает он ТОЛЬКО дверью
`GET /codes?to=<адрес>&after=<строка>`: отчёт прогона выкладывается артефактом
публичного репозитория, а тело письма несёт код прозой, которую чистка отчёта не
режет; под именем `codes` значение срезается именем. Код кладётся в переменные
с последним словом `Code`, пароли — в переменные с `Password`, печенья и признаки
формы — с `Cookie` и `Csrf`: чистка режет их именем. Утверждения значений не
получают — сообщение литерал, предмет булев или число.

СВОИ ЛЮДИ У КАЖДОГО КЕЙСА. Кейс завершения заводит человека сам — регистрацией,
подтверждением адреса кодом письма регистрации и запросом кода восстановления
(`_person`, `_recovery_code`) — со своим адресом (`{{runId}}` и случайная
добавка) и своим источником: восстановление меняет пароль, неверные предъявления
копят счёт по адресу и по источнику, и человек посева, которого читают соседние
наборы (церемония, второй фактор), не должен ни того, ни другого получить.

ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ. Ответ и предел времени попытки при МОЛЧАЩЕМ почтовом
узле (задержка приёма у приёмника стенда отвечает временным отказом сразу и
предела времени не испытывает); время ответа двух полос запроса; состав ответа
службы краю о сессии (глагол внутреннего слушателя без HTTP-привязки). Почему и
кто держит каждое — ведомость долга позиций `.github/scripts/newman-suite-debt.py`.

Coverage:
  IAM-RECOVERY-OK-REQUEST-SAME-ANSWER   — запрос кода для существующего и для
                                          несуществующего адреса отвечает 200 {nextStep} побайтово
                                          одинаково и не ставит печений (Ф5-01, Ф5-02)
  IAM-RECOVERY-NEG-WRONG-CODE           — неверный код с новым паролем → 401 code 16
                                          одним текстом, носителя нет (Ф5-04/05/07 по форме
                                          отказа; сам код здесь заведомо чужой)
  IAM-RECOVERY-NEG-CSRF-MISSING         — форма предъявления без признака → 400, поле
                                          названо; глагол не исполняется
  IAM-RECOVERY-OK-CODE-IN-TIME          — Ф5-03: негодный новый пароль называет поле и код
                                          не тратит; тот же код с годным — сессия выдана,
                                          прежняя сессия личности негодна, новая годна
  IAM-RECOVERY-NEG-CODE-SECOND-TIME     — Ф5-05: применённый код второй раз — 401 без
                                          носителя; свежий код, предъявленный трижды
                                          одновременно, проходит ровно у одного
  IAM-RECOVERY-NEG-RATE-LIMIT           — Ф5-08: N неверных кодов — 401 каждый, следующий
                                          (верный) — 429 TOO_MANY_ATTEMPTS с Retry-After,
                                          побайтово равный отказу адреса, которого нет; N
                                          спрошено у полосы, а не выписано; близнец — N−1
                                          неверных, и верный код принимается
  IAM-RECOVERY-OK-NEW-PASSWORD-SIGNS-IN — Ф5-18: после завершения новым паролем входит;
                                          прежним — единый отказ
  IAM-RECOVERY-OK-ENDS-EVERY-SESSION    — Ф5-19: две живые сессии (восстановление запрошено
                                          из первой) после завершения негодны обе; выданная
                                          завершением — годна
  IAM-RECOVERY-NEG-BLOCKED-STAYS-BLOCKED — Ф5-17: заблокированная надзором облака проходит
                                          восстановление — отказ завершения равен отказу завершения
                                          на неверном коде (Р10 п. 2), новым паролем войти нельзя; после
                                          снятия блокировки надзором входит новым, а не прежним
  IAM-RECOVERY-OK-COMPLETION-RESETS-AS-FULL-LOGIN — Ф5-25: после N_адрес − 1 неверных
                                          завершение у личности с фактором (а) счёт не обнуляет
                                          (401, затем 429), у близнеца без фактора (б) — обнуляет
                                          (401, 401), у заблокированной (в) — отказ завершения
                                          сосчитан, следующая попытка — 429
  IAM-RECOVERY-OK-UNDELIVERED-AGE-VISIBLE — Ф5-14: приём приёмника задержан (временный отказ) —
                                          возраст головы почтовой очереди с нуля растёт, служба
                                          пыталась сдать письмо, письма у приёмника нет; задержка
                                          снята — письмо дошло, возраст вернулся к нулю, код годен
  IAM-RECOVERY-NEG-PACED-PER-RECIPIENT  — Ф5-26: N + 1 запросов для P — писем ровно N, ответ
                                          (N + 1)-го побайтово равен ответу о Z, recipient-paced
                                          +1, queued +N, код N-го письма проходит; (б) Q в том же
                                          окне — письмо; (в) P′ с окном приглашения, заполненным
                                          до N, — N писем восстановления
  IAM-RECOVERY-NEG-PACED-PER-SOURCE     — Ф5-27: M запросов о Z с источника S — запрос для P с
                                          S тот же ответ, письма нет, source-paced +1, no-row +M;
                                          (б) с S′ — письмо поставлено

Техники: классы эквивалентности (годный / негодный пароль; свой / чужой /
применённый код), граница счёта по адресу (N−1 · N · N+1), угадывание ошибок
(одновременное предъявление одного кода), переходы состояния сессии (жива →
отозвана), положительный близнец у каждого отказа.
"""

import urllib.parse as _urlparse

HOME = "kaname"

CASES = []

_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это не отказ продукта, а условие, "
             "которого стенд не создал")

_CSRF = "/iam/v1/auth/csrf"
_RECOVERY = "/iam/v1/auth/recovery"
_COMPLETE = "/iam/v1/auth/recovery/complete"

# Ответ запроса кода — ОДИН на все исходы и называет шаг (Ф5 Р10 п. 1,
# kaname#211); тело ровно `{"nextStep": …}` в той форме, что печатает
# слушатель (без пробелов).
_NEXT_STEP = ("a letter with a recovery code is sent if this address can recover access; "
              "if no letter arrives, request again later, sign in and confirm the address, "
              "or ask an administrator to reset your sign-in methods")
_NEXT_STEP_BODY = '{"nextStep":"' + _NEXT_STEP + '"}'
# Отказ завершения — ОДИН на все причины глагола, свой у глагола (Ф5 Р10 п. 2, Д22).
_NOT_RESTORED = ("access not restored; request a new recovery code, and if a new code "
                 "does not restore access, ask an administrator")

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
                "pm.test('REQUEST-EXISTING: тело называет шаг (Р10 п. 1), исход не сообщается', () => "
                f"pm.expect(pm.response.text()).to.eql({js_str(_NEXT_STEP_BODY)}));",
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
            test_script=[*_refusal(401, 16, _NOT_RESTORED, "WRONG-CODE"),
                         # Эталон отказа завершения для BLOCKED-COMPLETE (Ф1-59 по
                         # свойству: блокировка неотличима от прочих причин глагола).
                         "pm.environment.set('rcvCompletionRefusal', pm.response.text());"],
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


# ═══════════════════════════════════════════════════════════════════════════
# ЗАВЕРШЕНИЕ НАСТОЯЩИМ КОДОМ ИЗ ПИСЬМА (Ф5-03, Ф5-05, Ф5-08, Ф5-18, Ф5-19).
#
# Каждый кейс заводит своих людей: глаголами полосы (регистрация, подтверждение
# адреса кодом письма регистрации, запрос кода восстановления), с адресом из
# `{{runId}}` и случайной добавки и со своим источником. Шаги условия утверждают
# свой исход — отказ регистрации либо письма называет свой шаг, а не следующий.
# ═══════════════════════════════════════════════════════════════════════════

_REGISTER = "/iam/v1/auth/register"
_LOGIN = "/iam/v1/auth/login"
_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
# Чтение, требующее живой сессии и ничего не меняющее: состояние второго
# фактора. Живая сессия — 200, отозванная — 401 `authentication failed`.
_SESSION_PROBE = "/iam/v1/auth/second-factor"

_MAILBOX_WHY = ("чтение приёмника писем стенда посадки `own`; адрес пишет посев "
                "полосы входа — вне стенда `own` приёмника нет, и это условие, "
                "которого стенд не создал")
_HEAD_VERIFY = "Код подтверждения:"
_HEAD_RECOVERY = "Код восстановления:"
# Куда ложится код письма каждого вида; у каждого — свой счёт прочитанного.
_MAIL_STORES = ("VerifyCode", "MailCode")
# Предел ожидания письма: попыток и пауза между ними (мс). Замер на стенде kind
# посадки `own`: письмо доходит до приёмника за ~1 с; предел — с запасом на
# загруженный раннер, как у посева (`LETTER_BUDGET_S`).
_MAIL_WAIT_CAP = 90
_MAIL_WAIT_MS = 1000
# Код, заведомо не выданный никому: форма годная, отказ обязан прийти от
# предъявления, а не от полей.
_FOREIGN_CODE = "AAAAA-AAAAA"
# Предел петли «неверные предъявления до отказа по частоте»: выше любой разумной
# величины профиля; петля, упёршаяся в него, — красное с числом.
_LIMIT_PROBE_CAP = 30


def _v(p, name):
    return p + name


def _src_pre(p):
    return [f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: pm.environment.get({js_str(_v(p, 'Src'))}) || ''}});"]


def _person_init(p, tag):
    """Адрес, пароли и источник человека кейса — один раз, первым шагом."""
    return [
        "{",
        "  const __nonce = () => Math.floor(Math.random() * 2176782336).toString(36);",
        f"  pm.environment.set({js_str(_v(p, 'Email'))}, {js_str(tag + '-')} + pm.environment.get('runId') + '-' + __nonce() + '@kaname.local');",
        f"  pm.environment.set({js_str(_v(p, 'Password'))}, 'Pw-' + __nonce() + __nonce() + '-first');",
        f"  pm.environment.set({js_str(_v(p, 'NewPassword'))}, 'Pw-' + __nonce() + __nonce() + '-renewed');",
        f"  pm.environment.set({js_str(_v(p, 'Src'))}, '198.18.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
        # Счёт прочитанных кодов — СВОЙ у каждого вида письма: чтение отдаёт
        # элемент на КАЖДОЕ письмо адресата, и у письма другого вида он пуст,
        # поэтому общий счёт письма регистрации ждал бы второго кода
        # восстановления там, где пришёл первый.
        *(f"  pm.environment.set({js_str(_v(p, 'MailSeen' + store))}, '0');" for store in _MAIL_STORES),
        *(f"  pm.environment.unset({js_str(_v(p, n))});" for n in (
            "FormCookie", "SessionCookie", "Csrf", "VerifyCode", "MailCode")),
        "}",
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


def _no_session_issued(label):
    return [f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
            "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
            "&& h.value.startsWith('kaname_session=')).length).to.eql(0));"]


def _status_is(code, label):
    return [f"pm.test({js_str(label + f': ответ {code}')}, () => pm.expect(pm.response.code).to.eql({code}));"]


def _refused(status, grpc, text, label):
    """Отказ полосы: статус, код и текст порознь; значений удостоверений нет."""
    return [
        *_status_is(status, label),
        "let __r = {}; try { __r = pm.response.json(); } catch (e) { __r = {}; }",
        f"pm.test({js_str(label + f': код отказа {grpc}')}, () => pm.expect(__r.code).to.eql({grpc}));",
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => pm.expect(__r.message).to.eql({js_str(text)}));",
        *_no_session_issued(label),
    ]


def _csrf_step(p, name, form, *, init=None, with_session=None):
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


def _await_code(p, name, heading, store):
    """Код письма, пришедшего СВЕРХ уже прочитанных: петля с настоящей паузой."""
    path = (f"/codes?to={{{{{_v(p, 'Email')}}}}}&after="
            f"{_urlparse.quote(heading)}")
    counter, started = f"_mb_{p}_{name}".replace("-", "_"), f"_mbs_{p}_{name}".replace("-", "_")
    if store not in _MAIL_STORES:
        raise ValueError(f"_await_code: store {store!r} is not a declared mail store {_MAIL_STORES}")
    seen, label = _v(p, "MailSeen" + store), name.upper()
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
            "const __got = Array.isArray(__codes) ? __codes.filter(c => typeof c === 'string' && c.length > 0) : [];",
            f"if (pm.response.code === 200 && __got.length <= __seen && __n < {_MAIL_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _mbd = Date.now(); while (Date.now() - _mbd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': письмо с кодом дошло до приёмника стенда в пределе ожидания')}, () => "
            "pm.expect(__got.length > __seen).to.eql(true));",
            "if (__got.length > __seen) {",
            f"  pm.environment.set({js_str(_v(p, store))}, __got[__got.length - 1]);",
            f"  pm.environment.set({js_str(seen)}, String(__got.length));",
            "}",
        ],
    )


def _post(p, name, path, body, *, with_session=None, test_script=()):
    cookies = [("kaname_form", _v(p, "FormCookie"))]
    if with_session:
        cookies.append(("kaname_session", _v(p, with_session)))
    return Step(
        name=name, method="POST", path=path, body=body,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_src_pre(p),
                    *_with_cookies(*cookies)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=list(test_script),
    )


def _person(p, tag):
    """Человек кейса: регистрация → код письма регистрации → адрес подтверждён.

    Сессия подтверждённого адреса остаётся в `<p>SessionCookie`."""
    return [
        _csrf_step(p, f"{tag}-csrf-register", "register", init=_person_init(p, tag)),
        _post(p, f"{tag}-register", _REGISTER,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, 'Password')}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=[
                  *_status_is(200, f"{tag.upper()}-REGISTER"),
                  *_capture(p, "kaname_session", "SessionCookie", f"{tag.upper()}-REGISTER"),
                  *_capture(p, "kaname_form", "FormCookie", f"{tag.upper()}-REGISTER", required=False),
              ]),
        _await_code(p, f"{tag}-verify-letter", _HEAD_VERIFY, "VerifyCode"),
        _csrf_step(p, f"{tag}-csrf-verify", "verify-email-confirm", with_session="SessionCookie"),
        _post(p, f"{tag}-verify", _VERIFY_CONFIRM,
              {"code": f"{{{{{_v(p, 'VerifyCode')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[
                  *_status_is(200, f"{tag.upper()}-VERIFY"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(tag.upper() + '-VERIFY: адрес подтверждён')}, () => "
                  "pm.expect(!!(__j.session && __j.session.emailVerified === true)).to.eql(true));",
                  *_capture(p, "kaname_session", "SessionCookie", f"{tag.upper()}-VERIFY", required=False),
              ]),
        # Письмо восстановления идёт после письма регистрации: прочитанные коды
        # подтверждения в счёт писем восстановления не идут.
    ]


def _recovery_code(p, tag, *, from_session=None):
    """Запрос кода восстановления и код из письма — в `<p>MailCode`."""
    return [
        _csrf_step(p, f"{tag}-csrf-recovery", "recovery", with_session=from_session),
        _post(p, f"{tag}-request-code", _RECOVERY,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session=from_session,
              test_script=[
                  *_status_is(200, f"{tag.upper()}-REQUEST"),
                  f"pm.test({js_str(tag.upper() + '-REQUEST: тело называет шаг (Р10 п. 1)')}, () => "
                  f"pm.expect(pm.response.text()).to.eql({js_str(_NEXT_STEP_BODY)}));",
              ]),
        _await_code(p, f"{tag}-recovery-letter", _HEAD_RECOVERY, "MailCode"),
    ]


def _complete(p, name, *, code_var="MailCode", password_var="NewPassword", password_literal=None,
              test_script=()):
    pw = password_literal if password_literal is not None else f"{{{{{_v(p, password_var)}}}}}"
    return _post(p, name, _COMPLETE,
                 {"email": f"{{{{{_v(p, 'Email')}}}}}", "code": f"{{{{{_v(p, code_var)}}}}}",
                  "newPassword": pw, "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
                 test_script=test_script)


def _issued(p, label, store="RecoveredCookie"):
    """Успех завершения: тело входа и носитель сессии; новый контекст формы."""
    return [
        *_status_is(200, label),
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        f"pm.test({js_str(label + ': тело несёт человека и сессию')}, () => "
        "pm.expect(!!(__j.user && __j.user.id && __j.session && __j.session.expiresAt)).to.eql(true));",
        *_capture(p, "kaname_session", store, label),
        *_capture(p, "kaname_form", "FormCookie", label, required=False),
    ]


def _session_probe(p, name, cookie_var, alive):
    """Жива ли сессия: чтение, требующее сессии; ничего не меняет."""
    label = name.upper()
    return Step(
        name=name, method="GET", path=_SESSION_PROBE,
        pre_script=[*require_env_url("loginLaneBaseUrl", _SESSION_PROBE, _LANE_WHY), *_src_pre(p),
                    f"pm.test({js_str(label + ': носитель, который предъявляется, был выдан (контроль непустоты)')}, () => "
                    f"pm.expect(!!pm.environment.get({js_str(_v(p, cookie_var))})).to.eql(true));",
                    *_with_cookies(("kaname_session", _v(p, cookie_var)))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=(_status_is(200, label + " (сессия жива)") if alive
                     else _refused(401, 16, "authentication failed", label + " (сессия отозвана)")),
    )


def _login(p, tag, password_var, *, ok, store=None, user_var=None, keep=None, same_as=None):
    """Вход паролем. `user_var` — куда положить id человека из тела успеха;
    `keep` — запомнить тело отказа; `same_as` — отказ побайтово равен запомненному."""
    label = f"{tag.upper()}"
    test = ([*_status_is(200, label),
             "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
             f"pm.test({js_str(label + ': сессия выдана')}, () => "
             "pm.expect(!!(__j.session && __j.session.expiresAt)).to.eql(true));",
             *_capture(p, "kaname_session", store or "LoginCookie", label),
             *_capture(p, "kaname_form", "FormCookie", label, required=False)]
            if ok else _refused(401, 16, "authentication failed", label))
    if ok and user_var:
        test += [
            f"pm.test({js_str(label + ': тело называет человека')}, () => "
            "pm.expect(typeof (__j.user && __j.user.id) === 'string' && __j.user.id.length > 0).to.eql(true));",
            f"if (__j.user && __j.user.id) {{ pm.environment.set({js_str(_v(p, user_var))}, __j.user.id); }}",
        ]
    if not ok and keep:
        test += [f"pm.environment.set({js_str(keep)}, pm.response.text());"]
    if not ok and same_as:
        test += [f"pm.test({js_str(label + ': тело отказа побайтово равно запомненному')}, () => "
                 f"pm.expect(pm.response.text() === pm.environment.get({js_str(same_as)})).to.eql(true));"]
    return [
        _csrf_step(p, f"{tag}-csrf", "login"),
        _post(p, tag, _LOGIN,
              {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": f"{{{{{_v(p, password_var)}}}}}",
               "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              test_script=test),
    ]


# ───────────────────────────────────────────────────────────────────────────
# Ф5-03: код в срок вместе с новым паролем.
# ───────────────────────────────────────────────────────────────────────────
_P03 = "rcvA"
CASES.append(Case(
    id="IAM-RECOVERY-OK-CODE-IN-TIME",
    title="Код в срок: негодный пароль называет поле и код не тратит; годный — сессия выдана, прежняя отозвана",
    classes=["CRUD", "SEC", "VAL"],
    priority="P0",
    steps=[
        *_person(_P03, "in-time"),
        # Положительный контроль отзыва ниже: сессия личности жива ДО завершения.
        _session_probe(_P03, "in-time-session-alive-before", "SessionCookie", alive=True),
        *_recovery_code(_P03, "in-time"),
        _csrf_step(_P03, "in-time-csrf-complete", "recovery-complete"),
        # Негодный пароль (короче объявленной длины) — отказ правила с именем поля;
        # код при этом не тратится: следующий шаг предъявляет ТОТ ЖЕ код.
        _complete(_P03, "in-time-complete-weak-password", password_literal="Short7x",
                  test_script=_refused(400, 3, "Illegal argument newPassword: shorter than the declared minimum length",
                                       "IN-TIME-WEAK")),
        _complete(_P03, "in-time-complete", test_script=_issued(_P03, "IN-TIME-COMPLETE")),
        _session_probe(_P03, "in-time-previous-session", "SessionCookie", alive=False),
        _session_probe(_P03, "in-time-recovered-session", "RecoveredCookie", alive=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф5-05: применённый код второй раз; одновременное предъявление одного кода.
# ───────────────────────────────────────────────────────────────────────────
_P05 = "rcvB"
_PARALLEL = 3
CASES.append(Case(
    id="IAM-RECOVERY-NEG-CODE-SECOND-TIME",
    title="Применённый код второй раз — единый отказ; свежий код, предъявленный одновременно трижды, проходит ровно один раз",
    classes=["NEG", "SEC", "CONC"],
    priority="P0",
    steps=[
        *_person(_P05, "twice"),
        *_recovery_code(_P05, "twice"),
        _csrf_step(_P05, "twice-csrf-complete", "recovery-complete"),
        _complete(_P05, "twice-complete-first", test_script=_issued(_P05, "TWICE-FIRST")),
        _csrf_step(_P05, "twice-csrf-complete-again", "recovery-complete"),
        _complete(_P05, "twice-complete-again", password_var="Password",
                  test_script=_refused(401, 16, _NOT_RESTORED, "TWICE-AGAIN")),
        *_recovery_code(_P05, "twice-fresh"),
        # Предмет шага — не его собственный запрос (признак формы), а три
        # одновременных предъявления свежего кода из его тест-скрипта: решение
        # принимает один оператор базы, и проходит ровно одно.
        Step(
            name="twice-parallel-complete", method="GET", path=f"{_CSRF}?form=recovery-complete",
            pre_script=[*require_env_url("loginLaneBaseUrl", f"{_CSRF}?form=recovery-complete", _LANE_WHY),
                        *_src_pre(_P05), *_with_cookies(("kaname_form", _v(_P05, "FormCookie")))],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, "TWICE-PARALLEL: признак формы"),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                "const __base = pm.environment.get('loginLaneBaseUrl');",
                "const __got = [];",
                f"const __done = () => {{ if (__got.length !== {_PARALLEL}) {{ return; }}",
                "  const ok = __got.filter(r => r.code === 200).length;",
                f"  const refused = __got.filter(r => r.code === 401 && r.message === {js_str(_NOT_RESTORED)}).length;",
                f"  pm.test({js_str(f'TWICE-PARALLEL: ровно одно из {_PARALLEL} одновременных предъявлений проходит')}, () => pm.expect(ok).to.eql(1));",
                f"  pm.test('TWICE-PARALLEL: остальные получают единый отказ 401', () => pm.expect(refused).to.eql({_PARALLEL - 1}));",
                "};",
                f"for (let __i = 0; __i < {_PARALLEL}; __i++) {{",
                "  pm.sendRequest({",
                f"    url: __base + {js_str(_COMPLETE)}, method: 'POST',",
                "    header: {'Content-Type': 'application/json',",
                f"      'X-Forwarded-For': pm.environment.get({js_str(_v(_P05, 'Src'))}) || '',",
                f"      'Cookie': 'kaname_form=' + (pm.environment.get({js_str(_v(_P05, 'FormCookie'))}) || '')}},",
                "    body: {mode: 'raw', raw: JSON.stringify({",
                f"      email: pm.environment.get({js_str(_v(_P05, 'Email'))}),",
                f"      code: pm.environment.get({js_str(_v(_P05, 'MailCode'))}),",
                f"      newPassword: pm.environment.get({js_str(_v(_P05, 'NewPassword'))}) + '-' + __i,",
                "      csrfToken: __j.csrfToken})},",
                "  }, (err, res) => {",
                "    let m = ''; try { m = res ? res.json().message : ''; } catch (e) { m = ''; }",
                "    __got.push({code: err ? 0 : res.code, message: m});",
                "    __done();",
                "  });",
                "}",
            ],
        ),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф5-08: отказ по частоте. Величину N полоса называет сама: адрес, которого
# нет, получает неверные коды до первого 429, и число 401 перед ним и есть N.
# ───────────────────────────────────────────────────────────────────────────
_P08N, _P08H, _P08C = "rcvN", "rcvH", "rcvC"


def _wrong_until_limit(p, name):
    """Неверный код до первого отказа по частоте; число 401 перед ним — N."""
    counter, started = f"_lim_{p}".replace("-", "_"), f"_lims_{p}".replace("-", "_")
    label = name.upper()
    step = _complete(p, name, code_var="ForeignCode", test_script=[
        f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
        f"if (pm.response.code === 401 && __n < {_LIMIT_PROBE_CAP}) {{",
        f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
        "  const _lpd = Date.now(); while (Date.now() - _lpd < 50) { /* pace between presentations */ }",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        f"pm.environment.unset({js_str(counter)});",
        f"pm.environment.unset({js_str(started)});",
        f"pm.test({js_str(label + ': серия неверных кодов упёрлась в отказ по частоте, а не в предел петли')}, () => "
        "pm.expect(pm.response.code).to.eql(429));",
        f"pm.test({js_str(label + ': величина N не меньше двух (иначе близнец N−1 не строится)')}, () => pm.expect(__n >= 2).to.eql(true));",
        "pm.environment.set('rcvLimitN', String(__n));",
        "pm.environment.set('rcvLimitRefusal', pm.response.text());",
    ])
    step.pre_script = [
        f"pm.environment.set({js_str(_v(p, 'ForeignCode'))}, {js_str(_FOREIGN_CODE)});",
        f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
        f"  pm.environment.set({js_str(counter)}, '0');",
        f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
        "}",
        *step.pre_script,
    ]
    return step


def _wrong_times(p, name, times_expr):
    """Ровно `times_expr` неверных кодов подряд; каждый обязан получить 401."""
    counter, started, bad = (f"_wt_{p}_{name}".replace("-", "_"), f"_wts_{p}_{name}".replace("-", "_"),
                             f"_wtb_{p}_{name}".replace("-", "_"))
    label = name.upper()
    step = _complete(p, name, code_var="ForeignCode", test_script=[
        f"const __i = parseInt(pm.environment.get({js_str(counter)}) || '0', 10) + 1;",
        f"const __bad = parseInt(pm.environment.get({js_str(bad)}) || '0', 10) + (pm.response.code === 401 ? 0 : 1);",
        f"pm.environment.set({js_str(bad)}, String(__bad));",
        f"if (__i < ({times_expr})) {{",
        f"  pm.environment.set({js_str(counter)}, String(__i));",
        "  const _wtd = Date.now(); while (Date.now() - _wtd < 50) { /* pace between presentations */ }",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        f"pm.environment.unset({js_str(counter)});",
        f"pm.environment.unset({js_str(started)});",
        f"pm.environment.unset({js_str(bad)});",
        f"pm.test({js_str(label + ': серия исполнена полностью')}, () => pm.expect(__i).to.eql({times_expr}));",
        f"pm.test({js_str(label + ': каждое неверное предъявление серии — единый отказ 401')}, () => pm.expect(__bad).to.eql(0));",
    ])
    step.pre_script = [
        f"pm.environment.set({js_str(_v(p, 'ForeignCode'))}, {js_str(_FOREIGN_CODE)});",
        f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
        f"  pm.environment.set({js_str(counter)}, '0');",
        f"  pm.environment.set({js_str(bad)}, '0');",
        f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
        "}",
        *step.pre_script,
    ]
    return step


_LIMIT_N = "parseInt(pm.environment.get('rcvLimitN') || '0', 10)"

CASES.append(Case(
    id="IAM-RECOVERY-NEG-RATE-LIMIT",
    title="N неверных кодов — следующий (верный) получает отказ по частоте, равный отказу адреса, которого нет; N−1 — верный код принимается",
    classes=["NEG", "SEC", "BVA"],
    priority="P0",
    steps=[
        # Адрес, которого нет: неверные коды до первого 429 — N называет полоса.
        _csrf_step(_P08N, "limit-nobody-csrf", "recovery-complete",
                   init=_person_init(_P08N, "limit-nobody")),
        _wrong_until_limit(_P08N, "limit-nobody-until-refused"),
        # Человек с кодом: ровно N неверных — 401 каждый; верный следом — 429.
        *_person(_P08H, "limit-over"),
        *_recovery_code(_P08H, "limit-over"),
        _csrf_step(_P08H, "limit-over-csrf-complete", "recovery-complete"),
        _wrong_times(_P08H, "limit-over-wrong-n", _LIMIT_N),
        _complete(_P08H, "limit-over-right-code", test_script=[
            *_refused(429, 8, "too many attempts; try again later", "LIMIT-OVER"),
            "pm.test('LIMIT-OVER: причина — TOO_MANY_ATTEMPTS', () => pm.expect(((__r.details || [])[0] || {}).reason).to.eql('TOO_MANY_ATTEMPTS'));",
            "pm.test('LIMIT-OVER: Retry-After — положительное число секунд', () => pm.expect(parseInt(pm.response.headers.get('Retry-After') || '0', 10) > 0).to.eql(true));",
            "pm.test('LIMIT-OVER: отказ побайтово равен отказу адреса, которого нет (существование не раскрыто)', () => "
            "pm.expect(pm.response.text() === pm.environment.get('rcvLimitRefusal')).to.eql(true));",
        ]),
        # Близнец: N−1 неверных — верный код принимается (Ф5-03 в пределах величины).
        *_person(_P08C, "limit-under"),
        *_recovery_code(_P08C, "limit-under"),
        _csrf_step(_P08C, "limit-under-csrf-complete", "recovery-complete"),
        _wrong_times(_P08C, "limit-under-wrong-n-minus-1", _LIMIT_N + " - 1"),
        _complete(_P08C, "limit-under-right-code", test_script=_issued(_P08C, "LIMIT-UNDER")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф5-18: незаблокированная входит новым паролем; прежний — единый отказ.
# ───────────────────────────────────────────────────────────────────────────
_P18 = "rcvD"
CASES.append(Case(
    id="IAM-RECOVERY-OK-NEW-PASSWORD-SIGNS-IN",
    title="После завершения восстановления человек входит новым паролем; прежним — единый отказ",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_person(_P18, "signs-in"),
        *_recovery_code(_P18, "signs-in"),
        _csrf_step(_P18, "signs-in-csrf-complete", "recovery-complete"),
        _complete(_P18, "signs-in-complete", test_script=_issued(_P18, "SIGNS-IN-COMPLETE")),
        *_login(_P18, "signs-in-login-new-password", "NewPassword", ok=True),
        *_login(_P18, "signs-in-login-old-password", "Password", ok=False),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф5-19: отсечка гасит ВСЕ прежние сессии, включая ту, из которой запрошено.
# ───────────────────────────────────────────────────────────────────────────
_P19 = "rcvE"
CASES.append(Case(
    id="IAM-RECOVERY-OK-ENDS-EVERY-SESSION",
    title="Две живые сессии, восстановление запрошено из первой: после завершения обе негодны, выданная завершением годна",
    classes=["SEC", "STATE"],
    priority="P0",
    steps=[
        *_person(_P19, "every-session"),
        *_login(_P19, "every-session-login-first", "Password", ok=True, store="FirstCookie"),
        *_login(_P19, "every-session-login-second", "Password", ok=True, store="SecondCookie"),
        # Положительный контроль: обе сессии живы ДО завершения.
        _session_probe(_P19, "every-session-first-alive", "FirstCookie", alive=True),
        _session_probe(_P19, "every-session-second-alive", "SecondCookie", alive=True),
        *_recovery_code(_P19, "every-session", from_session="FirstCookie"),
        _csrf_step(_P19, "every-session-csrf-complete", "recovery-complete"),
        _complete(_P19, "every-session-complete", test_script=_issued(_P19, "EVERY-SESSION-COMPLETE")),
        _session_probe(_P19, "every-session-first-ended", "FirstCookie", alive=False),
        _session_probe(_P19, "every-session-second-ended", "SecondCookie", alive=False),
        _session_probe(_P19, "every-session-recovered-alive", "RecoveredCookie", alive=True),
    ],
))


# ═══════════════════════════════════════════════════════════════════════════
# БЛОКИРОВКА АДМИНИСТРАТОРОМ (Ф5-17, Ф5-25) — kaname#468.
#
# ПРИЁМКА — `docs/engineering/acceptance/recovery-of-access.md`, одобренная
# редакция с отпечатком `17b2d02c…` (запись
# `docs/specs/reviews/recovery-of-access/17b2d02c8bff38378135467750b21e026118c62fd9d8828538c6315b6d4644e3.yaml`,
# APPROVED). Текст сценариев Ф5-17 и Ф5-25 в редакции 9 (`be4dfb5a…`, kaname#608)
# тот же байт в байт; кейсы написаны по нему, а не по коду глаголов.
#
# КТО БЛОКИРУЕТ. `UserService.Block` / `Unblock` спрашивают отношение
# `identity_suspender` — надзор облака — и пол уровня «2». Такого человека заводит
# посев церемонии стенда чарта (`seed_ceremony.py`, kaname#468): свой человек с
# `system_admin` на кластере и заведённым вторым фактором; в окружение уезжают
# его адрес, пароль и секрет фактора. Предъявителя кейс куёт сам — вход паролем
# со вторым фактором (сессия «2») → код авторизации → обмен, — и предъявляет его
# собственному публичному фронту, где живут глаголы блокировки и опрос операций.
# Пустой ключ посева — «условие не создано» помеченным утверждением.
#
# Техники: переходы состояния личности (действующая → заблокирована → снова
# действующая) с исходом каждого перехода, прочитанным из операции; таблица
# решений Ф5-25 по двум входам (второй фактор заведён · личность заблокирована) с
# близнецом (б), отличающимся от (а) и (в) одним фактом; граница счёта по адресу
# (`N_адрес − 1` неверных → завершение → первая и вторая попытки после).
# ═══════════════════════════════════════════════════════════════════════════

_OWN_WHY = ("собственный публичный фронт службы: глаголы блокировки и опрос операций; "
            "адрес пишет посев церемонии стенда посадки `own`")
_ISSUANCE_WHY = ("поверхность выдачи службы: точка авторизации и обмен кода на токен; "
                 "адрес пишет посев церемонии стенда посадки `own`")
_AUTHORIZE = "/iam/v1/authorize"
_TOKEN = "/iam/v1/token"
_SECOND_FACTOR_ENROLL = "/iam/v1/auth/second-factor/enroll"
_SECOND_FACTOR_CONFIRM = "/iam/v1/auth/second-factor/confirm"
_SUPERVISOR_KEYS = ("cloudSupervisorEmail", "cloudSupervisorPassword", "cloudSupervisorTotpSecret")
_SUPERVISOR_WHY = ("надзор облака стенда (`identity_suspender` уровнем «2») — его адрес, пароль и "
                   "секрет фактора пишет посев церемонии стенда чарта (`stand-chart.sh "
                   "seed-ceremony`); без них блокировать личность кейсу нечем")
# Предел опроса операции и пауза между опросами (мс): операция блокировки — одна
# запись строки личности; предел покрывает загруженный раннер с запасом.
_OP_POLL_CAP = 60
_OP_POLL_MS = 500

# Код по времени в песочнице прогонщика: base32 → HMAC-SHA1 (crypto-js) →
# динамическое усечение → шесть цифр (RFC 6238). Ступень — свежее последней
# принятой: повторно предъявленную ступень служба отвергает (Ф12-15), а оба кейса
# блокировки входят одним надзором.
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
    "const __stepNow = () => Math.floor(Date.now() / 1000 / 30);",
]


def _require_supervisor():
    """Ключи надзора облака заданы посевом — иначе третий исход, а не красное."""
    missing = " || ".join(f"!pm.environment.get({js_str(k)})" for k in _SUPERVISOR_KEYS)
    return [
        f"if ({missing}) {{",
        *precondition_not_met("посев стенда: " + ", ".join(_SUPERVISOR_KEYS) + " заданы",
                              _SUPERVISOR_WHY, indent="  "),
        "}",
    ]


def _supervisor_bearer(s, tag):
    """Предъявитель надзора облака уровнем «2»: вход со вторым фактором → код → обмен."""
    up = tag.upper()
    login_label = f"{up}-LOGIN"
    authorize_label, exchange_label = f"{up}-AUTHORIZE", f"{up}-EXCHANGE"
    query = _v(s, "Query")
    return [
        _csrf_step(s, f"{tag}-csrf-login", "login", init=[
            *_require_supervisor(),
            f"pm.environment.set({js_str(_v(s, 'Src'))}, '198.18.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
            *(f"pm.environment.unset({js_str(_v(s, n))});" for n in (
                "FormCookie", "SessionCookie", "Csrf", "OauthCode", "Token", "Verifier", "State")),
        ]),
        Step(
            name=f"{tag}-login", method="POST", path=_LOGIN,
            body={"email": "{{cloudSupervisorEmail}}", "password": "{{cloudSupervisorPassword}}",
                  "secondFactor": {"method": "totp", "code": f"{{{{{_v(s, 'TotpCode')}}}}}"},
                  "csrfToken": f"{{{{{_v(s, 'Csrf')}}}}}"},
            pre_script=[
                *_require_supervisor(),
                *_TOTP_JS,
                "const __last = parseInt(pm.environment.get('rcvSupervisorLastStep') || '0', 10);",
                "let __step = __stepNow();",
                # Ступень, уже принятая службой, второй раз не проходит: ждём
                # следующую — настоящей паузой, не дольше одной ступени.
                "if (__step <= __last) {",
                "  const _tw = Date.now(); while (__stepNow() <= __last && Date.now() - _tw < 31000) { /* wait for the next TOTP step */ }",
                "  __step = __stepNow();",
                "}",
                f"pm.environment.set({js_str(_v(s, 'TotpStep'))}, String(__step));",
                f"pm.environment.set({js_str(_v(s, 'TotpCode'))}, __totp(pm.environment.get('cloudSupervisorTotpSecret'), __step));",
                *require_env_url("loginLaneBaseUrl", _LOGIN, _LANE_WHY), *_src_pre(s),
                *_with_cookies(("kaname_form", _v(s, "FormCookie"))),
            ],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, login_label),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"pm.test({js_str(login_label + ': сессия уровня «2» — вход со вторым фактором')}, () => "
                "pm.expect(__j.session && __j.session.assuranceLevel).to.eql('2'));",
                f"if (pm.response.code === 200) {{ pm.environment.set('rcvSupervisorLastStep', pm.environment.get({js_str(_v(s, 'TotpStep'))})); }}",
                *_capture(s, "kaname_session", "SessionCookie", login_label),
            ],
        ),
        Step(
            name=f"{tag}-authorize", method="GET", path=_AUTHORIZE + "?{{" + query + "}}",
            pre_script=[
                "if (!pm.environment.get('oauthClientId') || !pm.environment.get('oauthClientSecret') || !pm.environment.get('oauthRedirectUri')) {",
                *precondition_not_met(
                    "посев стенда: oauthClientId, oauthClientSecret, oauthRedirectUri заданы",
                    "посев церемонии стенда посадки own (`stand-chart.sh seed-ceremony`) не завёл "
                    "конфиденциального клиента — выковать предъявитель надзора нечем", indent="  "),
                "}",
                "const __b64u = (wa) => { let x = CryptoJS.enc.Base64.stringify(wa).split('+').join('-')"
                ".split('/').join('_'); while (x.endsWith('=')) { x = x.slice(0, -1); } return x; };",
                "const __ver = __b64u(CryptoJS.lib.WordArray.random(32));",
                "const __st = __b64u(CryptoJS.lib.WordArray.random(32));",
                f"pm.environment.set({js_str(_v(s, 'Verifier'))}, __ver);",
                f"pm.environment.set({js_str(_v(s, 'State'))}, __st);",
                "const __q = [['response_type', 'code'], ['client_id', pm.environment.get('oauthClientId')],",
                "  ['redirect_uri', pm.environment.get('oauthRedirectUri')], ['scope', 'openid'], ['state', __st],",
                "  ['code_challenge', __b64u(CryptoJS.SHA256(__ver))], ['code_challenge_method', 'S256']]",
                "  .map((kv) => encodeURIComponent(kv[0]) + '=' + encodeURIComponent(kv[1])).join('&');",
                f"pm.environment.set({js_str(query)}, __q);",
                *require_env_url("iamRegistryTokenBaseUrl", _AUTHORIZE + "?{{" + query + "}}", _ISSUANCE_WHY),
                f"if (!pm.environment.get({js_str(_v(s, 'SessionCookie'))})) {{",
                *report_then_skip(f"{authorize_label}: сессия надзора не захвачена входом",
                                  "вход выше не выдал kaname_session — точке авторизации нечего "
                                  "предъявить; причина — в шаге входа, не здесь", indent="  "),
                "} else {",
                f"  pm.request.headers.upsert({{key: 'Cookie', value: 'kaname_session=' + pm.environment.get({js_str(_v(s, 'SessionCookie'))})}});",
                "}",
            ],
            insecure_tls=True, auth="anonymous", cookie_jar=False, follow_redirects=False,
            test_script=[
                *_status_is(302, authorize_label),
                "const __loc = String(pm.response.headers.get('Location') || '');",
                "const __qs = {}; (__loc.split('?')[1] || '').split('#')[0].split('&').forEach((kv) => { const i = kv.indexOf('=');",
                "  if (i > 0) { __qs[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1)); } });",
                f"pm.test({js_str(authorize_label + ': перенаправление несёт код и state запроса')}, () => "
                f"pm.expect([typeof __qs.code === 'string' && __qs.code.length > 0, __qs.state === pm.environment.get({js_str(_v(s, 'State'))})]).to.eql([true, true]));",
                f"if (__qs.code) {{ pm.environment.set({js_str(_v(s, 'OauthCode'))}, __qs.code); }}",
            ],
        ),
        Step(
            name=f"{tag}-exchange", method="POST", path=_TOKEN,
            form=[("grant_type", "authorization_code"), ("code", "{{_rcvFCode}}"),
                  ("redirect_uri", "{{_rcvFRedirect}}"), ("code_verifier", "{{_rcvFVerifier}}")],
            pre_script=[
                f"if (!pm.environment.get({js_str(_v(s, 'OauthCode'))})) {{",
                *report_then_skip(f"{exchange_label}: код не выдан точкой авторизации",
                                  "шаг авторизации выше не выдал code — обменивать нечего; "
                                  "причина — в нём, не здесь", indent="  "),
                "}",
                f"pm.variables.set('_rcvFCode', encodeURIComponent(pm.environment.get({js_str(_v(s, 'OauthCode'))}) || ''));",
                "pm.variables.set('_rcvFRedirect', encodeURIComponent(pm.environment.get('oauthRedirectUri') || ''));",
                f"pm.variables.set('_rcvFVerifier', encodeURIComponent(pm.environment.get({js_str(_v(s, 'Verifier'))}) || ''));",
                *require_env_url("iamRegistryTokenBaseUrl", _TOKEN, _ISSUANCE_WHY),
                "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' + "
                "CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
                "  encodeURIComponent(pm.environment.get('oauthClientId') || '') + ':' + "
                "encodeURIComponent(pm.environment.get('oauthClientSecret') || '')))});",
            ],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                f"pm.environment.unset({js_str(_v(s, 'Token'))});",
                *_status_is(200, exchange_label),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"pm.test({js_str(exchange_label + ': выдан токен доступа надзора')}, () => "
                "pm.expect(typeof __j.access_token === 'string' && __j.access_token.length > 0).to.eql(true));",
                f"if (__j.access_token) {{ pm.environment.set({js_str(_v(s, 'Token'))}, __j.access_token); }}",
            ],
        ),
    ]


def _admin_verb(s, p, name, verb):
    """`:block` / `:unblock` личности `p` предъявителем надзора `s`; id операции — в `<p><Verb>Op`."""
    label = name.upper()
    op = _v(p, verb.capitalize() + "Op")
    path = f"/iam/v1/users/{{{{{_v(p, 'UserId')}}}}}:{verb}"
    return Step(
        name=name, method="POST", path=path, body={}, auth=_v(s, "Token"), insecure_tls=True,
        pre_script=[
            *require_env_url("ownRestBaseUrl", path, _OWN_WHY),
            f"if (!pm.environment.get({js_str(_v(p, 'UserId'))}) || !pm.environment.get({js_str(_v(s, 'Token'))})) {{",
            *report_then_skip(f"{label}: человек либо предъявитель надзора не захвачен",
                              "вход человека не назвал user.id либо обмен не выдал токен надзора — "
                              "путь глагола не собрать; причина — в шаге выше", indent="  "),
            "}",
            f"pm.environment.unset({js_str(op)});",
        ],
        test_script=[
            *_status_is(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(label + ': ответ — операция с id')}, () => "
            "pm.expect(typeof __j.id === 'string' && __j.id.length > 0).to.eql(true));",
            f"if (typeof __j.id === 'string' && __j.id) {{ pm.environment.set({js_str(op)}, __j.id); }}",
        ],
    )


def _admin_op(s, p, name, verb, state):
    """Исход операции `:verb`: `done`, без ошибки, личность `p` в состоянии `state`."""
    label = name.upper()
    op = _v(p, verb.capitalize() + "Op")
    counter, started = f"_rop_{p}_{name}".replace("-", "_"), f"_rops_{p}_{name}".replace("-", "_")
    path = "/operations/{{" + op + "}}"
    return Step(
        name=name, method="GET", path=path, auth=_v(s, "Token"), insecure_tls=True,
        pre_script=[
            *require_env_url("ownRestBaseUrl", path, _OWN_WHY),
            f"if (!pm.environment.get({js_str(op)})) {{",
            *report_then_skip(f"{label}: операция не возвращена шагом выше",
                              "глагол выше отвергнут синхронно либо не вернул id операции — "
                              "опрашивать нечего; причина — в нём, не здесь", indent="  "),
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
            f"  const _opd = Date.now(); while (Date.now() - _opd < {_OP_POLL_MS}) {{ /* inter-poll delay: operation not done yet */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': операция завершена')}, () => pm.expect(__j.done).to.eql(true));",
            f"pm.test({js_str(label + ': операция без ошибки и с ответом')}, () => "
            "pm.expect([!!__j.error, !!__j.response], JSON.stringify(__j.error || {})).to.eql([false, true]));",
            f"pm.test({js_str(label + ': личность — та, что названа, в состоянии ' + state)}, () => "
            f"pm.expect([__j.response && __j.response.id, __j.response && __j.response.inviteStatus])"
            f".to.eql([pm.environment.get({js_str(_v(p, 'UserId'))}), {js_str(state)}]));",
        ],
    )


# ───────────────────────────────────────────────────────────────────────────
# Ф5-17: блокировка НЕ снимается восстановлением.
# ───────────────────────────────────────────────────────────────────────────
_P17, _S17 = "rcvG", "rcvSG"
CASES.append(Case(
    id="IAM-RECOVERY-NEG-BLOCKED-STAYS-BLOCKED",
    title="Ф5-17: заблокированная проходит восстановление — учётные данные сменены, войти нельзя; "
          "снимает блокировку администратор, после чего входит новым паролем, а не прежним",
    classes=["NEG", "SEC", "STATE"],
    priority="P0",
    steps=[
        *_person(_P17, "blocked"),
        *_login(_P17, "blocked-login-before-block", "Password", ok=True, user_var="UserId"),
        *_supervisor_bearer(_S17, "blocked-supervisor"),
        _admin_verb(_S17, _P17, "blocked-block", "block"),
        _admin_op(_S17, _P17, "blocked-block-op", "block", "BLOCKED"),
        # Блокировка в силе ДО восстановления: прежний (верный) пароль — единый отказ.
        *_login(_P17, "blocked-login-old-refused", "Password", ok=False, keep="rcvBlockedRefusal"),
        *_recovery_code(_P17, "blocked"),
        _csrf_step(_P17, "blocked-csrf-complete", "recovery-complete"),
        # Ф1-59 по свойству (Ф5 Р10 п. 2, Д22): учётные данные сменяются, сессии
        # нет; ответ — отказ ЗАВЕРШЕНИЯ, побайтово равный отказу завершения на
        # неверном коде: блокировка неотличима от прочих причин этого глагола.
        # Отказ входа до и после — прежний (`rcvBlockedRefusal` ниже).
        _complete(_P17, "blocked-complete", test_script=[
            *_refused(401, 16, _NOT_RESTORED, "BLOCKED-COMPLETE"),
            "pm.test('BLOCKED-COMPLETE: отказ побайтово равен отказу завершения на неверном коде', () => "
            "pm.expect(pm.response.text() === pm.environment.get('rcvCompletionRefusal')).to.eql(true));",
        ]),
        # Главное «Тогда»: войти по-прежнему нельзя — и новым паролем тоже.
        *_login(_P17, "blocked-login-new-refused", "NewPassword", ok=False, same_as="rcvBlockedRefusal"),
        # Близнец: снимает администратор. После снятия новый пароль входит, а
        # прежний — нет: значит, восстановление сменило учётные данные, пока
        # личность была заблокирована, а не просто отказало.
        _admin_verb(_S17, _P17, "blocked-unblock", "unblock"),
        _admin_op(_S17, _P17, "blocked-unblock-op", "unblock", "ACTIVE"),
        *_login(_P17, "blocked-login-new-after-unblock", "NewPassword", ok=True),
        *_login(_P17, "blocked-login-old-after-unblock", "Password", ok=False),
    ],
))


# ───────────────────────────────────────────────────────────────────────────
# Ф5-25: завершение обнуляет счёт по адресу только как вход, завершённый до
# уровня всех заведённых факторов. Величины — из профиля посадки, который стенд
# `chart-own` ставит как есть (`deploy/values.prod.yaml`, узел `authn.login`).
# ───────────────────────────────────────────────────────────────────────────
import pathlib as _rl_pathlib  # noqa: E402
import re as _rl_re  # noqa: E402

_RL_PROFILE = _rl_pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _rl_profile(key):
    found = _rl_re.findall(rf"^    {key}: (\S+)\s*$", _RL_PROFILE.read_text(encoding="utf-8"), _rl_re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-recovery-lane: ключ профиля authn.login.{key} найден "
                         f"{len(found)} раз в {_RL_PROFILE} — ждали ровно один")
    return found[0]


_N_ADDR = int(_rl_profile("addressAttempts"))
_N_SRC = int(_rl_profile("sourceAttempts"))
_T_ADDR = _rl_profile("addressWindow")
_T_SRC = _rl_profile("sourceWindow")
# «Дано» Ф5-25: `N_адрес ≥ 2` и `N_источник > N_адрес + 1`. Профиль, где это не так,
# сценария не строит — генерация отказывает с именем условия, а не зеленеет.
if _N_ADDR < 2:
    raise SystemExit("kaname-recovery-lane: addressAttempts < 2 — серия N_адрес − 1 и две попытки "
                     "после завершения (Ф5-25) не строятся")
if not _N_SRC > _N_ADDR + 1:
    raise SystemExit("kaname-recovery-lane: sourceAttempts ≤ addressAttempts + 1 — отказ по "
                     "источнику наступил бы раньше отказа по адресу (Ф5-25)")

_WRONG_PASSWORD = "Wrong-{{runId}}-not-the-password"
_TOO_MANY = "too many attempts; try again later"


def _wrong_logins(p, name, times):
    """Ровно `times` неверных паролей на входе подряд; каждый — единый отказ 401."""
    counter, started, bad = (f"_wl_{p}_{name}".replace("-", "_"), f"_wls_{p}_{name}".replace("-", "_"),
                             f"_wlb_{p}_{name}".replace("-", "_"))
    label = name.upper()
    step = _post(p, name, _LOGIN,
                 {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": _WRONG_PASSWORD,
                  "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
                 test_script=[
                     f"const __i = parseInt(pm.environment.get({js_str(counter)}) || '0', 10) + 1;",
                     f"const __bad = parseInt(pm.environment.get({js_str(bad)}) || '0', 10) + (pm.response.code === 401 ? 0 : 1);",
                     f"pm.environment.set({js_str(bad)}, String(__bad));",
                     f"if (__i < {times}) {{",
                     f"  pm.environment.set({js_str(counter)}, String(__i));",
                     "  const _wld = Date.now(); while (Date.now() - _wld < 50) { /* pace between presentations */ }",
                     "  pm.execution.setNextRequest(pm.info.requestName);",
                     "  return;",
                     "}",
                     f"pm.environment.unset({js_str(counter)});",
                     f"pm.environment.unset({js_str(started)});",
                     f"pm.environment.unset({js_str(bad)});",
                     f"pm.test({js_str(label + f': серия исполнена полностью — {times} неверных')}, () => pm.expect(__i).to.eql({times}));",
                     f"pm.test({js_str(label + ': каждое неверное предъявление серии — единый отказ 401')}, () => pm.expect(__bad).to.eql(0));",
                 ])
    step.pre_script = [
        f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
        f"  pm.environment.set({js_str(counter)}, '0');",
        f"  pm.environment.set({js_str(bad)}, '0');",
        f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
        "}",
        *step.pre_script,
    ]
    return step


def _wrong_login(p, name, *, limited):
    """Одна попытка неверным паролем: 401 единым отказом либо 429 формы Ф3-28."""
    label = name.upper()
    if limited:
        test = [
            *_refused(429, 8, _TOO_MANY, label),
            f"pm.test({js_str(label + ': причина — TOO_MANY_ATTEMPTS')}, () => "
            "pm.expect((Array.isArray(__r.details) ? __r.details : []).map(d => d.reason)).to.include('TOO_MANY_ATTEMPTS'));",
            f"pm.test({js_str(label + ': Retry-After — положительное число секунд')}, () => "
            "pm.expect(parseInt(pm.response.headers.get('Retry-After') || '0', 10) > 0).to.eql(true));",
        ]
    else:
        test = _refused(401, 16, "authentication failed", label)
    return _post(p, name, _LOGIN,
                 {"email": f"{{{{{_v(p, 'Email')}}}}}", "password": _WRONG_PASSWORD,
                  "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
                 test_script=test)


def _enroll_second_factor(p, tag):
    """Второй фактор человека `p`: заведение → подтверждение кодом по времени (Ф12)."""
    up = tag.upper()
    return [
        _csrf_step(p, f"{tag}-csrf-second-factor", "second-factor", with_session="SessionCookie"),
        _post(p, f"{tag}-enroll", _SECOND_FACTOR_ENROLL, {"csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
              with_session="SessionCookie",
              test_script=[
                  *_status_is(200, f"{up}-ENROLL"),
                  "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                  f"pm.test({js_str(up + '-ENROLL: секрет выдан')}, () => "
                  "pm.expect(typeof __j.secret === 'string' && __j.secret.length > 0).to.eql(true));",
                  f"if (__j.secret) {{ pm.environment.set({js_str(_v(p, 'TotpSecret'))}, __j.secret); }}",
              ]),
        Step(
            name=f"{tag}-confirm", method="POST", path=_SECOND_FACTOR_CONFIRM,
            body={"code": f"{{{{{_v(p, 'TotpCode')}}}}}", "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
            pre_script=[
                *_TOTP_JS,
                f"pm.environment.set({js_str(_v(p, 'TotpCode'))}, __totp(pm.environment.get({js_str(_v(p, 'TotpSecret'))}), __stepNow()));",
                *require_env_url("loginLaneBaseUrl", _SECOND_FACTOR_CONFIRM, _LANE_WHY), *_src_pre(p),
                *_with_cookies(("kaname_form", _v(p, "FormCookie")), ("kaname_session", _v(p, "SessionCookie"))),
            ],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, f"{up}-CONFIRM"),
                "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                f"pm.test({js_str(up + '-CONFIRM: фактор заведён — сессия уровня «2»')}, () => "
                "pm.expect(__j.session && __j.session.assuranceLevel).to.eql('2'));",
                *_capture(p, "kaname_session", "SessionCookie", f"{up}-CONFIRM", required=False),
            ],
        ),
    ]


_P25A, _P25B, _P25C, _S25 = "rcvLA", "rcvLB", "rcvLC", "rcvSL"
_N_BEFORE = _N_ADDR - 1


def _f5_25_series(p, tag):
    """`N_адрес − 1` неверных паролей на входе в окне `T_адрес` — до завершения."""
    return [_csrf_step(p, f"{tag}-csrf-login", "login"), _wrong_logins(p, f"{tag}-wrong-before", _N_BEFORE)]


CASES.append(Case(
    id="IAM-RECOVERY-OK-COMPLETION-RESETS-AS-FULL-LOGIN",
    title=f"Ф5-25: N_адрес={_N_ADDR}, N_источник={_N_SRC}; после {_N_BEFORE} неверных завершение "
          "обнуляет счёт по адресу только у незаблокированной без второго фактора",
    classes=["SEC", "BVA", "STATE"],
    priority="P0",
    steps=[
        # Величины печатаются утверждением: «Дано» сценария названо числом.
        Step(
            name="rl-profile-csrf", method="GET", path=f"{_CSRF}?form=login",
            pre_script=[*require_env_url("loginLaneBaseUrl", f"{_CSRF}?form=login", _LANE_WHY)],
            insecure_tls=True, auth="anonymous", cookie_jar=False,
            test_script=[
                *_status_is(200, "RL-PROFILE"),
                f"pm.test({js_str(f'RL-PROFILE: профиль — N_адрес={_N_ADDR} за {_T_ADDR}, N_источник={_N_SRC} за {_T_SRC}; N_адрес ≥ 2 и N_источник > N_адрес + 1')}, () => "
                f"pm.expect([{_N_ADDR} >= 2, {_N_SRC} > {_N_ADDR} + 1]).to.eql([true, true]));",
            ],
        ),
        # (а) A — второй фактор заведён: завершение выдаёт сессию, счёт НЕ обнулён.
        *_person(_P25A, "rl-a"),
        *_enroll_second_factor(_P25A, "rl-a"),
        *_recovery_code(_P25A, "rl-a"),
        *_f5_25_series(_P25A, "rl-a"),
        _csrf_step(_P25A, "rl-a-csrf-complete", "recovery-complete"),
        _complete(_P25A, "rl-a-complete", test_script=_issued(_P25A, "RL-A-COMPLETE")),
        _csrf_step(_P25A, "rl-a-csrf-login-after", "login"),
        _wrong_login(_P25A, "rl-a-wrong-after-first", limited=False),
        _wrong_login(_P25A, "rl-a-wrong-after-second", limited=True),
        # (б) B — близнец: второго фактора нет, не заблокирована — счёт обнулён.
        *_person(_P25B, "rl-b"),
        *_recovery_code(_P25B, "rl-b"),
        *_f5_25_series(_P25B, "rl-b"),
        _csrf_step(_P25B, "rl-b-csrf-complete", "recovery-complete"),
        _complete(_P25B, "rl-b-complete", test_script=_issued(_P25B, "RL-B-COMPLETE")),
        _csrf_step(_P25B, "rl-b-csrf-login-after", "login"),
        _wrong_login(_P25B, "rl-b-wrong-after-first", limited=False),
        _wrong_login(_P25B, "rl-b-wrong-after-second", limited=False),
        # (в) C — заблокирована администратором: учётные данные сменены, сессии
        # нет, отказ завершения сосчитан N-й попыткой, счёт не обнулён.
        *_person(_P25C, "rl-c"),
        *_login(_P25C, "rl-c-login-before-block", "Password", ok=True, user_var="UserId"),
        *_supervisor_bearer(_S25, "rl-supervisor"),
        _admin_verb(_S25, _P25C, "rl-c-block", "block"),
        _admin_op(_S25, _P25C, "rl-c-block-op", "block", "BLOCKED"),
        *_recovery_code(_P25C, "rl-c"),
        *_f5_25_series(_P25C, "rl-c"),
        _csrf_step(_P25C, "rl-c-csrf-complete", "recovery-complete"),
        _complete(_P25C, "rl-c-complete", test_script=_refused(401, 16, _NOT_RESTORED, "RL-C-COMPLETE")),
        _csrf_step(_P25C, "rl-c-csrf-login-after", "login"),
        _wrong_login(_P25C, "rl-c-wrong-after-first", limited=True),
        # Уборка: личность C снова действующая — следующий прогон заводит своих,
        # но заблокированная строка не остаётся на стенде.
        _admin_verb(_S25, _P25C, "rl-c-unblock", "unblock"),
        _admin_op(_S25, _P25C, "rl-c-unblock-op", "unblock", "ACTIVE"),
    ],
))


# ═══════════════════════════════════════════════════════════════════════════
# НАБЛЮДАЕМОСТЬ И ЧАСТОТА: Ф5-14, Ф5-26, Ф5-27.
#
# Кейсы читают СЛУШАТЕЛЬ МЕТРИК процесса (`{{standMetricsUrl}}`): клетки счётчика
# исходов запроса кода и возраст головы почтовой очереди. Адрес и величины окон
# (`recoveryLettersPerRecipient` · `recoveryLetterWindow` — N и T окна писем
# адресату; `recoverySourceAttempts` · `recoverySourceWindow` — M и окно
# обращений источника) пишет посев `tests/authz-fixtures/seed_mail_pace.py` из
# карты настроек, которую ЧИТАЕТ процесс: числа не выписаны в кейсе и печатаются
# утверждением. Клетки счётчика процессные и общие на прогон — кейсы набора идут
# по одному, поэтому дельта между двумя чтениями принадлежит запросам кейса; ждёт
# кейс УСЛОВИЯ (дельта достигла), а не времени, и только после этого сравнивает
# дельту с ожидаемым РАВЕНСТВОМ.
# ═══════════════════════════════════════════════════════════════════════════

_METRICS_WHY = ("слушатель метрик процесса службы; адрес пишет посев частоты запроса кода "
                "(`stand-chart.sh seed-stored-value` → `seed_mail_pace.py`) — вне стенда `own` "
                "его нет, и это условие, которого стенд не создал")
_METRICS = "/metrics"
_SERIES_REQ = "kaname_recovery_request_outcomes_total"
_SERIES_AGE = 'kaname_outbox_oldest_pending_age_seconds{table="kaname.invite_mail_outbox"}'
_PACE_KEYS = ("recoveryLettersPerRecipient", "recoveryLetterWindow", "recoverySourceAttempts",
              "recoverySourceWindow")
# Предел ожидания условия на метриках: собиратель возраста очереди сканирует раз в
# 15 с (`cmd/kaname/invite_mail_wiring.go`), повтор отправки — с паузой до 30 с;
# 120 попыток по 1 с покрывают оба с запасом на загруженный раннер.
_METRIC_WAIT_CAP = 120
_METRIC_WAIT_MS = 1000

_METRIC_JS = [
    "const __mtext = pm.response.code === 200 ? pm.response.text() : '';",
    "const __m = (series) => { const ln = __mtext.split('\\n').filter((l) => l.startsWith(series + ' '))[0];",
    "  return ln === undefined ? null : Number(ln.slice(series.length + 1)); };",
    f"const __out = (o) => __m({js_str(_SERIES_REQ)} + '{{outcome=\"' + o + '\"}}');",
    "const __num = (k) => parseInt(pm.environment.get(k) || 'NaN', 10);",
]


def _pace_given():
    """Величины окон посева — иначе третий исход; печатаются числом."""
    cond = " || ".join(f"!pm.environment.get({js_str(k)})" for k in _PACE_KEYS)
    return [
        f"if ({cond}) {{",
        *precondition_not_met("величины окон посадки записаны посевом: " + ", ".join(_PACE_KEYS),
                              "ключи пусты — посев частоты запроса кода (`seed_mail_pace.py`) не "
                              "исполнялся на этом стенде", indent="  "),
        "}",
    ]


def _metrics_step(name, *, until=None, tests=(), pre=()):
    """Чтение слушателя метрик. `until` — JS-условие на `__m`/`__out`: пока ложно,
    шаг повторяется с настоящей паузой до предела; затем исполняются `tests`."""
    counter, started = f"_mt_{name}".replace("-", "_"), f"_mts_{name}".replace("-", "_")
    loop = []
    if until is not None:
        loop = [
            f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
            f"if (!({until}) && __n < {_METRIC_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _mtd = Date.now(); while (Date.now() - _mtd < {_METRIC_WAIT_MS}) {{ /* inter-poll delay: condition on the metrics not reached yet */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
        ]
    return Step(
        name=name, method="GET", path=_METRICS, auth="anonymous", cookie_jar=False, insecure_tls=True,
        pre_script=[
            *pre,
            *require_env_url("standMetricsUrl", _METRICS, _METRICS_WHY),
            f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter)}, '0');",
            f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
        ],
        test_script=[*_METRIC_JS, *loop, *_status_is(200, name.upper()), *tests],
    )


def _keep_outcomes(prefix, outcomes):
    """Запомнить клетки исходов как базу дельты; клетка обязана существовать."""
    out = []
    for o in outcomes:
        out += [
            f"pm.test({js_str(prefix.upper() + ': клетка ' + o + ' публикуется до события кейса')}, () => "
            f"pm.expect(__out({js_str(o)})).to.be.a('number'));",
            f"pm.environment.set({js_str(prefix + '_' + o)}, String(__out({js_str(o)})));",
        ]
    return out


def _delta(prefix, o):
    return f"(__out({js_str(o)}) - __num({js_str(prefix + '_' + o)}))"


def _mailbox_count(p, name, heading, *, at_least=None, exactly=None, email_var=None):
    """Число писем вида `heading` адресату: ждать «не меньше», затем утверждать «ровно»."""
    email = email_var or _v(p, "Email")
    path = f"/codes?to={{{{{email}}}}}&after={_urlparse.quote(heading)}"
    counter, started = f"_mc_{p}_{name}".replace("-", "_"), f"_mcs_{p}_{name}".replace("-", "_")
    label = name.upper()
    lines = [
        "const __num = (k) => parseInt(pm.environment.get(k) || 'NaN', 10);",
        "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
        "const __got = Array.isArray(__codes) ? __codes.filter((c) => typeof c === 'string' && c.length > 0) : [];",
    ]
    if at_least is not None:
        lines += [
            f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
            f"const __want = {at_least};",
            f"if (pm.response.code === 200 && __got.length < __want && __n < {_MAIL_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _mcd = Date.now(); while (Date.now() - _mcd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letters not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            f"pm.test({js_str(label + ': писем дошло не меньше ожидаемого в пределе ожидания')}, () => "
            "pm.expect(__got.length >= __want).to.eql(true));",
            "if (__got.length > 0) {",
            f"  pm.environment.set({js_str(_v(p, 'MailCode'))}, __got[__got.length - 1]);",
            f"  pm.environment.set({js_str(_v(p, 'MailSeenMailCode'))}, String(__got.length));",
            "}",
        ]
    if exactly is not None:
        lines.append(f"pm.test({js_str(label + ': писем ровно столько, сколько окно пропустило')}, () => "
                     f"pm.expect(__got.length).to.eql({exactly}));")
    return Step(
        name=name, method="GET", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[
            *require_env_url("standMailboxUrl", path, _MAILBOX_WHY),
            f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter)}, '0');",
            f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
        ],
        test_script=[*_status_is(200, label), *lines],
    )


def _mailbox_hold(name, verb, tests=()):
    """Задержка приёма приёмника писем стенда: `hold`, `release` либо `state`."""
    path = "/release" if verb == "release" else "/hold"
    return Step(
        name=name, method="GET" if verb == "state" else "POST", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[*require_env_url("standMailboxUrl", path, _MAILBOX_WHY)],
        test_script=[
            *_status_is(200, name.upper()),
            "let __h = {}; try { __h = pm.response.json(); } catch (e) { __h = {}; }",
            *tests,
        ],
    )


def _request_for(p, name, email_expr, src_var, *, times_var=None, keep=None, same_as=None):
    """Запрос кода восстановления для адреса `email_expr` с источника `src_var`.

    `times_var` — повторить столько раз, сколько велит переменная (каждый —
    `200 {nextStep}`, Р10 п. 1); `keep` — запомнить тело последнего; `same_as` — тело побайтово
    равно запомненному."""
    counter, started = f"_rq_{p}_{name}".replace("-", "_"), f"_rqs_{p}_{name}".replace("-", "_")
    label = name.upper()
    test = [
        f"pm.test({js_str(label + ': ответ 200 и тело называет шаг (Р10 п. 1)')}, () => "
        f"pm.expect([pm.response.code, pm.response.text()]).to.eql([200, {js_str(_NEXT_STEP_BODY)}]));",
    ]
    if times_var is not None:
        test = [
            f"const __i = parseInt(pm.environment.get({js_str(counter)}) || '0', 10) + 1;",
            f"const __bad = parseInt(pm.environment.get({js_str(counter + '_bad')}) || '0', 10) + "
            f"((pm.response.code === 200 && pm.response.text() === {js_str(_NEXT_STEP_BODY)}) ? 0 : 1);",
            f"pm.environment.set({js_str(counter + '_bad')}, String(__bad));",
            f"if (__i < parseInt(pm.environment.get({js_str(times_var)}) || '0', 10)) {{",
            f"  pm.environment.set({js_str(counter)}, String(__i));",
            "  const _rqd = Date.now(); while (Date.now() - _rqd < 50) { /* pace between requests of the series */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            f"pm.environment.unset({js_str(counter + '_bad')});",
            f"pm.test({js_str(label + ': серия исполнена полностью')}, () => "
            f"pm.expect(__i).to.eql(parseInt(pm.environment.get({js_str(times_var)}) || '0', 10)));",
            f"pm.test({js_str(label + ': каждый запрос серии — 200 и тело с шагом')}, () => pm.expect(__bad).to.eql(0));",
        ]
    if keep:
        test.append(f"pm.environment.set({js_str(keep)}, pm.response.text());")
    if same_as:
        test.append(f"pm.test({js_str(label + ': тело побайтово равно запомненному ответу')}, () => "
                    f"pm.expect(pm.response.text() === pm.environment.get({js_str(same_as)})).to.eql(true));")
    step = Step(
        name=name, method="POST", path=_RECOVERY,
        body={"email": email_expr, "csrfToken": f"{{{{{_v(p, 'Csrf')}}}}}"},
        pre_script=[
            f"if (pm.environment.get({js_str(started)}) !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(counter)}, '0');",
            f"  pm.environment.set({js_str(counter + '_bad')}, '0');",
            f"  pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
            *require_env_url("loginLaneBaseUrl", _RECOVERY, _LANE_WHY),
            f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: pm.environment.get({js_str(src_var)}) || ''}});",
            *_with_cookies(("kaname_form", _v(p, "FormCookie"))),
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test,
    )
    return step


def _fresh_src(var):
    return [f"pm.environment.set({js_str(var)}, '198.19.' + Math.floor(Math.random() * 256) + '.' "
            "+ (1 + Math.floor(Math.random() * 254)));"]


# ───────────────────────────────────────────────────────────────────────────
# Ф5-14: недоставленное ВИДНО. Приёмник писем стенда задерживает приём (временный
# отказ 4xx — письма кластер не покидают); возраст самого старого неотправленного
# растёт, а после снятия задержки письмо доходит и возраст возвращается к нулю.
# Положительный контроль — ноль ДО задержки и счёт отказов приёмника: служба
# пыталась сдать письмо, а не молчала. Техники: переход состояния очереди
# (пусто → неотправленное → доставлено), граница «ноль / больше нуля», близнец
# по одному факту — задержка.
# ───────────────────────────────────────────────────────────────────────────
_P14 = "rcvU"
CASES.append(Case(
    id="IAM-RECOVERY-OK-UNDELIVERED-AGE-VISIBLE",
    title="Ф5-14: письмо восстановления не покидает кластер — возраст неотправленного растёт; доставка вернулась — письмо дошло, возраст к нулю",
    classes=["SEC", "STATE"],
    priority="P1",
    steps=[
        *_person(_P14, "undelivered"),
        _metrics_step("undelivered-age-zero-before", until=f"__m({js_str(_SERIES_AGE)}) === 0", tests=[
            "pm.test('UNDELIVERED-AGE-ZERO-BEFORE: возраст головы почтовой очереди публикуется и равен нулю до задержки', () => "
            f"pm.expect(__m({js_str(_SERIES_AGE)})).to.eql(0));",
        ]),
        _mailbox_hold("undelivered-hold", "hold", tests=[
            "pm.test('UNDELIVERED-HOLD: приём задержан', () => pm.expect(__h.hold).to.eql(true));",
            "pm.environment.set('rcvURefusedBefore', String(__h.refusedWhileHeld));",
        ]),
        _csrf_step(_P14, "undelivered-csrf-recovery", "recovery"),
        _post(_P14, "undelivered-request-code", _RECOVERY,
              {"email": f"{{{{{_v(_P14, 'Email')}}}}}", "csrfToken": f"{{{{{_v(_P14, 'Csrf')}}}}}"},
              test_script=[*_status_is(200, "UNDELIVERED-REQUEST")]),
        _metrics_step("undelivered-age-grows", until=f"__m({js_str(_SERIES_AGE)}) > 0", tests=[
            "pm.test('UNDELIVERED-AGE: возраст неотправленного стал больше нуля', () => "
            f"pm.expect(__m({js_str(_SERIES_AGE)}) > 0).to.eql(true));",
            f"pm.environment.set('rcvUAgeFirst', String(__m({js_str(_SERIES_AGE)})));",
        ]),
        _metrics_step("undelivered-age-grows-again",
                      until=f"__m({js_str(_SERIES_AGE)}) > Number(pm.environment.get('rcvUAgeFirst'))", tests=[
            "pm.test('UNDELIVERED-AGE-AGAIN: возраст продолжает расти, пока доставки нет', () => "
            f"pm.expect(__m({js_str(_SERIES_AGE)}) > Number(pm.environment.get('rcvUAgeFirst'))).to.eql(true));",
        ]),
        _mailbox_hold("undelivered-hold-state", "state", tests=[
            "pm.test('UNDELIVERED-STATE: служба пыталась сдать письмо и получила временный отказ', () => "
            "pm.expect(__h.refusedWhileHeld > Number(pm.environment.get('rcvURefusedBefore'))).to.eql(true));",
        ]),
        _mailbox_count(_P14, "undelivered-not-delivered", _HEAD_RECOVERY, exactly=0),
        _mailbox_hold("undelivered-release", "release", tests=[
            "pm.test('UNDELIVERED-RELEASE: задержка снята', () => pm.expect(__h.hold).to.eql(false));",
        ]),
        _await_code(_P14, "undelivered-letter-arrives", _HEAD_RECOVERY, "MailCode"),
        _metrics_step("undelivered-age-back-to-zero", until=f"__m({js_str(_SERIES_AGE)}) === 0", tests=[
            "pm.test('UNDELIVERED-AGE-ZERO-AFTER: после доставки возраст вернулся к нулю', () => "
            f"pm.expect(__m({js_str(_SERIES_AGE)})).to.eql(0));",
        ]),
        _csrf_step(_P14, "undelivered-csrf-complete", "recovery-complete"),
        _complete(_P14, "undelivered-complete", test_script=_issued(_P14, "UNDELIVERED-COMPLETE")),
    ],
))


# ───────────────────────────────────────────────────────────────────────────
# Ф5-26: окно писем адресата. N + 1 запросов для P в одном окне — писем ровно N,
# ответ сверхнормативного побайтово равен ответу о Z, клетки recipient-paced +1 и
# queued +N, код N-го письма проходит. Близнецы: (б) Q — письмо поставлено (факт —
# адрес); (в) P′ с окном ПРИГЛАШЕНИЯ, заполненным посевом до N, — N писем
# восстановления (факт — вид заполненного окна). Техники: граница N · N + 1,
# классы эквивалентности адреса и вида окна, угадывание ошибок (вытеснение
# прежнего кода сверхнормативным запросом).
# ───────────────────────────────────────────────────────────────────────────
_P26, _Q26, _PP26 = "rcvPace", "rcvPaceQ", "rcvPaceP2"
CASES.append(Case(
    id="IAM-RECOVERY-NEG-PACED-PER-RECIPIENT",
    title="Ф5-26: N + 1 запросов кода для адреса — писем ровно N, ответ тот же, прежний код жив; окно — у пары «вид письма · адрес»",
    classes=["SEC", "BVA", "NEG"],
    priority="P0",
    steps=[
        *_person(_P26, "pace-p"),
        *_person(_Q26, "pace-q"),
        _metrics_step("pace-baseline", pre=_pace_given(), tests=[
            "const __N = __num('recoveryLettersPerRecipient'), __M = __num('recoverySourceAttempts');",
            "pm.test('PACE-GIVEN: окно писем адресату N=' + __N + ' за ' + pm.environment.get('recoveryLetterWindow') "
            "+ ', окно источника M=' + __M + ' за ' + pm.environment.get('recoverySourceWindow') "
            "+ '; окно источника больше обращений пробы (N + 2)', () => pm.expect([__N >= 1, __M > __N + 2]).to.eql([true, true]));",
            "pm.environment.set('rcvPaceTimes', String(__N + 1));",
            *_keep_outcomes("rcvPace0", ("queued", "recipient-paced")),
        ]),
        _csrf_step(_P26, "pace-csrf-recovery", "recovery", init=_fresh_src("rcvPaceSrc")),
        _request_for(_P26, "pace-p-n-plus-one", f"{{{{{_v(_P26, 'Email')}}}}}", "rcvPaceSrc",
                     times_var="rcvPaceTimes", keep="rcvPaceOverBody"),
        _request_for(_P26, "pace-z-nobody", "nobody-pace-{{runId}}@example.invalid", "rcvPaceSrc",
                     same_as="rcvPaceOverBody"),
        _metrics_step("pace-cells", until=f"{_delta('rcvPace0', 'recipient-paced')} >= 1 && "
                                          f"{_delta('rcvPace0', 'queued')} >= __num('recoveryLettersPerRecipient')",
                      tests=[
            "pm.test('PACE-CELLS: клетка recipient-paced выросла ровно на 1', () => "
            f"pm.expect({_delta('rcvPace0', 'recipient-paced')}).to.eql(1));",
            "pm.test('PACE-CELLS: клетка queued выросла ровно на N', () => "
            f"pm.expect({_delta('rcvPace0', 'queued')}).to.eql(__num('recoveryLettersPerRecipient')));",
        ]),
        _mailbox_count(_P26, "pace-p-letters", _HEAD_RECOVERY, at_least="__num('recoveryLettersPerRecipient')"),
        # (б) Q — тот же источник, та же форма, другой адрес: письмо поставлено.
        _request_for(_P26, "pace-q-same-window", f"{{{{{_v(_Q26, 'Email')}}}}}", "rcvPaceSrc"),
        _await_code(_Q26, "pace-q-letter", _HEAD_RECOVERY, "MailCode"),
        # Письмо Q дошло — поставленное до него письмо P дошло бы тоже: писем P ровно N.
        _mailbox_count(_P26, "pace-p-letters-exactly", _HEAD_RECOVERY,
                       exactly="__num('recoveryLettersPerRecipient')"),
        _metrics_step("pace-cells-after-q", until=f"{_delta('rcvPace0', 'queued')} >= "
                                                 "__num('recoveryLettersPerRecipient') + 1", tests=[
            "pm.test('PACE-CELLS-Q: письмо Q поставлено — queued выросла ещё на 1, recipient-paced не выросла', () => "
            f"pm.expect([{_delta('rcvPace0', 'queued')}, {_delta('rcvPace0', 'recipient-paced')}])"
            ".to.eql([__num('recoveryLettersPerRecipient') + 1, 1]));",
        ]),
        # Код N-го письма проходит: сверхнормативный запрос прежнего кода не вытеснил.
        _csrf_step(_P26, "pace-csrf-complete", "recovery-complete"),
        _complete(_P26, "pace-complete-nth-code", test_script=_issued(_P26, "PACE-NTH-CODE")),
        # (в) P′ — окно писем ПРИГЛАШЕНИЯ заполнено посевом до N: N запросов кода —
        # N писем восстановления, recipient-paced не растёт.
        _metrics_step("pace-invite-full-baseline", tests=[
            "pm.test('PACE-INVITE-FULL-GIVEN: адресат P′ с заполненным окном приглашения положен посевом', () => "
            "pm.expect(!!pm.environment.get('paceInviteFullEmail')).to.eql(true));",
            "pm.environment.set('rcvPaceTimesN', String(__num('recoveryLettersPerRecipient')));",
            *_keep_outcomes("rcvPace1", ("queued", "recipient-paced")),
        ]),
        _csrf_step(_PP26, "pace-invite-full-csrf", "recovery", init=_fresh_src(_v(_PP26, "Src"))),
        _request_for(_PP26, "pace-invite-full-n", "{{paceInviteFullEmail}}", _v(_PP26, "Src"),
                     times_var="rcvPaceTimesN"),
        _metrics_step("pace-invite-full-cells", until=f"{_delta('rcvPace1', 'queued')} >= "
                                                     "__num('recoveryLettersPerRecipient')", tests=[
            "pm.test('PACE-INVITE-FULL: N писем восстановления поставлено, recipient-paced не выросла — окно у пары вид · адрес', () => "
            f"pm.expect([{_delta('rcvPace1', 'queued')}, {_delta('rcvPace1', 'recipient-paced')}])"
            ".to.eql([__num('recoveryLettersPerRecipient'), 0]));",
        ]),
        _mailbox_count(_PP26, "pace-invite-full-letters", _HEAD_RECOVERY,
                       at_least="__num('recoveryLettersPerRecipient')", exactly="__num('recoveryLettersPerRecipient')",
                       email_var="paceInviteFullEmail"),
    ],
))


# ───────────────────────────────────────────────────────────────────────────
# Ф5-27: окно обращений источника. M запросов о НЕСУЩЕСТВУЮЩЕМ адресе с источника
# S исчерпывают окно; запрос для P с того же S — тот же ответ, письма нет,
# source-paced +1. Близнец (б): тот же запрос с S′ — письмо поставлено (факт —
# источник). Техники: граница M · M + 1, класс «адреса нет» как исчерпывающий окно
# (окно списывается до чтения адреса), близнец по источнику.
# ───────────────────────────────────────────────────────────────────────────
_P27 = "rcvSrc"
CASES.append(Case(
    id="IAM-RECOVERY-NEG-PACED-PER-SOURCE",
    title="Ф5-27: M запросов о несуществующем адресе с источника — запрос для существующего тот же ответ, письма нет; другой источник — письмо",
    classes=["SEC", "BVA", "NEG"],
    priority="P0",
    steps=[
        *_person(_P27, "src-p"),
        _metrics_step("src-baseline", pre=_pace_given(), tests=[
            "const __N = __num('recoveryLettersPerRecipient'), __M = __num('recoverySourceAttempts');",
            "pm.test('SRC-GIVEN: окно источника M=' + __M + ' за ' + pm.environment.get('recoverySourceWindow') "
            "+ ', окно писем адресату N=' + __N + ' за ' + pm.environment.get('recoveryLetterWindow') "
            "+ ' больше писем пробы одному адресату (1)', () => pm.expect([__M >= 1, __N > 1]).to.eql([true, true]));",
            "pm.environment.set('rcvSrcTimes', String(__M));",
            *_keep_outcomes("rcvSrc0", ("queued", "source-paced", "no-row")),
        ]),
        _csrf_step(_P27, "src-csrf-recovery", "recovery", init=[*_fresh_src("rcvSrcS"), *_fresh_src("rcvSrcS2")]),
        _request_for(_P27, "src-z-m-times", "nobody-src-{{runId}}@example.invalid", "rcvSrcS",
                     times_var="rcvSrcTimes", keep="rcvSrcZBody"),
        _request_for(_P27, "src-p-same-source", f"{{{{{_v(_P27, 'Email')}}}}}", "rcvSrcS", same_as="rcvSrcZBody"),
        _metrics_step("src-cells", until=f"{_delta('rcvSrc0', 'source-paced')} >= 1 && "
                                         f"{_delta('rcvSrc0', 'no-row')} >= __num('recoverySourceAttempts')", tests=[
            "pm.test('SRC-CELLS: source-paced выросла ровно на 1, queued не выросла', () => "
            f"pm.expect([{_delta('rcvSrc0', 'source-paced')}, {_delta('rcvSrc0', 'queued')}]).to.eql([1, 0]));",
            "pm.test('SRC-CELLS: окно исчерпали запросы о несуществующем адресе — no-row выросла ровно на M', () => "
            f"pm.expect({_delta('rcvSrc0', 'no-row')}).to.eql(__num('recoverySourceAttempts')));",
        ]),
        # (б) S′ — другой источник, тот же адрес: письмо поставлено (исход Ф5-01).
        _request_for(_P27, "src-p-other-source", f"{{{{{_v(_P27, 'Email')}}}}}", "rcvSrcS2"),
        _await_code(_P27, "src-p-letter-other-source", _HEAD_RECOVERY, "MailCode"),
        # Письмо с S′ дошло; письма с S не было — писем восстановления у P ровно одно.
        _mailbox_count(_P27, "src-p-letters-exactly", _HEAD_RECOVERY, exactly=1),
        _metrics_step("src-cells-after-other-source", until=f"{_delta('rcvSrc0', 'queued')} >= 1", tests=[
            "pm.test('SRC-CELLS-S2: queued выросла на 1, source-paced осталась +1', () => "
            f"pm.expect([{_delta('rcvSrc0', 'queued')}, {_delta('rcvSrc0', 'source-paced')}]).to.eql([1, 1]));",
        ]),
    ],
))
