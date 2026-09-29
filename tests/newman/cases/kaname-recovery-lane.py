# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set восстановления доступа кодом по почте (Ф5, kacho#1271).

Предмет — два глагола на СОБСТВЕННОМ слушателе формы службы
(`/iam/v1/auth/recovery`, `/iam/v1/auth/recovery/complete`), той же полосы, что
вход (Ф3): поднимается только посадкой `authn.identityProvider: own` и допускает
РОВНО край по SAN клиентского сертификата. Переменные:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`; под `external` не поднят)
  {{loginLaneEmail}}     — почта человека с подтверждённым адресом (посев)
  {{standMailboxUrl}}    — чтение приёмника писем стенда (`stand-mailbox.py`; посев)

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

ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ. Доставку письма за пределы кластера и наблюдаемость
недоставленного (вторая половина Ф1-31, производитель `kacho#1773`); ответ при
недоступном почтовом узле (стенд держит узел поднятым весь прогон); время ответа
двух полос запроса; блокировку администратором (её глаголу нужен распорядитель
повышенного уровня, которого стенд не куёт); состав ответа службы краю о сессии
(глагол внутреннего слушателя без HTTP-привязки). Почему и кто держит каждое —
ведомость долга позиций `.github/scripts/newman-suite-debt.py`.

Coverage:
  IAM-RECOVERY-OK-REQUEST-SAME-ANSWER   — запрос кода для существующего и для
                                          несуществующего адреса отвечает 200 {} побайтово
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
                  f"pm.test({js_str(tag.upper() + '-REQUEST: тело — пустой объект')}, () => "
                  "pm.expect(pm.response.text()).to.eql('{}'));",
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


def _login(p, tag, password_var, *, ok, store=None):
    label = f"{tag.upper()}"
    test = ([*_status_is(200, label),
             "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
             f"pm.test({js_str(label + ': сессия выдана')}, () => "
             "pm.expect(!!(__j.session && __j.session.expiresAt)).to.eql(true));",
             *_capture(p, "kaname_session", store or "LoginCookie", label),
             *_capture(p, "kaname_form", "FormCookie", label, required=False)]
            if ok else _refused(401, 16, "authentication failed", label))
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
                  test_script=_refused(401, 16, "authentication failed", "TWICE-AGAIN")),
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
                "  const refused = __got.filter(r => r.code === 401 && r.message === 'authentication failed').length;",
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
