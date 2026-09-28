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
цифр, шаг 30 с. ПРИНЯТЫЙ ШАГ — У СТРОКИ (Р5): код той же либо младшей ступени,
чем последний принятый, верный продукт отвергает повтором. Поэтому набор держит
последний принятый шаг сам (`sfLastStep` — пишет его шаг, получивший `200`) и
каждый следующий код берёт ступенью `max(последний + 1, текущая)`: она старше
принятого и лежит в окне ±1. Где такой ступени в окне ещё нет, её ЖДУТ — шаг
ожидания опрашивает признак формы с настоящей паузой между опросами и конечным
пределом, пока часы не дойдут до нужной ступени. Это не пауза вместо условия:
условие здесь и есть ступень часов, и её называет приёмка («часы пробы сдвинуты
не меньше чем на одну ступень», §5 преамбула). Первые два кода строки (подтверждение
и вход, Ф12-08) по-прежнему идут без ожидания: ступень `t₀ + 1` в окне сразу.

ПОРЯДОК КЕЙСОВ НЕСУЩИЙ: человек посева один, и каждый кейс стоит на состоянии,
которое оставил предыдущий. Без фактора (отказы «не заведён») → строка `pending`
(заведение не способ) → хребет (замена ожидающего, подтверждение, «уже заведён»,
вход с кодом) → запасные коды (церемония, вход, однократность) → код по времени
в церемонии и повтор → перечеканка → исчерпание → окно ±1 → отказы снятия →
снятие → формы. Последний кейс возвращает посев в исходное: следующий прогон
снова заводит фактор с нуля.

СЧЁТ НЕВЕРНЫХ ПРЕДЪЯВЛЕНИЙ ОБЩИЙ У ВСЕХ КЕЙСОВ, и набор его ведёт. По адресу
человека счёт обнуляет только предъявление, доводящее вход до уровня всех
заведённых факторов (Р7); поэтому между двумя такими успехами неверных не
больше четырёх — ниже величины профиля, и ни один кейс не получает отказа по
частоте, которого не утверждает. По источнику счёт не обнуляется вовсе, и
источник — свой у каждого прогона (`sfSource`): повторный прогон в том же окне
не наследует чужих попыток.

ГДЕ НАБОР ГОНЯЕТСЯ. Задание `chart-own` процесса `e2e-newman.yml` — тем же
вызовом прогонщика, что вход и восстановление, после них: стенд чарта посадки
`own`, лист края и посев человека те же (`stand-chart.sh`, `seed_login_lane.py`).

УТВЕРЖДЕНИЯ НАБОРА НЕ ПОЛУЧАЮТ ЗНАЧЕНИЙ УДОСТОВЕРЕНИЙ (kaname#417). Отчёт прогона
выкладывается артефактом публичного репозитория, а текст упавшего утверждения —
проза: chai печатает в нём сообщение, ПРЕДМЕТ и ОЖИДАЕМОЕ, и срез отчёта
(`.github/scripts/redact-newman-report.py`) на прозе этой полосы слеп — у
запасного кода и кода по времени нет формы. Поэтому ни сообщение, ни предмет, ни
ожидаемое не несут ни тела ответа, ни заголовков, ни переменной с удостоверением:
сообщение — литерал, форма секрета и кодов утверждается булевым предметом,
состав — числом, равенство тел — булевым сравнением. Общие помощники
`assert_status` и `assert_grpc_code` кладут в сообщение тело ответа, и потому
здесь не зовутся: отрицательный шаг `enroll` при дефекте получает тело с
секретом. Разбор падения при этом не теряется — тело ответа лежит в отчёте, и
срез режет в нём удостоверения по имени. Переменные с удостоверением названы так,
как их знает срез: секрет — словом `secret` в имени, код и набор кодов —
последним словом `code`/`codes`, печенье — словом `cookie`. Держит это
`tests/newman/scripts/second_factor_assertion_values_test.py`.

Coverage (техники: классы эквивалентности состояния строки — нет · `pending` ·
`active`; переходы состояний; таблица решений «способ × состояние»; граничные
значения окна ±1; угадывание ошибок — повтор кода, чужая сессия, прежний носитель):
  IAM-2FA-NEG-NOT-ENROLLED-STATE          — Ф12-17 (`B`): церемония кодом и запасным
                                            кодом без фактора — 400
                                            SECOND_FACTOR_NOT_ENROLLED, тела равны;
                                            Ф12-29 (г): снятие — тот же отказ;
                                            Ф12-25 (в, `B`): перечеканка — тот же
                                            отказ
  IAM-2FA-OK-ENROLL-PENDING-IS-NOT-A-METHOD
                                          — Ф12-01: секрет, адрес otpauth с доменом
                                            и адресом человека, срок до секунды и он
                                            же в состоянии; вход с кодом от
                                            ожидающего секрета — 401 побайтово как на
                                            неверный пароль, без кода — «1»; Ф12-17
                                            (`C`), Ф12-29 (д: тело равно «г»,
                                            `pending` не тронута), Ф12-25 (в, `C`);
                                            Ф12-03: неверный код подтверждения — 401
                                            без носителя, `pending` осталась
  IAM-2FA-OK-ENROLL-CONFIRM-LOGIN-LEVEL2  — Ф12-08 цепочка; Ф12-05 (б): второе
                                            заведение при `pending` — новый секрет,
                                            код прежнего — 401; Ф12-02: коды один
                                            раз, сессия «2», носитель перевыпущен,
                                            срок сессии прежний, прежний носитель —
                                            как несуществующая сессия; Ф12-05 (а):
                                            заведение при `active` — 409, строка не
                                            тронута; Ф12-11: вход с кодом — «2»;
                                            Ф12-14: без кода — «1»; повтор — 401
  IAM-2FA-OK-BACKUP-CODE-STEP-UP          — Ф12-18: церемония запасным кодом — «2»,
                                            остаток в ответе; тот же код второй раз
                                            — 401; состояние — остаток на один меньше
  IAM-2FA-OK-LOGIN-WITH-BACKUP-CODE       — Ф12-12: вход паролем и запасным кодом —
                                            «2»; тот же код на следующем входе — 401
                                            тем же телом, что неверный пароль;
                                            остаток на один меньше
  IAM-2FA-OK-BACKUP-CODE-ONCE-EACH        — Ф12-23: №3 — 200, №3 снова — 401, №7 —
                                            200; остаток на два меньше
  IAM-2FA-OK-STEP-UP-TOTP-AND-REPLAY      — Ф12-15: код по времени в сессии «1» —
                                            «2», носитель перевыпущен, срок прежний,
                                            прежний носитель — как несуществующая
                                            сессия; Ф12-22: тот же код и младший —
                                            401, следующий — 200, принятый код из
                                            другой сессии — 401, её носитель годен;
                                            Ф12-16: неверный код в сессии «1» — 401,
                                            носитель прежний и годен
  IAM-2FA-OK-REGENERATE-BACKUP-CODES      — Ф12-25: без кода — 400 с именем поля,
                                            неверный — 401 и набор не тронут, кодом
                                            по времени — десять новых, «2», носитель
                                            перевыпущен; все десять прежних — 401
  IAM-2FA-OK-BACKUP-CODES-EXHAUSTED       — Ф12-26: десятый потреблённый называет
                                            остаток 0; состояние 0 из 10;
                                            одиннадцатый — 401; код по времени — 200
  IAM-2FA-BVA-TOTP-WINDOW                 — Ф12-21: `t−2` и `t+2` — 401 окном,
                                            `t−1`, `t`, `t+1` — 200, в одной сессии, по
                                            возрастанию, `t ≥ t₀ + 3`
  IAM-2FA-NEG-REMOVE-REFUSALS             — Ф12-29 (а, б, в): без кода — 400 с полем,
                                            неверный и повторённый — 401; строки не
                                            сняты, носитель не перевыпущен
  IAM-2FA-OK-REMOVE-BY-CODE               — Ф12-28: снятие кодом по времени — сессия
                                            «2», остаток 0; состояние — не заведён;
                                            вход с кодом после снятия — тот же 401,
                                            что на неверный пароль (Ф12-13 е); без
                                            кода — «1»
  IAM-2FA-NEG-FORMS-AND-STATE             — Ф12-06/Ф12-41: `enroll` с чужим признаком —
                                            403 FORM_TOKEN_REJECTED; `confirm` без кода
                                            — 400 с именем поля; `step-up` с `method`
                                            вне словаря — 400; `confirm` без ожидающего
                                            заведения — 400 ENROLLMENT_NOT_PENDING
                                            (Ф12-04 в)
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — и почему; идентификаторы здесь стоят КОММЕНТАРИЕМ,
# а не строкой: перепись долга (`.github/scripts/newman-suite-debt.py`) считает
# позицию несомой по строковому литералу модуля, и упоминание «не утверждаем»
# строкой зачло бы её набору.
#   · гонки Ф12-07 и Ф12-24 — уровень I, интеграция;
#   · подбор Ф12-31, Ф12-32, Ф12-46 и ответ церемонии на трёх сессиях Ф12-19 — на
#     человеке посева N неверных в одном окне закрыли бы ему адрес на всё окно
#     профиля, и следующий кейс и прогон стали бы красными по частоте; их место —
#     кейсы со своим человеком на прогон, чей код подтверждения набор прочтёт из
#     приёмника писем стенда (запись долга в `newman-suite-debt.py`);
#   · неразличимость по времени Ф12-33 — измерительная, приборы этой формы в
#     дереве — ручка уровня I;
#   · свежесть Ф12-09/10 и истёкшее заведение Ф12-04 (а, б) — окно профиля
#     стенда 15 мин, часов пробы у чёрного ящика нет;
#   · глагол с полом «2» по новому носителю (Ф12-02, Ф12-15) — пол судит край, а
#     края у стенда службы нет; наблюдаемое на полосе — носитель и уровень.

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

# Адрес источника, который на живом проводе ставит край (Р10). Свой у каждого
# прогона: счёт по источнику не обнуляется успехом, и повторный прогон в том же
# окне профиля с общим литералом наследовал бы попытки прошлого.
_SOURCE_JS = [
    "if (!pm.environment.get('sfSource')) {",
    "  pm.environment.set('sfSource', '2001:db8:12::' + (Date.now() % 65536).toString(16));",
    "}",
    "pm.request.headers.upsert({key: 'X-Forwarded-For', value: pm.environment.get('sfSource')});",
]

# Вычисление кода по времени в песочнице прогонщика: base32 (RFC 4648, без
# дополнения) → HMAC-SHA1 (crypto-js) → динамическое усечение → шесть цифр.
# Объявляется в pre-script каждого шага, которому нужен код, — песочница между
# шагами функции не хранит.
_TOTP_JS = [
    "const __totp = (secretB32, step) => {",
    "  const CryptoJS = require('crypto-js');",
    # Алфавит — двумя строками: одной строкой он есть пробег формы секрета, и срез
    # отчёта вырезал бы его из скрипта коллекции как секрет.
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
    # Последний принятый шаг строки — тот, что набор записал на `200`.
    "const __lastStep = () => parseInt(pm.environment.get('sfLastStep') || '0', 10);",
    # Ступень, старше принятой и в окне: младшая из законных.
    "const __freshStep = () => Math.max(__lastStep() + 1, __stepNow());",
    # Код, которого нет ни на одной ступени окна: неверный наверняка, а не с
    # вероятностью трёх миллионных.
    "const __wrongCode = (secretB32) => {",
    "  const now = __stepNow();",
    "  const near = [now - 1, now, now + 1].map(s => __totp(secretB32, s));",
    "  for (let i = 0; i < 1000; i++) { const c = String(i).padStart(6, '0'); if (!near.includes(c)) { return c; } }",
    "  return '999999';",
    "};",
]


def _present_totp(label, secret_var="sfSecret"):
    """Pre-script: код по времени свежей ступени в `sfCode`, ступень — в
    `sfPresentedStep`; ступень обязана лежать в окне (иначе ожидание не сделало
    своего)."""
    return [
        *_TOTP_JS,
        "const __s = __freshStep();",
        "pm.environment.set('sfPresentedStep', String(__s));",
        f"pm.environment.set('sfCode', __totp(pm.environment.get({js_str(secret_var)}), __s));",
        f"pm.test({js_str(label + ': ступень кода старше принятой и в окне ±1')}, () => "
        "pm.expect(__s <= __stepNow() + 1, 'ступень в окне').to.eql(true));",
    ]


# На `200` принятый шаг строки — тот, что предъявлен.
_ACCEPTED_STEP = [
    "if (pm.response.code === 200) { pm.environment.set('sfLastStep', pm.environment.get('sfPresentedStep')); }",
]


def _backup_code(label, index, set_var="sfBackupCodes"):
    """Pre-script: запасной код №`index` набора `set_var` в `sfBackupCode`."""
    return [
        "let __set = [];",
        f"try {{ __set = JSON.parse(pm.environment.get({js_str(set_var)}) || '[]'); }} catch (e) {{ __set = []; }}",
        f"pm.test({js_str(label + ': набор запасных кодов захвачен прежним кейсом')}, () => "
        f"pm.expect(Array.isArray(__set) && __set.length === 10 && typeof __set[{index}] === 'string', 'набор на месте').to.eql(true));",
        f"pm.environment.set('sfBackupCode', Array.isArray(__set) && typeof __set[{index}] === 'string' ? __set[{index}] : '');",
    ]


# Код ответа и код отказа — литеральным сообщением: общий помощник кладёт в
# сообщение тело ответа, а тело этой полосы бывает телом с секретом и кодами.
_OK = ["pm.test('status 200', () => pm.expect(pm.response.code, 'код ответа').to.eql(200));"]


def _status(status):
    return [f"pm.test({js_str(f'status {status}')}, () => pm.expect(pm.response.code, 'код ответа').to.eql({status}));"]


def _grpc_code(code, code_name):
    return [
        f"pm.test({js_str(f'grpc code {code} ({code_name})')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.code, 'код отказа').to.eql({code});",
        "});",
    ]


def _backup_summary(label, remaining):
    """Сводка набора состояния: члены и числа — без значений кодов."""
    return [
        f"pm.test({js_str(label)}, () => {{",
        "  const bc = (j.backupCodes && typeof j.backupCodes === 'object' && !Array.isArray(j.backupCodes)) ? j.backupCodes : {};",
        "  pm.expect(Object.keys(bc).sort(), 'члены сводки набора').to.eql(['remaining', 'total']);",
        f"  pm.expect([bc.remaining, bc.total], 'остаток и размер набора').to.eql([{remaining}, 10]);",
        "});",
    ]


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


def _session_and_form(session_var="sfSessionCookie", form_var="sfFormCookie"):
    return _with_cookies(("kaname_session", session_var), ("kaname_form", form_var))


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


def _no_cookies(label):
    return [
        f"pm.test({js_str(label + ': печений не пишет — носитель и контекст прежние')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length, 'печений').to.eql(0));",
    ]


def _body_equals(var, label):
    return [
        f"pm.test({js_str(label)}, () => "
        f"pm.expect(pm.response.text() === pm.environment.get({js_str(var)}), 'тело равно эталону').to.eql(true));",
    ]


def _keep_body(var):
    return [f"pm.environment.set({js_str(var)}, pm.response.text());"]


def _refusal(status, code, text, label, reason=None):
    names = {16: "UNAUTHENTICATED", 3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED", 9: "FAILED_PRECONDITION", 6: "ALREADY_EXISTS"}
    out = [
        *_status(status),
        *_grpc_code(code, names[code]),
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


_NOT_ENROLLED = ("second factor is not enrolled", "SECOND_FACTOR_NOT_ENROLLED")
_AUTH_FAILED = "authentication failed"


def _not_enrolled(label):
    return _refusal(400, 9, _NOT_ENROLLED[0], label, reason=_NOT_ENROLLED[1])


def _csrf_step(name, kind, var, label, form_var="sfFormCookie"):
    return Step(
        name=name,
        method="GET",
        path=_CSRF + "?form=" + kind,
        pre_script=[*_lane(_CSRF + "?form=" + kind), *_with_cookies(("kaname_form", form_var))],
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
            f"  if (__sc.length === 1) {{ pm.environment.set({js_str(form_var)}, __sc[0].value.split(';')[0].slice(12)); }}",
            "}",
        ],
    )


def _await_step(name, kind, var, need, label, early=False):
    """Ожидание ступени часов: коды ступеней `последний + 1 … последний + need`
    все в окне ±1 (а при `early` — ещё и в первой половине ступени, чтобы
    несколько шагов одного кейса легли на ОДНУ ступень). Шаг — признак формы
    `kind`: он нужен следующему шагу и состояния не меняет.

    Опрос — повтором этого же шага с настоящей паузой перед ним и конечным
    пределом; утверждение исполняется на КАЖДОМ опросе и краснеет только тогда,
    когда предел исчерпан, а ступени нет."""
    early_js = " && (Date.now() % 30000) < 12000" if early else ""
    # Предел опросов — от ожидаемого: до `need + 1` ступеней по 30 с при паузе
    # около полусекунды на опрос.
    cap = 70 * (need + 1)
    return Step(
        name=name,
        method="GET",
        path=_CSRF + "?form=" + kind,
        pre_script=[*_lane(_CSRF + "?form=" + kind), *_with_cookies(("kaname_form", "sfFormCookie"))],
        insecure_tls=True,
        auth="anonymous",
        test_script=[
            *_OK,
            "const j = pm.response.json();",
            f"pm.environment.set({js_str(var)}, j.csrfToken);",
            "const __last = parseInt(pm.environment.get('sfLastStep') || '0', 10);",
            "const __polls = parseInt(pm.environment.get('sfAwaitPolls') || '0', 10);",
            f"const __ready = Math.floor(Date.now() / 30000) + 1 >= __last + {need}{early_js};",
            f"pm.test({js_str(label + ': часы дошли до нужной ступени либо ожидание в пределе')}, () => "
            f"pm.expect(__ready || __polls < {cap}, 'ступень часов').to.eql(true));",
            f"if (!__ready && __polls < {cap}) {{",
            "  pm.environment.set('sfAwaitPolls', String(__polls + 1));",
            "  const _w = Date.now(); while (Date.now() - _w < 500) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            "  pm.environment.unset('sfAwaitPolls');",
            "  pm.environment.set('sfWindowStep', String(Math.floor(Date.now() / 30000)));",
            "}",
        ],
    )


def _login_step(name, label, second_factor=None, level="1", session_var="sfSessionCookie",
                form_var="sfFormCookie", csrf_var="sfCsrfLogin", expires_var=None, pre=None, extra_tests=None):
    body = {"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{" + csrf_var + "}}"}
    if second_factor is not None:
        body["secondFactor"] = second_factor
    tests = [
        *_OK,
        "const j = pm.response.json();",
        f"pm.test({js_str(label + ': сессия уровня ' + level)}, () => pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql({js_str(level)}));",
        *_capture_cookie("kaname_session", session_var, label),
        *_capture_cookie("kaname_form", form_var, label),
    ]
    if expires_var:
        tests.append(f"pm.environment.set({js_str(expires_var)}, j.session && j.session.expiresAt);")
    tests.extend(extra_tests or [])
    return Step(
        name=name,
        method="POST",
        path=_LOGIN,
        body=body,
        pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", form_var)), *(pre or [])],
        insecure_tls=True,
        auth="anonymous",
        test_script=tests,
    )


def _refused_login(name, label, body_var_equal=None, second_factor=None, password="{{loginLanePassword}}",
                   pre=None, keep=None):
    body = {"email": "{{loginLaneEmail}}", "password": password, "csrfToken": "{{sfCsrfLogin}}"}
    if second_factor is not None:
        body["secondFactor"] = second_factor
    tests = [*_refusal(401, 16, _AUTH_FAILED, label)]
    if body_var_equal:
        tests += _body_equals(body_var_equal, label + ': тело побайтово равно отказу на неверный пароль')
    if keep:
        tests += _keep_body(keep)
    return Step(
        name=name,
        method="POST",
        path=_LOGIN,
        body=body,
        pre_script=[*_lane(_LOGIN), *_with_cookies(("kaname_form", "sfFormCookie")), *(pre or [])],
        insecure_tls=True,
        auth="anonymous",
        test_script=tests,
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
            test_script=[*_OK, "pm.environment.unset('sfSessionCookie');"],
        ),
        _csrf_step(prefix + "-csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
    ]


def _status_step(name, tests, session_var="sfSessionCookie", form_var="sfFormCookie"):
    return Step(
        name=name,
        method="GET",
        path=_STATUS,
        pre_script=[*_lane(_STATUS), *_session_and_form(session_var, form_var)],
        insecure_tls=True,
        auth="anonymous",
        test_script=[*_OK, "const j = pm.response.json();", *tests],
    )


def _keep_remaining(var):
    return [
        "{",
        "  const bc = (j.backupCodes && typeof j.backupCodes === 'object') ? j.backupCodes : {};",
        f"  pm.environment.set({js_str(var)}, String(bc.remaining));",
        "}",
    ]


def _remaining_is(var, delta, label):
    """Остаток набора в состоянии равен захваченному ранее минус `delta`."""
    return [
        f"pm.test({js_str(label)}, () => {{",
        "  const bc = (j.backupCodes && typeof j.backupCodes === 'object') ? j.backupCodes : {};",
        f"  pm.expect(bc.remaining, 'остаток набора').to.eql(parseInt(pm.environment.get({js_str(var)}), 10) - {delta});",
        "});",
    ]


def _step_up(name, body, pre, tests, session_var="sfSessionCookie", form_var="sfFormCookie"):
    return Step(
        name=name,
        method="POST",
        path=_STEP_UP,
        body=body,
        pre_script=[*_lane(_STEP_UP), *_session_and_form(session_var, form_var), *pre],
        insecure_tls=True,
        auth="anonymous",
        test_script=tests,
    )


def _post(name, path, body, pre, tests, session_var="sfSessionCookie"):
    return Step(
        name=name,
        method="POST",
        path=path,
        body=body,
        pre_script=[*_lane(path), *_session_and_form(session_var), *pre],
        insecure_tls=True,
        auth="anonymous",
        test_script=tests,
    )


def _backup_step_up_ok(name, index, label, remaining=None, set_var="sfBackupCodes", keep_after=None):
    tests = [
        *_OK,
        "const j = pm.response.json();",
        f"pm.test({js_str(label + ': «2» после запасного кода')}, () => pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2'));",
        *_capture_cookie("kaname_session", "sfSessionCookie", label),
    ]
    if remaining is not None:
        tests.append(
            f"pm.test({js_str(label + ': остаток ' + str(remaining) + ' назван в ответе')}, () => "
            f"pm.expect(j.backupCodesRemaining, 'остаток запасных кодов').to.eql({remaining}));")
    return _step_up(
        name,
        {"method": "lookup_secret", "code": "{{sfBackupCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
        _backup_code(label, index, set_var),
        tests,
    )


def _backup_step_up_refused(name, index, label, set_var="sfBackupCodes"):
    return _step_up(
        name,
        {"method": "lookup_secret", "code": "{{sfBackupCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
        _backup_code(label, index, set_var),
        [*_refusal(401, 16, _AUTH_FAILED, label), *_body_equals("sfWrongPasswordRefusalBody", label + ': тело равно отказу на неверный пароль')],
    )


# Отказ по несуществующей сессии — эталон для «прежний носитель» (Ф12-02, Ф12-15).
def _no_session_reference(name):
    return Step(
        name=name,
        method="GET",
        path=_STATUS,
        pre_script=[
            *_lane(_STATUS),
            "pm.request.headers.upsert({key: 'Cookie', value: 'kaname_session=not-a-session-' + pm.environment.get('runId')});",
        ],
        insecure_tls=True,
        auth="anonymous",
        test_script=[*_refusal(401, 16, _AUTH_FAILED, "NO-SESSION"), *_keep_body("sfNoSessionRefusalBody")],
    )


def _old_bearer_refused(name, label):
    return _status_step_refused(name, "sfOldSessionCookie", label)


def _status_step_refused(name, session_var, label):
    return Step(
        name=name,
        method="GET",
        path=_STATUS,
        pre_script=[*_lane(_STATUS), *_session_and_form(session_var)],
        insecure_tls=True,
        auth="anonymous",
        test_script=[
            *_refusal(401, 16, _AUTH_FAILED, label),
            *_body_equals("sfNoSessionRefusalBody", label + ': тело побайтово равно отказу по несуществующей сессии'),
        ],
    )


_KEEP_OLD_SESSION = ["pm.environment.set('sfOldSessionCookie', pm.environment.get('sfSessionCookie'));"]


def _new_bearer(label):
    return [
        f"pm.test({js_str(label + ': носитель перевыпущен — новое значение')}, () => "
        "pm.expect(pm.environment.get('sfSessionCookie') !== pm.environment.get('sfOldSessionCookie'), 'носитель сменился').to.eql(true));",
    ]


def _expires_kept(var, label):
    return [
        f"pm.test({js_str(label + ': срок сессии прежний')}, () => "
        f"pm.expect(j.session && j.session.expiresAt, 'срок сессии').to.eql(pm.environment.get({js_str(var)})));",
    ]


# ───────────────────────────────────────────────────────────────────────────
# Без фактора: отказы «не заведён» (Ф12-17 `B`, Ф12-29 г, Ф12-25 в `B`).
# Человек посева на входе в набор фактора не имеет — это утверждается шагом
# состояния, а не предполагается.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-NEG-NOT-ENROLLED-STATE",
    title="Без фактора: церемония кодом и запасным кодом, снятие и перечеканка — 400 SECOND_FACTOR_NOT_ENROLLED одним телом (Ф12-17, Ф12-29 г, Ф12-25 в)",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        _no_session_reference("no-session-reference"),
        _csrf_step("ne-csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
        _login_step("ne-login", "LOGIN-NE"),
        _status_step("ne-status", [
            "pm.test('STATUS-NONE: фактора нет — ни заведённого, ни ожидающего, набора нет', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j.totp || {}, 'pendingUntil'), 'срок ожидания').to.eql(false);",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j, 'backupCodes'), 'сводка набора в ответе').to.eql(false);",
            "});",
        ]),
        _csrf_step("ne-csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        _step_up("ne-step-up-totp", {"method": "totp", "code": "123456", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 [*_not_enrolled("NE-STEP-UP-TOTP"), *_no_cookies("NE-STEP-UP-TOTP"), *_keep_body("sfNotEnrolledRefusalBody")]),
        _step_up("ne-step-up-lookup-secret", {"method": "lookup_secret", "code": "ABCDEFGHJK", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 [*_not_enrolled("NE-STEP-UP-LOOKUP"),
                  *_body_equals("sfNotEnrolledRefusalBody", "NE-STEP-UP-LOOKUP: тело побайтово равно отказу кодом по времени")]),
        _csrf_step("ne-csrf-second-factor", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        _post("ne-remove", _REMOVE, {"method": "totp", "code": "123456", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_not_enrolled("NE-REMOVE"), *_no_cookies("NE-REMOVE"), *_keep_body("sfRemoveNotEnrolledBody")]),
        _post("ne-backup-codes", _BACKUP_CODES, {"method": "totp", "code": "123456", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_not_enrolled("NE-BACKUP-CODES"), *_no_cookies("NE-BACKUP-CODES")]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Строка `pending` — не способ (Ф12-01, Ф12-17 `C`, Ф12-29 д, Ф12-25 в `C`,
# Ф12-03). Положительный контроль Ф12-03 — подтверждение хребта ниже.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-ENROLL-PENDING-IS-NOT-A-METHOD",
    title="Начатое заведение не способ: секрет и срок один раз, вход с его кодом — 401 как неверный пароль, церемония, снятие и перечеканка — «не заведён», неверный код подтверждения — 401 (Ф12-01, Ф12-17, Ф12-29 д, Ф12-25 в, Ф12-03)",
    classes=["CRUD", "NEG", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("pe-csrf-second-factor", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        Step(
            name="pe-enroll",
            method="POST",
            path=_ENROLL,
            body={"csrfToken": "{{sfCsrfSecondFactor}}"},
            pre_script=[*_lane(_ENROLL), *_session_and_form()],
            insecure_tls=True,
            auth="anonymous",
            test_script=[
                *_OK,
                "const j = pm.response.json();",
                "pm.test('PE-ENROLL: секрет base32 без дополнения — 32 знака, 20 байт', () => "
                "pm.expect(/^[A-Z2-7]{32}$/.test(String(j.secret)), 'форма секрета').to.eql(true));",
                "pm.test('PE-ENROLL: адрес otpauth — метка «домен:адрес человека», тот же секрет, издатель — домен, SHA1, 6 цифр, 30 с', () => {",
                "  const m = /^otpauth:\\/\\/totp\\/([^?]+)\\?secret=([A-Z2-7]+)&issuer=([^&]+)&algorithm=SHA1&digits=6&period=30$/.exec(String(j.otpauthUri));",
                "  const label = m ? decodeURIComponent(m[1]) : '';",
                "  const issuer = m ? decodeURIComponent(m[3]) : '';",
                "  pm.expect(m !== null, 'форма адреса').to.eql(true);",
                "  pm.expect(m !== null && m[2] === j.secret, 'секрет адреса равен секрету ответа').to.eql(true);",
                "  pm.expect(issuer.length > 0 && label === issuer + ':' + pm.environment.get('loginLaneEmail'), 'метка — домен и адрес человека').to.eql(true);",
                "});",
                "pm.test('PE-ENROLL: срок заведения — момент до секунды, позже ответа', () => {",
                "  const at = String(j.expiresAt);",
                "  const date = Date.parse(pm.response.headers.get('Date') || '');",
                "  pm.expect(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/.test(at), 'срок до секунды').to.eql(true);",
                "  pm.expect(Date.parse(at) > date, 'срок позже ответа').to.eql(true);",
                "});",
                "pm.environment.set('sfPendingSecret', j.secret);",
                "pm.environment.set('sfPendingUntil', j.expiresAt);",
                *_no_cookies("PE-ENROLL"),
            ],
        ),
        _status_step("pe-status-pending", [
            "pm.test('PE-STATUS: не заведён; срок ожидания — тот, что назвал ответ заведения; набора нет', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(j.totp && j.totp.pendingUntil, 'срок ожидания').to.eql(pm.environment.get('sfPendingUntil'));",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j, 'backupCodes'), 'сводка набора в ответе').to.eql(false);",
            "});",
        ]),
        _csrf_step("pe-csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
        _refused_login("pe-login-wrong-password", "PE-WRONG-PW", password="not-the-password-{{runId}}",
                       second_factor={"method": "totp", "code": "000000"}, keep="sfWrongPasswordRefusalBody"),
        _refused_login("pe-login-with-pending-code", "PE-PENDING-CODE", body_var_equal="sfWrongPasswordRefusalBody",
                       second_factor={"method": "totp", "code": "{{sfCode}}"},
                       pre=[*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfPendingSecret'), __stepNow()));"]),
        _login_step("pe-login-plain", "PE-LOGIN-PLAIN"),
        _csrf_step("pe-csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        _step_up("pe-step-up-totp", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 [*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfPendingSecret'), __stepNow()));"],
                 [*_not_enrolled("PE-STEP-UP-TOTP"), *_no_cookies("PE-STEP-UP-TOTP"),
                  *_body_equals("sfNotEnrolledRefusalBody", "PE-STEP-UP-TOTP: тело побайтово равно отказу без строки")]),
        _step_up("pe-step-up-lookup-secret", {"method": "lookup_secret", "code": "ABCDEFGHJK", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 [*_not_enrolled("PE-STEP-UP-LOOKUP"),
                  *_body_equals("sfNotEnrolledRefusalBody", "PE-STEP-UP-LOOKUP: тело побайтово равно отказу без строки")]),
        _csrf_step("pe-csrf-second-factor-2", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        _post("pe-remove", _REMOVE, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfPendingSecret'), __stepNow()));"],
              [*_not_enrolled("PE-REMOVE"), *_no_cookies("PE-REMOVE"),
               *_body_equals("sfRemoveNotEnrolledBody", "PE-REMOVE: тело побайтово равно снятию без строки (Ф12-29 г)")]),
        _post("pe-backup-codes", _BACKUP_CODES, {"method": "lookup_secret", "code": "ABCDEFGHJK", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_not_enrolled("PE-BACKUP-CODES"), *_no_cookies("PE-BACKUP-CODES")]),
        _post("pe-confirm-wrong-code", _CONFIRM, {"code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __wrongCode(pm.environment.get('sfPendingSecret')));"],
              [*_refusal(401, 16, _AUTH_FAILED, "PE-CONFIRM-WRONG"), *_no_cookies("PE-CONFIRM-WRONG")]),
        _status_step("pe-status-still-pending", [
            "pm.test('PE-STATUS-AFTER: строка по-прежнему ожидает — снятие, перечеканка и неверный код её не тронули', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(j.totp && j.totp.pendingUntil, 'срок ожидания').to.eql(pm.environment.get('sfPendingUntil'));",
            "});",
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# ХРЕБЕТ Ф12-08: вход → enroll → confirm → состояние → выход → вход с кодом → «2».
# Заведение здесь — ВТОРОЕ при `pending` прежнего кейса (Ф12-05 б).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-ENROLL-CONFIRM-LOGIN-LEVEL2",
    title="Фактор заводится и предъявляется без браузера: enroll заменяет ожидающее, confirm перевыпускает носитель, повторный enroll — 409, вход с кодом даёт «2» (Ф12-08, Ф12-05, Ф12-02, Ф12-11, Ф12-14)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("csrf-login", "login", "sfCsrfLogin", "CSRF-LOGIN"),
        _login_step("login-level-1", "LOGIN-1", expires_var="sfSessionExpiresAt"),
        _status_step("status-before-enroll", [
            "pm.test('STATUS-0: фактор не заведён, набора нет', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j, 'backupCodes'), 'сводка набора в ответе').to.eql(false);",
            "});",
        ]),
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
                *_OK,
                "const j = pm.response.json();",
                "pm.test('ENROLL: секрет base32 без дополнения (32 знака — 20 байт), адрес otpauth, срок', () => {",
                "  pm.expect(/^[A-Z2-7]{32}$/.test(String(j.secret)), 'форма секрета').to.eql(true);",
                "  pm.expect(/^otpauth:\\/\\/totp\\/.+\\?secret=[A-Z2-7]{32}&issuer=.+&algorithm=SHA1&digits=6&period=30$/.test(String(j.otpauthUri)), 'форма адреса otpauth').to.eql(true);",
                "  pm.expect(j.expiresAt, 'срок заведения').to.be.a('string').and.not.empty;",
                "});",
                "pm.test('ENROLL: при ожидающем заведении — НОВЫЙ секрет, прежний заменён (Ф12-05 б)', () => "
                "pm.expect(typeof j.secret === 'string' && j.secret !== pm.environment.get('sfPendingSecret'), 'секрет новый').to.eql(true));",
                "pm.environment.set('sfSecret', j.secret);",
                "pm.environment.unset('sfLastStep');",
                *_no_cookies("ENROLL"),
            ],
        ),
        _status_step("status-pending", [
            "pm.test('STATUS-PENDING: не заведён, срок ожидания назван, набора нет', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(j.totp && j.totp.pendingUntil, 'срок ожидания').to.be.a('string').and.not.empty;",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j, 'backupCodes'), 'сводка набора в ответе').to.eql(false);",
            "});",
        ]),
        _post("confirm-with-replaced-secret", _CONFIRM, {"code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfPendingSecret'), __stepNow()));"],
              [*_refusal(401, 16, _AUTH_FAILED, "CONFIRM-REPLACED"), *_no_cookies("CONFIRM-REPLACED")]),
        _post("confirm", _CONFIRM, {"code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_present_totp("CONFIRM"), *_KEEP_OLD_SESSION],
              [
                  *_OK,
                  *_ACCEPTED_STEP,
                  "const j = pm.response.json();",
                  "pm.test('CONFIRM: десять запасных кодов по десять знаков Crockford, сессия «2», assurance', () => {",
                  "  const codes = Array.isArray(j.backupCodes) ? j.backupCodes : [];",
                  "  pm.expect(Array.isArray(j.backupCodes) ? j.backupCodes.length : -1, 'запасных кодов').to.eql(10);",
                  "  pm.expect(codes.filter(c => !/^[0-9A-HJKMNP-TV-Z]{10}$/.test(String(c))).length, 'кодов вне формы Crockford').to.eql(0);",
                  "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2');",
                  "  pm.expect(j.assurance, 'assurance').to.eql({level: '2', level2Reachable: true, missingForLevel2: []});",
                  "});",
                  *_expires_kept("sfSessionExpiresAt", "CONFIRM"),
                  "if (j.backupCodes && j.backupCodes.length === 10) {",
                  "  pm.environment.set('sfBackupCode0', j.backupCodes[0]);",
                  "  pm.environment.set('sfBackupCode1', j.backupCodes[1]);",
                  "  pm.environment.set('sfBackupCodes', JSON.stringify(j.backupCodes));",
                  "}",
                  *_capture_cookie("kaname_session", "sfSessionCookie", "CONFIRM"),
                  *_new_bearer("CONFIRM"),
              ]),
        _old_bearer_refused("confirm-old-bearer", "CONFIRM-OLD-BEARER"),
        _status_step("status-enrolled", [
            "pm.test('STATUS-ACTIVE: заведён, момент подтверждения', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(true);",
            "  pm.expect(j.totp && j.totp.confirmedAt, 'момент подтверждения').to.be.a('string').and.not.empty;",
            "});",
            *_backup_summary("STATUS-ACTIVE: 10 из 10", 10),
            "pm.test('STATUS: ни секрета, ни кодов, ни адреса в ответе (Ф12-27)', () => {",
            "  const t = pm.response.text();",
            "  const has = (k) => { const v = pm.environment.get(k); return typeof v === 'string' && v !== '' && t.includes(v); };",
            "  pm.expect(t.includes('otpauth'), 'адрес otpauth в ответе').to.eql(false);",
            "  pm.expect(has('sfSecret'), 'секрет в ответе').to.eql(false);",
            "  pm.expect(has('sfBackupCode0') || has('sfBackupCode1'), 'запасной код в ответе').to.eql(false);",
            "});",
            "pm.environment.set('sfConfirmedAt', j.totp && j.totp.confirmedAt);",
        ]),
        _post("enroll-when-active", _ENROLL, {"csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_refusal(409, 6, "second factor is already enrolled", "ENROLL-ACTIVE", reason="SECOND_FACTOR_ALREADY_ENROLLED"),
               *_no_cookies("ENROLL-ACTIVE")]),
        _status_step("status-after-enroll-when-active", [
            "pm.test('STATUS-ACTIVE-KEPT: строка не изменена — момент подтверждения прежний', () => "
            "pm.expect(j.totp && j.totp.confirmedAt, 'момент подтверждения').to.eql(pm.environment.get('sfConfirmedAt')));",
            *_backup_summary("STATUS-ACTIVE-KEPT: 10 из 10", 10),
        ]),
        *_logout_steps("after-confirm"),
        _login_step("login-with-totp-level-2", "LOGIN-2FA", second_factor={"method": "totp", "code": "{{sfCode}}"},
                    level="2", pre=_present_totp("LOGIN-2FA"), extra_tests=_ACCEPTED_STEP),
        *_logout_steps("after-level-2"),
        # Ф12-13 (г): тот же код — повтор, 401 одним текстом.
        _refused_login("login-replayed-code", "REPLAY", second_factor={"method": "totp", "code": "{{sfCode}}"}),
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
    title="Церемония запасным кодом поднимает сессию до «2» и называет остаток; тот же код второй раз — 401 (Ф12-18)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _csrf_step("csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        _step_up("step-up-with-backup-code",
                 {"method": "lookup_secret", "code": "{{sfBackupCode0}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 [
                     "pm.test('STEP-UP: фикстура хребта на месте — сессия и запасной код захвачены', () => {",
                     "  const got = (k) => { const v = pm.environment.get(k); return typeof v === 'string' && v !== ''; };",
                     "  pm.expect(got('sfSessionCookie'), 'носитель захвачен').to.eql(true);",
                     "  pm.expect(got('sfBackupCode0'), 'запасной код захвачен').to.eql(true);",
                     "});",
                 ],
                 [
                     *_OK,
                     "const j = pm.response.json();",
                     "pm.test('STEP-UP: «2», остаток 9 назван только здесь', () => {",
                     "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2');",
                     "  pm.expect(j.assurance && j.assurance.level, 'уровень assurance').to.eql('2');",
                     "  pm.expect(j.backupCodesRemaining, 'остаток запасных кодов').to.eql(9);",
                     "});",
                     *_capture_cookie("kaname_session", "sfSessionCookie", "STEP-UP"),
                 ]),
        _step_up("step-up-same-backup-code-again",
                 {"method": "lookup_secret", "code": "{{sfBackupCode0}}", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 _refusal(401, 16, _AUTH_FAILED, "BACKUP-AGAIN")),
        _status_step("status-after-backup-code", [*_backup_summary("STATUS: 9 из 10", 9)]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-12: вход паролем и запасным кодом — «2»; тот же код — 401; остаток −1.
# Близнец Ф12-11 (хребет): различие одно — способ.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-LOGIN-WITH-BACKUP-CODE",
    title="Вход паролем и запасным кодом даёт «2» и потребляет код: тот же код на следующем входе — 401, остаток на один меньше (Ф12-12)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _status_step("lb-status-before", [*_keep_remaining("sfRemainingBefore")]),
        *_logout_steps("lb-before"),
        _login_step("lb-login-with-backup-code", "LB-LOGIN", second_factor={"method": "lookup_secret", "code": "{{sfBackupCode}}"},
                    level="2", pre=_backup_code("LB-LOGIN", 2)),
        *_logout_steps("lb-after"),
        _refused_login("lb-login-same-backup-code", "LB-AGAIN", body_var_equal="sfWrongPasswordRefusalBody",
                       second_factor={"method": "lookup_secret", "code": "{{sfBackupCode}}"}, pre=_backup_code("LB-AGAIN", 2)),
        _login_step("lb-login-plain", "LB-PLAIN"),
        _status_step("lb-status-after", [*_remaining_is("sfRemainingBefore", 1, "LB-STATUS: остаток на один меньше — код потреблён")]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-23: каждый код принимается один раз; прочие годны.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-BACKUP-CODE-ONCE-EACH",
    title="Запасной код принимается один раз, прочие годны: №3 — 200, №3 снова — 401, №7 — 200, остаток на два меньше (Ф12-23)",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        _status_step("oe-status-before", [*_keep_remaining("sfRemainingBefore")]),
        _csrf_step("oe-csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        _backup_step_up_ok("oe-code-3", 3, "OE-3"),
        _backup_step_up_refused("oe-code-3-again", 3, "OE-3-AGAIN"),
        _backup_step_up_ok("oe-code-7", 7, "OE-7"),
        _status_step("oe-status-after", [*_remaining_is("sfRemainingBefore", 2, "OE-STATUS: остаток на два меньше")]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-15 и Ф12-22: код по времени в сессии «1»; повтор — у строки, не у сессии.
# `S1` — сессия «1» входом без кода; `S2` — вторая сессия той же личности.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-STEP-UP-TOTP-AND-REPLAY",
    title="Код по времени в сессии «1» поднимает до «2» на новом носителе; тот же и младший код — 401, следующий — 200, принятый код и неверный код из другой сессии — 401 без последствий (Ф12-15, Ф12-22, Ф12-16)",
    classes=["CRUD", "SEC", "NEG"],
    priority="P0",
    steps=[
        *_logout_steps("su-before"),
        _login_step("su-login-s1", "SU-S1", expires_var="sfSessionExpiresAt"),
        _csrf_step("su-csrf-login-s2", "login", "sfCsrfLogin2", "CSRF-LOGIN-S2", form_var="sfForm2Cookie"),
        _login_step("su-login-s2", "SU-S2", session_var="sfSession2Cookie", form_var="sfForm2Cookie", csrf_var="sfCsrfLogin2"),
        _await_step("su-await-two-steps", "step-up", "sfCsrfStepUp", 2, "SU-AWAIT"),
        _step_up("su-step-up-totp", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 [*_present_totp("SU-TOTP"), *_KEEP_OLD_SESSION],
                 [
                     *_OK,
                     *_ACCEPTED_STEP,
                     "const j = pm.response.json();",
                     "pm.test('SU-TOTP: «2», путь к «2» пройден — недостающего нет', () => {",
                     "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2');",
                     "  pm.expect(j.assurance, 'assurance').to.eql({level: '2', level2Reachable: true, missingForLevel2: []});",
                     "});",
                     *_expires_kept("sfSessionExpiresAt", "SU-TOTP"),
                     "pm.environment.set('sfAcceptedCode', pm.environment.get('sfCode'));",
                     *_capture_cookie("kaname_session", "sfSessionCookie", "SU-TOTP"),
                     *_new_bearer("SU-TOTP"),
                 ]),
        _old_bearer_refused("su-old-bearer", "SU-OLD-BEARER"),
        _step_up("su-same-code-again", {"method": "totp", "code": "{{sfAcceptedCode}}", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 [*_refusal(401, 16, _AUTH_FAILED, "SU-REPLAY"), *_body_equals("sfWrongPasswordRefusalBody", "SU-REPLAY: тело равно отказу неверного кода")]),
        _step_up("su-younger-code", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 [*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfSecret'), __lastStep() - 1));"],
                 _refusal(401, 16, _AUTH_FAILED, "SU-YOUNGER")),
        _step_up("su-next-code", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 _present_totp("SU-NEXT"),
                 [
                     *_OK,
                     *_ACCEPTED_STEP,
                     "const j = pm.response.json();",
                     "pm.test('SU-NEXT: код следующей ступени принят', () => pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2'));",
                     *_capture_cookie("kaname_session", "sfSessionCookie", "SU-NEXT"),
                 ]),
        _csrf_step("su-csrf-step-up-s2", "step-up", "sfCsrfStepUp2", "CSRF-STEP-UP-S2", form_var="sfForm2Cookie"),
        _step_up("su-s2-accepted-code", {"method": "totp", "code": "{{sfAcceptedCode}}", "csrfToken": "{{sfCsrfStepUp2}}"}, [],
                 [*_refusal(401, 16, _AUTH_FAILED, "SU-S2-REPLAY"), *_no_cookies("SU-S2-REPLAY")],
                 session_var="sfSession2Cookie", form_var="sfForm2Cookie"),
        # Ф12-16: неверный код в сессии «1» — отказ без последствий: носитель
        # прежний и годен (шаг состояния ниже).
        _step_up("su-s2-wrong-code", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp2}}"},
                 [*_TOTP_JS, "pm.environment.set('sfCode', __wrongCode(pm.environment.get('sfSecret')));"],
                 [*_refusal(401, 16, _AUTH_FAILED, "SU-S2-WRONG"), *_no_cookies("SU-S2-WRONG"),
                  *_body_equals("sfWrongPasswordRefusalBody", "SU-S2-WRONG: тело равно отказу на неверный пароль")],
                 session_var="sfSession2Cookie", form_var="sfForm2Cookie"),
        _status_step("su-s2-bearer-intact", [
            "pm.test('SU-S2: отказ сессию не погасил — носитель годен', () => pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(true));",
        ], session_var="sfSession2Cookie", form_var="sfForm2Cookie"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-25: перечеканка. Прежние коды непригодны ВСЕ; неверные предъявления
# перемежаются новым кодом — счёт по адресу не доходит до величины профиля.
# ───────────────────────────────────────────────────────────────────────────
_REGEN_OLD_REFUSALS = []
for _i, _idx in enumerate((0, 2, 3, 4, 5, 6, 7, 8, 9)):
    _REGEN_OLD_REFUSALS.append(_backup_step_up_refused(f"rg-old-code-{_idx}", _idx, f"RG-OLD-{_idx}", set_var="sfOldBackupCodes"))
    if _i in (2, 6):
        _REGEN_OLD_REFUSALS.append(_backup_step_up_ok(f"rg-reset-new-{_i}", 0 if _i == 2 else 1, f"RG-RESET-{_i}"))
_REGEN_OLD_REFUSALS.append(_backup_step_up_ok("rg-reset-new-last", 2, "RG-RESET-LAST"))

CASES.append(Case(
    id="IAM-2FA-OK-REGENERATE-BACKUP-CODES",
    title="Перечеканка: без кода — 400 с полем, неверным — 401 и набор цел, кодом по времени — десять новых и «2»; все десять прежних — 401 (Ф12-25)",
    classes=["CRUD", "SEC", "NEG"],
    priority="P0",
    steps=[
        _status_step("rg-status-before", [*_keep_remaining("sfRemainingBefore")]),
        _csrf_step("rg-csrf-second-factor", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        _post("rg-without-code", _BACKUP_CODES, {"method": "totp", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_refusal(400, 3, "Illegal argument code: required", "RG-NO-CODE"), *_no_cookies("RG-NO-CODE")]),
        _post("rg-wrong-code", _BACKUP_CODES, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __wrongCode(pm.environment.get('sfSecret')));"],
              [*_refusal(401, 16, _AUTH_FAILED, "RG-WRONG"), *_no_cookies("RG-WRONG")]),
        _status_step("rg-status-untouched", [*_remaining_is("sfRemainingBefore", 0, "RG-UNTOUCHED: набор не тронут неверным кодом")]),
        _await_step("rg-await-step", "second-factor", "sfCsrfSecondFactor", 1, "RG-AWAIT"),
        _post("rg-regenerate", _BACKUP_CODES, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_present_totp("RG-REGEN"), *_KEEP_OLD_SESSION],
              [
                  *_OK,
                  *_ACCEPTED_STEP,
                  "const j = pm.response.json();",
                  "pm.test('RG-REGEN: десять новых кодов Crockford, сессия «2», assurance «2»', () => {",
                  "  const codes = Array.isArray(j.backupCodes) ? j.backupCodes : [];",
                  "  pm.expect(codes.length, 'новых кодов').to.eql(10);",
                  "  pm.expect(codes.filter(c => !/^[0-9A-HJKMNP-TV-Z]{10}$/.test(String(c))).length, 'кодов вне формы').to.eql(0);",
                  "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2');",
                  "  pm.expect(j.assurance && j.assurance.level, 'уровень assurance').to.eql('2');",
                  "});",
                  "pm.test('RG-REGEN: ни один новый код не совпал с прежним', () => {",
                  "  let old = []; try { old = JSON.parse(pm.environment.get('sfBackupCodes') || '[]'); } catch (e) { old = []; }",
                  "  const codes = Array.isArray(j.backupCodes) ? j.backupCodes : [];",
                  "  pm.expect(codes.filter(c => old.includes(c)).length, 'совпавших').to.eql(0);",
                  "});",
                  "if (Array.isArray(j.backupCodes) && j.backupCodes.length === 10) {",
                  "  pm.environment.set('sfOldBackupCodes', pm.environment.get('sfBackupCodes'));",
                  "  pm.environment.set('sfBackupCodes', JSON.stringify(j.backupCodes));",
                  "}",
                  *_capture_cookie("kaname_session", "sfSessionCookie", "RG-REGEN"),
                  *_new_bearer("RG-REGEN"),
              ]),
        _status_step("rg-status-fresh-set", [*_backup_summary("RG-STATUS: 10 из 10", 10)]),
        _post("rg-regenerate-with-old-code", _BACKUP_CODES,
              {"method": "lookup_secret", "code": "{{sfBackupCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              _backup_code("RG-OLD-1", 1, "sfOldBackupCodes"),
              [*_refusal(401, 16, _AUTH_FAILED, "RG-OLD-1"), *_no_cookies("RG-OLD-1")]),
        _csrf_step("rg-csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        *_REGEN_OLD_REFUSALS,
        _status_step("rg-status-after", [*_backup_summary("RG-STATUS-AFTER: три новых потреблены — 7 из 10", 7)]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-26: исчерпание — остаток 0 числом, одиннадцатый — 401, код по времени — 200.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-BACKUP-CODES-EXHAUSTED",
    title="Исчерпание запасных кодов: десятый потреблённый называет остаток 0, одиннадцатый — 401, код по времени по-прежнему даёт «2» (Ф12-26)",
    classes=["BVA", "SEC"],
    priority="P1",
    steps=[
        _csrf_step("ex-csrf-step-up", "step-up", "sfCsrfStepUp", "CSRF-STEP-UP"),
        *[_backup_step_up_ok(f"ex-code-{i}", i, f"EX-{i}", remaining=9 - i) for i in range(3, 10)],
        _status_step("ex-status-zero", [*_backup_summary("EX-STATUS: 0 из 10 — остаток назван числом", 0)]),
        _backup_step_up_refused("ex-eleventh", 3, "EX-ELEVENTH"),
        _await_step("ex-await-step", "step-up", "sfCsrfStepUp", 1, "EX-AWAIT"),
        _step_up("ex-totp-still-works", {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"},
                 _present_totp("EX-TOTP"),
                 [
                     *_OK,
                     *_ACCEPTED_STEP,
                     "const j = pm.response.json();",
                     "pm.test('EX-TOTP: код по времени после исчерпания — «2»', () => pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2'));",
                     *_capture_cookie("kaname_session", "sfSessionCookie", "EX-TOTP"),
                 ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-21: окно ±1 — обе стороны оси; одна сессия, по возрастанию шага; ступень
# `t` неподвижна весь кейс, `t ≥ t₀ + 3` (принятый шаг младше `t − 2`).
# ───────────────────────────────────────────────────────────────────────────
def _window_step(name, offset, ok):
    label = f"WIN{offset:+d}"
    pre = [
        *_TOTP_JS,
        "const __t = parseInt(pm.environment.get('sfWindowStep') || '0', 10);",
        f"pm.test({js_str(label + ': ступень t неподвижна — часы на той же ступени, что в начале кейса')}, () => "
        "pm.expect(__stepNow() === __t, 'ступень часов').to.eql(true));",
        f"pm.environment.set('sfPresentedStep', String(__t + ({offset})));",
        f"pm.environment.set('sfCode', __totp(pm.environment.get('sfSecret'), __t + ({offset})));",
    ]
    if ok:
        tests = [
            *_OK,
            *_ACCEPTED_STEP,
            "const j = pm.response.json();",
            f"pm.test({js_str(label + ': в окне — предъявление, «2»')}, () => pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2'));",
            *_capture_cookie("kaname_session", "sfSessionCookie", label),
        ]
    else:
        tests = [*_refusal(401, 16, _AUTH_FAILED, label)]
    return _step_up(name, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfStepUp}}"}, pre, tests)


CASES.append(Case(
    id="IAM-2FA-BVA-TOTP-WINDOW",
    title="Окно расхождения часов ±1 шаг: t−2 и t+2 — 401 окном, t−1, t, t+1 — 200, одна сессия, по возрастанию (Ф12-21)",
    classes=["BVA", "SEC"],
    priority="P1",
    steps=[
        _await_step("win-await", "step-up", "sfCsrfStepUp", 4, "WIN-AWAIT", early=True),
        _window_step("win-minus-2", -2, False),
        _window_step("win-minus-1", -1, True),
        _window_step("win-zero", 0, True),
        _window_step("win-plus-1", 1, True),
        _window_step("win-plus-2", 2, False),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-29 (а, б, в): отказы снятия при заведённом факторе.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-NEG-REMOVE-REFUSALS",
    title="Снятие без кода — 400 с именем поля; с неверным и с принятым в этой сессии кодом — 401; строки не сняты, носитель не перевыпущен (Ф12-29)",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        _csrf_step("rr-csrf-second-factor", "second-factor", "sfCsrfSecondFactor", "CSRF-2FA"),
        _post("rr-without-code", _REMOVE, {"method": "totp", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              [*_refusal(400, 3, "Illegal argument code: required", "RR-NO-CODE"), *_no_cookies("RR-NO-CODE")]),
        _post("rr-wrong-code", _REMOVE, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __wrongCode(pm.environment.get('sfSecret')));"],
              [*_refusal(401, 16, _AUTH_FAILED, "RR-WRONG"), *_no_cookies("RR-WRONG")]),
        _post("rr-replayed-code", _REMOVE, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              [*_TOTP_JS, "pm.environment.set('sfCode', __totp(pm.environment.get('sfSecret'), __lastStep()));"],
              [*_refusal(401, 16, _AUTH_FAILED, "RR-REPLAY"), *_no_cookies("RR-REPLAY")]),
        _status_step("rr-status-kept", [
            "pm.test('RR-STATUS: фактор заведён — ни один отказ строк не снял, носитель годен', () => pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(true));",
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-28: снятие кодом по времени; после — состояние «не заведён», вход с кодом —
# тот же 401 «authentication failed», что на неверный пароль, тело побайтово
# (Ф12-13 е, kaname#257: код при незаведённом факторе не называет совпавшего
# пароля), без кода — «1». Порядок трёх входов несущий: неверный пароль + код
# → верный пароль + код (тело равно первому) → верный пароль без кода (сессия
# «1», положительный близнец). Заодно возвращает посев в исходное: следующий
# прогон снова заводит фактор с нуля.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-2FA-OK-REMOVE-BY-CODE",
    title="Снятие фактора кодом по времени: строки сняты, сессия жива на «2», вход с кодом после — тот же 401, что на неверный пароль (Ф12-28)",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        _await_step("await-remove", "second-factor", "sfCsrfSecondFactor", 1, "REMOVE-AWAIT"),
        _post("remove-with-totp", _REMOVE, {"method": "totp", "code": "{{sfCode}}", "csrfToken": "{{sfCsrfSecondFactor}}"},
              _present_totp("REMOVE"),
              [
                  *_OK,
                  *_ACCEPTED_STEP,
                  "const j = pm.response.json();",
                  "pm.test('REMOVE: сессия «2», остаток 0 всегда (фактор снят, набора нет — Р4 ред. 10), путь к «2» закрыт', () => {",
                  "  pm.expect(j.session && j.session.assuranceLevel, 'уровень сессии').to.eql('2');",
                  "  pm.expect(j.backupCodesRemaining, 'остаток запасных кодов').to.eql(0);",
                  "  pm.expect(j.assurance, 'assurance').to.eql({level: '2', level2Reachable: false, missingForLevel2: []});",
                  "});",
                  *_capture_cookie("kaname_session", "sfSessionCookie", "REMOVE"),
              ]),
        _status_step("status-after-remove", [
            "pm.test('STATUS: не заведён, набора нет', () => {",
            "  pm.expect(j.totp && j.totp.enrolled, 'фактор заведён').to.eql(false);",
            "  pm.expect(Object.prototype.hasOwnProperty.call(j, 'backupCodes'), 'сводка набора в ответе').to.eql(false);",
            "});",
        ]),
        *_logout_steps("after-remove"),
        _refused_login("login-wrong-password-with-code-after-remove", "WRONG-PW-WITH-CODE", password="not-the-password-{{runId}}",
                       second_factor={"method": "totp", "code": "000000"}, keep="sfWrongPasswordRefusalBody"),
        _refused_login("login-with-code-after-remove", "NOT-ENROLLED-ON-LOGIN", body_var_equal="sfWrongPasswordRefusalBody",
                       second_factor={"method": "totp", "code": "000000"}),
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
        _post("enroll-with-step-up-token", _ENROLL, {"csrfToken": "{{sfCsrfStepUp}}"}, [],
              _refusal(403, 7, "form token rejected", "FOREIGN-TOKEN", reason="FORM_TOKEN_REJECTED")),
        _post("confirm-without-code", _CONFIRM, {"csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              _refusal(400, 3, "Illegal argument code: required", "NO-CODE")),
        _step_up("step-up-method-outside-vocabulary", {"method": "sms", "code": "123456", "csrfToken": "{{sfCsrfStepUp}}"}, [],
                 _refusal(400, 3, "Illegal argument method: must be one of password|totp|lookup_secret", "BAD-METHOD")),
        _post("confirm-without-pending-enrollment", _CONFIRM, {"code": "123456", "csrfToken": "{{sfCsrfSecondFactor}}"}, [],
              _refusal(400, 9, "no pending enrollment: begin with enroll", "NOT-PENDING", reason="ENROLLMENT_NOT_PENDING")),
        *_logout_steps("after-negatives"),
    ],
))
