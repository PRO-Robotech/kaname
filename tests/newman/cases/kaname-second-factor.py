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
  {{standMailboxUrl}}    — чтение приёмника писем стенда (`stand-mailbox.py`; посев):
                           им кейсы со своим человеком читают код подтверждения
                           адреса и код восстановления

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
снова заводит фактор с нуля. Кейсы со СВОИМ человеком (Ф12-19, Ф12-31, Ф12-32,
Ф12-46 и кейс окна профиля) стоят после хребта и человека посева не трогают: у
каждого свой адрес, свой источник и свой принятый шаг строки.

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
Последний кейс ждёт окна профиля (`addressWindow`, `selfServiceFreshness` — по
15 мин): набор идёт на эти минуты дольше, и предел шага задания назван этим
числом, а не взят с запасом.

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
  IAM-2FA-OK-ASSURANCE-NAMES-WHAT-IS-MISSING
                                          — Ф12-19: сессия восстановления личности с
                                            фактором кодом по времени — «1»,
                                            недостаёт пароля; затем пароль и код —
                                            «2»; сессия входа паролем той же
                                            личности кодом — «2»; личность без
                                            фактора паролем — «1», путь к «2» закрыт
  IAM-2FA-NEG-FIRST-FACTOR-SUCCESS-DOES-NOT-RESET
                                          — Ф12-46: вход паролем между неверными
                                            кодами счёт по адресу не обнуляет —
                                            (N+1)-й код 429; близнец — верный код
                                            между сериями обнуляет: во второй серии
                                            N-й 401, (N+1)-й 429
  IAM-2FA-NEG-CODE-GUESSING-RATE          — Ф12-31: (а) N неверных, (N+1)-й верный
                                            — 429 и не сверяется; (б) N−1 неверных
                                            паролей и неверный код — один счёт; (в)
                                            по источнику — 429 при незадетом адресе,
                                            тот же код со своего источника — 200;
                                            (д) успех кода обнуляет счёт
  IAM-2FA-OK-REFUSALS-ARE-NOT-ATTEMPTS    — Ф12-32: после N−1 неверных отказ формы
                                            и отказ признака счёта не растят; у
                                            личности без фактора — отказы «не
                                            заведён» и «нет ожидающего заведения»
  IAM-2FA-BVA-PROFILE-WINDOW-ELAPSED      — окно профиля прошло, ожидание одно на
                                            четыре ветви: Ф12-31 (г) — по истечении
                                            Retry-After верный код 200, «2»; Ф12-09 —
                                            заведение из несвежей сессии 403
                                            SESSION_NOT_FRESH, строки нет, носитель
                                            годен; Ф12-10 — пароль в той же сессии
                                            освежает окно, «1», заведение 200;
                                            Ф12-32 — отказ по свежести после N−1
                                            неверных счёта не растит; Ф12-04 (а) —
                                            истёкшее заведение в освежённой сессии
                                            400 ENROLLMENT_NOT_PENDING побайтово как
                                            не начатое, при истёкших обоих — 403
                                            свежести, новое заведение — 200
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — и почему; идентификаторы здесь стоят КОММЕНТАРИЕМ,
# а не строкой: перепись долга (`.github/scripts/newman-suite-debt.py`) считает
# позицию несомой по строковому литералу модуля, и упоминание «не утверждаем»
# строкой зачло бы её набору.
#   · гонки Ф12-07 и Ф12-24 — уровень I, интеграция;
#   · Ф12-32 — недоступность материала (Ф12-35) и исчерпание ёмкости
#     проверяющего на запасном коде (PWV-15): «Дано» стенд не строит (перекатка
#     процесса с другим ключом обёртки, подставной проверяющий), позиция —
#     «E + I», эти два исхода держит уровень I (kaname#480); отказ по свежести
#     несёт кейс IAM-2FA-BVA-PROFILE-WINDOW-ELAPSED, прочие четыре исхода —
#     кейс IAM-2FA-OK-REFUSALS-ARE-NOT-ATTEMPTS;
#   · неразличимость по времени Ф12-33 — измерительная, приборы этой формы в
#     дереве — ручка уровня I;
#   · заведение, снятое уборкой, Ф12-04 (б): момент прохода уборки чёрному ящику
#     не виден и профилем не задаётся, а проход уборки держит уровень I (Ф12-44);
#     ветви (а) и (в) несут кейсы окна профиля и формы;
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


# ═══════════════════════════════════════════════════════════════════════════
# СВОЙ НА ПРОГОН ЧЕЛОВЕК С ФАКТОРОМ (Ф12-19, Ф12-31, Ф12-32, Ф12-46).
#
# Частоту подбора и ответ церемонии на трёх сессиях нельзя мерить на человеке
# посева: N неверных в одном окне запирают его адрес на окно профиля, и
# следующий кейс, набор и прогон краснеют по частоте, а восстановление меняет
# ему пароль. Поэтому каждый кейс ниже заводит людей сам — глаголами полосы:
# регистрация → код письма регистрации у приёмника стенда (`GET /codes`, та же
# дверь, что у набора восстановления) → подтверждение адреса → заведение и
# подтверждение фактора. Адрес — `{{runId}}` и случайная добавка, источник — свой
# у каждого человека: счёт по источнику успехом не обнуляется.
#
# ПРИНЯТЫЙ ШАГ — У СТРОКИ КАЖДОГО ЧЕЛОВЕКА (Р5): свой `<p>LastStep`, и код берётся
# ступенью `max(последний + 1, текущая)` — как у человека посева (`_TOTP_JS`).
#
# ВЕЛИЧИНЫ ЧАСТОТЫ — ИЗ ПРОФИЛЯ, С КОТОРЫМ СТЕНД ПОДНЯТ: `chart-own` ставит
# `deploy/values.prod.yaml` как есть, и N, окно и N источника читаются оттуда
# (та же форма, что у набора входа, `kaname-login-lane.py`).
# ═══════════════════════════════════════════════════════════════════════════

import pathlib as _fp_pathlib
import re as _fp_re
import urllib.parse as _fp_urlparse

_FP_PROFILE = _fp_pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _fp_profile(key):
    found = _fp_re.findall(rf"^    {key}: (\S+)\s*$", _FP_PROFILE.read_text(encoding="utf-8"), _fp_re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-second-factor: ключ профиля authn.login.{key} найден "
                         f"{len(found)} раз в {_FP_PROFILE} — ждали ровно один")
    return found[0]


def _fp_seconds(duration):
    m = _fp_re.fullmatch(r"(\d+)([smh])", duration)
    if m is None:
        raise SystemExit(f"kaname-second-factor: срок {duration!r} не в форме <число><s|m|h>")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


_N_ADDR = int(_fp_profile("addressAttempts"))
_T_ADDR = _fp_seconds(_fp_profile("addressWindow"))
_N_SRC = int(_fp_profile("sourceAttempts"))
_T_SRC = _fp_seconds(_fp_profile("sourceWindow"))
if _N_ADDR < 2:
    raise SystemExit("kaname-second-factor: addressAttempts < 2 — близнецы N−1 и серии Ф12-31 (д) не строятся")

_FP_MAILBOX_WHY = ("чтение приёмника писем стенда посадки `own`; адрес пишет посев "
                   "полосы входа — вне стенда `own` приёмника нет, и это условие, "
                   "которого стенд не создал")
_FP_REGISTER = "/iam/v1/auth/register"
_FP_RECOVERY = "/iam/v1/auth/recovery"
_FP_RECOVERY_COMPLETE = "/iam/v1/auth/recovery/complete"
_FP_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
_FP_HEADS = {"Verify": "Код подтверждения:", "Recovery": "Код восстановления:"}
_FP_MAIL_WAIT_CAP = 90
_FP_MAIL_WAIT_MS = 1000
_TOO_MANY = "too many attempts; try again later"

# Ядро кода по времени — то же вычисление, что `_TOTP_JS`, без переменных
# человека посева: строки до определения ступени.
_FP_TOTP_CORE = _TOTP_JS[:_TOTP_JS.index("const __stepNow = () => Math.floor(Date.now() / 1000 / 30);") + 1]


def _fp(p, name):
    return p + name


def _fp_totp_js(p):
    return [
        *_FP_TOTP_CORE,
        f"const __lastStep = () => parseInt(pm.environment.get({js_str(_fp(p, 'LastStep'))}) || '0', 10);",
        "const __freshStep = () => Math.max(__lastStep() + 1, __stepNow());",
        "const __wrongCode = (secretB32) => {",
        "  const now = __stepNow();",
        "  const near = [now - 1, now, now + 1].map(s => __totp(secretB32, s));",
        "  for (let i = 0; i < 1000; i++) { const c = String(i).padStart(6, '0'); if (!near.includes(c)) { return c; } }",
        "  return '999999';",
        "};",
    ]


def _fp_src(p, var="Src"):
    return [f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: pm.environment.get({js_str(_fp(p, var))}) || ''}});"]


def _fp_cookies(p, with_session):
    pairs = [("kaname_form", _fp(p, "FormCookie"))]
    if with_session:
        pairs.append(("kaname_session", _fp(p, with_session)))
    return _with_cookies(*pairs)


def _fp_init(p, tag):
    return [
        "{",
        "  const __nonce = () => Math.floor(Math.random() * 2176782336).toString(36);",
        "  const __domain = String(pm.environment.get('loginLaneEmail') || '').split('@')[1] || 'kaname.local';",
        f"  pm.environment.set({js_str(_fp(p, 'Email'))}, ({js_str('sf-' + tag + '-')} + pm.environment.get('runId') + '-' + __nonce() + '@' + __domain).toLowerCase());",
        f"  pm.environment.set({js_str(_fp(p, 'Password'))}, 'Pw-' + __nonce() + __nonce() + '-first');",
        f"  pm.environment.set({js_str(_fp(p, 'NewPassword'))}, 'Pw-' + __nonce() + __nonce() + '-renewed');",
        f"  pm.environment.set({js_str(_fp(p, 'Src'))}, '198.20.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));",
        *(f"  pm.environment.set({js_str(_fp(p, kind + 'Seen'))}, '0');" for kind in _FP_HEADS),
        *(f"  pm.environment.unset({js_str(_fp(p, n))});" for n in (
            "FormCookie", "SessionCookie", "LoginSessionCookie", "RecoveredCookie", "Csrf", "Secret",
            "LastStep", "PresentedStep", "Code", "VerifyCode", "RecoveryCode", "BackupCodes", "BackupCode")),
        "}",
    ]


def _fp_status(code, label):
    return [f"pm.test({js_str(label + f': ответ {code}')}, () => pm.expect(pm.response.code, 'код ответа').to.eql({code}));"]


def _fp_refused(status, grpc, text, label, reason=None):
    out = [
        *_fp_status(status, label),
        "let __r = {}; try { __r = pm.response.json(); } catch (e) { __r = {}; }",
        f"pm.test({js_str(label + f': код отказа {grpc}')}, () => pm.expect(__r.code, 'код отказа').to.eql({grpc}));",
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => pm.expect(__r.message, 'текст отказа').to.eql({js_str(text)}));",
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, 'печений сессии').to.eql(0));",
    ]
    if reason:
        out += [
            "const __info = (Array.isArray(__r.details) ? __r.details : [])"
            ".filter(d => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            f"pm.test({js_str(label + ': признак отказа ' + reason)}, () => pm.expect(__info.reason, 'признак отказа').to.eql({js_str(reason)}));",
        ]
    return out


def _fp_too_many(label, window):
    return [
        *_fp_refused(429, 8, _TOO_MANY, label, reason="TOO_MANY_ATTEMPTS"),
        f"pm.test({js_str(label + ': Retry-After — секунды до конца окна, в [1, ' + str(window) + ']')}, () => {{",
        "  const ra = pm.response.headers.get('Retry-After');",
        f"  pm.expect(/^[0-9]+$/.test(String(ra)) && Number(ra) >= 1 && Number(ra) <= {window}, 'Retry-After в окне').to.eql(true);",
        "});",
    ]


def _fp_capture(p, cookie, var, label, required=True):
    lines = [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(cookie + '=')}));",
    ]
    if required:
        lines.append(f"  pm.test({js_str(label + ': ответ ставит печенье ' + cookie)}, () => pm.expect(__sc.length, {js_str('печений ' + cookie)}).to.eql(1));")
    lines += [
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(_fp(p, var))}, __sc[0].value.split(';')[0].slice({len(cookie) + 1})); }}",
        "}",
    ]
    return lines


def _fp_csrf(p, name, form, *, with_session="SessionCookie", init=None, src="Src"):
    path = f"{_CSRF}?form={form}"
    label = name.upper()
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*(init or []), *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
                    *_fp_src(p, src), *_fp_cookies(p, with_session)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_fp_status(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.test({js_str(label + ': признак формы выдан строкой')}, () => "
            "pm.expect(typeof __j.csrfToken === 'string' && __j.csrfToken.length > 0, 'признак формы').to.eql(true));",
            f"pm.environment.set({js_str(_fp(p, 'Csrf'))}, __j.csrfToken || '');",
            *_fp_capture(p, "kaname_form", "FormCookie", label, required=False),
        ],
    )


def _fp_post(p, name, path, body, *, with_session=None, pre=(), tests=(), src="Src"):
    return Step(
        name=name, method="POST", path=path, body=body,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_fp_src(p, src),
                    *_fp_cookies(p, with_session), *pre],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=list(tests),
    )


def _fp_await_letter(p, name, kind):
    """Письмо вида `kind` СВЕРХ уже прочитанных: петля с настоящей паузой.

    Утверждения исполняются на КАЖДОМ опросе и краснеют только при исчерпанном
    пределе: письма нет — «не дошло в пределе», а не «пока нет»."""
    heading = _FP_HEADS[kind]
    path = f"/codes?to={{{{{_fp(p, 'Email')}}}}}&after={_fp_urlparse.quote(heading)}"
    counter = f"_sfmb_{p}_{name}".replace("-", "_")
    seen, store, label = _fp(p, kind + "Seen"), _fp(p, kind + "Code"), name.upper()
    return Step(
        name=name, method="GET", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[*require_env_url("standMailboxUrl", path, _FP_MAILBOX_WHY)],
        test_script=[
            f"const __n = parseInt(pm.environment.get({js_str(counter)}) || '0', 10);",
            f"const __seen = parseInt(pm.environment.get({js_str(seen)}) || '0', 10);",
            "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
            "const __got = Array.isArray(__codes) ? __codes.filter(c => typeof c === 'string' && c.length > 0) : [];",
            "const __ready = __got.length > __seen;",
            *_fp_status(200, label),
            f"pm.test({js_str(label + ': письмо дошло до приёмника стенда в пределе ожидания')}, () => "
            f"pm.expect(__ready || __n < {_FP_MAIL_WAIT_CAP}, 'письмо дошло').to.eql(true));",
            f"if (pm.response.code === 200 && !__ready && __n < {_FP_MAIL_WAIT_CAP}) {{",
            f"  pm.environment.set({js_str(counter)}, String(__n + 1));",
            f"  const _sfd = Date.now(); while (Date.now() - _sfd < {_FP_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(counter)});",
            "  if (__ready) {",
            f"    pm.environment.set({js_str(store)}, __got[__got.length - 1]);",
            f"    pm.environment.set({js_str(seen)}, String(__got.length));",
            "  }",
            "}",
        ],
    )


def _fp_person(p, tag, *, factor=True):
    """Человек кейса: регистрация → код письма → адрес подтверждён → (фактор).

    С фактором — строка `active` (подтверждение кодом ступени «сейчас»), секрет в
    `<p>Secret`, набор запасных кодов в `<p>BackupCodes`, принятый шаг в
    `<p>LastStep`; носитель подтверждения — в `<p>SessionCookie`."""
    up = tag.upper()
    steps = [
        _fp_csrf(p, f"{tag}-csrf-register", "register", with_session=None, init=_fp_init(p, tag)),
        _fp_post(p, f"{tag}-register", _FP_REGISTER,
                 {"email": f"{{{{{_fp(p, 'Email')}}}}}", "password": f"{{{{{_fp(p, 'Password')}}}}}",
                  "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                 tests=[*_fp_status(200, f"{up}-REGISTER"),
                        *_fp_capture(p, "kaname_session", "SessionCookie", f"{up}-REGISTER"),
                        *_fp_capture(p, "kaname_form", "FormCookie", f"{up}-REGISTER", required=False)]),
        _fp_await_letter(p, f"{tag}-verify-letter", "Verify"),
        _fp_csrf(p, f"{tag}-csrf-verify", "verify-email-confirm"),
        _fp_post(p, f"{tag}-verify", _FP_VERIFY_CONFIRM,
                 {"code": f"{{{{{_fp(p, 'VerifyCode')}}}}}", "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                 with_session="SessionCookie",
                 tests=[*_fp_status(200, f"{up}-VERIFY"),
                        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                        f"pm.test({js_str(up + '-VERIFY: адрес подтверждён')}, () => "
                        "pm.expect(!!(__j.session && __j.session.emailVerified === true), 'адрес подтверждён').to.eql(true));",
                        *_fp_capture(p, "kaname_session", "SessionCookie", f"{up}-VERIFY")]),
    ]
    if not factor:
        return steps
    return steps + [
        _fp_csrf(p, f"{tag}-csrf-enroll", "second-factor"),
        _fp_post(p, f"{tag}-enroll", _ENROLL, {"csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                 with_session="SessionCookie",
                 tests=[*_fp_status(200, f"{up}-ENROLL"),
                        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                        f"pm.test({js_str(up + '-ENROLL: секрет base32 выдан')}, () => "
                        "pm.expect(/^[A-Z2-7]{32}$/.test(String(__j.secret)), 'форма секрета').to.eql(true));",
                        f"pm.environment.set({js_str(_fp(p, 'Secret'))}, __j.secret || '');",
                        f"pm.environment.unset({js_str(_fp(p, 'LastStep'))});"]),
        _fp_post(p, f"{tag}-confirm-factor", _CONFIRM,
                 {"code": f"{{{{{_fp(p, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                 with_session="SessionCookie", pre=_fp_present(p, f"{up}-CONFIRM"),
                 tests=[*_fp_status(200, f"{up}-CONFIRM"),
                        *_fp_accepted(p),
                        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                        f"pm.test({js_str(up + '-CONFIRM: фактор заведён — сессия «2», десять запасных кодов')}, () => "
                        "pm.expect(!!__j.session && __j.session.assuranceLevel === '2' && Array.isArray(__j.backupCodes) "
                        "&& __j.backupCodes.length === 10, 'фактор заведён').to.eql(true));",
                        f"if (Array.isArray(__j.backupCodes)) {{ pm.environment.set({js_str(_fp(p, 'BackupCodes'))}, JSON.stringify(__j.backupCodes)); }}",
                        *_fp_capture(p, "kaname_session", "SessionCookie", f"{up}-CONFIRM")]),
    ]


def _fp_present(p, label):
    """Pre-script: код ступени `max(последний + 1, текущая)` в `<p>Code`."""
    return [
        *_fp_totp_js(p),
        "const __s = __freshStep();",
        f"pm.environment.set({js_str(_fp(p, 'PresentedStep'))}, String(__s));",
        f"pm.environment.set({js_str(_fp(p, 'Code'))}, __totp(pm.environment.get({js_str(_fp(p, 'Secret'))}), __s));",
        f"pm.test({js_str(label + ': ступень кода старше принятой и в окне ±1')}, () => "
        "pm.expect(__s <= __stepNow() + 1, 'ступень в окне').to.eql(true));",
    ]


def _fp_wrong(p):
    """Pre-script: код, которого нет ни на одной ступени окна, — в `<p>Code`."""
    return [*_fp_totp_js(p),
            f"pm.environment.set({js_str(_fp(p, 'Code'))}, __wrongCode(pm.environment.get({js_str(_fp(p, 'Secret'))})));"]


def _fp_backup(p, index, label):
    return [
        "let __set = [];",
        f"try {{ __set = JSON.parse(pm.environment.get({js_str(_fp(p, 'BackupCodes'))}) || '[]'); }} catch (e) {{ __set = []; }}",
        f"pm.test({js_str(label + ': набор запасных кодов захвачен подтверждением фактора')}, () => "
        f"pm.expect(Array.isArray(__set) && typeof __set[{index}] === 'string', 'набор на месте').to.eql(true));",
        f"pm.environment.set({js_str(_fp(p, 'BackupCode'))}, Array.isArray(__set) && typeof __set[{index}] === 'string' ? __set[{index}] : '');",
    ]


def _fp_accepted(p):
    return [f"if (pm.response.code === 200) {{ pm.environment.set({js_str(_fp(p, 'LastStep'))}, pm.environment.get({js_str(_fp(p, 'PresentedStep'))})); }}"]


def _fp_await_step(p, name, form, session_var, label):
    """Ожидание ступени часов: код ступени `последний + 1` должен лечь в окно ±1
    (часы — не младше `последний`). Опрос признака формы `form` с настоящей
    паузой и конечным пределом; его последний признак нужен следующему шагу."""
    path = f"{_CSRF}?form={form}"
    polls = f"_sfaw_{p}_{name}".replace("-", "_")
    cap = 70 * 2
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_fp_src(p),
                    *_fp_cookies(p, session_var)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_fp_status(200, label),
            "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
            f"pm.environment.set({js_str(_fp(p, 'Csrf'))}, __j.csrfToken || '');",
            f"const __last = parseInt(pm.environment.get({js_str(_fp(p, 'LastStep'))}) || '0', 10);",
            f"const __polls = parseInt(pm.environment.get({js_str(polls)}) || '0', 10);",
            "const __ready = Math.floor(Date.now() / 30000) + 1 >= __last + 1;",
            f"pm.test({js_str(label + ': часы дошли до нужной ступени либо ожидание в пределе')}, () => "
            f"pm.expect(__ready || __polls < {cap}, 'ступень часов').to.eql(true));",
            f"if (!__ready && __polls < {cap}) {{",
            f"  pm.environment.set({js_str(polls)}, String(__polls + 1));",
            "  const _w = Date.now(); while (Date.now() - _w < 500) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(polls)});",
            "}",
        ],
    )


def _fp_login(p, name, *, password_var="Password", level="1", into="LoginSessionCookie", src="Src"):
    up = name.upper()
    return [
        _fp_csrf(p, f"{name}-csrf", "login", with_session=None, src=src),
        _fp_post(p, name, _LOGIN,
                 {"email": f"{{{{{_fp(p, 'Email')}}}}}", "password": f"{{{{{_fp(p, password_var)}}}}}",
                  "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"}, src=src,
                 tests=[*_fp_status(200, up),
                        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                        f"pm.test({js_str(up + ': сессия уровня ' + level)}, () => "
                        f"pm.expect(!!__j.session && __j.session.assuranceLevel === {js_str(level)}, 'уровень сессии').to.eql(true));",
                        *_fp_capture(p, "kaname_session", into, up),
                        *_fp_capture(p, "kaname_form", "FormCookie", up, required=False)]),
    ]


def _fp_wrong_logins(p, prefix, count):
    """`count` неверных паролей на входе — 401 каждый."""
    out = [_fp_csrf(p, f"{prefix}-csrf", "login", with_session=None)]
    for i in range(1, count + 1):
        out.append(_fp_post(p, f"{prefix}-{i}", _LOGIN,
                            {"email": f"{{{{{_fp(p, 'Email')}}}}}", "password": f"not-the-password-{i}-{{{{runId}}}}",
                             "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                            tests=_fp_refused(401, 16, _AUTH_FAILED, f"{prefix.upper()}-{i}")))
    return out


def _fp_step_up_wrong(p, name, session_var, *, src="Src", tests=None):
    return _fp_post(p, name, _STEP_UP,
                    {"method": "totp", "code": f"{{{{{_fp(p, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                    with_session=session_var, pre=_fp_wrong(p), src=src,
                    tests=tests if tests is not None else _fp_refused(401, 16, _AUTH_FAILED, name.upper()))


def _fp_wrong_codes(p, prefix, count, session_var, *, src="Src"):
    """`count` неверных кодов в церемонии — 401 каждый; признак формы один."""
    return [_fp_csrf(p, f"{prefix}-csrf", "step-up", with_session=session_var, src=src),
            *[_fp_step_up_wrong(p, f"{prefix}-{i}", session_var, src=src) for i in range(1, count + 1)]]


def _fp_step_up_right(p, name, session_var, tests, *, src="Src"):
    return _fp_post(p, name, _STEP_UP,
                    {"method": "totp", "code": f"{{{{{_fp(p, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                    with_session=session_var, pre=_fp_present(p, name.upper()), src=src,
                    tests=[*tests, *_fp_accepted(p)])


def _fp_level(label, level, reachable, missing):
    return [
        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
        f"pm.test({js_str(label + ': assurance — уровень ' + level + ', level2Reachable ' + str(reachable).lower() + ', missingForLevel2 ' + _json_compact(missing))}, () => "
        "pm.expect(JSON.stringify(__j.assurance), 'assurance').to.eql("
        f"{js_str(_json_compact({'level': level, 'level2Reachable': reachable, 'missingForLevel2': missing}))}));",
    ]


def _json_compact(obj):
    import json as _json
    return _json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ───────────────────────────────────────────────────────────────────────────
# Ф12-19: ответ церемонии называет достигнутый уровень и чего не хватает — на
# трёх сессиях. (б) идёт первым: сессия входа той же личности поднимается кодом
# ступени `t₀ + 1`, которая в окне сразу; (а) ждёт следующую ступень.
# ───────────────────────────────────────────────────────────────────────────
_P19, _P19N = "sfAs", "sfAn"
CASES.append(Case(
    id="IAM-2FA-OK-ASSURANCE-NAMES-WHAT-IS-MISSING",
    title="Ответ церемонии на трёх сессиях: восстановление с фактором кодом — «1», недостаёт пароля; вход паролем кодом — «2»; без фактора паролем — «1», путь к «2» закрыт (Ф12-19)",
    classes=["SEC", "CRUD"],
    priority="P0",
    steps=[
        *_fp_person(_P19, "f19a"),
        # (б) сессия «1» входом паролем той же личности; предъявлен код по времени.
        *_fp_login(_P19, "f19b-login"),
        _fp_csrf(_P19, "f19b-csrf-step-up", "step-up", with_session="LoginSessionCookie"),
        _fp_step_up_right(_P19, "f19b-step-up-totp", "LoginSessionCookie",
                          [*_fp_status(200, "F19B"), *_fp_level("F19B", "2", True, [])]),
        # (а) сессия восстановления: запрос кода, код из письма, новый пароль.
        _fp_csrf(_P19, "f19a-csrf-recovery", "recovery", with_session=None),
        _fp_post(_P19, "f19a-request-recovery", _FP_RECOVERY,
                 {"email": f"{{{{{_fp(_P19, 'Email')}}}}}", "csrfToken": f"{{{{{_fp(_P19, 'Csrf')}}}}}"},
                 tests=[*_fp_status(200, "F19A-REQUEST")]),
        _fp_await_letter(_P19, "f19a-recovery-letter", "Recovery"),
        _fp_csrf(_P19, "f19a-csrf-complete", "recovery-complete", with_session=None),
        _fp_post(_P19, "f19a-complete", _FP_RECOVERY_COMPLETE,
                 {"email": f"{{{{{_fp(_P19, 'Email')}}}}}", "code": f"{{{{{_fp(_P19, 'RecoveryCode')}}}}}",
                  "newPassword": f"{{{{{_fp(_P19, 'NewPassword')}}}}}", "csrfToken": f"{{{{{_fp(_P19, 'Csrf')}}}}}"},
                 tests=[*_fp_status(200, "F19A-COMPLETE"),
                        "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                        "pm.test('F19A-COMPLETE: сессия восстановления — «1»', () => "
                        "pm.expect(!!__j.session && __j.session.assuranceLevel === '1', 'уровень сессии').to.eql(true));",
                        *_fp_capture(_P19, "kaname_session", "RecoveredCookie", "F19A-COMPLETE"),
                        *_fp_capture(_P19, "kaname_form", "FormCookie", "F19A-COMPLETE", required=False)]),
        _fp_await_step(_P19, "f19a-await-step", "step-up", "RecoveredCookie", "F19A-AWAIT"),
        _fp_step_up_right(_P19, "f19a-step-up-totp-only", "RecoveredCookie",
                          [*_fp_status(200, "F19A"), *_fp_level("F19A", "1", True, ["password"]),
                           *_fp_capture(_P19, "kaname_session", "RecoveredCookie", "F19A")]),
        # (а), затем заданный пароль и код — «2» (Ф11-29). Код — запасной: предмет
        # здесь порядок предъявлений, а не способ, и ступени часов ждать незачем.
        _fp_csrf(_P19, "f19a-csrf-password", "step-up", with_session="RecoveredCookie"),
        _fp_post(_P19, "f19a-step-up-password", _STEP_UP,
                 {"method": "password", "password": f"{{{{{_fp(_P19, 'NewPassword')}}}}}",
                  "csrfToken": f"{{{{{_fp(_P19, 'Csrf')}}}}}"},
                 with_session="RecoveredCookie",
                 tests=[*_fp_status(200, "F19A-PASSWORD"),
                        *_fp_capture(_P19, "kaname_session", "RecoveredCookie", "F19A-PASSWORD")]),
        _fp_post(_P19, "f19a-step-up-code-after-password", _STEP_UP,
                 {"method": "lookup_secret", "code": f"{{{{{_fp(_P19, 'BackupCode')}}}}}",
                  "csrfToken": f"{{{{{_fp(_P19, 'Csrf')}}}}}"},
                 with_session="RecoveredCookie", pre=_fp_backup(_P19, 0, "F19A-CODE"),
                 tests=[*_fp_status(200, "F19A-CODE"), *_fp_level("F19A-CODE", "2", True, [])]),
        # (в) личность без фактора, сессия «1»; предъявлен пароль.
        *_fp_person(_P19N, "f19c", factor=False),
        _fp_csrf(_P19N, "f19c-csrf-step-up", "step-up"),
        _fp_post(_P19N, "f19c-step-up-password", _STEP_UP,
                 {"method": "password", "password": f"{{{{{_fp(_P19N, 'Password')}}}}}",
                  "csrfToken": f"{{{{{_fp(_P19N, 'Csrf')}}}}}"},
                 with_session="SessionCookie",
                 tests=[*_fp_status(200, "F19C"), *_fp_level("F19C", "1", False, [])]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-46: успех ПЕРВОГО фактора счёт подбора кода не обнуляет; обнуляет успех
# КОДА. Две личности — отличающий факт один: что предъявлено успешно между
# сериями, пароль (а) либо код, доводящий до «2» (б).
# ───────────────────────────────────────────────────────────────────────────
_P46A, _P46B = "sfLa", "sfLb"
_F46_FIRST = 2
CASES.append(Case(
    id="IAM-2FA-NEG-FIRST-FACTOR-SUCCESS-DOES-NOT-RESET",
    title=f"N={_N_ADDR}: вход паролем между неверными кодами счёт не обнуляет — (N+1)-й код 429; верный код между сериями обнуляет — вторая серия N-й 401, (N+1)-й 429 (Ф12-46)",
    classes=["SEC", "BVA", "NEG"],
    priority="P0",
    steps=[
        *_fp_person(_P46A, "f46a"),
        *_fp_login(_P46A, "f46a-login"),
        *_fp_wrong_codes(_P46A, "f46a-before-login", _F46_FIRST, "LoginSessionCookie"),
        *_fp_login(_P46A, "f46a-password-success-between"),
        *_fp_wrong_codes(_P46A, "f46a-after-login", _N_ADDR - _F46_FIRST, "LoginSessionCookie"),
        _fp_step_up_wrong(_P46A, "f46a-code-n-plus-1", "LoginSessionCookie",
                          tests=_fp_too_many("F46A-N+1", _T_ADDR)),
        *_fp_person(_P46B, "f46b"),
        *_fp_login(_P46B, "f46b-login"),
        *_fp_wrong_codes(_P46B, "f46b-first-series", _N_ADDR - 1, "LoginSessionCookie"),
        _fp_step_up_right(_P46B, "f46b-right-code", "LoginSessionCookie",
                          [*_fp_status(200, "F46B-RIGHT"), *_fp_level("F46B-RIGHT", "2", True, []),
                           *_fp_capture(_P46B, "kaname_session", "LoginSessionCookie", "F46B-RIGHT")]),
        *_fp_wrong_codes(_P46B, "f46b-second-series", _N_ADDR, "LoginSessionCookie"),
        _fp_step_up_wrong(_P46B, "f46b-code-n-plus-1", "LoginSessionCookie",
                          tests=_fp_too_many("F46B-N+1", _T_ADDR)),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-31: N неверных кодов → отказ по частоте; счёт общий с паролем; по
# источнику; обнуление. Ветвь (г) — «после окна» — несёт последний кейс набора:
# её «Дано» — время, и ожидание у того кейса одно на четыре ветви.
#
# (в) — ЛИЧНОСТЕЙ СТОЛЬКО, СКОЛЬКО НУЖНО, ЧТОБЫ АДРЕСНЫЙ СЧЁТ НЕ ЗАДЕТЬ. Приёмка
# кладёт по одному коду на личность, чтобы отказ пришёл по источнику, а не по
# адресу. Тем же условием служит не больше N − 1 кодов на личность: адресный счёт
# каждой остаётся ниже N. Личностей ⌈N_источник / (N − 1)⌉ вместо N_источник —
# свойство то же (отказ по источнику, адрес не задет ни у одной), а заведение
# человека с фактором — семь обращений и письмо.
# ───────────────────────────────────────────────────────────────────────────
_P31A, _P31B, _P31E = "sfGa", "sfGb", "sfGe"
_P31C = [f"sfGc{i}" for i in range(1, -(-_N_SRC // (_N_ADDR - 1)) + 1)]
_P31C_NEXT = "sfGcx"
_F31C_SPLIT = [min(_N_ADDR - 1, _N_SRC - i * (_N_ADDR - 1)) for i in range(len(_P31C))]
if sum(_F31C_SPLIT) != _N_SRC or max(_F31C_SPLIT) > _N_ADDR - 1 or min(_F31C_SPLIT) < 1:
    raise SystemExit(f"kaname-second-factor: раскладка Ф12-31 (в) {_F31C_SPLIT} не даёт N_источник={_N_SRC} "
                     f"при не больше {_N_ADDR - 1} на личность")
# Общий источник ветви (в): свой у прогона, записан первым шагом.
_F31C_SRC_INIT = ["pm.environment.set('sfGcSharedSrc', '198.21.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));"]


def _f31c_on_shared(p):
    """Источник общей ветви — переменная человека `<p>SharedSrc`."""
    return [f"pm.environment.set({js_str(_fp(p, 'SharedSrc'))}, pm.environment.get('sfGcSharedSrc') || '');"]


_F31C_STEPS = []
for _i, (_p, _k) in enumerate(zip(_P31C, _F31C_SPLIT), start=1):
    _F31C_STEPS += [*_fp_person(_p, f"f31c-{_i}"), *_fp_login(_p, f"f31c-{_i}-login")]
    _csrf = _fp_csrf(_p, f"f31c-{_i}-csrf-shared", "step-up", with_session="LoginSessionCookie", src="SharedSrc")
    _csrf.pre_script = [*_f31c_on_shared(_p), *_csrf.pre_script]
    _F31C_STEPS += [_csrf, *[_fp_step_up_wrong(_p, f"f31c-{_i}-wrong-{_j}", "LoginSessionCookie", src="SharedSrc")
                             for _j in range(1, _k + 1)]]
_F31C_STEPS += [*_fp_person(_P31C_NEXT, "f31c-next"), *_fp_login(_P31C_NEXT, "f31c-next-login")]
_csrf = _fp_csrf(_P31C_NEXT, "f31c-next-csrf-shared", "step-up", with_session="LoginSessionCookie", src="SharedSrc")
_csrf.pre_script = [*_f31c_on_shared(_P31C_NEXT), *_csrf.pre_script]
_F31C_STEPS += [
    _csrf,
    _fp_step_up_right(_P31C_NEXT, "f31c-next-right-code-refused-by-source", "LoginSessionCookie",
                      _fp_too_many("F31C-SOURCE", _T_SRC), src="SharedSrc"),
    # Близнец: тот же код той же личности со своего источника — адрес не задет.
    _fp_csrf(_P31C_NEXT, "f31c-next-csrf-own-source", "step-up", with_session="LoginSessionCookie"),
    _fp_step_up_right(_P31C_NEXT, "f31c-next-right-code-own-source", "LoginSessionCookie",
                      [*_fp_status(200, "F31C-OWN-SOURCE"), *_fp_level("F31C-OWN-SOURCE", "2", True, [])]),
]
_F31C_STEPS[0].pre_script = [*_F31C_SRC_INIT, *_F31C_STEPS[0].pre_script]

CASES.append(Case(
    id="IAM-2FA-NEG-CODE-GUESSING-RATE",
    title=f"N={_N_ADDR}, N_источник={_N_SRC}: (N+1)-й верный код — 429 и не сверяется; пароль и код — один счёт; по источнику — 429 при незадетом адресе; успех кода обнуляет счёт (Ф12-31)",
    classes=["SEC", "BVA", "NEG"],
    priority="P0",
    steps=[
        # (а) N неверных, затем верный — 429, носитель не перевыпущен.
        *_fp_person(_P31A, "f31a"),
        *_fp_login(_P31A, "f31a-login"),
        *_fp_wrong_codes(_P31A, "f31a-wrong", _N_ADDR, "LoginSessionCookie"),
        _fp_step_up_right(_P31A, "f31a-right-code-refused", "LoginSessionCookie",
                          [*_fp_too_many("F31A", _T_ADDR),
                           "pm.test('F31A: верный код не сверен — носитель не перевыпущен, уровень прежний', () => "
                           "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').length, 'печений').to.eql(0));"]),
        # (б) N − 1 неверных паролей, N-й — неверный код, (N + 1)-й — верный код.
        *_fp_person(_P31B, "f31b"),
        *_fp_login(_P31B, "f31b-login"),
        *_fp_wrong_logins(_P31B, "f31b-wrong-password", _N_ADDR - 1),
        *_fp_wrong_codes(_P31B, "f31b-wrong-code", 1, "LoginSessionCookie"),
        _fp_step_up_right(_P31B, "f31b-right-code-refused", "LoginSessionCookie", _fp_too_many("F31B", _T_ADDR)),
        # (в) по источнику.
        *_F31C_STEPS,
        # (д) N − 1 неверных, верный, снова N − 1 неверных, верный — оба 200.
        *_fp_person(_P31E, "f31e"),
        *_fp_login(_P31E, "f31e-login"),
        *_fp_wrong_codes(_P31E, "f31e-first-series", _N_ADDR - 1, "LoginSessionCookie"),
        _fp_step_up_right(_P31E, "f31e-first-right", "LoginSessionCookie",
                          [*_fp_status(200, "F31E-FIRST"),
                           *_fp_capture(_P31E, "kaname_session", "LoginSessionCookie", "F31E-FIRST")]),
        *_fp_wrong_codes(_P31E, "f31e-second-series", _N_ADDR - 1, "LoginSessionCookie"),
        # Второй верный — запасной код: предмет — обнуление успехом кода, и ступени
        # часов ждать незачем.
        _fp_post(_P31E, "f31e-second-right", _STEP_UP,
                 {"method": "lookup_secret", "code": f"{{{{{_fp(_P31E, 'BackupCode')}}}}}",
                  "csrfToken": f"{{{{{_fp(_P31E, 'Csrf')}}}}}"},
                 with_session="LoginSessionCookie", pre=_fp_backup(_P31E, 0, "F31E-SECOND"),
                 tests=[*_fp_status(200, "F31E-SECOND")]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф12-32: что попыткой НЕ считается. N − 1 неверных плюс любой сосчитанный
# промежуточный дали бы N, и верное предъявление получило бы 429.
# Отказ по свежести несёт последний кейс набора — его «Дано» время. Недоступность
# материала (Ф12-35) и исчерпание ёмкости проверяющего (PWV-15) стенд не строит —
# их держит уровень I позиции («E + I»), запись — в шапке набора.
# ───────────────────────────────────────────────────────────────────────────
_P32A, _P32B = "sfNa", "sfNb"
CASES.append(Case(
    id="IAM-2FA-OK-REFUSALS-ARE-NOT-ATTEMPTS",
    title=f"N={_N_ADDR}: после N−1 неверных отказ формы и отказ признака счёта не растят — верный код проходит; у личности без фактора SECOND_FACTOR_NOT_ENROLLED и ENROLLMENT_NOT_PENDING — тоже (Ф12-32)",
    classes=["SEC", "BVA", "NEG"],
    priority="P1",
    steps=[
        *_fp_person(_P32A, "f32a"),
        *_fp_login(_P32A, "f32a-login"),
        *_fp_wrong_codes(_P32A, "f32a-wrong", _N_ADDR - 1, "LoginSessionCookie"),
        _fp_post(_P32A, "f32a-form-refusal", _STEP_UP, {"method": "totp", "csrfToken": f"{{{{{_fp(_P32A, 'Csrf')}}}}}"},
                 with_session="LoginSessionCookie",
                 tests=_fp_refused(400, 3, "Illegal argument code: required", "F32A-FORM")),
        _fp_csrf(_P32A, "f32a-csrf-foreign-kind", "logout", with_session="LoginSessionCookie"),
        _fp_post(_P32A, "f32a-token-refusal", _STEP_UP,
                 {"method": "totp", "code": "000000", "csrfToken": f"{{{{{_fp(_P32A, 'Csrf')}}}}}"},
                 with_session="LoginSessionCookie",
                 tests=_fp_refused(403, 7, "form token rejected", "F32A-TOKEN", reason="FORM_TOKEN_REJECTED")),
        _fp_csrf(_P32A, "f32a-csrf-right", "step-up", with_session="LoginSessionCookie"),
        _fp_step_up_right(_P32A, "f32a-right-code", "LoginSessionCookie",
                          [*_fp_status(200, "F32A-RIGHT"), *_fp_level("F32A-RIGHT", "2", True, [])]),
        *_fp_person(_P32B, "f32b", factor=False),
        *_fp_wrong_logins(_P32B, "f32b-wrong-password", _N_ADDR - 1),
        _fp_csrf(_P32B, "f32b-csrf-step-up", "step-up"),
        _fp_post(_P32B, "f32b-not-enrolled", _STEP_UP,
                 {"method": "totp", "code": "000000", "csrfToken": f"{{{{{_fp(_P32B, 'Csrf')}}}}}"},
                 with_session="SessionCookie",
                 tests=_fp_refused(400, 9, _NOT_ENROLLED[0], "F32B-NOT-ENROLLED", reason=_NOT_ENROLLED[1])),
        _fp_csrf(_P32B, "f32b-csrf-confirm", "second-factor"),
        _fp_post(_P32B, "f32b-not-pending", _CONFIRM,
                 {"code": "000000", "csrfToken": f"{{{{{_fp(_P32B, 'Csrf')}}}}}"},
                 with_session="SessionCookie",
                 tests=_fp_refused(400, 9, "no pending enrollment: begin with enroll", "F32B-NOT-PENDING",
                                   reason="ENROLLMENT_NOT_PENDING")),
        *_fp_login(_P32B, "f32b-right-password"),
    ],
))

# ═══════════════════════════════════════════════════════════════════════════
# ОКНО ПРОФИЛЯ ИСТЕКЛО — ОДНО ОЖИДАНИЕ НА ЧЕТЫРЕ ВЕТВИ (kaname#480).
#
# «Дано» каждой ветви ниже — «прошло окно профиля плюс ε», и производит его
# время, а не посев: часов службы у чёрного ящика нет, а поставляемый профиль
# стенд `chart-own` ставит как есть (шапка `.github/scripts/stand-chart.sh`),
# поэтому окно — величина профиля (`authn.login.addressWindow`,
# `authn.selfServiceFreshness`), и читается она отсюда же, из
# `deploy/values.prod.yaml`.
#
# ВЕТВИ ЖДУТ ОДНОГО И ТОГО ЖЕ, И ОЖИДАНИЕ У КЕЙСА ОДНО. Сначала каждая ветвь
# взводит свой срок — момент, после которого её «Дано» наступило; затем шаг
# ожидания опрашивает признак формы с настоящей паузой, пока часы не пройдут
# самый поздний из взведённых сроков; и только после него ветви утверждают исход.
# Порознь четыре ожидания стоили бы четыре окна.
#
# Срок ветви Ф12-31 (г) — не окно, а `Retry-After` отказа по частоте: столько
# секунд до конца окна называет сам продукт (Р10), и ветвь утверждает, что по их
# истечении верный код проходит. Сроки остальных — окно свежести от ОТВЕТА,
# выдавшего сессию либо строку `pending`: сервер отмечает момент раньше ответа,
# поэтому отсчёт от ответа запаздывает, а не опережает. ε — пять секунд: часы
# прогонщика и службы на стенде одни (kind на том же узле), и ε покрывает лишь
# задержку ответа и округление до секунды.
#
# ЧТО ВЕТВИ УТВЕРЖДАЮТ, И ЧТО ИХ РОНЯЕТ:
#   · Ф12-31 (г) — после окна верный код `200`, «2»; до окна тот же код — `429`
#     (ветвь взводится им же — отказ по частоте ДО ожидания и есть её близнец);
#   · Ф12-09 — заведение из сессии входа паролем, в которой после окна не было
#     предъявления, — `403 SESSION_NOT_FRESH`; строки `pending` нет, носитель годен;
#   · Ф12-10 — единственное отличие от Ф12-09 — пароль, предъявленный внутри той же
#     сессии: окно освежено, уровень «1», заведение по новому носителю — `200`;
#   · Ф12-32, исход «отказ по свежести» — после окна `N − 1` неверных кодов, затем
#     отказ по свежести, затем верный код проходит без отказа по частоте: засчитай
#     продукт отказ попыткой, верный код получил бы `429` (Ф12-31 а);
#   · Ф12-04 (а) — заведение истекло, а сессия освежена паролем: `confirm` верным
#     кодом — `400 ENROLLMENT_NOT_PENDING`, тело побайтово равно отказу не
#     начатому (в) той же личности; при истёкших обоих первым отвечает свежесть
#     — `403 SESSION_NOT_FRESH`; положительный контроль — новое заведение и код от
#     него — `200`.
# Инъекция одного факта «окно не прошло» (шаг ожидания снят) роняет каждую ветвь:
# (г) получает `429`, Ф12-09 и отказ Ф12-32 — `200`/`409` вместо `403`, Ф12-04 (а) —
# `200` на истёкшем заведении.
# ═══════════════════════════════════════════════════════════════════════════


def _fp_authn(key):
    found = _fp_re.findall(rf"^  {key}: (\S+)\s*$", _FP_PROFILE.read_text(encoding="utf-8"), _fp_re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-second-factor: ключ профиля authn.{key} найден "
                         f"{len(found)} раз в {_FP_PROFILE} — ждали ровно один")
    return found[0]


_T_FRESH = _fp_seconds(_fp_authn("selfServiceFreshness"))
_NOT_FRESH_TEXT = "re-authentication required: present a credential again"
_NOT_PENDING_TEXT = "no pending enrollment: begin with enroll"

_WIN_DEADLINE = "sfWinDeadline"
_WIN_EPS_MS = 5000
_WIN_POLL_MS = 10000
# Предел опросов — от самого длинного окна плюс время заведения четырёх людей до
# ожидания (регистрация, письмо, фактор): их шаги идут раньше, и их срок —
# позже начала кейса. Исчерпан предел раньше срока — утверждение шага ожидания
# краснеет с названием причины, а не прогон повисает.
_WIN_SETUP_S = 300
_WIN_CAP = -(-((max(_T_ADDR, _T_FRESH) + _WIN_SETUP_S) * 1000) // _WIN_POLL_MS)


def _win_arm_window(seconds):
    """Test-script: срок ветви — ответ + окно + ε; взводится наибольший из сроков."""
    return [
        "{",
        f"  const __cur = parseInt(pm.environment.get({js_str(_WIN_DEADLINE)}) || '0', 10);",
        "  if (pm.response.code === 200) {",
        f"    pm.environment.set({js_str(_WIN_DEADLINE)}, String(Math.max(__cur, Date.now() + {seconds * 1000 + _WIN_EPS_MS})));",
        "  }",
        "}",
    ]


# Срок ветви (г) — `Retry-After` отказа по частоте, названный продуктом.
_WIN_ARM_RETRY_AFTER = [
    "{",
    "  const __ra = String(pm.response.headers.get('Retry-After') || '');",
    f"  const __cur = parseInt(pm.environment.get({js_str(_WIN_DEADLINE)}) || '0', 10);",
    "  if (pm.response.code === 429 && /^[0-9]+$/.test(__ra)) {",
    f"    pm.environment.set({js_str(_WIN_DEADLINE)}, String(Math.max(__cur, Date.now() + Number(__ra) * 1000 + {_WIN_EPS_MS})));",
    "  }",
    "}",
]


def _win_wait(name, src_person):
    """Ожидание самого позднего взведённого срока: опрос признака формы входа с
    настоящей паузой (не дольше `_WIN_POLL_MS` и не дольше остатка) и конечным
    пределом. Утверждения исполняются на КАЖДОМ опросе."""
    path = f"{_CSRF}?form=login"
    polls = "_sfWinPolls"
    label = "WIN-WAIT"
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*require_env_url("loginLaneBaseUrl", path, _LANE_WHY), *_fp_src(src_person)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_fp_status(200, label),
            f"const __deadline = parseInt(pm.environment.get({js_str(_WIN_DEADLINE)}) || '0', 10);",
            f"const __polls = parseInt(pm.environment.get({js_str(polls)}) || '0', 10);",
            "const __ready = Date.now() >= __deadline;",
            f"pm.test({js_str(label + ': срок взведён ветвями кейса')}, () => pm.expect(__deadline > 0, 'срок взведён').to.eql(true));",
            f"pm.test({js_str(label + f': окно профиля прошло либо ожидание в пределе {_WIN_CAP} опросов')}, () => "
            f"pm.expect(__ready || __polls < {_WIN_CAP}, 'окно прошло').to.eql(true));",
            f"if (__deadline > 0 && !__ready && __polls < {_WIN_CAP}) {{",
            f"  pm.environment.set({js_str(polls)}, String(__polls + 1));",
            f"  const __pause = Math.min({_WIN_POLL_MS}, Math.max(0, __deadline - Date.now()));",
            "  const _ww = Date.now(); while (Date.now() - _ww < __pause) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "} else {",
            f"  pm.environment.unset({js_str(polls)});",
            "}",
        ],
    )


def _win_login(p, name):
    """Вход паролем; срок ветви — окно свежести от ответа, выдавшего сессию."""
    steps = _fp_login(p, name)
    steps[-1].test_script = [*steps[-1].test_script, *_win_arm_window(_T_FRESH)]
    return steps


def _fp_enroll(p, name, session_var, tests=()):
    up = name.upper()
    return _fp_post(p, name, _ENROLL, {"csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"}, with_session=session_var,
                    tests=[*_fp_status(200, up),
                           "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                           f"pm.test({js_str(up + ': секрет base32 выдан')}, () => "
                           "pm.expect(/^[A-Z2-7]{32}$/.test(String(__j.secret)), 'форма секрета').to.eql(true));",
                           f"pm.environment.set({js_str(_fp(p, 'Secret'))}, __j.secret || '');",
                           f"pm.environment.unset({js_str(_fp(p, 'LastStep'))});",
                           *tests])


def _fp_state(p, name, session_var, tests):
    """Состояние фактора под носителем `session_var`: `200` — носитель годен."""
    return Step(
        name=name, method="GET", path=_STATUS,
        pre_script=[*require_env_url("loginLaneBaseUrl", _STATUS, _LANE_WHY), *_fp_src(p),
                    *_fp_cookies(p, session_var)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[*_fp_status(200, name.upper()),
                     "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }", *tests],
    )


def _fp_step_up_password(p, name, session_var, tests):
    return _fp_post(p, name, _STEP_UP,
                    {"method": "password", "password": f"{{{{{_fp(p, 'Password')}}}}}",
                     "csrfToken": f"{{{{{_fp(p, 'Csrf')}}}}}"},
                    with_session=session_var, tests=tests)


_PWG, _PWF, _PWP, _PWE = "sfWg", "sfWf", "sfWp", "sfWe"

_WIN_STEPS = [
    # ── взведение ────────────────────────────────────────────────────────────
    # Ф12-31 (г): N неверных кодов, верный — 429; срок — Retry-After ответа.
    *_fp_person(_PWG, "win-g"),
    *_fp_login(_PWG, "win-g-login"),
    *_fp_wrong_codes(_PWG, "win-g-wrong", _N_ADDR, "LoginSessionCookie"),
    _fp_step_up_right(_PWG, "win-g-right-code-in-window", "LoginSessionCookie",
                      [*_fp_too_many("WIN-G-IN-WINDOW", _T_ADDR), *_WIN_ARM_RETRY_AFTER]),
    # Ф12-09/10: у личности только пароль; сессия — входом паролем.
    *_fp_person(_PWF, "win-f", factor=False),
    *_win_login(_PWF, "win-f-login"),
    # Ф12-32: личность с фактором; сессия — входом паролем.
    *_fp_person(_PWP, "win-p"),
    *_win_login(_PWP, "win-p-login"),
    # Ф12-04: (в) до заведения — «не начато», его тело — эталон; затем заведение.
    *_fp_person(_PWE, "win-e", factor=False),
    _fp_csrf(_PWE, "win-e-csrf-not-started", "second-factor"),
    _fp_post(_PWE, "win-e-confirm-not-started", _CONFIRM,
             {"code": "000000", "csrfToken": f"{{{{{_fp(_PWE, 'Csrf')}}}}}"}, with_session="SessionCookie",
             tests=[*_fp_refused(400, 9, _NOT_PENDING_TEXT, "WIN-E-NOT-STARTED", reason="ENROLLMENT_NOT_PENDING"),
                    *_keep_body("sfWeNotPendingRefusalBody")]),
    _fp_csrf(_PWE, "win-e-csrf-enroll", "second-factor"),
    _fp_enroll(_PWE, "win-e-enroll", "SessionCookie", tests=_win_arm_window(_T_FRESH)),
    # ── ожидание ─────────────────────────────────────────────────────────────
    _win_wait("win-wait", _PWG),
    # ── исходы ───────────────────────────────────────────────────────────────
    # Ф12-31 (г): после окна верный код — 200, «2».
    _fp_csrf(_PWG, "win-g-csrf-after-window", "step-up", with_session="LoginSessionCookie"),
    _fp_step_up_right(_PWG, "win-g-right-code-after-window", "LoginSessionCookie",
                      [*_fp_status(200, "WIN-G-AFTER-WINDOW"), *_fp_level("WIN-G-AFTER-WINDOW", "2", True, [])]),
    # Ф12-09: заведение из несвежей сессии — 403 SESSION_NOT_FRESH; строки нет,
    # носитель годен.
    _fp_csrf(_PWF, "win-f-csrf-enroll-not-fresh", "second-factor", with_session="LoginSessionCookie"),
    _fp_post(_PWF, "win-f-enroll-not-fresh", _ENROLL, {"csrfToken": f"{{{{{_fp(_PWF, 'Csrf')}}}}}"},
             with_session="LoginSessionCookie",
             tests=_fp_refused(403, 7, _NOT_FRESH_TEXT, "WIN-F-NOT-FRESH", reason="SESSION_NOT_FRESH")),
    _fp_state(_PWF, "win-f-state-after-refusal", "LoginSessionCookie", [
        "pm.test('WIN-F-STATE-AFTER-REFUSAL: строки pending нет — отказ по свежести заведения не начал', () => "
        "pm.expect(!!__j.totp && __j.totp.enrolled === false "
        "&& !Object.prototype.hasOwnProperty.call(__j.totp, 'pendingUntil'), 'строка pending').to.eql(true));",
    ]),
    # Ф12-10: пароль внутри той же сессии освежает окно; уровень «1»; заведение
    # по новому носителю — 200.
    _fp_csrf(_PWF, "win-f-csrf-step-up-password", "step-up", with_session="LoginSessionCookie"),
    _fp_step_up_password(_PWF, "win-f-step-up-password", "LoginSessionCookie", [
        *_fp_status(200, "WIN-F-PASSWORD"),
        *_fp_level("WIN-F-PASSWORD", "1", False, []),
        f"pm.environment.set({js_str(_fp(_PWF, 'OldLoginSessionCookie'))}, pm.environment.get({js_str(_fp(_PWF, 'LoginSessionCookie'))}) || '');",
        *_fp_capture(_PWF, "kaname_session", "LoginSessionCookie", "WIN-F-PASSWORD"),
        "pm.test('WIN-F-PASSWORD: носитель перевыпущен — новое значение', () => "
        f"pm.expect(pm.environment.get({js_str(_fp(_PWF, 'LoginSessionCookie'))}) !== "
        f"pm.environment.get({js_str(_fp(_PWF, 'OldLoginSessionCookie'))}), 'носитель сменился').to.eql(true));",
    ]),
    _fp_csrf(_PWF, "win-f-csrf-enroll-fresh", "second-factor", with_session="LoginSessionCookie"),
    _fp_enroll(_PWF, "win-f-enroll-fresh", "LoginSessionCookie"),
    # Ф12-32, исход «отказ по свежести»: N − 1 неверных кодов после окна, отказ по
    # свежести, верный код — 200 без отказа по частоте.
    *_fp_wrong_codes(_PWP, "win-p-wrong", _N_ADDR - 1, "LoginSessionCookie"),
    _fp_csrf(_PWP, "win-p-csrf-enroll-not-fresh", "second-factor", with_session="LoginSessionCookie"),
    _fp_post(_PWP, "win-p-enroll-not-fresh", _ENROLL, {"csrfToken": f"{{{{{_fp(_PWP, 'Csrf')}}}}}"},
             with_session="LoginSessionCookie",
             tests=_fp_refused(403, 7, _NOT_FRESH_TEXT, "WIN-P-NOT-FRESH", reason="SESSION_NOT_FRESH")),
    _fp_csrf(_PWP, "win-p-csrf-right-code", "step-up", with_session="LoginSessionCookie"),
    _fp_step_up_right(_PWP, "win-p-right-code", "LoginSessionCookie",
                      [*_fp_status(200, "WIN-P-RIGHT"), *_fp_level("WIN-P-RIGHT", "2", True, [])]),
    # Ф12-04 (а): при истёкших обоих первым отвечает свежесть.
    _fp_csrf(_PWE, "win-e-csrf-both-expired", "second-factor"),
    _fp_post(_PWE, "win-e-confirm-both-expired", _CONFIRM,
             {"code": f"{{{{{_fp(_PWE, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(_PWE, 'Csrf')}}}}}"},
             with_session="SessionCookie", pre=_fp_present(_PWE, "WIN-E-BOTH-EXPIRED"),
             tests=_fp_refused(403, 7, _NOT_FRESH_TEXT, "WIN-E-BOTH-EXPIRED", reason="SESSION_NOT_FRESH")),
    # Сессия освежена паролем — истекло только заведение: верный код — тот же
    # отказ, что не начатому, побайтово.
    _fp_csrf(_PWE, "win-e-csrf-step-up-password", "step-up"),
    _fp_step_up_password(_PWE, "win-e-step-up-password", "SessionCookie", [
        *_fp_status(200, "WIN-E-PASSWORD"),
        *_fp_capture(_PWE, "kaname_session", "SessionCookie", "WIN-E-PASSWORD"),
    ]),
    _fp_csrf(_PWE, "win-e-csrf-confirm-expired", "second-factor"),
    _fp_post(_PWE, "win-e-confirm-expired", _CONFIRM,
             {"code": f"{{{{{_fp(_PWE, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(_PWE, 'Csrf')}}}}}"},
             with_session="SessionCookie", pre=_fp_present(_PWE, "WIN-E-EXPIRED"),
             tests=[*_fp_refused(400, 9, _NOT_PENDING_TEXT, "WIN-E-EXPIRED", reason="ENROLLMENT_NOT_PENDING"),
                    *_body_equals("sfWeNotPendingRefusalBody",
                                  "WIN-E-EXPIRED: тело побайтово равно отказу не начатому заведению")]),
    # Положительный контроль: новое заведение, код от НЕГО — 200, «2».
    _fp_csrf(_PWE, "win-e-csrf-re-enroll", "second-factor"),
    _fp_enroll(_PWE, "win-e-re-enroll", "SessionCookie"),
    _fp_post(_PWE, "win-e-confirm-new", _CONFIRM,
             {"code": f"{{{{{_fp(_PWE, 'Code')}}}}}", "csrfToken": f"{{{{{_fp(_PWE, 'Csrf')}}}}}"},
             with_session="SessionCookie", pre=_fp_present(_PWE, "WIN-E-NEW"),
             tests=[*_fp_status(200, "WIN-E-NEW"), *_fp_accepted(_PWE),
                    "let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }",
                    "pm.test('WIN-E-NEW: фактор заведён новым секретом — сессия «2»', () => "
                    "pm.expect(!!__j.session && __j.session.assuranceLevel === '2', 'фактор заведён').to.eql(true));"]),
]
_WIN_STEPS[0].pre_script = [f"pm.environment.unset({js_str(_WIN_DEADLINE)});", *_WIN_STEPS[0].pre_script]

CASES.append(Case(
    id="IAM-2FA-BVA-PROFILE-WINDOW-ELAPSED",
    title=(f"Окно профиля прошло (N={_N_ADDR}, окно {_T_ADDR} с, свежесть {_T_FRESH} с): после Retry-After "
           "верный код — 200 (Ф12-31 г); заведение из несвежей сессии — 403 SESSION_NOT_FRESH, пароль внутри "
           "сессии окно освежает (Ф12-09, Ф12-10); отказ по свежести попыткой не считается (Ф12-32); "
           "истёкшее заведение — тот же отказ, что не начатое, свежесть отвечает первой (Ф12-04 а)"),
    classes=["SEC", "BVA", "NEG"],
    priority="P0",
    steps=_WIN_STEPS,
))
