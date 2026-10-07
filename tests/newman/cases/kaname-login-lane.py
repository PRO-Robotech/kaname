# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set полосы входа паролем и нашей сессии (Ф3, kacho#1269).

Предмет — СОБСТВЕННЫЙ слушатель формы службы (`/iam/v1/auth/{csrf,login,logout,
password}`), а не край платформы. Слушатель поднимает посадка службы — она одна,
`own` (ключ посадки снят, kaname#363), — и допускает РОВНО край — по SAN
клиентского сертификата (Р7, Р16). Поэтому набор адресуется ОТДЕЛЬНОЙ переменной и ждёт от
прогонщика клиентский лист с именем края:

  {{loginLaneBaseUrl}}   — слушатель формы (посадка `own`)
  {{loginLaneEmail}}     — почта человека с заведённым способом входа паролем (посев)
  {{loginLanePassword}}  — его пароль (посев)

ГДЕ ТРИ УСЛОВИЯ СОЗДАЮТСЯ. Стенд чарта (`.github/scripts/stand-chart.sh up`,
задание `chart-own` процесса `e2e-newman.yml`) ставит боевой профиль с накладкой
оператора `own` и выписывает клиентский лист с именем края; подкоманда
`seed-login-lane` того же скрипта заводит человека глаголом продукта на полосе и
пишет три переменные выше (`tests/authz-fixtures/seed_login_lane.py`).

ТРЕТЬЯ КАТЕГОРИЯ НАЗВАНА ВСЛУХ. Остальные стенды дерева условий этого набора не
создают: `.github/scripts/stand-own.sh` поднимает службу без края (его предмет), а
`stand-chart.sh` без подкоманды `seed-login-lane` человека не заводит. Посадка у
службы одна (ключ посадки снят, kaname#363), и отличие — в условиях, а не в посадке.
Там `loginLaneBaseUrl` не задан, и КАЖДЫЙ шаг ниже уходит в «условие не создано»
помеченным утверждением, а не в зелёное и не в красное.

ГДЕ ЭТУ КАТЕГОРИЮ ЧИТАТЬ. Её считает вердиктный слой
`scripts/assert-suites-green.sh` — отдельной долей строки коллекции («из них N
УСЛОВИЕ НЕ СОЗДАНО, находок M») и итоговой строкой по категориям. Сводка самого
прогонщика `scripts/run.sh` той же доли не выделяет: помеченные утверждения
идут у неё в «упавших», и выходит она кодом 1. Прогон без стенда, прочитанный
по одной сводке прогонщика, выглядит красным о продукте.

Клиентский лист службы на обоих стендах выписан на имя самой службы
(`stand-own.sh` — `v3_srv`, `stand-chart.sh` — `_leaf cli`), а не края. Слушатель
формы такому листу отвечает 403 `permission denied`, поэтому прогонщику набора
передаётся ДРУГОЙ лист — `_leaf edge` стенда чарта с SAN края.

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
                                          носителя (Ф3-02, половина «не тот пароль»)
  IAM-LOGINLANE-OK-LOGIN-LOGOUT-REPRESENT — вход выдаёт носитель; выход завершает сессию
                                          на стороне службы; СОХРАНЁННЫЙ носитель после выхода
                                          отвергается (Ф3-01, Ф3-15)
  IAM-LOGINLANE-NEG-CSRF-MISSING        — форма без признака → 400, поле названо (Ф3-36 а)

ТРАССА ИСПРАВЛЕНА (kaname#467). Прежняя редакция этой шапки называла у кейса
неверного пароля позицию неподтверждённого адреса, а у хребта вход-выход — позицию
недоступного хранилища. Ни один из двух кейсов своего условия не создаёт, и
перепись долга (`.github/scripts/newman-suite-debt.py`) засчитывала обе позиции
несомыми по одному упоминанию. Неподтверждённый адрес теперь несёт свой кейс ниже;
недоступное хранилище записано долгом переписи с держателем.

Позиции ниже заведены kaname#467. Каждый кейс своё условие создаёт сам: свой
контекст формы, свой адрес источника на прогон (`198.18.x.y` — счёт частоты по
источнику у кейсов раздельный и у повторного прогона новый), свежего человека
регистрацией, где предмет — счёт по адресу. Человек стенда (`loginLaneEmail`)
меняет пароль только кейсами с возвратом: второй сменой пароль возвращается к
посеянному, и соседние наборы (`kaname-recovery-lane`, `kaname-authorization-code`,
`kaname-second-factor`) входят им же.

Величины предела частоты и длины пароля кейсы берут из поставляемого профиля
(`deploy/values.prod.yaml`, узел `authn.login`) при генерации, а не литералом:
стенд `chart-own` ставит этот профиль как есть, и величина, вписанная рядом,
разошлась бы с посадкой молча.

  IAM-LOGINLANE-NEG-REFUSAL-ONE-FOR-ALL — не тот пароль и адрес без личности: один код,
                                          один статус, побайтово одно тело, носителя нет;
                                          верный пароль после неверного проходит (Ф3-02:
                                          половины «нет строки способа входа» и «заблокирован»
                                          стенд не производит — первую ни один глагол полосы
                                          не заводит, вторую зовёт распорядитель уровня «2»;
                                          значения E1…E3 кладёт проба уровня I)
  IAM-LOGINLANE-OK-LOGIN-EMAIL-CASE-FOLDED — адрес другим регистром букв входит так же, ключ
                                          почты приведён к нижнему регистру (Ф3-01)
  IAM-LOGINLANE-NEG-FORM-FIELDS         — без `password`, без `email`, с лишним полем — 400 с
                                          именем поля, носителя нет; полная форма проходит
                                          (Ф3-05; «в счёт частоты не идёт» — кейс Ф3-30 ниже)
  IAM-LOGINLANE-OK-UNVERIFIED-LOGIN     — неподтверждённый адрес входит, ответ несёт
                                          `emailVerified: false`; близнец с подтверждённым —
                                          `true` (Ф3-03, Ф3-01)
  IAM-LOGINLANE-OK-COOKIE-HOST-ONLY     — адресная посадка: у носителя нет ключа `Domain`,
                                          прочие атрибуты Р3 дословно, следующий запрос с
                                          носителем принят (Ф3-07)
  IAM-LOGINLANE-OK-TWO-SESSIONS-DISTINCT — два входа — два непрозрачных значения не короче 22
                                          знаков base64url; выход из первой вторую не гасит
                                          (Ф3-08, Ф3-15; проба генератора на длину — уровень I)
  IAM-LOGINLANE-OK-LOGOUT-SAME-ANSWER   — выход без носителя, с неизвестным значением и
                                          повторный выход снятой сессией побайтово равны
                                          выходу живой (Ф3-18, Ф3-15)
  IAM-LOGINLANE-OK-PASSWORD-CHANGE-ROUNDTRIP — смена по текущему паролю: носитель перевыпущен
                                          с тем же сроком, прежний отвергнут, прежний пароль
                                          негоден, новый входит; перед сменой — три близнеца,
                                          каждый меняет один факт: признак до входа, признак
                                          выхода, без носителя; вход, смена, выход — каждая
                                          форма своим признаком (Ф3-19, Ф3-37, Ф3-38, Ф3-39,
                                          Ф3-40)
  IAM-LOGINLANE-NEG-PASSWORD-CHANGE-REFUSALS — без `currentPassword` — 400 с полем; неверный
                                          текущий — 401 тем же текстом, что вход; без носителя
                                          — 401; носитель не перевыпущен, пароль прежний (Ф3-20
                                          а, б, в; счёт неподошедшего подтверждения и половины
                                          через край — не здесь)
  IAM-LOGINLANE-NEG-NEW-PASSWORD-RULE   — новый пароль короче объявленной длины и схожий с
                                          адресом — 400 с полем и правилом; пароль прежний
                                          (Ф3-22; база утечек профилем выключена)
  IAM-LOGINLANE-SEC-FORWARDED-PRINCIPAL-IGNORED — заголовки переданной личности чужого
                                          субъекта слушатель не читает: без носителя исходы
                                          побайтово те же, с носителем пароль меняется у
                                          владельца носителя, чужой входит прежним (Ф3-51,
                                          половина службы; половина края — дом платформы)
  IAM-LOGINLANE-NEG-RATE-BY-ADDRESS     — N неверных по существующему и по несуществующему
                                          адресу: N + 1-я — 429 `TOO_MANY_ATTEMPTS` с
                                          `Retry-After`, ответы побайтово равны (Ф3-28)
  IAM-LOGINLANE-NEG-RATE-ADDRESS-CASE-FOLDED — N неверных разным регистром одного адреса дают
                                          тот же 429 (Ф3-28)
  IAM-LOGINLANE-OK-RATE-RESET-ON-SUCCESS — успешный вход обнуляет счёт по адресу (Ф3-28)
  IAM-LOGINLANE-NEG-RATE-BY-SOURCE      — N по разным адресам с одного источника — 429; другой
                                          источник не задет (Ф3-29; отказы слушателя не-краю —
                                          другим листом, одним прогоном не предъявить)
  IAM-LOGINLANE-OK-NOT-COUNTED          — N − 1 неверных, отказ формы и отказ признака чужого
                                          контекста счёта не растят: верный пароль проходит
                                          без 429 (Ф3-30, Ф3-36 б; исчерпание ёмкости — I)

Позиции приёмки ID-PW-1 (`password-verifier-follows-the-stored-value.md`, редакция
5), заведённые kaname#467. «Дано» кладёт посев хранимых значений
(`tests/authz-fixtures/seed_stored_value.py`, подкоманда `seed-stored-value`
стенда чарта) и пишет четыре переменные `storedValue{A,B}{Email,Password}`; без
него каждый шаг уходит в «условие не создано» помеченным утверждением.

  IAM-LOGINLANE-OK-STORED-FORMAT-A      — значение формата A (bcrypt `2a`, стоимость 12),
                                          положенное посевом: прежний пароль входит, тело —
                                          ровно `session` и `user`; неверный пароль первым —
                                          401 тем же текстом (PWV-01)
  IAM-LOGINLANE-OK-STORED-FORMAT-B      — то же на формате B (argon2id, проходов больше
                                          ручки — проверяющий читает параметры значения)
                                          (PWV-02)

Позиция FP-12 приёмки заведения первого пароля
(`first-password-from-a-live-session.md`, kaname#213). «Дано» — личность без
строки пароля с ключом доступа — кладёт посев `tests/authz-fixtures/seed_key_person.py`
(та же подкоманда `seed-stored-value`): ключ заводится глаголом собственного
фронта, строка пароля снимается записью (§4.0 приёмки: такой личности продукт не
производит). Утверждение входа ключом кейс собирает подставным аутентификатором
набора ключей доступа (`cases/kaname-access-keys.py`, `_KEYS` и `_LIB` читаются
разбором — второй копии материала нет). Без посева — «условие не создано».

  IAM-LOGINLANE-OK-FP12-KEY-PERSON-ENROLLS-PASSWORD — FP-12: вошедшая ключом
                                          личность без пароля заводит пароль (`200`,
                                          тело `session`, носитель не перевыпущен), выходит
                                          и входит этим паролем (`200`); иной пароль — `401`;
                                          повтор заведения из новой сессии — `409` код 6
                                          `PASSWORD_ALREADY_SET` (отказ FP-02)
"""

import pathlib as _pathlib
import re as _re

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


# ═══════════════════════════════════════════════════════════════════════════
# ПОЗИЦИИ УРОВНЯ E, ЗАВЕДЁННЫЕ kaname#467. Трасса «сценарий — кейс» — шапка
# модуля; ниже — устройство кейсов и почему оно такое.
# ═══════════════════════════════════════════════════════════════════════════

_STATUS = "/iam/v1/auth/second-factor"
_REGISTER = "/iam/v1/auth/register"

# ВЕЛИЧИНЫ ПРОФИЛЯ — ИЗ ПОСТАВЛЯЕМОГО ПРОФИЛЯ, А НЕ ЛИТЕРАЛОМ. Стенд `chart-own`
# ставит `deploy/values.prod.yaml` как есть (накладка несёт только координаты
# установки), поэтому предел частоты, окно и длина пароля, которые кейс ждёт, —
# ровно те, с которыми служба поднята. Узел читается разбором строки ключа: каждый
# ключ узла `authn.login` в профиле единственный, и второе вхождение — отказ
# генерации с именем ключа, а не молчаливый выбор первого.
_PROFILE = _pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _profile_login(key):
    found = _re.findall(rf"^    {key}: (\S+)\s*$", _PROFILE.read_text(encoding="utf-8"), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-login-lane: ключ профиля authn.login.{key} найден "
                         f"{len(found)} раз в {_PROFILE} — ждали ровно один")
    return found[0]


def _seconds(duration):
    m = _re.fullmatch(r"(\d+)([smh])", duration)
    if m is None:
        raise SystemExit(f"kaname-login-lane: срок {duration!r} не в форме <число><s|m|h>")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


_N_ADDRESS = int(_profile_login("addressAttempts"))
_T_ADDRESS = _seconds(_profile_login("addressWindow"))
_N_SOURCE = int(_profile_login("sourceAttempts"))
_MIN_LENGTH = int(_profile_login("passwordMinLength"))
# Кейс адресной посадки (Ф3-07) стоит на объявлении профиля: посадка с доменным
# именем — другое «Дано», и кейс на ней утверждал бы не то, что названо.
if _profile_login("cookieDomain") != "none":
    raise SystemExit("kaname-login-lane: профиль объявил cookieDomain — кейс адресной посадки "
                     "IAM-LOGINLANE-OK-COOKIE-HOST-ONLY стоит на `none`")

_REFUSED = "authentication failed"
_TOO_MANY = "too many attempts; try again later"
_FORM_REJECTED = "form token rejected"


def _fresh_source(var):
    """Свой адрес источника на прогон: счёт частоты по источнику у кейса свой."""
    return [f"pm.environment.set({js_str(var)}, '198.18.' + (1 + Math.floor(Math.random() * 254)) "
            "+ '.' + (1 + Math.floor(Math.random() * 254)));"]


def _lane_via(path, src_var):
    return [
        *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
        f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: String(pm.environment.get({js_str(src_var)}))}});",
    ]


def _no_session(label):
    return [
        f"pm.test({js_str(label + ': носитель сессии НЕ выдан')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
    ]


def _message(text, label):
    return [
        f"pm.test({js_str(label + ': текст отказа фиксирован')}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({js_str(text)});",
        "});",
    ]


def _reason(reason, label):
    return [
        f"pm.test({js_str(label + ': reason ' + reason)}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        "  const d = Array.isArray(j.details) ? j.details : [];",
        f"  pm.expect(d.map(x => x.reason), JSON.stringify(j)).to.include({js_str(reason)});",
        "});",
    ]


def _refused_401(label):
    return [*assert_status(401), *assert_grpc_code(16, "UNAUTHENTICATED"), *_message(_REFUSED, label),
            *_no_session(label)]


def _invalid_400(text, label):
    return [*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"), *_message(text, label),
            *_no_session(label)]


def _form_rejected_403(label):
    return [*assert_status(403), *assert_grpc_code(7, "PERMISSION_DENIED"), *_message(_FORM_REJECTED, label),
            *_reason("FORM_TOKEN_REJECTED", label), *_no_session(label)]


def _too_many_429(label):
    return [
        *assert_status(429), *assert_grpc_code(8, "RESOURCE_EXHAUSTED"), *_message(_TOO_MANY, label),
        *_reason("TOO_MANY_ATTEMPTS", label), *_no_session(label),
        f"pm.test({js_str(label + ': Retry-After — секунды до конца окна, в (0, ' + str(_T_ADDRESS) + ']')}, () => {{",
        "  const ra = pm.response.headers.get('Retry-After');",
        "  pm.expect(ra, JSON.stringify(pm.response.headers.all())).to.match(/^[0-9]+$/);",
        f"  pm.expect(Number(ra)).to.be.within(1, {_T_ADDRESS});",
        "});",
    ]


def _keep_answer(var):
    """Запомнить ответ целиком — код и тело — для побайтового сравнения."""
    return [f"pm.environment.set({js_str(var)}, pm.response.code + ' ' + pm.response.text());"]


def _same_answer(var, label):
    return [
        f"pm.test({js_str(label + ': ответ побайтово равен запомненному')}, () => {{",
        f"  const kept = pm.environment.get({js_str(var)});",
        "  pm.expect(kept, 'близнец не отработал — сравнивать не с чем').to.be.a('string').and.not.empty;",
        "  pm.expect(pm.response.code + ' ' + pm.response.text()).to.eql(kept);",
        "});",
    ]


def _csrf(name, form, tok_var, form_var, src_var, fresh_context=False, first=False):
    """Признак вида `form`; `fresh_context` — без печенья, контекст выдаётся заново."""
    pre = [*(_fresh_source(src_var) if first else []), *_lane_via(_CSRF + "?form=" + form, src_var)]
    if not fresh_context:
        pre += _with_cookies(("kaname_form", form_var))
    test = [
        *assert_status(200),
        "const j = pm.response.json();",
        f"pm.test({js_str(name + ': признак выдан строкой')}, () => "
        "pm.expect(j.csrfToken, JSON.stringify(j)).to.be.a('string').and.not.empty);",
        f"pm.environment.set({js_str(tok_var)}, j.csrfToken);",
    ]
    if fresh_context:
        test += _capture_cookie("kaname_form", form_var, name)
    return Step(name=name, method="GET", path=_CSRF + "?form=" + form, pre_script=pre,
                insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test)


def _post(name, path, body, src_var, cookies, test, extra_pre=()):
    return Step(name=name, method="POST", path=path, body=body,
                pre_script=[*extra_pre, *_lane_via(path, src_var), *_with_cookies(*cookies)],
                insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test)


def _login(name, email, password, tok_var, form_var, src_var, test, extra_pre=()):
    return _post(name, _LOGIN, {"email": email, "password": password, "csrfToken": "{{" + tok_var + "}}"},
                 src_var, [("kaname_form", form_var)], test, extra_pre)


def _login_ok(label, session_var, form_var, verified=True):
    """Вход состоялся: тело, носитель; контекст сменён входом — захват нового."""
    return [
        *assert_status(200),
        "const j = pm.response.json();",
        f"pm.test({js_str(label + ': тело несёт человека и сессию')}, () => {{",
        "  pm.expect(j.user, JSON.stringify(j)).to.have.property('id');",
        "  pm.expect(j.session, JSON.stringify(j)).to.have.property('expiresAt');",
        "});",
        f"pm.test({js_str(label + ': emailVerified ' + ('true' if verified else 'false'))}, () => "
        f"pm.expect(j.session.emailVerified, JSON.stringify(j)).to.eql({'true' if verified else 'false'}));",
        *_capture_cookie("kaname_session", session_var, label),
        *_capture_cookie("kaname_form", form_var, label),
    ]


def _session_probe(name, session_var, form_var, src_var, alive):
    """Годен ли носитель — чтением под сессией, которое ничего не меняет."""
    control = [
        f"pm.test({js_str(name + ': носитель захвачен (контроль непустоты)')}, () => "
        f"pm.expect(pm.environment.get({js_str(session_var)}), 'носитель не захвачен').to.be.a('string').and.not.empty);",
    ]
    test = control + ([*assert_status(200)] if alive else _refused_401(name))
    return Step(name=name, method="GET", path=_STATUS,
                pre_script=[*_lane_via(_STATUS, src_var),
                            *_with_cookies(("kaname_session", session_var), ("kaname_form", form_var))],
                insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test)


def _fresh_person(prefix, email_var, pw_var, id_var, tok_var, form_var, src_var, session_var):
    """Свежий человек регистрацией: неподтверждённый, входит (вход доступен в положении подтверждения)."""
    seed = [
        f"pm.environment.set({js_str(email_var)}, ({js_str('ll-' + prefix + '-')} + pm.environment.get('runId') "
        "+ '@kaname.local').toLowerCase());",
        f"pm.environment.set({js_str(pw_var)}, 'Fresh-' + Math.random().toString(36).slice(2, 12) + '-Q9');",
    ]
    reg_tok = tok_var + "Reg"
    return [
        _csrf(prefix + "-csrf-register", "register", reg_tok, form_var, src_var, fresh_context=True, first=True),
        _post(prefix + "-register", _REGISTER,
              {"email": "{{" + email_var + "}}", "password": "{{" + pw_var + "}}", "csrfToken": "{{" + reg_tok + "}}"},
              src_var, [("kaname_form", form_var)],
              [
                  *assert_status(200),
                  "const j = pm.response.json();",
                  f"pm.test({js_str(prefix + ': регистрация — человек неподтверждён')}, () => "
                  "pm.expect(j.session && j.session.emailVerified, JSON.stringify(j)).to.eql(false));",
                  f"pm.environment.set({js_str(id_var)}, j.user && j.user.id);",
                  *_capture_cookie("kaname_session", session_var, prefix + "-register"),
                  *_capture_cookie("kaname_form", form_var, prefix + "-register"),
              ],
              extra_pre=seed),
        _csrf(prefix + "-csrf-login", "login", tok_var, form_var, src_var),
    ]


# ───────────────────────────────────────────────────────────────────────────
# Ф3-02. Отказ входа один на все причины, которые стенд производит.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-REFUSAL-ONE-FOR-ALL",
    title="Не тот пароль и адрес без личности: один код, один статус, побайтово одно тело; верный после неверного проходит",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _csrf("f02-csrf", "login", "ll02Tok", "ll02Form", "ll02Src", fresh_context=True, first=True),
        _login("f02-wrong-password", "{{loginLaneEmail}}", "not-the-password-{{runId}}", "ll02Tok", "ll02Form",
               "ll02Src", [*_refused_401("F02-A"), *_keep_answer("ll02AnswerA")]),
        _login("f02-absent-address", "absent-{{runId}}@kaname.local", "not-the-password-{{runId}}", "ll02Tok",
               "ll02Form", "ll02Src", [*_refused_401("F02-B"), *_same_answer("ll02AnswerA", "F02-B")]),
        # Положительный контроль ПОСЛЕ неверного (F4d-16): без него равенство
        # двух отказов зеленело бы на входе, отвергающем всё.
        _login("f02-right-after-wrong", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll02Tok", "ll02Form",
               "ll02Src", _login_ok("F02-CONTROL", "ll02Session", "ll02Form")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-01, строка о регистре: ключ почты нормализован, вход находит строку так же.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-LOGIN-EMAIL-CASE-FOLDED",
    title="Адрес, отличающийся только регистром букв, входит так же; ответ называет адрес в нижнем регистре",
    classes=["CRUD", "BVA"],
    priority="P1",
    steps=[
        _csrf("f01-csrf", "login", "ll01Tok", "ll01Form", "ll01Src", fresh_context=True, first=True),
        _login("f01-login-upper-case", "{{ll01Upper}}", "{{loginLanePassword}}", "ll01Tok", "ll01Form", "ll01Src",
               [
                   *_login_ok("F01-UPPER", "ll01Session", "ll01Form"),
                   "pm.test('F01-UPPER: адрес в запросе действительно другим регистром (контроль)', () => "
                   "pm.expect(pm.environment.get('ll01Upper')).to.not.eql(pm.environment.get('loginLaneEmail')));",
                   "pm.test('F01-UPPER: ответ называет адрес строки — в нижнем регистре', () => "
                   "pm.expect(j.user.email, JSON.stringify(j)).to.eql(String(pm.environment.get('loginLaneEmail')).toLowerCase()));",
               ],
               extra_pre=["pm.environment.set('ll01Upper', String(pm.environment.get('loginLaneEmail')).toUpperCase());"]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-05. Форма запроса: отсутствующее поле называется, лишнее отвергается.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-FORM-FIELDS",
    title="Вход без password, без email и с необъявленным полем — 400 с именем поля, носителя нет; полная форма проходит",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        _csrf("f05-csrf", "login", "ll05Tok", "ll05Form", "ll05Src", fresh_context=True, first=True),
        _post("f05-no-password", _LOGIN, {"email": "{{loginLaneEmail}}", "csrfToken": "{{ll05Tok}}"}, "ll05Src",
              [("kaname_form", "ll05Form")], _invalid_400("Illegal argument password: required", "F05-NO-PW")),
        _post("f05-no-email", _LOGIN, {"password": "{{loginLanePassword}}", "csrfToken": "{{ll05Tok}}"}, "ll05Src",
              [("kaname_form", "ll05Form")], _invalid_400("Illegal argument email: required", "F05-NO-EMAIL")),
        _post("f05-undeclared-field", _LOGIN,
              {"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}", "csrfToken": "{{ll05Tok}}",
               "rememberMe": True},
              "ll05Src", [("kaname_form", "ll05Form")],
              _invalid_400("Illegal argument rememberMe: unknown field", "F05-EXTRA")),
        _login("f05-full-form", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll05Tok", "ll05Form", "ll05Src",
               _login_ok("F05-CONTROL", "ll05Session", "ll05Form")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-03. Неподтверждённый адрес: вход состоится, ответ это называет. Близнец —
# человек стенда, адрес которого посев подтвердил; различие одно.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-UNVERIFIED-LOGIN",
    title="Неподтверждённый адрес входит верным паролем и ответ несёт emailVerified false; подтверждённый — true",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_fresh_person("f03", "ll03Email", "ll03Password", "ll03UserId", "ll03Tok", "ll03Form", "ll03Src",
                       "ll03RegSession"),
        _login("f03-login-unverified", "{{ll03Email}}", "{{ll03Password}}", "ll03Tok", "ll03Form", "ll03Src",
               _login_ok("F03-UNVERIFIED", "ll03Session", "ll03Form", verified=False)),
        _csrf("f03-csrf-twin", "login", "ll03TwinTok", "ll03TwinForm", "ll03Src", fresh_context=True),
        _login("f03-login-verified-twin", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll03TwinTok",
               "ll03TwinForm", "ll03Src", _login_ok("F03-TWIN", "ll03TwinSession", "ll03TwinForm", verified=True)),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-07. Адресная посадка: ключа Domain нет, прочие атрибуты Р3 — дословно.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-COOKIE-HOST-ONLY",
    title="Носитель на адресной посадке — без ключа Domain, с атрибутами Р3; следующий запрос с ним принят",
    classes=["SEC"],
    priority="P0",
    steps=[
        _csrf("f07-csrf", "login", "ll07Tok", "ll07Form", "ll07Src", fresh_context=True, first=True),
        _login("f07-login", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll07Tok", "ll07Form", "ll07Src",
               [
                   *_login_ok("F07", "ll07Session", "ll07Form"),
                   "const __sess = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
                   "&& h.value.startsWith('kaname_session='));",
                   "const __attrs = __sess.length === 1 ? __sess[0].value.split(';').slice(1).map(a => a.trim()) : [];",
                   "pm.test('F07: ключа Domain в носителе нет вовсе', () => "
                   "pm.expect(__attrs.filter(a => /^domain(=|$)/i.test(a)), JSON.stringify(__attrs)).to.eql([]));",
                   "pm.test('F07: атрибуты Р3 дословно — Path=/, Max-Age=86400, HttpOnly, Secure, SameSite=Lax', () => "
                   "pm.expect(__attrs.slice().sort(), JSON.stringify(__attrs)).to.eql("
                   "['HttpOnly', 'Max-Age=86400', 'Path=/', 'SameSite=Lax', 'Secure']));",
               ]),
        _session_probe("f07-next-request-carries-cookie", "ll07Session", "ll07Form", "ll07Src", alive=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-08 (+ Ф3-15): два входа — две непрозрачные сессии, различимые для отзыва.
# ───────────────────────────────────────────────────────────────────────────
_OPAQUE = [
    "{",
    "  const v1 = String(pm.environment.get('ll08S1')), v2 = String(pm.environment.get('ll08S2'));",
    "  const id = String(pm.environment.get('ll08UserId')), local = String(pm.environment.get('loginLaneEmail')).split('@')[0];",
    "  pm.test('F08: значения двух входов различны', () => pm.expect(v1).to.not.eql(v2));",
    "  pm.test('F08: значение — base64url, не короче 22 знаков (128 бит)', () => {",
    "    pm.expect(v1, 'первое').to.match(/^[A-Za-z0-9_-]{22,}$/);",
    "    pm.expect(v2, 'второе').to.match(/^[A-Za-z0-9_-]{22,}$/);",
    "  });",
    "  pm.test('F08: из значения не читаются ни субъект, ни адрес', () => {",
    "    pm.expect(id, 'идентификатор человека не захвачен').to.be.a('string').and.not.empty;",
    "    [v1, v2].forEach(v => { pm.expect(v).to.not.include(id); pm.expect(v.toLowerCase()).to.not.include(local.toLowerCase()); });",
    "  });",
    "}",
]

CASES.append(Case(
    id="IAM-LOGINLANE-OK-TWO-SESSIONS-DISTINCT",
    title="Два входа одной личности — два непрозрачных значения; выход из первой вторую не гасит",
    classes=["SEC", "CRUD"],
    priority="P0",
    steps=[
        _csrf("f08-csrf-device-1", "login", "ll08Tok1", "ll08Form1", "ll08Src", fresh_context=True, first=True),
        _login("f08-login-device-1", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll08Tok1", "ll08Form1",
               "ll08Src", [*_login_ok("F08-S1", "ll08S1", "ll08Form1"),
                           "pm.environment.set('ll08UserId', j.user.id);"]),
        _csrf("f08-csrf-device-2", "login", "ll08Tok2", "ll08Form2", "ll08Src", fresh_context=True),
        _login("f08-login-device-2", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll08Tok2", "ll08Form2",
               "ll08Src", [*_login_ok("F08-S2", "ll08S2", "ll08Form2"), *_OPAQUE]),
        _csrf("f08-csrf-logout-1", "logout", "ll08LogoutTok", "ll08Form1", "ll08Src"),
        _post("f08-logout-1", _LOGOUT, {"csrfToken": "{{ll08LogoutTok}}"}, "ll08Src",
              [("kaname_session", "ll08S1"), ("kaname_form", "ll08Form1")], [*assert_status(200)]),
        _session_probe("f08-first-ended", "ll08S1", "ll08Form1", "ll08Src", alive=False),
        _session_probe("f08-second-alive", "ll08S2", "ll08Form2", "ll08Src", alive=True),
        _csrf("f08-csrf-logout-2", "logout", "ll08LogoutTok2", "ll08Form2", "ll08Src"),
        _post("f08-logout-2-cleanup", _LOGOUT, {"csrfToken": "{{ll08LogoutTok2}}"}, "ll08Src",
              [("kaname_session", "ll08S2"), ("kaname_form", "ll08Form2")], [*assert_status(200)]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-18 (+ Ф3-15, третья строка): выход без сессии — тот же ответ.
# ───────────────────────────────────────────────────────────────────────────
_LOGOUT_OK = [
    *assert_status(200),
    "pm.test('LOGOUT: тело {}', () => pm.expect(pm.response.text()).to.eql('{}'));",
    "pm.test('LOGOUT: носитель снят — пустое значение, Max-Age=0, атрибуты Р3', () => {",
    "  const sc = pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='));",
    "  pm.expect(sc.map(h => h.value), JSON.stringify(pm.response.headers.all())).to.eql("
    "['kaname_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax']);",
    "});",
]

CASES.append(Case(
    id="IAM-LOGINLANE-OK-LOGOUT-SAME-ANSWER",
    title="Выход без носителя, с неизвестным значением и повторный выход снятой сессией побайтово равны выходу живой",
    classes=["IDM", "SEC"],
    priority="P0",
    steps=[
        _csrf("f18-csrf", "login", "ll18Tok", "ll18Form", "ll18Src", fresh_context=True, first=True),
        _login("f18-login", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll18Tok", "ll18Form", "ll18Src",
               _login_ok("F18", "ll18Session", "ll18Form")),
        _csrf("f18-csrf-logout", "logout", "ll18LogoutTok", "ll18Form", "ll18Src"),
        _post("f18-logout-live", _LOGOUT, {"csrfToken": "{{ll18LogoutTok}}"}, "ll18Src",
              [("kaname_session", "ll18Session"), ("kaname_form", "ll18Form")],
              [*_LOGOUT_OK, *_keep_answer("ll18Answer"),
               "pm.environment.set('ll18SetCookie', JSON.stringify(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie').map(h => h.value)));"]),
        *[
            _post(f"f18-logout-{kind}", _LOGOUT, {"csrfToken": "{{ll18LogoutTok}}"}, "ll18Src", cookies,
                  [*_LOGOUT_OK, *_same_answer("ll18Answer", "F18-" + kind.upper()),
                   f"pm.test({js_str('F18-' + kind.upper() + ': Set-Cookie тот же, что у выхода живой')}, () => "
                   "pm.expect(JSON.stringify(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie')"
                   ".map(h => h.value))).to.eql(pm.environment.get('ll18SetCookie')));"],
                  extra_pre=pre)
            for kind, cookies, pre in (
                ("no-carrier", [("kaname_form", "ll18Form")], []),
                ("unknown-value", [("kaname_session", "ll18Unknown"), ("kaname_form", "ll18Form")],
                 ["pm.environment.set('ll18Unknown', 'A'.repeat(43));"]),
                ("ended-again", [("kaname_session", "ll18Session"), ("kaname_form", "ll18Form")], []),
            )
        ],
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-19, Ф3-37, Ф3-38, Ф3-39, Ф3-40: смена пароля и её близнецы. Каждый близнец
# стоит ПЕРЕД сменой и меняет ровно один факт против неё; смена — их
# положительный контроль. Пароль человека стенда возвращается второй сменой.
# ───────────────────────────────────────────────────────────────────────────
_NEW_PW = "{{loginLanePassword}}-Changed-{{runId}}"
_SAME_EXPIRY = [
    "pm.test('F19: срок перевыпущенной сессии — тот же, что у входа', () => "
    "pm.expect(j.session.expiresAt, JSON.stringify(j)).to.eql(pm.environment.get('llPwExpires')));",
]


def _password_change(name, current, new, tok_var, session_var, form_var, test, extra_pre=(), headers=()):
    pre = [*extra_pre, *[f"pm.request.headers.upsert({{key: {js_str(k)}, value: {js_str(v)}}});" for k, v in headers]]
    return _post(name, _PASSWORD, {"currentPassword": current, "newPassword": new, "csrfToken": "{{" + tok_var + "}}"},
                 "llPwSrc", [("kaname_session", session_var), ("kaname_form", form_var)], test, pre)


CASES.append(Case(
    id="IAM-LOGINLANE-OK-PASSWORD-CHANGE-ROUNDTRIP",
    title="Смена пароля по текущему: носитель перевыпущен с тем же сроком, прежний пароль негоден; близнецы признака и носителя отвергнуты",
    classes=["CRUD", "SEC", "NEG"],
    priority="P0",
    steps=[
        # Признак смены пароля — ДО входа, под контекстом K1 (Ф3-37).
        _csrf("pw-csrf-before-login", "password", "llPwTokK1", "llPwForm", "llPwSrc", fresh_context=True, first=True),
        _csrf("pw-csrf-login", "login", "llPwLoginTok", "llPwForm", "llPwSrc"),
        _login("pw-login", "{{loginLaneEmail}}", "{{loginLanePassword}}", "llPwLoginTok", "llPwForm", "llPwSrc",
               [*_login_ok("PW-LOGIN", "llPwSession", "llPwForm"),
                "pm.environment.set('llPwExpires', j.session.expiresAt);"]),
        _csrf("pw-csrf-password", "password", "llPwTok", "llPwForm", "llPwSrc"),
        _csrf("pw-csrf-logout", "logout", "llPwLogoutTok", "llPwForm", "llPwSrc"),
        _password_change("pw-twin-token-before-login", "{{loginLanePassword}}", _NEW_PW, "llPwTokK1",
                         "llPwSession", "llPwForm", _form_rejected_403("F37-K1")),
        _password_change("pw-twin-logout-token", "{{loginLanePassword}}", _NEW_PW, "llPwLogoutTok",
                         "llPwSession", "llPwForm", _form_rejected_403("F38-LOGOUT-KIND")),
        _post("pw-twin-no-carrier", _PASSWORD,
              {"currentPassword": "{{loginLanePassword}}", "newPassword": _NEW_PW, "csrfToken": "{{llPwTok}}"},
              "llPwSrc", [("kaname_form", "llPwForm")], _refused_401("F39-NO-CARRIER")),
        _password_change("pw-change", "{{loginLanePassword}}", _NEW_PW, "llPwTok", "llPwSession", "llPwForm",
                         [*assert_status(200), "const j = pm.response.json();",
                          "pm.test('F19: тело несёт сессию', () => pm.expect(j.session, JSON.stringify(j)).to.have.property('expiresAt'));",
                          *_SAME_EXPIRY,
                          *_capture_cookie("kaname_session", "llPwSession2", "F19"),
                          "pm.test('F19: носитель перевыпущен — значение другое', () => "
                          "pm.expect(pm.environment.get('llPwSession2')).to.not.eql(pm.environment.get('llPwSession')));"]),
        _session_probe("pw-old-carrier-ended", "llPwSession", "llPwForm", "llPwSrc", alive=False),
        _session_probe("pw-new-carrier-alive", "llPwSession2", "llPwForm", "llPwSrc", alive=True),
        _csrf("pw-csrf-login-2", "login", "llPwLoginTok2", "llPwForm", "llPwSrc"),
        _login("pw-login-old-password", "{{loginLaneEmail}}", "{{loginLanePassword}}", "llPwLoginTok2", "llPwForm",
               "llPwSrc", _refused_401("F19-OLD-PW")),
        _login("pw-login-new-password", "{{loginLaneEmail}}", _NEW_PW, "llPwLoginTok2", "llPwForm", "llPwSrc",
               _login_ok("F19-NEW-PW", "llPwSession3", "llPwForm")),
        # Признак, выданный под прежним контекстом, после входа новой сессией
        # отвергнут: контекст сменился входом (Ф3-37, строка различимости).
        _password_change("pw-twin-token-before-relogin", _NEW_PW, "{{loginLanePassword}}", "llPwTok",
                         "llPwSession3", "llPwForm", _form_rejected_403("F37-RELOGIN")),
        _csrf("pw-csrf-restore", "password", "llPwTokRestore", "llPwForm", "llPwSrc"),
        _password_change("pw-restore", _NEW_PW, "{{loginLanePassword}}", "llPwTokRestore", "llPwSession3",
                         "llPwForm", [*assert_status(200),
                                      *_capture_cookie("kaname_session", "llPwSession4", "PW-RESTORE")]),
        _csrf("pw-csrf-logout-2", "logout", "llPwLogoutTok2", "llPwForm", "llPwSrc"),
        _post("pw-logout", _LOGOUT, {"csrfToken": "{{llPwLogoutTok2}}"}, "llPwSrc",
              [("kaname_session", "llPwSession4"), ("kaname_form", "llPwForm")], _LOGOUT_OK),
        _csrf("pw-csrf-login-3", "login", "llPwLoginTok3", "llPwForm", "llPwSrc"),
        _login("pw-login-restored", "{{loginLaneEmail}}", "{{loginLanePassword}}", "llPwLoginTok3", "llPwForm",
               "llPwSrc", _login_ok("PW-RESTORED", "llPwSession5", "llPwForm")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-20 (а, б, в): отказы смены. Носитель не перевыпущен, пароль прежний.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-PASSWORD-CHANGE-REFUSALS",
    title="Смена без currentPassword — 400 с полем; неверный текущий и без носителя — 401 текстом входа; ничего не изменено",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _csrf("f20-csrf", "login", "ll20LoginTok", "ll20Form", "ll20Src", fresh_context=True, first=True),
        _login("f20-login", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll20LoginTok", "ll20Form", "ll20Src",
               _login_ok("F20", "ll20Session", "ll20Form")),
        _csrf("f20-csrf-password", "password", "ll20Tok", "ll20Form", "ll20Src"),
        _post("f20-a-no-current", _PASSWORD, {"newPassword": _NEW_PW, "csrfToken": "{{ll20Tok}}"}, "ll20Src",
              [("kaname_session", "ll20Session"), ("kaname_form", "ll20Form")],
              _invalid_400("Illegal argument currentPassword: required", "F20-A")),
        _post("f20-b-wrong-current", _PASSWORD,
              {"currentPassword": "not-the-password-{{runId}}", "newPassword": _NEW_PW, "csrfToken": "{{ll20Tok}}"},
              "ll20Src", [("kaname_session", "ll20Session"), ("kaname_form", "ll20Form")], _refused_401("F20-B")),
        _post("f20-c-no-carrier", _PASSWORD,
              {"currentPassword": "{{loginLanePassword}}", "newPassword": _NEW_PW, "csrfToken": "{{ll20Tok}}"},
              "ll20Src", [("kaname_form", "ll20Form")], _refused_401("F20-C")),
        _session_probe("f20-carrier-not-reissued", "ll20Session", "ll20Form", "ll20Src", alive=True),
        _csrf("f20-csrf-login-2", "login", "ll20LoginTok2", "ll20Form", "ll20Src"),
        _login("f20-password-unchanged", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll20LoginTok2", "ll20Form",
               "ll20Src", _login_ok("F20-UNCHANGED", "ll20Session2", "ll20Form")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-22: новый пароль судится правилом регистрации и восстановления.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-NEW-PASSWORD-RULE",
    title="Новый пароль короче объявленной длины и схожий с адресом — 400 с полем и правилом; пароль прежний",
    classes=["NEG", "VAL", "BVA"],
    priority="P1",
    steps=[
        _csrf("f22-csrf", "login", "ll22LoginTok", "ll22Form", "ll22Src", fresh_context=True, first=True),
        _login("f22-login", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll22LoginTok", "ll22Form", "ll22Src",
               _login_ok("F22", "ll22Session", "ll22Form")),
        _csrf("f22-csrf-password", "password", "ll22Tok", "ll22Form", "ll22Src"),
        # Граница: длина min − 1 (BVA); min — положительный контроль смены (кейс выше
        # задаёт пароль длиннее, границу min положительно держит правило регистрации).
        _post("f22-shorter-than-min", _PASSWORD,
              {"currentPassword": "{{loginLanePassword}}", "newPassword": "Q9" + "x" * (_MIN_LENGTH - 3),
               "csrfToken": "{{ll22Tok}}"},
              "ll22Src", [("kaname_session", "ll22Session"), ("kaname_form", "ll22Form")],
              [*_invalid_400("Illegal argument newPassword: shorter than the declared minimum length", "F22-SHORT"),
               f"pm.test({js_str(f'F22-SHORT: предъявлено ровно {_MIN_LENGTH - 1} знаков (контроль границы)')}, () => "
               f"pm.expect(JSON.parse(pm.request.body.raw).newPassword.length).to.eql({_MIN_LENGTH - 1}));"]),
        _post("f22-resembles-address", _PASSWORD,
              {"currentPassword": "{{loginLanePassword}}", "newPassword": "{{ll22Local}}", "csrfToken": "{{ll22Tok}}"},
              "ll22Src", [("kaname_session", "ll22Session"), ("kaname_form", "ll22Form")],
              _invalid_400("Illegal argument newPassword: must not resemble the e-mail address", "F22-LIKE-ADDRESS"),
              extra_pre=["pm.environment.set('ll22Local', String(pm.environment.get('loginLaneEmail')).split('@')[0]);"]),
        _csrf("f22-csrf-login-2", "login", "ll22LoginTok2", "ll22Form", "ll22Src"),
        _login("f22-password-unchanged", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll22LoginTok2", "ll22Form",
               "ll22Src", _login_ok("F22-UNCHANGED", "ll22Session2", "ll22Form")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-51, половина службы: переданная личность на поверхности формы не читается.
# Лист у прогона — края; заголовки обеих форм называют чужого субъекта B —
# свежего человека, чей пароль известен кейсу.
# ───────────────────────────────────────────────────────────────────────────
_FORGED = (
    ("x-kacho-principal-type", "user"),
    ("x-kacho-principal-id", "{{ll51BId}}"),
    ("Grpc-Metadata-X-Kacho-Principal-Type", "user"),
    ("Grpc-Metadata-X-Kacho-Principal-Id", "{{ll51BId}}"),
)


def _forged():
    return [f"pm.request.headers.upsert({{key: {js_str(k)}, value: {js_str(v)}}});" for k, v in _FORGED]


_FORGED_CONTROL = [
    "pm.test('F51: заголовки чужого субъекта действительно предъявлены (контроль)', () => {",
    "  pm.expect(String(pm.environment.get('ll51BId')), 'субъект B не заведён').to.match(/^usr/);",
    "  pm.expect(pm.request.headers.get('x-kacho-principal-id')).to.eql(pm.environment.get('ll51BId'));",
    "});",
]

CASES.append(Case(
    id="IAM-LOGINLANE-SEC-FORWARDED-PRINCIPAL-IGNORED",
    title="Заголовки переданной личности чужого субъекта не читаются: исходы без носителя те же, пароль меняется у владельца носителя",
    classes=["SEC", "NEG"],
    priority="P0",
    steps=[
        *_fresh_person("f51", "ll51BEmail", "ll51BPassword", "ll51BId", "ll51BTok", "ll51BForm", "ll51Src",
                       "ll51BSession"),
        _csrf("f51-csrf-a", "login", "ll51LoginTok", "ll51Form", "ll51Src", fresh_context=True),
        _csrf("f51-csrf-password-anon", "password", "ll51PwTokAnon", "ll51Form", "ll51Src"),
        _csrf("f51-csrf-logout-anon", "logout", "ll51LogoutTokAnon", "ll51Form", "ll51Src"),
        # (1) без носителя: пара «без заголовков — с заголовками», исходы побайтово равны.
        _post("f51-password-no-carrier-plain", _PASSWORD,
              {"currentPassword": "{{ll51BPassword}}", "newPassword": _NEW_PW, "csrfToken": "{{ll51PwTokAnon}}"},
              "ll51Src", [("kaname_form", "ll51Form")], [*_refused_401("F51-PW-PLAIN"), *_keep_answer("ll51PwPlain")]),
        _post("f51-password-no-carrier-forged", _PASSWORD,
              {"currentPassword": "{{ll51BPassword}}", "newPassword": _NEW_PW, "csrfToken": "{{ll51PwTokAnon}}"},
              "ll51Src", [("kaname_form", "ll51Form")],
              [*_FORGED_CONTROL, *_refused_401("F51-PW-FORGED"), *_same_answer("ll51PwPlain", "F51-PW-FORGED")],
              extra_pre=_forged()),
        _post("f51-logout-no-carrier-plain", _LOGOUT, {"csrfToken": "{{ll51LogoutTokAnon}}"}, "ll51Src",
              [("kaname_form", "ll51Form")], [*_LOGOUT_OK, *_keep_answer("ll51LogoutPlain")]),
        _post("f51-logout-no-carrier-forged", _LOGOUT, {"csrfToken": "{{ll51LogoutTokAnon}}"}, "ll51Src",
              [("kaname_form", "ll51Form")],
              [*_FORGED_CONTROL, *_LOGOUT_OK, *_same_answer("ll51LogoutPlain", "F51-LOGOUT-FORGED")],
              extra_pre=_forged()),
        # (2) с носителем A: смена исполнена для A, у B не изменено ничего.
        _login("f51-login-a", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll51LoginTok", "ll51Form", "ll51Src",
               _login_ok("F51-A", "ll51ASession", "ll51Form")),
        _csrf("f51-csrf-password-a", "password", "ll51PwTok", "ll51Form", "ll51Src"),
        _post("f51-change-a-forged", _PASSWORD,
              {"currentPassword": "{{loginLanePassword}}", "newPassword": _NEW_PW, "csrfToken": "{{ll51PwTok}}"},
              "ll51Src", [("kaname_session", "ll51ASession"), ("kaname_form", "ll51Form")],
              [*_FORGED_CONTROL, *assert_status(200), *_keep_answer("ll51ChangeForged"),
               *_capture_cookie("kaname_session", "ll51ASession2", "F51-CHANGE")],
              extra_pre=_forged()),
        # Возврат пароля A тем же носителем без заголовков: тот же исход побайтово —
        # срок перевыпущенной сессии тот же, тело то же. Успех возврата по
        # `currentPassword` = новый доказывает, что сменён пароль ИМЕННО A.
        _post("f51-restore-a-plain", _PASSWORD,
              {"currentPassword": _NEW_PW, "newPassword": "{{loginLanePassword}}", "csrfToken": "{{ll51PwTok}}"},
              "ll51Src", [("kaname_session", "ll51ASession2"), ("kaname_form", "ll51Form")],
              [*assert_status(200), *_same_answer("ll51ChangeForged", "F51-RESTORE")]),
        _csrf("f51-csrf-login-b", "login", "ll51BLoginTok", "ll51BForm", "ll51Src"),
        _login("f51-b-password-untouched", "{{ll51BEmail}}", "{{ll51BPassword}}", "ll51BLoginTok", "ll51BForm",
               "ll51Src", _login_ok("F51-B", "ll51BSession2", "ll51BForm", verified=False)),
        _csrf("f51-csrf-login-a-2", "login", "ll51LoginTok2", "ll51Form", "ll51Src"),
        _login("f51-a-password-restored", "{{loginLaneEmail}}", "{{loginLanePassword}}", "ll51LoginTok2", "ll51Form",
               "ll51Src", _login_ok("F51-A-RESTORED", "ll51ASession3", "ll51Form")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-28: предел по адресу. Существующий адрес — свежий человек (посеянного
# предел запер бы для соседних наборов на окно); несуществующий — литерал с
# `runId`. (N + 1)-я попытка у существующего — ВЕРНЫМ паролем: отказ приходит
# от предела, а не от сверки.
# ───────────────────────────────────────────────────────────────────────────
def _wrong_run(prefix, count, email, tok_var, form_var, src_var, label):
    return [
        _login(f"{prefix}-wrong-{i}", email, f"not-the-password-{i}-{{{{runId}}}}", tok_var, form_var, src_var,
               _refused_401(f"{label}-{i}"))
        for i in range(1, count + 1)
    ]


CASES.append(Case(
    id="IAM-LOGINLANE-NEG-RATE-BY-ADDRESS",
    title=f"{_N_ADDRESS} неверных по существующему и по несуществующему адресу: следующая — 429 с Retry-After, ответы побайтово равны",
    classes=["NEG", "SEC", "BVA"],
    priority="P0",
    steps=[
        *_fresh_person("f28", "ll28Email", "ll28Password", "ll28UserId", "ll28Tok", "ll28Form", "ll28Src",
                       "ll28RegSession"),
        *_wrong_run("f28-a", _N_ADDRESS, "{{ll28Email}}", "ll28Tok", "ll28Form", "ll28Src", "F28-A"),
        _login("f28-a-limit-right-password", "{{ll28Email}}", "{{ll28Password}}", "ll28Tok", "ll28Form", "ll28Src",
               [*_too_many_429("F28-A"), *_keep_answer("ll28AnswerA")]),
        *_wrong_run("f28-b", _N_ADDRESS, "absent-rate-{{runId}}@kaname.local", "ll28Tok", "ll28Form", "ll28Src",
                    "F28-B"),
        _login("f28-b-limit", "absent-rate-{{runId}}@kaname.local", "not-the-password-{{runId}}", "ll28Tok",
               "ll28Form", "ll28Src", [*_too_many_429("F28-B"), *_same_answer("ll28AnswerA", "F28-B")]),
    ],
))

_CASE_VARIANTS = (
    "String(pm.environment.get('ll28cEmail')).toUpperCase()",
    "String(pm.environment.get('ll28cEmail'))",
    "(s => s.charAt(0).toUpperCase() + s.slice(1))(String(pm.environment.get('ll28cEmail')))",
    "String(pm.environment.get('ll28cEmail')).split('@')[0] + '@' + String(pm.environment.get('ll28cEmail')).split('@')[1].toUpperCase()",
)

CASES.append(Case(
    id="IAM-LOGINLANE-NEG-RATE-ADDRESS-CASE-FOLDED",
    title=f"{_N_ADDRESS} неверных по одному адресу разным регистром букв — следующая получает тот же 429",
    classes=["NEG", "SEC", "BVA"],
    priority="P1",
    steps=[
        *_fresh_person("f28c", "ll28cEmail", "ll28cPassword", "ll28cUserId", "ll28cTok", "ll28cForm", "ll28cSrc",
                       "ll28cRegSession"),
        *[
            _login(f"f28c-wrong-{i}", "{{ll28cVariant}}", f"not-the-password-{i}-{{{{runId}}}}", "ll28cTok",
                   "ll28cForm", "ll28cSrc", _refused_401(f"F28C-{i}"),
                   extra_pre=[f"pm.environment.set('ll28cVariant', {_CASE_VARIANTS[(i - 1) % len(_CASE_VARIANTS)]});"])
            for i in range(1, _N_ADDRESS + 1)
        ],
        _login("f28c-limit", "{{ll28cEmail}}", "{{ll28cPassword}}", "ll28cTok", "ll28cForm", "ll28cSrc",
               _too_many_429("F28C")),
    ],
))

CASES.append(Case(
    id="IAM-LOGINLANE-OK-RATE-RESET-ON-SUCCESS",
    title=f"Успешный вход обнуляет счёт по адресу: дважды по {_N_ADDRESS - 1} неверных с верным между — отказа по частоте нет",
    classes=["SEC", "BVA"],
    priority="P1",
    steps=[
        *_fresh_person("f28r", "ll28rEmail", "ll28rPassword", "ll28rUserId", "ll28rTok", "ll28rForm", "ll28rSrc",
                       "ll28rRegSession"),
        *_wrong_run("f28r-first", _N_ADDRESS - 1, "{{ll28rEmail}}", "ll28rTok", "ll28rForm", "ll28rSrc", "F28R-1"),
        _login("f28r-right", "{{ll28rEmail}}", "{{ll28rPassword}}", "ll28rTok", "ll28rForm", "ll28rSrc",
               _login_ok("F28R-RIGHT", "ll28rSession", "ll28rForm", verified=False)),
        _csrf("f28r-csrf-again", "login", "ll28rTok", "ll28rForm", "ll28rSrc"),
        *_wrong_run("f28r-second", _N_ADDRESS - 1, "{{ll28rEmail}}", "ll28rTok", "ll28rForm", "ll28rSrc", "F28R-2"),
        _login("f28r-right-again", "{{ll28rEmail}}", "{{ll28rPassword}}", "ll28rTok", "ll28rForm", "ll28rSrc",
               _login_ok("F28R-RIGHT-AGAIN", "ll28rSession2", "ll28rForm", verified=False)),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-29: предел по источнику. Адреса — несуществующие и разные, по одной
# попытке на каждый: предел по адресу не задет ни у одного.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-NEG-RATE-BY-SOURCE",
    title=f"{_N_SOURCE} неверных по разным адресам с одного источника — следующая 429; другой источник не задет",
    classes=["NEG", "SEC", "BVA"],
    priority="P0",
    steps=[
        _csrf("f29-csrf", "login", "ll29Tok", "ll29Form", "ll29Src", fresh_context=True, first=True),
        *[
            _login(f"f29-address-{i}", f"absent-src-{i}-{{{{runId}}}}@kaname.local", "not-the-password-{{runId}}",
                   "ll29Tok", "ll29Form", "ll29Src", _refused_401(f"F29-{i}"))
            for i in range(1, _N_SOURCE + 1)
        ],
        _login("f29-limit", "absent-src-next-{{runId}}@kaname.local", "not-the-password-{{runId}}", "ll29Tok",
               "ll29Form", "ll29Src", _too_many_429("F29")),
        _login("f29-other-source-untouched", "absent-src-1-{{runId}}@kaname.local", "not-the-password-{{runId}}",
               "ll29Tok", "ll29Form", "ll29SrcOther",
               ["pm.test('F29-OTHER: источник другой (контроль)', () => "
                "pm.expect(pm.request.headers.get('X-Forwarded-For')).to.not.eql(pm.environment.get('ll29Src')));",
                *_refused_401("F29-OTHER")],
               extra_pre=_fresh_source("ll29SrcOther")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф3-30 (+ Ф3-36 б): что попыткой НЕ считается. N − 1 неверных плюс любой
# сосчитанный промежуточный дали бы N, и верный пароль получил бы 429 — ровно
# как (N + 1)-я верным паролем в Ф3-28.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-LOGINLANE-OK-NOT-COUNTED",
    title=f"{_N_ADDRESS - 1} неверных, отказ формы и отказ признака чужого контекста счёта не растят — верный пароль проходит",
    classes=["SEC", "BVA", "NEG"],
    priority="P1",
    steps=[
        *_fresh_person("f30", "ll30Email", "ll30Password", "ll30UserId", "ll30Tok", "ll30Form", "ll30Src",
                       "ll30RegSession"),
        *_wrong_run("f30", _N_ADDRESS - 1, "{{ll30Email}}", "ll30Tok", "ll30Form", "ll30Src", "F30"),
        _post("f30-form-refusal", _LOGIN, {"email": "{{ll30Email}}", "csrfToken": "{{ll30Tok}}"}, "ll30Src",
              [("kaname_form", "ll30Form")], _invalid_400("Illegal argument password: required", "F30-FORM")),
        # Второй «браузер»: признак выдан другому контексту и предъявлен под своим.
        _csrf("f30-csrf-other-context", "login", "ll30OtherTok", "ll30OtherForm", "ll30Src", fresh_context=True),
        _login("f30-foreign-token", "{{ll30Email}}", "not-the-password-{{runId}}", "ll30OtherTok", "ll30Form",
               "ll30Src", _form_rejected_403("F30-TOKEN")),
        _login("f30-right-password", "{{ll30Email}}", "{{ll30Password}}", "ll30Tok", "ll30Form", "ll30Src",
               _login_ok("F30-RIGHT", "ll30Session", "ll30Form", verified=False)),
    ],
))


# ═══════════════════════════════════════════════════════════════════════════
# ID-PW-1 PWV-01 и PWV-02 (kaname#467): Ф1-04 на КАЖДОМ формате перечня.
#
# «Дано» — человек, чьё проверочное значение положено ПОСЕВОМ и несёт признак
# формата A (bcrypt `2a`) либо B (argon2id), пароль с посева не менялся (Д-01,
# Д-02). Значения строит сторонняя библиотека, кладёт посев
# `tests/authz-fixtures/seed_stored_value.py` (подкоманда `seed-stored-value`
# стенда посадки `own`) и утверждает его ЗНАЧЕНИЕМ В ХРАНИЛИЩЕ, а не входом:
# успешный вход переписывает формат A (Р5), и посев, доказавший себя входом,
# отдал бы кейсу уже не «Дано». Поэтому первый успешный вход этого человека —
# шаг кейса ниже, и только он.
#
# Близнец каждого положительного — НЕВЕРНЫЙ пароль тому же человеку, и он стоит
# ПЕРВЫМ: отказ значение не переписывает (PWV-08.7), а успешный вход — да, и
# близнец после него судил бы уже другое значение. Различие с положительным одно —
# пароль.
#
# «Требования сменить или сбросить пароль ответ не несёт» (Ф1 Р1, Р8) утверждается
# составом тела: ключей ровно два — `session` и `user`. Ключ требования не назван
# ни одной приёмкой, и проверка «нет ключа с таким-то именем» зеленела бы на любом
# другом.
#
# Повторный прогон набора на том же стенде без нового посева встретит у человека
# формата A уже переписанное значение, и «на формате A» станет неправдой при
# зелёном кейсе. Посев поэтому стоит в конвейере перед каждым прогоном набора
# (`chart-own`), а люди у него свежие на каждый посев.
# ═══════════════════════════════════════════════════════════════════════════

_STORED_WHY = ("посев хранимых значений (`stand-chart.sh seed-stored-value`) не исполнялся на "
               "этом стенде — человека с положенным значением формата нет")


def _stored_given(letter):
    """Условие кейса: посев положил человека формата `letter` — иначе третий исход."""
    email, pw = f"storedValue{letter}Email", f"storedValue{letter}Password"
    return [
        f"if (!pm.environment.get({js_str(email)}) || !pm.environment.get({js_str(pw)})) {{",
        *precondition_not_met(f"«Дано» PWV формата {letter}: {email} и {pw} заданы",
                              f"{email}/{pw} пусты — {_STORED_WHY}", indent="  "),
        "}",
    ]


def _body_is_session_and_user(label):
    return [
        f"pm.test({js_str(label + ': тело — ровно session и user, требования сменить пароль нет')}, () => {{",
        "  const j = pm.response.json();",
        "  pm.expect(Object.keys(j).sort(), JSON.stringify(Object.keys(j))).to.eql(['session', 'user']);",
        "});",
    ]


def _stored_format_case(letter, position, fmt, sid):
    src, tok, form, ses = f"llSv{letter}Src", f"llSv{letter}Tok", f"llSv{letter}Form", f"llSv{letter}Session"
    email, pw = "{{storedValue" + letter + "Email}}", "{{storedValue" + letter + "Password}}"
    given = _stored_given(letter)
    return Case(
        id=f"IAM-LOGINLANE-OK-STORED-FORMAT-{letter}",
        title=f"Значение формата {letter} ({fmt}), положенное посевом: прежний пароль входит без требования "
              f"смены; неверный отвергнут тем же отказом ({position})",
        classes=["CRUD", "NEG", "SEC"],
        priority="P0",
        steps=[
            _csrf(f"{sid}-csrf", "login", tok, form, src, fresh_context=True, first=True),
            _login(f"{sid}-wrong-password-first", email, "not-the-password-{{runId}}", tok, form, src,
                   _refused_401(f"{sid.upper()}-WRONG"), extra_pre=given),
            _login(f"{sid}-right-password", email, pw, tok, form, src,
                   [*_login_ok(f"{sid.upper()}-RIGHT", ses, form, verified=False),
                    *_body_is_session_and_user(f"{sid.upper()}-RIGHT")],
                   extra_pre=given),
        ],
    )


CASES.append(_stored_format_case("A", "PWV-01", "bcrypt 2a, стоимость 12", "pwv01"))
CASES.append(_stored_format_case("B", "PWV-02", "argon2id, проходов больше ручки", "pwv02"))


# ═══════════════════════════════════════════════════════════════════════════
# FP-12 (kaname#213): вошедшая ключом личность без пароля заводит первый пароль
# из живой сессии и входит им.
#
# Техники: переход состояния способов входа (только ключ → ключ и пароль),
# положительный и отрицательный исход одного глагола на одной личности
# (заведение → повтор заведения — FP-02), классы эквивалентности пароля при
# входе (заведённый — иной). Различие повтора против заведения — одно: у
# субъекта появилась строка «пароль».
# ═══════════════════════════════════════════════════════════════════════════

import ast as _ast
import json as _json

_ACCESS_KEY_BEGIN = "/iam/v1/auth/access-key/begin"
_ACCESS_KEY_LOGIN = "/iam/v1/auth/access-key/login"
_PASSWORD_ENROLL = "/iam/v1/auth/password/enroll"
_ALREADY_SET = "password is already set; change it with the current password"
_KEY_PERSON_WHY = ("посев личности с ключом (`stand-chart.sh seed-stored-value` → "
                   "`tests/authz-fixtures/seed_key_person.py`) не исполнялся на этом стенде — "
                   "личности без пароля с ключом нет")
# Флаги утверждения: присутствие и проверка пользователя (WebAuthn L2 §6.1).
_FLAGS_UP_UV = 0x01 | 0x04


def _authenticator_lib():
    """`_LIB` подставного аутентификатора набора ключей доступа — разбором модуля.

    Материал (`_KEYS`) читается литералом; первая строка `_LIB` — объявление
    материала в JS — собирается тем же выражением, что в модуле, и форма этого
    выражения сверяется: модуль, сменивший её, роняет генерацию, а не уезжает
    второй копией."""
    path = _pathlib.Path(__file__).resolve().parent / "kaname-access-keys.py"
    tree = _ast.parse(path.read_text(encoding="utf-8"))
    nodes = {t.id: n.value for n in tree.body if isinstance(n, _ast.Assign)
             for t in n.targets if isinstance(t, _ast.Name)}
    if "_KEYS" not in nodes or "_LIB" not in nodes or not isinstance(nodes["_LIB"], _ast.List):
        raise SystemExit("kaname-login-lane: в kaname-access-keys.py нет _KEYS либо _LIB списком — "
                         "подставного аутентификатора для FP-12 нет")
    keys = _ast.literal_eval(nodes["_KEYS"])
    head = _ast.unparse(nodes["_LIB"].elts[0])
    if head != "'const _akKeys = ' + _json.dumps(_KEYS, separators=(',', ':')) + ';'":
        raise SystemExit(f"kaname-login-lane: первая строка _LIB сменила форму ({head}) — сверить разбор")
    lib = ["const _akKeys = " + _json.dumps(keys, separators=(",", ":")) + ";"]
    for elt in nodes["_LIB"].elts[1:]:
        if not (isinstance(elt, _ast.Constant) and isinstance(elt.value, str)):
            raise SystemExit("kaname-login-lane: _LIB несёт не строку — сверить разбор")
        lib.append(elt.value)
    return lib


_AK_LIB = _authenticator_lib()


def _key_person_given():
    return [
        "if (!pm.environment.get('keyPersonEmail') || !pm.environment.get('keyPersonCredentialId') "
        "|| !pm.environment.get('keyPersonUserHandle') || !pm.environment.get('keyPersonOrigin')) {",
        *precondition_not_met("«Дано» FP-12: keyPersonEmail, keyPersonCredentialId, keyPersonUserHandle, "
                              "keyPersonOrigin заданы", "ключи пусты — " + _KEY_PERSON_WHY, indent="  "),
        "}",
    ]


def _no_session_reissued(label):
    return [
        f"pm.test({js_str(label + ': носитель сессии НЕ перевыпущен')}, () => "
        "pm.expect(pm.response.headers.all().filter(h => h.key.toLowerCase() === 'set-cookie' "
        "&& h.value.startsWith('kaname_session=')).length, JSON.stringify(pm.response.headers.all())).to.eql(0));",
    ]


def _enroll(name, session_var, form_var, tok_var, test):
    return _post(name, _PASSWORD_ENROLL, {"newPassword": "{{llFpPassword}}", "csrfToken": "{{" + tok_var + "}}"},
                 "llFpSrc", [("kaname_session", session_var), ("kaname_form", form_var)], test)


def _csrf_with_session(name, form, session_var):
    step = _csrf(name, form, "llFpTok", "llFpForm", "llFpSrc")
    step.pre_script = [*_lane_via(_CSRF + "?form=" + form, "llFpSrc"),
                       *_with_cookies(("kaname_form", "llFpForm"), ("kaname_session", session_var))]
    return step


def _fp12_first_csrf():
    """Первый шаг кейса: свой источник и свой пароль на прогон — пароль уходит
    в переменную со словом `Password`, и чистка отчёта режет её именем."""
    step = _csrf("fp12-csrf-key-begin", "access-key-begin", "llFpTok", "llFpForm", "llFpSrc",
                 fresh_context=True, first=True)
    step.pre_script = [
        "pm.environment.set('llFpPassword', 'Fp12-' + Math.floor(Math.random() * 2176782336).toString(36) "
        "+ Math.floor(Math.random() * 2176782336).toString(36) + '-first');",
        *step.pre_script,
    ]
    return step


CASES.append(Case(
    id="IAM-LOGINLANE-OK-FP12-KEY-PERSON-ENROLLS-PASSWORD",
    title="FP-12: вошедшая ключом личность без пароля заводит пароль и входит им; повтор заведения — 409",
    classes=["CRUD", "NEG", "SEC"],
    priority="P0",
    steps=[
        _fp12_first_csrf(),
        Step(name="fp12-key-begin", method="POST", path=_ACCESS_KEY_BEGIN, body={"csrfToken": "{{llFpTok}}"},
             pre_script=[*_key_person_given(), *_lane_via(_ACCESS_KEY_BEGIN, "llFpSrc"),
                         *_with_cookies(("kaname_form", "llFpForm"))],
             insecure_tls=True, auth="anonymous", cookie_jar=False,
             test_script=[
                 *assert_status(200),
                 "const j = pm.response.json();",
                 "const pk = j.publicKey || {};",
                 "pm.test('FP12-BEGIN: испытание выдано, круг удостоверений не ограничен', () => "
                 "pm.expect([typeof pk.challenge === 'string' && pk.challenge.length > 0, typeof pk.rpId, "
                 "Array.isArray(pk.allowCredentials) && pk.allowCredentials.length === 0])"
                 ".to.eql([true, 'string', true]));",
                 "pm.environment.set('llFpChallenge', pk.challenge || '');",
                 "pm.environment.set('llFpRpId', pk.rpId || '');",
             ]),
        _csrf("fp12-csrf-key-login", "access-key-login", "llFpTok", "llFpForm", "llFpSrc"),
        Step(name="fp12-key-login", method="POST", path=_ACCESS_KEY_LOGIN, body={},
             pre_script=[
                 *_key_person_given(),
                 *_AK_LIB,
                 "const _fpU = (s) => s.split('+').join('-').split('/').join('_').split('=').join('');",
                 "const _fpA = _ak.assert({ challenge: _ak.unb64(pm.environment.get('llFpChallenge') || ''), "
                 "rpId: pm.environment.get('llFpRpId') || '', origin: pm.environment.get('keyPersonOrigin') || '', "
                 f"flags: {_FLAGS_UP_UV}, count: 1, credId: _ak.unb64(pm.environment.get('keyPersonCredentialId') || ''), "
                 "key: 0, tamper: false });",
                 "const _fpBody = JSON.stringify({ csrfToken: pm.environment.get('llFpTok'), credential: { "
                 "id: _fpU(_fpA.id), rawId: _fpU(_fpA.id), type: 'public-key', response: { "
                 "clientDataJSON: _fpU(_fpA.clientDataJson), authenticatorData: _fpU(_fpA.authenticatorData), "
                 "signature: _fpU(_fpA.signature), userHandle: pm.environment.get('keyPersonUserHandle') } } });",
                 "pm.request.body = { mode: 'raw', raw: _fpBody, options: { raw: { language: 'json' } } };",
                 *_lane_via(_ACCESS_KEY_LOGIN, "llFpSrc"),
                 *_with_cookies(("kaname_form", "llFpForm")),
             ],
             insecure_tls=True, auth="anonymous", cookie_jar=False,
             test_script=[*_login_ok("FP12-KEY-LOGIN", "llFpKeySession", "llFpForm", verified=True)]),
        _csrf_with_session("fp12-csrf-enroll", "password-enroll", "llFpKeySession"),
        _enroll("fp12-enroll", "llFpKeySession", "llFpForm", "llFpTok", [
            *assert_status(200),
            "const j = pm.response.json();",
            "pm.test('FP12-ENROLL: тело — сессия формы Ф3-01', () => "
            "pm.expect([Object.keys(j), typeof (j.session && j.session.expiresAt)])"
            ".to.eql([['session'], 'string']));",
            *_no_session_reissued("FP12-ENROLL"),
        ]),
        _csrf_with_session("fp12-csrf-logout", "logout", "llFpKeySession"),
        _post("fp12-logout", _LOGOUT, {"csrfToken": "{{llFpTok}}"}, "llFpSrc",
              [("kaname_session", "llFpKeySession"), ("kaname_form", "llFpForm")],
              [*assert_status(200)]),
        _csrf("fp12-csrf-login", "login", "llFpTok", "llFpForm", "llFpSrc"),
        _login("fp12-login-other-password", "{{keyPersonEmail}}", "not-the-password-{{runId}}", "llFpTok",
               "llFpForm", "llFpSrc", _refused_401("FP12-OTHER-PASSWORD")),
        _login("fp12-login-enrolled-password", "{{keyPersonEmail}}", "{{llFpPassword}}", "llFpTok", "llFpForm",
               "llFpSrc", _login_ok("FP12-PASSWORD-LOGIN", "llFpPwSession", "llFpForm", verified=True)),
        _csrf_with_session("fp12-csrf-enroll-again", "password-enroll", "llFpPwSession"),
        _enroll("fp12-enroll-again", "llFpPwSession", "llFpForm", "llFpTok", [
            *assert_status(409),
            *assert_grpc_code(6, "ALREADY_EXISTS"),
            *_message(_ALREADY_SET, "FP12-ENROLL-AGAIN"),
            *_reason("PASSWORD_ALREADY_SET", "FP12-ENROLL-AGAIN"),
            *_no_session("FP12-ENROLL-AGAIN"),
        ]),
    ],
))

