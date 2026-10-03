# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set ключей доступа: шесть глаголов `AccessKeyService` сквозь собственный фронт (Ф7, kaname#268).

ПРЕДМЕТ — приёмка `docs/engineering/acceptance/access-keys-are-ours.md` в
одобренной редакции 12 (отпечаток `3ab7b401…`, запись
`docs/specs/reviews/access-keys-are-ours/3ab7b4011a658e6ef2e0c2fad2abbff949179992f3ac0d203e009804e0bd8b3d.yaml`,
`APPROVED`). Кейсы написаны чёрным ящиком по её §3 и по контракту
`proto/kaname/cloud/iam/v1/access_key_service.proto`, а не по коду
обработчиков: церемония регистрации (испытание → результат), перечень,
снятие, испытание предъявления → утверждение.

АДРЕСА — ЧЕТЫРЕ ПОВЕРХНОСТИ СЛУЖБЫ, у каждой своя переменная:

  {{loginLaneBaseUrl}}         — слушатель формы (регистрация, подтверждение
                                 адреса, вход паролем; посадка `own`)
  {{standMailboxUrl}}          — приёмник писем стенда: код подтверждения адреса
  {{iamRegistryTokenBaseUrl}}  — поверхность выдачи: точка авторизации и обмен
                                 кода на токен человека
  {{ownRestBaseUrl}}           — собственный публичный фронт: шесть глаголов
                                 ключа и опрос операций

Клиента церемонии `authorization_code` набор не заводит, а читает — его заводит
посев церемонии (`seed_ceremony.py`): `{{oauthClientId}}`, `{{oauthClientSecret}}`,
`{{oauthRedirectUri}}`. Непосеянный ключ — «условие не создано» помеченным
утверждением, а не зелёное и не красное.

СВОИ ЛЮДИ НА ПРОГОН. Человек посева — общий у шести наборов той же двери, и его
ключи пережили бы прогон, а потолок `iam.user.accessKey` считает ключи
человека. Поэтому набор заводит двух своих людей регистрацией (адрес с
`{{runId}}` и случайной добавкой, свой источник), подтверждает их адреса кодом из
письма и входит каждым паролем. Токен человека выковывается нашей церемонией:
вход → код → обмен; предъявляется он собственному фронту. Окно свежести (Р5)
открывает вход: регистрация и снятие идут внутри него, и перед снятием, после
ожидания срока испытания, человек входит заново — окно открывается
предъявлением, а не ожиданием (Ф7-04, положительная сторона).

АУТЕНТИФИКАТОР — ПОДСТАВНОЙ, В ПЕСОЧНИЦЕ ПРОГОНЩИКА (§8 приёмки: «подставной
аутентификатор обязан уметь отдать результат со снятым битом»). Ключ — RSA 2048
(`RS256`, COSE `-257`), подпись — RSASSA-PKCS1-v1_5 над SHA-256 возведением в
степень `BigInt` по китайской теореме об остатках; `authData`,
`attestationObject` и открытый ключ COSE кодируются CBOR вручную; аттестация
`none` (Р4). Материал двух ключей лежит ниже константой: это не удостоверение
продукта, а ключ ПОДСТАВНОГО аутентификатора, значимый только для строк,
заведённых этим набором на стенде, и снятых им же. Идентификатор удостоверения
— случайный на прогон, поэтому повторный прогон заводит другие удостоверения.

ЧТО ДЕЛАЕТ НАБОР СЕМЕЙСТВОМ ВЕЛИЧИН, А НЕ ЛИТЕРАЛОМ. Имя доверяющей стороны,
перечень происхождений, перечень алгоритмов и потолок ключей объявляет
ПРОФИЛЬ посадки (Р2, Р8), а стенд `chart-own` ставит `deploy/values.prod.yaml`
как есть. Набор читает их из профиля при генерации — тем же способом, что набор
подтверждения адреса читает интервал писем, — и второе вхождение ключа в
профиле роняет генерацию с именем ключа.

ЕДИНЫЙ ОТКАЗ АУТЕНТИФИКАЦИИ (§3.0) СУДИТСЯ ПОБАЙТОВО. Первый отказ полосы
утверждения (Ф7-07, подделанная подпись) записывает тело ответа; каждая
следующая полоса сравнивает своё тело с ним целиком (`pm.response.text()`), а не
код и текст порознь: продукт, чей отказ на одной полосе отличается хоть байтом,
красный здесь.

ОТЧЁТ ПУБЛИКУЕТСЯ, И УДОСТОВЕРЕНИЯ НЕ ПОПАДАЮТ В ПРОЗУ. Тело запроса регистрации
и утверждения лежит под именем `credential` (чистка отчёта режет его именем),
токен человека — в переменной со словом `Token`, пароль — `Password`, код
письма и код церемонии — последним словом `Code`, печенья — `Cookie`, признак
формы — `Csrf`. Утверждения значений удостоверений не получают: сообщение —
литерал, предмет — булево либо число.

ПОРЯДОК КЕЙСОВ НЕСУЩИЙ: люди и ключи одни на набор, и каждый кейс стоит на
состоянии, которое оставил предыдущий. Испытание регистрации (человек A
заводится здесь) → заведение и утверждение → ось испытания регистрации → оси
результата церемонии → единый отказ утверждения → чужой ключ и чужое испытание
(человек B заводится здесь) → потолок → срок испытаний → снятие. Последний кейс
снимает все ключи обоих людей: следующий прогон заводит своих.

Coverage (техники: классы эквивалентности результата церемонии и утверждения;
таблица решений «ось × полоса»; граничные значения имени, описания и потолка;
переходы состояния испытания — выдано · предъявлено · просрочено; угадывание
ошибок — чужой ключ, чужое испытание, повтор; положительный близнец у каждого
отказа):
  IAM-ACCESSKEY-OK-REGISTRATION-CHALLENGE-NAMES-THE-CONTRACT
                                          — Ф7-40: испытание регистрации называет шесть
                                            величин контракта, каждая равна объявленной
                                            (имя и алгоритмы — профилю, видимое имя
                                            непусто, проверка пользователя
                                            «preferred», обнаруживаемое «required»,
                                            аттестация «none»), запрос свойств
                                            удостоверения, срок меньше окна свежести
  IAM-ACCESSKEY-OK-REGISTER-LIST-ASSERT   — Ф7-01: результат церемонии → операция →
                                            ключ `ak-…` в перечне с именем, равным `id`
                                            (Ф7-46, пустое имя), описанием и моментом;
                                            Ф7-41: «обнаруживаемое» принимается; Ф7-42:
                                            испытание предъявления «preferred» и свои
                                            удостоверения; Ф7-06: утверждение называет
                                            вызывающего, момент предъявления сдвинулся;
                                            Ф7-28: флаги доезжают различимо
  IAM-ACCESSKEY-NEG-REGISTRATION-CHALLENGE-AXIS
                                          — Ф7-02: результат над невыданным испытанием —
                                            отказ CHALLENGE_NOT_ISSUED; Ф7-03: тот же
                                            результат повторно — CHALLENGE_ALREADY_PRESENTED;
                                            перечень прежний, ключ один
  IAM-ACCESSKEY-NEG-CEREMONY-RESULT-AXES  — на одном испытании: Ф7-35 алгоритм вне
                                            перечня, Ф7-41 «не обнаруживаемое», Ф7-44
                                            происхождение вне перечня при совпадающем
                                            заголовке, Ф7-45 хэш чужого имени, Ф7-48
                                            проверка без присутствия, Ф7-46 три имени и
                                            описание 257 — отказы с полем и правилом;
                                            перечень прежний; положительный контроль на
                                            том же испытании — имя `moy-noutbuk`,
                                            описание 256, свойства не сообщены,
                                            присутствие без проверки — принят
  IAM-ACCESSKEY-NEG-ASSERTION-SINGLE-REFUSAL
                                          — единый отказ, тела побайтово равны: Ф7-07
                                            подпись, Ф7-08 подписано вторым ключом,
                                            Ф7-09 неизвестное удостоверение, Ф7-10 и
                                            Ф7-11 происхождение вне перечня (с
                                            заголовком), хэш чужого имени, Ф7-49 без
                                            присутствия, Ф7-18 счётчик не вырос, Ф7-52
                                            невыданное испытание; моменты не
                                            сдвинулись; положительный контроль на том
                                            же испытании (Ф7-17), Ф7-53 повтор — тот же
                                            отказ; Ф7-19 ноль не судится; Ф7-29/Ф7-30
                                            флаги без проверки и с резервом
  IAM-ACCESSKEY-NEG-FOREIGN-KEY-AND-FOREIGN-CHALLENGE
                                          — Ф7-05: идентификатор принятого удостоверения
                                            своим и чужим — отказы равны, ключи не
                                            переназначены; Ф7-51: чужой ключ из своей
                                            сессии — единый отказ, свой проходит;
                                            Ф7-55: испытание, выданное второму, из
                                            сессии первого — единый отказ, второй
                                            проходит на нём же
  IAM-ACCESSKEY-BVA-CEILING               — Ф7-37: ключей ровно потолок — принят; ещё
                                            один — отказ со следующим шагом и величиной;
                                            Ф7-14: первый ключ проходит; снятие
                                            возвращает слот; потолок другого человека
                                            не расходуется
  IAM-ACCESSKEY-BVA-CHALLENGE-EXPIRY      — Ф7-34: результат над испытанием регистрации
                                            за сроком — CHALLENGE_EXPIRED со следующим
                                            шагом; Ф7-54: утверждение над испытанием
                                            предъявления за сроком — единый отказ;
                                            срок — из ответа службы, не литерал
  IAM-ACCESSKEY-NEG-REVOKE-REFUSALS-AND-REVOKE
                                          — Ф7-47 (б): негодная форма `id` — синхронный
                                            отказ формы; Ф7-27: чужой ключ и годная
                                            форма без строки — один отказ; чужой
                                            известный тип — тот же; Ф7-25: снятый ключ
                                            перестаёт проходить, второй проходит;
                                            уборка — все ключи обоих людей сняты
"""

# ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — и почему; идентификаторы здесь КОММЕНТАРИЕМ, а не
# строкой (перепись долга считает позицию несомой по строковому литералу модуля).
#   · Ф7-04 и Ф7-36 (окно свежести ИСТЕКЛО) — «Дано» требует 15 минут без
#     предъявления; набор этой двери уже ждёт окно профиля в наборе второго
#     фактора, второе такое ожидание удвоило бы предел шага задания. Отказ
#     `SESSION_NOT_FRESH` держит уровень I (`internal/apps/kaname/api/access_keys/usecase_test.go`);
#     положительная сторона — повторный вход перед снятием — здесь;
#   · Ф7-12 в собственной форме («служба объявляет имя B» и возврат к A) — смена
#     ручки посадки посреди прогона, стенд её не делает; полосу хэша чужого имени на
#     утверждении набор судит тем же единым отказом (кейс единого отказа), а
#     полосу церемонии — Ф7-45;
#   · Ф7-13 и Ф7-38 — отказ старта, предмет — профиль, а не глагол: уровень I и
#     стражи чарта;
#   · Ф7-15 и Ф7-20 — конкуренция, исход зависит от порядка фиксации: уровень I
#     (testcontainers Postgres);
#   · Ф7-16, Ф7-31, Ф7-32, Ф7-39 — независимость таблиц, представление и
#     снятие обещания на странице: уровень I и гейты дерева;
#   · Ф7-26 — «Дано» есть человек, у которого единственный способ входа — ключ:
#     такого человека не заводит ни один глагол дерева (регистрация ключом —
#     `kacho#2703`, вход ключом — Ф13 `kacho#1282`), и стенд его не строит;
#   · Ф7-33 — поле множества предъявленного объявляет Ф11, наружу его не
#     отдаёт ни один ответ фронта;
#   · Ф7-47 (а) — пустой идентификатор в пути REST-маршрута не выразим:
#     маршрутизатор не сопоставляет путь с пустым сегментом, и шаг судил бы
#     маршрутизацию, а не глагол; ветвь держит уровень I;
#   · поток аудита (Ф7-01, Ф7-25) — наружу фронта не выходит; держит уровень I.

import json as _json
import pathlib as _pathlib
import re as _re
import urllib.parse as _urlparse

HOME = "kaname"

CASES = []

# ── поверхности ──────────────────────────────────────────────────────────────

_LANE = "loginLaneBaseUrl"
_LANE_WHY = ("слушатель полосы формы службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это условие, которого стенд не создал")
_MAILBOX = "standMailboxUrl"
_MAILBOX_WHY = ("чтение приёмника писем стенда посадки `own`; адрес пишет посев полосы "
                "входа — вне стенда `own` приёмника нет")
_ISSUANCE = "iamRegistryTokenBaseUrl"
_ISSUANCE_WHY = ("поверхность выдачи службы: точка авторизации и токен-эндпоинт церемонии "
                 "стоят на ней и больше нигде")
_OWN_WHY = ("собственный публичный фронт службы: шесть глаголов ключа доступа и опрос "
            "операций стоят на нём")

_CSRF = "/iam/v1/auth/csrf"
_REGISTER = "/iam/v1/auth/register"
_LOGIN = "/iam/v1/auth/login"
_VERIFY_CONFIRM = "/iam/v1/auth/verify-email/confirm"
_AUTHORIZE = "/iam/v1/authorize"
_TOKEN = "/iam/v1/token"

_HEAD_VERIFY = "Код подтверждения:"
_MAIL_WAIT_CAP = 90
_MAIL_WAIT_MS = 1000

# ── величины профиля ─────────────────────────────────────────────────────────

_PROFILE = _pathlib.Path(__file__).resolve().parents[3] / "deploy" / "values.prod.yaml"


def _profile_text():
    return _PROFILE.read_text(encoding="utf-8")


def _profile_access_keys():
    """Блок `authn.accessKeys` профиля: имя, происхождения, алгоритмы — ровно одно вхождение."""
    found = _re.findall(
        r"^  accessKeys:\n    rpId: (\S+)\n    origins:\n((?:      - \S+\n)+)    algorithms: \[([^\]]*)\]\s*$",
        _profile_text(), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-access-keys: блок authn.accessKeys найден {len(found)} раз в {_PROFILE} "
                         "в форме «rpId · origins · algorithms» — ждали ровно один")
    rp_id, origins_raw, algs_raw = found[0]
    origins = _re.findall(r"^      - (\S+)$", origins_raw, _re.M)
    algorithms = [int(a.strip()) for a in algs_raw.split(",") if a.strip()]
    if not origins or not algorithms:
        raise SystemExit("kaname-access-keys: профиль объявляет пустой перечень происхождений либо "
                         "алгоритмов — церемония на стенде неисполнима, набор нечем гонять")
    if -257 not in algorithms:
        raise SystemExit("kaname-access-keys: профиль не допускает RS256 (-257) — подставной "
                         "аутентификатор набора подписывает только им")
    return rp_id, origins, algorithms


def _profile_ceiling():
    found = _re.findall(r"^  accessKeysPerUser: (\d+)\s*$", _profile_text(), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-access-keys: ключ ownCeilings.accessKeysPerUser найден {len(found)} "
                         f"раз в {_PROFILE} — ждали ровно один")
    return int(found[0])


_RP_ID, _ORIGINS, _ALGORITHMS = _profile_access_keys()
_ORIGIN = _ORIGINS[0]
_CEILING = _profile_ceiling()
# Кейс потолка стоит на двух ключах человека A (Ф7-01 и положительный контроль
# осей церемонии): при потолке ниже трёх «Дано» кейсов до него не строится.
if _CEILING < 3:
    raise SystemExit(f"kaname-access-keys: потолок ключей профиля {_CEILING} < 3 — порядок кейсов "
                     "заводит два ключа до кейса потолка")

# Происхождение и имя, которых профиль НЕ объявляет: поддомен того же корня
# (аутентификатор собирает такой результат без отказа — §1.2 приёмки) и чужое имя.
_FOREIGN_ORIGIN = "https://elsewhere." + _RP_ID
_FOREIGN_RP_ID = "elsewhere-" + _RP_ID
if _FOREIGN_ORIGIN in _ORIGINS:
    raise SystemExit("kaname-access-keys: «чужое» происхождение набора объявлено профилем")

# ── контракт (приёмка Р9, Р4, Ф7-34; тексты отказа — контракт фронта) ────────

_UV_PREFERRED = "preferred"
_RESIDENT_REQUIRED = "required"
_ATTESTATION_NONE = "none"
_FRESHNESS_WINDOW_S = 15 * 60
_REFUSAL_DOMAIN = "iam.kaname.cloud"
_ASSERTION_REFUSED = "access key assertion is not accepted"
_CHALLENGE_NOT_ISSUED = ("CHALLENGE_NOT_ISSUED", "registration challenge was not issued: begin registration again")
_CHALLENGE_PRESENTED = ("CHALLENGE_ALREADY_PRESENTED",
                        "registration challenge was already presented: begin registration again")
_CHALLENGE_EXPIRED = ("CHALLENGE_EXPIRED", "registration challenge expired: begin registration again")
_ORIGIN_REFUSED = ("ORIGIN_NOT_ALLOWED", "credential origin is not in the declared list")
_RP_REFUSED = ("RP_ID_MISMATCH", "credential was created for another relying party")
_UP_REFUSED = ("USER_NOT_PRESENT", "authenticator did not report user presence")
_ALG_REFUSED = ("ALGORITHM_NOT_ALLOWED", "credential public key algorithm is not in the declared list")
_NOT_DISCOVERABLE = ("CREDENTIAL_NOT_DISCOVERABLE",
                     "credential is not discoverable: a discoverable credential is required")
_CEILING_NEXT_STEP = "revoke an access key you no longer need"
# Алгоритм вне словаря проверяющего и вне профиля: PS256 (COSE -37).
_ALG_OUTSIDE = -37

# Флаги данных аутентификатора (WebAuthn L2 §6.1).
_UP, _UV, _BE, _BS, _AT = 0x01, 0x04, 0x08, 0x10, 0x40

# ── подставной аутентификатор ────────────────────────────────────────────────
#
# Два ключа RSA 2048: n, e и компоненты китайской теоремы об остатках. Ключ 0 —
# основной, ключ 1 — «второй ключ того же человека» (Ф7-08) и ключ человека B.
_KEYS = [
    {
        "n": (
            "91572056d7ad57ef06dcc0f6884fc039d3377b17eacc571196329234f8836784"
            "15f1778e894e6ec7e942091c8a5fda9ea346bcecc41c84eb6dd38a62b559283b"
            "6b68de835a32ae377097017e0054431e35feffb0f217df1eb3b8f37e00cf42a7"
            "34dbbd1edeee41f13b3d101739bb84ff63eb96a9b0bd1458ce2603c1347eb1a8"
            "41dc50f588bd3fae7b5babe2b5a0587499b9901569c96cab63389c165f8c761f"
            "2061d98927d272a1b6689ab12849d566356bb8da7349a60061c626333869e5d8"
            "e76cc2f124bb2f3aedc5b054d1b72256bcbc447e7461983e5671559c59c18d02"
            "cb3101ed6ef61149d8502776abfc736d6fc6430731563b31a6d40529edfdbe0b"
        ),
        "e": "010001",
        "p": (
            "c14b1ca28dbc97798355e81b4828da6c8d67bd9bb3b231eb554d367da814769d"
            "4c40f64774a031348fe53d676f0d3eafc36debf64185e95ffeb255a2a31be8d1"
            "6c2d3e7ad6f5935cd9b4e509a5955b5f516fb196b68a8f974a4bde2d408c6b50"
            "d8a46a7dc78c3bcb0217ba5771b3bced520682838be0012778f4ab8c298706e7"
        ),
        "q": (
            "c07d8b4faddcf54ebbd2a98181eb05a254d780f08b786be8135745e36950cae9"
            "06d052021fb1ae71e14a5854ba85478bcd5c8eef626b4ff875ae303c0f9c3da3"
            "5909c601c6a5cb8aace2174a011e4c49f4e8fa71d7509c4b639904811ecbf93c"
            "0a793925a58e9b621157c037407f8fbd8e70bceb810e20936334bc18ee67ff3d"
        ),
        "dp": (
            "5d767d451875cd64831de1da773cd1c8d563092aa56c0f793448de8549e58329"
            "31fae35acfc8b9a229c5f5b7f2d99bab0f3b3272636265e2f5dbb34eadc1cc04"
            "9f630d280692be0b9275469e308394a7f54fa5b63353b274bc070d4a2241038f"
            "170201400a62037378f29236c012e1d27aec0ce5a097d2d70c447a428ebdec97"
        ),
        "dq": (
            "5b9ca4ac046c7017cbce843c0df0241b5153cb9b3055dccd743f0a1524af7e13"
            "0fda1fddc0e5d8c77c58dcd75e7a4645e4345416dc79847314d7153fd09224c7"
            "d47d914e9113a15edbcf33145699ebe71af7b312714e7d44681f90843f7b06a0"
            "abbf6c125dcc1469c5254567467c2f9620efc90a30bedf8426281809a995b765"
        ),
        "qi": (
            "15065c255aa1c0cde367b0871bf18d6fdc07bcbe0c1e49f6a33dd67fbc2bfa09"
            "5dd93f68ddea3b0793c8388815c320e4ebd26994daa3770654e6e38208469ca4"
            "8f6ac7498a6874597b9090a182a49b669b536bd5411b0266f9ec749e31ca2712"
            "c3f715451893e9ea6bf39d57e31688bf319d486ad9c8dd2c174cb57e541eec4e"
        ),
    },
    {
        "n": (
            "c6dfa590a3c13a2901429dfc6b5d36566e67fef9b701c90e90f3bca6a2e9d1f4"
            "ad97151586339795e378fb2233dce73b24ce8cfcd9d85d8dc2a1a695bdfdee05"
            "10cf1390e69d5f1710a9272fa17f584a6f7d63df304520a03d690d6f55c78dc9"
            "d342da8c68ce02b40f7f62586aa64ac2418fcbe4414b34fcde4179cc813586cf"
            "07b1253cb84c3c30a863b920dae6791c2a48ad05e8a1bb3e6bd1f5a0be47b856"
            "a7b9377f3e0d6ceded50675f9fa49195ec8064b22822d65a1bf216b7840707c2"
            "cee4f9c835e2ff5f1728a3c92610a2d86a6c5c476baa4cfcb5ac753d4f15db6d"
            "d7363ab6b0b3f628dffa9186748801941ab7cbd5d42d831fb38782ccda6377eb"
        ),
        "e": "010001",
        "p": (
            "ed3c54048fa2f03aead86b7a5923340b29f767619419e8a9252758ee646c03d2"
            "14d26ed226733a93034b1b0dc313ed5a98e5148095bfd5ac411c729909f4dbbb"
            "73e562801389e79b53d3bea0d79e2462b17f2b0f7f6996e00aaecfd2a616be73"
            "1d1ffa36164e89202867831357319a3e6d9f0710b8f6e4ad4a54d9701db81513"
        ),
        "q": (
            "d69a8b3f287043a65b18b66a841f4c4af58251845142c5a18ee5d71fd8176277"
            "56e091030dc3aae3db98cf5b0f5cf5d4fcbb844902c0a6da4bc1365f8d4f4f77"
            "638264a29970d81cda7c7da3034672fd0dba7dfac6a46bb192b76361214ab627"
            "cd24ba1cc5fc3535b465bcf5dc32ac261159e12a9a9b92314af0d0b22652e4c9"
        ),
        "dp": (
            "98911aab504086642d91ff14d0ec7dd4cc296a97eb69fa21855e57a8007722c1"
            "e1582fa300cd4c172da008870234f7893318e7e585e8b81eae4500420190321b"
            "cc7df1a9d266f6c702d3031e676c319432f848960fe7b4fae283e7ed5d98f4e4"
            "0d0ffa96fc2387b661a5a83b30f11a7419859342a2e14cd151235e2ee73df277"
        ),
        "dq": (
            "149f81662e62ab7d9f1f7ed8399e305cbbbf2c4a44ecdfc528d0599e0bcc2380"
            "486f08407ce022da06ce668edfa9154ec482d8b1937c240cb25efcf4adc5c363"
            "3bc2da1cee15f40ec1c858e2837c0facd5d6e828635285aee8e48abe58ceaf36"
            "9ff639946e4a506abacd541d646dd2314e558ed7e347b402dcaacbc372ff6051"
        ),
        "qi": (
            "b58e15320d76225ec26040961ad70a6b7ed598b0539b9d6854226a956e39777d"
            "5e1b2aa7fb849b30c124665d21e81c4f98e532a2f9f669a9f7cb9885b67b9e3a"
            "d2353f8461e32150d595fd8b7e3f21b16eb9e1cfab6f55090969c4d3e9b72360"
            "ec07238b1b003820ddb68aee6e6a3157cddc33baec6b35efbf74f5906be1c9ab"
        ),
    },
]

# Индексы ключей в `_KEYS`: какой материал подписывает какую строку.
_MAT_MAIN, _MAT_SECOND = 0, 1

_LIB = [
    "const _akKeys = " + _json.dumps(_KEYS, separators=(",", ":")) + ";",
    "const _ak = (() => {",
    "  const utf8 = (s) => { const out = []; const e = unescape(encodeURIComponent(s)); for (let i = 0; i < e.length; i++) { out.push(e.charCodeAt(i)); } return out; };",
    "  const AB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';",
    "  const b64 = (b) => { let s = ''; for (let i = 0; i < b.length; i += 3) { const n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);",
    "    s += AB[(n >> 18) & 63] + AB[(n >> 12) & 63] + (i + 1 < b.length ? AB[(n >> 6) & 63] : '=') + (i + 2 < b.length ? AB[n & 63] : '='); } return s; };",
    "  const b64u = (b) => b64(b).split('+').join('-').split('/').join('_').split('=').join('');",
    "  const unb64 = (s) => { s = String(s || '').split('-').join('+').split('_').join('/').split('=').join(''); const out = []; let acc = 0; let bits = 0;",
    "    for (let i = 0; i < s.length; i++) { const v = AB.indexOf(s[i]); if (v < 0) { return null; } acc = ((acc << 6) | v) & 0xffffff; bits += 6;",
    "      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); } } return out; };",
    "  const hex = (b) => b.map((x) => (x < 16 ? '0' : '') + x.toString(16)).join('');",
    "  const unhex = (h) => { const out = []; for (let i = 0; i < h.length; i += 2) { out.push(parseInt(h.slice(i, i + 2), 16)); } return out; };",
    "  const sha256 = (b) => unhex(CryptoJS.SHA256(CryptoJS.enc.Hex.parse(hex(b))).toString(CryptoJS.enc.Hex));",
    "  const rand = (n) => unhex(CryptoJS.lib.WordArray.random(n).toString(CryptoJS.enc.Hex));",
    "  const u32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];",
    "  const u16 = (n) => [(n >>> 8) & 255, n & 255];",
    "  const head = (major, n) => { const m = major << 5; if (n < 24) { return [m | n]; } if (n < 256) { return [m | 24, n]; }",
    "    if (n < 65536) { return [m | 25].concat(u16(n)); } return [m | 26].concat(u32(n)); };",
    "  const cbor = (v) => {",
    "    if (typeof v === 'number') { return v >= 0 ? head(0, v) : head(1, -1 - v); }",
    "    if (typeof v === 'string') { const b = utf8(v); return head(3, b.length).concat(b); }",
    "    if (v && v.bytes) { return head(2, v.bytes.length).concat(v.bytes); }",
    "    if (v && v.map) { let out = head(5, v.map.length); v.map.forEach((kv) => { out = out.concat(cbor(kv[0]), cbor(kv[1])); }); return out; }",
    "    return null; };",
    "  const big = (h) => BigInt('0x' + h);",
    "  const bytesOf = (n, len) => { let h = n.toString(16); if (h.length % 2) { h = '0' + h; } const b = unhex(h); while (b.length < len) { b.unshift(0); } return b; };",
    "  const modpow = (base, exp, mod) => { let r = 1n; base %= mod; while (exp > 0n) { if (exp & 1n) { r = (r * base) % mod; } base = (base * base) % mod; exp >>= 1n; } return r; };",
    "  const DIGEST_INFO = unhex('3031300d060960864801650304020105000420');",
    "  const rsaSign = (k, msg) => {",
    "    const len = k.n.length / 2; const t = DIGEST_INFO.concat(sha256(msg)); const em = [0, 1];",
    "    for (let i = 0; i < len - t.length - 3; i++) { em.push(255); }",
    "    const m = big(hex(em.concat([0], t))); const p = big(k.p); const q = big(k.q);",
    "    const m1 = modpow(m, big(k.dp), p); const m2 = modpow(m, big(k.dq), q);",
    "    const h = (big(k.qi) * (((m1 - m2) % p) + p)) % p;",
    "    return bytesOf(m2 + h * q, len); };",
    "  const cose = (k, alg) => cbor({ map: [[1, 3], [3, alg], [-1, { bytes: unhex(k.n) }], [-2, { bytes: unhex(k.e) }]] });",
    "  const clientData = (type, challenge, origin) => utf8(JSON.stringify({ type: type, challenge: b64u(challenge), origin: origin, crossOrigin: false }));",
    "  const authData = (rpId, flags, count) => sha256(utf8(rpId)).concat([flags], u32(count));",
    # Результат церемонии регистрации: `PublicKeyCredential` с аттестацией `none`.
    "  const register = (o) => {",
    "    const cd = clientData('webauthn.create', o.challenge, o.origin);",
    "    const ad = authData(o.rpId, o.flags, 0).concat(new Array(16).fill(0), u16(o.credId.length), o.credId, cose(_akKeys[o.key], o.alg));",
    "    const att = cbor({ map: [['fmt', 'none'], ['attStmt', { map: [] }], ['authData', { bytes: ad }]] });",
    "    return { id: b64(o.credId), clientDataJson: b64(cd), attestationObject: b64(att) }; };",
    # Утверждение: подпись над authData ‖ SHA-256(clientDataJSON).
    "  const assert = (o) => {",
    "    const cd = clientData('webauthn.get', o.challenge, o.origin);",
    "    const ad = authData(o.rpId, o.flags, o.count);",
    "    const sig = rsaSign(_akKeys[o.key], ad.concat(sha256(cd)));",
    "    if (o.tamper) { sig[sig.length - 1] = sig[sig.length - 1] ^ 1; }",
    "    return { id: b64(o.credId), clientDataJson: b64(cd), authenticatorData: b64(ad), signature: b64(sig) }; };",
    "  return { utf8: utf8, b64: b64, unb64: unb64, rand: rand, register: register, assert: assert };",
    "})();",
]


def _env(key):
    return f"pm.environment.get({js_str(key)})"


def _set(key, expr):
    return f"pm.environment.set({js_str(key)}, {expr});"


def _status_is(code, label):
    return [f"pm.test({js_str(label + f': ответ {code}')}, () => pm.expect(pm.response.code).to.eql({code}));"]


def _parse_body():
    return ["let __j = {}; try { __j = pm.response.json(); } catch (e) { __j = {}; }"]


# ── человек: регистрация, подтверждение адреса, вход, токен ─────────────────

def _src_pre(p):
    return [f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: {_env(p + 'Src')} || ''}});"]


def _with_cookies(*pairs):
    parts = " + ".join(
        f"({_env(v)} ? {js_str(name)} + '=' + {_env(v)} + '; ' : '')" for name, v in pairs)
    return [
        f"const __cookie = ({parts}).replace(/; $/, '');",
        "if (__cookie) { pm.request.headers.upsert({key: 'Cookie', value: __cookie}); }",
    ]


def _capture_cookie(p, cookie, var, label, required=True):
    lines = [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(cookie + '=')}));",
    ]
    if required:
        lines.append(f"  pm.test({js_str(label + ': ответ ставит печенье ' + cookie)}, () => pm.expect(__sc.length).to.eql(1));")
    lines += [
        f"  if (__sc.length === 1) {{ {_set(p + var, '__sc[0].value.split(\";\")[0].slice(' + str(len(cookie) + 1) + ')')} }}",
        "}",
    ]
    return lines


def _person_init(p, tag):
    return [
        "{",
        "  const __nonce = () => Math.floor(Math.random() * 2176782336).toString(36);",
        f"  const __domain = String({_env('loginLaneEmail')} || '').split('@')[1] || 'kaname.local';",
        "  " + _set(p + "Email", f"({js_str('ak-' + tag + '-')} + {_env('runId')} + '-' + __nonce() + '@' + __domain).toLowerCase()"),
        "  " + _set(p + "Password", "'Pw-' + __nonce() + __nonce() + '-first'"),
        "  " + _set(p + "Src", "'198.18.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254))"),
        "  " + _set(p + "MailSeen", "'0'"),
        *(f"  pm.environment.unset({js_str(p + n)});" for n in (
            "FormCookie", "SessionCookie", "Csrf", "Code", "UserId", "Token", "OauthCode")),
        "}",
    ]


def _csrf(p, name, form, *, init=None, with_session=False):
    path = f"{_CSRF}?form={form}"
    cookies = [("kaname_form", p + "FormCookie")]
    if with_session:
        cookies.append(("kaname_session", p + "SessionCookie"))
    label = name.upper()
    return Step(
        name=name, method="GET", path=path,
        pre_script=[*(init or []), *require_env_url(_LANE, path, _LANE_WHY), *_src_pre(p), *_with_cookies(*cookies)],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_status_is(200, label),
            *_parse_body(),
            f"pm.test({js_str(label + ': признак формы выдан строкой')}, () => "
            "pm.expect(typeof __j.csrfToken === 'string' && __j.csrfToken.length > 0).to.eql(true));",
            _set(p + "Csrf", "__j.csrfToken || ''"),
            *_capture_cookie(p, "kaname_form", "FormCookie", label, required=False),
        ],
    )


def _lane_post(p, name, path, body, *, with_session=False, test_script=(), extra_pre=()):
    cookies = [("kaname_form", p + "FormCookie")]
    if with_session:
        cookies.append(("kaname_session", p + "SessionCookie"))
    return Step(
        name=name, method="POST", path=path, body=body,
        pre_script=[*extra_pre, *require_env_url(_LANE, path, _LANE_WHY), *_src_pre(p), *_with_cookies(*cookies)],
        insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=list(test_script),
    )


def _await_letter(p, name):
    """Письмо подтверждения сверх уже прочитанных: петля с настоящей паузой."""
    path = f"/codes?to={{{{{p}Email}}}}&after={_urlparse.quote(_HEAD_VERIFY)}"
    counter, started = f"_akmb_{p}_{name}".replace("-", "_"), f"_akmbs_{p}_{name}".replace("-", "_")
    label = name.upper()
    return Step(
        name=name, method="GET", path=path, auth="anonymous", cookie_jar=False,
        pre_script=[
            *require_env_url(_MAILBOX, path, _MAILBOX_WHY),
            f"if ({_env(started)} !== pm.info.requestName) {{",
            "  " + _set(counter, "'0'"),
            "  " + _set(started, "pm.info.requestName"),
            "}",
        ],
        test_script=[
            f"const __n = parseInt({_env(counter)} || '0', 10);",
            f"const __seen = parseInt({_env(p + 'MailSeen')} || '0', 10);",
            "let __codes = null; try { __codes = pm.response.json().codes; } catch (e) { __codes = null; }",
            "const __all = Array.isArray(__codes) ? __codes : [];",
            f"if (pm.response.code === 200 && __all.length <= __seen && __n < {_MAIL_WAIT_CAP}) {{",
            "  " + _set(counter, "String(__n + 1)"),
            f"  const _akd = Date.now(); while (Date.now() - _akd < {_MAIL_WAIT_MS}) {{ /* inter-poll delay: letter not yet at the stand mailbox */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(counter)});",
            f"pm.environment.unset({js_str(started)});",
            *_status_is(200, label),
            f"pm.test({js_str(label + ': письмо подтверждения дошло до приёмника стенда в пределе ожидания')}, () => "
            "pm.expect(__all.length > __seen).to.eql(true));",
            "const __last = __all.length > __seen ? __all[__all.length - 1] : null;",
            "if (__all.length > __seen) {",
            "  " + _set(p + "Code", "typeof __last === 'string' ? __last : ''"),
            "  " + _set(p + "MailSeen", "String(__all.length)"),
            "}",
        ],
    )


_PKCE = [
    "const _akB64u = (wa) => { let s = CryptoJS.enc.Base64.stringify(wa).split('+').join('-')"
    ".split('/').join('_'); while (s.endsWith('=')) { s = s.slice(0, -1); } return s; };",
]


def _authorize(p, name):
    """Код церемонии: точка авторизации под сессией человека, PKCE S256."""
    label = name.upper()
    q = p + "Query"
    return Step(
        name=name, method="GET", path=_AUTHORIZE + "?{{" + q + "}}",
        pre_script=[
            f"if (!{_env('oauthClientId')} || !{_env('oauthClientSecret')} || !{_env('oauthRedirectUri')}) {{",
            *precondition_not_met(
                "посев стенда: oauthClientId, oauthClientSecret, oauthRedirectUri заданы",
                "посев церемонии стенда посадки own (`stand-chart.sh seed-ceremony`) не завёл "
                "конфиденциального клиента — выковать токен человека нечем. Шаг не может "
                "исполниться, и молча выпасть ему нельзя.", indent="  "),
            "}",
            *_PKCE,
            "const _akV = _akB64u(CryptoJS.lib.WordArray.random(32));",
            _set(p + "Verifier", "_akV"),
            "const _akS = _akB64u(CryptoJS.lib.WordArray.random(32));",
            _set(p + "State", "_akS"),
            "const _akQ = [['response_type', 'code'], ['client_id', " + _env("oauthClientId") + "],",
            "  ['redirect_uri', " + _env("oauthRedirectUri") + "], ['scope', 'openid'], ['state', _akS],",
            "  ['code_challenge', _akB64u(CryptoJS.SHA256(_akV))], ['code_challenge_method', 'S256']]",
            "  .map((kv) => encodeURIComponent(kv[0]) + '=' + encodeURIComponent(kv[1])).join('&');",
            _set(q, "_akQ"),
            f"pm.environment.unset({js_str(p + 'OauthCode')});",
            *require_env_url(_ISSUANCE, _AUTHORIZE + "?{{" + q + "}}", _ISSUANCE_WHY),
            f"if (!{_env(p + 'SessionCookie')}) {{",
            *report_then_skip(f"{label}: сессия человека не захвачена входом",
                              "вход выше не выдал kaname_session — точке авторизации нечего "
                              "предъявить; причина — в шаге входа, не здесь", indent="  "),
            "} else {",
            f"  pm.request.headers.upsert({{key: 'Cookie', value: 'kaname_session=' + {_env(p + 'SessionCookie')}}});",
            "}",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False, follow_redirects=False,
        test_script=[
            *_status_is(302, label),
            "const _akLoc = String(pm.response.headers.get('Location') || '');",
            "const _akQs = {}; (_akLoc.split('?')[1] || '').split('#')[0].split('&').forEach((kv) => { const i = kv.indexOf('=');",
            "  if (i > 0) { _akQs[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1)); } });",
            f"pm.test({js_str(label + ': перенаправление несёт код и state запроса')}, () => "
            f"pm.expect([typeof _akQs.code === 'string' && _akQs.code.length > 0, _akQs.state === {_env(p + 'State')}]).to.eql([true, true]));",
            f"if (_akQs.code) {{ {_set(p + 'OauthCode', '_akQs.code')} }}",
        ],
    )


def _exchange(p, name):
    label = name.upper()
    return Step(
        name=name, method="POST", path=_TOKEN,
        form=[("grant_type", "authorization_code"), ("code", "{{_akFCode}}"),
              ("redirect_uri", "{{_akFRedirect}}"), ("code_verifier", "{{_akFVerifier}}")],
        pre_script=[
            f"if (!{_env(p + 'OauthCode')}) {{",
            *report_then_skip(f"{label}: код не выдан точкой авторизации",
                              "шаг авторизации выше не выдал code — обменивать нечего; "
                              "причина — в нём, не здесь", indent="  "),
            "}",
            f"pm.variables.set('_akFCode', encodeURIComponent({_env(p + 'OauthCode')} || ''));",
            f"pm.variables.set('_akFRedirect', encodeURIComponent({_env('oauthRedirectUri')} || ''));",
            f"pm.variables.set('_akFVerifier', encodeURIComponent({_env(p + 'Verifier')} || ''));",
            *require_env_url(_ISSUANCE, _TOKEN, _ISSUANCE_WHY),
            "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' + "
            "CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
            f"  encodeURIComponent({_env('oauthClientId')} || '') + ':' + encodeURIComponent({_env('oauthClientSecret')} || '')))}});",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            f"pm.environment.unset({js_str(p + 'Token')});",
            *_status_is(200, label),
            *_parse_body(),
            f"pm.test({js_str(label + ': выдан токен доступа человека')}, () => "
            "pm.expect(typeof __j.access_token === 'string' && __j.access_token.length > 0).to.eql(true));",
            f"if (__j.access_token) {{ {_set(p + 'Token', '__j.access_token')} }}",
        ],
    )


def _login(p, tag):
    """Вход паролем → код → токен: окно свежести открывается этим предъявлением (Р5)."""
    return [
        _csrf(p, f"{tag}-login-csrf", "login"),
        _lane_post(p, f"{tag}-login", _LOGIN,
                   {"email": "{{" + p + "Email}}", "password": "{{" + p + "Password}}", "csrfToken": "{{" + p + "Csrf}}"},
                   test_script=[
                       *_status_is(200, f"{tag.upper()}-LOGIN"),
                       *_parse_body(),
                       f"pm.test({js_str(tag.upper() + '-LOGIN: тело называет человека, адрес подтверждён, уровень 1')}, () => "
                       "pm.expect([typeof (__j.user && __j.user.id), !!__j.session && __j.session.emailVerified, "
                       "__j.session && __j.session.assuranceLevel]).to.eql(['string', true, '1']));",
                       f"if (__j.user && __j.user.id) {{ {_set(p + 'UserId', '__j.user.id')} }}",
                       *_capture_cookie(p, "kaname_session", "SessionCookie", f"{tag.upper()}-LOGIN"),
                   ]),
        _authorize(p, f"{tag}-authorize"),
        _exchange(p, f"{tag}-exchange"),
    ]


def _human(p, tag):
    """Свой человек: регистрация → код письма → подтверждение → вход → токен."""
    up = tag.upper()
    return [
        _csrf(p, f"{tag}-register-csrf", "register", init=_person_init(p, tag)),
        _lane_post(p, f"{tag}-register", _REGISTER,
                   {"email": "{{" + p + "Email}}", "password": "{{" + p + "Password}}", "csrfToken": "{{" + p + "Csrf}}"},
                   test_script=[
                       *_status_is(200, f"{up}-REGISTER"),
                       *_capture_cookie(p, "kaname_session", "SessionCookie", f"{up}-REGISTER"),
                       *_capture_cookie(p, "kaname_form", "FormCookie", f"{up}-REGISTER", required=False),
                   ]),
        _await_letter(p, f"{tag}-letter"),
        _csrf(p, f"{tag}-verify-csrf", "verify-email-confirm", with_session=True),
        _lane_post(p, f"{tag}-verify", _VERIFY_CONFIRM,
                   {"code": "{{" + p + "Code}}", "csrfToken": "{{" + p + "Csrf}}"}, with_session=True,
                   test_script=[
                       *_status_is(200, f"{up}-VERIFY"),
                       *_parse_body(),
                       f"pm.test({js_str(up + '-VERIFY: адрес подтверждён')}, () => "
                       "pm.expect(!!__j.session && __j.session.emailVerified === true).to.eql(true));",
                       *_capture_cookie(p, "kaname_session", "SessionCookie", f"{up}-VERIFY"),
                   ]),
        *_login(p, tag),
    ]


# ── глаголы ключа на собственном фронте ─────────────────────────────────────

def _keys_path(p):
    return "/iam/v1/users/{{" + p + "UserId}}/accessKeys"


def _need(var, label, why):
    """Предмет шага не создан ПРЕДЫДУЩИМ шагом — находка о продукте или кейсе."""
    return [f"if (!{_env(var)}) {{", *report_then_skip(label, why, indent="  "), "}"]


def _own(p, name, method, path, *, pre=(), tests=(), body=None):
    return Step(name=name, method=method, path=path, body=body, auth=p + "Token",
                insecure_tls=True, pre_script=[*_need(p + "UserId", f"{name.upper()}: человек не назван входом",
                                                      "вход выше не вернул user.id — путь глагола не собрать"),
                                               *pre],
                test_script=list(tests))


def _raw_body(expr):
    return [f"pm.request.body = {{ mode: 'raw', raw: {expr}, options: {{ raw: {{ language: 'json' }} }} }};"]


def _list(p, name, *, count, extra=()):
    """Перечень ключей человека: число строк и, по выбору, утверждения сверх него."""
    label = name.upper()
    return _own(p, name, "GET", _keys_path(p), tests=[
        *_status_is(200, label),
        *_parse_body(),
        "const _akL = Array.isArray(__j.accessKeys) ? __j.accessKeys : [];",
        f"pm.test({js_str(label + f': ключей у человека {count}')}, () => pm.expect(_akL.length).to.eql({count}));",
        *extra,
    ])


def _key_listed(slot, label, *, last_used=None, row_tests=()):
    """Строка ключа `slot` в перечне `_akL` — своим блоком, строка в `_akRow`.

    `last_used`: None — не судится; 'moved' — сдвинулся и записан; 'record' —
    записан; 'kept' — равен записанному. `row_tests` исполняются в том же блоке."""
    key_id, stored = "ak" + slot + "KeyId", "ak" + slot + "LastUsed"
    out = [
        "{",
        f"const _akRow = _akL.filter((k) => k.id === {_env(key_id)})[0] || null;",
        f"pm.test({js_str(label + ': ключ ' + slot + ' в перечне назван своим id')}, () => pm.expect(!!_akRow).to.eql(true));",
    ]
    if last_used == "moved":
        out += [
            f"pm.test({js_str(label + ': момент последнего предъявления ключа ' + slot + ' сдвинулся')}, () => "
            f"pm.expect(!!_akRow && !!_akRow.lastUsedAt && _akRow.lastUsedAt !== ({_env(stored)} || null)).to.eql(true));",
            f"if (_akRow) {{ {_set(stored, '_akRow.lastUsedAt || \'\'')} }}",
        ]
    elif last_used == "record":
        out.append(f"if (_akRow) {{ {_set(stored, '_akRow.lastUsedAt || \'\'')} }}")
    elif last_used == "kept":
        out.append(
            f"pm.test({js_str(label + ': момент последнего предъявления ключа ' + slot + ' не сдвинулся')}, () => "
            f"pm.expect(!!_akRow && (_akRow.lastUsedAt || '') === ({_env(stored)} || '')).to.eql(true));")
    out += [*row_tests, "}"]
    return out


def _begin_registration(p, name, slot, *, tests=()):
    label = name.upper()
    return _own(p, name, "POST", _keys_path(p) + ":beginRegistration", body={}, tests=[
        f"pm.environment.unset({js_str('akRegCh' + slot)});",
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': испытание выдано непустым')}, () => "
        "pm.expect(typeof __j.challenge === 'string' && __j.challenge.length > 0).to.eql(true));",
        f"if (__j.challenge) {{ {_set('akRegCh' + slot, '__j.challenge')} }}",
        f"if (__j.expiresAt) {{ {_set('akRegExp' + slot, '__j.expiresAt')} }}",
        *tests,
    ])


def _begin_assertion(p, name, slot, *, tests=()):
    label = name.upper()
    return _own(p, name, "POST", "/iam/v1/accessKeys:beginAssertion", body={}, tests=[
        f"pm.environment.unset({js_str('akAsCh' + slot)});",
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': испытание выдано непустым')}, () => "
        "pm.expect(typeof __j.challenge === 'string' && __j.challenge.length > 0).to.eql(true));",
        f"if (__j.challenge) {{ {_set('akAsCh' + slot, '__j.challenge')} }}",
        f"if (__j.expiresAt) {{ {_set('akAsExp' + slot, '__j.expiresAt')} }}",
        *tests,
    ])


def _challenge_js(var):
    """Байты испытания: выданное службой (переменная) либо случайное (None)."""
    if var is None:
        return "_ak.rand(32)"
    return f"_ak.unb64({_env(var)} || '')"


def _cred_js(slot, fresh):
    """Идентификатор удостоверения строки `slot`; `fresh` — случайный, записываемый здесь."""
    if fresh:
        return [
            "const _akCred = _ak.rand(16);",
            _set("ak" + slot + "CredId", "_ak.b64(_akCred)"),
        ]
    return [f"const _akCred = _ak.unb64({_env('ak' + slot + 'CredId')} || '');"]


def _finish_registration(p, name, *, slot, ch, key=_MAT_MAIN, fresh_cred=True, flags=_UP | _UV | _AT,
                         alg=-257, origin=None, rp_id=None, discoverable=True, key_name="",
                         description="", origin_header=None, keep_as=None, replay=None, tests=()):
    """Результат церемонии регистрации собран подставным аутентификатором.

    `ch` — переменная выданного испытания либо None (испытание, которого служба не
    выдавала). `replay` — переменная с телом прежнего запроса: шлётся дословно.
    `keep_as` — переменная, куда тело запроса записывается для повтора."""
    pre = []
    if replay is not None:
        pre += [*_need(replay, f"{name.upper()}: прежний результат не записан",
                       "шаг заведения выше не записал тело — повторять нечего"),
                *_raw_body(f"{_env(replay)} || '{{}}'")]
    else:
        if ch is not None:
            pre += _need(ch, f"{name.upper()}: испытание не выдано",
                         "шаг выдачи испытания выше не вернул challenge — собирать результат не на чем")
        pre += [
            *_LIB,
            *_cred_js(slot, fresh_cred),
            f"const _akR = _ak.register({{ challenge: {_challenge_js(ch)}, rpId: {js_str(rp_id or _RP_ID)}, "
            f"origin: {js_str(origin or _ORIGIN)}, flags: {int(flags)}, credId: _akCred, key: {int(key)}, alg: {int(alg)} }});",
            "const _akC = { id: _akR.id, clientDataJson: _akR.clientDataJson, attestationObject: _akR.attestationObject };",
            *([] if discoverable is None else [f"_akC.discoverable = {'true' if discoverable else 'false'};"]),
            f"const _akBody = JSON.stringify({{ name: {js_str(key_name)}, description: {js_str(description)}, credential: _akC }});",
            *_raw_body("_akBody"),
        ]
        if keep_as is not None:
            pre.append(_set(keep_as, "_akBody"))
    if origin_header is not None:
        pre.append(f"pm.request.headers.upsert({{key: 'Origin', value: {js_str(origin_header)}}});")
    return _own(p, name, "POST", _keys_path(p), body={}, pre=pre, tests=list(tests))


def _registration_accepted(slot, label):
    """Синхронная часть: результат принят к исполнению операцией."""
    op = "ak" + slot + "Op"
    return [
        f"pm.environment.unset({js_str(op)});",
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': ответ — операция службы iam')}, () => "
        "pm.expect(typeof __j.id === 'string' && /^iop[a-z0-9]+$/.test(__j.id)).to.eql(true));",
        f"if (__j.id) {{ {_set(op, '__j.id')} }}",
    ]


def _refused(status, grpc, label, *, reason=None, text=None, contains=None):
    """Синхронный отказ фронта: статус, код, признак ErrorInfo, текст."""
    out = [
        *_status_is(status, label),
        *_parse_body(),
        f"pm.test({js_str(label + f': код отказа {grpc}')}, () => pm.expect(__j.code).to.eql({grpc}));",
    ]
    if text is not None:
        out.append(f"pm.test({js_str(label + ': текст отказа')}, () => pm.expect(__j.message).to.eql({js_str(text)}));")
    if contains is not None:
        out.append(f"pm.test({js_str(label + ': текст отказа называет правило')}, () => "
                   f"pm.expect(String(__j.message || '').indexOf({js_str(contains)}) >= 0).to.eql(true));")
    if reason is not None:
        out += [
            "const __info = (Array.isArray(__j.details) ? __j.details : [])"
            ".filter((d) => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            f"pm.test({js_str(label + ': признак отказа ' + reason + ' в домене службы')}, () => "
            f"pm.expect([__info.reason, __info.domain]).to.eql([{js_str(reason)}, {js_str(_REFUSAL_DOMAIN)}]));",
        ]
    return out


def _violation(label, field, rule):
    """Отказ формы называет поле и правило (`google.rpc.BadRequest`)."""
    return [
        *_refused(400, 3, label),
        f"pm.test({js_str(label + ': отказ называет поле ' + field + ' и правило')}, () => {{",
        "  const __br = (Array.isArray(__j.details) ? __j.details : []).filter((d) => String(d['@type'] || '').indexOf('BadRequest') >= 0)[0] || {};",
        f"  const __fv = (__br.fieldViolations || []).filter((v) => v.field === {js_str(field)})[0] || {{}};",
        f"  pm.expect(String(__fv.description || '').indexOf({js_str(rule)}) >= 0).to.eql(true); }});",
    ]


def _ceremony_refused(pair, label):
    reason, text = pair
    return _refused(400, 3 if reason not in ("CHALLENGE_NOT_ISSUED", "CHALLENGE_ALREADY_PRESENTED", "CHALLENGE_EXPIRED") else 9,
                    label, reason=reason, text=text)


def _await_op(p, name, slot, *, ok=True, error_into=None, error_code=None, tests=()):
    """Исход операции заведения либо снятия: опрос до `done` с настоящей паузой."""
    op = "ak" + slot + "Op"
    counter, started = f"_akop_{slot}_{name}".replace("-", "_"), f"_akops_{slot}_{name}".replace("-", "_")
    label = name.upper()
    body = [
        f"const __n = parseInt({_env(counter)} || '0', 10);",
        *_parse_body(),
        f"if (pm.response.code === 200 && !__j.done && __n < {POLL_CAP}) {{",
        "  " + _set(counter, "String(__n + 1)"),
        "  const _akpd = Date.now(); while (Date.now() - _akpd < 500) { /* inter-poll delay: operation not done yet */ }",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        f"pm.environment.unset({js_str(counter)});",
        f"pm.environment.unset({js_str(started)});",
        *_status_is(200, label),
        f"pm.test({js_str(label + ': операция завершена')}, () => pm.expect(__j.done).to.eql(true));",
    ]
    if ok:
        body += [
            f"pm.test({js_str(label + ': операция без ошибки и с ответом')}, () => "
            "pm.expect([!!__j.error, !!__j.response]).to.eql([false, true]));",
        ]
    else:
        body += [
            f"pm.test({js_str(label + ': операция завершилась отказом')}, () => "
            "pm.expect(!!__j.error && typeof __j.error.code === 'number' && __j.error.code !== 0).to.eql(true));",
        ]
        if error_code is not None:
            body.append(f"pm.test({js_str(label + f': код отказа операции {error_code}')}, () => "
                        f"pm.expect(__j.error && __j.error.code).to.eql({error_code}));")
        if error_into is not None:
            body.append(f"if (__j.error) {{ {_set(error_into, 'JSON.stringify(__j.error)')} }}")
    body += list(tests)
    return Step(
        name=name, method="GET", path="/operations/{{" + op + "}}", auth=p + "Token", insecure_tls=True,
        pre_script=[
            *_need(op, f"{label}: операция не возвращена шагом выше",
                   "мутация выше отвергнута синхронно либо не вернула id операции — опрашивать нечего; "
                   "причина — в ней, не здесь"),
            f"if ({_env(started)} !== pm.info.requestName) {{",
            "  " + _set(counter, "'0'"),
            "  " + _set(started, "pm.info.requestName"),
            "}",
        ],
        test_script=body,
    )


def _key_registered(slot, label, key=_MAT_MAIN):
    """Ответ операции заведения: ключ назван `ak-…`; id записан для перечня и снятия."""
    return [
        "const _akK = (__j.response && __j.response.accessKey) || {};",
        f"pm.test({js_str(label + ': ключ назван платформенным id формы ak-<17>')}, () => "
        "pm.expect(/^ak-[0-9a-hjkmnp-tv-z]{17}$/.test(String(_akK.id || ''))).to.eql(true));",
        f"if (_akK.id) {{ {_set('ak' + slot + 'KeyId', '_akK.id')} }}",
        _set("ak" + slot + "Count", "'0'"),
        _set("ak" + slot + "LastUsed", "''"),
        _set("ak" + slot + "Mat", f"'{int(key)}'"),
    ]


def _register_ok(p, tag, slot, *, key=_MAT_MAIN, flags=_UP | _UV | _AT, discoverable=True, key_name="",
                 description="", keep_as=None, tests=()):
    """Испытание → результат → операция без ошибки: ключ `slot` заведён."""
    up = tag.upper()
    return [
        _begin_registration(p, f"{tag}-begin", slot),
        _finish_registration(p, f"{tag}-finish", slot=slot, ch="akRegCh" + slot, key=key, flags=flags,
                             discoverable=discoverable, key_name=key_name, description=description,
                             keep_as=keep_as, tests=_registration_accepted(slot, f"{up}-FINISH")),
        _await_op(p, f"{tag}-op", slot, tests=[*_key_registered(slot, f"{up}-OP", key), *tests]),
    ]


def _finish_assertion(p, name, *, slot, ch, key=None, cred_slot=None, unknown_cred=False, flags=_UP | _UV, count="next",
                      origin=None, rp_id=None, tamper=False, origin_header=None, keep_as=None, replay=None,
                      tests=()):
    """Утверждение ключа `slot` подставным аутентификатором.

    `ch` — переменная выданного испытания предъявления либо None (невыданное);
    `key` — материал подписи (по умолчанию — материал строки); `cred_slot` —
    чей идентификатор удостоверения назван (по умолчанию — строки `slot`);
    `count` — 'next' (записанный + 1), 'same' (записанный) либо число."""
    pre = []
    if replay is not None:
        pre += [*_need(replay, f"{name.upper()}: прежнее утверждение не записано",
                       "шаг утверждения выше не записал тело — повторять нечего"),
                *_raw_body(f"{_env(replay)} || '{{}}'")]
    else:
        if ch is not None:
            pre += _need(ch, f"{name.upper()}: испытание предъявления не выдано",
                         "шаг выдачи испытания выше не вернул challenge — собирать утверждение не на чем")
        cred = cred_slot or slot
        if not unknown_cred:
            pre += _need("ak" + cred + "CredId", f"{name.upper()}: удостоверение строки {cred} не заведено",
                         "кейс выше не завёл ключ — предъявлять нечего")
        key_expr = str(int(key)) if key is not None else f"parseInt({_env('ak' + slot + 'Mat')} || '0', 10)"
        if count == "next":
            count_expr = f"parseInt({_env('ak' + slot + 'Count')} || '0', 10) + 1"
        elif count == "same":
            count_expr = f"parseInt({_env('ak' + slot + 'Count')} || '0', 10)"
        else:
            count_expr = str(int(count))
        pre += [
            *_LIB,
            *(["const _akCred = _ak.rand(16);"] if unknown_cred else _cred_js(cred, False)),
            f"const _akN = {count_expr};",
            _set("_akSentCount", "String(_akN)"),
            f"const _akA = _ak.assert({{ challenge: {_challenge_js(ch)}, rpId: {js_str(rp_id or _RP_ID)}, "
            f"origin: {js_str(origin or _ORIGIN)}, flags: {int(flags)}, count: _akN, credId: _akCred, "
            f"key: {key_expr}, tamper: {'true' if tamper else 'false'} }});",
            "const _akBody = JSON.stringify({ credential: _akA });",
            *_raw_body("_akBody"),
        ]
        if keep_as is not None:
            pre.append(_set(keep_as, "_akBody"))
    if origin_header is not None:
        pre.append(f"pm.request.headers.upsert({{key: 'Origin', value: {js_str(origin_header)}}});")
    return _own(p, name, "POST", "/iam/v1/accessKeys:finishAssertion", body={}, pre=pre, tests=list(tests))


def _assertion_passed(p, slot, label, *, uv, be=False):
    """Утверждение прошло: ответ называет вызывающего, ключ и флаги ЭТОГО утверждения."""
    return [
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': ответ называет вызывающего и ключ')}, () => "
        f"pm.expect([__j.userId === {_env(p + 'UserId')}, __j.accessKeyId === {_env('ak' + slot + 'KeyId')}]).to.eql([true, true]));",
        f"pm.test({js_str(label + ': флаги утверждения доезжают различимо')}, () => "
        "pm.expect(__j.flags && [__j.flags.userPresent, __j.flags.userVerified, __j.flags.backupEligible])"
        f".to.eql([true, {'true' if uv else 'false'}, {'true' if be else 'false'}]));",
        f"if (pm.response.code === 200) {{ {_set('ak' + slot + 'Count', _env('_akSentCount'))} }}",
    ]


def _single_refusal(label, *, record=False):
    """Единый отказ аутентификации (§3.0): 400, код 3, текст; тело — побайтово равно первому."""
    out = [
        *_status_is(400, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': единый отказ — код 3 и текст')}, () => "
        f"pm.expect([__j.code, __j.message]).to.eql([3, {js_str(_ASSERTION_REFUSED)}]));",
    ]
    if record:
        out.append(f"if (pm.response.code === 400) {{ {_set('akRefusalBody', 'pm.response.text()')} }}")
    else:
        out.append(f"pm.test({js_str(label + ': тело побайтово равно телу единого отказа Ф7-07')}, () => "
                   f"pm.expect(!!{_env('akRefusalBody')} && pm.response.text() === {_env('akRefusalBody')}).to.eql(true));")
    return out


def _challenge_named(label):
    """Шесть величин контракта в испытании регистрации (Ф7-40) и перепись пары."""
    algs = _json.dumps(_ALGORITHMS)
    return [
        "const _akSix = [",
        f"  ['rp.id', !!__j.rp && __j.rp.id === {js_str(_RP_ID)}],",
        f"  ['pubKeyCredParams', Array.isArray(__j.pubKeyCredParams) && JSON.stringify(__j.pubKeyCredParams.map((x) => x.alg)) === {js_str(algs)}"
        " && __j.pubKeyCredParams.every((x) => x.type === 'public-key')],",
        "  ['rp.name', !!__j.rp && typeof __j.rp.name === 'string' && __j.rp.name.length > 0],",
        f"  ['authenticatorSelection.userVerification', !!__j.authenticatorSelection && __j.authenticatorSelection.userVerification === {js_str(_UV_PREFERRED)}],",
        f"  ['authenticatorSelection.residentKey', !!__j.authenticatorSelection && __j.authenticatorSelection.residentKey === {js_str(_RESIDENT_REQUIRED)}],",
        f"  ['attestation', __j.attestation === {js_str(_ATTESTATION_NONE)}],",
        "];",
        f"pm.test({js_str(label + ': величин контракта, попадающих в испытание регистрации 6 · названных и равных объявленным 6')}, () => "
        "pm.expect(_akSix.filter((x) => !x[1]).map((x) => x[0])).to.eql([]));",
        f"pm.test({js_str(label + ': запрос свойств удостоверения — отдельно от шести')}, () => "
        "pm.expect(!!__j.extensions && __j.extensions.credProps === true).to.eql(true));",
        f"pm.test({js_str(label + ': человек глазами аутентификатора — платформенный id байтами')}, () => "
        f"pm.expect(!!__j.user && __j.user.id === CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse({_env('akAUserId')} || ''))).to.eql(true));",
        f"pm.test({js_str(label + ': срок испытания в будущем и короче окна свежести')}, () => {{",
        "  const __exp = Date.parse(__j.expiresAt || ''); const __now = Date.now();",
        f"  pm.expect([__exp > __now, __exp - __now < {_FRESHNESS_WINDOW_S * 1000}]).to.eql([true, true]); }});",
    ]


# ───────────────────────────────────────────────────────────────────────────
# Ф7-40: человек A заводится здесь; испытание регистрации называет контракт.
# ───────────────────────────────────────────────────────────────────────────
_A, _B = "akA", "akB"
CASES.append(Case(
    id="IAM-ACCESSKEY-OK-REGISTRATION-CHALLENGE-NAMES-THE-CONTRACT",
    title="Ф7-40: испытание регистрации называет шесть величин контракта, равных объявленным, и запрос свойств удостоверения",
    classes=["CONF"],
    priority="P0",
    steps=[
        *_human(_A, "ak-a"),
        _list(_A, "ak40-list-empty", count=0),
        _begin_registration(_A, "ak40-begin", "40", tests=_challenge_named("AK40-BEGIN")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-01 → Ф7-06: заведение, перечень, предъявление тем же ключом.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-ACCESSKEY-OK-REGISTER-LIST-ASSERT",
    title="Ф7-01, Ф7-06, Ф7-42, Ф7-28: ключ заведён церемонией, виден в перечне, его утверждение называет вызывающего",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_register_ok(_A, "ak01", "K1", description="first key of the run", keep_as="akK1RegCredential"),
        _list(_A, "ak01-list", count=1, extra=_key_listed("K1", "AK01-LIST", row_tests=[
            "pm.test('AK01-LIST: пустое имя замещено id, описание, момент заведения и человек названы', () => "
            "pm.expect(!!_akRow && [_akRow.name === _akRow.id, _akRow.description, "
            "!Number.isNaN(Date.parse(_akRow.createdAt || '')), _akRow.userId === "
            + _env(_A + "UserId") + "]).to.eql([true, 'first key of the run', true, true]));",
            "pm.test('AK01-LIST: ключ ещё не предъявлялся', () => pm.expect(!!_akRow && !_akRow.lastUsedAt).to.eql(true));",
        ])),
        _begin_assertion(_A, "ak42-begin", "1", tests=[
            f"pm.test('AK42-BEGIN: требование проверки пользователя — preferred, имя доверяющей стороны — объявленное', () => "
            f"pm.expect([__j.userVerification, __j.rpId]).to.eql([{js_str(_UV_PREFERRED)}, {js_str(_RP_ID)}]));",
            "pm.test('AK42-BEGIN: перечень удостоверений — свой ключ вызывающего', () => "
            f"pm.expect((__j.allowCredentials || []).map((c) => [c.type, c.id])).to.eql([['public-key', {_env('akK1CredId')}]]));",
        ]),
        _finish_assertion(_A, "ak06-assert", slot="K1", ch="akAsCh1", flags=_UP | _UV,
                          tests=_assertion_passed(_A, "K1", "AK06-ASSERT", uv=True)),
        _list(_A, "ak06-list", count=1, extra=_key_listed("K1", "AK06-LIST", last_used="moved")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-02, Ф7-03: ось испытания на полосе церемонии.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-ACCESSKEY-NEG-REGISTRATION-CHALLENGE-AXIS",
    title="Ф7-02, Ф7-03: результат над невыданным испытанием и повтор принятого — отказ, ключ не заведён",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _finish_registration(_A, "ak02-not-issued", slot="X02", ch=None,
                             tests=_ceremony_refused(_CHALLENGE_NOT_ISSUED, "AK02-NOT-ISSUED")),
        _finish_registration(_A, "ak03-replay", slot="K1", ch=None, replay="akK1RegCredential",
                             tests=_ceremony_refused(_CHALLENGE_PRESENTED, "AK03-REPLAY")),
        _list(_A, "ak03-list", count=1, extra=_key_listed("K1", "AK03-LIST")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Оси результата церемонии на ОДНОМ испытании: синхронный отказ испытания не
# гасит, и положительный контроль в конце идёт над ним же.
# ───────────────────────────────────────────────────────────────────────────
_LONG_DESC = "d" * 257
_EDGE_DESC = "d" * 256
CASES.append(Case(
    id="IAM-ACCESSKEY-NEG-CEREMONY-RESULT-AXES",
    title="Ф7-35, Ф7-41, Ф7-44, Ф7-45, Ф7-46, Ф7-48: каждая ось результата отвергает один факт, контроль на том же испытании принят",
    classes=["NEG", "BVA", "SEC"],
    priority="P0",
    steps=[
        _begin_registration(_A, "akx-begin", "X"),
        _finish_registration(_A, "ak35-algorithm-outside", slot="X35", ch="akRegChX", alg=_ALG_OUTSIDE,
                             tests=_ceremony_refused(_ALG_REFUSED, "AK35-ALGORITHM-OUTSIDE")),
        _finish_registration(_A, "ak41-not-discoverable", slot="X41", ch="akRegChX", discoverable=False,
                             tests=_ceremony_refused(_NOT_DISCOVERABLE, "AK41-NOT-DISCOVERABLE")),
        _finish_registration(_A, "ak44-origin-outside", slot="X44", ch="akRegChX", origin=_FOREIGN_ORIGIN,
                             origin_header=_FOREIGN_ORIGIN,
                             tests=_ceremony_refused(_ORIGIN_REFUSED, "AK44-ORIGIN-OUTSIDE")),
        _finish_registration(_A, "ak45-foreign-rp-hash", slot="X45", ch="akRegChX", rp_id=_FOREIGN_RP_ID,
                             tests=_ceremony_refused(_RP_REFUSED, "AK45-FOREIGN-RP-HASH")),
        _finish_registration(_A, "ak48-verified-not-present", slot="X48", ch="akRegChX", flags=_UV | _AT,
                             tests=_ceremony_refused(_UP_REFUSED, "AK48-VERIFIED-NOT-PRESENT")),
        *[_finish_registration(_A, f"ak46-name-{tag}", slot=f"X46{tag}", ch="akRegChX", key_name=bad,
                               tests=_violation(f"AK46-NAME-{tag.upper()}", "name", "must match"))
          for tag, bad in (("upper", "Laptop"), ("space", "my laptop"), ("cyrillic", "ноутбук"))],
        _finish_registration(_A, "ak46-description-257", slot="X46d", ch="akRegChX", description=_LONG_DESC,
                             tests=_violation("AK46-DESCRIPTION-257", "description", "256")),
        _list(_A, "akx-list-unchanged", count=1, extra=_key_listed("K1", "AKX-LIST-UNCHANGED")),
        # Положительный контроль: то же испытание; имя законной формы, описание на
        # границе, свойства удостоверения НЕ сообщены, присутствие без проверки.
        _finish_registration(_A, "akx-control", slot="K2", ch="akRegChX", key=_MAT_SECOND, flags=_UP | _AT,
                             discoverable=None, key_name="moy-noutbuk", description=_EDGE_DESC,
                             tests=_registration_accepted("K2", "AKX-CONTROL")),
        _await_op(_A, "akx-control-op", "K2", tests=_key_registered("K2", "AKX-CONTROL-OP", _MAT_SECOND)),
        _list(_A, "akx-list", count=2, extra=[
            *_key_listed("K1", "AKX-LIST"),
            *_key_listed("K2", "AKX-LIST", row_tests=[
                "pm.test('AKX-LIST: второй ключ назван именем и описанием на границе 256', () => "
                "pm.expect(!!_akRow && [_akRow.name, (_akRow.description || '').length]).to.eql(['moy-noutbuk', 256]));",
            ]),
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Единый отказ утверждения: четырнадцать полос снаружи неотличимы (§3.0).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-ACCESSKEY-NEG-ASSERTION-SINGLE-REFUSAL",
    title="Ф7-07…10, Ф7-11, Ф7-18, Ф7-49, Ф7-52, Ф7-53: единый отказ побайтово один; Ф7-17, Ф7-19, Ф7-29, Ф7-30 — проходы",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _begin_assertion(_A, "aks-begin", "S"),
        _finish_assertion(_A, "ak07-forged-signature", slot="K1", ch="akAsChS", tamper=True,
                          tests=_single_refusal("AK07-FORGED-SIGNATURE", record=True)),
        _finish_assertion(_A, "ak08-signed-by-second-key", slot="K1", ch="akAsChS", key=_MAT_SECOND,
                          tests=_single_refusal("AK08-SIGNED-BY-SECOND-KEY")),
        _finish_assertion(_A, "ak09-unknown-credential", slot="K1", ch="akAsChS", unknown_cred=True,
                          tests=_single_refusal("AK09-UNKNOWN-CREDENTIAL")),
        _finish_assertion(_A, "ak10-origin-outside", slot="K1", ch="akAsChS", origin=_FOREIGN_ORIGIN,
                          tests=_single_refusal("AK10-ORIGIN-OUTSIDE")),
        _finish_assertion(_A, "ak11-origin-header-agrees", slot="K1", ch="akAsChS", origin=_FOREIGN_ORIGIN,
                          origin_header=_FOREIGN_ORIGIN, tests=_single_refusal("AK11-ORIGIN-HEADER-AGREES")),
        _finish_assertion(_A, "ak-foreign-rp-hash", slot="K1", ch="akAsChS", rp_id=_FOREIGN_RP_ID,
                          tests=_single_refusal("AK-FOREIGN-RP-HASH")),
        _finish_assertion(_A, "ak49-not-present", slot="K1", ch="akAsChS", flags=_UV,
                          tests=_single_refusal("AK49-NOT-PRESENT")),
        _finish_assertion(_A, "ak18-counter-not-grown", slot="K1", ch="akAsChS", count="same",
                          tests=_single_refusal("AK18-COUNTER-NOT-GROWN")),
        _finish_assertion(_A, "ak52-challenge-not-issued", slot="K1", ch=None,
                          tests=_single_refusal("AK52-CHALLENGE-NOT-ISSUED")),
        _list(_A, "aks-list-kept", count=2, extra=[*_key_listed("K1", "AKS-LIST-KEPT", last_used="kept"),
                                                    *_key_listed("K2", "AKS-LIST-KEPT", last_used="kept")]),
        # Положительный контроль на ТОМ ЖЕ испытании (Ф7-17): счётчик вырос — проходит,
        # отказы выше испытания не погасили. Повтор того же утверждения — Ф7-53.
        _finish_assertion(_A, "ak17-control", slot="K1", ch="akAsChS", flags=_UP | _UV, keep_as="akS17Assertion",
                          tests=_assertion_passed(_A, "K1", "AK17-CONTROL", uv=True)),
        _finish_assertion(_A, "ak53-replay", slot="K1", ch=None, replay="akS17Assertion",
                          tests=_single_refusal("AK53-REPLAY")),
        # Ф7-19: ключ, сообщающий ноль при сохранённом нуле, проходит; без проверки
        # пользователя и с признаком резерва — флаги доезжают различимо (Ф7-29, Ф7-30).
        _begin_assertion(_A, "ak19-begin", "19"),
        _finish_assertion(_A, "ak19-zero-counter", slot="K2", ch="akAsCh19", flags=_UP | _BE, count=0,
                          tests=_assertion_passed(_A, "K2", "AK19-ZERO-COUNTER", uv=False, be=True)),
        _list(_A, "aks-list-moved", count=2, extra=[*_key_listed("K1", "AKS-LIST-MOVED", last_used="moved"),
                                                     *_key_listed("K2", "AKS-LIST-MOVED", last_used="moved")]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-05, Ф7-51, Ф7-55: человек B заводится здесь.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-ACCESSKEY-NEG-FOREIGN-KEY-AND-FOREIGN-CHALLENGE",
    title="Ф7-05, Ф7-51, Ф7-55: чужое удостоверение, чужой ключ и чужое испытание — отказ, свой близнец проходит",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_human(_B, "ak-b"),
        *_register_ok(_B, "akb", "KB", key=_MAT_SECOND),
        # Ф7-05: идентификатор удостоверения K1 уже принят; ветвь б — другой человек,
        # ветвь а — владелец. Отказы равны, ни у кого ключ не переназначен.
        _begin_registration(_B, "ak05b-begin", "05b"),
        _finish_registration(_B, "ak05b-finish", slot="K1", ch="akRegCh05b", fresh_cred=False,
                             tests=_registration_accepted("D05b", "AK05B-FINISH")),
        _await_op(_B, "ak05b-op", "D05b", ok=False, error_into="akDupErrB"),
        _begin_registration(_A, "ak05a-begin", "05a"),
        _finish_registration(_A, "ak05a-finish", slot="K1", ch="akRegCh05a", fresh_cred=False,
                             tests=_registration_accepted("D05a", "AK05A-FINISH")),
        _await_op(_A, "ak05a-op", "D05a", ok=False, error_into="akDupErrA", tests=[
            "pm.test('AK05A-OP: отказы владельцу и другому человеку побайтово равны', () => "
            f"pm.expect(!!{_env('akDupErrA')} && {_env('akDupErrA')} === {_env('akDupErrB')}).to.eql(true));",
        ]),
        _list(_A, "ak05-list-a", count=2, extra=_key_listed("K1", "AK05-LIST-A")),
        _list(_B, "ak05-list-b", count=1, extra=_key_listed("KB", "AK05-LIST-B")),
        # Ф7-51: из сессии A — утверждение ключа B, годное во всём остальном.
        _begin_assertion(_A, "ak51-begin", "51"),
        _finish_assertion(_A, "ak51-foreign-key", slot="KB", ch="akAsCh51",
                          tests=_single_refusal("AK51-FOREIGN-KEY")),
        _list(_B, "ak51-list-b-kept", count=1, extra=_key_listed("KB", "AK51-LIST-B-KEPT", last_used="kept")),
        _finish_assertion(_A, "ak51-own-control", slot="K1", ch="akAsCh51",
                          tests=_assertion_passed(_A, "K1", "AK51-OWN-CONTROL", uv=True)),
        # Ф7-55: испытание выдано B; A предъявляет над ним собственный ключ.
        _begin_assertion(_B, "ak55-begin-b", "55"),
        _finish_assertion(_A, "ak55-foreign-challenge", slot="K1", ch="akAsCh55",
                          tests=_single_refusal("AK55-FOREIGN-CHALLENGE")),
        _finish_assertion(_B, "ak55-owner-control", slot="KB", ch="akAsCh55",
                          tests=_assertion_passed(_B, "KB", "AK55-OWNER-CONTROL", uv=True)),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-37, Ф7-14: потолок ключей человека — величина профиля.
# ───────────────────────────────────────────────────────────────────────────
_FILL = [f"K{n}" for n in range(3, _CEILING + 1)]
CASES.append(Case(
    id="IAM-ACCESSKEY-BVA-CEILING",
    title=f"Ф7-37, Ф7-14: ключей ровно {_CEILING} — принят, ещё один — отказ со следующим шагом; снятие возвращает слот",
    classes=["BVA", "NEG"],
    priority="P1",
    steps=[
        *[s for slot in _FILL for s in _register_ok(_A, f"ak37-fill-{slot.lower()}", slot)],
        _list(_A, "ak37-list-full", count=_CEILING),
        _begin_assertion(_A, "ak14-begin", "14"),
        _finish_assertion(_A, "ak14-first-key-unchanged", slot="K1", ch="akAsCh14",
                          tests=_assertion_passed(_A, "K1", "AK14-FIRST-KEY-UNCHANGED", uv=True)),
        _begin_registration(_A, "ak37-over-begin", "37"),
        _finish_registration(_A, "ak37-over-finish", slot="K37", ch="akRegCh37",
                             tests=_registration_accepted("K37", "AK37-OVER-FINISH")),
        _await_op(_A, "ak37-over-op", "K37", ok=False, error_code=8, tests=[
            "pm.test('AK37-OVER-OP: отказ называет следующий шаг и действующую величину', () => {",
            "  const __m = String((__j.error && __j.error.message) || '');",
            f"  pm.expect([__m.indexOf({js_str(_CEILING_NEXT_STEP)}) >= 0, __m.indexOf({js_str(str(_CEILING))}) >= 0]).to.eql([true, true]); }});",
        ]),
        _list(_A, "ak37-list-still-full", count=_CEILING),
        # Потолок другого человека не расходуется: у B один ключ, второй заводится.
        *_register_ok(_B, "ak37-other-human", "KB2", key=_MAT_SECOND),
        # Снятие возвращает слот (Ф7-25 — свой кейс ниже); та же церемония проходит.
        _own(_A, f"ak37-revoke-{_FILL[-1].lower()}", "DELETE", _keys_path(_A) + "/{{ak" + _FILL[-1] + "KeyId}}",
             tests=_registration_accepted(_FILL[-1] + "R", f"AK37-REVOKE-{_FILL[-1]}")),
        _await_op(_A, f"ak37-revoke-{_FILL[-1].lower()}-op", _FILL[-1] + "R"),
        *_register_ok(_A, "ak37-slot-returned", "K37b"),
        _list(_A, "ak37-list-after", count=_CEILING),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-34, Ф7-54: срок испытания — из ответа службы; ожидание петлёй.
# ───────────────────────────────────────────────────────────────────────────
_CLOCK_TURN_MS = 5_000
# Срок испытания — литерал контракта, строго меньше окна свежести (15 мин): предел
# оборотов покрывает окно целиком, а ждёт шаг ровно до срока из ответа службы.
_CLOCK_CAP = _FRESHNESS_WINDOW_S * 1000 // _CLOCK_TURN_MS


def _clock_until(p, name, exp_var):
    turns, started = f"_akclk_{name}".replace("-", "_"), f"_akclks_{name}".replace("-", "_")
    label = name.upper()
    return _own(p, name, "GET", _keys_path(p), pre=[
        f"if ({_env(started)} !== pm.info.requestName) {{",
        "  " + _set(turns, "'0'"),
        "  " + _set(started, "pm.info.requestName"),
        "}",
    ], tests=[
        f"const _akTurn = parseInt({_env(turns)} || '0', 10);",
        f"const _akUntil = Date.parse({_env(exp_var)} || '') + 2000;",
        "const _akLeft = Number.isNaN(_akUntil) ? 0 : _akUntil - Date.now();",
        f"if (_akLeft > 0 && _akTurn < {_CLOCK_CAP}) {{",
        "  " + _set(turns, "String(_akTurn + 1)"),
        f"  const _akTick = Date.now(); while (Date.now() - _akTick < Math.min(_akLeft, {_CLOCK_TURN_MS})) {{ /* срок испытания, не готовность */ }}",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        f"pm.environment.unset({js_str(turns)}); pm.environment.unset({js_str(started)});",
        f"pm.test({js_str(label + ': срок испытания назван ответом службы')}, () => pm.expect(Number.isNaN(_akUntil)).to.eql(false));",
        f"pm.test({js_str(label + ': срок испытания выдержан по часам прогона')}, () => pm.expect(_akLeft <= 0).to.eql(true));",
        *_status_is(200, label),
    ])


CASES.append(Case(
    id="IAM-ACCESSKEY-BVA-CHALLENGE-EXPIRY",
    title="Ф7-34, Ф7-54: испытания регистрации и предъявления за сроком — отказ со следующим шагом и единый отказ",
    classes=["BVA", "NEG"],
    priority="P1",
    steps=[
        _list(_A, "ak34-list-before", count=_CEILING, extra=_key_listed("K1", "AK34-LIST-BEFORE", last_used="record")),
        _begin_registration(_A, "ak34-begin", "34"),
        _begin_assertion(_A, "ak54-begin", "54"),
        _clock_until(_A, "ak34-wait-expiry", "akRegExp34"),
        _clock_until(_A, "ak54-wait-expiry", "akAsExp54"),
        *_login(_A, "ak-a-relogin"),
        _finish_registration(_A, "ak34-expired", slot="X34", ch="akRegCh34",
                             tests=_ceremony_refused(_CHALLENGE_EXPIRED, "AK34-EXPIRED")),
        _finish_assertion(_A, "ak54-expired", slot="K1", ch="akAsCh54",
                          tests=_single_refusal("AK54-EXPIRED")),
        _list(_A, "ak34-list-unchanged", count=_CEILING, extra=_key_listed("K1", "AK34-LIST-UNCHANGED", last_used="kept")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф7-47, Ф7-27, Ф7-25: снятие; уборка — все ключи обоих людей.
# ───────────────────────────────────────────────────────────────────────────
_ABSENT_ID = "ak-0000000000000000z"
_FOREIGN_TYPE_ID = "usr-0000000000000000z"
_BAD_FORM_ID = "ключ-1"


def _revoke(p, name, slot, *, path_id=None, tests=()):
    path = _keys_path(p) + "/" + (path_id or ("{{ak" + slot + "KeyId}}"))
    return _own(p, name, "DELETE", path, tests=list(tests))


def _not_found_same_form(label, sent_id_expr, *, record=False):
    """Ф7-27: отказ «не найден», тело — с точностью до названного id — одно."""
    out = [
        *_status_is(404, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': код 5')}, () => pm.expect(__j.code).to.eql(5));",
        f"const _akShape = pm.response.text().split({sent_id_expr}).join('<id>');",
    ]
    if record:
        out.append(_set("akNotFoundShape", "_akShape"))
    else:
        out.append(f"pm.test({js_str(label + ': тело отказа то же, что у годной формы без строки')}, () => "
                   f"pm.expect(!!{_env('akNotFoundShape')} && _akShape === {_env('akNotFoundShape')}).to.eql(true));")
    return out


_CLEAN_A = ["K1", "K2", *_FILL[:-1], "K37b"]
_CLEAN_B = ["KB", "KB2"]
CASES.append(Case(
    id="IAM-ACCESSKEY-NEG-REVOKE-REFUSALS-AND-REVOKE",
    title="Ф7-47 (б), Ф7-27, Ф7-25: отказ формы, один отказ на чужой и отсутствующий ключ, снятый ключ перестаёт проходить",
    classes=["NEG", "SEC", "CRUD"],
    priority="P0",
    steps=[
        _revoke(_A, "ak47-bad-form", "-", path_id=_urlparse.quote(_BAD_FORM_ID),
                tests=_refused(400, 3, "AK47-BAD-FORM", text=f"invalid access key id '{_BAD_FORM_ID}'")),
        _revoke(_A, "ak27-absent", "-", path_id=_ABSENT_ID,
                tests=_not_found_same_form("AK27-ABSENT", js_str(_ABSENT_ID), record=True)),
        _revoke(_A, "ak27-foreign", "KB", tests=_not_found_same_form("AK27-FOREIGN", _env("akKBKeyId"))),
        _revoke(_A, "ak47-foreign-known-type", "-", path_id=_FOREIGN_TYPE_ID,
                tests=_not_found_same_form("AK47-FOREIGN-KNOWN-TYPE", js_str(_FOREIGN_TYPE_ID))),
        _list(_B, "ak27-list-b-kept", count=2, extra=_key_listed("KB", "AK27-LIST-B-KEPT")),
        _list(_A, "ak47-list-a-kept", count=_CEILING),
        # Ф7-25: снятие K2; утверждение K2 перестаёт проходить, K1 проходит.
        _revoke(_A, "ak25-revoke", "K2", tests=_registration_accepted("K2R", "AK25-REVOKE")),
        _await_op(_A, "ak25-revoke-op", "K2R", tests=[
            f"pm.test('AK25-REVOKE-OP: ответ называет снятый ключ', () => "
            f"pm.expect(__j.response && __j.response.accessKeyId).to.eql({_env('akK2KeyId')}));",
        ]),
        _begin_assertion(_A, "ak25-begin", "25"),
        _finish_assertion(_A, "ak25-revoked-key", slot="K2", ch="akAsCh25",
                          tests=_single_refusal("AK25-REVOKED-KEY")),
        _finish_assertion(_A, "ak25-other-key", slot="K1", ch="akAsCh25",
                          tests=_assertion_passed(_A, "K1", "AK25-OTHER-KEY", uv=True)),
        # Уборка: прочие ключи обоих людей — следующий прогон заводит своих.
        *[s for slot in _CLEAN_A if slot != "K2" for s in (
            _revoke(_A, f"ak-cleanup-{slot.lower()}", slot, tests=_registration_accepted(slot + "C", f"AK-CLEANUP-{slot}")),
            _await_op(_A, f"ak-cleanup-{slot.lower()}-op", slot + "C"))],
        *[s for slot in _CLEAN_B for s in (
            _revoke(_B, f"ak-cleanup-{slot.lower()}", slot, tests=_registration_accepted(slot + "C", f"AK-CLEANUP-{slot}")),
            _await_op(_B, f"ak-cleanup-{slot.lower()}-op", slot + "C"))],
        _list(_A, "ak-cleanup-list-a", count=0),
        _list(_B, "ak-cleanup-list-b", count=0),
    ],
))

CASES = address_own_front(CASES, _OWN_WHY)
