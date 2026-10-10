# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set ключей доступа: шесть глаголов `AccessKeyService` сквозь собственный фронт (Ф7, kaname#268).

ПРЕДМЕТ — приёмка `docs/engineering/acceptance/access-keys-are-ours.md` в
одобренной редакции 15 (отпечаток `5ea26ad0…`, запись
`docs/specs/reviews/access-keys-are-ours/5ea26ad012add99800a8c185e98b9e2f38910c1c54daec5bdd8a5c4f3ea3efbe.yaml`,
`APPROVED`) — сведение ветви снятия переноса (ред. 12, `3ab7b401…`, по ней набор
написан первым) и ветви решения Р12 (признак обнаружимости, три состояния).
Сценариев 51; каждый кейс несёт ID сценария этой редакции, снятые редакцией
(Ф7-21…24, Ф7-43, Ф7-50 — перенос) не несёт ни один. Кейсы написаны чёрным ящиком по её §3 и по контракту
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
(человек B заводится здесь) → потолок → независимость строк пароля и ключа
(пароль B сменяется здесь) → срок испытаний → снятие. Последний кейс
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
                                            удостоверения, срок меньше окна свежести;
                                            Ф13-33 (I): рукоятка `user.id` — 64 байта,
                                            не несёт ни `id`, ни адреса, повторная
                                            церемония того же человека даёт ту же
                                            (у человека B — своя, AK05B-BEGIN)
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
  IAM-ACCESSKEY-OK-PASSWORD-AND-KEY-ROWS-INDEPENDENT
                                          — Ф7-16: у B пароль и два ключа; смена
                                            пароля (глагол Ф2) — вход новым паролем,
                                            строки обоих ключей побайтово прежние,
                                            оба ключа проходят; третий ключ заведён —
                                            вход новым паролем проходит
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

ВХОД БЕЗ ПАРОЛЯ КЛЮЧОМ (Ф13, kaname#643, приёмка
`passwordless-login-with-access-key.md`) — блок кейсов `IAM-AKLOGIN-*` в конце
модуля: два глагола полосы формы (`access-key/begin`, `access-key/login`) на
слушателе формы тем же подставным аутентификатором. Единый отказ входа судится
побайтово против отказа неверному паролю. Трасса «позиция — кейс»:
  Ф13-20 — IAM-AKLOGIN-NEG-PERSON-WITHOUT-KEY-ROW;
  Ф13-01, Ф13-27 — IAM-AKLOGIN-OK-CHALLENGE-NAMES-NOBODY;
  Ф13-02 — IAM-AKLOGIN-NEG-BEGIN-FORM;
  Ф13-05 — IAM-AKLOGIN-OK-SIGN-IN-WITHOUT-PASSWORD;
  Ф13-07 — IAM-AKLOGIN-NEG-LOGIN-FORM;
  Ф13-03 — IAM-AKLOGIN-NEG-CHALLENGE-REPLACED;
  Ф13-08 — IAM-AKLOGIN-NEG-CHALLENGE-ONE-TIME;
  Ф13-26 — IAM-AKLOGIN-NEG-LOGIN-FORM-KIND;
  Ф13-04 — IAM-AKLOGIN-BVA-BEGIN-BY-SOURCE;
  Ф13-32 — IAM-AKLOGIN-BVA-KEY-LOGIN-RESETS-ADDRESS-COUNT;
  Ф13-18 — IAM-AKLOGIN-OK-TWO-LANES-INDEPENDENT;
  Ф13-13 — IAM-AKLOGIN-OK-LEVEL-COPIES-READ-THE-RECORD;
  Ф13-16, Ф13-17 — IAM-AKLOGIN-OK-SECOND-FACTOR-AND-KEY-SESSIONS;
  Ф13-19, Ф13-22, Ф13-23 — IAM-AKLOGIN-OK-PASSWORDLESS-PERSON;
  Ф13-25 — IAM-AKLOGIN-OK-RECOVERY-OF-PASSWORDLESS-PERSON.
Позиции, которые блок не утверждает, названы комментарием в его шапке.
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
#   · Ф7-31, Ф7-32, Ф7-39 — представление и снятие обещания на странице:
#     уровень I и гейты дерева;
#   · Ф7-26 и Ф7-56 — «Дано» есть человек без пароля, и приёмка строит его
#     ЗАПИСЬЮ строки (ред. 15): в проде такой личности не возникает — полосы
#     регистрации ключом не будет (`kacho#2703`), глагола снятия пароля в дереве
#     нет (Р12), вход ключом — Ф13 `kacho#1282`. Глаголом края этого «Дано» не
#     построить, и стенд его не строит; держатель — уровень I (запись строки);
#   · Ф7-57 и признак обнаружимости принятой строки в Ф7-41 (ред. 15, Р12) —
#     признак наружу фронта не выходит ни одним ответом (`AccessKey` его не
#     несёт), и единственный его читатель — страж последнего способа входа,
#     наблюдаемый только на человеке без пароля (Ф7-56). Сквозной кейс утверждал
#     бы здесь лишь то, что уже утверждает: результат с «обнаруживаемое» и без
#     расширения принят (кейс осей результата церемонии); держатель — уровень I;
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

# Происхождение и имя, которых установка НЕ объявляет: поддомен того же корня
# (аутентификатор собирает такой результат без отказа — §1.2 приёмки) и чужое имя.
# Выводятся из имени доверяющей стороны В МОМЕНТ ШАГА (`_FOREIGN_*_JS` ниже);
# здесь — только сверка с профилем. Для привязки стенда ту же сверку делает посев.
_FOREIGN_ORIGIN = "https://elsewhere." + _RP_ID
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


# ── привязка стенда (kaname#684) ─────────────────────────────────────────────
#
# Имя доверяющей стороны и происхождение консоли — величины УСТАНОВКИ, а не
# набора: стенд платформы объявляет свои (происхождение — из адреса консоли своего
# пространства), автономный стенд службы — профильные. Поэтому шаг читает их из
# окружения в момент исполнения: `accessKeysRpId` и `accessKeysOrigin` пишет посев
# личностей с ключом (`tests/authz-fixtures/seed_key_person.py`) из переменных
# стенда `KANAME_STAND_ACCESS_KEYS_RP_ID` / `_ORIGIN`, а без них — из профиля.
# Незаписанный ключ — величина профиля, вшитая при сборке: прогон без посева на
# автономном стенде собирает церемонии как прежде. Голого литерала профиля в шаге
# нет — держит `scripts/access_keys_stand_binding_test.py`.
_RP_ID_KEY, _ORIGIN_KEY = "accessKeysRpId", "accessKeysOrigin"
_RP_JS = f"({_env(_RP_ID_KEY)} || {js_str(_RP_ID)})"
_ORIGIN_JS = f"({_env(_ORIGIN_KEY)} || {js_str(_ORIGIN)})"
_FOREIGN_ORIGIN_JS = f"('https://elsewhere.' + {_RP_JS})"
_FOREIGN_RP_ID_JS = f"('elsewhere-' + {_RP_JS})"


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


def _await_letter(p, name, head=_HEAD_VERIFY, seen="MailSeen", code="Code", kind="подтверждения"):
    """Письмо вида `head` сверх уже прочитанных: петля с настоящей паузой.

    Счёт прочитанного (`seen`) и место кода (`code`) — свои у каждого вида письма:
    коды подтверждения и восстановления приёмник отдаёт разными перечнями."""
    path = f"/codes?to={{{{{p}Email}}}}&after={_urlparse.quote(head)}"
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
            f"const __seen = parseInt({_env(p + seen)} || '0', 10);",
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
            f"pm.test({js_str(label + ': письмо ' + kind + ' дошло до приёмника стенда в пределе ожидания')}, () => "
            "pm.expect(__all.length > __seen).to.eql(true));",
            "const __last = __all.length > __seen ? __all[__all.length - 1] : null;",
            "if (__all.length > __seen) {",
            "  " + _set(p + code, "typeof __last === 'string' ? __last : ''"),
            "  " + _set(p + seen, "String(__all.length)"),
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
    `keep_as` — переменная, куда тело запроса записывается для повтора.
    `origin`, `rp_id` и `origin_header` — выражения JS, вычисляемые в момент шага;
    по умолчанию — привязка стенда (`_ORIGIN_JS`, `_RP_JS`)."""
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
            f"const _akR = _ak.register({{ challenge: {_challenge_js(ch)}, rpId: {rp_id or _RP_JS}, "
            f"origin: {origin or _ORIGIN_JS}, flags: {int(flags)}, credId: _akCred, key: {int(key)}, alg: {int(alg)} }});",
            "const _akC = { id: _akR.id, clientDataJson: _akR.clientDataJson, attestationObject: _akR.attestationObject };",
            *([] if discoverable is None else [f"_akC.discoverable = {'true' if discoverable else 'false'};"]),
            f"const _akBody = JSON.stringify({{ name: {js_str(key_name)}, description: {js_str(description)}, credential: _akC }});",
            *_raw_body("_akBody"),
        ]
        if keep_as is not None:
            pre.append(_set(keep_as, "_akBody"))
    if origin_header is not None:
        pre.append(f"pm.request.headers.upsert({{key: 'Origin', value: {origin_header}}});")
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
    `count` — 'next' (записанный + 1), 'same' (записанный) либо число;
    `origin`, `rp_id` и `origin_header` — выражения JS, вычисляемые в момент шага;
    по умолчанию — привязка стенда (`_ORIGIN_JS`, `_RP_JS`)."""
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
            f"const _akA = _ak.assert({{ challenge: {_challenge_js(ch)}, rpId: {rp_id or _RP_JS}, "
            f"origin: {origin or _ORIGIN_JS}, flags: {int(flags)}, count: _akN, credId: _akCred, "
            f"key: {key_expr}, tamper: {'true' if tamper else 'false'} }});",
            "const _akBody = JSON.stringify({ credential: _akA });",
            *_raw_body("_akBody"),
        ]
        if keep_as is not None:
            pre.append(_set(keep_as, "_akBody"))
    if origin_header is not None:
        pre.append(f"pm.request.headers.upsert({{key: 'Origin', value: {origin_header}}});")
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


# Рукоятка церемонии — `user.id` испытания регистрации (приёмка
# `passwordless-login-with-access-key.md`, Р3, Ф13-33 (I)): 64 случайных байта
# человека, одни у всех его церемоний, не равные его `id` и не несущие ни `id`,
# ни адреса. Вхождение судится без учёта регистра — так же, как его судит
# замок производителя. Разбор — свой, без библиотеки песочницы: функция одна,
# и её же исполняет проба способности упасть `scripts/ceremony_handle_probe_test.py`.
_HANDLE_BYTES = 64
_HANDLE_FACTS_JS = (
    "const _akHandleFacts = (s, id, email) => {"
    " const AB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';"
    " const t = typeof s === 'string' ? s : '';"
    " const canonical = t.length > 0 && t.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(t);"
    " const b = []; let acc = 0; let bits = 0;"
    " for (const c of t.split('=').join('')) { const v = AB.indexOf(c); if (v < 0) { break; }"
    " acc = ((acc << 6) | v) & 0xffffff; bits += 6; if (bits >= 8) { bits -= 8; b.push((acc >> bits) & 255); } }"
    " const low = b.map((x) => (x >= 65 && x <= 90 ? x + 32 : x));"
    " const has = (v) => { const e = unescape(encodeURIComponent(String(v || '').toLowerCase()));"
    " const n = []; for (let i = 0; i < e.length; i++) { n.push(e.charCodeAt(i)); }"
    " if (n.length === 0) { return false; }"
    " for (let i = 0; i + n.length <= low.length; i++) { let k = 0; while (k < n.length && low[i + k] === n[k]) { k++; } if (k === n.length) { return true; } }"
    " return false; };"
    " return { canonical: canonical, bytes: b.length, zero: b.length > 0 && b.every((x) => x === 0),"
    " carriesId: has(id), carriesEmail: has(email) }; };"
)


def _handle_is_its_own(label, p):
    """Рукоятка человека `p` в испытании: 64 байта, не нули, без его `id` и адреса.

    `id` и адрес обязаны быть известны набору — иначе «не несёт» выполнялось бы
    на пустом образце; поэтому их наличие стоит в том же утверждении."""
    return [
        _HANDLE_FACTS_JS,
        f"const _akHf = _akHandleFacts(__j.user && __j.user.id, {_env(p + 'UserId')}, {_env(p + 'Email')});",
        f"pm.test({js_str(label + f': рукоятка человека — {_HANDLE_BYTES} байта в канонической записи, не нули')}, () => "
        f"pm.expect([_akHf.canonical, _akHf.bytes, _akHf.zero]).to.eql([true, {_HANDLE_BYTES}, false]));",
        f"pm.test({js_str(label + ': рукоятка не несёт ни id, ни адреса человека')}, () => "
        f"pm.expect([!!{_env(p + 'UserId')}, !!{_env(p + 'Email')}, _akHf.carriesId, _akHf.carriesEmail])"
        ".to.eql([true, true, false, false]));",
    ]


def _handle_same_as(label, p, stored):
    """Рукоятка этой церемонии равна сохранённой рукоятке `stored`."""
    return [
        f"pm.test({js_str(label + ': две церемонии одного человека — одна рукоятка')}, () => "
        f"pm.expect([!!{_env(stored)}, !!__j.user && __j.user.id === {_env(stored)}]).to.eql([true, true]));",
    ]


def _handle_differs_from(label, p, other):
    """Рукоятка человека `p` — своя: годной формы и не равна рукоятке `other`."""
    return [
        *_handle_is_its_own(label, p),
        f"pm.test({js_str(label + ': у двух разных людей рукоятки разные')}, () => "
        f"pm.expect([!!{_env(other)}, !!__j.user && typeof __j.user.id === 'string' && __j.user.id !== {_env(other)}])"
        ".to.eql([true, true]));",
    ]


def _challenge_named(label):
    """Шесть величин контракта в испытании регистрации (Ф7-40) и перепись пары.

    Идентификатор алгоритма COSE — `int64` контракта, и каноническая форма JSON
    отдаёт его СТРОКОЙ («-7»), а не числом; сравнивается значение, а не запись
    (замер на стенде chart-own: `{"type":"public-key","alg":"-7"}`)."""
    algs = _json.dumps(_ALGORITHMS, separators=(",", ":"))
    return [
        "const _akSix = [",
        f"  ['rp.id', !!__j.rp && __j.rp.id === {_RP_JS}],",
        f"  ['pubKeyCredParams', Array.isArray(__j.pubKeyCredParams) && JSON.stringify(__j.pubKeyCredParams.map((x) => Number(x.alg))) === {js_str(algs)}"
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
        *_handle_is_its_own(label, _A),
        f"pm.environment.unset({js_str(_A + 'Handle')});",
        f"if (_akHf.canonical && _akHf.bytes === {_HANDLE_BYTES}) {{ {_set(_A + 'Handle', '__j.user.id')} }}",
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
        _begin_registration(_A, "ak40-begin-again", "40r",
                            tests=_handle_same_as("AK40-BEGIN-AGAIN", _A, _A + "Handle")),
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
            f"pm.expect([__j.userVerification, __j.rpId]).to.eql([{js_str(_UV_PREFERRED)}, {_RP_JS}]));",
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
        _finish_registration(_A, "ak44-origin-outside", slot="X44", ch="akRegChX", origin=_FOREIGN_ORIGIN_JS,
                             origin_header=_FOREIGN_ORIGIN_JS,
                             tests=_ceremony_refused(_ORIGIN_REFUSED, "AK44-ORIGIN-OUTSIDE")),
        _finish_registration(_A, "ak45-foreign-rp-hash", slot="X45", ch="akRegChX", rp_id=_FOREIGN_RP_ID_JS,
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
        _finish_assertion(_A, "ak10-origin-outside", slot="K1", ch="akAsChS", origin=_FOREIGN_ORIGIN_JS,
                          tests=_single_refusal("AK10-ORIGIN-OUTSIDE")),
        _finish_assertion(_A, "ak11-origin-header-agrees", slot="K1", ch="akAsChS", origin=_FOREIGN_ORIGIN_JS,
                          origin_header=_FOREIGN_ORIGIN_JS, tests=_single_refusal("AK11-ORIGIN-HEADER-AGREES")),
        _finish_assertion(_A, "ak-foreign-rp-hash", slot="K1", ch="akAsChS", rp_id=_FOREIGN_RP_ID_JS,
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
        _begin_registration(_B, "ak05b-begin", "05b",
                            tests=_handle_differs_from("AK05B-BEGIN", _B, _A + "Handle")),
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
# Ф7-16: строки способа «пароль» и строки ключа независимы. «Дано» строится
# ДЕЙСТВИЯМИ (ред. 15): у B пароль и два принятых ключа (KB — кейс чужого ключа,
# KB2 — кейс потолка). Смена пароля — глагол Ф2 на слушателе формы; обе строки
# ключа после неё побайтово те же, и оба ключа проходят. Обратно: третий ключ
# заводится, и вход новым паролем после него проходит.
# ───────────────────────────────────────────────────────────────────────────
_PASSWORD_CHANGE = "/iam/v1/auth/password"
_ROWS_16 = ("JSON.stringify(_akL.filter((k) => [" + _env("akKBKeyId") + ", " + _env("akKB2KeyId") + "]"
            ".indexOf(k.id) >= 0).sort((x, y) => (x.id < y.id ? -1 : 1)))")
CASES.append(Case(
    id="IAM-ACCESSKEY-OK-PASSWORD-AND-KEY-ROWS-INDEPENDENT",
    title="Ф7-16: смена пароля не трогает строк ключа — оба ключа проходят; третий ключ не трогает пароля",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        _list(_B, "ak16-list-before", count=2, extra=[
            *_key_listed("KB", "AK16-LIST-BEFORE"),
            *_key_listed("KB2", "AK16-LIST-BEFORE"),
            _set("ak16Rows", _ROWS_16),
        ]),
        _csrf(_B, "ak16-password-csrf", "password", with_session=True),
        _lane_post(_B, "ak16-password-change", _PASSWORD_CHANGE,
                   {"currentPassword": "{{" + _B + "Password}}", "newPassword": "{{" + _B + "PasswordNext}}",
                    "csrfToken": "{{" + _B + "Csrf}}"}, with_session=True,
                   extra_pre=[_set(_B + "PasswordNext", f"String({_env(_B + 'Password')} || '').replace(/-first$/, '') + '-second'")],
                   test_script=[
                       *_status_is(200, "AK16-PASSWORD-CHANGE"),
                       *_capture_cookie(_B, "kaname_session", "SessionCookie", "AK16-PASSWORD-CHANGE"),
                       f"if (pm.response.code === 200) {{ {_set(_B + 'Password', _env(_B + 'PasswordNext'))} }}",
                   ]),
        # Вход НОВЫМ паролем — смена попала в строку пароля; токен — заново (смена
        # снимает прочие сессии человека).
        *_login(_B, "ak16-login-new-password"),
        _list(_B, "ak16-list-after-change", count=2, extra=[
            "pm.test('AK16-LIST-AFTER-CHANGE: строки обоих ключей побайтово те же, что до смены пароля', () => "
            f"pm.expect(!!{_env('ak16Rows')} && {_ROWS_16} === {_env('ak16Rows')}).to.eql(true));",
        ]),
        _begin_assertion(_B, "ak16-begin-kb", "16b"),
        _finish_assertion(_B, "ak16-kb-passes", slot="KB", ch="akAsCh16b",
                          tests=_assertion_passed(_B, "KB", "AK16-KB-PASSES", uv=True)),
        _begin_assertion(_B, "ak16-begin-kb2", "16c"),
        _finish_assertion(_B, "ak16-kb2-passes", slot="KB2", ch="akAsCh16c",
                          tests=_assertion_passed(_B, "KB2", "AK16-KB2-PASSES", uv=True)),
        # Обратно: третий ключ заводится, строка пароля не тронута — вход ею проходит.
        *_register_ok(_B, "ak16-third-key", "KB3", key=_MAT_SECOND),
        _list(_B, "ak16-list-three", count=3, extra=_key_listed("KB3", "AK16-LIST-THREE")),
        *_login(_B, "ak16-login-after-third-key"),
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
_CLEAN_B = ["KB", "KB2", "KB3"]
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
        _list(_B, "ak27-list-b-kept", count=3, extra=_key_listed("KB", "AK27-LIST-B-KEPT")),
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


# ═══════════════════════════════════════════════════════════════════════════
# Ф13 — ВХОД БЕЗ ПАРОЛЯ КЛЮЧОМ ДОСТУПА (kaname#643, приёмка
# `docs/engineering/acceptance/passwordless-login-with-access-key.md`).
#
# Два глагола полосы формы — `access-key/begin` и `access-key/login` на слушателе
# формы (`loginLaneBaseUrl`) — тем же подставным аутентификатором, что заводит
# ключи выше: материал `_KEYS`, подпись `_LIB`. Ключи людей заводятся глаголом
# собственного фронта под токеном нашей церемонии, как у кейсов Ф7. Люди свои на
# прогон: C (пароль и ключи), D и E (предел частоты по адресу), и «личность без
# пароля» f13 — её кладёт посев стенда (`seed_key_person.py`, приставка
# `f13Person`): строки пароля у неё нет by construction продукта, и «Дано» §5
# преамбулы строится только записью.
#
# Единый отказ входа (Р7) сверяется ПОБАЙТОВО с отказом входа паролем (Ф3-02):
# первый кейс записывает тело отказа неверному паролю, и каждая полоса ключа
# сравнивает своё тело с ним целиком. Свой источник у каждого кейса: счёт частоты
# по источнику (Р9) не обнуляется успехом, и кейсы делили бы его.
#
# Техники: классы эквивалентности формы и утверждения; граничные значения
# пределов частоты (N−1 · N · N+1); переходы состояния испытания (выдано ·
# замещено · сгорело) и сессии (выдана · перевыпущена · снята); таблица решений
# «вид признака × контекст»; положительный близнец у каждого отказа с одним
# изменённым фактом.
#
# ЧЕГО ЭТОТ БЛОК НЕ УТВЕРЖДАЕТ — позиции названы КОММЕНТАРИЕМ, не строкой
# (перепись долга считает позицию несомой по строковому литералу модуля); у
# каждой запись долга с доводом и держателем в `.github/scripts/newman-suite-debt.py`:
#   · Ф13-06 — ветвь «и» (владелец заблокирован распорядителем уровня «2») и
#     ветвь «л» (время, критерий Ф1-48); прочие ветви единого отказа несут кейсы
#     ниже (подпись, повтор, чужой контекст, неизвестное удостоверение);
#   · Ф13-09 — вторая половина: отсечка принудительного выхода на крае;
#   · Ф13-10, Ф13-11, Ф13-12, Ф13-15 — пол «2» судит край, ответ краю о сессии —
#     глагол внутреннего слушателя; копия уровня в ответе входа утверждается здесь
#     на каждом входе;
#   · Ф13-28 — ретрансляция краем, дом пробы — платформа.

import ast as _ast_f13

_AK_BEGIN = "/iam/v1/auth/access-key/begin"
_AK_LOGIN = "/iam/v1/auth/access-key/login"
_SF_STATUS = "/iam/v1/auth/second-factor"
_SF_ENROLL = "/iam/v1/auth/second-factor/enroll"
_SF_CONFIRM = "/iam/v1/auth/second-factor/confirm"
_SESSIONS = "/iam/v1/auth/sessions"
_STEP_UP = "/iam/v1/auth/step-up"
_LOGOUT = "/iam/v1/auth/logout"
_RECOVERY = "/iam/v1/auth/recovery"
# Ответ запроса кода — один на все исходы и называет шаг (Ф5 Р10 п. 1,
# kaname#211); тело в форме слушателя, без пробелов.
_RECOVERY_NEXT_STEP_BODY = ('{"nextStep":"a letter with a recovery code is sent if this address can recover access; '
                            'if no letter arrives, request again later, sign in and confirm the address, '
                            'or ask an administrator to reset your sign-in methods"}')
_RECOVERY_COMPLETE = "/iam/v1/auth/recovery/complete"
_HEAD_RECOVERY = "Код восстановления:"
_AUTH_FAILED_BODY = {"code": 16, "message": "authentication failed", "details": []}
_FORM_REJECTED = "form token rejected"
_TOO_MANY = "too many attempts; try again later"
_LAST_METHOD = ("LAST_SIGN_IN_METHOD",
                "last sign-in method cannot be revoked: enrol another sign-in method first")
# Срок испытания — литерал контракта Ф7 (`access_keys.ChallengeTTL`), его же
# называет полоса входа браузеру в миллисекундах (Ф13-01).
_CHALLENGE_TTL_MS = 5 * 60 * 1000


def _login_profile(key):
    found = _re.findall(rf"^    {key}: (\S+)\s*$", _profile_text(), _re.M)
    if len(found) != 1:
        raise SystemExit(f"kaname-access-keys: ключ профиля authn.login.{key} найден {len(found)} раз "
                         f"в {_PROFILE} — ждали ровно один")
    return found[0]


def _seconds(duration):
    m = _re.fullmatch(r"(\d+)([smh])", duration)
    if m is None:
        raise SystemExit(f"kaname-access-keys: срок {duration!r} не в форме <число><s|m|h>")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


_N_SOURCE = int(_login_profile("sourceAttempts"))
_T_SOURCE = _seconds(_login_profile("sourceWindow"))
_N_ADDRESS = int(_login_profile("addressAttempts"))
_T_ADDRESS = _seconds(_login_profile("addressWindow"))
_SESSION_TTL_S = _seconds(_login_profile("sessionTtl"))
# «Дано» Ф13-32: без N_адрес ≥ 2 обнуление неотличимо от его отсутствия (Н11), а
# при N_источник < 2·N_адрес граница по источнику перейдена раньше адресной.
if _N_ADDRESS < 2 or _N_SOURCE < 2 * _N_ADDRESS:
    raise SystemExit(f"kaname-access-keys: профиль addressAttempts={_N_ADDRESS}, sourceAttempts={_N_SOURCE} "
                     "— «Дано» обнуления счёта по адресу не строится (нужно N_адрес ≥ 2 и "
                     "N_источник ≥ 2·N_адрес)")


def _borrowed_totp():
    """Код по времени — функцией набора второго фактора, разбором модуля, а не копией.

    `_TOTP_JS` читается литералом; счёт принятой ступени переименован в свой,
    чтобы два набора не делили переменную окружения."""
    path = _pathlib.Path(__file__).resolve().parent / "kaname-second-factor.py"
    tree = _ast_f13.parse(path.read_text(encoding="utf-8"))
    nodes = {t.id: n.value for n in tree.body if isinstance(n, _ast_f13.Assign)
             for t in n.targets if isinstance(t, _ast_f13.Name)}
    if "_TOTP_JS" not in nodes:
        raise SystemExit("kaname-access-keys: в kaname-second-factor.py нет _TOTP_JS — кода по времени нет")
    lines = _ast_f13.literal_eval(nodes["_TOTP_JS"])
    if not (isinstance(lines, list) and all(isinstance(x, str) for x in lines)
            and sum("sfLastStep" in x for x in lines) == 1):
        raise SystemExit("kaname-access-keys: _TOTP_JS сменил форму (ждали список строк с одним "
                         "чтением sfLastStep) — сверить разбор")
    return [x.replace("sfLastStep", "akCLastStep") for x in lines]


_TOTP = _borrowed_totp()
_AKU = "const _akU = (s) => String(s || '').split('+').join('-').split('/').join('_').split('=').join('');"
_C, _D, _E, _F = "akC", "akD", "akE", "f13"
# Второй «браузер» человека C: свой контекст формы и свой источник, человек тот же.
_CB = "akCb"
_RATE = "akR"


def _fresh_src(p):
    return [_set(p + "Src", "'198.19.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254))")]


def _lane(p, name, method, path, *, body=None, form_var=None, session=None, pre=(), tests=()):
    """Шаг слушателя формы: печенье контекста `p` (либо `form_var`), сессия — по выбору."""
    cookies = [("kaname_form", form_var or (p + "FormCookie"))]
    if session:
        cookies.append(("kaname_session", session))
    return Step(name=name, method=method, path=path, body=body,
                pre_script=[*pre, *require_env_url(_LANE, path, _LANE_WHY), *_src_pre(p), *_with_cookies(*cookies)],
                insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=list(tests))


def _no_cookies(label):
    return [f"pm.test({js_str(label + ': ответ не ставит ни одного печенья')}, () => "
            "pm.expect(pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie').length)"
            ".to.eql(0));"]


def _tok(p, name, form, var, *, fresh=False, session=None, init=()):
    """Признак формы вида `form` в `var`; `fresh` — без печенья: контекст выдаётся заново."""
    path = f"{_CSRF}?form={form}"
    cookies = [] if fresh else [("kaname_form", p + "FormCookie")]
    if session:
        cookies.append(("kaname_session", session))
    label = name.upper()
    return Step(name=name, method="GET", path=path,
                pre_script=[*init, *require_env_url(_LANE, path, _LANE_WHY), *_src_pre(p),
                            *(_with_cookies(*cookies) if cookies else [])],
                insecure_tls=True, auth="anonymous", cookie_jar=False,
                test_script=[
                    *_status_is(200, label),
                    *_parse_body(),
                    f"pm.test({js_str(label + ': признак формы выдан строкой')}, () => "
                    "pm.expect(typeof __j.csrfToken === 'string' && __j.csrfToken.length > 0).to.eql(true));",
                    _set(var, "__j.csrfToken || ''"),
                    *_capture_cookie(p, "kaname_form", "FormCookie", label, required=fresh),
                ])


def _begin(p, name, ch, tok, *, body=None, tests=None, form_var=None, extra_tests=()):
    """Выдача испытания входа ключом; по умолчанию — `200` и испытание в `ch`."""
    label = name.upper()
    if tests is None:
        tests = [
            *_status_is(200, label),
            *_parse_body(),
            f"pm.test({js_str(label + ': испытание выдано непустым')}, () => "
            "pm.expect(typeof (__j.publicKey && __j.publicKey.challenge) === 'string' "
            "&& __j.publicKey.challenge.length > 0).to.eql(true));",
            f"if (__j.publicKey && __j.publicKey.challenge) {{ {_set(ch, '__j.publicKey.challenge')} }}",
        ]
    return _lane(p, name, "POST", _AK_BEGIN, body={"csrfToken": "{{" + tok + "}}"} if body is None else body,
                 form_var=form_var, tests=[*tests, *extra_tests])


def _assertion_js(slot, ch, *, flags, count, key, handle, unknown_cred, tamper, tok, drop, extra, extra_js=None):
    """Тело входа ключом: утверждение подставного аутентификатора в форме браузера."""
    if count == "next":
        count_expr = f"parseInt({_env('ak' + slot + 'Count')} || '0', 10) + 1"
    else:
        count_expr = str(int(count))
    key_expr = str(int(key)) if key is not None else f"parseInt({_env('ak' + slot + 'Mat')} || '0', 10)"
    handle_expr = "_akU(_ak.b64(_ak.rand(64)))" if handle is None else f"_akU({_env(handle)} || '')"
    lines = [
        *_LIB,
        _AKU,
        ("const _akCred = _ak.rand(16);" if unknown_cred
         else f"const _akCred = _ak.unb64({_env('ak' + slot + 'CredId')} || '');"),
        f"const _akN = {count_expr};",
        _set("_akSentCount", "String(_akN)"),
        f"const _akA = _ak.assert({{ challenge: _ak.unb64({_env(ch)} || ''), rpId: {_RP_JS}, "
        f"origin: {_ORIGIN_JS}, flags: {int(flags)}, count: _akN, credId: _akCred, key: {key_expr}, "
        f"tamper: {'true' if tamper else 'false'} }});",
        "const _akR = { clientDataJSON: _akU(_akA.clientDataJson), authenticatorData: _akU(_akA.authenticatorData), "
        f"signature: _akU(_akA.signature), userHandle: {handle_expr} }};",
        "const _akCr = { id: _akU(_akA.id), rawId: _akU(_akA.id), type: 'public-key', response: _akR };",
        f"const _akB = {{ csrfToken: {_env(tok)} || '', credential: _akCr }};",
    ]
    for d in drop:
        lines.append({"csrfToken": "delete _akB.csrfToken;", "credential": "delete _akB.credential;",
                      "userHandle": "delete _akR.userHandle;", "signature": "delete _akR.signature;"}[d])
    if extra:
        lines.append(f"Object.assign(_akB, {_json.dumps(extra, ensure_ascii=False)});")
    if extra_js:
        lines.append(f"Object.assign(_akB, {extra_js});")
    lines += _raw_body("JSON.stringify(_akB)")
    return lines


def _key_login(p, name, *, slot, ch, tok, flags=_UP | _UV, count="next", key=None, handle=None,
               unknown_cred=False, tamper=False, drop=(), extra=None, extra_js=None, pre=(), form_var=None,
               tests=()):
    """Предъявление утверждения полосе входа ключом (`p` — «браузер»: контекст и источник)."""
    pre = [*pre, *_need(ch, f"{name.upper()}: испытание входа не выдано",
                        "шаг выдачи испытания выше не вернул challenge — собирать утверждение не на чем")]
    if not unknown_cred:
        pre += _need("ak" + slot + "CredId", f"{name.upper()}: удостоверение строки {slot} не заведено",
                     "кейс выше не завёл ключ — предъявлять нечего")
    pre += _assertion_js(slot, ch, flags=flags, count=count, key=key, handle=handle,
                         unknown_cred=unknown_cred, tamper=tamper, tok=tok, drop=drop, extra=extra, extra_js=extra_js)
    return _lane(p, name, "POST", _AK_LOGIN, body={}, form_var=form_var, pre=pre, tests=list(tests))


def _signed_in(p, label, slot, session_var, level, *, user_var=None):
    """Вход ключом состоялся: форма Ф3-01, уровень по флагам, носитель и НОВЫЙ контекст."""
    out = [
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': тело — человек и сессия формы входа паролем (Ф3-01)')}, () => "
        "pm.expect([Object.keys(__j).sort(), Object.keys(__j.user || {}).sort(), Object.keys(__j.session || {}).sort()])"
        ".to.eql([['session', 'user'], ['displayName', 'email', 'id'], ['assuranceLevel', 'emailVerified', 'expiresAt']]));",
        f"pm.test({js_str(label + f': уровень сессии «{level}» — по флагам этого утверждения')}, () => "
        f"pm.expect(__j.session && __j.session.assuranceLevel).to.eql({js_str(level)}));",
        "{",
        "  const __fc = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_form='));",
        f"  pm.test({js_str(label + ': контекст формы сменён выдачей — новое печенье kaname_form')}, () => "
        f"pm.expect([__fc.length, __fc.length === 1 && __fc[0].value.split(';')[0].slice(12) !== ({_env(p + 'FormCookie')} || '')])"
        ".to.eql([1, true]));",
        "}",
        *_capture_cookie(p, "kaname_form", "FormCookie", label),
        "{",
        "  const __ss = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='));",
        f"  pm.test({js_str(label + ': носитель сессии поставлен')}, () => pm.expect(__ss.length).to.eql(1));",
        f"  if (__ss.length === 1) {{ {_set(session_var, '__ss[0].value.split(\";\")[0].slice(15)')} }}",
        "}",
        f"if (pm.response.code === 200) {{ {_set('ak' + slot + 'Count', _env('_akSentCount'))} }}",
    ]
    if user_var is not None:
        out.append(f"pm.test({js_str(label + ': вошёл владелец ключа')}, () => "
                   f"pm.expect([!!{_env(user_var)}, (__j.user || {{}}).id === {_env(user_var)}]).to.eql([true, true]));")
    return out


def _signin_refused(label):
    """Единый отказ входа (Р7): тело побайтово равно отказу неверному паролю (Ф3-02)."""
    return [
        *_status_is(401, label),
        f"pm.test({js_str(label + ': единый отказ входа — тело побайтово равно отказу неверному паролю')}, () => "
        f"pm.expect([!!{_env('akF13RefusedBody')}, pm.response.text() === {_env('akF13RefusedBody')}]).to.eql([true, true]));",
        *_no_cookies(label),
    ]


def _field_refused(label, field, rule="required"):
    """Отказ формы: 400, код 3, текст называет поле (и правило)."""
    return [
        *_status_is(400, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': код 3, текст называет поле ' + field)}, () => "
        f"pm.expect([__j.code, __j.message]).to.eql([3, {js_str('Illegal argument ' + field + ': ' + rule)}]));",
        *_no_cookies(label),
    ]


def _form_refused(label):
    """Признак чужого вида либо чужого контекста — 403 FORM_TOKEN_REJECTED, неразличимо."""
    return [
        *_status_is(403, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': код 7 и текст отказа признака')}, () => "
        f"pm.expect([__j.code, __j.message]).to.eql([7, {js_str(_FORM_REJECTED)}]));",
        "const __fi = (Array.isArray(__j.details) ? __j.details : []).filter((d) => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
        f"pm.test({js_str(label + ': признак отказа FORM_TOKEN_REJECTED')}, () => pm.expect(__fi.reason).to.eql('FORM_TOKEN_REJECTED'));",
        *_no_cookies(label),
    ]


def _password_login(p, name, person, tok, *, password=None, tests=()):
    body = {"email": "{{" + person + "Email}}", "password": password or ("{{" + person + "Password}}"),
            "csrfToken": "{{" + tok + "}}"}
    return _lane(p, name, "POST", _LOGIN, body=body, tests=list(tests))


def _password_signed_in(p, label, session_var, *, level="1"):
    return [
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + f': вход паролем — сессия уровня «{level}»')}, () => "
        f"pm.expect(__j.session && __j.session.assuranceLevel).to.eql({js_str(level)}));",
        *_capture_cookie(p, "kaname_form", "FormCookie", label),
        "{",
        "  const __ss = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='));",
        f"  pm.test({js_str(label + ': носитель сессии поставлен')}, () => pm.expect(__ss.length).to.eql(1));",
        f"  if (__ss.length === 1) {{ {_set(session_var, '__ss[0].value.split(\";\")[0].slice(15)')} }}",
        "}",
    ]


def _probe(p, name, session_var, *, alive):
    """Годен ли носитель — чтением состояния второго фактора, которое ничего не меняет."""
    label = name.upper()
    tests = [f"pm.test({js_str(label + ': носитель захвачен (контроль непустоты)')}, () => "
             f"pm.expect(!!{_env(session_var)}).to.eql(true));"]
    if alive:
        tests += _status_is(200, label)
    else:
        tests += [
            *_status_is(401, label),
            f"pm.test({js_str(label + ': отказ побайтово равен отказу по несуществующей сессии')}, () => "
            f"pm.expect([!!{_env('akF13NoSessionBody')}, pm.response.text() === {_env('akF13NoSessionBody')}])"
            ".to.eql([true, true]));",
        ]
    return _lane(p, name, "GET", _SF_STATUS, session=session_var, tests=tests)


def _no_session_reference(p, name):
    return Step(name=name, method="GET", path=_SF_STATUS,
                pre_script=[*require_env_url(_LANE, _SF_STATUS, _LANE_WHY), *_src_pre(p),
                            "pm.request.headers.upsert({key: 'Cookie', value: 'kaname_session=not-a-session-' + "
                            + _env("runId") + "});"],
                insecure_tls=True, auth="anonymous", cookie_jar=False,
                test_script=[*_status_is(401, name.upper()),
                             _set("akF13NoSessionBody", "pm.response.text()")])


def _current_session(p, name, session_var, tests):
    """Перечень своих сессий из `session_var`: текущая запись — в `_akCur`."""
    label = name.upper()
    return _lane(p, name, "GET", _SESSIONS, session=session_var, tests=[
        *_status_is(200, label),
        *_parse_body(),
        "const _akSess = Array.isArray(__j.sessions) ? __j.sessions : [];",
        "const _akCur = _akSess.filter((s) => s.current === true)[0] || null;",
        f"pm.test({js_str(label + ': текущая запись названа ровно одна')}, () => "
        "pm.expect(_akSess.filter((s) => s.current === true).length).to.eql(1));",
        *tests,
    ])


def _register_key(p, tag, slot, *, key=_MAT_MAIN, handle_var=None):
    """Ключ `slot` человека `p`: испытание → результат → операция без ошибки; рукоятка — в `handle_var`."""
    up = tag.upper()
    begin_tests = []
    if handle_var is not None:
        begin_tests.append(f"if (__j.user && __j.user.id) {{ {_set(handle_var, '__j.user.id')} }}")
    return [
        _begin_registration(p, f"{tag}-begin", slot, tests=begin_tests),
        _finish_registration(p, f"{tag}-finish", slot=slot, ch="akRegCh" + slot, key=key,
                             tests=_registration_accepted(slot, f"{up}-FINISH")),
        _await_op(p, f"{tag}-op", slot, tests=_key_registered(slot, f"{up}-OP", key)),
    ]


def _step_up(p, name, session_var, body, *, pre=(), tests=()):
    return _lane(p, name, "POST", _STEP_UP, body=body, session=session_var, pre=pre, tests=list(tests))


def _stepped_up(p, label, session_var, level):
    """Церемония внутри сессии: уровень прежний, недостающего нет, носитель перевыпущен."""
    return [
        *_status_is(200, label),
        *_parse_body(),
        f"pm.test({js_str(label + f': достигнутый уровень «{level}» — равен прежнему; недостающего нет')}, () => "
        "pm.expect([__j.assurance && __j.assurance.level, __j.assurance && __j.assurance.missingForLevel2, "
        f"__j.session && __j.session.assuranceLevel]).to.eql([{js_str(level)}, [], {js_str(level)}]));",
        _set(session_var + "Old", _env(session_var)),
        "{",
        "  const __ss = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='));",
        f"  pm.test({js_str(label + ': носитель перевыпущен — новое значение')}, () => "
        f"pm.expect([__ss.length, __ss.length === 1 && __ss[0].value.split(';')[0].slice(15) !== {_env(session_var)}]).to.eql([1, true]));",
        f"  if (__ss.length === 1) {{ {_set(session_var, '__ss[0].value.split(\";\")[0].slice(15)')} }}",
        "}",
    ]


def _tick_past(var):
    """Часы прогона перешагнули момент `var` — моменты записей усечены до секунды."""
    return [
        f"const _akAt = Date.parse({_env(var)} || '');",
        "const _akDeadline = Date.now() + 3000;",
        "while (!Number.isNaN(_akAt) && Date.now() < _akAt + 1100 && Date.now() < _akDeadline) { /* секунда записи прошла */ }",
    ]


# ───────────────────────────────────────────────────────────────────────────
# Ф13-20: у личности без строки ключа сессии не появляется. Человек C
# заводится здесь — с паролем и без единого ключа; эталон единого отказа —
# отказ неверному паролю (Ф3-02) — записывается здесь же.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-PERSON-WITHOUT-KEY-ROW",
    title="Ф13-20: утверждение по удостоверению, которого нет, у человека без строки ключа — единый отказ, сессии нет",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_human(_C, "ak-c"),
        _no_session_reference(_C, "f13-no-session-reference"),
        _tok(_C, "f13-20-login-tok", "login", "akCTokLogin", init=_fresh_src(_C)),
        _password_login(_C, "f13-20-wrong-password", _C, "akCTokLogin", password="not-the-password-{{runId}}", tests=[
            *_status_is(401, "F13-20-WRONG-PASSWORD"),
            *_parse_body(),
            "pm.test('F13-20-WRONG-PASSWORD: эталон Ф3-02 — код 16, текст, details пуст', () => "
            f"pm.expect(__j).to.eql({_json.dumps(_AUTH_FAILED_BODY)}));",
            _set("akF13RefusedBody", "pm.response.text()"),
        ]),
        _current_session(_C, "f13-20-sessions-before", _C + "SessionCookie", [
            _set("akC20Count", "String(_akSess.length)"),
            _set("akC20Current", "(_akCur && _akCur.id) || ''"),
        ]),
        _list(_C, "f13-20-no-key-rows", count=0),
        _tok(_C, "f13-20-begin-tok", "access-key-begin", "akCTokBegin"),
        _begin(_C, "f13-20-begin", "akLc20", "akCTokBegin"),
        _tok(_C, "f13-20-login-key-tok", "access-key-login", "akCTokKey"),
        _key_login(_C, "f13-20-unknown-credential", slot="X20", ch="akLc20", tok="akCTokKey", unknown_cred=True,
                   key=_MAT_MAIN, count=1, tests=_signin_refused("F13-20-UNKNOWN-CREDENTIAL")),
        _current_session(_C, "f13-20-sessions-after", _C + "SessionCookie", [
            "pm.test('F13-20-SESSIONS-AFTER: записей сессий столько же, текущая та же', () => "
            f"pm.expect([String(_akSess.length), (_akCur && _akCur.id) || '']).to.eql([{_env('akC20Count')}, {_env('akC20Current')}]));",
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-01, Ф13-27: испытание не называет человека; два вида формы полосы.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-OK-CHALLENGE-NAMES-NOBODY",
    title="Ф13-01, Ф13-27: испытание без человека в объявленной форме, разное на каждый запрос; два вида формы, третий — отказ",
    classes=["CONF", "NEG"],
    priority="P0",
    steps=[
        _tok(_C, "f13-01-begin-tok", "access-key-begin", "akC01Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-01-begin", "akLc01", "akC01Begin", tests=[
            *_status_is(200, "F13-01-BEGIN"),
            *_parse_body(),
            "const _akPk = __j.publicKey || {};",
            "pm.test('F13-01-BEGIN: тело — только publicKey, пять полей', () => pm.expect([Object.keys(__j), "
            "Object.keys(_akPk).sort()]).to.eql([['publicKey'], ['allowCredentials', 'challenge', 'rpId', 'timeout', 'userVerification']]));",
            "pm.test('F13-01-BEGIN: испытание base64url без дополнения', () => "
            "pm.expect(/^[A-Za-z0-9_-]+$/.test(String(_akPk.challenge || ''))).to.eql(true));",
            f"pm.test('F13-01-BEGIN: имя доверяющей стороны и срок испытания — объявленные', () => "
            f"pm.expect([_akPk.rpId, _akPk.timeout]).to.eql([{_RP_JS}, {_CHALLENGE_TTL_MS}]));",
            f"pm.test('F13-01-BEGIN: проверка пользователя — preferred', () => pm.expect(_akPk.userVerification).to.eql({js_str(_UV_PREFERRED)}));",
            "pm.test('F13-01-BEGIN: allowCredentials — пустой массив словом, не отсутствие', () => "
            "pm.expect(Array.isArray(_akPk.allowCredentials) && _akPk.allowCredentials.length === 0).to.eql(true));",
            *_no_cookies("F13-01-BEGIN"),
            f"if (_akPk.challenge) {{ {_set('akLc01', '_akPk.challenge')} }}",
        ]),
        _begin(_C, "f13-01-begin-again", "akLc01b", "akC01Begin", tests=[
            *_status_is(200, "F13-01-BEGIN-AGAIN"),
            *_parse_body(),
            "pm.test('F13-01-BEGIN-AGAIN: второй запрос — другое испытание', () => "
            f"pm.expect([!!{_env('akLc01')}, typeof (__j.publicKey && __j.publicKey.challenge) === 'string' "
            f"&& __j.publicKey.challenge !== {_env('akLc01')}]).to.eql([true, true]));",
            *_no_cookies("F13-01-BEGIN-AGAIN"),
        ]),
        _tok(_C, "f13-27-login-tok", "access-key-login", "akC27Login"),
        Step(name="f13-27-kinds-differ", method="GET", path=f"{_CSRF}?form=access-key-begin",
             pre_script=[*require_env_url(_LANE, f"{_CSRF}?form=access-key-begin", _LANE_WHY), *_src_pre(_C),
                         *_with_cookies(("kaname_form", _C + "FormCookie"))],
             insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=[
                 *_status_is(200, "F13-27-KINDS-DIFFER"),
                 *_parse_body(),
                 "pm.test('F13-27-KINDS-DIFFER: под одним контекстом признаки двух видов разные', () => "
                 f"pm.expect([__j.csrfToken === {_env('akC01Begin')}, __j.csrfToken !== {_env('akC27Login')}]).to.eql([true, true]));",
             ]),
        Step(name="f13-27-third-kind-refused", method="GET", path=f"{_CSRF}?form=access-key",
             pre_script=[*require_env_url(_LANE, f"{_CSRF}?form=access-key", _LANE_WHY), *_src_pre(_C),
                         *_with_cookies(("kaname_form", _C + "FormCookie"))],
             insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=[
                 *_status_is(400, "F13-27-THIRD-KIND-REFUSED"),
                 *_parse_body(),
                 "pm.test('F13-27-THIRD-KIND-REFUSED: код 3, текст называет поле form', () => "
                 "pm.expect([__j.code, String(__j.message || '').indexOf('Illegal argument form: ') === 0]).to.eql([3, true]));",
             ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-02: форма выдачи испытания — по одному изменённому факту против (е).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-BEGIN-FORM",
    title="Ф13-02: без признака и с лишним полем — 400 с полем; признак чужого вида или контекста — 403; свой — 200",
    classes=["NEG", "VAL", "SEC"],
    priority="P0",
    steps=[
        _tok(_C, "f13-02-begin-tok", "access-key-begin", "akC02Begin", fresh=True, init=_fresh_src(_C)),
        _tok(_C, "f13-02-login-kind-tok", "login", "akC02Pw"),
        _tok(_C, "f13-02-akl-kind-tok", "access-key-login", "akC02Akl"),
        _begin(_C, "f13-02a-no-token", "akLc02", "akC02Begin", body={},
               tests=_field_refused("F13-02A-NO-TOKEN", "csrfToken")),
        _begin(_C, "f13-02b-login-kind", "akLc02", "akC02Pw", tests=_form_refused("F13-02B-LOGIN-KIND")),
        _begin(_C, "f13-02d-email-field", "akLc02", "akC02Begin",
               body={"csrfToken": "{{akC02Begin}}", "email": "{{akCEmail}}"},
               tests=_field_refused("F13-02D-EMAIL-FIELD", "email", "unknown field")),
        _begin(_C, "f13-02e-neighbour-kind", "akLc02", "akC02Akl", tests=_form_refused("F13-02E-NEIGHBOUR-KIND")),
        _begin(_C, "f13-02f-own-kind", "akLc02", "akC02Begin"),
        # (в) вход паролем в том же браузере сменил контекст: признак прежнего
        # контекста при новом печенье — отказ признака.
        _password_login(_C, "f13-02c-password-login", _C, "akC02Pw",
                        tests=_password_signed_in(_C, "F13-02C-PASSWORD-LOGIN", "akC02PwSession")),
        _begin(_C, "f13-02c-changed-context", "akLc02", "akC02Begin", tests=_form_refused("F13-02C-CHANGED-CONTEXT")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-05: вход без пароля. Ключ C1 заводится здесь; утверждение без проверки
# пользователя и без резерва — уровень «2».
# ───────────────────────────────────────────────────────────────────────────
_NO_PASSWORD_FIELD = ("pm.test({label}, () => {{ let __b = {{}}; try {{ __b = JSON.parse(pm.request.body.raw || '{{}}'); }} "
                      "catch (e) {{ __b = {{}}; }} pm.expect(JSON.stringify(__b).indexOf('\"password\"')).to.eql(-1); }});")
CASES.append(Case(
    id="IAM-AKLOGIN-OK-SIGN-IN-WITHOUT-PASSWORD",
    title="Ф13-05: вход ключом — сессия формы Ф3-01 уровня «2», носитель и новый контекст, пароль не предъявлен",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_register_key(_C, "f13-05-key", "C1", handle_var=_C + "Handle"),
        _tok(_C, "f13-05-begin-tok", "access-key-begin", "akC05Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-05-begin", "akLc05", "akC05Begin", extra_tests=[
            _NO_PASSWORD_FIELD.format(label=js_str("F13-05-BEGIN: в теле запроса нет поля password"))]),
        _tok(_C, "f13-05-login-tok", "access-key-login", "akC05Login"),
        _key_login(_C, "f13-05-login", slot="C1", ch="akLc05", tok="akC05Login", flags=_UP, handle=_C + "Handle",
                   tests=[
                       *_signed_in(_C, "F13-05-LOGIN", "C1", "akCS1", "2", user_var=_C + "UserId"),
                       _NO_PASSWORD_FIELD.format(label=js_str("F13-05-LOGIN: в теле запроса нет поля password")),
                       "{",
                       "  const __ss = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='))[0];",
                       "  const __v = __ss ? __ss.value : '';",
                       "  pm.test('F13-05-LOGIN: атрибуты носителя те же, что у входа паролем — HttpOnly, Secure, SameSite=Lax, Path=/, без Domain', () => "
                       "pm.expect([/; HttpOnly/i.test(__v), /; Secure/i.test(__v), /; SameSite=Lax/i.test(__v), /; Path=\\//.test(__v), /; Domain=/i.test(__v)])"
                       ".to.eql([true, true, true, true, false]));",
                       f"  pm.test({js_str('F13-05-LOGIN: срок сессии — момент выдачи плюс ' + str(_SESSION_TTL_S) + ' с')}, () => {{",
                       "    const __issued = Date.parse(pm.response.headers.get('Date') || '');",
                       "    const __exp = Date.parse((__j.session && __j.session.expiresAt) || '');",
                       f"    pm.expect(Math.abs(__exp - __issued - {_SESSION_TTL_S * 1000}) <= 2000).to.eql(true); }});",
                       "}",
                   ]),
        _current_session(_C, "f13-05-session-record", "akCS1", [
            "pm.test('F13-05-SESSION-RECORD: момент последнего предъявления равен моменту аутентификации', () => "
            "pm.expect(!!_akCur && _akCur.lastPresentedAt === _akCur.authenticatedAt).to.eql(true));",
        ]),
        _list(_C, "f13-05-key-presented", count=1, extra=_key_listed("C1", "F13-05-KEY-PRESENTED", last_used="moved")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-07: форма входа — отказ формы до сверки, испытание не сгорает.
# ───────────────────────────────────────────────────────────────────────────
_LOGIN_FORM_AXIS = (
    ("no-credential", dict(drop=("credential",)), ("credential", "required")),
    ("no-user-handle", dict(drop=("userHandle",)), ("credential.response.userHandle", "required")),
    ("no-signature", dict(drop=("signature",)), ("credential.response.signature", "required")),
    ("no-csrf-token", dict(drop=("csrfToken",)), ("csrfToken", "required")),
    ("second-factor-field", dict(extra={"secondFactor": {"method": "totp", "code": "123456"}}),
     ("secondFactor", "unknown field")),
    ("email-field", dict(extra={"email": "nobody@kaname.local"}), ("email", "unknown field")),
    ("password-field", dict(extra={"password": "not-a-password"}), ("password", "unknown field")),
    ("client-extension-results-field", dict(extra={"clientExtensionResults": {}}),
     ("clientExtensionResults", "unknown field")),
)
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-LOGIN-FORM",
    title="Ф13-07: отсутствующее поле и лишнее — 400 с именем; чужой вид — 403; испытание не сгорело — полная форма проходит",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        _tok(_C, "f13-07-begin-tok", "access-key-begin", "akC07Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-07-begin", "akLc07", "akC07Begin"),
        _tok(_C, "f13-07-login-tok", "access-key-login", "akC07Login"),
        _tok(_C, "f13-07-login-kind-tok", "login", "akC07Pw"),
        *[_key_login(_C, f"f13-07-{tag}", slot="C1", ch="akLc07", tok="akC07Login", handle=_C + "Handle", **kw,
                     tests=_field_refused(f"F13-07-{tag.upper()}", field, rule))
          for tag, kw, (field, rule) in _LOGIN_FORM_AXIS],
        _key_login(_C, "f13-07-login-kind", slot="C1", ch="akLc07", tok="akC07Pw", handle=_C + "Handle",
                   tests=_form_refused("F13-07-LOGIN-KIND")),
        _key_login(_C, "f13-07-full-form", slot="C1", ch="akLc07", tok="akC07Login", handle=_C + "Handle",
                   tests=_signed_in(_C, "F13-07-FULL-FORM", "C1", "akCS7", "3", user_var=_C + "UserId")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-03: одно живое испытание на контекст — второе замещает первое.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-CHALLENGE-REPLACED",
    title="Ф13-03: два испытания одному контексту — утверждение над первым единый отказ, над вторым — вход",
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        _tok(_C, "f13-03-begin-tok", "access-key-begin", "akC03Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-03-begin-first", "akLc03a", "akC03Begin"),
        _begin(_C, "f13-03-begin-second", "akLc03b", "akC03Begin"),
        _tok(_C, "f13-03-login-tok", "access-key-login", "akC03Login"),
        _key_login(_C, "f13-03-over-first", slot="C1", ch="akLc03a", tok="akC03Login", handle=_C + "Handle",
                   tests=_signin_refused("F13-03-OVER-FIRST")),
        _key_login(_C, "f13-03-over-second", slot="C1", ch="akLc03b", tok="akC03Login", handle=_C + "Handle",
                   tests=_signed_in(_C, "F13-03-OVER-SECOND", "C1", "akCS3x", "3", user_var=_C + "UserId")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-08: испытание однократно и сгорает первым предъявлением.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-CHALLENGE-ONE-TIME",
    title="Ф13-08: повтор над принятым испытанием и годное после негодного — единый отказ; свежее испытание — вход",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _tok(_C, "f13-08a-begin-tok", "access-key-begin", "akC08Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-08a-begin", "akLc08", "akC08Begin"),
        _tok(_C, "f13-08a-login-tok", "access-key-login", "akC08Login"),
        _key_login(_C, "f13-08a-first", slot="C1", ch="akLc08", tok="akC08Login", handle=_C + "Handle", tests=[
            _set("akC08Context", _env(_C + "FormCookie")),
            *_signed_in(_C, "F13-08A-FIRST", "C1", "akCS8", "3", user_var=_C + "UserId"),
        ]),
        # Повтор — в том же контексте, свежей подписью со счётчиком выше: внесённое
        # различие одно — испытание уже предъявлено.
        _key_login(_C, "f13-08a-again", slot="C1", ch="akLc08", tok="akC08Login", handle=_C + "Handle",
                   form_var="akC08Context", tests=_signin_refused("F13-08A-AGAIN")),
        _tok(_C, "f13-08b-begin-tok", "access-key-begin", "akC08bBegin", fresh=True),
        _begin(_C, "f13-08b-begin", "akLc08b", "akC08bBegin"),
        _tok(_C, "f13-08b-login-tok", "access-key-login", "akC08bLogin"),
        _key_login(_C, "f13-08b-forged", slot="C1", ch="akLc08b", tok="akC08bLogin", handle=_C + "Handle",
                   tamper=True, tests=_signin_refused("F13-08B-FORGED")),
        _key_login(_C, "f13-08b-valid-after-forged", slot="C1", ch="akLc08b", tok="akC08bLogin", handle=_C + "Handle",
                   tests=_signin_refused("F13-08B-VALID-AFTER-FORGED")),
        _begin(_C, "f13-08c-begin", "akLc08c", "akC08bBegin"),
        _key_login(_C, "f13-08c-fresh", slot="C1", ch="akLc08c", tok="akC08bLogin", handle=_C + "Handle",
                   tests=_signed_in(_C, "F13-08C-FRESH", "C1", "akCS8c", "3", user_var=_C + "UserId")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-26: признак формы запроса форму подтверждения не закрывает.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-NEG-LOGIN-FORM-KIND",
    title="Ф13-26: признак выдачи на форме входа — 403, свой — 200; после выдачи негодны оба; испытание чужого контекста — единый отказ",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _tok(_C, "f13-26-begin-tok", "access-key-begin", "akC26Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-26-begin", "akLc26", "akC26Begin"),
        _tok(_C, "f13-26-login-tok", "access-key-login", "akC26Login"),
        _tok(_C, "f13-26-password-kind-tok", "password", "akC26Pw"),
        _key_login(_C, "f13-26a-no-token", slot="C1", ch="akLc26", tok="akC26Login", handle=_C + "Handle",
                   drop=("csrfToken",), tests=_field_refused("F13-26A-NO-TOKEN", "csrfToken")),
        _key_login(_C, "f13-26b-password-kind", slot="C1", ch="akLc26", tok="akC26Pw", handle=_C + "Handle",
                   tests=_form_refused("F13-26B-PASSWORD-KIND")),
        _key_login(_C, "f13-26d-begin-kind", slot="C1", ch="akLc26", tok="akC26Begin", handle=_C + "Handle",
                   tests=_form_refused("F13-26D-BEGIN-KIND")),
        _key_login(_C, "f13-26g-own-kind", slot="C1", ch="akLc26", tok="akC26Login", handle=_C + "Handle",
                   tests=_signed_in(_C, "F13-26G-OWN-KIND", "C1", "akCS26", "3", user_var=_C + "UserId")),
        # После выдачи контекст сменён: оба прежних признака при новом печенье — отказ.
        _begin(_C, "f13-26g-begin-token-stale", "akLc26x", "akC26Begin", tests=_form_refused("F13-26G-BEGIN-TOKEN-STALE")),
        _key_login(_C, "f13-26g-login-token-stale", slot="C1", ch="akLc26", tok="akC26Login", handle=_C + "Handle",
                   tests=_form_refused("F13-26G-LOGIN-TOKEN-STALE")),
        # (в) новый контекст K3: испытание под ним, затем вход паролем сменил контекст.
        _tok(_C, "f13-26c-begin-tok", "access-key-begin", "akC26cBegin", fresh=True),
        _begin(_C, "f13-26c-begin", "akLc26c", "akC26cBegin"),
        _tok(_C, "f13-26c-login-tok", "access-key-login", "akC26cLogin"),
        _tok(_C, "f13-26c-pw-tok", "login", "akC26cPw"),
        _password_login(_C, "f13-26c-password-login", _C, "akC26cPw",
                        tests=_password_signed_in(_C, "F13-26C-PASSWORD-LOGIN", "akC26PwSession")),
        _key_login(_C, "f13-26c-stale-token", slot="C1", ch="akLc26c", tok="akC26cLogin", handle=_C + "Handle",
                   tests=_form_refused("F13-26C-STALE-TOKEN")),
        _tok(_C, "f13-26c-new-login-tok", "access-key-login", "akC26cLogin2"),
        _key_login(_C, "f13-26c-foreign-context-challenge", slot="C1", ch="akLc26c", tok="akC26cLogin2",
                   handle=_C + "Handle", tests=_signin_refused("F13-26C-FOREIGN-CONTEXT-CHALLENGE")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-04: выдача испытания — попытка по источнику; отказ формы — нет.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-BVA-BEGIN-BY-SOURCE",
    title=f"Ф13-04: {_N_SOURCE} отказов формы окна не исчерпывают; {_N_SOURCE}-я выдача — 200, следующая — 429 с Retry-After",
    classes=["BVA", "NEG"],
    priority="P1",
    steps=[
        _tok(_RATE, "f13-04-begin-tok", "access-key-begin", "akR04Begin", fresh=True, init=_fresh_src(_RATE)),
        *[_begin(_RATE, f"f13-04-form-refusal-{i}", "akLc04", "akR04Begin", body={},
                 tests=_field_refused(f"F13-04-FORM-REFUSAL-{i}", "csrfToken"))
          for i in range(1, _N_SOURCE + 1)],
        *[_begin(_RATE, f"f13-04-begin-{i}", f"akLc04n{i}", "akR04Begin") for i in range(1, _N_SOURCE + 1)],
        _begin(_RATE, f"f13-04-begin-{_N_SOURCE + 1}", "akLc04over", "akR04Begin", tests=[
            *_status_is(429, f"F13-04-BEGIN-{_N_SOURCE + 1}"),
            *_parse_body(),
            f"pm.test('F13-04-OVER: код 8 и текст предела', () => pm.expect([__j.code, __j.message]).to.eql([8, {js_str(_TOO_MANY)}]));",
            "const __ti = (Array.isArray(__j.details) ? __j.details : []).filter((d) => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo')[0] || {};",
            "pm.test('F13-04-OVER: признак отказа TOO_MANY_ATTEMPTS', () => pm.expect(__ti.reason).to.eql('TOO_MANY_ATTEMPTS'));",
            f"pm.test({js_str('F13-04-OVER: Retry-After — секунды до конца окна, в (0, ' + str(_T_SOURCE) + ']')}, () => {{",
            "  const ra = String(pm.response.headers.get('Retry-After') || '');",
            f"  pm.expect([/^[0-9]+$/.test(ra), Number(ra) >= 1 && Number(ra) <= {_T_SOURCE}]).to.eql([true, true]); }});",
            *_no_cookies("F13-04-OVER"),
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-32: вход ключом обнуляет счёт неверных предъявлений по адресу. Человек D
# — (а), человек E — близнец (б): та же серия без входа ключом.
# ───────────────────────────────────────────────────────────────────────────
def _wrong_passwords(p, tag, person, tok, count, first, label_ok):
    return [_password_login(p, f"{tag}-wrong-{first + i}", person, tok, password="not-the-password-{{runId}}",
                            tests=_signin_refused(f"{tag.upper()}-WRONG-{first + i}") if label_ok else [])
            for i in range(count)]


def _too_many(label):
    return [
        *_status_is(429, label),
        *_parse_body(),
        f"pm.test({js_str(label + ': код 8 и текст предела')}, () => pm.expect([__j.code, __j.message]).to.eql([8, {js_str(_TOO_MANY)}]));",
        f"pm.test({js_str(label + f': Retry-After — секунды до конца окна, в (0, {_T_ADDRESS}]')}, () => {{",
        "  const ra = String(pm.response.headers.get('Retry-After') || '');",
        f"  pm.expect([/^[0-9]+$/.test(ra), Number(ra) >= 1 && Number(ra) <= {_T_ADDRESS}]).to.eql([true, true]); }});",
        *_no_cookies(label),
    ]


CASES.append(Case(
    id="IAM-AKLOGIN-BVA-KEY-LOGIN-RESETS-ADDRESS-COUNT",
    title=f"Ф13-32: {_N_ADDRESS} неверных, вход ключом, ещё {_N_ADDRESS - 1} — ни одного 429; близнец без входа — следующая 429",
    classes=["BVA", "NEG", "SEC"],
    priority="P1",
    steps=[
        *_human(_D, "ak-d"),
        *_register_key(_D, "f13-32-key", "D1", handle_var=_D + "Handle"),
        _tok(_D, "f13-32-login-tok", "login", "akD32Pw", fresh=True, init=_fresh_src(_D)),
        *_wrong_passwords(_D, "f13-32a", _D, "akD32Pw", _N_ADDRESS, 1, True),
        _tok(_D, "f13-32a-begin-tok", "access-key-begin", "akD32Begin"),
        _begin(_D, "f13-32a-begin", "akLd32", "akD32Begin"),
        _tok(_D, "f13-32a-key-tok", "access-key-login", "akD32Key"),
        _key_login(_D, "f13-32a-key-login", slot="D1", ch="akLd32", tok="akD32Key", handle=_D + "Handle",
                   tests=_signed_in(_D, "F13-32A-KEY-LOGIN", "D1", "akDS32", "3", user_var=_D + "UserId")),
        _tok(_D, "f13-32a-login-tok-after", "login", "akD32Pw2"),
        *_wrong_passwords(_D, "f13-32a-after", _D, "akD32Pw2", _N_ADDRESS - 1, 1, True),
        *_human(_E, "ak-e"),
        _tok(_E, "f13-32b-login-tok", "login", "akE32Pw", fresh=True, init=_fresh_src(_E)),
        *_wrong_passwords(_E, "f13-32b", _E, "akE32Pw", _N_ADDRESS, 1, True),
        _password_login(_E, f"f13-32b-wrong-{_N_ADDRESS + 1}", _E, "akE32Pw", password="not-the-password-{{runId}}",
                        tests=_too_many(f"F13-32B-WRONG-{_N_ADDRESS + 1}")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-18: две полосы входа одного человека независимы. Два «браузера» — два
# контекста формы; выход из одной сессии другую не гасит.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-OK-TWO-LANES-INDEPENDENT",
    title="Ф13-18: паролем — «1», ключом — «3», две записи; выход из сессии пароля сессию ключа не гасит",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        _tok(_C, "f13-18-pw-tok", "login", "akC18Pw", fresh=True, init=_fresh_src(_C)),
        _password_login(_C, "f13-18-password-login", _C, "akC18Pw",
                        tests=_password_signed_in(_C, "F13-18-PASSWORD-LOGIN", "akC18Pw1")),
        _tok(_CB, "f13-18-begin-tok", "access-key-begin", "akCb18Begin", fresh=True, init=_fresh_src(_CB)),
        _begin(_CB, "f13-18-begin", "akLc18", "akCb18Begin"),
        _tok(_CB, "f13-18-key-tok", "access-key-login", "akCb18Key"),
        _key_login(_CB, "f13-18-key-login", slot="C1", ch="akLc18", tok="akCb18Key", handle=_C + "Handle",
                   tests=_signed_in(_CB, "F13-18-KEY-LOGIN", "C1", "akC18Key1", "3", user_var=_C + "UserId")),
        _current_session(_CB, "f13-18-key-session-id", "akC18Key1", [_set("akC18KeyId", "(_akCur && _akCur.id) || ''")]),
        _current_session(_C, "f13-18-two-records", "akC18Pw1", [
            "pm.test('F13-18-TWO-RECORDS: из сессии пароля видна запись ключа отдельной записью', () => "
            f"pm.expect([!!{_env('akC18KeyId')}, _akSess.some((s) => s.id === {_env('akC18KeyId')} && s.current === false), "
            f"!!_akCur && _akCur.id !== {_env('akC18KeyId')}]).to.eql([true, true, true]));",
        ]),
        _tok(_C, "f13-18-logout-tok", "logout", "akC18Out"),
        _lane(_C, "f13-18-logout-password-session", "POST", _LOGOUT, body={"csrfToken": "{{akC18Out}}"},
              session="akC18Pw1", tests=[*_status_is(200, "F13-18-LOGOUT")]),
        _probe(_C, "f13-18-password-session-ended", "akC18Pw1", alive=False),
        _probe(_CB, "f13-18-key-session-alive", "akC18Key1", alive=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-13: копии уровня читают запись. S3 — вход ключом с проверкой («3»), S2 —
# без неё («2»): церемония и смена пароля называют уровень записи.
# ───────────────────────────────────────────────────────────────────────────
def _key_session(p, tag, session_var, level, flags):
    up = tag.upper()
    return [
        _tok(p, f"{tag}-begin-tok", "access-key-begin", f"{p}{tag.replace('-', '')}B", fresh=True, init=_fresh_src(p)),
        _begin(p, f"{tag}-begin", f"akLc{tag.replace('-', '')}", f"{p}{tag.replace('-', '')}B"),
        _tok(p, f"{tag}-key-tok", "access-key-login", f"{p}{tag.replace('-', '')}K"),
        _key_login(p, f"{tag}-key-login", slot="C1", ch=f"akLc{tag.replace('-', '')}", tok=f"{p}{tag.replace('-', '')}K",
                   handle=_C + "Handle", flags=flags,
                   tests=_signed_in(p, f"{up}-KEY-LOGIN", "C1", session_var, level, user_var=_C + "UserId")),
    ]


def _password_change(p, name, session_var, level):
    label = name.upper()
    return [
        _tok(p, f"{name}-tok", "password", f"{p}PwChange", session=session_var),
        _lane(p, name, "POST", _PASSWORD_CHANGE, session=session_var,
              body={"currentPassword": "{{" + _C + "Password}}", "newPassword": "{{" + _C + "PasswordNext}}",
                    "csrfToken": "{{" + p + "PwChange}}"},
              pre=[_set(_C + "PasswordNext", f"'Pw-' + Math.floor(Math.random() * 2176782336).toString(36) + '-' + {_env('runId')} + '-next'")],
              tests=[
                  *_status_is(200, label),
                  *_parse_body(),
                  f"pm.test({js_str(label + f': ответ смены пароля называет уровень записи «{level}»')}, () => "
                  f"pm.expect(__j.session && __j.session.assuranceLevel).to.eql({js_str(level)}));",
                  "{",
                  "  const __ss = pm.response.headers.all().filter((h) => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith('kaname_session='));",
                  f"  pm.test({js_str(label + ': новый носитель')}, () => pm.expect([__ss.length, __ss.length === 1 && "
                  f"__ss[0].value.split(';')[0].slice(15) !== {_env(session_var)}]).to.eql([1, true]));",
                  f"  if (__ss.length === 1) {{ {_set(session_var, '__ss[0].value.split(\";\")[0].slice(15)')} }}",
                  "}",
                  f"if (pm.response.code === 200) {{ {_set(_C + 'Password', _env(_C + 'PasswordNext'))} }}",
              ]),
    ]


CASES.append(Case(
    id="IAM-AKLOGIN-OK-LEVEL-COPIES-READ-THE-RECORD",
    title="Ф13-13: из сессии ключа «3» церемония и смена пароля называют «3», из «2» — «2»; недостающего нет",
    classes=["CONF", "SEC"],
    priority="P1",
    steps=[
        *_key_session(_C, "f13-13-s3", "akC13S3", "3", _UP | _UV),
        *_key_session(_CB, "f13-13-s2", "akC13S2", "2", _UP),
        _tok(_C, "f13-13b-s3-tok", "step-up", "akC13UpS3", session="akC13S3"),
        _step_up(_C, "f13-13b-s3-password", "akC13S3",
                 {"method": "password", "password": "{{" + _C + "Password}}", "csrfToken": "{{akC13UpS3}}"},
                 tests=_stepped_up(_C, "F13-13B-S3-PASSWORD", "akC13S3", "3")),
        _tok(_CB, "f13-13b-s2-tok", "step-up", "akC13UpS2", session="akC13S2"),
        _step_up(_CB, "f13-13b-s2-password", "akC13S2",
                 {"method": "password", "password": "{{" + _C + "Password}}", "csrfToken": "{{akC13UpS2}}"},
                 tests=_stepped_up(_CB, "F13-13B-S2-PASSWORD", "akC13S2", "2")),
        # Смена пароля снимает прочие сессии человека: сперва из «2», затем из
        # свежей «3».
        *_password_change(_CB, "f13-13a-s2-password-change", "akC13S2", "2"),
        *_key_session(_C, "f13-13-s3-again", "akC13S3b", "3", _UP | _UV),
        *_password_change(_C, "f13-13a-s3-password-change", "akC13S3b", "3"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-16, Ф13-17: у C заводится второй фактор; поле `secondFactor` у входа
# ключом отвергается и кода не тратит; церемонии внутри сессий ключа «3» и «2».
# ───────────────────────────────────────────────────────────────────────────
def _totp_code(var, *, wrong=False):
    """Pre-script: код свежей ступени (либо заведомо неверный) в `var`; ступень — в akCPresentedStep."""
    if wrong:
        return [*_TOTP, _set(var, f"__wrongCode({_env('akCTotpSecret')})")]
    return [*_TOTP, "const __s = __freshStep();", _set("akCPresentedStep", "String(__s)"),
            _set(var, f"__totp({_env('akCTotpSecret')}, __s)")]


_TOTP_ACCEPTED = "if (pm.response.code === 200) { pm.environment.set('akCLastStep', pm.environment.get('akCPresentedStep')); }"


def _await_fresh_step(p, name, var):
    """Ступень часов, у которой код ещё не принят и лежит в окне ±1: опрос с паузой."""
    label = name.upper()
    polls = f"_akTotpPolls_{name}".replace("-", "_")
    return Step(
        name=name, method="GET", path=f"{_CSRF}?form=step-up",
        pre_script=[*require_env_url(_LANE, f"{_CSRF}?form=step-up", _LANE_WHY), *_src_pre(p),
                    *_with_cookies(("kaname_form", p + "FormCookie"))],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            *_status_is(200, label),
            *_parse_body(),
            _set(var, "__j.csrfToken || ''"),
            f"const __last = parseInt({_env('akCLastStep')} || '0', 10);",
            f"const __n = parseInt({_env(polls)} || '0', 10);",
            "const __ready = Math.floor(Date.now() / 30000) + 1 >= __last + 1 && (Date.now() % 30000) < 25000;",
            f"pm.test({js_str(label + ': ступень кода в окне либо ожидание в пределе')}, () => pm.expect(__ready || __n < 140).to.eql(true));",
            "if (!__ready && __n < 140) {",
            "  " + _set(polls, "String(__n + 1)"),
            "  const _akw = Date.now(); while (Date.now() - _akw < 500) { /* ступень кода по времени ещё не сменилась */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(polls)});",
        ])


def _step_up_refused(label):
    return [
        *_status_is(401, label),
        f"pm.test({js_str(label + ': единый отказ предъявления — тело равно отказу неверному паролю')}, () => "
        f"pm.expect(pm.response.text() === {_env('akF13RefusedBody')}).to.eql(true));",
        *_no_cookies(label),
    ]


def _inside(p, tag, session_var, level, *, reuse_code=False):
    """Ф13-17 в одной сессии: (а) код по времени, (в) неверный код, (б) пароль.

    `reuse_code` — код (а) тот, что отверг вход ключом с полем `secondFactor`
    (Ф13-16): он не потреблён, и церемония его принимает."""
    up = tag.upper()
    last = p + tag.replace("-", "") + "Last"
    code_pre = [] if reuse_code else _totp_code("akCTotpCode")
    return [
        _current_session(p, f"{tag}-before", session_var, [_set(last, "(_akCur && _akCur.lastPresentedAt) || ''")]),
        (_tok(p, f"{tag}-step-tok", "step-up", f"{p}Up", session=session_var) if reuse_code
         else _await_fresh_step(p, f"{tag}-step-tok", f"{p}Up")),
        _step_up(p, f"{tag}-a-totp", session_var, {"method": "totp", "code": "{{akCTotpCode}}", "csrfToken": "{{" + p + "Up}}"},
                 pre=[*code_pre, *_tick_past(last)],
                 tests=[*_stepped_up(p, f"{up}-A-TOTP", session_var, level), _TOTP_ACCEPTED]),
        _probe(p, f"{tag}-a-old-bearer-ended", session_var + "Old", alive=False),
        _current_session(p, f"{tag}-a-presented-moved", session_var, [
            f"pm.test({js_str(up + '-A: момент последнего предъявления сдвинут')}, () => "
            f"pm.expect(!!_akCur && Date.parse(_akCur.lastPresentedAt) > Date.parse({_env(last)} || '')).to.eql(true));",
        ]),
        _tok(p, f"{tag}-c-tok", "step-up", f"{p}Up", session=session_var),
        _step_up(p, f"{tag}-c-wrong-totp", session_var, {"method": "totp", "code": "{{akCTotpWrong}}", "csrfToken": "{{" + p + "Up}}"},
                 pre=_totp_code("akCTotpWrong", wrong=True), tests=_step_up_refused(f"{up}-C-WRONG-TOTP")),
        _probe(p, f"{tag}-c-bearer-still-valid", session_var, alive=True),
        _step_up(p, f"{tag}-b-password", session_var,
                 {"method": "password", "password": "{{" + _C + "Password}}", "csrfToken": "{{" + p + "Up}}"},
                 tests=_stepped_up(p, f"{up}-B-PASSWORD", session_var, level)),
    ]


CASES.append(Case(
    id="IAM-AKLOGIN-OK-SECOND-FACTOR-AND-KEY-SESSIONS",
    title="Ф13-16, Ф13-17: secondFactor у входа ключом — 400 и код не потрачен; церемонии в сессиях «3» и «2» уровня не меняют",
    classes=["NEG", "SEC", "CRUD"],
    priority="P1",
    steps=[
        *_login(_C, "f13-17-relogin"),
        _tok(_C, "f13-17-enroll-tok", "second-factor", "akC17Sf", session=_C + "SessionCookie", init=_fresh_src(_C)),
        _lane(_C, "f13-17-enroll", "POST", _SF_ENROLL, body={"csrfToken": "{{akC17Sf}}"}, session=_C + "SessionCookie", tests=[
            *_status_is(200, "F13-17-ENROLL"),
            *_parse_body(),
            "pm.test('F13-17-ENROLL: секрет base32 выдан', () => pm.expect(/^[A-Z2-7]{16,}$/.test(String(__j.secret || ''))).to.eql(true));",
            _set("akCTotpSecret", "__j.secret || ''"),
            "pm.environment.unset('akCLastStep');",
        ]),
        _lane(_C, "f13-17-confirm", "POST", _SF_CONFIRM, body={"code": "{{akCTotpCode}}", "csrfToken": "{{akC17Sf}}"},
              session=_C + "SessionCookie", pre=_totp_code("akCTotpCode"),
              tests=[*_status_is(200, "F13-17-CONFIRM"), _TOTP_ACCEPTED,
                     *_capture_cookie(_C, "kaname_session", "SessionCookie", "F13-17-CONFIRM", required=False)]),
        # Ф13-16: поле `secondFactor` с ВЕРНЫМ кодом — отказ формы до сверки; тот
        # же запрос без поля проходит; код после этого принимает церемония.
        _await_fresh_step(_C, "f13-16-step", "akC16Unused"),
        _tok(_C, "f13-16-begin-tok", "access-key-begin", "akC16Begin", fresh=True, init=_fresh_src(_C)),
        _begin(_C, "f13-16-begin", "akLc16", "akC16Begin"),
        _tok(_C, "f13-16-key-tok", "access-key-login", "akC16Key"),
        _key_login(_C, "f13-16-second-factor-field", slot="C1", ch="akLc16", tok="akC16Key", handle=_C + "Handle",
                   pre=_totp_code("akCTotpCode"),
                   extra_js="{ secondFactor: { method: 'totp', code: pm.environment.get('akCTotpCode') } }",
                   tests=_field_refused("F13-16-SECOND-FACTOR-FIELD", "secondFactor", "unknown field")),
        _key_login(_C, "f13-16-without-field", slot="C1", ch="akLc16", tok="akC16Key", handle=_C + "Handle",
                   tests=_signed_in(_C, "F13-16-WITHOUT-FIELD", "C1", "akC17S3", "3", user_var=_C + "UserId")),
        *_inside(_C, "f13-17-s3", "akC17S3", "3", reuse_code=True),
        *_key_session(_CB, "f13-17-s2", "akC17S2", "2", _UP),
        *_inside(_CB, "f13-17-s2", "akC17S2", "2"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-19, Ф13-22, Ф13-23: личность без пароля (посев, приставка `f13Person`).
# Ключ F1 — посеянный; токен человека выковывается церемонией из сессии,
# выданной КЛЮЧОМ: это и есть «Дано» Ф13-23, до Ф13 не строимое ничем.
# ───────────────────────────────────────────────────────────────────────────
_F13_PERSON_WHY = ("посев личностей с ключом (`stand-chart.sh seed-stored-value` → "
                   "`tests/authz-fixtures/seed_key_person.py`, приставка `f13Person`) не исполнялся на "
                   "этом стенде — личности без пароля нет")


def _f13_person_present():
    return [
        "if (!pm.environment.get('f13PersonEmail') || !pm.environment.get('f13PersonCredentialId') "
        "|| !pm.environment.get('f13PersonUserHandle')) {",
        *precondition_not_met("«Дано» полосы «личность без пароля»: f13PersonEmail, f13PersonCredentialId, "
                              "f13PersonUserHandle заданы", "ключи пусты — " + _F13_PERSON_WHY, indent="  "),
        "}",
    ]


def _f13_person_given():
    """«Дано» и стартовые величины строки посева: счётчик ключа — ноль регистрации."""
    return [
        *_f13_person_present(),
        _set(_F + "Email", "pm.environment.get('f13PersonEmail') || ''"),
        _set(_F + "Handle", "pm.environment.get('f13PersonUserHandle') || ''"),
        _set("akF1CredId", "pm.environment.get('f13PersonCredentialId') || ''"),
        _set("akF1Mat", f"'{_MAT_MAIN}'"),
        _set("akF1Count", "'0'"),
        _set(_F + "MailSeen", "'0'"),
        _set(_F + "RecoverySeen", "'0'"),
    ]


def _f13_sign_in(tag, slot, session_var, *, init=()):
    up = tag.upper()
    return [
        _tok(_F, f"{tag}-begin-tok", "access-key-begin", f"f13{tag.replace('-', '')}B", fresh=True,
             init=[*init, *_fresh_src(_F)]),
        _begin(_F, f"{tag}-begin", f"akLf{tag.replace('-', '')}", f"f13{tag.replace('-', '')}B"),
        _tok(_F, f"{tag}-key-tok", "access-key-login", f"f13{tag.replace('-', '')}K"),
        _key_login(_F, f"{tag}-key-login", slot=slot, ch=f"akLf{tag.replace('-', '')}", tok=f"f13{tag.replace('-', '')}K",
                   handle=_F + "Handle", tests=[
                       *_signed_in(_F, f"{up}-KEY-LOGIN", slot, session_var, "3"),
                       f"if (__j.user && __j.user.id) {{ {_set(_F + 'UserId', '__j.user.id')} }}",
                   ]),
    ]


CASES.append(Case(
    id="IAM-AKLOGIN-OK-PASSWORDLESS-PERSON",
    title="Ф13-19, Ф13-22, Ф13-23: без пароля — ключом входит, паролем единый отказ; последний ключ не снимается; новый ключ из сессии ключа",
    classes=["CRUD", "NEG", "SEC"],
    priority="P0",
    steps=[
        # Ф13-19 (а): ключ достаточен — первая сессия такой личности.
        *_f13_sign_in("f13-19a", "F1", _F + "SessionCookie", init=_f13_person_given()),
        # Ф13-19 (б): пароля нет, полоса пароля этого не раскрывает.
        _tok(_F, "f13-19b-login-tok", "login", "f13Pw"),
        _password_login(_F, "f13-19b-password-login", _F, "f13Pw", password="any-password-{{runId}}",
                        tests=_signin_refused("F13-19B-PASSWORD-LOGIN")),
        # Токен человека — церемонией из сессии, выданной ключом.
        _authorize(_F, "f13-23-authorize"),
        _exchange(_F, "f13-23-exchange"),
        _list(_F, "f13-22a-one-key", count=1, extra=[
            "if (_akL.length === 1) { " + _set("akF1KeyId", "_akL[0].id") + " }",
            "pm.test('F13-22A-ONE-KEY: ключ посева назван платформенным id', () => "
            "pm.expect(_akL.length === 1 && /^ak-[0-9a-hjkmnp-tv-z]{17}$/.test(String(_akL[0].id))).to.eql(true));",
        ]),
        # Ф13-22 (а): единственный ключ без второго способа не снимается.
        _revoke(_F, "f13-22a-revoke-only-key", "F1",
                tests=_refused(400, 9, "F13-22A-REVOKE-ONLY-KEY", reason=_LAST_METHOD[0], text=_LAST_METHOD[1])),
        _list(_F, "f13-22a-key-kept", count=1, extra=_key_listed("F1", "F13-22A-KEY-KEPT")),
        *_f13_sign_in("f13-22a-still", "F1", "f13Still"),
        # Ф13-23: из сессии, выданной ключом, — церемония НОВОГО ключа (окно
        # свежести открыто входом ключом выше).
        _begin_registration(_F, "f13-23-begin", "F2", tests=[
            "pm.test('F13-23-BEGIN: рукоятка — та же случайная величина человека', () => "
            f"pm.expect([!!{_env(_F + 'Handle')}, String((__j.user && __j.user.id) || '').split('+').join('-')"
            f".split('/').join('_').split('=').join('') === {_env(_F + 'Handle')}]).to.eql([true, true]));",
        ]),
        _finish_registration(_F, "f13-23-finish", slot="F2", ch="akRegChF2", key=_MAT_SECOND,
                             tests=_registration_accepted("F2", "F13-23-FINISH")),
        _await_op(_F, "f13-23-op", "F2", tests=_key_registered("F2", "F13-23-OP", _MAT_SECOND)),
        _list(_F, "f13-23-two-keys", count=2, extra=[*_key_listed("F1", "F13-23-TWO-KEYS"),
                                                     *_key_listed("F2", "F13-23-TWO-KEYS")]),
        *_f13_sign_in("f13-23-new-key", "F2", "f13NewKey"),
        *_f13_sign_in("f13-23-old-key", "F1", "f13OldKey"),
        # Ф13-22 (б): из двух ключей один снимается; вход оставшимся проходит.
        _revoke(_F, "f13-22b-revoke-one-of-two", "F2", tests=_registration_accepted("F2R", "F13-22B-REVOKE")),
        _await_op(_F, "f13-22b-revoke-op", "F2R"),
        _list(_F, "f13-22b-one-left", count=1, extra=_key_listed("F1", "F13-22B-ONE-LEFT")),
        *_f13_sign_in("f13-22b-remaining", "F1", "f13Remaining"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-25: личность без пароля, утратившая ключ, возвращает доступ
# восстановлением и заводит новый ключ. Ключ F1 «утерян»: проба им больше не
# входит, кроме последнего шага — снятый ключ отвергнут.
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-OK-RECOVERY-OF-PASSWORDLESS-PERSON",
    title="Ф13-25: восстановление заводит пароль, вход им «1», новый ключ, снятие утраченного — им единый отказ, новым вход",
    classes=["CRUD", "SEC"],
    priority="P1",
    steps=[
        _tok(_F, "f13-25-recovery-tok", "recovery", "f13Rec", fresh=True, init=[*_f13_person_present(), *_fresh_src(_F)]),
        _lane(_F, "f13-25-recovery", "POST", _RECOVERY, body={"email": "{{f13Email}}", "csrfToken": "{{f13Rec}}"},
              tests=[*_status_is(200, "F13-25-RECOVERY"),
                     # Тело — шаг Ф5 Р10 п. 1 (kaname#211), одно на все исходы.
                     "pm.test('F13-25-RECOVERY: тело называет шаг (Ф5 Р10 п. 1)', () => "
                     f"pm.expect(pm.response.text()).to.eql({js_str(_RECOVERY_NEXT_STEP_BODY)}));"]),
        _await_letter(_F, "f13-25-letter", head=_HEAD_RECOVERY, seen="RecoverySeen", code="RecoveryCode",
                      kind="восстановления"),
        _tok(_F, "f13-25-complete-tok", "recovery-complete", "f13RecDone"),
        _lane(_F, "f13-25-complete", "POST", _RECOVERY_COMPLETE,
              body={"email": "{{f13Email}}", "code": "{{f13RecoveryCode}}", "newPassword": "{{f13Password}}",
                    "csrfToken": "{{f13RecDone}}"},
              pre=[_set(_F + "Password", f"'Rec-' + Math.floor(Math.random() * 2176782336).toString(36) + '-' + {_env('runId')} + '-pw'")],
              tests=[*_status_is(200, "F13-25-COMPLETE"),
                     *_capture_cookie(_F, "kaname_session", "SessionCookie", "F13-25-COMPLETE")]),
        _tok(_F, "f13-25-login-tok", "login", "f13PwLogin", fresh=True),
        _password_login(_F, "f13-25-password-login", _F, "f13PwLogin",
                        tests=_password_signed_in(_F, "F13-25-PASSWORD-LOGIN", _F + "SessionCookie")),
        _authorize(_F, "f13-25-authorize"),
        _exchange(_F, "f13-25-exchange"),
        *_register_key(_F, "f13-25-new-key", "F3", key=_MAT_SECOND),
        _revoke(_F, "f13-25-revoke-lost-key", "F1", tests=_registration_accepted("F1R", "F13-25-REVOKE-LOST-KEY")),
        _await_op(_F, "f13-25-revoke-lost-key-op", "F1R"),
        _tok(_F, "f13-25-begin-tok", "access-key-begin", "f1325B", fresh=True, init=_fresh_src(_F)),
        _begin(_F, "f13-25-begin", "akLf1325", "f1325B"),
        _tok(_F, "f13-25-key-tok", "access-key-login", "f1325K"),
        _key_login(_F, "f13-25-lost-key-refused", slot="F1", ch="akLf1325", tok="f1325K", handle=_F + "Handle",
                   tests=_signin_refused("F13-25-LOST-KEY-REFUSED")),
        *_f13_sign_in("f13-25-new-key-login", "F3", "f13AfterRecovery"),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Ф13-21: снятие ключа гасит ПРОЧИЕ сессии человека причиной
# `access-key-revoked`; текущая — сессия, в которой выпущен токен снимающего
# (выпуск → семейство → сессия церемонии), — остаётся (Р8, kaname#669). S2 —
# вход паролем и токен собственного фронта; S1 — вход ключом A во втором
# «браузере». Вторая ветвь оси: снят НЕ ключ сессии, а другой — сессия гаснет
# тоже. Причина конца записи наружу полосы не выходит — её держат пробы службы
# (`access_key_revoke_ends_sessions_integration_test.go`).
# ───────────────────────────────────────────────────────────────────────────
def _key_session_of(p, tag, slot, session_var):
    up = tag.upper()
    t = tag.replace("-", "")
    return [
        _tok(p, f"{tag}-begin-tok", "access-key-begin", f"{p}{t}B", fresh=True, init=_fresh_src(p)),
        _begin(p, f"{tag}-begin", f"akLc{t}", f"{p}{t}B"),
        _tok(p, f"{tag}-key-tok", "access-key-login", f"{p}{t}K"),
        _key_login(p, f"{tag}-key-login", slot=slot, ch=f"akLc{t}", tok=f"{p}{t}K", handle=_C + "Handle",
                   tests=_signed_in(p, f"{up}-KEY-LOGIN", slot, session_var, "3", user_var=_C + "UserId")),
    ]


CASES.append(Case(
    id="IAM-AKLOGIN-SEC-REVOKE-ENDS-OTHER-SESSIONS",
    title="Ф13-21: снятие ключа гасит прочие сессии человека, текущая жива; снятый ключ не входит, другой входит",
    classes=["SEC", "CRUD"],
    priority="P0",
    steps=[
        *_login(_C, "f13-21"),
        *_register_key(_C, "f13-21-a", "C21"),
        *_key_session_of(_CB, "f13-21-s1", "C21", "akC21S1"),
        # Положительный контроль: до снятия оба носителя годны.
        _probe(_CB, "f13-21-s1-alive-before", "akC21S1", alive=True),
        _probe(_C, "f13-21-s2-alive-before", _C + "SessionCookie", alive=True),
        _revoke(_C, "f13-21-revoke-a", "C21", tests=_registration_accepted("C21R", "F13-21-REVOKE-A")),
        _await_op(_C, "f13-21-revoke-a-op", "C21R"),
        _probe(_CB, "f13-21-s1-ended", "akC21S1", alive=False),
        _probe(_C, "f13-21-s2-current-alive", _C + "SessionCookie", alive=True),
        # Ключ A — единый отказ входа; ключ C1 входит.
        _tok(_CB, "f13-21-revoked-begin-tok", "access-key-begin", "akCb21RB", fresh=True, init=_fresh_src(_CB)),
        _begin(_CB, "f13-21-revoked-begin", "akLc21R", "akCb21RB"),
        _tok(_CB, "f13-21-revoked-key-tok", "access-key-login", "akCb21RK"),
        _key_login(_CB, "f13-21-revoked-key", slot="C21", ch="akLc21R", tok="akCb21RK", handle=_C + "Handle",
                   tests=_signin_refused("F13-21-REVOKED-KEY")),
        *_key_session_of(_CB, "f13-21-s3", "C1", "akC21S3"),
        # Вторая ветвь оси: снят другой ключ — сессия, выданная C1, гаснет тоже.
        *_register_key(_C, "f13-21-b", "C21b"),
        _revoke(_C, "f13-21-revoke-b", "C21b", tests=_registration_accepted("C21bR", "F13-21-REVOKE-B")),
        _await_op(_C, "f13-21-revoke-b-op", "C21bR"),
        _probe(_CB, "f13-21-s3-ended", "akC21S3", alive=False),
        _probe(_C, "f13-21-s2-still-alive", _C + "SessionCookie", alive=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# Уборка блока Ф13: ключи, заведённые набором, сняты; у личности посева
# остаётся только ключ, заведённый Ф13-25 (без него у неё не было бы способа
# входа ключом, а пароль ей завело восстановление).
# ───────────────────────────────────────────────────────────────────────────
CASES.append(Case(
    id="IAM-AKLOGIN-OK-CLEANUP-KEYS",
    title="Уборка Ф13: ключи людей C и D сняты, перечни пусты",
    classes=["CRUD"],
    priority="P2",
    steps=[
        *_login(_C, "f13-cleanup-c-login"),
        _revoke(_C, "f13-cleanup-c1", "C1", tests=_registration_accepted("C1C", "F13-CLEANUP-C1")),
        _await_op(_C, "f13-cleanup-c1-op", "C1C"),
        _list(_C, "f13-cleanup-list-c", count=0),
        *_login(_D, "f13-cleanup-d-login"),
        _revoke(_D, "f13-cleanup-d1", "D1", tests=_registration_accepted("D1C", "F13-CLEANUP-D1")),
        _await_op(_D, "f13-cleanup-d1-op", "D1C"),
        _list(_D, "f13-cleanup-list-d", count=0),
    ],
))


CASES = address_own_front(CASES, _OWN_WHY)
