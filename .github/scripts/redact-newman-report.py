#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ЧИСТКА ОТЧЁТА ПРОГОНА ПЕРЕД ВЫКЛАДЫВАНИЕМ В АРТЕФАКТ ПУБЛИЧНОГО РЕПОЗИТОРИЯ.

ПРЕДМЕТ И ЦЕНА, КОТОРАЯ УЖЕ УПЛАЧЕНА. Артефакт прогона публичного репозитория
скачивается кем угодно по ссылке и живёт до истечения срока хранения. Машинный
отчёт newman несёт ОКРУЖЕНИЕ ПРОГОНА ЦЕЛИКОМ — то есть все удостоверения,
которые посев в него записал. Артефакт `own-front-newman-report` (53 104 байта)
нёс 51 вхождение строк вида JWT, включая четыре посеянных предъявителя; он удалён
руками, но производил его КОД, и правило публичных артефактов не про срок
годности удостоверения, а про то, что выложенное ОПУБЛИКОВАНО.

ВЫБОР: ЧИСТКА, А НЕ СВОДКА. Сводка (выложить только `summary.txt`) дешевле и
безопаснее by construction, но теряет РАЗБОР ПАДЕНИЙ — тело ответа, код, текст
утверждения, — а артефакт затем и нужен, что на красном по сводке не починить
ничего. Чистка дороже ровно тем, что обязана знать ВСЕ формы, в которых отчёт
несёт удостоверение. Поэтому она устроена не перечнем позиций, а ОБХОДОМ ВСЕГО
документа: неизвестная форма покрывается построением, а не списком.

ФОРМЫ ЗАМЕРЕНЫ, А НЕ ПРЕДПОЛОЖЕНЫ — ИХ ВОСЕМЬ: семь ПОЗИЦИЙ отчёта и одна форма
ВНУТРИ позиции (тело, которое само есть JSON). Замер: синтетический прогон newman
6.2.2 с маркерами в каждой позиции (окружение · заголовок запроса · заголовок
ответа · тело запроса · параметр адреса · тело ответа · литерал в скрипте) и
обход отчёта с печатью пути каждого вхождения:

    newman run col.json -e env.json --reporters json \
      --reporter-json-export report.json
    # затем обход report.json с печатью json-пути каждого маркера

  1 `environment.values[].value` и `globals.values[].value` — окружение целиком:
    и то, что записал посев, и то, что дописали скрипты коллекции;
  2 `run.executions[].request.header[].value` — `Authorization`,
    `X-Kacho-Hook-Token`, `X-Api-Token` КАЖДОГО запроса;
  3 `run.executions[].response.header[].value` — `Set-Cookie` каждого ответа;
  4 `request.body.raw` — ТРИ позиции на один запрос
    (`collection.item[]`, `run.executions[].item`, `run.executions[].request`);
  5 `request.url.query[].value` и `url.raw` — удостоверение в параметре адреса;
  6 `run.executions[].response.stream` — ТЕЛО ОТВЕТА БАЙТОВЫМ МАССИВОМ
    (`{"type":"Buffer","data":[123,34,…]}`). Это самая опасная форма: ТЕКСТОВЫЙ
    ГРЕП ЕЁ НЕ ВИДИТ ВООБЩЕ. Замер «51 вхождение» получен текстовым предикатом,
    значит он НЕ СЧИТАЛ тела ответов — утечка была шире названного числа;
  7 `collection.item[].event[].script.exec[]` — литерал, вписанный в скрипт
    коллекции (и его копия в `run.executions[].item`);
  8 ТЕЛО (4 и 6), КОТОРОЕ САМО ЕСТЬ JSON, — секрет стоит ПОД ИМЕНЕМ КЛЮЧА внутри
    текста, а формы у значения нет: `response.secret` у `SAKeyService.Issue`
    вида SECRET (строка показывается один раз) и `nextPageToken` списков. Обход
    узлов отчёта имён внутри строки не видит by construction, поэтому такое тело
    разбирается и судится теми же правилами — по имени и по форме. Захвачено на
    автономном стенде (задача #19): два остатка в 47 файлах, оба этой формы.

ЧТО ОСТАЁТСЯ. Имена ключей, имена заголовков, пути запросов, коды, тексты
утверждений, числа и времена — то есть РАЗБОР ПАДЕНИЯ. Чистка, съедающая имя
ключа, неотличима от удаления файла, и проба требует обратного прямо.

ИСХОДЫ:
    0  — вычищено, и ОСТАТОК ПРОВЕРЕН: повторный обход выхода не нашёл ничего;
    1  — остаток найден (чистка неполна) либо обход пуст: «ноль находок» при
         нулевом прочитанном неотличимо от чистого файла.

ОСТАТОК НАЗЫВАЕТСЯ ПУТЁМ, А НЕ ЗНАЧЕНИЕМ. Отказ, печатающий недочищенное
удостоверение, публикует его в журнал прогона — то есть туда же, откуда его
убирали.

САМОПРОВЕРКА — `--self-test`: по одной оси на каждую из восьми форм, законный
близнец рядом (идентификатор, адрес, текст утверждения обязаны выжить), ось
ОДНОГО КРИТЕРИЯ (всё, что проверка выхода назовёт удостоверением, срез срезает;
срез отключён — проверка отказывает), пустой обход обязан дать отказ.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import NamedTuple

# ── ПРЕДИКАТ ФОРМЫ ЗНАЧЕНИЯ ──────────────────────────────────────────────────
#
# Два независимых предиката, объединённых: по ФОРМЕ значения и по ИМЕНИ ключа.
# Ни один не покрывает другого. Форма ловит удостоверение в позиции без имени
# (тело ответа, текст утверждения); имя ловит секрет, у которого формы нет вовсе
# — общий секрет хука `stand-hook-secret-0123456789` не отличим от слова.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                    re.DOTALL)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")

# Имя ключа/заголовка/параметра, чьё значение есть удостоверение. Регистр не
# значим: заголовки приходят и `Authorization`, и `authorization`.
#
# `csrf`/`xsrf` — признак формы, привязанный к контексту входа: с печеньем
# контекста он и есть право отправить форму от имени человека. Захвачено в
# прогоне 35895962909: `loginLaneCsrfLogin` и `loginLaneCsrfLogout` перечень не
# знал, а `loginLaneCsrfPassword` резался только потому, что в имени стоит
# `password`, — то есть случайно.
SECRET_NAME_RE = re.compile(
    r"(?i)(jwt|token|secret|password|passwd|apikey|api[-_]?key|assertion|"
    r"credential|bearer|authorization|privatekey|private[-_]?key|keypem|"
    r"key[-_]?pem|cookie|signature|clientsecret|csrf|xsrf)")


def _named_secret(key_hint: str | None) -> bool:
    """Имя называет значение секретом? ОДИН предикат для среза и для проверки
    выхода: разойдись они здесь — срез оставил бы то, что проверка назовёт."""
    return bool(key_hint) and SECRET_NAME_RE.search(key_hint) is not None

REDACTED = "«ВЫРЕЗАНО ПЕРЕД ПУБЛИКАЦИЕЙ»"

# ПАРАМЕТР АДРЕСА ВНУТРИ ЦЕЛЬНОЙ СТРОКИ. Форма 5 живёт в отчёте ДВАЖДЫ: разобранным
# `url.query[].value` (у него есть имя, и он чистится по имени) и цельной строкой
# `url.raw`, у которой имени нет вовсе. Замер на выложенном отчёте: значение
# `pageToken` вырезано в двух разобранных узлах и ОСТАЛОСЬ читаемым в `url.raw` тех
# же двух запросов. Для `pageToken` цена нулевая, но непрозрачное удостоверение без
# формы JWT прошло бы там же и по той же причине: предикат формы его не видит, а
# имени у строки нет. Поэтому имя берётся из САМОЙ строки — из ключа параметра.
QUERY_SECRET_RE = re.compile(
    r"(?i)([?&][A-Za-z0-9_.\[\]-]*"
    r"(?:token|secret|key|assertion|password|passwd|jwt|credential|signature|csrf|xsrf)"
    r"[A-Za-z0-9_.\[\]-]*=)([^&\s\"'<>]+)")

# ВИДЫ ФАЙЛОВ, КОТОРЫЕ ЧИСТКА БЕРЁТСЯ ПРОЧЕСТЬ. Перечень, а не «всё подряд»:
# двоичный файл, вычищенный как текст, портится молча, и судить его содержимое всё
# равно нечем. Файл незнакомого вида НЕ КОПИРУЕТСЯ в каталог выкладывания вовсе —
# то есть пропуск здесь fail-closed, — но НАЗЫВАЕТСЯ в переписи: тихо выпавший из
# артефакта файл и вычищенный файл ведут читателя в разные места.
TEXT_SUFFIXES = (".json", ".cli", ".txt", ".rc", ".log")


def shaped_credential(text: str) -> str | None:
    """Форма значения выдаёт удостоверение? Возвращает имя формы или None."""
    if JWT_RE.search(text):
        return "вид JWT"
    if PEM_RE.search(text):
        return "приватный ключ PEM"
    if BEARER_RE.search(text):
        return "предъявление Bearer"
    return None


class Scrubbed(NamedTuple):
    """Итог среза по форме: текст и сколько вырезано — видовыми предикатами и
    критерием проверки выхода. `by_criterion` печатается отдельной строкой
    переписи: это цена ложной находки критерия, и она обязана быть видна."""
    text: str
    by_kind: int
    by_criterion: int

    @property
    def cut(self) -> int:
        return self.by_kind + self.by_criterion


def scrub_text(text: str) -> Scrubbed:
    """Вырезать удостоверения ИЗ ТЕКСТА, оставив остальное.

    Видовые предикаты (PEM, JWT, Bearer, параметр адреса) режут первыми: у них
    есть что сохранить — имя параметра, слово `Bearer`. Последним режет
    КРИТЕРИЙ ПРОВЕРКИ ВЫХОДА (`credential_spans`), тот же объект, которым
    судит `residue`: всё, что проверка назовёт удостоверением, срез срезает, и
    расхождения «проверка знает форму, срез — нет» не бывает по построению.
    """
    n = 0

    def sub(pattern: "re.Pattern[str]", src: str) -> str:
        nonlocal n

        def one(m: "re.Match[str]") -> str:
            nonlocal n
            n += 1
            return REDACTED
        return pattern.sub(one, src)

    out = sub(PEM_RE, text)
    out = sub(JWT_RE, out)
    out = sub(BEARER_RE, out)

    # Имя параметра ОСТАЁТСЯ, вырезается только значение: `?access_token=<…>`
    # читается как координата отказа, а `?<…>` — уже нет.
    def one_param(m: "re.Match[str]") -> str:
        nonlocal n
        n += 1
        return m.group(1) + REDACTED
    out = QUERY_SECRET_RE.sub(one_param, out)
    out, k = _cut_by_criterion(out)
    return Scrubbed(out, n, k)


class Census:
    """Перепись обхода. Печатается ВСЕГДА: «ноль вырезанного» обязано быть
    отличимо от «ноль прочитанного»."""

    def __init__(self) -> None:
        self.nodes = 0
        self.strings = 0
        self.buffers = 0
        self.redacted_by_name = 0
        self.redacted_by_shape = 0
        # Часть `redacted_by_shape`, срезанная критерием проверки выхода.
        self.redacted_by_criterion = 0
        self.files = 0

    def add(self, s: Scrubbed) -> None:
        self.redacted_by_shape += s.cut
        self.redacted_by_criterion += s.by_criterion

    @property
    def redacted(self) -> int:
        return self.redacted_by_name + self.redacted_by_shape


def _embedded_json(text: str) -> object | None:
    """Текст, который сам есть JSON-объект или массив, — иначе None.

    ФОРМА 8: ТЕЛО ЗАПРОСА И ТЕЛО ОТВЕТА — ТЕКСТ, А ВНУТРИ ТЕКСТА ЕСТЬ ИМЕНА.
    Обход узлов отчёта видит имя ключа только у УЗЛА (`{"key": …, "value": …}`,
    поле словаря); имя внутри строки тела ему невидимо by construction, и тело
    резалось только по ФОРМЕ значения. У отчеканенной строки секрета формы нет
    (`credsecret.Mint`: ни `eyJ`, ни точек, ни `Bearer`), поэтому
    `SAKeyService.Issue` вида SECRET уезжал в артефакт с `response.secret`
    целиком — и то же с `nextPageToken` списков. Захвачено на автономном стенде
    (задача #19): два остатка в 47 файлах, оба — тело ответа, оба под именем,
    которое узел отчёта уже режет, когда оно стоит в заголовке или параметре.

    Разбирается ТОЛЬКО объект или массив: голая строка в кавычках и число телом
    не являются, и «вычищенное» число ничем не отличалось бы от исходного.
    """
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _scrub_body(text: str, c: Census) -> str:
    """Вычистить ТЕКСТ тела: JSON — по именам И по форме, иначе — по форме.

    Возвращает текст; сколько вырезано, считает перепись — по имени либо по
    форме, ровно как у узлов отчёта. Тело, разобранное как JSON, собирается
    обратно ТОЛЬКО если из него что-то вырезано: иначе байты остаются исходными,
    и «вычищенный» файл не отличается от исходного ничем, кроме вырезанного.
    """
    parsed = _embedded_json(text)
    if parsed is not None:
        before = c.redacted
        cleaned = _walk(parsed, None, c)
        if c.redacted != before:
            return json.dumps(cleaned, ensure_ascii=False)
        return text
    s = scrub_text(text)
    c.add(s)
    return s.text


def _walk(node: object, key_hint: str | None, c: Census) -> object:
    """Обойти ВЕСЬ документ. Перечня позиций здесь нет намеренно: неизвестная
    форма покрывается обходом, а перечень разошёлся бы с newman молча."""
    c.nodes += 1
    if isinstance(node, dict):
        # Форма `{"key": …, "value": …}` — окружение, заголовок, параметр адреса.
        # Имя ключа остаётся, значение чистится ПО ИМЕНИ, даже если формы нет.
        name = node.get("key") if isinstance(node.get("key"), str) else None
        # Байтовый массив: декодировать → вычистить → собрать обратно. Без этого
        # тело ответа уезжает в артефакт целиком, и текстовый греп его не видит.
        if node.get("type") == "Buffer" and isinstance(node.get("data"), list):
            c.buffers += 1
            try:
                raw = bytes(int(b) & 0xFF for b in node["data"]).decode("utf-8", "replace")
            except (TypeError, ValueError):
                return node
            clean = _scrub_body(raw, c)
            if clean != raw:
                return {"type": "Buffer", "data": list(clean.encode("utf-8"))}
            return node
        out: dict = {}
        for k, v in node.items():
            hint = name if (k == "value" and name) else (k if isinstance(k, str) else None)
            out[k] = _walk(v, hint, c)
        return out
    if isinstance(node, list):
        return [_walk(v, key_hint, c) for v in node]
    if isinstance(node, str):
        c.strings += 1
        if _named_secret(key_hint) and node:
            c.redacted_by_name += 1
            return REDACTED
        # Строка, которая сама есть JSON (тело запроса `body.raw`), несёт имена
        # ВНУТРИ себя — форма 8, та же, что у байтового массива тела ответа.
        return _scrub_body(node, c)
    return node


def redact_document(doc: object, c: Census) -> object:
    return _walk(doc, None, c)


# ── КРИТЕРИЙ УДОСТОВЕРЕНИЯ: ОДИН ДЛЯ СРЕЗА И ДЛЯ ПОВТОРНОГО ОБХОДА ВЫХОДА ───
#
# КРИТЕРИЙ ГРУБЕЕ ВИДОВЫХ ПРЕДИКАТОВ: не «похоже на JWT нашей чеканки», а «в
# тексте стоит длинная непрерывная строка из алфавита секретов». Он не знает ни
# приставки `eyJ`, ни слова `Bearer` — и потому ловит форму, которой видовые
# предикаты не знают.
#
# ПРЕЖНЯЯ РЕДАКЦИЯ ДЕРЖАЛА ЕГО ТОЛЬКО У ПРОВЕРКИ, И ЭТО БЫЛ КЛАСС (kaname#183).
# Проверка знала пробег 40+ и тройку через точку, срез — нет; всё, что лежало
# между ними, превращало ЗЕЛЁНЫЙ прогон в невыложенный артефакт, и каждая
# следующая переменная без имени из перечня повторяла отказ. Захвачено: прогон
# 35895962909, два признака формы полосы входа по 43 знака, «вырезано по форме:
# 0». Поэтому критерий один, и им режет срез (`scrub_text`, последним шагом).
#
# ВТОРОЙ ВЗГЛЯД ОСТАЁТСЯ ВТОРЫМ — по ОБХОДУ, а не по критерию. Проверка читает
# ВЫХОД своим обходом, а не счётчики среза, и потому краснеет на сломанном или
# отключённом срезе. Это держится инъекцией: срез по форме отключён — отказ по
# остатку; видовые предикаты среза ослеплены — общий критерий срезает то же.
#
# ЦЕНА НАЗВАНА: критерий заведомо срабатывает на законной длинной строке
# (шестнадцатеричный отпечаток; идентификатор, где буква стоит вплотную к
# цифре). Исход такой находки теперь — ВЫРЕЗАННОЕ значение в выложенном
# артефакте, посчитанное отдельной строкой переписи. Это безопасно: срез не
# публикует ничего, и прежний исход того же входа — отказ выложить артефакт
# целиком — был строго хуже для разбора падения, ради которого артефакт и есть.

FORM_PEM = "приватный ключ PEM"
FORM_DOTTED = "тройка через точку с длинными частями"
FORM_OPAQUE = "непрерывный пробег алфавита секретов (40+, буквы и цифры)"

# Тройка, разделённая точками, с длинными частями: форма подписанного
# удостоверения БЕЗ знания его приставки. Границы длин выбраны так, чтобы имя
# файла (`kaname-own-rest-front.postman_collection.json`) под неё не подпадало.
DOTTED_TRIPLE_RE = re.compile(
    r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}")
DOTTED_TRIPLE_MIN = 60
# Непрерывный пробег алфавита секретов: непрозрачное удостоверение без точек.
LONG_OPAQUE_RE = re.compile(r"[A-Za-z0-9_-]{40,}")
DIGIT_RE = re.compile(r"[0-9]")
LETTER_RE = re.compile(r"[A-Za-z]")
# Буква ВПЛОТНУЮ к цифре — внутри сегмента без разделителя.
MIXED_ADJACENT_RE = re.compile(r"[A-Za-z][0-9]|[0-9][A-Za-z]")
# Разделители СОСТАВНОГО ИМЕНИ. У имени, построенного из слов, они часты; у
# base64url их два знака из шестидесяти четырёх, то есть на сорок знаков их
# ожидается 1,25.
NAME_SEPARATOR_RE = re.compile(r"[_-]")
# Длина сегмента, при которой пробег перестаёт быть похожим на составное имя.
# Величина ЗАМЕРЕНА: при 11 из дерева уходят ВСЕ 26 ложных находок, а потеря на
# 200 000 случайных пробегов base64url — 0 при длинах 40, 43 и 64.
OPAQUE_SEGMENT_LEN = 11
# Сколько букв КАЖДОГО регистра делает пробег плотным. Имя генератора несёт либо
# один регистр на всю строку, либо две-три заглавные внутри слов; у base64url на
# сорок знаков заглавных ожидается 16, строчных столько же.
OPAQUE_CASE_MIX = 4


def _opaque_run(run: str) -> bool:
    """Пробег 40+ (целиком, как его отдал `LONG_OPAQUE_RE`) ЕСТЬ удостоверение?
    Требуется смешение букв и цифр.

    ПОРОГ ОДНОЙ ДЛИНЫ НЕ РАБОТАЕТ, И ЭТО ЗАМЕР, А НЕ ОПАСЕНИЕ. Первая редакция
    считала удостоверением любой пробег 40+ и покраснела на ПЕРВОМ ЖЕ прогоне
    конвейера: в журнале службы стоит имя поля
    `catalog_entries_demanding_a_raised_floor` — ровно 40 знаков алфавита
    `[A-Za-z0-9_-]`, и ни одного из них секретом не делает ничто. Строка взята в
    самопроверку ниже ЗАКОННЫМ БЛИЗНЕЦОМ — та самая, из артефакта прогона
    34689147074, а не придуманная похожей.

    Что различает: у непрозрачного удостоверения алфавит смешан. Шанс, что в 40
    знаках base64url не встретится ни одной цифры, — около 0,25 %; имя поля и
    путь, напротив, цифр обычно не несут вовсе. Предикат поэтому требует И букву,
    И цифру, оставаясь независимым от ВИДОВЫХ предикатов (ни `eyJ`, ни `Bearer`).

    СМЕШЕНИЕ ТРЕБУЕТСЯ ВПЛОТНУЮ, А НЕ ГДЕ-НИБУДЬ В ПРОБЕГЕ — второй замер того же
    рода. Вторая редакция («есть буква и есть цифра») покраснела на идентификаторе
    кейса `NEG-G-02-catalog-anonymous-unauthenticated`: 42 знака алфавита, цифры в
    нём есть, — но стоят отдельным сегментом между дефисами. Строка захвачена из
    отчёта прогона коллекции каталога прав на автономном стенде (kacho#1814) и
    стоит в самопроверке законным близнецом рядом с одно-фактным отрицательным:
    тот же идентификатор с одним снятым дефисом (`02catalog`) — находка.

    У непрозрачного удостоверения буква и цифра соседствуют почти всегда, у
    составного идентификатора они разнесены разделителями. Цена уточнения
    ИЗМЕРЕНА, а не оценена: из 200 000 случайных пробегов base64url длиной ровно
    40 прежний предикат ловил 99,886 %, уточнённый — 99,883 % (теряется 6 из
    200 000); при длинах 40–64 — 1 из 200 000, при 64–128 — ноль. Потеря на два
    порядка меньше собственного промаха предиката (пробег без единой цифры).
    Самопроверка держит нижнюю границу на засеянной выборке, чтобы следующее
    сужение не прошло молча.

    СОСТАВНОЕ ИМЯ ОТЛИЧАЕТСЯ УСТРОЙСТВОМ, А НЕ ПРОИСХОЖДЕНИЕМ — третий замер
    того же рода. Третья редакция («есть смешение вплотную») краснела на именах,
    которые строит НАШ ЖЕ генератор: рабочий ключ опроса
    `_poll200_started_<имя шага>` при длинном имени шага переваливает за сорок
    знаков, а `poll200` даёт смешение вплотную. Замер по дереву: пробегов 40+ в
    коллекциях 79, помечались удостоверением 26 в восьми коллекциях — и ни одна
    из шести гоняемых сегодня коллекций такого имени не несёт, поэтому класс
    молчал, а каждая ПЕРЕЕЗЖАЮЩАЯ приносила бы отказ выложить артефакт на
    зелёном прогоне.

    Различает УСТРОЙСТВО строки: имя из слов несёт частые разделители (сегменты
    коротки) и один регистр либо почти один; base64url разделителя почти не
    содержит — два знака из шестидесяти четырёх — и смешивает регистры густо.
    Отсюда два признака, объединённых ИЛИ, и ни один не покрывает другого:
    длинный сегмент со смешением ловит удостоверение БЕЗ заглавных (крокфорд,
    шестнадцатеричный пробег), густое смешение регистров — плотное
    удостоверение, разорванное разделителями на короткие куски.

    ЦЕНА УТОЧНЕНИЯ ИЗМЕРЕНА И ОНА НУЛЕВАЯ: на 200 000 случайных пробегов
    base64url прежний и уточнённый предикаты ловят ПОРОВНУ — 99,8925 % при длине
    40, 99,9360 % при 43, 99,9970 % при 64; потеря 0 из 200 000 на каждой длине.
    Самопроверка держит нижнюю границу на засеянной выборке, а одно-фактные
    близнецы — на обоих признаках: снятый разделитель (сегмент стал длинным) и
    поднятый регистр одной буквы (заглавных стало четыре).

    ЦЕНА ОСТАЁТСЯ И НАЗВАНА: длинный шестнадцатеричный отпечаток (закреплённая
    ревизия, `sha256:` и 64 знака) под этот предикат подпадёт — сегмент длинный,
    буква соседствует с цифрой, — и ФОРМОЙ он неотличим от шестнадцатеричного
    секрета. Исход — отпечаток СРЕЗАН и посчитан строкой переписи; список
    прощённых не заводится, потому что каждая его запись — место, куда секрет
    проедет незамеченным.
    """
    if not MIXED_ADJACENT_RE.search(run):
        return False
    # ПРИЗНАК ПЕРВЫЙ: длинный сегмент со смешением. Ловит удостоверение,
    # у которого регистра нет вовсе (шестнадцатеричный пробег, крокфорд).
    if any(len(seg) >= OPAQUE_SEGMENT_LEN and MIXED_ADJACENT_RE.search(seg)
           for seg in NAME_SEPARATOR_RE.split(run)):
        return True
    # ПРИЗНАК ВТОРОЙ: густое смешение регистров. Ловит плотное удостоверение,
    # разорванное разделителями на короткие куски. Ни один признак не
    # покрывает другого — потому они и объединены, а не заменяют друг друга.
    uppers = sum(1 for c in run if c.isupper())
    lowers = sum(1 for c in run if c.islower())
    return uppers >= OPAQUE_CASE_MIX and lowers >= OPAQUE_CASE_MIX


def credential_spans(text: str) -> list[tuple[int, int, str]]:
    """КРИТЕРИЙ: где в тексте стоит удостоверение — (начало, конец, форма).

    Один объект на два потребителя: срез вырезает эти промежутки, проверка
    выхода называет их остатком. Порядок форм — порядок имени в отказе.
    """
    spans = [(m.start(), m.end(), FORM_PEM) for m in PEM_RE.finditer(text)]
    spans += [(m.start(), m.end(), FORM_DOTTED) for m in DOTTED_TRIPLE_RE.finditer(text)
              if len(m.group(0)) >= DOTTED_TRIPLE_MIN]
    spans += [(m.start(), m.end(), FORM_OPAQUE) for m in LONG_OPAQUE_RE.finditer(text)
              if _opaque_run(m.group(0))]
    return spans


def _cut_by_criterion(text: str) -> tuple[str, int]:
    """Вырезать всё, что критерий называет удостоверением. (текст, сколько).

    До НЕПОДВИЖНОЙ ТОЧКИ, а не одним проходом: срезанный промежуток мог
    заслонять собой другое совпадение (короткая тройка через точку, съевшая
    начало длинной). Цикл конечен: замена не несёт ни одного знака алфавита
    секретов, и с каждым проходом их строго меньше. Выход по построению чист
    для того же критерия, которым его судит проверка.
    """
    n = 0
    while True:
        spans = sorted((s, e) for s, e, _ in credential_spans(text))
        if not spans:
            return text, n
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        for s, e in reversed(merged):
            text = text[:s] + REDACTED + text[e:]
        n += len(merged)


def residue_shaped(text: str) -> str | None:
    """Проверка выхода по форме — тем же критерием, каким режет срез."""
    spans = credential_spans(text)
    return spans[0][2] if spans else None


def residue(node: object, path: str, found: list[str],
            key_hint: str | None = None) -> None:
    """Пути (НЕ значения!) мест, где удостоверение осталось."""
    if isinstance(node, dict):
        if node.get("type") == "Buffer" and isinstance(node.get("data"), list):
            try:
                raw = bytes(int(b) & 0xFF for b in node["data"]).decode("utf-8", "replace")
            except (TypeError, ValueError):
                raw = ""
            # Тело, разбираемое как JSON, судится ПО ИМЕНАМ внутри себя — второй
            # взгляд обязан видеть форму 8 сам, иначе ослепший разбор тела у
            # чистки прошёл бы молча. Неразбираемое тело судится по форме целиком.
            parsed = _embedded_json(raw)
            if parsed is not None:
                residue(parsed, f"{path}[байтовый массив, JSON]", found)
                return
            form = residue_shaped(raw)
            if form:
                found.append(f"{path}[байтовый массив] — {form}")
            return
        name = node.get("key") if isinstance(node.get("key"), str) else None
        for k, v in node.items():
            residue(v, f"{path}.{k}", found,
                    name if (k == "value" and name) else
                    (k if isinstance(k, str) else None))
        return
    if isinstance(node, list):
        for i, v in enumerate(node):
            residue(v, f"{path}[{i}]", found, key_hint)
        return
    if isinstance(node, str):
        # Имя ключа названо секретом, а значение не вырезано — остаток по ИМЕНИ.
        # Эта половина ловит секрет без формы: у общего секрета хука формы нет.
        if _named_secret(key_hint) and node and node != REDACTED:
            found.append(f"{path} — значение ключа {key_hint!r} не вырезано "
                         f"(длина {len(node)})")
            return
        # Строка-тело (`body.raw`), разбираемая как JSON, — та же форма 8.
        parsed = _embedded_json(node)
        if parsed is not None:
            residue(parsed, f"{path}[JSON]", found)
            return
        form = residue_shaped(node)
        if form:
            found.append(f"{path} — {form} (длина {len(node)})")


# ── ФАЙЛЫ ────────────────────────────────────────────────────────────────────


def process(src: pathlib.Path, dst: pathlib.Path, c: Census) -> list[str]:
    """Вычистить один файл. Возвращает остаток (пути), найденный В ВЫХОДЕ."""
    c.files += 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.suffix == ".json":
        doc = json.loads(src.read_text(encoding="utf-8"))
        clean = redact_document(doc, c)
        dst.write_text(json.dumps(clean, ensure_ascii=False, indent=1), encoding="utf-8")
        found: list[str] = []
        residue(clean, src.name, found)
        return found
    # Текстовые выходы прогонщика (`.cli`, `summary.txt`, `coverage.txt`): у них
    # структуры нет, поэтому чистится текст. Греп по ним и был бы достаточен,
    # если бы у отчёта не было формы 6.
    raw = src.read_text(encoding="utf-8", errors="replace")
    s = scrub_text(raw)
    clean = s.text
    # Единица счёта у текстового файла — СТРОКА, а не файл: «строк осмотрено 1» на
    # журнале из ста двенадцати строк называет объём, которого не читали.
    c.strings += len(raw.splitlines()) or 1
    c.add(s)
    dst.write_text(clean, encoding="utf-8")
    found = []
    for lineno, line in enumerate(clean.splitlines(), 1):
        form = residue_shaped(line)
        if form:
            found.append(f"{src.name}:{lineno} — {form}")
    return found


def run(src_dir: pathlib.Path, dst_dir: pathlib.Path) -> int:
    if not src_dir.is_dir():
        print(f"ОТКАЗ: {src_dir} не каталог — чистить нечего, и это НЕ «чисто»",
              file=sys.stderr)
        return 1
    files = sorted(p for p in src_dir.iterdir()
                   if p.is_file() and p.suffix in TEXT_SUFFIXES)
    skipped = sorted(p.name for p in src_dir.iterdir()
                     if p.is_file() and p.suffix not in TEXT_SUFFIXES)
    c = Census()
    leftovers: list[str] = []
    for f in files:
        leftovers += process(f, dst_dir / f.name, c)

    print("===== чистка отчёта прогона перед публикацией =====")
    print(f"файлов прочитано:        {c.files}")
    print(f"узлов обойдено:          {c.nodes}")
    print(f"строк осмотрено:         {c.strings}")
    print(f"байтовых массивов:       {c.buffers}")
    print(f"вырезано по имени ключа: {c.redacted_by_name}")
    print(f"вырезано по форме:       {c.redacted_by_shape}")
    print(f"  из них критерием проверки выхода: {c.redacted_by_criterion}")
    print(f"ВСЕГО вырезано:          {c.redacted}")
    print(f"пропущено (вид неизвестен, В АРТЕФАКТ НЕ ПОПАДУТ): {len(skipped)}"
          + (f" — {', '.join(skipped)}" if skipped else ""))
    print(f"выход:                   {dst_dir}")

    if not c.files or not c.strings:
        print("ОТКАЗ: обход пуст — прочитано ноль строк. «Ничего не нашлось» здесь "
              "означает «ничего не читалось», и выкладывать вывод нельзя.",
              file=sys.stderr)
        return 1
    if leftovers:
        print(f"ОТКАЗ: в ВЫХОДЕ осталось {len(leftovers)} удостоверени(й) — "
              f"чистка неполна, выкладывать нельзя. Ниже ПУТИ, не значения: "
              f"печатать недочищенное значило бы опубликовать его в журнал.",
              file=sys.stderr)
        for p in leftovers[:40]:
            print(f"  · {p}", file=sys.stderr)
        return 1
    print("ЧИСТО: повторный обход выхода не нашёл ни одного удостоверения "
          "(включая тела ответов в байтовой форме).")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


# Маркеры вида JWT: настоящая форма, а не слово. Первая часть обязана начинаться
# на `eyJ` — это base64url от `{"`, то есть форма, а не совпадение.
def _jwt(mark: str) -> str:
    # Длины частей — как у настоящего RS256: 36 · 48 · 44. Короткий маркер
    # («eyJ…».«LEFT»…) не подпадал бы под НЕЗАВИСИМЫЙ предикат остатка, и ось
    # ослеплённого предиката доказывала бы не то, что называет.
    return (f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
            f".eyJzdWIiOiJ{mark}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            f".{mark}c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJlc2ln")


def _opaque(mark: str) -> str:
    # Удостоверение БЕЗ формы: ни `eyJ`, ни точек, ни `Bearer`, ни PEM. Ловится
    # только ИМЕНЕМ ключа; длина и смешение — как у отчеканенной строки секрета
    # (`credsecret.Mint`: 59 знаков, буквы и цифры вплотную).
    return f"kt_{mark}_9f3Ac71Qd0Ze8Bx2Yv5Nm4Kj6Hg1Fs3Dp7Lw0Rt2UqXe4Vb"


def _report(mark_env: str, mark_reqh: str, mark_resh: str, mark_body: str,
            mark_query: str, mark_stream: str, mark_script: str,
            mark_json: str = "JSN8") -> dict:
    """Отчёт формы newman 6.2.2 — позиции взяты ЗАМЕРОМ (см. шапку файла)."""
    return {
        "collection": {"item": [{
            "name": "probe",
            "event": [{"listen": "prerequest", "script": {"exec": [
                f"pm.environment.set('minted', '{_jwt(mark_script)}');"]}}],
            "request": {"body": {"mode": "raw", "raw": '{"assertion":"' + _jwt(mark_body) + '"}'},
                        "url": {"query": [{"key": "access_token", "value": _jwt(mark_query)}]}},
        }]},
        "environment": {"values": [
            {"key": "ownRestBaseUrl", "value": "https://localhost:9098"},
            {"key": "jwtAccountAdminA", "value": _jwt(mark_env)},
            {"key": "apiTokenA", "value": "kt_plain_secret_value_no_shape"},
            {"key": "accountAId", "value": "acc0123456789abcdefgh"},
        ]},
        "globals": {"values": []},
        "run": {
            "stats": {"assertions": {"total": 2, "failed": 1}},
            "failures": [{"error": {"test": "иам возвращает 200",
                                    "message": "expected 200 got 401"}}],
            "executions": [{
                "item": {"name": "probe", "event": [{"listen": "prerequest", "script": {
                    "exec": [f"pm.environment.set('minted', '{_jwt(mark_script)}');"]}}]},
                "request": {
                    "method": "GET",
                    "header": [{"key": "Authorization", "value": f"Bearer {_jwt(mark_reqh)}"},
                               {"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"assertion":"' + _jwt(mark_body) + '"}'},
                    "url": {"raw": f"https://localhost:9098/iam/token?access_token={_jwt(mark_query)}",
                            "path": ["iam", "token"],
                            "query": [{"key": "access_token", "value": _jwt(mark_query)}]},
                },
                "response": {
                    "code": 401,
                    "status": "Unauthorized",
                    "responseTime": 12,
                    "header": [{"key": "Set-Cookie", "value": f"session={_jwt(mark_resh)}; Path=/"},
                               {"key": "Content-Type", "value": "application/json"}],
                    "stream": {"type": "Buffer", "data": list(
                        ('{"accessToken":"' + _jwt(mark_stream) + '"}').encode("utf-8"))},
                },
                "assertions": [{"assertion": "иам возвращает 200", "error": None}],
            }, {
                # ФОРМА 8 — JSON-ТЕЛО, НЕСУЩЕЕ СЕКРЕТ ПОД ИМЕНЕМ КЛЮЧА. Значение
                # формы не имеет, поэтому по форме его не срезать; имя стоит ВНУТРИ
                # текста тела, а не в узле отчёта, — и обход узлов его не видит.
                # Захвачено на автономном стенде (задача #19): `SAKeyService.Issue`
                # вида SECRET отдаёт `response.secret` один раз, а `List` отдаёт
                # `nextPageToken`. Тот же ключ секрета уезжает и телом ЗАПРОСА.
                "item": {"name": "probe-json-body", "event": []},
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw",
                             "raw": json.dumps({"clientSecret": _opaque(mark_json),
                                                "pageSize": 1})},
                    "url": {"raw": "https://localhost:9098/iam/v1/projects",
                            "path": ["iam", "v1", "projects"], "query": []},
                },
                "response": {
                    "code": 200,
                    "status": "OK",
                    "responseTime": 9,
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "stream": {"type": "Buffer", "data": list(json.dumps({
                        "done": True,
                        "response": {"secret": _opaque(mark_json),
                                     "keyId": "sak0123456789abcdefgh",
                                     "privateKeyPem": ""},
                        "projects": [{"id": "prj0123456789abcdefgh", "name": "prj-legit-7"}],
                        "nextPageToken": _opaque(mark_json),
                        "total": 3,
                    }).encode("utf-8"))},
                },
                "assertions": [{"assertion": "секрет объявленной формы", "error": None}],
            }],
        },
    }


def self_test() -> int:
    import contextlib
    import io
    import tempfile
    print("redact-newman-report: доказательство способности упасть")
    marks = ("ENVV", "REQH", "RESH", "BODY", "QUER", "STRM", "SCRP")
    doc = _report(*marks)

    with tempfile.TemporaryDirectory(prefix="redact-proof-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        (src / "kaname-own-rest-front.json").write_text(
            json.dumps(doc), encoding="utf-8")
        (src / "kaname-own-rest-front.cli").write_text(
            "GET /iam/v1/accounts\n"
            f"  Authorization: Bearer {_jwt('CLIT')}\n"
            "  1 assertion failed\n", encoding="utf-8")
        (src / "summary.txt").write_text(
            "kaname-own-rest-front  requests=23 assertions=58 failed=0\n",
            encoding="utf-8")
        rc = run(src, dst)
        _c("чистка прошла и остатка не нашла (код 0)", rc == 0)

        text = (dst / "kaname-own-rest-front.json").read_text(encoding="utf-8")
        out = json.loads(text)

        # ── ОДНА ОСЬ НА КАЖДУЮ ИЗ СЕМИ ЗАМЕРЕННЫХ ПОЗИЦИЙ (восьмая форма — ниже) ──
        forms = (
            ("1 окружение (`environment.values[].value`)", "ENVV"),
            ("2 заголовок запроса (`request.header[].value`)", "REQH"),
            ("3 заголовок ответа (`response.header[].value`)", "RESH"),
            ("4 тело запроса (`request.body.raw`, три позиции)", "BODY"),
            ("5 параметр адреса (`url.query[].value` и `url.raw`)", "QUER"),
            ("6 тело ответа БАЙТОВЫМ МАССИВОМ (`response.stream`)", "STRM"),
            ("7 литерал в скрипте коллекции (`event[].script.exec[]`)", "SCRP"),
        )
        for label, mark in forms:
            _c(f"форма {label}: удостоверения в выходе НЕТ",
               mark not in text, f"маркер {mark} остался в выходе")

        # Форма 6 отдельно: она невидима ТЕКСТОВОМУ предикату, значит проверять
        # её текстом выхода недостаточно — надо декодировать массив.
        stream = out["run"]["executions"][0]["response"]["stream"]
        decoded = bytes(stream["data"]).decode("utf-8", "replace") \
            if isinstance(stream, dict) and stream.get("type") == "Buffer" else str(stream)
        _c("форма 6: и в ДЕКОДИРОВАННОМ массиве его нет",
           "STRM" not in decoded and shaped_credential(decoded) is None, decoded[:120])

        # ── ФОРМА 8: JSON-ТЕЛО НЕСЁТ СЕКРЕТ ПОД ИМЕНЕМ КЛЮЧА, А ФОРМЫ У НЕГО НЕТ ──
        #
        # Тело — ТЕКСТ, и обход узлов отчёта имён внутри него не видит: до этой оси
        # значение под `secret` внутри `response.stream` резалось только по форме,
        # а формы у отчеканенной строки секрета нет. Пара: секрет вырезан ПО ИМЕНИ
        # в теле ответа и в теле запроса; соседние несекретные поля тела выжили и
        # тело осталось JSON — иначе разбор падения по нему невозможен.
        ex8 = out["run"]["executions"][1]
        stream8 = ex8["response"]["stream"]
        decoded8 = bytes(stream8["data"]).decode("utf-8", "replace") \
            if isinstance(stream8, dict) and stream8.get("type") == "Buffer" else str(stream8)
        _c("форма 8 тело ответа — JSON с секретом ПОД ИМЕНЕМ: удостоверения в выходе НЕТ",
           "JSN8" not in decoded8, decoded8[:160])
        try:
            body8 = json.loads(decoded8)
        except ValueError:
            body8 = None
        _c("форма 8: тело ответа ОСТАЛОСЬ JSON после чистки", isinstance(body8, dict), decoded8[:160])
        if isinstance(body8, dict):
            _c("форма 8: `response.secret` вырезан по имени, а не удалён вместе с ключом",
               body8.get("response", {}).get("secret") == REDACTED, f"{body8.get('response')}")
            _c("форма 8: `nextPageToken` вырезан по имени (как и в параметре адреса)",
               body8.get("nextPageToken") == REDACTED, f"{body8.get('nextPageToken')!r}")
            _c("форма 8: соседние несекретные поля тела выжили (законный близнец)",
               body8.get("projects") == [{"id": "prj0123456789abcdefgh", "name": "prj-legit-7"}]
               and body8.get("total") == 3 and body8.get("done") is True
               and body8.get("response", {}).get("keyId") == "sak0123456789abcdefgh",
               f"{body8}")
            _c("форма 8: ПУСТОЕ значение секретного ключа не превращается в «вырезано»",
               body8.get("response", {}).get("privateKeyPem") == "", f"{body8.get('response')}")
        raw8 = ex8["request"]["body"]["raw"]
        _c("форма 8 тело запроса — JSON с `clientSecret`: удостоверения в выходе НЕТ",
           "JSN8" not in raw8 and '"pageSize": 1' in raw8.replace(":1", ": 1"), raw8[:160])

        # ── ИМЯ КЛЮЧА ОБЯЗАНО ОСТАТЬСЯ: иначе чистка = удаление файла ────────
        names = [v["key"] for v in out["environment"]["values"]]
        _c("имена ключей окружения остались все четыре",
           names == ["ownRestBaseUrl", "jwtAccountAdminA", "apiTokenA", "accountAId"],
           f"{names}")
        hdr = [h["key"] for h in out["run"]["executions"][0]["request"]["header"]]
        _c("имена заголовков запроса остались", hdr == ["Authorization", "Content-Type"], f"{hdr}")

        # ── СЕКРЕТ БЕЗ ФОРМЫ — ловится ПО ИМЕНИ, а не по виду значения ───────
        api = next(v for v in out["environment"]["values"] if v["key"] == "apiTokenA")
        _c("секрет без формы вырезан ПО ИМЕНИ ключа",
           "plain_secret_value" not in json.dumps(api, ensure_ascii=False), f"{api}")

        # ── ЗАКОННЫЕ БЛИЗНЕЦЫ: разбор падения обязан ВЫЖИТЬ ─────────────────
        acc = next(v for v in out["environment"]["values"] if v["key"] == "accountAId")
        _c("идентификатор ресурса выжил (он не удостоверение)",
           acc["value"] == "acc0123456789abcdefgh", f"{acc}")
        _c("адрес фронта выжил",
           out["environment"]["values"][0]["value"] == "https://localhost:9098")
        _c("код и текст ответа выжили",
           out["run"]["executions"][0]["response"]["code"] == 401
           and out["run"]["executions"][0]["response"]["status"] == "Unauthorized")
        _c("текст упавшего утверждения выжил",
           out["run"]["failures"][0]["error"]["message"] == "expected 200 got 401")
        _c("путь запроса выжил",
           out["run"]["executions"][0]["request"]["url"]["path"] == ["iam", "token"])
        _c("числа прогона выжили",
           out["run"]["stats"]["assertions"] == {"total": 2, "failed": 1})

        # ── ТЕКСТОВЫЙ ВЫХОД ПРОГОНЩИКА ТОЖЕ ЧИСТИТСЯ ────────────────────────
        cli = (dst / "kaname-own-rest-front.cli").read_text(encoding="utf-8")
        _c("в текстовом выводе прогонщика удостоверения нет", "CLIT" not in cli, cli)
        _c("а строка про упавшее утверждение в нём осталась",
           "1 assertion failed" in cli, cli)

    # ── ОСЬ: ПАРАМЕТР АДРЕСА В ЦЕЛЬНОЙ СТРОКЕ — БЕЗ ФОРМЫ И БЕЗ ИМЕНИ УЗЛА ──
    #
    # Удостоверение вида JWT в `url.raw` ловится формой; НЕПРОЗРАЧНОЕ — нет, и имени
    # у цельной строки тоже нет. Пара: значение секретного параметра вырезано, имя
    # параметра и соседний несекретный параметр остались целиком.
    raw_url = ("https://localhost:9098/iam/v1/accounts"
               "?pageSize=10&access_token=opaque-short-2Fx9&filter=name%3Da")
    cleaned, cut = scrub_text(raw_url)[0], scrub_text(raw_url).cut
    _c("непрозрачный параметр адреса вырезан (формы у него нет)",
       "opaque-short-2Fx9" not in cleaned and cut == 1, cleaned)
    _c("имя параметра осталось — иначе координата отказа теряется",
       "access_token=" in cleaned, cleaned)
    _c("несекретные параметры остались целиком",
       "pageSize=10" in cleaned and "filter=name%3Da" in cleaned, cleaned)

    # ── ОСЬ: ЖУРНАЛ СЛУЖБЫ ЧИСТИТСЯ ТЕМ ЖЕ, А ЧУЖОЙ ВИД НЕ УЕЗЖАЕТ МОЛЧА ────
    #
    # Журнал выкладывается вторым артефактом того же задания, и замер на нём дал
    # ноль удостоверений — СЕГОДНЯ. Выкладывается КОД, поэтому журнал идёт через ту
    # же чистку; ось доказывает, что `.log` она вообще читает (первая редакция не
    # читала: перечень видов файла её не знал, и шаг падал «обход пуст»).
    with tempfile.TemporaryDirectory(prefix="redact-log-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "log-src", tmp / "log-public"
        src.mkdir()
        (src / "kaname.log").write_text(
            "уровень=INFO рубеж пропустил\n"
            f"уровень=WARN предъявитель {_jwt('LOGT')} отклонён\n", encoding="utf-8")
        # Файл незнакомого вида рядом: он обязан быть НАЗВАН и НЕ скопирован.
        (src / "wrapping.key").write_bytes(b"\x00\x01binary-key-material")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(src, dst)
        out = buf.getvalue()
        _c("журнал службы вычищен (код 0)", rc == 0, out[-300:])
        log = (dst / "kaname.log").read_text(encoding="utf-8")
        _c("удостоверения в журнале нет", "LOGT" not in log, log)
        _c("а строки уровня и текст отказа остались",
           "уровень=WARN" in log and "отклонён" in log, log)
        _c("файл незнакомого вида НЕ скопирован в выкладывание",
           not (dst / "wrapping.key").exists())
        _c("и он НАЗВАН в переписи, а не выпал молча",
           "wrapping.key" in out and "В АРТЕФАКТ НЕ ПОПАДУТ" in out, out[:600])

    # ── ОСЬ: ЗАКОННЫЙ ДЛИННЫЙ ПРОБЕГ ПРОТИВ НЕПРОЗРАЧНОГО УДОСТОВЕРЕНИЯ ─────
    #
    # Вход ЗАХВАЧЕН, а не придуман: строка журнала — из артефакта прогона
    # 34689147074, на котором первая редакция предиката и покраснела. Без второй
    # половины пары «не краснеет» означало бы «не смотрит».
    real_log_line = ('{"level":"INFO","msg":"identity posture lane wiring",'
                     '"catalog_readable":true,'
                     '"catalog_entries_demanding_a_raised_floor":0}')
    _c("имя поля из НАСТОЯЩЕГО журнала (40 знаков, без цифр) — НЕ удостоверение",
       residue_shaped(real_log_line) is None, f"{residue_shaped(real_log_line)}")
    opaque = "kt9f3Ac71Qd0Ze8Bx2Yv5Nm4Kj6Hg1Fs3Dp7Lw0Rt2Uq"
    _c("непрозрачный пробег той же длины С ЦИФРАМИ — удостоверение",
       residue_shaped(opaque) is not None, f"{residue_shaped(opaque)}")
    # Прежняя редакция утверждала здесь ОБРАТНОЕ — «чистка сама его не режет,
    # ловит второй взгляд» — и это утверждение и было классом kaname#183: то,
    # что проверка называет удостоверением, срез не резал, и зелёный прогон
    # кончался невыложенным артефактом. Теперь срез судит тем же критерием.
    _c("и срез его режет: критерий у среза и у проверки один (kaname#183)",
       opaque not in scrub_text(opaque)[0] and residue_shaped(scrub_text(opaque)[0]) is None)

    # Идентификатор кейса — захвачен из отчёта прогона коллекции каталога прав на
    # автономном стенде: вторая редакция предиката на нём и покраснела. Пара
    # отличается ОДНИМ фактом — снят дефис между «02» и «catalog».
    case_id_line = ("→ NEG-G-02-catalog-anonymous-unauthenticated :: "
                    "list-permission-catalog-anon")
    _c("идентификатор кейса (42 знака, цифры отдельным сегментом) — НЕ удостоверение",
       residue_shaped(case_id_line) is None, f"{residue_shaped(case_id_line)}")
    glued = case_id_line.replace("02-catalog", "02catalog")
    _c("тот же идентификатор, цифра ВПЛОТНУЮ к букве — удостоверение",
       residue_shaped(glued) is not None, f"{residue_shaped(glued)}")

    # Нижняя граница на засеянной выборке: уточнение не вправе потерять больше,
    # чем замерено. Выборка детерминирована, поэтому число воспроизводится.
    import random
    rnd = random.Random(1814)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    sample = ["".join(rnd.choice(alphabet) for _ in range(40)) for _ in range(20000)]
    caught = sum(1 for t in sample if residue_shaped(t) is not None)
    print(f"  выборка непрозрачных пробегов длиной 40: поймано {caught} из {len(sample)}")
    _c("случайные пробеги base64url длиной 40 ловятся не хуже 99,8 %",
       caught >= 19960, f"поймано {caught} из {len(sample)}")

    # ── ОСЬ: ИМЯ, ПОСТРОЕННОЕ ГЕНЕРАТОРОМ, — НЕ УДОСТОВЕРЕНИЕ ───────────────
    #
    # ТРЕТИЙ ЗАМЕР ТОГО ЖЕ РОДА, и вход снова ЗАХВАЧЕН, а не придуман: все четыре
    # строки взяты из коллекций дерева. Генератор строит рабочие ключи опроса
    # `_poll200_started_<имя шага>` и несёт идентификаторы кейсов в текстах
    # утверждений; при длине от 40 знаков прежний предикат называл их
    # удостоверениями — на ЗЕЛЁНОМ прогоне, отказом выложить артефакт.
    #
    # Замер по дереву на день правки: пробегов 40+ в коллекциях 79, из них
    # прежний предикат помечал удостоверением 26 в восьми коллекциях. Ни одна из
    # шести гоняемых сегодня коллекций такого имени не несёт — поэтому класс и
    # не проявлялся, а каждая ПЕРЕЕЗЖАЮЩАЯ приносила бы отказ без дефекта.
    #
    # РАЗЛИЧАЕТ УСТРОЙСТВО СТРОКИ, А НЕ СПИСОК ПРОЩЁННЫХ. Имя, построенное из
    # слов, несёт частые разделители: сегменты коротки, а регистр либо один на
    # всю строку, либо почти один. Непрозрачное удостоверение base64url
    # разделителя почти не содержит (2 знака из 64) и смешивает регистры густо.
    # Отсюда два независимых признака, объединённых ИЛИ, — ни один не покрывает
    # другого: первый ловит длинное удостоверение БЕЗ заглавных (шестнадцатеричный
    # пробег, крокфорд), второй — плотное короткое, разорванное разделителями.
    #
    # ЦЕНА ИЗМЕРЕНА И ОНА НУЛЕВАЯ: на 200 000 случайных пробегов base64url прежний
    # и уточнённый предикаты ловят ПОРОВНУ — 99,8925 % при длине 40, 99,9360 %
    # при 43, 99,9970 % при 64; потеря 0 из 200 000 на каждой длине. То есть
    # уточнение снимает 26 ложных находок и не теряет ни одной настоящей.
    generated = [
        # `iam-account` — ключ опроса, 41 знак
        "_poll200_started_teardown_bva_max_account",
        # `iam-rbac-subjects` — тот же ключ с заглавными внутри, 42 знака
        "_poll200_started_teardown_group_e30GroupId",
        # `iam-invite-grant-fga` — идентификатор кейса, 44 знака, весь заглавный
        "INVGRANT-TE2-CROSS-ACCOUNT-PROJECT-INVISIBLE",
        # `iam-token-facade-conformance` — имя шага, 54 знака, весь строчный
        "control-public-listener-404s-an-internal-route-it-lacks",
    ]
    for name in generated:
        _c(f"имя генератора ({len(name)} знаков) — НЕ удостоверение: {name[:34]}…",
           residue_shaped(name) is None, f"{residue_shaped(name)}")

    # ОДНО-ФАКТНЫЙ БЛИЗНЕЦ ПО ПЕРВОМУ ПРИЗНАКУ: снят ОДИН разделитель, и два
    # коротких сегмента слились в длинный с цифрой вплотную к букве.
    glued_seg = "_poll200_started_teardown_group_e30GroupId".replace(
        "group_e30", "groupe30")
    _c("то же имя без ОДНОГО разделителя (сегмент стал длинным) — удостоверение",
       residue_shaped(glued_seg) is not None, f"{glued_seg} -> {residue_shaped(glued_seg)}")

    # ОДНО-ФАКТНЫЙ БЛИЗНЕЦ ПО ВТОРОМУ ПРИЗНАКУ: у имени генератора три заглавные,
    # порог — четыре. Поднят регистр ОДНОЙ буквы.
    three_caps = "_poll200_started_teardown_unmember_gmGrantGroupId_0"
    _c("имя генератора с ТРЕМЯ заглавными — НЕ удостоверение",
       residue_shaped(three_caps) is None, f"{residue_shaped(three_caps)}")
    four_caps = three_caps.replace("unmember", "Unmember")
    _c("оно же с ЧЕТВЁРТОЙ заглавной — удостоверение",
       residue_shaped(four_caps) is not None, f"{four_caps} -> {residue_shaped(four_caps)}")

    # ── ОСЬ: СРЕЗ И ПРОВЕРКА ВЫХОДА СУДЯТ ОДНИМ КРИТЕРИЕМ (kaname#183) ──────
    #
    # ЗАХВАЧЕНО: прогон 35895962909, `own-landing-newman-report` НЕ выложен на
    # зелёном наборе. Проверка выхода назвала удостоверением
    # `environment.values[92]` и `[95]` полосы входа — признаки формы
    # `loginLaneCsrfLogin` и `loginLaneCsrfLogout`, 43 знака base64url, — а
    # перепись насчитала «вырезано по форме: 0». Срез знал JWT, PEM и Bearer,
    # проверка — ещё и пробег 40+ и тройку через точку; имени `csrf` не знал
    # перечень. Каждая следующая переменная без имени из перечня повторила бы
    # отказ, поэтому предмет — КЛАСС: всё, что проверка назовёт удостоверением,
    # срез срезает.
    #
    # Законный близнец, у которого критерий НЕ срабатывает, обязан выжить срез
    # нетронутым: иначе «срезано» значило бы «срезано всё длинное».
    for legit in (real_log_line, case_id_line, *generated, three_caps):
        _c(f"законный близнец выжил срез нетронутым: {legit[:34]}…",
           scrub_text(legit)[0] == legit)

    # Законный близнец, у которого критерий СРАБАТЫВАЕТ: шестнадцатеричный
    # отпечаток. Строка захвачена из дерева — закреплённая ревизия действия в
    # `.github/workflows/e2e-newman.yml`, 40 знаков, буква вплотную к цифре.
    # Отличить его ФОРМОЙ от шестнадцатеричного секрета нельзя (`rand -hex`
    # даёт ту же форму), список прощённых не заводится — каждая его запись есть
    # место, куда секрет проедет молча. Поэтому он СРЕЗАЕТСЯ, и это безопасно:
    # срез не публикует ничего, цена — невидимый в артефакте отпечаток, и она
    # СЧИТАНА строкой переписи. Прежняя цена того же входа — отказ выложить
    # артефакт целиком.
    pinned = "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7"
    _c("предпосылка: закреплённую ревизию (40 hex) проверка называет удостоверением",
       residue_shaped(pinned) is not None)
    cut_pinned = scrub_text(pinned)[0]
    _c("отпечаток срезан, а окружающий текст строки выжил",
       "043fb46d1a93" not in cut_pinned and "actions/upload-artifact@" in cut_pinned
       and "# v7" in cut_pinned and residue_shaped(cut_pinned) is None, cut_pinned)

    # Засеянная выборка — то же свойство на двадцати тысячах входов: каждый
    # пробег, который проверка назвала удостоверением, после среза проверке
    # чист. Это определение «одного критерия», а не пример к нему.
    leaked = sum(1 for t in sample
                 if residue_shaped(t) is not None
                 and residue_shaped(scrub_text(t)[0]) is not None)
    print(f"  выборка: пойманных проверкой и НЕ срезанных срезом — {leaked} из {caught}")
    _c("каждый пробег, названный проверкой удостоверением, срез срезает",
       leaked == 0, f"не срезано {leaked} из {caught}")

    # Самопроба инъекцией, вход — форма захваченного отказа: переменная
    # окружения с БЕЗОБИДНЫМ именем и значением-пробегом 43 знака. Значение
    # детерминировано и не взято ни из какого прогона.
    import base64
    import hashlib
    flow_value = base64.urlsafe_b64encode(
        hashlib.sha256(b"kaname#183 one-criterion probe").digest()).rstrip(b"=").decode()
    harmless = "loginLaneFlowHandle"
    _c("предпосылка: значение — пробег 43 знака, и проверка зовёт его удостоверением",
       len(flow_value) == 43 and residue_shaped(flow_value) is not None)
    _c("предпосылка: безобидное имя перечнем имён НЕ ловится (иначе проба про имя)",
       not SECRET_NAME_RE.search(harmless))
    env_doc = {"environment": {"values": [
        {"key": "ownRestBaseUrl", "value": "https://localhost:9098"},
        {"key": harmless, "value": flow_value},
        {"key": "accountAId", "value": "acc0123456789abcdefgh"},
    ]}}
    for cut_on in (True, False):
        with tempfile.TemporaryDirectory(prefix="redact-one-criterion-") as td:
            tmp = pathlib.Path(td)
            src, dst = tmp / "out", tmp / "out-public"
            src.mkdir()
            (src / "kaname-login-lane.json").write_text(json.dumps(env_doc), encoding="utf-8")
            saved_scrub = globals()["scrub_text"]
            if not cut_on:
                # СРЕЗ ПО ФОРМЕ ОТКЛЮЧЁН ЦЕЛИКОМ: у проверки выхода свой обход,
                # и отказ обязан наступить на нём, а не у среза.
                globals()["scrub_text"] = lambda text: Scrubbed(text, 0, 0)
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    rc = run(src, dst)
            finally:
                globals()["scrub_text"] = saved_scrub
            out = buf.getvalue()
            if cut_on:
                published = (dst / "kaname-login-lane.json").read_text(encoding="utf-8")
                _c("безобидное имя, значение-пробег 43 знака — СРЕЗАНО, артефакт выложен (код 0)",
                   rc == 0 and flow_value not in published, out[-400:])
                _c("срезано ПО ФОРМЕ критерием проверки, а не по имени — перепись это называет",
                   "критерием проверки выхода: 1" in out and "вырезано по имени ключа: 0" in out,
                   out[:700])
                vals = json.loads(published)["environment"]["values"]
                _c("имя переменной и соседние значения выжили",
                   [v["key"] for v in vals] == ["ownRestBaseUrl", harmless, "accountAId"]
                   and vals[0]["value"] == "https://localhost:9098"
                   and vals[2]["value"] == "acc0123456789abcdefgh", f"{[v['key'] for v in vals]}")
            else:
                _c("срез отключён — проверка выхода ОТКАЗЫВАЕТ (код 1), а не молчит",
                   rc == 1 and "осталось 1 удостоверени" in out, out[-400:])
                _c("отказ называет ПУТЬ переменной, а значение не печатает",
                   "environment.values[1].value" in out and flow_value not in out, out[-400:])

    # ИМЯ `csrf` В ПЕРЕЧНЕ — вторая, независимая половина. Значение КОРОТКОЕ и
    # без формы: критерий среза его не видит, поймать его может только имя.
    # Одно-фактный близнец — безобидное имя выше: тот же вход, другое имя.
    for name in ("loginLaneCsrfLogin", "loginLaneCsrfLogout", "X-CSRF-Token", "xsrfState"):
        _c(f"имя {name!r} перечень имён называет секретом", bool(SECRET_NAME_RE.search(name)))
    short_env = {"environment": {"values": [
        {"key": "loginLaneCsrfLogin", "value": "csrf-short-2Fx9"},
        {"key": "accountAId", "value": "acc0123456789abcdefgh"},
    ]}}
    with tempfile.TemporaryDirectory(prefix="redact-csrf-name-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        (src / "kaname-login-lane.json").write_text(json.dumps(short_env), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = run(src, dst)
        published = (dst / "kaname-login-lane.json").read_text(encoding="utf-8")
        _c("короткий признак формы без формы вырезан ПО ИМЕНИ csrf (код 0)",
           rc == 0 and "csrf-short-2Fx9" not in published
           and "loginLaneCsrfLogin" in published, buf.getvalue()[-400:])
    # Путь `/auth/csrf` — законный близнец имени: слово `csrf` в ПУТИ не имя
    # параметра, и путь обязан выжить целиком.
    csrf_url = "https://localhost:9098/iam/v1/auth/csrf?form=login&csrf=csrf-short-2Fx9"
    cut_url = scrub_text(csrf_url)[0]
    _c("параметр адреса `csrf=` вырезан, его имя, путь `/auth/csrf` и `form=login` выжили",
       "csrf-short-2Fx9" not in cut_url and "&csrf=" in cut_url
       and "/iam/v1/auth/csrf?form=login&" in cut_url, cut_url)

    # ── ОСЬ: ОСТАТОК ЛОВИТСЯ, А НЕ ОБЕЩАЕТСЯ ────────────────────────────────
    #
    # Две инъекции, и каждая про своё. Первая слепит ВИДОВЫЕ предикаты среза
    # (JWT, Bearer): срез обязан всё равно срезать то же удостоверение общим
    # критерием — это и есть «один критерий», а не совпадение двух списков.
    # Вторая отключает срез по форме ЦЕЛИКОМ: тогда отказ обязан наступить на
    # ПОВТОРНОМ обходе выхода, а не быть объявлен зелёным. PEM не слепится:
    # его предикат у среза и у проверки один и тот же объект.
    never = re.compile(r"ZZZ_NEVER_MATCHES_ZZZ")
    for inject in ("виды", "срез"):
        with tempfile.TemporaryDirectory(prefix="redact-residue-") as td:
            tmp = pathlib.Path(td)
            src, dst = tmp / "out", tmp / "out-public"
            src.mkdir()
            (src / "r.json").write_text(json.dumps(
                {"run": {"executions": [{"leftover": _jwt("LEFT")}]}}), encoding="utf-8")
            names = ("JWT_RE", "BEARER_RE") if inject == "виды" else ("scrub_text",)
            saved = {k: globals()[k] for k in names}
            for k in saved:
                globals()[k] = never if inject == "виды" else (lambda text: Scrubbed(text, 0, 0))
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    rc = run(src, dst)
            finally:
                globals().update(saved)
            if inject == "виды":
                left = (dst / "r.json").read_text(encoding="utf-8")
                _c("видовые предикаты среза ослеплены — общий критерий срезал то же (код 0)",
                   rc == 0 and "LEFT" not in left, buf.getvalue()[-400:])
            else:
                _c("срез по форме отключён — отказ по ОСТАТКУ, а не зелёное",
                   rc == 1 and "осталось 1 удостоверени" in buf.getvalue(), buf.getvalue()[-400:])

    # ФОРМА 8 ОТДЕЛЬНО: ослеплён РАЗБОР ТЕЛА у чистки (тело снова режется только
    # по форме), а секрет под именем — КОРОТКИЙ, ниже порога пробега 40+, и формы
    # у него нет. Тогда поймать его может только именная половина второго
    # взгляда, читающая JSON тела сама; и отказ обязан назвать путь В ТЕЛЕ, а не
    # значение. Близнец: та же чистка без ослепления — код 0.
    short_secret = '{"done":true,"response":{"secret":"kt_short_2Fx9_value","keyId":"sak1"}}'
    for blinded, want in ((True, 1), (False, 0)):
        with tempfile.TemporaryDirectory(prefix="redact-form8-") as td:
            tmp = pathlib.Path(td)
            src, dst = tmp / "out", tmp / "out-public"
            src.mkdir()
            # Рядом с телом — обычная строка узла: без неё обход насчитал бы ноль
            # строк и отказал бы «обход пуст», то есть по ДРУГОЙ причине, и код 1
            # доказывал бы не то, что назван.
            (src / "r.json").write_text(json.dumps({"run": {"executions": [{
                "item": {"name": "probe-short-secret"},
                "response": {"stream": {"type": "Buffer",
                                        "data": list(short_secret.encode("utf-8"))}}}]}}),
                encoding="utf-8")
            saved_body = globals()["_scrub_body"]
            if blinded:
                def _shape_only(text: str, c: Census) -> str:
                    s = scrub_text(text)
                    c.add(s)
                    return s.text
                globals()["_scrub_body"] = _shape_only
            buf = io.StringIO()
            try:
                # Остаток печатается в stderr — читаем оба потока, иначе «путь
                # назван» проверялось бы по потоку, в котором его нет by construction.
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    rc = run(src, dst)
            finally:
                globals()["_scrub_body"] = saved_body
            out = buf.getvalue()
            if blinded:
                _c("форма 8: разбор тела у чистки ослеплён, секрет короткий и без формы — "
                   "отказ по ИМЕНИ внутри тела (а не «обход пуст»)",
                   rc == want and "обход пуст" not in out and "осталось 1 удостоверени" in out,
                   out[-400:])
                _c("форма 8: остаток назван ПУТЁМ внутри тела, значение не напечатано",
                   "[байтовый массив, JSON]" in out and "kt_short_2Fx9_value" not in out,
                   out[-400:])
            else:
                _c("форма 8: тот же вход при живой чистке — код 0 (близнец)",
                   rc == want, out[-400:])

    # ── ОСЬ: ПУСТОЙ ОБХОД — ОТКАЗ, А НЕ «ЧИСТО» ────────────────────────────
    with tempfile.TemporaryDirectory(prefix="redact-empty-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        rc = run(src, dst)
        _c("пустой каталог — код 1, а НЕ «чисто»", rc == 1)
        rc = run(tmp / "нет-такого", dst)
        _c("каталога нет — код 1, а НЕ «чисто»", rc == 1)

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: все восемь замеренных форм вычищены (включая байтовый массив "
          "тела ответа, невидимый текстовому грепу, и секрет под именем ключа внутри "
          "JSON-тела), имена ключей и разбор падения выжили, всё, что проверка выхода "
          "называет удостоверением, срез срезает, отключённый срез отвергается по "
          "остатку, пустой обход — отказ.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src", default="tests/newman/out")
    ap.add_argument("--out", dest="dst", default="tests/newman/out-public")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.src), pathlib.Path(args.dst))


if __name__ == "__main__":
    sys.exit(main())
