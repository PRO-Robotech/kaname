#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДОЛГ СКВОЗНОГО НАБОРА, НАЗВАННЫЙ ЧИСЛОМ: что на автономном стенде НЕ гоняется.

ПРЕДМЕТ. Автономный стенд поднимает службу и её базу без края платформы, её
сервисов и достижимого поставщика удостоверений. Сквозной набор при этом
адресуется почти целиком к КРАЮ, и край — не транспорт: он производит проверяемые
свойства. Значит прогон здесь покрывает НЕ ВСЁ, и разница обязана быть напечатана
ЧИСЛОМ по каждой позиции — иначе зелёный шаг читается шире сделанного, а это брак
независимо от того, сколько сделано.

ВЕЛИЧИН ДВЕ, И ОНИ О РАЗНОМ. АДРЕСАЦИЯ выводится из самой коллекции — по
переменным адреса, которые её шаги действительно используют. РЕШЕНИЕ О
ПРОИЗВОДИТЕЛЕ выводом не берётся: оно ОБЪЯВЛЕНО ведомостью с доводом по каждой
позиции, и перепись его читает, а не производит.

ПОЧЕМУ ЭТО НЕ ОТКАЗ ОТ ПРЕЖНЕГО РЕШЕНИЯ, А ЕГО УТОЧНЕНИЕ. Здесь стояло «разрез
ВЫВОДИТСЯ, а не объявляется вторым списком», и довод — «выписанный перечень
разошёлся бы с деревом молча: новая коллекция в него просто не попала бы» — верен
для АДРЕСАЦИИ и остаётся в силе: она по-прежнему выводится. Неверен он оказался
для ПРОИЗВОДИТЕЛЯ, и вот чем.

Ярлык, выведенный из адреса, НЕОПРОВЕРЖИМ как утверждение о производителе:
переадресация коллекции меняет адрес И ярлык одним движением, поэтому ярлык не
может оказаться неверным ни при каком состоянии дерева. Генератор приписывает
`{{baseUrl}}` каждому шагу автоматически, значит ярлык края получает BY
CONSTRUCTION всякая коллекция, чьи шаги не переадресованы, — включая те, все
утверждения которых производит сама служба. На день разреза #24 таких было 40
из 41, и разрез, читавший ПРОДУКТ, а не адрес, дал по тем же 40: A 18 · B 9 ·
C 8 · D 5. Для восемнадцати выведенный ярлык был ложен.

Довод «перечень разошёлся бы молча» снят МЕХАНИЗМОМ, а не обещанием: ведомость
сверяется с деревом В ОБЕ СТОРОНЫ — коллекция без записи роняет перепись, запись
без коллекции роняет её же. Новая коллекция в ведомость не «не попадёт» — она
уронит прогон, пока решение о ней не записано.

ПЕЧАТАЮТСЯ ОБЕ ВЕЛИЧИНЫ ПО КАЖДОЙ ПОЗИЦИИ, и расхождение между ними видно, а не
сглажено: адресация говорит, куда коллекция стучится, ведомость — чей
производитель отвечает на её утверждения.

ПЕЧАТАЮТСЯ ОБЕ ВЕЛИЧИНЫ. «Гоняется здесь N» без «не гоняется M» скрывает ровно тот
случай, ради которого перепись и делается.

НЕПОСЕЯННОСТЬ — ТРИ СОСТОЯНИЯ, А НЕ ОДНО, И ОНИ ЛОМАЮТСЯ ПО-РАЗНОМУ. Прежний
предикат спрашивал одно («значение в шаблоне ПУСТО») и потому не видел двух
других: ключа с правдоподобным литералом ЧУЖОГО стенда (`userNOBId`, `userAAAId`,
`projectB1Id` несут непустые `usr…`/`prj…`) и ключа, которого в шаблоне НЕТ вовсе
(`iamRegistryTokenBaseUrl`, `jwtHumanCeremony*`). Оба выглядели покрытыми, и мера
работы переезда занижалась: коллекция читалась переводимой одним адресом, а на
стенде падала на пустоте. Состояния печатаются ОТДЕЛЬНО — своей переписью и рядом
с каждым названным ключом, — потому что чинятся они разным, а пустой ключ падает
ГРОМКО (страж набора утверждает его по имени до первого запроса), тогда как
литерал чужого стенда доезжает до службы и возвращается 403/404, то есть ПОХОЖИМ
НА ДЕФЕКТ ПРОДУКТА.

КАТЕГОРИЯ ВЕДОМОСТИ СВЕРЯЕТСЯ С ТРЕБОВАНИЕМ ЦЕРЕМОНИИ. Запись A у коллекции,
читающей предъявителя церемонии, объявляет её переводимой машинным посевом —
возможность, неисполнимую by construction. Сверка идёт в ОДНУ сторону: обратное
(«B не требует церемонии») находкой не объявляется, потому что у B бывает и другое
препятствие — недостижимый внешний поставщик.

«ГОНЯЕТСЯ» ЧИТАЕТСЯ ИЗ ОБЪЯВЛЕНИЯ КОНВЕЙЕРА, А НЕ ВЫВОДИТСЯ ИЗ ОТСУТСТВИЯ
ПРЕПЯТСТВИЙ. Прежняя редакция печатала «гоняется здесь: 1», не читая конвейер
ВОВСЕ: снятие шага прогона из `.github/workflows/e2e-newman.yml` величину не
меняло. То есть она утверждала «гоняется», а измеряла «ничто не мешает гонять» —
две разные вещи, и расходятся они именно в том случае, ради которого перепись
делается. Теперь у коллекции два независимых условия, и оба названы по каждой
позиции: препятствия по дереву И шаг конвейера, который её гоняет.

Объявление читается РАЗОБРАННЫМ (`yaml.safe_load`), а не подстрокой: имя
коллекции встречается в комментариях объявления десятки раз, и проверка по
подстроке считала бы собственное объяснение. Тело шага `run:` тоже читается
разобранным — как программа bash: прогон засчитывается команде прогонщика, а флаг
`--service` в комментарии тела, в строковом литерале и в данных heredoc прогоном
не является (`shell_commands`, `runner_stems`).

У КАЖДОЙ КОЛЛЕКЦИИ ЕСТЬ ПРОИЗВОДИТЕЛЬ В КОНВЕЙЕРЕ: шаг, который её гоняет, либо
ДЕРЖАТЕЛЬ — третье поле записи ведомости, задача, которая её прогонит. Прежде
запись несла категорию и довод, и «не гоняется» было концом записи: причина
печаталась, а кто снимет препятствие, не было записано нигде. Замер на `d22123ba`:
коллекций 47, гоняют шаги 17, у тридцати остальных держателя не было ни одного.
Сверка идёт В ОБЕ СТОРОНЫ: негоняемая коллекция без держателя роняет перепись, и
держатель у коллекции, которую шаг уже гоняет, роняет её же — запись пережила
свой предмет и истекает вместе с препятствием, а не остаётся ведомостью прощения.
Форма держателя закрыта (`HOLDER_RE`): адрес задачи и то, что она сделает.

ИСХОДЫ:
    0  — перепись напечатана (долг — не отказ: он именно объявляется);
    1  — перепись беспредметна: коллекций либо шаблона окружения нет, разбор дал
         ноль. «Ноль находок» здесь означало бы «ноль прочитанного»;
   75  — УСЛОВИЕ НЕ СОЗДАНО: объявлений конвейера не прочитано ни одного либо нет
         разборщика YAML. Величина «гоняется» тогда не измерена, и печатать ноль
         значило бы выдать несозданное условие за вердикт.

САМОПРОВЕРКА — `--self-test`: синтетическое дерево, где коллекция БЕЗ препятствий
обязана попасть в «гоняется», с препятствием — в «не гоняется», а пустой обход
обязан дать отказ.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

RC_UNMET = 75

VAR_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
GET_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")
CFG_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*BaseUrl)['\"]")

# Переменные адреса КРАЯ ПЛАТФОРМЫ. Их производитель — чужой стенд; наведение их
# на собственный фронт службы запрещено гейтом набора, и запрет верен: те же
# кейсы, тот же зелёный отчёт, проверено РАЗНОЕ.
EDGE_VARS = frozenset({"baseUrl", "internalBaseUrl", "externalBaseUrl"})
# Переменные адреса СОБСТВЕННЫХ HTTP-поверхностей службы — те, что автономный
# стенд производит сам: два REST-фронта и слушатель полосы входа паролем (Ф3,
# kacho#1269; поднимается посадкой `own` — стенд чарта с ручкой
# `KANAME_STAND_IDENTITY_PROVIDER=own`, посев `seed_login_lane.py`). Ярлык поверхности у трёх
# один — он контракт с посевом стенда (`--minted-surface`), а не описание порта.
OWN_VARS = frozenset({"ownRestBaseUrl", "ownInternalRestBaseUrl", "loginLaneBaseUrl"})
# Поверхности, которые служба поднимает, но чей ОТВЕТ зависит от недостижимого
# соседа: зеркало набора ключей и полоса docker-токена.
NEIGHBOUR_VARS = frozenset({"iamJwksBaseUrl", "iamRegistryTokenBaseUrl",
                            "providerPublicBaseUrl", "registryDataPlaneBaseUrl"})
# ─────────────── СОСТОЯНИЕ КЛЮЧА: ТРИ, А НЕ ДВА ────────────────────────────
#
# Непосеянность — не одно состояние, и разные состояния ЛОМАЮТСЯ ПО-РАЗНОМУ.
# Прежний предикат спрашивал одно («значение в шаблоне пусто») и потому не видел
# двух других: ключ с правдоподобным литералом ЧУЖОГО стенда и ключ, которого в
# шаблоне нет вовсе. Оба выглядели покрытыми, и мера работы переезда занижалась.
#
#   · ПУСТО — строка в шаблоне есть, значения нет. Падает ГРОМКО: страж набора
#     (`require_env_url` и его родня) утверждает ключ по имени ДО первого запроса;
#   · ЛИТЕРАЛ ЧУЖОГО СТЕНДА — значение непустое и правдоподобное (`usr…`, `prj…`),
#     но куёт его ЧУЖОЙ посев. Доезжает до службы и возвращается 403/404, то есть
#     ПОХОЖИМ НА ДЕФЕКТ ПРОДУКТА — самый дорогой из трёх исходов;
#   · НЕТ В ШАБЛОНЕ — строки под ключ нет вовсе. Лечится иначе: сперва строка,
#     потом значение.
#
# Названия — КОНСТАНТЫ, а не текст в двух местах: самопроверка ищет ровно их, и
# переименование не оставит её зелёной на прежнем слове.
KEY_STATE_EMPTY = "пусто"
KEY_STATE_LITERAL = "ЛИТЕРАЛ чужого стенда"
KEY_STATE_ABSENT = "НЕТ в шаблоне"

# КЛЮЧ, КОТОРЫЙ КОЛЛЕКЦИЯ ПИШЕТ САМА, ПРЕПЯТСТВИЕМ НЕ ЯВЛЯЕТСЯ. Генератор заводит
# сотни рабочих записей (`opId`, `_pollCount`, `_provisionalIds`, идентификаторы
# созданного по ходу): их производит сам прогон, и требовать их от стенда значило
# бы объявить неисполнимую возможность.
#
# НАПИСАНИЙ ТРИ, И РАСПОЗНАВАТЕЛЬ ЗНАЕТ ВСЕ ТРИ (`testing.md` §«Гейт на класс»,
# п. 7). Тело шага лежит в JSON строкой, поэтому кавычка бывает и обычной, и
# ЭКРАНИРОВАННОЙ (`set(\"k\"` — так генератор пишет разбор набора ключей: замер
# по дереву даёт 4 вхождения в одной коллекции), а снятие (`unset`) — та же
# принадлежность ключа коллекции, что и запись. Предикат без учёта экранирования
# объявил бы `_facadeByKid` и `_facadeOwnByKid` требованием к стенду — то есть
# завёл бы ЛОЖНУЮ находку там, где ключ производит сам прогон.
_Q = r"\\?['\"]"
OWN_KEY_RE = re.compile(
    r"pm\.(?:environment|collectionVariables|variables|globals)\.(?:set|unset)\(\s*"
    + _Q + r"([A-Za-z_][A-Za-z0-9_]*)" + _Q)

# Предъявитель, которого машинный посев не производит: он требует ЧЕЛОВЕКА.
CEREMONY_PREFIXES = ("jwtHuman", "ceremony")
# ИДЕНТИФИКАТОР ЧЕЛОВЕКА ЦЕРЕМОНИИ — та же природа, что у его предъявителя, и тот
# же производитель. Выведено ЗАМЕРОМ по кейсам, а не по имени: `humanAccCrudUserId`
# читается в папке, чей предъявитель — `jwtHumanAccCrud`, утверждением
# «ownerUserId == caller», и образец требует префикса `usr`. То есть ключ есть
# идентификатор ТОГО ЖЕ вызывающего, и машинный посев не производит его ни при
# каком устройстве: служебная учётка человеком не является, её идентификатор несёт
# префикс `sva`, а подставленное значение дало бы кейс, проверивший подстановку.
#
# ИМЯ ВРЁТ В ОБЕ СТОРОНЫ, поэтому образец узкий. `svaInviteeId` по имени похож на
# приглашённого человека, а кейсы читают его при `subjectType=service_account` —
# это МАШИННЫЙ ключ, и он обязан остаться в машинном препятствии.
CEREMONY_ID_RE = re.compile(r"^human[A-Z][A-Za-z0-9]*UserId$")
# ПРЕДЪЯВИТЕЛЬ ПОВЫШЕННОГО УРОВНЯ — тоже церемония, под каким бы именем слот ни
# стоял. Сходится из двух независимых мест: набор объявляет
# `jwtAccountAdminAStepUp` НЕПОДДЕЛЫВАЕМЫМ посевом (шапка
# `cases/iam-interactive-client.py`), а продукт берёт `kaname_acr` только из сессии
# поставщика (`token_enrichment_service.go` кладёт пробросом,
# `authzguard/acr_floor.go` читает) — служебная учётка от порога освобождена, то
# есть поднять уровень машине нечем.
CEREMONY_STEPUP_SUFFIX = "StepUp"
# АДРЕС ПОВЕРХНОСТИ — не удостоверение и не предмет посева: его НАЗЫВАЕТ посадка.
# Объединение всех трёх наборов адресов выше; своя поверхность здесь тоже нужна —
# посев её адреса пишет, и тогда ключ отсеется как покрытый, а не как адрес.
ADDRESS_VARS = EDGE_VARS | OWN_VARS | NEIGHBOUR_VARS


def is_ceremony_key(key: str) -> bool:
    """Ключ, производимый ЦЕРЕМОНИЕЙ человека: предъявитель либо его идентификатор."""
    return (key.startswith(CEREMONY_PREFIXES)
            or key.endswith(CEREMONY_STEPUP_SUFFIX)
            or bool(CEREMONY_ID_RE.match(key)))


def collections(newman: pathlib.Path) -> list[pathlib.Path]:
    return sorted((newman / "collections").glob("*.postman_collection.json"))


def template_keys(newman: pathlib.Path) -> dict[str, str]:
    """Объявленные ключи шаблона — СО ЗНАЧЕНИЯМИ.

    Прежде отдавалась пара множеств («все» и «пустые»), и вызывающий видел ровно
    два состояния ключа. Непосеянность их не исчерпывает (см. `key_state`), а
    третье — «в шаблоне его нет» — множеством «все» выражалось только вычитанием,
    которого никто не делал.
    """
    path = newman / "environments" / "local.postman_environment.template.json"
    if not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {v["key"]: str(v.get("value", "")) for v in doc.get("values", [])}


def used_keys(text: str) -> set[str]:
    return set(VAR_RE.findall(text)) | set(GET_RE.findall(text))


# ЯРЛЫК КРАЯ НАЗЫВАЕТ ТО, ЧТО ПРЕДИКАТ СЧИТАЕТ. Прежде он звался «край
# платформы» — утверждением о ПРОИЗВОДИТЕЛЕ, — а считалась переменная базового
# адреса. Для восемнадцати коллекций из сорока это утверждение ложно, и отличить
# ложное от истинного читатель мог только прочитав их содержимое — ту самую
# работу, которую перепись обещает не требовать.
#
# Ярлыки собственной поверхности и соседа НЕ переименованы, и это решение:
# `--minted-surface` посева — контракт между посевом и переписью, и его ключ
# `служба (собственный REST-фронт)` сменить здесь в одиночку значило бы развести
# два места об одном предмете. Предмет задачи — ярлык, читаемый как вердикт о
# производителе; у собственной поверхности адрес и производитель совпадают.
SURFACE_EDGE = "адресуется к краю платформы"


def surface_of(text: str, keys: set[str]) -> str:
    """АДРЕСАЦИЯ коллекции: к чьему базовому адресу стучатся её шаги.

    Это НЕ утверждение о производителе: решение о нём объявлено `PRODUCER_LEDGER`.
    """
    addressed = set(CFG_RE.findall(text)) | (keys & (EDGE_VARS | OWN_VARS | NEIGHBOUR_VARS))
    if addressed & OWN_VARS:
        return "служба (собственный REST-фронт)"
    if addressed & EDGE_VARS or "baseUrl" in keys:
        return SURFACE_EDGE
    if addressed & NEIGHBOUR_VARS:
        return "служба + недостижимый сосед"
    return "не определена"


def key_state(key: str, declared: dict[str, str], own: set[str]) -> str | None:
    """Состояние ключа: что стенд обязан ему дать. `None` — не обязан ничего.

    ТРИ СОСТОЯНИЯ, А НЕ ОДНО, и это замер: прежний предикат спрашивал только
    `k in empty` и потому не видел ни ключа с литералом чужого стенда (их в
    шаблоне 16 имён, читают их 35 коллекций), ни ключа, которого в шаблоне нет
    вовсе (4 имени, 9 коллекций).

    ДВА ВЫЧЕТА, И КАЖДЫЙ НАЗВАН, ЧТОБЫ ЕГО НЕ ПРИНЯЛИ ЗА СЛЕПОТУ:

      · ключ, который коллекция ПИШЕТ САМА, — её собственная рабочая запись, а не
        требование к стенду. Замер: таких вычетов из сегодняшних препятствий
        РОВНО НОЛЬ (147 пустых ключей, самозаписанных среди них 0), то есть вычет
        ничего не маскирует — он гатит ТОЛЬКО новое третье состояние;
      · АДРЕС с непустым значением. Его поверхность уже названа отдельной строкой
        («адресуется к краю платформы»), и второй раз он не считается. Пустой либо
        отсутствующий адрес состояние получает — его называет посадка, и эту
        строку долг печатает.
    """
    if key == "runId" or key in own:
        return None
    if key not in declared:
        return KEY_STATE_ABSENT
    if not declared[key]:
        return KEY_STATE_EMPTY
    if key in ADDRESS_VARS:
        return None
    return KEY_STATE_LITERAL


def blockers(surface: str, keys: set[str], declared: dict[str, str],
             own: set[str], minted_by_surface: dict[str, set[str]],
             runs: list[str] | None = None) -> tuple[list[str], dict[str, int]]:
    """Препятствия коллекции. `minted` — ключи, которые посев дерева УМЕЕТ писать.

    ПРЕДМЕТ СЧИТАЕТСЯ ПОКЛЮЧЕВО, А НЕ ОДНИМ ФЛАГОМ «посев есть». Флаг снимал
    препятствие у ВСЕХ сразу: первый заведённый посев объявил бы посеянными и
    коллекции края, чьих удостоверений он не куёт, — и объявил бы молча. Разница
    наблюдаема: у коллекции края остаётся и своё препятствие края, и непокрытые
    ключи, а у собственной поверхности не остаётся ни одного.

    СЛОВО «удостоверение» ЗДЕСЬ НЕ УПОТРЕБЛЯЕТСЯ, и это замер: из шести пустых
    ключей `kaname-own-rest-front` — на день замера единственной коллекции своей
    поверхности — два (`ownRestBaseUrl`,
    `ownInternalRestBaseUrl`) — АДРЕСА собственных фронтов, которые производит
    сам стенд. Прежняя редакция называла удостоверениями все шесть.

    ПРИРОД У НЕПОКРЫТОГО КЛЮЧА ТРИ, И РАЗНЫЕ У НИХ ПРОИЗВОДИТЕЛИ. Прежняя
    редакция сваливала их в одно препятствие «нужен машинный посев», и это не
    неточность формулировки, а ОБЪЯВЛЕНИЕ НЕИСПОЛНИМОЙ ВОЗМОЖНОСТИ: строка звала
    читателя завести машинный посев тому, чего машинный посев не производит.
    Перепись по стволу 37ace71de4 дала на 20 ключей машинного препятствия 4 ключа
    природы «человек» (`humanAccCrudUserId`, `humanAccRdDeriveUserId`,
    `humanAccRdSagaUserId`, `jwtAccountAdminAStepUp`) и 2 природы «адрес»
    (`iamJwksBaseUrl`, `providerPublicBaseUrl`) — то есть каждый третий.

      · ЦЕРЕМОНИЯ ЧЕЛОВЕКА — предъявитель человека либо его идентификатор;
      · АДРЕС поверхности — его называет посадка, не подписант;
      · машинный посев — удостоверение, которое чеканит сама служба.

    И ПОВЕРХНОСТЬ НАЗЫВАЕТСЯ В СТРОКЕ, А НЕ ТОЛЬКО СЧИТАЕТСЯ. Учёт по
    поверхности здесь с самого начала, а строка про него молчала: «не пишет ни
    один посев ЭТОЙ поверхности» не называла, КАКОЙ. Цена измерена и это план
    целой полосы: печатный долг показывал 39 коллекций с препятствием «нужен
    машинный посев», под него заводилась полоса «расширить посев», — а все 39
    суть коллекции КРАЯ, которым посев собственного фронта не зачитывается НИ
    ОДНИМ ключом by construction (ось 3г). Число, на которое ставился план,
    сдвинуть было нечем, и увидеть это по печатному долгу читатель не мог.

    КЛЮЧ ЗАЧИТЫВАЕТСЯ ТОЛЬКО СВОЕЙ ПОВЕРХНОСТИ, И ЭТО ЗАМЕР. Учёт по одному
    перечню имён снял препятствие посева у ВОСЬМИ коллекций, из которых СЕМЬ —
    коллекции КРАЯ платформы: их `jwtAccountAdmin*` производит чужой посев чужого
    стенда, а совпало только ИМЯ ключа. Предъявитель, выкованный на собственном
    фронте службы, краю не годится ничем — ни издателем, ни адресатом, ни
    арендатором. Поэтому `minted_by_surface` — отображение «поверхность → ключи»,
    и посев, своей поверхности не объявивший, не зачитывается НИКОМУ.
    """
    out = []
    if runs is not None and not runs:
        out.append("ни один шаг конвейера её не гоняет "
                   "(объявление читается разобранным YAML)")
    if surface == SURFACE_EDGE:
        out.append("адресуется к краю платформы (переменная базового адреса)")
    minted = minted_by_surface.get(surface, set())
    states = {k: key_state(k, declared, own) for k in sorted(keys)}
    need = [k for k, s in states.items() if s is not None]
    # ПЕРЕПИСЬ СЧИТАЕТ НЕПОСЕЯННОЕ, А НЕ ВСЁ ОБЪЯВЛЕННОЕ: ключ, который посев ЭТОЙ
    # поверхности куёт, состоянием долга не является — иначе величина росла бы
    # вместе с посевом, то есть двигалась бы в обратную сторону от цели.
    census = {KEY_STATE_EMPTY: 0, KEY_STATE_LITERAL: 0, KEY_STATE_ABSENT: 0}
    for k in need:
        if k not in minted:
            census[states[k]] += 1

    def named(ks: list[str]) -> str:
        """Ключи С ИХ СОСТОЯНИЕМ: чинятся они разным, и знать это надо сразу."""
        shown = ", ".join(f"{k} ({states[k]})" for k in ks[:3])
        return shown + ("…" if len(ks) > 3 else "")

    ceremony = [k for k in need if is_ceremony_key(k)]
    rest = [k for k in need if k not in ceremony and k not in minted]
    address = [k for k in rest if k in ADDRESS_VARS]
    machine = [k for k in rest if k not in ADDRESS_VARS]
    if ceremony:
        out.append(f"нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА ({len(ceremony)} ключ(ей) — "
                   f"предъявитель человека либо его идентификатор, производит их "
                   f"одна и та же церемония, а машинный посев не производит ни "
                   f"одного: {named(ceremony)})")
    if address:
        out.append(f"нужен АДРЕС поверхности «{surface}» ({len(address)} ключ(ей) — "
                   f"его НАЗЫВАЕТ посадка, ни один подписант его не выпускает: "
                   f"{named(address)})")
    if machine:
        out.append(f"нужен машинный посев поверхности «{surface}» "
                   f"({len(machine)} ключ(ей) окружения, которых не пишет ни один "
                   f"посев ЭТОЙ поверхности: {named(machine)})")
    return out, census


# ─────────────── ПРОГОН — ЭТО КОМАНДА ПРОГОНЩИКА, А НЕ ТЕКСТ ТЕЛА ─────────────
#
# Коллекцию гоняет шаг, чьё тело `run:` ВЫЗЫВАЕТ прогонщик набора
# (`tests/newman/scripts/run.sh`) с аргументом `--service <stem>`. Прежний
# распознаватель искал образец `--service <stem>` по всему телу и потому
# засчитывал прогоном флаг в комментарии тела, в строковом литерале `echo` и в
# данных heredoc: шаг, у которого прогон сняли, а упоминание оставили, числился
# гоняющим, и держателя у такой коллекции перепись не требовала.
#
# Тело разбирается как программа bash — оболочка шагов дерева (`defaults.run.shell:
# bash`, у GitHub-исполнителя она же по умолчанию): слова, кавычки, продолжение
# строки, комментарий с начала слова, разделители команд, перенаправления,
# heredoc и подстановка команды. Прогоном считается простая команда, чьё слово
# команды — путь к прогонщику, после необязательных присваиваний окружения,
# служебных слов (`if`, `then`, `!`, `exec`, …) и интерпретатора `bash`/`sh`;
# `bash -c '<строка>'` разбирается как вложенная программа. Шаг с иной
# оболочкой (`shell: python`, `pwsh`) не читается вовсе: его тело — не bash.
#
# ГРАНИЦА НАЗВАНА: судится команда, а не достижимость. Команда в теле функции
# или в ветке, которая не исполнится, засчитывается; условие `if:` шага и
# задания не вычисляется. Пропуск в обратную сторону — громкий: имя коллекции,
# вычисляемое во время прогона (`--service "$s"`), прогоном не засчитывается, и
# перепись потребует у такой коллекции держателя.
RUNNER_RE = re.compile(r"(?:^|/)scripts/run\.sh$")
STEM_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PREFIX_WORDS = frozenset({"if", "then", "elif", "else", "do", "while", "until",
                           "!", "{", "time", "exec", "command", "env"})
_SHELLS = frozenset({"bash", "sh"})
# Операторы, отсортированные по длине: первым совпадает самый длинный.
_SEP_OPS = ("&&", "||", ";;&", ";;", ";&", "|&", ";", "&", "|")
_REDIR_OPS = ("<<<", "<<-", "&>>", "<<", ">>", "<&", ">&", "&>", "<>", ">|",
              "<", ">")
_OPS = tuple(sorted(_SEP_OPS + _REDIR_OPS, key=len, reverse=True))


class _ShellEOF(Exception):
    """Кавычка либо подстановка не закрыта до конца тела: bash отказал бы."""


def _braced(s: str, i: int, word: list[str]) -> int:
    """`${…}` целиком — одно слово: внутри бывают пробел и `}` вложенной формы."""
    depth, j = 0, i
    while j < len(s):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                word.append("$" + s[i:j + 1])
                return j + 1
        j += 1
    raise _ShellEOF


def _dquoted(s: str, i: int, word: list[str], cmds: list[list[str]]) -> int:
    """Тело двойных кавычек с позиции после `"`; подстановки внутри — команды."""
    while i < len(s):
        c = s[i]
        if c == '"':
            return i + 1
        if c == "\\" and i + 1 < len(s) and s[i + 1] in '$`"\\\n':
            if s[i + 1] != "\n":
                word.append(s[i + 1])
            i += 2
        elif c == "$" and s.startswith("$(", i):
            inner, i = _shell_list(s, i + 2, ")")
            cmds.extend(inner)
            word.append("$(…)")
        elif c == "`":
            inner, i = _shell_list(s, i + 1, "`")
            cmds.extend(inner)
            word.append("`…`")
        elif c == "$" and s.startswith("${", i):
            i = _braced(s, i + 1, word)
        else:
            word.append(c)
            i += 1
    raise _ShellEOF


def _skip_heredocs(s: str, i: int, pending: list[tuple[str, bool]]) -> int:
    """С позиции после перевода строки пропускает тела heredoc — это данные."""
    for delim, strip_tabs in pending:
        while i < len(s):
            end = s.find("\n", i)
            line = s[i:] if end < 0 else s[i:end]
            i = len(s) if end < 0 else end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                break
    pending.clear()
    return i


def _shell_list(s: str, i: int, closer: str | None) -> tuple[list[list[str]], int]:
    """Простые команды программы bash с позиции `i` до `closer` (либо до конца).

    Команда — список слов после снятия кавычек. Возвращает команды и позицию
    после закрывающего знака. Незакрытая кавычка либо подстановка внутри
    вложенного разбора — `_ShellEOF` вызывающему; на верхнем уровне
    (`closer is None`) недописанная команда отбрасывается вместе с подстановками
    внутри неё, как отбросил бы её bash, а завершённые до неё сохраняются — их
    bash уже исполнил.
    """
    cmds: list[list[str]] = []
    cur: list[str] = []
    word: list[str] | None = None
    target: str | None = None      # "delim<-" | "delim" | "skip" — судьба слова
    pending: list[tuple[str, bool]] = []
    depth = 0
    mark = 0                       # len(cmds) после последней завершённой команды

    def end_word() -> None:
        nonlocal word, target
        if word is None:
            return
        w = "".join(word)
        word = None
        if target in ("delim", "delim<-"):
            pending.append((w, target == "delim<-"))
        elif target != "skip":
            cur.append(w)
        target = None

    def end_cmd() -> None:
        nonlocal cur, target, mark
        end_word()
        # Перенаправление не переходит границу команды: `<(` открывает новую.
        target = None
        if cur:
            cmds.append(cur)
        cur = []
        mark = len(cmds)

    n = len(s)
    try:
        while i < n:
            c = s[i]
            if closer == "`" and c == "`":
                end_cmd()
                return cmds, i + 1
            if closer == ")" and c == ")" and depth == 0:
                end_cmd()
                return cmds, i + 1
            if c == "\\":
                if s.startswith("\\\n", i):
                    i += 2
                    continue
                word = (word or []) + [s[i + 1:i + 2]]
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise _ShellEOF
                word = (word or []) + [s[i + 1:j]]
                i = j + 1
                continue
            if c == '"':
                word = word or []
                i = _dquoted(s, i + 1, word, cmds)
                continue
            if c == "$" and s.startswith("$'", i):
                j, buf = i + 2, []
                while j < n and s[j] != "'":
                    esc = s[j] == "\\" and j + 1 < n
                    buf.append(s[j + 1] if esc else s[j])
                    j += 2 if esc else 1
                if j >= n:
                    raise _ShellEOF
                word = (word or []) + buf
                i = j + 1
                continue
            if c == "$" and s.startswith("$(", i):
                inner, i = _shell_list(s, i + 2, ")")
                cmds.extend(inner)
                word = (word or []) + ["$(…)"]
                continue
            if c == "`":
                inner, i = _shell_list(s, i + 1, "`")
                cmds.extend(inner)
                word = (word or []) + ["`…`"]
                continue
            if c == "$" and s.startswith("${", i):
                word = word or []
                i = _braced(s, i + 1, word)
                continue
            if c == "#" and word is None:
                j = s.find("\n", i)
                i = n if j < 0 else j
                continue
            if c in " \t":
                end_word()
                i += 1
                continue
            if c == "\n":
                end_cmd()
                i = _skip_heredocs(s, i + 1, pending)
                continue
            if c in "()":
                end_cmd()
                depth += 1 if c == "(" else -1
                i += 1
                continue
            op = next((o for o in _OPS if s.startswith(o, i)), None)
            if op is None:
                word = (word or []) + [c]
                i += 1
                continue
            if op in _SEP_OPS:
                end_cmd()
            else:
                # Номер дескриптора перед перенаправлением (`2>&1`) — не слово.
                if word is not None and "".join(word).isdigit():
                    word = None
                end_word()
                target = {"<<": "delim", "<<-": "delim<-"}.get(op, "skip")
            i += len(op)
        if closer is not None:
            raise _ShellEOF
        end_cmd()
        return cmds, i
    except _ShellEOF:
        if closer is not None:
            raise
        del cmds[mark:]
        return cmds, n


def shell_commands(body: str) -> list[list[str]]:
    """Простые команды тела шага `run:` — разбором, а не поиском по тексту."""
    return _shell_list(body, 0, None)[0]


def runner_stems(argv: list[str]) -> list[str]:
    """Коллекции, которые называет ОДНА простая команда, — если она прогонщик."""
    k = 0
    while k < len(argv) and (argv[k] in _PREFIX_WORDS or _ASSIGN_RE.match(argv[k])):
        k += 1
    if k < len(argv) and argv[k].rsplit("/", 1)[-1] in _SHELLS:
        k += 1
        while k < len(argv) and argv[k].startswith("-"):
            if argv[k] == "-c" and k + 1 < len(argv):
                return [st for sub in shell_commands(argv[k + 1])
                        for st in runner_stems(sub)]
            k += 1
    if k >= len(argv) or not RUNNER_RE.search(argv[k]):
        return []
    out: list[str] = []
    j = k + 1
    while j < len(argv):
        # Та же грамматика, что у разбора прогонщика: `--service` берёт следующее
        # слово целиком. Имя, собранное во время прогона, не литерал — и не счёт.
        if argv[j] == "--service" and j + 1 < len(argv):
            if STEM_RE.match(argv[j + 1]):
                out.append(argv[j + 1])
            j += 2
            continue
        j += 1
    return out


def _step_shell(step: dict, job: dict, doc: dict) -> str:
    """Оболочка шага: шаг → `defaults.run` задания → процесса → bash исполнителя."""
    def run_defaults(owner: dict) -> object:
        d = owner.get("defaults")
        return d.get("run") if isinstance(d, dict) else None

    for holder in (step, run_defaults(job), run_defaults(doc)):
        if isinstance(holder, dict) and isinstance(holder.get("shell"), str):
            return holder["shell"]
    return "bash"


def pipeline_runs(workflows: pathlib.Path) -> dict[str, list[str]]:
    """{stem: [«задание/шаг», …]} — какие коллекции гоняет объявление конвейера.

    Читается РАЗОБРАННЫЙ YAML: ключи `jobs:`, их `steps[]`, тело `run:`. Имя
    коллекции стоит в комментариях объявления десятки раз, поэтому подстрочный
    предикат считал бы собственное объяснение — тот же порядок, что требует ban #17
    от гейта на кириллический ключ задания. Тело `run:` тоже читается РАЗОБРАННЫМ —
    как программа bash (`shell_commands`), и прогоном засчитывается только
    команда прогонщика (`runner_stems`), а не упоминание флага в её тексте.

    Пустой словарь означает РОВНО «ни один шаг не гоняет ни одной коллекции».
    Отличить это от «объявлений не прочитано» — забота вызывающего: он спрашивает
    `workflow_files` отдельно.
    """
    import yaml  # локально: его отсутствие — третий исход, а не отказ разбора

    out: dict[str, list[str]] = {}
    for f in workflow_files(workflows):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise Unmet(f"{f.name} не разбирается как YAML: {e}") from e
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for i, stepv in enumerate(job.get("steps") or []):
                if not isinstance(stepv, dict):
                    continue
                body = stepv.get("run")
                if not isinstance(body, str):
                    continue
                shell = _step_shell(stepv, job, doc).split()
                if not shell or shell[0].rsplit("/", 1)[-1] not in _SHELLS:
                    continue
                label = f"{f.name}:{job_id}/{stepv.get('name') or f'шаг {i + 1}'}"
                for argv in shell_commands(body):
                    for stem in runner_stems(argv):
                        out.setdefault(stem, []).append(label)
    return out


def workflow_files(workflows: pathlib.Path) -> list[pathlib.Path]:
    if not workflows.is_dir():
        return []
    return sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml"))


class Unmet(Exception):
    """Условие не создано: величина не измерена, и ноль вместо неё — ложь."""


def seed_scripts(seed_dir: pathlib.Path) -> list[pathlib.Path]:
    """Посевы дерева — ОТБОРОМ по имени, а не перечнем и не перечнем исключений.

    Отбор глобом, потому что альтернативы хуже обе: выписанный перечень посевов
    разошёлся бы с деревом в одну сторону (новый посев в него не попал бы), а
    «любой .py/.sh, кроме названного» заставлял бы ИСПОЛНЯТЬ соседние файлы
    каталога ради вопроса, посев ли это. Прежняя редакция несла именно такое
    исключение по имени — у него не было предмета, кроме одного файла.
    """
    if not seed_dir.is_dir():
        return []
    out = sorted(p for p in seed_dir.glob("seed_*.py") if p.is_file())
    out += sorted(p for p in seed_dir.glob("seed-*.sh") if p.is_file())
    return out


def _ask(script: pathlib.Path, flag: str) -> tuple[int, list[str]]:
    cmd = ([sys.executable, str(script), flag] if script.suffix == ".py"
           else [str(script), flag])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return proc.returncode, [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def minted_by_seeds(scripts: list[pathlib.Path]
                    ) -> tuple[dict[str, set[str]], list[str]]:
    """Спросить у КАЖДОГО посева, какие ключи он пишет И ДЛЯ КАКОЙ ПОВЕРХНОСТИ.

    Перепись не держит второй копии ни перечня, ни поверхности: копия разошлась бы
    с посевом молча и разошлась бы в одну сторону. Посев, который на вопрос не
    отвечает, в счёт НЕ идёт и называется отдельной строкой — «посев есть, а что он
    пишет, неизвестно» и «посева нет» ведут читателя в разные места.

    ПОВЕРХНОСТЬ СПРАШИВАЕТСЯ ОТДЕЛЬНЫМ ВОПРОСОМ И FAIL-CLOSED. Посев, назвавший
    ключи и НЕ назвавший поверхность, не зачитывается никому: молча зачесть его
    значило бы вернуть учёт по совпадению имён, который и дал 40 → 32 через два
    разных стенда.
    """
    minted: dict[str, set[str]] = {}
    mute: list[str] = []
    for script in scripts:
        try:
            rc_keys, keys = _ask(script, "--minted-keys")
        except (OSError, subprocess.SubprocessError) as e:
            mute.append(f"{script.name}: не запустился ({e})")
            continue
        if rc_keys != 0 or not keys:
            mute.append(f"{script.name}: не назвал ни одного ключа "
                        f"(код {rc_keys})")
            continue
        try:
            rc_surf, surf = _ask(script, "--minted-surface")
        except (OSError, subprocess.SubprocessError) as e:
            mute.append(f"{script.name}: НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ "
                        f"(не запустился: {e})")
            continue
        if rc_surf != 0 or len(surf) != 1:
            mute.append(f"{script.name}: НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ "
                        f"(код {rc_surf}, строк {len(surf)}) — его {len(keys)} "
                        f"ключ(ей) не зачтены НИКОМУ: имя ключа совпадает через "
                        f"разные стенды, а предъявитель не переносится")
            continue
        minted.setdefault(surf[0], set()).update(keys)
    return minted, mute


def ceremony_need_of(text: str, declared: dict[str, str]) -> list[str]:
    """Ключи ЦЕРЕМОНИИ, которых коллекция ждёт от посева, а не ставит сама.

    ОДНА функция на двух читателей: этот разрез и объявление волны церемонии
    (`tests/authz-fixtures/ceremony_credentials.py`). Перечень волны обязан быть
    равен перечню «нужна церемония» отсюда, и равенство держится построением —
    второй предикат того же предмета разошёлся бы с первым молча.
    """
    own = set(OWN_KEY_RE.findall(text))
    return sorted(k for k in used_keys(text)
                  if key_state(k, declared, own) is not None and is_ceremony_key(k))


def ceremony_need(newman: pathlib.Path) -> dict[str, list[str]]:
    """По КАЖДОЙ коллекции набора — ключи церемонии, которых она ждёт от посева.

    Пустой обход — отказ, а не пустой ответ: «ни одной коллекции не нужна
    церемония» и «не прочитано ни одной коллекции» ведут читателя в разные места.
    """
    cols = collections(newman)
    if not cols:
        raise ValueError(f"в {newman / 'collections'} не прочитано ни одной коллекции")
    declared = template_keys(newman)
    if not declared:
        raise ValueError("шаблона окружения нет — природу ключа вывести не из чего")
    return {col.name[: -len(".postman_collection.json")]:
            ceremony_need_of(col.read_text(encoding="utf-8"), declared)
            for col in cols}


def survey(newman: pathlib.Path, workflows: pathlib.Path):
    """Разрез дерева: (гоняемые, заблокированные, по поверхности, по препятствию, …).

    Вынесен отдельной функцией затем, чтобы держатель согласованности
    (`tests/newman/scripts/pipeline_claims_test.py`) спрашивал ТУ ЖЕ величину, а не
    считал свою: второй счётчик того же предмета расходится с первым молча.
    """
    cols = collections(newman)
    declared = template_keys(newman)
    if not cols:
        raise ValueError(f"в {newman/'collections'} не прочитано ни одной коллекции — "
                         f"перепись беспредметна, а не пуста")
    if not declared:
        raise ValueError("шаблона окружения нет — препятствия вывести не из чего")

    wfs = workflow_files(workflows)
    if not wfs:
        raise Unmet(f"в {workflows} не прочитано ни одного объявления конвейера — "
                    f"величина «гоняется» НЕ ИЗМЕРЕНА, и ноль вместо неё был бы ложью")
    runs = pipeline_runs(workflows)

    seed_dir = newman.parent / "authz-fixtures"
    scripts = seed_scripts(seed_dir)
    minted, mute = minted_by_seeds(scripts)

    runnable, blocked = [], []
    by_surface: dict[str, int] = {}
    by_blocker: dict[str, int] = {}
    by_state: dict[str, int] = {KEY_STATE_EMPTY: 0, KEY_STATE_LITERAL: 0,
                                KEY_STATE_ABSENT: 0}
    ceremony_need: dict[str, list[str]] = {}
    for col in cols:
        text = col.read_text(encoding="utf-8")
        keys = used_keys(text)
        surface = surface_of(text, keys)
        by_surface[surface] = by_surface.get(surface, 0) + 1
        # Имя коллекции — БЕЗ приставки формата: `Path.stem` снимает только `.json`,
        # оставляя `.postman_collection`, и перепись читалась бы шумом.
        stem = col.name[: -len(".postman_collection.json")]
        own = set(OWN_KEY_RE.findall(text))
        ceremony_need[stem] = ceremony_need_of(text, declared)
        bl, states = blockers(surface, keys, declared, own, minted,
                              runs.get(stem, []))
        for state, n in states.items():
            by_state[state] += n
        if bl:
            blocked.append((stem, surface, bl))
            for b in bl:
                head = b.split(" (")[0]
                by_blocker[head] = by_blocker.get(head, 0) + 1
        else:
            runnable.append((stem, surface, runs.get(stem, [])))
    return (cols, wfs, runs, scripts, minted, mute, runnable, blocked,
            by_surface, by_blocker, by_state, ceremony_need)


def blocked_stems(newman: pathlib.Path, workflows: pathlib.Path) -> dict[str, list[str]]:
    """{stem: [препятствие, …]} — для держателя согласованности дерева."""
    blocked = survey(newman, workflows)[7]
    return {stem: bl for stem, _, bl in blocked}


# ─────────────────── ВЕДОМОСТЬ ПРОИЗВОДИТЕЛЯ: РЕШЕНИЕ, А НЕ ВЫВОД ───────────
#
# Ключ — стебель коллекции, значение — (категория, довод, держатель). Источник решения —
# разрез #24, читавший ПРОДУКТ: какие свойства утверждает коллекция и чей
# производитель их даёт. Адрес, по которому она сегодня стучится, решения не
# определяет: генератор приписывает переменную края каждому шагу сам.
#
# КАТЕГОРИИ ЗАКРЫТЫ, и у каждой свой исход:
#   A — производитель СЛУЖБА: переезжает на собственный фронт;
#   B — служба, но нужен ЧЕЛОВЕЧЕСКИЙ предъявитель: переезжает после полосы личности;
#   C — производитель КРАЙ платформы: остаётся её предметом;
#   D — не про сущности службы вовсе: остаётся в монорепо.
#
# ВЕДОМОСТЬ СВЕРЯЕТСЯ С ДЕРЕВОМ В ОБЕ СТОРОНЫ, и это то, чем снят довод против
# второго списка: коллекция без записи роняет перепись, запись без коллекции
# роняет её же. Перечень поэтому не может ни отстать от дерева, ни пережить его.
#
# ДЕРЖАТЕЛЬ — ТРЕТЬЕ ПОЛЕ, и оно пусто ровно у тех коллекций, которые гоняет шаг
# конвейера: производитель у них уже есть. У остальных держатель — задача, которая
# коллекцию прогонит, в закрытой форме `HOLDER_RE`. Категория говорит, ЧЕЙ
# производитель отвечает на утверждения; держатель — КТО снимет препятствие.
# Это разные вопросы: у одной категории бывают разные держатели (B — церемония
# либо недостижимый сосед, #156), а одна задача держит коллекции разных категорий.
PRODUCER_CATEGORIES = {
    "A": "служба",
    "B": "служба + человеческий предъявитель",
    "C": "край платформы",
    "D": "чужой домен",
}

# ФОРМА ДЕРЖАТЕЛЯ ЗАКРЫТА: адрес задачи и, через тире, что она сделает. Адрес —
# с владельцем и репозиторием, потому что держатель бывает и в дереве платформы, а
# голый `#N` читался бы номером того репозитория, где его прочли. Состояние задачи
# в трекере перепись НЕ сверяет — сверка сетевая; это названо строкой вывода.
HOLDER_RE = re.compile(r"^PRO-Robotech/[a-z0-9][a-z0-9-]*#[1-9][0-9]* — \S")
HOLDER_REF_RE = re.compile(r"^(PRO-Robotech/[a-z0-9][a-z0-9-]*#[1-9][0-9]*)")

# Держатели, общие нескольким позициям, — ИМЕНОВАННЫЕ ВЕЛИЧИНЫ, а не текст в
# одиннадцати местах: разойдись копии, свод по держателю посчитал бы две задачи.
_HOLDER_CEREMONY = (
    "PRO-Robotech/kaname#398 — объявление и посев волны церемонии в дереве службы: "
    "человеческий предъявитель на стенде, прогон волны `run-ceremony.sh`")
_HOLDER_EDGE_HALF = (
    "PRO-Robotech/kaname#155 — исход половины предмета, которую производит край: "
    "расщепить коллекцию либо переутвердить по фактическому производителю")
# Четырнадцать коллекций C и D: производитель их утверждений — край платформы
# либо чужой домен, а копий в платформе нет (набор iam снят оттуда 2026-09-12).
_HOLDER_PLATFORM_HOME = (
    "PRO-Robotech/kaname#415 — дом по предмету и шаг конвейера этого дома: "
    "переутвердить по фактическому производителю, перенести в платформу "
    "расщеплением либо снять вместе с предметом")
# Две коллекции производителя-службы, которые адресуются краю: у каждой своё
# условие стенда, а задача одна.
# Членство уже гоняет задание `stand` собственным фронтом, и его запись держателя
# снята тем же изменением, что завело шаг. Осталась вторая: регистрация клиента
# идёт в поставщика, которого на автономном стенде нет.
_HOLDER_SERVICE_ON_EDGE = (
    "PRO-Robotech/kaname#416 — прогон на стенде с адресом и посевом: интерактивный "
    "клиент — на посадке `own` поверх своей выдачи клиента (kaname#313), "
    "собственным внутренним фронтом и машинным посевом этой посадки")
_HOLDER_SECOND_FACTOR = (
    "PRO-Robotech/kaname#417 — срез отчёта знает удостоверения полосы второго "
    "фактора, и задание `chart-own` гоняет набор")

PRODUCER_LEDGER: dict[str, tuple[str, str, str]] = {
    "authz-deny": ("B", "матрица отказов по 6 классам субъектов; `jwtHumanCeremonyNoBindings` — человек", _HOLDER_CEREMONY),
    "authz-failclosed": ("C", "утверждает ПРОИЗВОДИТЕЛЯ отказа и он измерен — край, полоса чтения отзыва; условие создаётся сворачиванием базы и до службы не доходит", _HOLDER_PLATFORM_HOME),
    "authz-sa-apitoken": ("D", "20 из 30 запросов — `vpc`; половина ALLOW определена семантикой vpc («project-viewer-GATED List … owned by kacho-vpc»)", _HOLDER_PLATFORM_HOME),
    "basic-access-token": ("A", "выдача и отзыв — ручки iam. ПОЛОВИНА ПРЕДМЕТА ПРОИЗВОДИТСЯ КРАЕМ и потому здесь НЕ гоняется: предъявление непрозрачного секрета ресурсному эндпоинту делает край, а служба лишь АВТОРИТЕТ о нём (`InternalIAMService/ResolveBasicCredential`, чья шапка говорит «Край зовёт этот глагол»); рубеж собственного фронта проверяет подпись и непрозрачную строку не разбирает by construction. Исход выбирается задачей kaname#155", _HOLDER_EDGE_HALF),
    "docker-lane-credential-kind": ("A", "«адрес `:9096` — собственная ручка iam»; предмет — полоса выдачи kaname, не данные реестра", ""),
    "geo-read": ("D", "все 4 запроса — `/geo/v1`, путей `iam` ноль", _HOLDER_PLATFORM_HOME),
    "iam-access-binding-account-scope": ("B", "выдачи на ярусе аккаунта; все утверждения — свои коды, свои тела, своя модель. КАТЕГОРИЯ ИСПРАВЛЕНА С A: читает `jwtAccountAdminAStepUp` — предъявителя ЦЕРЕМОНИИ, которого машинный посев не производит", _HOLDER_CEREMONY),
    "iam-access-binding-include-revoked": ("B", "чтение с отозванными; статусов кроме 200 не утверждает вовсе. КАТЕГОРИЯ ИСПРАВЛЕНА С A: читает `jwtAccountAdminAStepUp` — предъявителя ЦЕРЕМОНИИ, которого машинный посев не производит", _HOLDER_CEREMONY),
    "iam-access-binding-redesign": ("A", "один предъявитель, `iam` целиком, `md.resource` — ноль", ""),
    "iam-account": ("B", "9 человеческих предъявителей из 14; аккаунт принадлежит человеку by construction", _HOLDER_CEREMONY),
    "iam-account-redesign": ("B", "7 человеческих предъявителей из 10", _HOLDER_CEREMONY),
    "iam-authz-grant-check-propagation": ("C", "1 утверждение читает `md.resource`", _HOLDER_PLATFORM_HOME),
    "iam-flat-authz-vbc": ("A", "вывод типа субъекта из префикса id — предмет службы; на строгий разбор края намеренно НЕ опирается", ""),
    "iam-group": ("C", "2 утверждения читают `md.resource`", _HOLDER_PLATFORM_HOME),
    "iam-interactive-client": ("B", "Create/Delete регистрируют клиента в ВНЕШНЕМ поставщике (`providerClients`, адаптер `*clients.HydraAdminClient`); на автономном стенде поставщик об…", _HOLDER_SERVICE_ON_EDGE),
    "iam-internal-only-check": ("C", "предмет — маршрутная таблица ОБЪЯВЛЕННОГО внешнего слушателя края (:8443); «ban #6 is a property of the LISTENER»", _HOLDER_PLATFORM_HOME),
    "iam-invite-grant-fga": ("A", "приглашение → выдача → сходимость модели, всё внутри iam", ""),
    "iam-invite-resend": ("A", "повторная отправка письма приглашения — глагол службы; ограничение частоты и hide-existence производит своя дверь; письмо у приёмника наблюдает стенд с почтой (MAIL-05), не этот набор", ""),
    "iam-list-visibility": ("A", "видимость перечня по членству; один предъявитель, только 200", ""),
    "iam-membership-create": ("A", "создание членства (kaname#181): два машинных распорядителя аккаунтов, исход читается своим списком аккаунта, отказы — своя дверь (403/7 на чужом, несуществующем и пустом аккаунте; `md.resource` не читается)", ""),
    "iam-membership-mine": ("B", "свой список членств `MembershipService.ListMine` (kaname#206, IAM-ID-2 S2 §2.5): читает `jwtHumanCeremonyNoBindings` — человек без выдач видит ровно свои строки; распорядитель аккаунта приглашает его машинным предъявителем; все утверждения — свои коды и тела службы (сужение по субъекту, страница `pageSize`/`pageToken`, `?userId=` ответа не меняет), `md.resource` не читается", _HOLDER_CEREMONY),
    "iam-membership-read": ("B", "`jwtHumanCeremony` + `…StepUp` — человек с поднятым уровнем", _HOLDER_CEREMONY),
    "iam-permission-catalog": ("A", "каталог прав — данные службы", ""),
    "iam-project": ("A", "CRUD проекта + чужой объект неотличим от промаха (404/code 5) — производит своя дверь", ""),
    "iam-project-edge-format": ("C", "один кейс, вынесенный из `iam-project` при её переезде: пара 400/3 на неизвестной приставке — короткое замыкание КРАЯ по форме до проверки прав; собственный фронт этого шага не несёт и отвечает 403/7 от проверки прав (замер на автономном стенде 2026-09-16)", _HOLDER_PLATFORM_HOME),
    "iam-rbac-rules-labels": ("A", "метки правил роли; один предъявитель, только 200", ""),
    "iam-rbac-scope-grant": ("A", "выдача на области; внутренний `iam:check` через внутренний фронт", ""),
    "iam-rbac-subjects": ("A", "субъекты выдач; единственное упоминание края — комментарий о том, ГДЕ живёт внутренний RPC", ""),
    "iam-read-authz-vget": ("B", "несущий кейс — «выдали не-владельцу ЧЕЛОВЕКУ → читает»", _HOLDER_CEREMONY),
    "iam-role": ("C", "1 утверждение читает `md.resource` (`assert_unscoped_rejected('iam.roles.create','account:*')`)", _HOLDER_PLATFORM_HOME),
    "iam-role-redesign": ("A", "форма роли; утверждает ОТСУТСТВИЕ полей области на роли — своя проекция", ""),
    "iam-service-account": ("C", "2 утверждения читают `md.resource`", _HOLDER_PLATFORM_HOME),
    "iam-subject-privileges-read": ("A", "чтение привилегий субъекта; 403 без `md.resource`", ""),
    "iam-system-grant-visibility": ("A", "один запрос, видимость системной выдачи", ""),
    "iam-token-facade-conformance": ("C", "утверждает, что КРАЙ принял предъявленное удостоверение, и что поверхности внешнего поставщика недосягаемы ЧЕРЕЗ край; дозванивается до `/admin/cli…", _HOLDER_PLATFORM_HOME),
    "iam-user": ("C", "5 утверждений читают `md.resource`. Сверх того нужен человек (`jwtHumanCeremony`) — то есть даже расщепление оставит остаток в B", _HOLDER_PLATFORM_HOME),
    "iam-whoami": ("B", "оба предъявителя человеческие; утверждает `subject = user:<id>`", _HOLDER_CEREMONY),
    "label-revoke-iam": ("A", "отзыв по метке ВНУТРИ iam; чужих домéнов ноль", ""),
    "label-revoke-nlb": ("D", "`geo` + `nlb` + `iam`; проверяет связку через границу домена", _HOLDER_PLATFORM_HOME),
    "label-revoke-storage": ("D", "`geo` + `storage` + `iam`", _HOLDER_PLATFORM_HOME),
    "label-revoke-vpc": ("D", "`vpc` + `iam`, 21 запрос в vpc", _HOLDER_PLATFORM_HOME),
    "rbac-subject-channel-equivalence": ("B", "равнозначность каналов субъекта требует человека как одного из каналов", _HOLDER_CEREMONY),
    "rbac-visibility-set": ("B", "`jwtHumanRbacVisSet` + `…StepUp`", _HOLDER_CEREMONY),
    # Коллекция СОБСТВЕННОГО фронта: она и есть поверхность службы, поэтому
    # разрезом #24 не судилась — судить было нечего.
    "kaname-own-rest-front": ("A", "собственный REST-фронт службы: предмет коллекции и есть эта поверхность", ""),
    # Полоса входа паролем (Ф3, kacho#1269): собственный слушатель формы службы,
    # предъявителя-JWT не читает вовсе — человек предъявляет пароль, а сессию
    # выдаёт сама служба. Условие стенда — посадка `own`, лист с SAN края и посев
    # человека со способом входа: их создаёт задание `chart-own` (стенд чарта
    # посадки `own` и `seed_login_lane.py`); без них — третья категория.
    "kaname-login-lane": ("A", "собственный слушатель формы службы (Р7, Р16): вход, выход, признак формы, смена пароля — всё производит служба; ни одного `jwt…` ключа не читает, человек предъявляет пароль", ""),
    # Восстановление доступа кодом по почте (Ф5, kacho#1271): два глагола на ТОМ ЖЕ
    # слушателе формы, что вход (`internal/handler/loginlanehttp`), те же две
    # переменные (`loginLaneBaseUrl`, `loginLaneEmail`) и то же условие стенда —
    # посадка `own`; без неё каждый шаг уходит в третью категорию помеченным
    # утверждением. Счастливого завершения с настоящим кодом набор не несёт: код
    # уходит письмом, и его наблюдает стенд с почтой (ID-MAIL-1 MAIL-04), не край.
    "kaname-recovery-lane": ("A", "собственный слушатель формы службы, полоса входа (Ф5-01, Ф5-02, Ф5-04): один ответ на запрос кода для существующего и несуществующего адреса, один отказ на неверный код без носителя, форма без признака — поле названо; всё производит служба, ни одного `jwt…` ключа не читает", ""),
    # Второй фактор (Ф12, kacho#1281): те же слушатель, посадка и условие стенда,
    # что у полосы входа; код по времени вычисляет сам посев из секрета ответа.
    # Задание `chart-own` его НЕ гоняет, хотя условие создаёт: шаг прогона
    # заводится вместе с тем, что его выход готов к публикации, — держатель ниже.
    "kaname-second-factor": ("A", "шесть глаголов второго фактора и поле `secondFactor` входа на собственном слушателе формы службы (Ф12 Р4): всё производит служба, ключей `jwt…` не читает, код вычисляет посев", _HOLDER_SECOND_FACTOR),
    # Церемония `authorization_code` (LINE-A-1, kaname#423): три поверхности службы
    # — слушатель формы (вход), поверхность выдачи (точка авторизации и
    # токен-эндпоинт), собственный фронт (приём выданного токена). Условие стенда
    # шире, чем создаёт задание `chart-own`: оно не выносит адресов двух последних
    # поверхностей и не сеет конфиденциальных клиентов — производителя такого
    # клиента у продукта нет (kaname#405), и приёмка называет клиента посевом.
    "kaname-authorization-code": ("A", "церемония `authorization_code` нашими силами (LINE-A-1): точка авторизации, обмен кода и обёртка токена обновления на поверхности выдачи службы, вход — полоса входа службы, приём токена — собственный фронт; все утверждения производит служба, ключей `jwt…` не читает; конфиденциальные клиенты — посев стенда", "PRO-Robotech/kaname#423 — DoD 15: стенд посадки `own` создаёт условие набора (адреса поверхности выдачи и собственного фронта, посев двух конфиденциальных клиентов с получателем собственного фронта) и задание `chart-own` его гоняет"),
}


def _surface_of_stem(stem, runnable, blocked) -> str:
    """Адресация позиции по её стеблю — для сверки двух величин между собой."""
    for s, surface, *_ in [*runnable, *blocked]:
        if s == stem:
            return surface
    return ""


Ledger = dict[str, tuple[str, str, str]]


def producer_of(stem: str, ledger: Ledger | None = None) -> tuple[str, str]:
    """Решение о производителе — ЧИТАЕТСЯ, а не выводится.

    Ведомость — ПАРАМЕТР, а не глобаль: самопроверка судит синтетические деревья,
    и подставить им объявленный перечень значило бы требовать записи о коллекциях,
    которых в дереве нет. Умолчание — объявленная ведомость.
    """
    cat, why, _holder = (PRODUCER_LEDGER if ledger is None else ledger)[stem]
    return cat, why


def holder_of(stem: str, ledger: Ledger | None = None) -> str:
    """Держатель позиции: задача, которая её прогонит. Пусто — держателя нет."""
    return (PRODUCER_LEDGER if ledger is None else ledger)[stem][2]


def reconcile_holders(stems: set[str], runs: dict[str, list[str]],
                      ledger: Ledger | None = None) -> list[str]:
    """Производитель в конвейере — шаг ЛИБО держатель, и сверка идёт В ОБЕ СТОРОНЫ.

    Негоняемая коллекция без держателя — долг без читателя: причина напечатана, а
    кто её снимет, не записано нигде. Держатель у коллекции, которую шаг уже
    гоняет, — запись, пережившая свой предмет: она обязана уйти тем же изменением,
    что завело шаг, иначе ведомость держателей стала бы ведомостью прощения.
    Позиция без записи ведомости здесь не судится — её называет
    `reconcile_producer_ledger`, и второй раз она не считается.
    """
    ledger = PRODUCER_LEDGER if ledger is None else ledger
    out = []
    for stem in sorted(stems & set(ledger)):
        holder = ledger[stem][2]
        where = runs.get(stem, [])
        if where and holder:
            out.append(f"держатель коллекции {stem} ({holder}) пережил предмет: её уже "
                       f"гоняет {'; '.join(where)} — запись снимается тем же изменением, "
                       f"что завело шаг")
        if not where and not holder:
            out.append(f"коллекция {stem} не гоняется ни одним шагом конвейера, а "
                       f"держателя в ведомости нет — кто снимет препятствие, не "
                       f"записано нигде")
        if holder and not HOLDER_RE.match(holder):
            out.append(f"держатель коллекции {stem} вне закрытой формы "
                       f"«PRO-Robotech/<репозиторий>#<номер> — <что сделает>»: {holder!r}")
    return out


def reconcile_producer_ledger(stems: set[str],
                              ledger: Ledger | None = None) -> list[str]:
    """Сверка ведомости с деревом В ОБЕ СТОРОНЫ."""
    ledger = PRODUCER_LEDGER if ledger is None else ledger
    out = []
    for stem in sorted(stems - set(ledger)):
        out.append(f"коллекция {stem} есть в дереве, а решения о её производителе "
                   f"не записано — перепись напечатала бы адрес вместо вердикта")
    for stem in sorted(set(ledger) - stems):
        out.append(f"запись про {stem} пережила свой предмет — такой коллекции в "
                   f"дереве нет, и прощать/объявлять нечего")
    for stem, (cat, why, _holder) in sorted(ledger.items()):
        if cat not in PRODUCER_CATEGORIES:
            out.append(f"запись про {stem} называет категорию {cat!r} вне закрытого "
                       f"словаря {sorted(PRODUCER_CATEGORIES)}")
        if not why.strip():
            out.append(f"запись про {stem} без довода — категория без довода есть "
                       f"мнение, а не решение")
    return out


def ledger_matches_ceremony(ceremony_need: dict[str, list[str]],
                            ledger: Ledger | None = None
                            ) -> list[str]:
    """Категория A у коллекции, требующей ЦЕРЕМОНИИ ЧЕЛОВЕКА, — находка.

    Сверка идёт в ОДНУ сторону намеренно. «A требует церемонии» — противоречие
    самой ведомости, и оно машинно разрешимо. Обратное («B не требует церемонии»)
    находкой НЕ объявляется: у B бывает и другое препятствие — недостижимый
    внешний поставщик, — и предикат, объявивший это расхождением, краснел бы на
    верной записи.
    """
    ledger = PRODUCER_LEDGER if ledger is None else ledger
    out = []
    for stem, keys in sorted(ceremony_need.items()):
        if not keys or stem not in ledger:
            continue
        if ledger[stem][0] == "A":
            out.append(
                f"коллекция {stem} объявлена категорией A (производитель — служба, "
                f"переезжает машинным посевом), а читает предъявителя ЦЕРЕМОНИИ "
                f"({', '.join(keys)}): машинный посев его не производит ни при "
                f"каком устройстве, значит это B")
    return out


def run(newman: pathlib.Path, workflows: pathlib.Path | None = None,
        ledger: Ledger | None = None) -> int:
    if workflows is None:
        workflows = ROOT / ".github" / "workflows"
    try:
        (cols, wfs, runs, scripts, minted, mute, runnable, blocked,
         by_surface, by_blocker, by_state, ceremony_need) = survey(newman, workflows)
    except ValueError as e:
        print(f"ОТКАЗ: {e}.", file=sys.stderr)
        return 1
    except ModuleNotFoundError as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: нет разборщика YAML ({e}) — объявление конвейера "
              f"не прочитано, величина «гоняется» НЕ ИЗМЕРЕНА.", file=sys.stderr)
        return RC_UNMET
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}.", file=sys.stderr)
        return RC_UNMET

    drift = reconcile_producer_ledger({stem for stem, *_ in
                                       [*runnable, *blocked]}, ledger)
    # КАТЕГОРИЯ СВЕРЯЕТСЯ С ТРЕБОВАНИЕМ ЦЕРЕМОНИИ, А НЕ ТОЛЬКО ОБЪЯВЛЯЕТСЯ.
    # Ведомость сама определяет B как «служба, но нужен ЧЕЛОВЕЧЕСКИЙ
    # предъявитель». Коллекция, объявленная A и читающая предъявителя церемонии,
    # объявлена переводимой машинным посевом — то есть ОБЕЩАЕТ ВОЗМОЖНОСТЬ,
    # неисполнимую by construction: машине поднять уровень нечем.
    # Цена названа: такая запись переносит коллекцию в план переезда, где её
    # нельзя закрыть ничем, и мера работы становится недостижимой.
    drift += ledger_matches_ceremony(ceremony_need, ledger)
    # ПРОИЗВОДИТЕЛЬ В КОНВЕЙЕРЕ: шаг либо держатель, по каждой позиции и в обе
    # стороны (`reconcile_holders`). Судится по объявлению конвейера (`runs`), а не
    # по половинам переписи: у гоняемой шагом коллекции бывают и препятствия — их
    # расхождение со шагом держит `pipeline_claims_test.py`.
    all_stems = {stem for stem, *_ in [*runnable, *blocked]}
    drift += reconcile_holders(all_stems, runs, ledger)
    if drift:
        print("ОТКАЗ: ведомость производителя разошлась с деревом:", file=sys.stderr)
        for d in drift:
            print(f"  · {d}", file=sys.stderr)
        return 1

    # «Здесь» — стенды службы, которые поднимает её конвейер: автономный и стенд
    # чарта посадки `own`. Какой именно гоняет коллекцию, называет её строка ниже.
    print("===== сквозной набор на стендах службы (автономный · посадка own): что гоняется, а что нет =====")
    print(f"коллекций в дереве: {len(cols)}")
    print(f"  гоняется здесь:    {len(runnable)}")
    print(f"  НЕ гоняется здесь: {len(blocked)}")
    print()
    # ОБЪЁМ ОСМОТРЕННОГО — рядом с величиной: «гоняется N», напечатанное
    # переписью, которая конвейер не читает, измеряет не то, что называет.
    print(f"объявлений конвейера прочитано: {len(wfs)} "
          f"({', '.join(f.name for f in wfs)})")
    print(f"коллекций гоняют шаги конвейера: {len(runs)}")
    for stem, where in sorted(runs.items()):
        print(f"  · {stem} ← {'; '.join(where)}")
    # ОСТАТОК И ЕГО ДЕРЖАТЕЛИ — ТЕМ ЖЕ ВЫВОДОМ: предикат «каждая из M−N названа
    # с держателем» читается здесь, а не прочтением ведомости. Сверка выше
    # уже отказала бы на позиции без держателя, поэтому «назван у K» при K < M−N
    # здесь не печатается никогда — строка есть свидетель, а не второй суд.
    unrun = sorted(all_stems - set(runs))
    by_holder: dict[str, list[str]] = {}
    for stem in unrun:
        m = HOLDER_REF_RE.match(holder_of(stem, ledger))
        by_holder.setdefault(m.group(1) if m else "—", []).append(stem)
    held_n = sum(len(v) for k, v in by_holder.items() if k != "—")
    print(f"НЕ гоняет ни один шаг: {len(unrun)} — держатель назван у {held_n}")
    print("по ДЕРЖАТЕЛЮ (задача, которая прогонит; состояние в трекере здесь НЕ сверяется):")
    for ref, stems in sorted(by_holder.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  · {ref}: {len(stems)} ({', '.join(stems)})")
    print()
    print("по АДРЕСАЦИИ (к чьему базовому адресу стучатся шаги):")
    for s, n in sorted(by_surface.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {s}")
    print()
    by_producer: dict[str, int] = {}
    for stem, *_ in [*runnable, *blocked]:
        cat, _why = producer_of(stem, ledger)
        label = f"{cat} — {PRODUCER_CATEGORIES[cat]}"
        by_producer[label] = by_producer.get(label, 0) + 1
    print("по ПРОИЗВОДИТЕЛЮ (объявлено ведомостью, разрез #24):")
    for label, n in sorted(by_producer.items()):
        print(f"  {n:3d}  {label}")
    print()
    # РАСХОЖДЕНИЕ ДВУХ ВЕЛИЧИН — ОТДЕЛЬНОЕ ЧИСЛО, а не то, что читатель обязан
    # сложить сам: адрес края при производителе-службе и есть предмет переезда.
    mismatch = [stem for stem, *_ in [*runnable, *blocked]
                if producer_of(stem, ledger)[0] in ("A", "B")
                and _surface_of_stem(stem, runnable, blocked) == SURFACE_EDGE]
    print(f"адресуется к краю, а производитель — служба: {len(mismatch)}")
    print("  (это и есть предмет переезда; ярлык адреса о производителе не говорит)")
    print()
    print("по препятствию (одна коллекция может иметь несколько):")
    for b, n in sorted(by_blocker.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {b}")
    print()
    # СОСТОЯНИЕ КЛЮЧА — ОТДЕЛЬНОЙ ПЕРЕПИСЬЮ. Одно число «непосеянных» скрыло бы
    # то, ради чего перепись и делается: пустой ключ падает громко (страж набора
    # утверждает его по имени), литерал чужого стенда — тихо и ПОХОЖЕ НА ДЕФЕКТ
    # ПРОДУКТА, а отсутствующей строки шаблона не хватает раньше значения.
    print("по СОСТОЯНИЮ непосеянного ключа (вхождений по всем коллекциям):")
    for state in (KEY_STATE_EMPTY, KEY_STATE_LITERAL, KEY_STATE_ABSENT):
        print(f"  {state}: {by_state[state]}")
    print()
    print(f"посев общих фикстур: {'есть' if scripts else 'ОТСУТСТВУЕТ'} "
          f"({len(scripts)} скрипт(ов) в authz-fixtures/), "
          f"ключей окружения он пишет: {sum(len(v) for v in minted.values())}")
    for surface, keys in sorted(minted.items()):
        print(f"  · для поверхности «{surface}»: {len(keys)} ключ(ей)")
    for script in scripts:
        print(f"  · {script.name}")
    for m in mute:
        print(f"  · НЕ НАЗВАЛ СВОИХ КЛЮЧЕЙ — {m}")
    print()
    if runnable:
        print("ГОНЯЕТСЯ ЗДЕСЬ (и КАКИМ шагом конвейера):")
        for stem, surface, where in runnable:
            cat, why = producer_of(stem, ledger)
            print(f"  · {stem} — адресация: {surface}; производитель: "
                  f"{cat} ({PRODUCER_CATEGORIES[cat]}) — {why}")
            for w in where:
                print(f"      ← {w}")
        print()
    print("НЕ ГОНЯЕТСЯ ЗДЕСЬ (по каждой позиции — причина):")
    for stem, surface, bl in blocked:
        cat, why = producer_of(stem, ledger)
        print(f"  · {stem} [адресация: {surface}; производитель: "
              f"{cat} ({PRODUCER_CATEGORIES[cat]})] — {why}")
        for b in bl:
            print(f"      — {b}")
        holder = holder_of(stem, ledger)
        if holder:
            print(f"      держатель: {holder}")
    print()
    print("ЧТО ЭТОТ ДОЛГ ЗНАЧИТ, СКАЗАНО ПРЯМО:")
    print("  · прогон автономного стенда проверяет свойства, чей производитель —")
    print("    САМА служба (её фронты, их непроницаемость, рубеж, разбор доступа,")
    print("    честный отказ при недостижимом соседе). Список — stand-assert.py;")
    print("  · свойства КРАЯ платформы здесь не проверяются вовсе и остаются")
    print("    предметом её конвейера;")
    print("  · полоса личности `own` (внешнего поставщика нет ВООБЩЕ) поднимается")
    print("    стендом чарта — задание `chart-own`; автономный стенд идёт на полосе")
    print("    `external` с ОБЪЯВЛЕННЫМ, но недостижимым поставщиком — это его")
    print("    предмет, а не неспособность продукта (врезка в .github/scripts/stand-own.sh);")
    print("  · человеческого предъявителя не куёт ни один посев: волна церемонии")
    print("    печатает свой долг сама (tests/authz-fixtures/ceremony_credentials.py --debt).")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


def _mk(tmp: pathlib.Path, cols: dict[str, str], tmpl: dict[str, str]) -> pathlib.Path:
    newman = tmp / "tests" / "newman"
    (newman / "collections").mkdir(parents=True, exist_ok=True)
    (newman / "environments").mkdir(parents=True, exist_ok=True)
    for name, body in cols.items():
        (newman / "collections" / f"{name}.postman_collection.json").write_text(
            body, encoding="utf-8")
    (newman / "environments" / "local.postman_environment.template.json").write_text(
        json.dumps({"values": [{"key": k, "value": v} for k, v in tmpl.items()]}),
        encoding="utf-8")
    return newman


def _wf(tmp: pathlib.Path, runs: list[str]) -> pathlib.Path:
    """Синтетическое объявление конвейера: по шагу на каждую гоняемую коллекцию."""
    wf = tmp / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    steps = "".join(
        f"      - name: коллекция {r} гоняется\n"
        f"        run: |\n"
        f"          cd tests/newman\n"
        f"          ./scripts/run.sh --service {r}\n"
        for r in runs) or "      - run: echo нечего\n"
    (wf / "e2e-newman.yml").write_text(
        "name: proof\non: [push]\njobs:\n  stand:\n    steps:\n" + steps,
        encoding="utf-8")
    return wf


def _st_ledger(newman: pathlib.Path, workflows: pathlib.Path | None) -> Ledger:
    """Синтетическая ведомость для синтетического дерева: одна запись на коллекцию.

    Самопроверка судит ДРУГИЕ оси; требовать от неё объявленных решений о
    коллекциях, которых в дереве нет, значило бы уронить её на предмете, к
    которому она не относится. Сверку самой ведомости держат оси 10 и 11 ниже —
    там расхождение вносится НАМЕРЕННО; сверку держателя — ось 16.

    Держатель ставится ровно там, где его требует сверка: у коллекции, которую
    шаг синтетического конвейера не гоняет. Иначе оси о посеве и адресации падали
    бы на держателе, к которому они не относятся.
    """
    declared = template_keys(newman)
    try:
        runs = pipeline_runs(workflows) if workflows is not None else {}
    except (Unmet, ModuleNotFoundError):
        runs = {}
    out: Ledger = {}
    for p in sorted((newman / "collections").glob("*.postman_collection.json")):
        stem = p.name.replace(".postman_collection.json", "")
        text = p.read_text(encoding="utf-8")
        own = set(OWN_KEY_RE.findall(text))
        # Категория выводится ТЕМ ЖЕ правилом, что сверяет `ledger_matches_ceremony`:
        # иначе оси 7 и 7б (фикстуры с предъявителем церемонии) падали бы на
        # проверке классификации, к которой они не относятся. Сама проверка от
        # этого не становится вакуумной — её ось ниже подаёт ведомость ЯВНО.
        cer = any(key_state(k, declared, own) is not None and is_ceremony_key(k)
                  for k in used_keys(text))
        holder = "" if runs.get(stem) else "PRO-Robotech/kaname#1 — синтетика самопроверки"
        out[stem] = ("B" if cer else "A", "синтетика самопроверки", holder)
    return out


def _st_run(newman: pathlib.Path, workflows: pathlib.Path | None = None,
            ledger: Ledger | None = None) -> int:
    return run(newman, workflows=workflows,
               ledger=_st_ledger(newman, workflows) if ledger is None else ledger)


def self_test() -> int:
    import io
    import contextlib
    import tempfile
    print("newman-suite-debt: доказательство способности упасть")
    with tempfile.TemporaryDirectory(prefix="debt-proof-") as td:
        tmp = pathlib.Path(td)

        # Ось 1: пустой обход — ОТКАЗ, а не «долга нет».
        empty = _mk(tmp / "empty", {}, {"baseUrl": "http://x"})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = _st_run(empty, workflows=_wf(tmp / "empty", runs=[]))
        _c("ноль коллекций — код 1, а НЕ 0", rc == 1, buf.getvalue()[-200:])
        _c("и отказ называет беспредметность", "беспредметна" in buf.getvalue())

        # Ось 2: коллекция БЕЗ препятствий обязана попасть в «гоняется».
        own = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        t2 = _mk(tmp / "own", {"own-only": own},
                 {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = _st_run(t2, workflows=_wf(tmp / "own", runs=["own-only"]))
        out = buf.getvalue()
        _c("коллекция без препятствий — код 0", rc == 0)
        _c("она в «гоняется здесь»", "гоняется здесь:    1" in out, out[:400])
        _c("и её поверхность названа службой", "собственный REST-фронт" in out)

        # Ось 3: ЗАКОННЫЙ БЛИЗНЕЦ — та же коллекция, но читает пустой ключ посева.
        own2 = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}},'
                '"event":[{"listen":"test","script":{"exec":['
                '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t3 = _mk(tmp / "own-seeded", {"own-seeded": own2},
                 {"ownRestBaseUrl": "https://localhost:9098", "jwtAccountAdminA": "",
                  "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t3, workflows=_wf(tmp / "own-seeded", runs=["own-seeded"]))
        out = buf.getvalue()
        _c("та же коллекция с пустым ключом посева — в «НЕ гоняется»",
           "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа посевом", "машинный посев" in out, out[:600])

        # Ось 3б: ПОСЕВ СНИМАЕТ ПРЕПЯТСТВИЕ ПОКЛЮЧЕВО, а не одним флагом.
        # Два синтетических посева: один пишет ИМЕННО тот ключ, что читает
        # коллекция, второй — соседний. Различие ровно в одном факте, и оно
        # обязано двигать коллекцию между половинами переписи.
        for lane, minted_key, expect_runs in (("covered", "jwtAccountAdminA", True),
                                              ("other", "jwtSomethingElse", False)):
            base = tmp / f"seed-{lane}"
            t3b = _mk(base, {"own-seeded": own2},
                      {"ownRestBaseUrl": "https://localhost:9098",
                       "jwtAccountAdminA": "", "runId": ""})
            fixtures = t3b.parent / "authz-fixtures"
            fixtures.mkdir(parents=True, exist_ok=True)
            script = fixtures / "seed_probe.py"
            script.write_text(
                "import sys\n"
                "if '--minted-keys' in sys.argv:\n"
                f"    print({minted_key!r})\n"
                "elif '--minted-surface' in sys.argv:\n"
                "    print('служба (собственный REST-фронт)')\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t3b, workflows=_wf(base, runs=["own-seeded"]))
            out = buf.getvalue()
            _c(f"посев, пишущий {minted_key}: коллекция "
               f"{'ГОНЯЕТСЯ' if expect_runs else 'НЕ гоняется'}",
               (f"гоняется здесь:    {1 if expect_runs else 0}" in out
                and f"НЕ гоняется здесь: {0 if expect_runs else 1}" in out),
               out[:500])

        # Ось 3в: посев, который на вопрос НЕ ОТВЕЧАЕТ, в счёт не идёт и
        # называется отдельно — «посев есть, а что пишет, неизвестно» и «посева
        # нет» ведут читателя в разные места.
        mute_base = tmp / "seed-mute"
        t3c = _mk(mute_base, {"own-seeded": own2},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtAccountAdminA": "", "runId": ""})
        mute_fixtures = t3c.parent / "authz-fixtures"
        mute_fixtures.mkdir(parents=True, exist_ok=True)
        (mute_fixtures / "seed_probe.py").write_text(
            "import sys\nsys.exit(2)\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t3c, workflows=_wf(mute_base, runs=["own-seeded"]))
        out = buf.getvalue()
        _c("молчащий посев не снимает препятствия", "НЕ гоняется здесь: 1" in out,
           out[:400])
        _c("и назван отдельной строкой", "НЕ НАЗВАЛ СВОИХ КЛЮЧЕЙ" in out, out[:600])

        # ── Ось 3г: ПОСЕВ СНИМАЕТ ПРЕПЯТСТВИЕ ТОЛЬКО НА СВОЕЙ ПОВЕРХНОСТИ ───
        #
        # Совпадение ИМЕНИ ключа через два разных стенда — не производство ключа.
        # Посев этого дерева куёт `jwtAccountAdminA` на СОБСТВЕННОМ фронте службы;
        # коллекция КРАЯ читает ключ того же имени, но её предъявителя производит
        # чужой посев чужого стенда. Различие ровно в поверхности, и оно обязано
        # двигать коллекцию между половинами переписи.
        for lane, surface_decl, edge_runs in (
                ("own-surface", "служба (собственный REST-фронт)", False),
                ("edge-surface", SURFACE_EDGE, True)):
            base = tmp / f"surface-{lane}"
            edge_seeded = ('{"item":[{"name":"s","request":{"url":{"raw":'
                           '"{{baseUrl}}/iam/v1/x"}},'
                           '"event":[{"listen":"test","script":{"exec":['
                           '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
            t3g = _mk(base, {"edge-seeded": edge_seeded},
                      {"baseUrl": "http://edge", "jwtAccountAdminA": "", "runId": ""})
            fixtures = t3g.parent / "authz-fixtures"
            fixtures.mkdir(parents=True, exist_ok=True)
            (fixtures / "seed_probe.py").write_text(
                "import sys\n"
                "if '--minted-keys' in sys.argv:\n"
                "    print('jwtAccountAdminA')\n"
                "elif '--minted-surface' in sys.argv:\n"
                f"    print({surface_decl!r})\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t3g, workflows=_wf(base, runs=["edge-seeded"]))
            out = buf.getvalue()
            _c(f"посев поверхности «{surface_decl}»: препятствие посева у коллекции "
               f"КРАЯ {'снято' if edge_runs else 'ОСТАЛОСЬ'}",
               ("машинный посев" in out) != edge_runs, out[:600])

        # Ось 3д: посев, не объявивший ПОВЕРХНОСТЬ, в счёт не идёт и назван.
        # Fail-closed: «ключи назвал, поверхность нет» и «поверхность края» ведут
        # читателя в разные места, а молча зачесть — значит вернуть совпадение имён.
        base = tmp / "surface-mute"
        own_seeded_edge = ('{"item":[{"name":"s","request":{"url":{"raw":'
                           '"{{ownRestBaseUrl}}/x"}},'
                           '"event":[{"listen":"test","script":{"exec":['
                           '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t3d = _mk(base, {"own-seeded": own_seeded_edge},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtAccountAdminA": "", "runId": ""})
        fx = t3d.parent / "authz-fixtures"
        fx.mkdir(parents=True, exist_ok=True)
        (fx / "seed_probe.py").write_text(
            "import sys\n"
            "if '--minted-keys' in sys.argv:\n"
            "    print('jwtAccountAdminA')\n",
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t3d, workflows=_wf(base, runs=["own-seeded"]))
        out = buf.getvalue()
        _c("посев без объявленной поверхности не снимает препятствия",
           "машинный посев" in out, out[:600])
        _c("и назван отдельной строкой", "НЕ НАЗВАЛ СВОЕЙ ПОВЕРХНОСТИ" in out, out[:700])

        # ── Ось 6: «ГОНЯЕТСЯ» ЧИТАЕТСЯ ИЗ ОБЪЯВЛЕНИЯ КОНВЕЙЕРА ──────────────
        #
        # Величина обязана измерять то, что называет. Прежняя редакция печатала
        # «гоняется здесь: N», не читая конвейер ВОВСЕ: снятие шага прогона из
        # `e2e-newman.yml` её не меняло, то есть она измеряла «ничто не мешает
        # гонять». Ось доказывает обратное ПАРОЙ: тот же тракт, шаг снят — и
        # коллекция уезжает в другую половину переписи.
        clean = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        for lane, runs, expect in (("declared", ["own-only"], 1), ("removed", [], 0)):
            base = tmp / f"pipeline-{lane}"
            t6 = _mk(base, {"own-only": clean},
                     {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = _st_run(t6, workflows=_wf(base, runs=runs))
            out = buf.getvalue()
            _c(f"шаг прогона {'объявлен' if runs else 'СНЯТ'} — гоняется {expect}",
               f"гоняется здесь:    {expect}" in out, out[:500])
            if not runs:
                _c("и причина названа отсутствием шага конвейера",
                   "ни один шаг конвейера" in out, out[:700])

        # Ось 6б: `--service` В КОММЕНТАРИИ не считается шагом. Разбор читает
        # разобранный YAML; проверка по подстроке краснела бы на объяснении.
        base = tmp / "pipeline-comment"
        t6b = _mk(base, {"own-only": clean},
                  {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        wf = _wf(base, runs=[])
        (wf / "e2e-newman.yml").write_text(
            "name: proof\non: [push]\njobs:\n  stand:\n    steps:\n"
            "      # ./scripts/run.sh --service own-only  (когда-то гонялось здесь)\n"
            "      - run: echo нечего\n", encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t6b, workflows=wf)
        out = buf.getvalue()
        _c("`--service` только в комментарии — НЕ шаг прогона",
           "гоняется здесь:    0" in out, out[:500])

        # ── Ось 6г: ВНУТРИ ТЕЛА `run:` ПРОГОН — ЭТО КОМАНДА, А НЕ ТЕКСТ ─────
        #
        # Ось 6б держит комментарий ВНЕ тела шага; эта — внутри. Флаг в
        # комментарии тела, в строковом литерале, в аргументах чужой команды и в
        # данных heredoc — не прогон: шаг, которому оставили только такое
        # упоминание, коллекцию не гоняет, и перепись обязана потребовать у неё
        # держателя. Пара у каждой формы — та же строка КОМАНДОЙ прогонщика, в
        # том числе в формах, которыми дерево её пишет (продолжение строки и
        # `|| rc=$?` у шага chart-own). Каждая форма судится обоими признаками:
        # ответом разборщика и половиной переписи.
        def _wf_body(base: pathlib.Path, body: str,
                     shell: str | None = None) -> pathlib.Path:
            wfb = base / ".github" / "workflows"
            wfb.mkdir(parents=True, exist_ok=True)
            block = "".join(f"          {ln}\n" if ln else "\n"
                            for ln in body.split("\n"))
            (wfb / "e2e-newman.yml").write_text(
                "name: proof\non: [push]\njobs:\n  stand:\n    steps:\n"
                "      - name: шаг с упоминанием прогонщика\n"
                + (f"        shell: {shell}\n" if shell else "")
                + "        run: |\n" + block, encoding="utf-8")
            return wfb

        body_forms = (
            ("комментарий тела", False,
             "cd tests/newman\n# снято до #999: ./scripts/run.sh --service own-only"),
            ("хвост-комментарий после команды", False,
             "cd tests/newman\ntrue  # ./scripts/run.sh --service own-only"),
            # Комментарий с разделителем команд: без разбора комментария `;`
            # отделил бы упоминание в самостоятельную команду.
            ("комментарий тела с разделителем команд", False,
             "cd tests/newman\n# снято до #999; ./scripts/run.sh --service own-only"),
            ("литерал echo в кавычках", False,
             'cd tests/newman\necho "снято: ./scripts/run.sh --service own-only"'),
            ("аргументы echo без кавычек", False,
             "cd tests/newman\necho снято: ./scripts/run.sh --service own-only"),
            ("литерал аргумента чужой команды", False,
             "printf '%s\\n' './scripts/run.sh --service own-only'"),
            ("данные heredoc", False,
             "cat <<'NOTE'\n./scripts/run.sh --service own-only\nNOTE"),
            ("та же строка командой", True,
             "cd tests/newman\n./scripts/run.sh --service own-only"),
            ("командой с продолжением строки и `|| rc=$?`", True,
             "cd tests/newman\nrc=0\n./scripts/run.sh \\\n  --service own-only \\\n"
             '  --ssl-client-cert "$W/edge.crt" || rc=$?'),
            # Продолжение строки посреди слова снимается целиком, как у bash:
            # имя коллекции склеивается, а не рвётся на два слова.
            ("командой с продолжением строки посреди имени", True,
             "./scripts/run.sh --service own-\\\nonly"),
            ("командой в условии if", True,
             "if ./scripts/run.sh --service own-only; then echo ok; fi"),
            ("командой внутри подстановки в кавычках", True,
             'out="$(./scripts/run.sh --service own-only)"'),
            # Апостроф в комментарии кавычки не открывает: иначе она проглотила
            # бы команду ниже, и настоящий прогон выпал бы из счёта.
            ("командой после комментария с апострофом", True,
             "# it's the recovery lane\n./scripts/run.sh --service own-only"),
            ("командой после heredoc", True,
             "cat <<'NOTE'\nничего\nNOTE\n./scripts/run.sh --service own-only"),
            ("командой через bash -c", True,
             "bash -c './scripts/run.sh --service own-only'"),
        )
        for k, (label, runs_it, body) in enumerate(body_forms):
            base = tmp / f"pipeline-body-{k}"
            t6g = _mk(base, {"own-only": clean},
                      {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
            wfb = _wf_body(base, body)
            parsed = pipeline_runs(wfb)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t6g, workflows=wfb)
            out = buf.getvalue()
            want = 1 if runs_it else 0
            _c(f"`--service` в теле `run:` — {label}: "
               f"{'ПРОГОН' if runs_it else 'НЕ прогон'}",
               bool(parsed.get("own-only")) == runs_it
               and f"гоняется здесь:    {want}" in out,
               f"разборщик: {parsed}; перепись: {out[:300]}")

        # Ось 6д: тело шага с ИНОЙ оболочкой — не программа bash, и её строка,
        # похожая на команду прогонщика, прогоном не засчитывается. Близнец —
        # то же тело под `shell: bash`: различие ровно в оболочке шага.
        same = "./scripts/run.sh --service own-only"
        for k, (shell, runs_it) in enumerate((("python {0}", False),
                                              ("bash {0}", True))):
            base = tmp / f"pipeline-shell-{k}"
            wfb = _wf_body(base, same, shell=shell)
            parsed = pipeline_runs(wfb)
            _c(f"та же строка под `shell: {shell}` — "
               f"{'ПРОГОН' if runs_it else 'НЕ прогон'}",
               bool(parsed.get("own-only")) == runs_it, f"разборщик: {parsed}")

        # Ось 6в: объявлений конвейера НЕТ — третий исход, а не «гоняется 0».
        base = tmp / "pipeline-absent"
        t6c = _mk(base, {"own-only": clean},
                  {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = _st_run(t6c, workflows=base / "нет-такого-каталога")
        _c("каталога объявлений нет — код 75, а НЕ 0 и не 1", rc == 75,
           buf.getvalue()[-300:])
        _c("и текст называет несозданное условие",
           "УСЛОВИЕ НЕ СОЗДАНО" in buf.getvalue(), buf.getvalue()[-300:])

        # ── Ось 7: ПРИРОДА КЛЮЧА РАЗЛИЧАЕТСЯ, И «ЧЕЛОВЕК» НЕ ЗОВЁТ МАШИНУ ───
        #
        # ЗАМЕР, А НЕ ИМЯ. `humanAccCrudUserId` читается кейсом как идентификатор
        # ТОГО ЖЕ вызывающего, чей предъявитель — `jwtHumanAccCrud`: утверждение
        # кейса — «ownerUserId == caller», и образец требует префикса `usr`.
        # Значит ключ производит ЦЕРЕМОНИЯ, а машинный посев не производит его ни
        # при каком устройстве: служебная учётка человеком не является, её
        # идентификатор несёт префикс `sva`, и подставленное значение дало бы
        # кейс, проверивший подстановку.
        #
        # ЦЕНА ПРЕЖНЕГО УЧЁТА НАЗВАНА: строка долга звала читателя завести
        # машинный посев тому, чего машинный посев не производит, — то есть
        # ОБЪЯВЛЯЛА возможность, неисполнимую by construction.
        #
        # ЗАКОННЫЙ БЛИЗНЕЦ РЯДОМ и отличается ОДНИМ фактом: `svaInviteeId` —
        # идентификатор СЛУЖЕБНОЙ учётки (кейсы читают его при
        # `subjectType=service_account`), и он обязан остаться машинным.
        for lane, key, want_ceremony in (("human-id", "humanAccCrudUserId", True),
                                         ("machine-id", "svaInviteeId", False)):
            base = tmp / f"nature-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t7 = _mk(base, {"nature": body},
                     {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t7, workflows=_wf(base, runs=["nature"]))
            out = buf.getvalue()
            # СУДИТСЯ ГОЛОВА ПРЕПЯТСТВИЯ, А НЕ ПОДСТРОКА ВЫВОДА, и это не
            # педантизм: первая редакция этой оси искала «машинный посев» по
            # всему выводу и краснела на СОБСТВЕННОМ объяснении препятствия
            # церемонии («…машинный посев не производит ни одного»). Тот самый
            # класс, который шапка `pipeline_runs` называет про грепанье
            # комментариев, применённый не к конвейеру, а к самой переписи.
            _c(f"{key}: препятствие названо "
               f"{'ЦЕРЕМОНИЕЙ ЧЕЛОВЕКА' if want_ceremony else 'машинным посевом'}",
               ("нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА" in out) == want_ceremony
               and ("нужен машинный посев поверхности" in out) != want_ceremony,
               out[:900])

        # ── Ось 7б: ПРЕДЪЯВИТЕЛЬ ПОВЫШЕННОГО УРОВНЯ — ТОЖЕ ЦЕРЕМОНИЯ ─────────
        #
        # ЗАМЕР, И ОН СХОДИТСЯ ИЗ ДВУХ НЕЗАВИСИМЫХ МЕСТ. Шапка
        # `cases/iam-interactive-client.py` говорит дословно:
        # «`jwtAccountAdminAStepUp` is declared unforgeable by the seed itself …
        # and every other `jwt*` fixture is a ServiceAccount token, i.e.
        # acr-exempt». И это подтверждается устройством продукта: `kaname_acr`
        # приходит ТОЛЬКО из сессии поставщика (`token_enrichment_service.go`
        # кладёт его пробросом, `authzguard/acr_floor.go` читает), а служебная
        # учётка от порога ОСВОБОЖДЕНА — то есть поднять уровень машине нечем.
        #
        # Значит приставки `jwtHuman` недостаточно: `*StepUp` — предъявитель, чей
        # производитель церемония, под каким бы именем слот ни стоял.
        # Законный близнец отличается ОДНИМ фактом: `jwtAccountAdminA` без
        # повышения — служебная учётка, и он обязан остаться машинным.
        for lane, key, want_ceremony in (("stepup", "jwtAccountAdminAStepUp", True),
                                         ("plain", "jwtAccountAdminA", False)):
            base = tmp / f"stepup-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t7b = _mk(base, {"stepup": body},
                      {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t7b, workflows=_wf(base, runs=["stepup"]))
            out = buf.getvalue()
            _c(f"{key}: препятствие названо "
               f"{'ЦЕРЕМОНИЕЙ ЧЕЛОВЕКА' if want_ceremony else 'машинным посевом'}",
               ("нужна ЦЕРЕМОНИЯ ЧЕЛОВЕКА" in out) == want_ceremony
               and ("нужен машинный посев поверхности" in out) != want_ceremony,
               out[:900])

        # ── Ось 8: АДРЕС — НЕ ПОСЕВ, И ЕГО ПРОИЗВОДИТ СТЕНД ──────────────────
        #
        # Тот же класс, что уже назван в шапке `blockers`: из шести пустых ключей
        # своей поверхности два были АДРЕСАМИ, и прежняя редакция звала их
        # удостоверениями. Ключи `iamJwksBaseUrl` и `providerPublicBaseUrl` — того
        # же рода: их не выпускает ни один подписант, их НАЗЫВАЕТ посадка.
        # Законный близнец — предъявитель той же коллекции: он обязан остаться
        # машинным посевом.
        for lane, key, want_address in (("addr", "iamJwksBaseUrl", True),
                                        ("cred", "jwtBootstrap", False)):
            base = tmp / f"addrnature-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{baseUrl}}/iam/v1/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    f'"pm.environment.get(\'{key}\')"]}}}}]}}]}}')
            t8 = _mk(base, {"nature": body},
                     {"baseUrl": "http://edge", key: "", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t8, workflows=_wf(base, runs=["nature"]))
            out = buf.getvalue()
            _c(f"{key}: препятствие названо "
               f"{'АДРЕСОМ' if want_address else 'машинным посевом'}",
               ("нужен АДРЕС поверхности" in out) == want_address
               and ("нужен машинный посев поверхности" in out) != want_address,
               out[:900])

        # ── Ось 9: СТРОКА ДОЛГА НАЗЫВАЕТ ПОВЕРХНОСТЬ, ЧЕЙ ПОСЕВ ТРЕБУЕТСЯ ────
        #
        # ЦЕНА ИЗМЕРЕНА И ОНА — ПЛАН ЦЕЛОЙ ПОЛОСЫ. Учёт поклюсевой и по
        # поверхности стоит здесь с самого начала (оси 3б и 3г), а вот СТРОКА про
        # него молчала: она говорила «которых не пишет ни один посев ЭТОЙ
        # поверхности», не называя, КАКОЙ. Читатель печатного долга видел 39
        # коллекций с препятствием «нужен машинный посев» и заводил полосу
        # «расширить посев» — при том что все 39 суть коллекции КРАЯ, и посев
        # собственного фронта им не зачитывается НИ ОДНИМ ключом by construction.
        # То есть число, на которое ставился план, сдвинуть было нечем.
        #
        # Инъекция: коллекция КРАЯ и посев СВОЕЙ поверхности в одном дереве.
        # Строка обязана назвать ЯРЛЫК АДРЕСАЦИИ края — поверхность, чьего посева
        # нет, — а не поверхность посева, который в дереве лежит. Ярлык берётся
        # КОНСТАНТОЙ: повтори его текстом, и переименование оставило бы эту ось
        # зелёной на прежнем слове.
        base = tmp / "surface-named"
        edge_seeded = ('{"item":[{"name":"s","request":{"url":{"raw":'
                       '"{{baseUrl}}/iam/v1/x"}},'
                       '"event":[{"listen":"test","script":{"exec":['
                       '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t9 = _mk(base, {"edge-seeded": edge_seeded},
                 {"baseUrl": "http://edge", "jwtAccountAdminA": "", "runId": ""})
        fx9 = t9.parent / "authz-fixtures"
        fx9.mkdir(parents=True, exist_ok=True)
        (fx9 / "seed_probe.py").write_text(
            "import sys\n"
            "if '--minted-keys' in sys.argv:\n"
            "    print('jwtAccountAdminA')\n"
            "elif '--minted-surface' in sys.argv:\n"
            "    print('служба (собственный REST-фронт)')\n",
            encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t9, workflows=_wf(base, runs=["edge-seeded"]))
        out = buf.getvalue()
        _c("строка машинного посева НАЗЫВАЕТ поверхность, чей посев требуется",
           f"машинный посев поверхности «{SURFACE_EDGE}»" in out, out[:800])
        _c("и НЕ называет поверхность посева, который в дереве лежит",
           "машинный посев поверхности «служба" not in out, out[:800])

        # ── Ось 12: НЕПОСЕЯННЫЙ КЛЮЧ С ЧУЖИМ ЛИТЕРАЛОМ ──────────────────────
        #
        # ПУСТОЙ КЛЮЧ — НЕ ЕДИНСТВЕННОЕ СОСТОЯНИЕ НЕПОСЕЯННОГО. Шаблон несёт
        # `userNOBId`, `userAAAId`, `projectB1Id` НЕПУСТЫМИ — правдоподобными
        # `usr…`/`prj…` чужого стенда. Посев автономного стенда их не куёт, значит
        # на нём они указывают в пустоту, а перепись их НЕ ВИДЕЛА: предикат
        # спрашивал только про пустое значение.
        #
        # ЦЕНА РАЗНАЯ, И ПОТОМУ ВИД НАЗЫВАЕТСЯ ОТДЕЛЬНО. Пустой ключ падает
        # ГРОМКО — страж набора утверждает его по имени до первого запроса.
        # Литерал чужого стенда доезжает до службы и возвращается 403/404, то есть
        # ПОХОЖИМ НА ДЕФЕКТ ПРОДУКТА.
        #
        # Законных близнеца ДВА, и каждый отличается одним фактом: тот же литерал,
        # но посев его КУЁТ — препятствия нет; и АДРЕС с непустым литералом — его
        # поверхность названа отдельной строкой, второй раз он не считается.
        for lane, minted_key, want in (("unminted", "jwtSomethingElse", True),
                                       ("minted", "userNOBId", False)):
            base = tmp / f"literal-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{ownRestBaseUrl}}/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    '"pm.environment.get(\'userNOBId\')"]}}]}]}')
            t12 = _mk(base, {"literal": body},
                      {"ownRestBaseUrl": "https://localhost:9098",
                       "userNOBId": "usry4tz0kfahkv1favw1", "runId": ""})
            fx = t12.parent / "authz-fixtures"
            fx.mkdir(parents=True, exist_ok=True)
            (fx / "seed_probe.py").write_text(
                "import sys\n"
                "if '--minted-keys' in sys.argv:\n"
                f"    print({minted_key!r})\n"
                "elif '--minted-surface' in sys.argv:\n"
                "    print('служба (собственный REST-фронт)')\n",
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t12, workflows=_wf(base, runs=["literal"]))
            out = buf.getvalue()
            _c(f"непустой `userNOBId`, посев его {'НЕ куёт' if want else 'куёт'} — "
               f"препятствие {'названо' if want else 'снято'}",
               (f"НЕ гоняется здесь: {1 if want else 0}" in out
                and f"{KEY_STATE_LITERAL}: {1 if want else 0}" in out), out[:900])

        # Законный близнец про АДРЕС: непустое значение переменной края вторым
        # препятствием не считается — его поверхность уже названа своей строкой.
        base = tmp / "literal-address"
        edge_plain = ('{"item":[{"name":"s","request":{"url":{"raw":'
                      '"{{baseUrl}}/iam/v1/x"}}}]}')
        t12b = _mk(base, {"edge-plain": edge_plain},
                   {"baseUrl": "http://localhost:18080", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t12b, workflows=_wf(base, runs=["edge-plain"]))
        out = buf.getvalue()
        _c("непустой АДРЕС края литералом чужого стенда НЕ называется",
           f"{KEY_STATE_LITERAL}: 0" in out, out[:900])
        _c("и его поверхность названа своей строкой",
           "адресуется к краю платформы (переменная базового адреса)" in out,
           out[:900])

        # ── Ось 13: КЛЮЧА НЕТ В ШАБЛОНЕ ВОВСЕ ───────────────────────────────
        #
        # Третье состояние непосеянного: ключ читается, а строки под него в
        # шаблоне НЕТ. Прежний предикат спрашивал `k in empty` и такой ключ не
        # видел by construction — непосеянность выглядела нулём.
        #
        # ЗАКОННЫХ БЛИЗНЕЦА ТРИ, и все три — законные написания того, что
        # коллекция производит САМА (`testing.md` §«Гейт на класс», п. 7):
        # обычные кавычки, ЭКРАНИРОВАННЫЕ кавычки (`set(\"k\"` — так генератор
        # пишет разбор набора ключей) и снятие (`unset('k')` — так снимается
        # временная запись). Ни одно из трёх препятствием не является: стенд
        # такой ключ производить не обязан.
        for lane, extra, want in (
                ("absent", '', True),
                ("self-plain", '","pm.environment.set(\'k13\', \'v\')', False),
                ("self-escaped", '","pm.environment.set(\\"k13\\", \'v\')', False),
                ("self-unset", '","pm.environment.unset(\'k13\')', False)):
            base = tmp / f"absent-{lane}"
            body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                    '"{{ownRestBaseUrl}}/x"}},'
                    '"event":[{"listen":"test","script":{"exec":['
                    '"pm.environment.get(\'k13\')' + extra + '"]}}]}]}')
            t13 = _mk(base, {"absent": body},
                      {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _st_run(t13, workflows=_wf(base, runs=["absent"]))
            out = buf.getvalue()
            _c(f"ключ вне шаблона, коллекция его "
               f"{'НЕ пишет' if want else f'пишет ({lane})'} — препятствие "
               f"{'названо' if want else 'снято'}",
               (f"НЕ гоняется здесь: {1 if want else 0}" in out
                and f"{KEY_STATE_ABSENT}: {1 if want else 0}" in out), out[:900])

        # ── Ось 14: ПЕРЕПИСЬ ПЕЧАТАЕТ СОСТОЯНИЯ ОТДЕЛЬНО ────────────────────
        #
        # «Оба вида отдельно» — не украшение: читатель, видящий одно число
        # «непосеянных ключей», не отличит громкого отказа стража от тихого
        # 404 по чужому литералу, а чинятся они разным.
        base = tmp / "states"
        body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                '"{{ownRestBaseUrl}}/x"}},'
                '"event":[{"listen":"test","script":{"exec":['
                '"pm.environment.get(\'jwtEmptyOne\')",'
                '"pm.environment.get(\'userNOBId\')",'
                '"pm.environment.get(\'absentOne\')"]}}]}]}')
        t14 = _mk(base, {"states": body},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtEmptyOne": "", "userNOBId": "usry4tz0kfahkv1favw1",
                   "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t14, workflows=_wf(base, runs=["states"]))
        out = buf.getvalue()
        _c("перепись печатает ТРИ состояния ключа по отдельности",
           all(f"{s}: " in out for s in (KEY_STATE_EMPTY, KEY_STATE_LITERAL,
                                         KEY_STATE_ABSENT)), out[:1200])
        _c("и каждое своим числом",
           f"{KEY_STATE_EMPTY}: 1" in out and f"{KEY_STATE_LITERAL}: 1" in out
           and f"{KEY_STATE_ABSENT}: 1" in out, out[:1200])

        # ── Ось 15: КАТЕГОРИЯ A ПРИ ТРЕБОВАНИИ ЦЕРЕМОНИИ — НАХОДКА ──────────
        #
        # Ведомость сама определяет B как «нужен ЧЕЛОВЕЧЕСКИЙ предъявитель».
        # Запись A у коллекции, читающей `*StepUp`, объявляет её переводимой
        # машинным посевом — возможность, неисполнимую by construction.
        # Ведомость подаётся ЯВНО, мимо `_st_ledger`: иначе ось судила бы то же
        # правило, которым синтетическая ведомость и строится, то есть себя.
        base = tmp / "misfiled"
        stepup_body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                       '"{{ownRestBaseUrl}}/x"}},'
                       '"event":[{"listen":"test","script":{"exec":['
                       '"pm.environment.get(\'jwtAccountAdminAStepUp\')"]}}]}]}')
        t15 = _mk(base, {"misfiled": stepup_body},
                  {"ownRestBaseUrl": "https://localhost:9098",
                   "jwtAccountAdminAStepUp": "", "runId": ""})
        wf15 = _wf(base, runs=["misfiled"])
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = run(t15, workflows=wf15, ledger={"misfiled": ("A", "довод", "")})
        _c("A при требовании церемонии — код 1", rc == 1, f"код {rc}")
        _c("и находка называет коллекцию и ключ",
           "misfiled" in err.getvalue()
           and "jwtAccountAdminAStepUp" in err.getvalue(), err.getvalue()[:400])

        # ЗАКОННЫЙ БЛИЗНЕЦ ПЕРВЫЙ: та же коллекция, категория B — молчание.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = run(t15, workflows=wf15, ledger={"misfiled": ("B", "довод", "")})
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: та же коллекция как B — код 0", rc == 0, f"код {rc}")

        # ЗАКОННЫЙ БЛИЗНЕЦ ВТОРОЙ: категория A у коллекции БЕЗ церемонии —
        # молчание. Без него ось краснела бы на любой записи A.
        base = tmp / "filed-ok"
        plain_body = ('{"item":[{"name":"s","request":{"url":{"raw":'
                      '"{{ownRestBaseUrl}}/x"}},'
                      '"event":[{"listen":"test","script":{"exec":['
                      '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t15b = _mk(base, {"filed-ok": plain_body},
                   {"ownRestBaseUrl": "https://localhost:9098",
                    "jwtAccountAdminA": "", "runId": ""})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = run(t15b, workflows=_wf(base, runs=["filed-ok"]),
                     ledger={"filed-ok": ("A", "довод", "")})
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: A без церемонии — код 0", rc == 0, f"код {rc}")

        # Ось 4: коллекция края попадает в «не гоняется» с причиной про край.
        edge = ('{"item":[{"name":"s","request":{"url":{"raw":"{{baseUrl}}/iam/v1/x"}}}]}')
        t4 = _mk(tmp / "edge", {"edge-only": edge}, {"baseUrl": "http://x", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _st_run(t4, workflows=_wf(tmp / "edge", runs=["edge-only"]))
        out = buf.getvalue()
        _c("коллекция края — в «НЕ гоняется»", "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа АДРЕСАЦИЕЙ, а не вердиктом о производителе",
           "адресуется к краю платформы (переменная базового адреса)" in out, out[:400])
        _c("причина НЕ утверждает о производителе",
           "его производитель — чужой стенд" not in out, out[:400])

        # ── Ось 10: ВЕДОМОСТЬ ПРОИЗВОДИТЕЛЯ СВЕРЯЕТСЯ С ДЕРЕВОМ В ОБЕ СТОРОНЫ ─
        #
        # Это тот механизм, которым снят довод против второго списка: «выписанный
        # перечень разошёлся бы с деревом молча». Молча он не разойдётся — он
        # УРОНИТ прогон, и обе стороны расхождения проверяются здесь по одной.
        # Без этой оси ведомость была бы ровно тем, чего опасалась прежняя шапка.
        lt = _mk(tmp / "ledger", {"edge-only": edge},
                 {"baseUrl": "http://x", "runId": ""})
        lwf = _wf(tmp / "ledger", runs=["edge-only"])

        buf = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = run(lt, workflows=lwf, ledger={})
        _c("коллекция БЕЗ записи ведомости роняет перепись", rc == 1, f"код {rc}")
        _c("и находка называет коллекцию",
           "edge-only" in err.getvalue() and "не записано" in err.getvalue(),
           err.getvalue()[:300])

        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = run(lt, workflows=lwf,
                     ledger={"edge-only": ("C", "довод", ""), "ушедшая": ("A", "довод", "")})
        _c("запись БЕЗ коллекции роняет перепись — перечень не переживает предмет",
           rc == 1, f"код {rc}")
        _c("и находка называет запись",
           "ушедшая" in err.getvalue() and "пережила свой предмет" in err.getvalue(),
           err.getvalue()[:300])

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(lt, workflows=lwf, ledger={"edge-only": ("C", "довод", "")})
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: ведомость сходится с деревом — перепись печатается",
           rc == 0, f"код {rc}")

        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = run(lt, workflows=lwf, ledger={"edge-only": ("Z", "довод", "")})
        _c("категория вне закрытого словаря — находка", rc == 1, f"код {rc}")

        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = run(lt, workflows=lwf, ledger={"edge-only": ("C", "   ", "")})
        _c("категория БЕЗ довода — находка: это мнение, а не решение",
           rc == 1, f"код {rc}")

        # ── Ось 11: ДВЕ ВЕЛИЧИНЫ РАЗЛИЧИМЫ, и их расхождение названо числом ──
        #
        # Ярлык адресации и решение о производителе обязаны РАСХОДИТЬСЯ на том
        # самом входе, ради которого ведомость и заведена: коллекция стучится к
        # краю, а утверждения её производит служба. Сойдись они здесь — ведомость
        # ничего не добавляла бы к выводу из адреса.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(lt, workflows=lwf, ledger={"edge-only": ("A", "предмет службы", "")})
        out = buf.getvalue()
        _c("адресация и производитель напечатаны ОБЕ",
           f"адресация: {SURFACE_EDGE}" in out and "производитель: A" in out,
           out[:600])
        _c("расхождение названо ОТДЕЛЬНЫМ числом",
           "адресуется к краю, а производитель — служба: 1" in out, out[:900])

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(lt, workflows=lwf, ledger={"edge-only": ("C", "предмет края", "")})
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: производитель края — расхождения ноль",
           "адресуется к краю, а производитель — служба: 0" in buf.getvalue(),
           buf.getvalue()[:900])

        # Ось 5: ОБЕ величины печатаются всегда — и когда вторая ноль.
        _c("печатаются обе величины, а не только одна",
           "гоняется здесь:" in out and "НЕ гоняется здесь:" in out)

        # ── Ось 16: У НЕГОНЯЕМОЙ КОЛЛЕКЦИИ ЕСТЬ ДЕРЖАТЕЛЬ, У ГОНЯЕМОЙ — НЕТ ─────
        #
        # Производитель коллекции — шаг конвейера, который её гоняет, либо
        # ДЕРЖАТЕЛЬ в ведомости: задача, которая её прогонит. Без третьего поля
        # «не гоняется» было концом записи: причина печаталась, а кто снимет
        # препятствие, не было записано нигде, и долг стоял без читателя.
        #
        # Пара по каждой стороне, различие ровно в одном факте. Сторона первая:
        # коллекция не гоняется, держателя нет — находка; тот же вход с
        # держателем по форме — молчание. Сторона вторая, САМОИСТЕЧЕНИЕ: шаг её
        # гоняет, а держатель записан — запись пережила свой предмет; тот же
        # шаг без держателя — молчание.
        hdir = tmp / "holder"
        held = _mk(hdir, {"edge-only": edge}, {"baseUrl": "http://x", "runId": ""})
        hwf_none = _wf(hdir / "none", runs=[])
        hwf_runs = _wf(hdir / "runs", runs=["edge-only"])
        holder = "PRO-Robotech/kaname#1 — синтетика: прогонит на своём стенде"
        for label, wf16, entry, want_rc, want_text in (
                ("не гоняется, держателя нет — находка",
                 hwf_none, ("C", "довод", ""), 1, "держателя"),
                ("ЗАКОННЫЙ БЛИЗНЕЦ: не гоняется, держатель по форме — молчание",
                 hwf_none, ("C", "довод", holder), 0, ""),
                ("гоняется шагом, а держатель записан — запись пережила предмет",
                 hwf_runs, ("C", "довод", holder), 1, "пережил"),
                ("ЗАКОННЫЙ БЛИЗНЕЦ: гоняется шагом, держателя нет — молчание",
                 hwf_runs, ("C", "довод", ""), 0, ""),
                ("держатель вне закрытой формы — находка",
                 hwf_none, ("C", "довод", "когда-нибудь прогоним"), 1, "форм")):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = run(held, workflows=wf16, ledger={"edge-only": entry})
            _c(f"держатель: {label} (код {want_rc})",
               rc == want_rc and (not want_text or (
                   want_text in err.getvalue() and "edge-only" in err.getvalue())),
               f"код {rc}; {err.getvalue()[:300]}")

        # Держатель ПЕЧАТАЕТСЯ рядом с позицией и сводится по задаче: предикат
        # задачи читается выводом переписи, а не прочтением ведомости.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(held, workflows=hwf_none, ledger={"edge-only": ("C", "довод", holder)})
        out16 = buf.getvalue()
        _c("строка позиции называет держателя",
           f"держатель: {holder}" in out16, out16[-900:])
        _c("свод по держателю назван числом",
           "по ДЕРЖАТЕЛЮ" in out16 and "PRO-Robotech/kaname#1: 1" in out16, out16[-900:])
        _c("негоняемые с держателем названы числом",
           "НЕ гоняет ни один шаг: 1 — держатель назван у 1" in out16, out16[-900:])

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: пустой обход отвергается, поверхность и препятствия выводятся из "
          "коллекции, а законный близнец (тот же адрес, но пустой ключ посева) уезжает "
          "в другую половину переписи.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--newman", default=str(ROOT / "tests" / "newman"))
    ap.add_argument("--workflows", default=str(ROOT / ".github" / "workflows"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.newman), pathlib.Path(args.workflows))


if __name__ == "__main__":
    sys.exit(main())
