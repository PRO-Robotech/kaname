# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Значение, попадающее в литерал РЕГУЛЯРНОГО ВЫРАЖЕНИЯ из ДЕКЛАРАЦИИ кейса,
обязано нести записанный исход (#1209).

ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ #1202
===========================
Проба-близнец `js_regex_literal_test.py` судит ГЕНЕРАТОРЫ
(`*/tests/newman/scripts/gen.py`) и свою границу называет числом: декларации
кейсов (`*/tests/newman/cases/*.py`) под неё не подпадают. Корпус там другой и
на два порядка больше, поэтому он закрывается отдельно — здесь.

Класс тот же: значение извне попадает в порождаемый код без разбора и ломает не
текст, а СИНТАКСИС — в СГЕНЕРИРОВАННОМ файле, которого автор значения не видит.
Дальше два исхода, оба плохи: newman пишет отказ разбора в `testScripts`, а НЕ в
`assertions.failed`, поэтому шаг даёт НОЛЬ упавших утверждений и отчитывается
зелёным по этой величине («не выполнилось», зачтённое в «прошло»), — либо скрипт
исполняется и утверждает не то.

ТРИ ИСХОДА, ЧЕТВЁРТОГО НЕТ — те же, что у близнеца
==================================================
1. КОД — образец проверяется ПРИ ГЕНЕРАЦИИ (`js_regex_src`), и негодный роняет
   её С ИМЕНЕМ МЕСТА, а не уезжает в коллекцию;
2. ТЕКСТ — экранируется по правилам РЕГУЛЯРНОГО ВЫРАЖЕНИЯ (`js_regex_literal_text`);
3. место снято вместе с предметом.
Исход выбран и ЗАПИСАН по каждому месту в ведомости `RECORDED` ниже.

ПОМОЩНИКИ БЕРУТСЯ У ГЕНЕРАТОРА, А НЕ ПИШУТСЯ ЗАНОВО. Декларация не импортирует
`gen` — помощники приезжают к ней впрыском в пространство имён модуля
(`gen._RUN.load`), тем же путём, каким она получает `Step`, `Case` и
`assert_status`. Вторая копия предиката разошлась бы с первой молча, и это ровно
тот класс, который здесь и стерегут.

ДВЕ ПОЗИЦИИ ОДНОГО ЗНАЧЕНИЯ — ДВА СРЕДСТВА
==========================================
Помощник кейса vpc `_assert_op_error` сажал ОДНО значение сразу в две позиции: в
литерал строки (подпись шага) и в позицию кода (`to.match(…)`, куда вызывающий
передавал готовый литерал `/…/` целиком). Ни одна не была закрыта.

Средства у позиций РАЗНЫЕ, потому что языки разные. Значение там — ТЕКСТ
контракт-тона, поэтому в литерал выражения он едет через
`js_regex_literal_text` (исход «текст»), а в подпись шага — через сериализатор
строки `js_str`. Взять одно средство на обе позиции нельзя: сериализатор строки
внутри `/…/` сменил бы СМЫСЛ, а экранирование по правилам выражения не трогает
апостроф, которым подпись и закрывалась.

Обе стороны утверждаются здесь ПОРОЗНЬ:
`test_hostile_text_becomes_letters_not_operators` (позиция выражения — знаки
обязаны стать буквами и совпасть с текстом дословно) и
`test_a_value_hostile_to_a_string_literal_does_not_break_the_title` (позиция
подписи). Вторая нужна именно потому, что первая её не покрывает: `won't be
found` — безупречный ТЕКСТ, экранирование выражения его пропускает целиком, — а
подпись шага он закрывал, и движок отвечал `SyntaxError: missing ) after
argument list`.

ГРАНИЦА, НАЗВАННАЯ ЧИСЛОМ, А НЕ УМОЛЧАНИЕМ
==========================================
Тем же разбором в декларациях находятся подстановки в литерал СТРОКИ — это корпус
#1181, и он здесь НЕ закрывается. Число названо и держится храповиком
(`STRING_LITERAL_CEILING`): расти ему нельзя, а падать оно обязано в том же
изменении, которым закрывают очередное место. Ноль означает, что граница
кончилась и этот храповик пора снять вместе с ней.

Ещё две зоны названы числом, потому что ноль, который не назван, читается как
«искали и не нашли», хотя означает «не искали»:

  * СОСТОЯНИЕ СЧИТАЕТСЯ НА f-СТРОКУ (см. `newman_js_lexer`). Литерал, открытый в
    одном элементе списка и закрытый в соседнем, разбору невидим. Держится не
    числом в докстроке, а УТВЕРЖДЕНИЕМ: перепись печатает «f-строк, оставляющих
    литерал открытым, N» и падает на N > 0;
  * ОСМАТРИВАЕТСЯ ТОЛЬКО `ast.JoinedStr`. Скрипт, собранный `%`-форматом,
    `.format` или конкатенацией, под перепись не подпадает. Замер по декларациям
    (единица — узел разбора) СЧИТАЕТСЯ, а не помнится:
    `test_the_forms_outside_the_census_are_named_by_number` печатает числа по
    каждой форме и падает, если хоть одна из них подставляет значение ВНУТРЬ
    литерала выражения. Конкатенацию она приводит к равносильной f-строке и
    отдаёт ТОМУ ЖЕ разбору, поэтому вердикт по ней точный, а не «в тексте
    встретилось `to.match(/`»; способность различать доказана на синтетике в
    обе стороны — `test_the_concatenation_verdict_discriminates_both_ways`.

ПОЧЕМУ ПРОБА ЛЕЖИТ ЗДЕСЬ
========================
Каталог выбран не по принадлежности предмета (места в четырёх сюитах), а по тому,
кто пробу ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` собирает состав по
образцу `services/*/tests/newman/scripts/*_test.py`. Проба, положенная
«правильнее», не исполнялась бы вовсе, — а это ровно тот класс, который она
стережёт. Та же причина и у обоих близнецов.
"""
import ast
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import newman_js_lexer as jslex  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[5]
CASE_GLOBS = ("services/*/tests/newman/cases/*.py",
              "gateway/tests/newman/cases/*.py")

CODE, TEXT = "код", "текст"
# Помощники, ЗАВЕРШАЮЩИЕ подстановку своим исходом. Признак членства один и
# проверяемый: помощник ВОЗВРАЩАЕТ результат помощника исхода — проверка
# образца происходит внутри него, а не в месте подстановки. Обёртка в месте
# вызова была бы вторым вызовом того же помощника и не проверяла бы ничего
# сверх, поэтому такой помощник признаётся, а не оборачивается (#1253).
SANITISER = {CODE: ("js_regex_src(", "credential_secret_pattern("),
             TEXT: ("js_regex_literal_text(",)}
_ALL_SANITISERS = tuple(h for hs in SANITISER.values() for h in hs)

# Потолок соседнего корпуса (#1181): подстановок в литерал СТРОКИ или комментария
# в декларациях. Замер 2026-08-24 на `8a3e00f18` + эта правка. Расти нельзя;
# закрыли место — опустите число тем же изменением.
STRING_LITERAL_CEILING = 473

# ВЕДОМОСТЬ ИСХОДОВ. Ключ — (файл, что подставляется); номер строки не годится,
# он двигается от чужой правки. Запись без места в дереве и место без записи —
# обе находки, и каждая своим утверждением.
RECORDED = {
    ("services/iam/tests/newman/cases/authz-sa-apitoken.py", "op_id_pattern"): CODE,
    ("services/registry/tests/newman/cases/registry.py", "op_envelope"): CODE,
    ("services/storage/tests/newman/cases/sec-d.py", "id_pattern"): CODE,
    ("services/vpc/tests/newman/cases/vpc1.py", "msg_text"): TEXT,
    # Форма секрета удостоверения: образец приходит из общего объявления
    # (`credential-secret-form.json`), а не выписан в кейсе. Вторая сторона,
    # читающая то же объявление, чеканит значения кодом продукта и требует,
    # чтобы образец их принимал, а подделки отвергал (#1253).
    ("services/iam/tests/newman/cases/basic-access-token.py", "'userToken'"): CODE,
    ("services/iam/tests/newman/cases/docker-lane-credential-kind.py",
     "'serviceAccountKey'"): CODE,
}


def _generator(service: str):
    """Модуль `gen.py` сюиты — он несёт и помощников, и загрузчик деклараций."""
    path = REPO_ROOT / "services" / service / "tests/newman/scripts/gen.py"
    assert path.is_file(), f"генератора сюиты {service} в дереве нет: {path}"
    name = f"kacho_cases_gen_{service}"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def _declaration(service: str, stem: str):
    """Декларация кейсов, загруженная ТЕМ ЖЕ загрузчиком, что и при генерации.

    Именно он впрыскивает помощников в пространство имён модуля, поэтому проба
    судит ту самую сборку, которая порождает коллекцию, а не свою копию.
    """
    gen = _generator(service)
    path = REPO_ROOT / "services" / service / "tests/newman/cases" / f"{stem}.py"
    assert path.is_file(), f"декларации {service}/{stem}.py в дереве нет"
    return gen._RUN.load(path)


# ------------------------------------------------------------------ движок

def _parse_as_function_body(source: str):
    """(разобралось?, сообщение). Обёртка-функция — как исполняет postman."""
    driver = ("const fs=require('fs');"
              "try{new Function(fs.readFileSync(process.argv[1],'utf8'));"
              "process.stdout.write('OK');}"
              "catch(e){process.stdout.write('ERR '+e.name+': '+e.message);}")
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8",
                                     delete=False) as fh:
        fh.write(source)
        name = fh.name
    try:
        proc = subprocess.run(["node", "-e", driver, name],
                              capture_output=True, text=True, timeout=60)
    except FileNotFoundError:  # pragma: no cover — окружение без node
        raise AssertionError(
            "node не найден: разобрать порождаемый JavaScript нечем. Это «ноль "
            "прочитанного», а не «ноль находок», поэтому проба ПАДАЕТ.") from None
    finally:
        Path(name).unlink(missing_ok=True)
    out = proc.stdout.strip()
    assert out.startswith(("OK", "ERR")), f"разборщик не ответил: {proc!r}"
    return out == "OK", out


# ------------------------------------------------------ перепись по дереву

def _predmet(expr: str) -> str:
    """Что именно подставляется: аргумент помощника, если он есть, иначе всё."""
    for helper in _ALL_SANITISERS:
        if expr.startswith(helper):
            depth, out = 0, []
            for ch in expr[len(helper):]:
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                out.append(ch)
            return "".join(out).strip()
    return expr


def _places():
    paths, total, places = jslex.scan_tree(REPO_ROOT, CASE_GLOBS)
    return paths, total, places


def test_every_regex_substitution_in_a_declaration_carries_a_recorded_outcome():
    """ФОРМА + перепись по исходам. Место без записи — находка, а не тишина."""
    paths, total, all_places = _places()
    assert paths, "деклараций кейсов не найдено — перепись беспредметна, а не пуста"
    assert total["js_fstrings"], (
        "f-строк, порождающих JavaScript, не найдено НИ ОДНОЙ — предикат переписи "
        "перестал узнавать свой предмет, и его молчание ничего не значит")
    places = [p for p in all_places if p.state in jslex.IN_REGEX]
    assert places, (
        "подстановок в литерал регулярного выражения не найдено НИ ОДНОЙ — либо "
        "предмет снят целиком (тогда ведомость обязана опустеть), либо разбор "
        "перестал различать литерал выражения и его молчание ничего не значит")

    per_outcome = {CODE: 0, TEXT: 0}
    matched = set()
    findings = []
    for place in places:
        key = (place.path, _predmet(place.expr))
        outcome = RECORDED.get(key)
        if outcome is not None:
            matched.add(key)
        if outcome is None:
            findings.append(
                f"{place} — исход НЕ ЗАПИСАН: подстановка в литерал регулярного "
                f"выражения обязана нести один из трёх исходов (#1209)")
            continue
        per_outcome[outcome] += 1
        if not place.expr.startswith(SANITISER[outcome]):
            findings.append(
                f"{place} — записан исход «{outcome}», но значение подставлено "
                f"без {' | '.join(SANITISER[outcome])}…)")
    strings = [p for p in all_places if p.state in jslex.IN_STRING + jslex.IN_COMMENT]
    print(f"осмотрено: деклараций {len(paths)}, f-строк {total['fstrings']}, "
          f"из них порождающих JS {total['js_fstrings']}, подстановок "
          f"{total['interpolations']}, из них в литерале регулярного выражения "
          f"{len(places)}, в литерале строки либо комментария {len(strings)}; "
          f"исходы: код {per_outcome[CODE]}, текст {per_outcome[TEXT]} (мест; "
          f"ключей ведомости с местом {len(matched)} из {len(RECORDED)}); "
          f"f-строк, оставляющих "
          f"литерал открытым, {total['open_at_end']}")
    assert total["open_at_end"] == 0, (
        f"f-строк, где литерал остаётся открытым до конца строки: "
        f"{total['open_at_end']}. Состояние считается НА f-СТРОКУ, поэтому "
        f"продолжение такого литерала в соседнем элементе списка разбору "
        f"НЕВИДИМО, и перепись занизит молча. Предпосылка задета: либо закройте "
        f"литерал в той же f-строке, либо научите разбор переносить состояние")
    assert not findings, (
        f"мест без записанного исхода либо без помощника своего исхода: "
        f"{len(findings)}\n  " + "\n  ".join(findings))


def test_the_ledger_expires_with_its_subject():
    """САМОИСТЕЧЕНИЕ. Запись, которой больше нечего называть, — находка."""
    _paths, _total, all_places = _places()
    live = {(p.path, _predmet(p.expr)) for p in all_places if p.state in jslex.IN_REGEX}
    orphaned = sorted(k for k in RECORDED if k not in live)
    assert not orphaned, (
        f"записей ведомости, потерявших предмет: {len(orphaned)} — место снято "
        f"или переименовано, а запись пережила его\n  " +
        "\n  ".join(f"{p}: {{{e}}} -> «{RECORDED[(p, e)]}»" for p, e in orphaned))
    print(f"осмотрено: записей ведомости {len(RECORDED)}, живых мест {len(live)}")


def test_the_neighbouring_string_corpus_is_bounded_by_a_number():
    """ГРАНИЦА #1181 названа ЧИСЛОМ и держится храповиком, а не намерением."""
    paths, total, all_places = _places()
    assert paths and total["js_fstrings"], (
        "перепись беспредметна: без осмотренных деклараций храповик молчал бы "
        "не потому, что корпус закрыт, а потому, что его никто не считал")
    strings = [p for p in all_places if p.state in jslex.IN_STRING + jslex.IN_COMMENT]
    print(f"осмотрено: деклараций {len(paths)}, подстановок в литерал строки либо "
          f"комментария {len(strings)}, потолок {STRING_LITERAL_CEILING}")
    assert len(strings) <= STRING_LITERAL_CEILING, (
        f"корпус #1181 в декларациях ВЫРОС: {len(strings)} против потолка "
        f"{STRING_LITERAL_CEILING}. Новое место обязано ехать сериализатором "
        f"(`js_str`/`js_comment`), а не вклейкой")
    if len(strings) < STRING_LITERAL_CEILING:
        print(f"    храповик пора опустить: {STRING_LITERAL_CEILING} -> {len(strings)}"
              + ("; корпус #1181 в декларациях ЗАКРЫТ — снимите храповик вместе "
                 "с границей" if not strings else ""))


def _classify(source: str) -> list:
    """Как перепись судит один файл: (что подставлено, обёрнуто ли своим)."""
    _seen, places = jslex.scan_source(source, "<синтетика>")
    return [(_predmet(p.expr),
             p.expr.startswith(_ALL_SANITISERS))
            for p in places if p.state in jslex.IN_REGEX]


def test_the_census_discriminates_wrapped_from_unwrapped():
    """Инъекция переписи в ОБЕ стороны — на синтетике, без правки дерева."""
    unwrapped = _classify('S = f"pm.expect(x).to.match(/{msg_regex}/);"\n')
    assert unwrapped == [("msg_regex", False)], (
        f"перепись НЕ УВИДЕЛА голую подстановку в литерал выражения: {unwrapped}")

    wrapped_code = _classify(
        'S = f"pm.expect(x).to.match(/{js_regex_src(msg_regex, where=\'a/b\')}/);"\n')
    assert wrapped_code == [("msg_regex", True)], (
        f"перепись не узнала помощника исхода «код»: {wrapped_code}")

    wrapped_text = _classify(
        'S = f"pm.expect(x).to.match(/^{js_regex_literal_text(resource_name)} x$/);"\n')
    assert wrapped_text == [("resource_name", True)], (
        f"перепись не узнала помощника исхода «текст»: {wrapped_text}")

    # Законный близнец: та же обёртка ВНЕ литерала выражения находкой не будет —
    # иначе перепись ловила бы форму вызова, а не место подстановки.
    outside = _classify('S = f"pm.expect(x).to.eql({js_regex_src(p, where=\'q\')});"\n')
    assert outside == [], f"перепись сочла находкой подстановку в КОД: {outside}"
    print("осмотрено: синтетических источников 4 (голый · «код» · «текст» · вне литерала)")


# ------------------------------------------------------------------- швы

_STORAGE_BODY = {"projectId": "{{_suiteProjectId}}", "name": "probe-{{runId}}",
                 "zoneId": "{{existingZoneId}}", "diskTypeId": "{{existingDiskTypeId}}",
                 "sizeBytes": 1}


def _with_attr(module, name, value, produce):
    """Подменить константу декларации на время одного вызова и вернуть обратно."""
    was = getattr(module, name)
    setattr(module, name, value)
    try:
        return produce()
    finally:
        setattr(module, name, was)


# (сервис, декларация, подпись места, вызов, что литерал обязан собой представлять).
#
# Пятое поле — СОСТАВ литерала, и оно не украшение: два места из трёх подставляют
# не весь образец, а ЕГО КУСОК (`^{prefix}[a-z0-9]+$`). Положительный контроль
# обязан искать в скрипте то, что там и окажется, иначе он ловил бы форму вызова.
CODE_SEAMS = [
    ("iam", "authz-sa-apitoken", "iam/allow_asserts/operation-id",
     lambda m, p: _with_attr(m, "_VPC_OPERATION_PREFIX", p,
                             lambda: m.allow_asserts("PROBE", "POST", "/vpc/v1/networks")),
     lambda p: f"/^{p}[a-z0-9]+$/"),
    ("registry", "registry", "registry/_delete_idempotent_op_match/op_envelope",
     lambda m, p: [m._delete_idempotent_op_match(p)],
     lambda p: f"/{p}/"),
    ("storage", "sec-d", "storage/_lifecycle_case/id_prefix",
     lambda m, p: m._lifecycle_case(case_id="PROBE", title="проба",
                                    base_path="/storage/v1/volumes",
                                    obj_type="storage_volume", id_var="volumeId",
                                    id_prefix=p, create_body=_STORAGE_BODY),
     lambda p: f"/^{p}/"),
]

TEXT_SEAMS = [
    ("vpc", "vpc1", "vpc/_assert_op_error/msg_text",
     lambda m, t: m._assert_op_error(3, "INVALID_ARGUMENT", t),
     lambda esc: f"/{esc}$/"),
]

ALL_SEAMS = [(svc, stem, label, call) for svc, stem, label, call, _w
             in CODE_SEAMS + TEXT_SEAMS]

# Негодные образцы, которых НЕ ЧИНИТ никакая сборка: разделитель литерала и
# концы строки ломают его, в какое бы окружение кусок ни попал.
BAD_PATTERNS = [
    ("голый разделитель закрывает литерал", "not found/again"),
    ("подмена: литерал закрылся, хвост стал КОДОМ", "x/; process.exit(1); //"),
    ("конец строки внутри литерала", "not\nfound"),
    ("возврат каретки", "not\rfound"),
    # Разделители строк записаны экранированными намеренно: вписанные знаками,
    # они невидимы в исходнике и первый же редактор молча их съест.
    ("разделитель строк U+2028", "not\u2028found"),
    ("разделитель строк U+2029", "not\u2029found"),
]

# Образцы, негодные САМИ ПО СЕБЕ, но которые СБОРКА способна починить: кусок
# `^[a-z0-9` внутри `^{кусок}[a-z0-9]+$` даёт законный класс символов. Требовать
# от них отказа значило бы требовать от проверки знания о НАМЕРЕНИИ, а не о
# синтаксисе. Инвариант у них слабее и проверяется отдельно: ЛИБО отказ с именем
# места, ЛИБО разбираемый скрипт — но никогда молчаливо порванный файл.
REPAIRABLE_PATTERNS = [
    ("незакрытая группа", "^(nlb|tgr"),
    ("незакрытый класс символов", "^[a-z0-9"),
    ("одинокий обратный слэш в конце", "not found\\"),
    ("пустой образец — это комментарий, а не выражение", ""),
]

# Законные образцы, чей смысл И СОСТОИТ в значимых знаках: помощник обязан
# пропустить их МОЛЧА и не тронуть ни одного знака. Каждый обязан оставаться
# законным во ВСЕХ трёх сборках, иначе положительный контроль мерил бы сборку.
GOOD_PATTERNS = [
    "enp",
    "(rop|reo)",
    "[a-z]{2,3}",
    r"a\/b",         # экранированный разделитель — законен
    "[/]",            # разделитель ВНУТРИ класса литерал не закрывает
    "vol",
    "x.y",
]


def _lines(produced) -> list:
    """Строки скриптов из того, что вернул помощник: список строк, Step или Case."""
    if isinstance(produced, list) and all(isinstance(x, str) for x in produced):
        return [produced]
    steps = getattr(produced, "steps", None)
    if steps is not None:
        out = []
        for step in steps:
            out += _lines(step)
        return out
    if isinstance(produced, (list, tuple)):
        out = []
        for item in produced:
            out += _lines(item)
        return out
    pre = list(getattr(produced, "pre_script", []) or [])
    test = list(getattr(produced, "test_script", []) or [])
    return [block for block in (pre, test) if block]


def _render(svc: str, stem: str, call, value: str) -> str:
    """Весь текст, порождённый помощником, — для поиска литерала ДОСЛОВНО."""
    return "\n".join(_blocks(svc, stem, call, value))


def _blocks(svc: str, stem: str, call, value: str) -> list:
    """Скрипты ПО ОДНОМУ на шаг: postman исполняет каждый в своей области.

    Склеивать их в один текст нельзя — соседние шаги объявляют одноимённые
    переменные (`const j = pm.response.json()`), и движок отвечал бы
    `Identifier 'j' has already been declared` на РОВНОМ месте, то есть проба
    краснела бы на собственной сборке, а не на дефекте.
    """
    blocks = _lines(call(_declaration(svc, stem), value))
    assert blocks, f"{svc}/{stem}: помощник не вернул ни одной строки скрипта"
    return ["\n".join(block) for block in blocks]


def _first_unparsable(blocks: list):
    """(индекс, сообщение) первого неразбираемого скрипта либо None."""
    for i, source in enumerate(blocks):
        ok, message = _parse_as_function_body(source)
        if not ok:
            return i, message
    return None


def test_every_recorded_place_has_a_seam_of_its_own_outcome():
    """Место в ведомости без шва — непроверенное место, а не проверенное.

    Шов обязан быть ТОГО ЖЕ исхода, что запись: шов «код» ничего не говорит о
    том, экранирован ли текст, и наоборот.
    """
    kinds = {svc: CODE for svc, _s, _l, _c, _w in CODE_SEAMS}
    kinds.update({svc: TEXT for svc, _s, _l, _c, _w in TEXT_SEAMS})
    wrong = []
    for (path, expr), outcome in sorted(RECORDED.items()):
        svc = path.split("/")[1] if path.startswith("services/") else path.split("/")[0]
        if svc not in kinds:
            wrong.append(f"{path}: {{{expr}}} «{outcome}» — шва нет вовсе")
        elif kinds[svc] != outcome:
            wrong.append(f"{path}: {{{expr}}} записан «{outcome}», а шов — «{kinds[svc]}»")
    assert not wrong, (
        f"записей ведомости без шва своего исхода: {len(wrong)}\n  " + "\n  ".join(wrong))
    print(f"осмотрено: записей ведомости {len(RECORDED)}, швов «код» {len(CODE_SEAMS)}, "
          f"швов «текст» {len(TEXT_SEAMS)}")


def test_bad_pattern_fails_generation_naming_the_place():
    """СУЩЕСТВО «код». Негодный образец роняет ГЕНЕРАЦИЮ, а не коллекцию."""
    leaked = []
    for svc, stem, label, call, _wrap in CODE_SEAMS:
        for why, pattern in BAD_PATTERNS:
            try:
                blocks = _blocks(svc, stem, call, pattern)
            except ValueError as exc:
                # Место — это ПОЛНАЯ координата «сервис/помощник/параметр», а не
                # имя функции: помощник у трёх сюит одноимённый, и проверка по
                # имени зеленела бы на `where=`, называющем ЧУЖОЙ сервис.
                if label not in str(exc):
                    leaked.append(
                        f"{svc}::{label} отверг «{why}», НЕ НАЗВАВ место "
                        f"(ждали «{label}»): {exc}")
                continue
            bad = _first_unparsable(blocks)
            leaked.append(
                f"{svc}::{label} ПРИНЯЛ негодный образец ({why}); порождённый "
                f"скрипт " + ("разбирается — образец сменил смысл молча"
                              if bad is None else f"НЕ разбирается -> {bad[1]}"))
    assert not leaked, (
        f"мест, где негодный образец уезжает в коллекцию: {len(leaked)}\n  "
        + "\n  ".join(leaked))
    print(f"осмотрено: швов «код» {len(CODE_SEAMS)}, негодных образцов "
          f"{len(BAD_PATTERNS)}, проверок {len(CODE_SEAMS) * len(BAD_PATTERNS)}")


def test_no_input_ever_yields_a_silently_broken_script():
    """ИНВАРИАНТ, общий всем швам и всем исходам: ЛИБО отказ с именем места, ЛИБО
    разбираемый скрипт. Молчаливо порванный файл не бывает НИ ПРИ КАКОМ входе.

    Он слабее предыдущего утверждения и потому не заменяет его: сборка способна
    ПОЧИНИТЬ негодный кусок (`^[a-z0-9` внутри `^{кусок}[a-z0-9]+$` — законный
    класс), и требовать отказа в таком случае значило бы требовать знания о
    намерении. А вот порваться файл не вправе никогда.
    """
    broken = []
    inputs = BAD_PATTERNS + REPAIRABLE_PATTERNS + [("законный", g) for g in GOOD_PATTERNS]
    for svc, stem, label, call in ALL_SEAMS:
        for why, value in inputs:
            try:
                blocks = _blocks(svc, stem, call, value)
            except ValueError as exc:
                if label not in str(exc):
                    broken.append(f"{svc}::{label} отверг «{why}», НЕ НАЗВАВ место: {exc}")
                continue
            bad = _first_unparsable(blocks)
            if bad is not None:
                broken.append(
                    f"{svc}::{label} на входе «{why}» ({value!r}) породил "
                    f"НЕРАЗБИРАЕМЫЙ скрипт (шаг {bad[0]}) и НЕ отказал -> {bad[1]}")
    assert not broken, (
        f"мест, где вход даёт молча порванный скрипт: {len(broken)}\n  "
        + "\n  ".join(broken))
    print(f"осмотрено: швов {len(ALL_SEAMS)}, входов {len(inputs)}, проверок "
          f"{len(ALL_SEAMS) * len(inputs)}")


def test_legal_pattern_passes_untouched_and_verbatim():
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ «код»: значимые знаки обязаны уцелеть ДОСЛОВНО.

    Без него зелёное давал бы помощник, отвергающий всё, — и сломал бы то, ради
    чего эти места вообще существуют.
    """
    broken = []
    for svc, stem, label, call, wrap in CODE_SEAMS:
        for pattern in GOOD_PATTERNS:
            try:
                blocks = _blocks(svc, stem, call, pattern)
            except ValueError as exc:
                broken.append(
                    f"{svc}::{label} отверг ЗАКОННЫЙ образец /{pattern}/: {exc}")
                continue
            bad = _first_unparsable(blocks)
            source = "\n".join(blocks)
            if bad is not None:
                broken.append(f"{svc}::{label} на /{pattern}/ -> {bad[1]}")
            elif wrap(pattern) not in source:
                broken.append(
                    f"{svc}::{label} исказил образец: {wrap(pattern)} в скрипте не "
                    f"найден — экранирование сменило бы СМЫСЛ выражения")
    assert not broken, (
        f"мест, где законный образец не проходит дословно: {len(broken)}\n  "
        + "\n  ".join(broken))
    print(f"осмотрено: швов «код» {len(CODE_SEAMS)}, законных образцов "
          f"{len(GOOD_PATTERNS)}, проверок {len(CODE_SEAMS) * len(GOOD_PATTERNS)}")


# Враждебный текст для исхода «текст»: знаки выражения обязаны стать буквами.
HOSTILE_TEXT = ("Route table (v2) [beta] a.b*c$ ^d|e+f? {1,2} \\ /slash/ "
                "конец\nстроки </script>")
TEXT_INPUTS = (HOSTILE_TEXT, "Security group", "", " ", "/", "\\", ".*", "a|b",
               "Route table", "a.c", "[x]", "(1)", "a*", "^$", "{2}", "a+b?",
               "ipv4_cidr_primary is immutable after Subnet.Create",
               # Разделители строк — экранированными: знаками они невидимы
               # в исходнике, и первый же редактор молча их съест.
               "\n", "\r", "\u2028", "\u2029")


def _regex_matches(pattern: str, subjects: list) -> list:
    """Для каждой строки — совпало ли выражение. Судит НАСТОЯЩИЙ движок."""
    driver = ("const a=JSON.parse(process.argv[1]);"
              "const r=new RegExp(a.pattern);"
              "process.stdout.write(JSON.stringify(a.subjects.map(s=>r.test(s))));")
    payload = json.dumps({"pattern": pattern, "subjects": subjects})
    proc = subprocess.run(["node", "-e", driver, payload],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"движок отверг выражение: {proc.stderr[:400]}"
    return json.loads(proc.stdout)


def test_hostile_text_becomes_letters_not_operators():
    """СУЩЕСТВО и ОБРАТИМОСТЬ «текст»: знаки выражения обязаны стать буквами."""
    broken = []
    for svc, stem, label, call, wrap in TEXT_SEAMS:
        escape = _declaration(svc, stem).js_regex_literal_text
        for text in TEXT_INPUTS:
            blocks = _blocks(svc, stem, call, text)
            source = "\n".join(blocks)
            bad = _first_unparsable(blocks)
            if bad is not None:
                broken.append(f"{svc}::{label} на тексте {text!r} -> {bad[1]}")
                continue
            if wrap(escape(text)) not in source:
                broken.append(
                    f"{svc}::{label} собрал не тот литерал на тексте {text!r}: "
                    f"{wrap(escape(text))} в скрипте не найден")
    assert not broken, (
        f"мест, где текст рвёт порождаемый скрипт: {len(broken)}\n  "
        + "\n  ".join(broken))

    for svc, stem, _label, _call, _wrap in TEXT_SEAMS:
        escape = _declaration(svc, stem).js_regex_literal_text
        for text in TEXT_INPUTS:
            pattern = escape(text)
            # Контроль в обе стороны: выражение обязано совпасть с самим текстом
            # и НЕ совпасть со строкой, где те же знаки сработали операторами.
            decoy = "".join("X" if ch in ".*+?|^$()[]{}\\/" else ch for ch in text)
            hits = _regex_matches(pattern, [text, decoy])
            assert hits[0], (
                f"{svc}: экранированный текст {text!r} не совпадает САМ С СОБОЙ — "
                f"экранирование сменило смысл")
            if decoy != text:
                assert not hits[1], (
                    f"{svc}: экранированный текст {text!r} совпал со строкой "
                    f"{decoy!r}, где его знаки сработали ОПЕРАТОРАМИ — "
                    f"экранирование неполно")
    print(f"осмотрено: швов «текст» {len(TEXT_SEAMS)}, входов {len(TEXT_INPUTS)}")


# Законные ВЫРАЖЕНИЯ (и законные ТЕКСТЫ), враждебные литералу СТРОКИ. Проверка
# исхода «код» их пропускает — и обязана: как выражения они безупречны. Опасны
# они в ДРУГОЙ позиции того же помощника — в подписи шага, и закрывает её другое
# средство. Без этого утверждения помощник vpc был бы закрыт наполовину.
HOSTILE_TO_A_TITLE = [
    ("апостроф закрывает подпись шага", "won't be found"),
    ("обратный слэш съедает следующий знак", "Subnet.Create"),
    ("двойная кавычка", 'say "no"'),
    # Разделитель ЭКРАНИРОВАН намеренно: голый `/` законен только как ТЕКСТ, и
    # общий для обоих исходов список мерил бы тогда сборку, а не подпись шага.
    ("экранированный разделитель и апостроф вместе", r"a\/b won't"),
]


def test_a_value_hostile_to_a_string_literal_does_not_break_the_title():
    """ВТОРАЯ ПОЗИЦИЯ того же значения: подпись шага — это ТЕКСТ, средство своё.

    Измерено, а не предположено: до правки `_assert_op_error(3, …, "/won't be
    found$/")` порождал `pm.test('op.error.message matches /won't be found$/', …)`
    — движок отвечал `SyntaxError: missing ) after argument list`, то есть шаг
    переставал проверять что бы то ни было и отчитывался НУЛЁМ упавших
    утверждений.

    ГРАНИЦА НАЗВАНА ЧИСЛОМ, А НЕ УМОЛЧАНИЕМ. Утверждение спрашивает ТОЛЬКО швы
    исхода «текст» — те, у которых обе позиции закрыты в этом же изменении. У
    швов исхода «код» значение вызывающего доходит и до других позиций, и они
    принадлежат ДРУГИМ корпусам: у storage `id_prefix` уезжает в имя шага, оттуда
    в ЧЕТЫРЕ литерала строки (корпус #1181) и в ОДИН идентификатор
    (`_ck_<имя>` — класс, который не открывал никто: идентификатор не
    экранируется, он либо годен, либо нет). Прогнать этот же вход по швам «код»
    значит покраснеть на чужом предмете, а починить одно место из 473 — «починить
    там, где нашли», оставив класс. Числа названы здесь, чтобы молчание было
    отличимо от осмотра.
    """
    broken = []
    for svc, stem, label, call, _wrap in TEXT_SEAMS:
        for why, value in HOSTILE_TO_A_TITLE:
            try:
                blocks = _blocks(svc, stem, call, value)
            except ValueError as exc:
                broken.append(
                    f"{svc}::{label} отверг ЗАКОННОЕ значение {value!r} ({why}): {exc}")
                continue
            bad = _first_unparsable(blocks)
            if bad is not None:
                broken.append(
                    f"{svc}::{label} на законном {value!r} ({why}) породил "
                    f"НЕРАЗБИРАЕМЫЙ скрипт -> {bad[1]}")
    assert not broken, (
        f"мест, где законное значение рвёт порождаемый скрипт ВНЕ литерала "
        f"выражения: {len(broken)}\n  " + "\n  ".join(broken))
    print(f"осмотрено: швов «текст» {len(TEXT_SEAMS)}, законных-но-враждебных "
          f"подписи значений {len(HOSTILE_TO_A_TITLE)}, проверок "
          f"{len(TEXT_SEAMS) * len(HOSTILE_TO_A_TITLE)}")


# ------------------------------------------------- границы вне переписи

_OPENERS = ("to.match(/", ".test(/", "RegExp(", "match(/")


def _flatten_concat(node) -> list:
    """Операнды конкатенации В ПОРЯДКЕ ИСХОДНИКА: `a + b + c` — это два узла."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_concat(node.left) + _flatten_concat(node.right)
    return [node]


def _concat_as_fstring(node) -> str:
    """Конкатенация → РАВНОСИЛЬНАЯ f-строка, чтобы её судил ТОТ ЖЕ разбор.

    Второй копии лексера здесь не заводится намеренно: копия разошлась бы с
    оригиналом молча — и разошлась бы именно там, где расхождение не видно.
    Постоянные операнды становятся статическим текстом, все прочие —
    подстановкой, а `ast.unparse` берёт на себя кавычки и экранирование.
    """
    values = []
    for part in _flatten_concat(node):
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            values.append(ast.Constant(value=part.value))
        else:
            values.append(ast.FormattedValue(value=ast.Name(id="x", ctx=ast.Load()),
                                             conversion=-1, format_spec=None))
    module = ast.Module(body=[ast.Assign(targets=[ast.Name(id="S", ctx=ast.Store())],
                                         value=ast.JoinedStr(values=values))],
                        type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(module))


def _concat_opens_a_regex(node) -> bool:
    """Садится ли хоть один НЕпостоянный операнд внутрь литерала выражения."""
    try:
        source = _concat_as_fstring(node)
    except (ValueError, RecursionError):  # pragma: no cover — неразбираемая сборка
        return True  # неизвестное считаем находкой, а не тишиной
    _seen, places = jslex.scan_source(source, "<конкатенация>")
    return any(pl.state in jslex.IN_REGEX for pl in places)


def test_the_forms_outside_the_census_are_named_by_number():
    """Формы сборки скрипта, которых перепись НЕ судит, — считаются, а не помнятся.

    Ноль, который не назван, читается как «искали и не нашли», хотя означает «не
    искали». Поэтому числа берутся разбором ЗДЕСЬ, и проба падает, если среди
    несудимых форм окажется подстановка ВНУТРИ литерала выражения.

    СУДЯТ ПО-РАЗНОМУ, И ЭТО НАЗВАНО. Конкатенацию можно привести к равносильной
    f-строке и отдать ТОМУ ЖЕ разбору — вердикт по ней точный. У `%`-формата и
    `.format` приведение потребовало бы разбирать чужой мини-язык подстановок,
    поэтому вердикт по ним ГРУБЫЙ: находкой считается само присутствие
    открывателя литерала в постоянной части. Грубее — значит строже, и молчание
    от этого не становится шире, чем осмотр. Сегодня таких узлов 2 и 0.
    """
    counted = {"%-формат": 0, ".format": 0, "конкатенация": 0,
               "отсеяно предфильтром": 0}
    found = {k: [] for k in counted}
    files = 0

    def _statics(node) -> str:
        return "".join(c.value for c in ast.walk(node)
                       if isinstance(c, ast.Constant) and isinstance(c.value, str))

    for glob in CASE_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            files += 1
            rel = str(path.relative_to(REPO_ROOT))
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            drop = jslex._not_generated_javascript(tree)
            for n in ast.walk(tree):
                kind, hit = None, False
                if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
                    if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
                        kind = "%-формат"
                        hit = any(o in _statics(n) for o in _OPENERS)
                elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                    if any(isinstance(x, ast.Constant) and isinstance(x.value, str)
                           for x in (n.left, n.right)):
                        kind = "конкатенация"
                        hit = (any(o in _statics(n) for o in _OPENERS)
                               and _concat_opens_a_regex(n))
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    if n.func.attr == "format":
                        kind = ".format"
                        hit = any(o in _statics(n) for o in _OPENERS)
                elif isinstance(n, ast.JoinedStr) and id(n) not in drop:
                    whole = "".join(v.value for v in n.values
                                    if isinstance(v, ast.Constant))
                    if not any(m in whole for m in jslex.JS_MARKERS):
                        kind = "отсеяно предфильтром"
                        hit = any(o in whole for o in _OPENERS)
                if kind is None:
                    continue
                counted[kind] += 1
                if hit:
                    found[kind].append(f"{rel}:{n.lineno} ({kind})")
    assert files, "деклараций не осмотрено — числа границ были бы вакуумны"
    print(f"осмотрено: деклараций {files}; вне переписи — "
          + ", ".join(f"{k} {v}" for k, v in counted.items())
          + "; из них подставляют внутрь литерала выражения "
          + ", ".join(f"{k} {len(v)}" for k, v in found.items()))
    leaked = [x for v in found.values() for x in v]
    assert not leaked, (
        f"сборок скрипта, которых перепись НЕ судит, но которые подставляют "
        f"значение ВНУТРЬ литерала регулярного выражения: {len(leaked)} — слепое "
        f"пятно перестало быть пустым, и перепись занижает молча\n  "
        + "\n  ".join(leaked))


def test_the_concatenation_verdict_discriminates_both_ways():
    """Инъекция вердикта по конкатенации — на синтетике, в ОБЕ стороны.

    Без неё «конкатенаций с подстановкой в литерал выражения ноль» означало бы
    только то, что предикат молчит, и ничего — о его способности УВИДЕТЬ.
    Законный близнец взят с натуры: `registry-repository.py` собирает шаг
    конкатенацией и НЕСЁТ литерал `/^reg/`, но подставляет в литерал СТРОКИ —
    первая, грубая редакция этой проверки объявляла его находкой.
    """
    def verdict(src: str) -> bool:
        tree = ast.parse(src)
        nodes = [n for n in ast.walk(tree)
                 if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)]
        assert nodes, "в синтетике нет конкатенации — проба судила бы пустоту"
        return any(_concat_opens_a_regex(n) for n in nodes)

    inside = ('S = "pm.expect(j.id).to.match(/^" + prefix + "/);"\n')
    assert verdict(inside), (
        "вердикт НЕ УВИДЕЛ подстановку внутрь литерала выражения, собранного "
        "конкатенацией")

    in_string = ("S = \"pm.test('id ' + \" + name + \" + ' ok', () => "
                 "pm.expect(j.id).to.match(/^reg/));\"\n")
    assert not verdict(in_string), (
        "вердикт счёл находкой подстановку в литерал СТРОКИ у сборки, которая "
        "лишь СОДЕРЖИТ литерал выражения, — это корпус #1181, а не этот")

    after = ('S = "pm.expect(j.id).to.match(/^reg/) && f(" + x + ");"\n')
    assert not verdict(after), (
        "вердикт счёл находкой подстановку ПОСЛЕ закрытого литерала выражения")
    print("осмотрено: синтетических конкатенаций 3 (внутрь · в строку · после)")
