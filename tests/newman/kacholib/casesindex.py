#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""tests/newman/kacholib/casesindex.py — сверщик КАТАЛОГА кейсов, один на дерево.

ЗАЧЕМ ОН ЗДЕСЬ, А НЕ СЕДЬМОЙ КОПИЕЙ В НАБОРЕ. Сверщик кейсов был у шести наборов
из семи, и шесть копий уже разошлись: по содержимому их **пять** разных — побайтно
совпадают только `nlb` и `registry`, у `geo` и `storage` свои редакции, `vpc` несёт
третью проверку, `compute` — пятую. Предикат:

    for s in vpc nlb storage compute geo registry; do
      md5sum < services/$s/tests/newman/scripts/validate-cases.py; done | sort -u | wc -l

Замер сделан В ДЕРЕВЕ ПЛАТФОРМЫ `PRO-Robotech/kacho`; в этом репозитории команда
не выполнится вовсе — каталога `services/` здесь нет.

Различия накопились копированием соседнего набора при заведении, и ни одно из них
никто не принимал. Седьмая копия сделала бы расхождение семикратным; общий слой уже
существует (`gen_shared.py`) и держит хребет генератора — каталог кейсов принадлежит
туда же.

ЧТО ЗДЕСЬ ОБЩЕЕ, А ЧТО ОСТАЁТСЯ РЕШЕНИЕМ НАБОРА. Общее — четыре свойства ниже.
Решение набора — где лежит его каталог, какие модули освобождены от покрытия и на
сколько сегментов режется идентификатор при поиске суффикс-паттерна: это части
таксономии, и у наборов она РАЗНАЯ (у шести id вида `<РЕСУРС>-<ГЛАГОЛ>-…`, у iam
— `IAM-<РЕСУРС>-<ГЛАГОЛ>-…`, то есть на сегмент длиннее). Унифицировать таксономию
здесь было бы унификацией по самой узкой семантике: суффикс-паттерн, годный
шестерым, у iam не сворачивает НИЧЕГО (замер: 729 идентификаторов → 729 различных
суффиксов при отрезании одного сегмента).

ЧЕТЫРЕ СВОЙСТВА, И КАЖДОЕ ЗАВЕДЕНО ПРОТИВ ТОГО, ЧТО В ДЕРЕВЕ УЖЕ ГНИЛО:

  1. НЕТ ДУБЛЕЙ ИДЕНТИФИКАТОРА. Проверка НЕ СВОЯ — делегируется в `_scan_suite`
     хребта, то есть в тот же код, который зовёт генерация. Своя копия была бы
     вторым местом об одном предмете: разойдясь, она давала бы «сверщик зелен,
     генерация красна» либо наоборот, и оба исхода читались бы как дефект набора.

  2. ПЕРЕПИСЬ КАТАЛОГА СОВПАДАЕТ С ДЕРЕВОМ — и всего, и по каждому модулю. Это
     единственная из четырёх, которая ловит кейс, ВЫПАВШИЙ из набора вместе со
     своим утверждением: покрытие (4) на выпавшем кейсе молчит by construction —
     ему нечего покрывать. Число, переписанное рукой, дрейфует само; вопрос лишь
     в том, заметит это гейт или следующий читатель, который на него положится.
     Класс наблюдался у compute: перепись в шапке разошлась с деревом (111/43
     против 117/49).

  3. НИ ОДИН ЗАГОЛОВОК НЕ НАЗЫВАЕТ МОДУЛЬ КЕЙСОВ, КОТОРОГО НЕТ. Раздел про
     удалённый файл читается как описание покрытия и переживает своё содержимое —
     именно так у compute выжил `## Instance (77 кейсов) — cases/instance.py`
     после удаления файла.

     Судятся ЗАГОЛОВКИ И СТРОКИ ПЕРЕПИСИ, а не весь текст, и это не поблажка:
     заголовок — то, что читатель принимает за «это есть», а упоминание удалённого
     модуля в ПРОЗЕ, прямо говорящей о его удалении, — законное историческое
     свидетельство. Гейт, запрещающий второе, заставлял бы стирать объяснение
     вместе с ложью.

  4. КАЖДЫЙ ИДЕНТИФИКАТОР КАТАЛОГИЗИРОВАН — литерально в каталоге, ЛИБО покрыт
     суффикс-паттерном `*-<СУФФИКС>`, ЛИБО помечен `# index: <ref>` рядом со
     строкой `id=` в модуле кейсов, ЛИБО живёт в освобождённом модуле.

ЧЕГО ЭТОТ СВЕРЩИК НЕ ДЕЛАЕТ. Он не судит СМЫСЛ записи каталога: что против
идентификатора написана правда, машинно не решается. Он судит, что запись ЕСТЬ и
что числа сходятся с деревом. Это надо говорить вслух — иначе «каталог зелёный»
прочитается шире сделанного.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from gen_shared import _scan_suite

# Ссылка на модуль кейсов в тексте каталога: `cases/<имя>.py`, с обратными
# кавычками или без. Именно эта форма и переживает удаление файла.
_CASES_FILE_REF_RE = re.compile(r"`?cases/([A-Za-z0-9_.-]+)\.py`?")
# Заголовок markdown любого уровня.
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")
# Строка переписи по модулю: `| `cases/<имя>.py` | <N> |`.
_CENSUS_ROW_RE = re.compile(
    r"^\s*\|\s*`?cases/([A-Za-z0-9_.-]+)\.py`?\s*\|\s*(\d+)\s*\|")
# Объявленный итог. Форма НАЗВАНА здесь, а не выведена из прозы: разбор
# естественного языка у compute читает фразу с тире и переносом строки, и его
# первая же перефразировка молча перестала бы находить число.
_CENSUS_TOTAL_RE = re.compile(r"^\s*[Вв]сего кейсов:\s*(\d+)\s*$", re.MULTILINE)
# Тег «инстанс уже каталогизированного паттерна».
_INDEX_TAG_RE = re.compile(r"#\s*index:\s*(\S+)")
# Объявление идентификатора в исходнике модуля кейсов.
_ID_RE = re.compile(r"""id\s*=\s*["']([A-Z0-9][A-Z0-9_-]+)["']""")


@dataclass
class Census:
    """Объём осмотренного. Печатается ВСЕГДА — и на зелёном тоже.

    Величины названы ПОРОЗНЬ: одно суммарное число скрыло бы ровно тот случай,
    ради которого сверщик заведён («ноль находок» неотличимо от «ноль
    прочитанного»).
    """

    modules: int = 0
    cases: int = 0
    unique_ids: int = 0
    exempt_modules: int = 0
    exempt_cases: int = 0
    by_literal: int = 0
    by_pattern: int = 0
    by_tag: int = 0
    index_bytes: int = 0
    census_rows: int = 0
    headings_with_file_ref: int = 0
    per_module: dict = field(default_factory=dict)

    def format(self) -> str:
        return (
            f"осмотрено: модулей {self.modules} (освобождённых {self.exempt_modules}), "
            f"кейсов {self.cases} (уникальных идентификаторов {self.unique_ids}, "
            f"в освобождённых модулях {self.exempt_cases}); "
            f"каталог {self.index_bytes} байт, строк переписи {self.census_rows}, "
            f"заголовков со ссылкой на модуль {self.headings_with_file_ref}; "
            f"покрытие: литералом {self.by_literal}, паттерном {self.by_pattern}, "
            f"тегом `# index:` {self.by_tag}"
        )


def _suffix(case_id: str, strip_segments: int) -> str:
    """`IAM-WAI-GT-CRUD-OK` при strip_segments=2 → `GT-CRUD-OK`.

    Сколько сегментов отрезать — решение НАБОРА, а не общего слоя: в таксономии
    шести наборов ресурс стоит первым сегментом, у iam — вторым.
    """
    parts = case_id.split("-")
    return "-".join(parts[strip_segments:]) if len(parts) > strip_segments else case_id


def _tagged_ids(modules: list) -> dict:
    """Идентификаторы, помеченные `# index:` на строке `id=` или на 1-2 выше.

    Читается ИСХОДНИК модуля, а не собранный кейс: тег — комментарий, до объекта
    `Case` он не доживает by construction.
    """
    tagged: dict = {}
    for f in modules:
        lines = f.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            m = _ID_RE.search(line)
            if not m:
                continue
            window = "\n".join(lines[max(0, i - 2): i + 1])
            if _INDEX_TAG_RE.search(window):
                tagged.setdefault(m.group(1), set()).add(f.name)
    return tagged


def audit(run, index_path: Path, *,
          exempt_file_re: Optional[re.Pattern] = None,
          strip_segments: int = 1,
          require_census: bool = True) -> tuple[list[str], Census]:
    """Свести каталог кейсов набора с деревом. Возвращает (находки, перепись).

    `run` — дескриптор оркестрации набора (`gen._RUN`). Модули берутся его
    отбором, а кейсы — его загрузчиком: сверщик обязан видеть ровно то, что
    увидит генерация. Пока он звал загрузчик своими руками, его вызов разошёлся
    с генератором на первой же смене подписи — и проверка перестала исполняться
    ВОВСЕ, отвечая отказом на каждый набор (#1379).
    """
    findings: list[str] = []
    cen = Census()

    # ---- (1) дубли и не-Case: тем же кодом, что зовёт генерация ----
    bad_types, dups = _scan_suite(run)
    if bad_types:
        findings.append("в CASES лежит не-Case:\n" + "\n".join(bad_types))
    if dups:
        findings.append("идентификатор кейса повторяется в наборе:\n" + "\n".join(dups))

    modules = run.case_modules()
    cen.modules = len(modules)
    if not modules:
        findings.append(
            f"модулей кейсов в {run.cases_dir} НОЛЬ — обход пуст, и сверять нечего.\n"
            "    Это отказ, а не чистое дерево: «ноль находок» обязано быть отличимо\n"
            "    от «ноль прочитанного».")
        return findings, cen

    exempt: Callable[[str], bool] = (
        (lambda n: bool(exempt_file_re.match(n))) if exempt_file_re else (lambda _n: False))

    cases: list[tuple[str, str]] = []
    for f in modules:
        ids = [c.id for c in getattr(run.load(f), "CASES", [])]
        cen.per_module[f.name] = len(ids)
        if exempt(f.name):
            cen.exempt_modules += 1
            cen.exempt_cases += len(ids)
        for cid in ids:
            cases.append((cid, f.name))
    cen.cases = len(cases)
    cen.unique_ids = len({c for c, _ in cases})

    if not cases:
        findings.append(
            f"кейсов в {run.cases_dir} НОЛЬ при {cen.modules} модулях — "
            "каталогу нечего покрывать.")
        return findings, cen

    index_text = index_path.read_text(encoding="utf-8") if index_path.is_file() else ""
    cen.index_bytes = len(index_text.encode("utf-8"))
    if not index_text.strip():
        findings.append(
            f"каталога кейсов нет либо он пуст: {index_path}.\n"
            "    Каталог — второе место, откуда видно, что кейс существует; без него\n"
            "    выпавший кейс не заметен ничем.")
        return findings, cen

    lines = index_text.splitlines()
    tree_modules = {f.name for f in modules}

    # ---- (3) заголовок и строка переписи не называют несуществующий модуль ----
    for n, line in enumerate(lines, 1):
        is_heading = bool(_HEADING_RE.match(line))
        is_census_row = bool(_CENSUS_ROW_RE.match(line))
        if not (is_heading or is_census_row):
            continue
        refs = _CASES_FILE_REF_RE.findall(line)
        if is_heading and refs:
            cen.headings_with_file_ref += 1
        for ref in refs:
            if f"{ref}.py" not in tree_modules:
                findings.append(
                    f"{index_path.name}:{n} — {'заголовок' if is_heading else 'строка переписи'} "
                    f"называет `cases/{ref}.py`, которого в дереве нет.\n"
                    "    Раздел, переживший свой модуль, читается как описание покрытия.")

    # ---- (2) перепись каталога совпадает с деревом ----
    declared_per: dict = {}
    for line in lines:
        m = _CENSUS_ROW_RE.match(line)
        if m:
            declared_per[f"{m.group(1)}.py"] = int(m.group(2))
    cen.census_rows = len(declared_per)

    m_total = _CENSUS_TOTAL_RE.search(index_text)
    if require_census:
        if m_total is None:
            findings.append(
                f"{index_path.name} не объявляет итог переписи строкой "
                f"«Всего кейсов: <N>» — сверять с деревом нечего.")
        elif int(m_total.group(1)) != cen.cases:
            findings.append(
                f"{index_path.name}: объявлено «Всего кейсов: {m_total.group(1)}», "
                f"в дереве {cen.cases}.\n"
                "    Расхождение означает, что кейс добавлен или выпал, а каталог об этом\n"
                "    не знает.")
        if not declared_per:
            findings.append(
                f"{index_path.name} не несёт ни одной строки переписи по модулю "
                "(`| `cases/<имя>.py` | <N> |`) — выпадение кейса из отдельного модуля\n"
                "    осталось бы незаметным при сходящемся итоге.")
        for name in sorted(tree_modules | set(declared_per)):
            want = cen.per_module.get(name)
            got = declared_per.get(name)
            if want is None:
                continue  # уже названо проверкой (3): модуля в дереве нет
            if got is None:
                findings.append(
                    f"{index_path.name}: модуль `cases/{name}` ({want} кейсов) "
                    "в переписи каталога отсутствует.")
            elif got != want:
                findings.append(
                    f"{index_path.name}: по `cases/{name}` объявлено {got}, "
                    f"в дереве {want}.")

    # ---- (4) покрытие каждого идентификатора ----
    tagged = _tagged_ids(modules)
    checked: set = set()
    for cid, fname in cases:
        if cid in checked:
            continue
        checked.add(cid)
        if exempt(fname):
            continue
        if cid in tagged:
            cen.by_tag += 1
            continue
        if cid in index_text:
            cen.by_literal += 1
            continue
        suf = _suffix(cid, strip_segments)
        if f"*-{suf}" in index_text:
            cen.by_pattern += 1
            continue
        findings.append(
            f"кейс {cid!r} (из {fname}) не каталогизирован в {index_path.name}.\n"
            f"    → НОВЫЙ уникальный паттерн: добавь запись `{cid}` (или `*-{suf}`) в каталог;\n"
            f"    → ИНСТАНС существующего паттерна: пометь строку с `id=` тегом "
            f"`# index: <ref>`.")

    return findings, cen


def main(run, index_path: Path, *,
         exempt_file_re: Optional[re.Pattern] = None,
         strip_segments: int = 1,
         require_census: bool = True) -> int:
    """Тело сверщика набора. Набор связывает СВОИ решения и возвращает этот код."""
    import sys

    findings, cen = audit(run, index_path, exempt_file_re=exempt_file_re,
                          strip_segments=strip_segments, require_census=require_census)
    if findings:
        sys.stderr.write("validate-cases: FAIL\n")
        for f in findings:
            sys.stderr.write("  - " + f + "\n")
        # Перепись печатается и на красном: без неё непонятно, СКОЛЬКО осмотрено,
        # и находка неотличима от усечённого обхода.
        sys.stderr.write("  " + cen.format() + "\n")
        return 1
    print(f"validate-cases: OK — {cen.unique_ids} уникальных идентификаторов, дублей нет, "
          f"все каталогизированы; перепись каталога совпадает с деревом")
    print(cen.format())
    return 0
