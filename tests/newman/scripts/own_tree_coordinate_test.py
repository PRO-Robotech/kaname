#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДЕРЖАТЕЛЬ КЛАССА «КООРДИНАТА ЧУЖОГО ДЕРЕВА, НАЗВАННАЯ СВОЕЙ».

ПРЕДМЕТ. Служба вынесена из монорепо отдельным продуктом, и текст набора уехал
вместе с ней ДОСЛОВНО. Координаты, верные в дереве платформы, читаются здесь как
действующие координаты ЭТОГО дерева: читатель идёт по ним и не находит ничего.
Утверждение пережило свой предмет ровно в момент выноса, и не покраснело нигде —
потому что ничем не удержано.

ТРИ ОСИ, И ВСЕ ТРИ ИЗМЕРЕНЫ, А НЕ ПРЕДПОЛОЖЕНЫ:

  A  проводка проб: «Проводку держит `tools/pythonprobes`» — 19 файлов при нуле
     отслеживаемых файлов по этой координате;
  A2 образец состава: «собирает обходом дерева по образцу
     `services/*/tests/newman/scripts/*_test.py`» — 24 файла, при том что
     прогонщик такого образца НЕ НЕСЁТ: набор лежит в корне, а не под
     `services/<имя>/`;
  B  координата фикстуры: `tests/authz-fixtures/prodseed_matrix.py` и соседи —
     каталог в дереве ЕСТЬ и несёт свой посев, поэтому координата под ним
     читается как своя, а файла нет.

ПОЧЕМУ ОСЬ A2 НАЙДЕНА ПЕРЕМЕРОМ, А НЕ СТОЯЛА В ЗАДАНИИ. Задача называла ось A и
число 19. Тот же разбор по второй форме дал 24 — на пять файлов больше, и это
ровно тот механизм, ради которого перечень форм пишется числом: форма, о которой
распознаватель не знает, даёт молчание, а не находку.

ПОЧЕМУ ОСЬ A2 СУДИТ ПО ПРОИЗВОДИТЕЛЮ, А НЕ ПО ЛИТЕРАЛУ. Образцы состава
объявлены прогонщиком (`DEFAULT_PATTERNS`). Выписать их здесь значило бы завести
второе место об одном предмете; вместо этого прогонщик ИМПОРТИРУЕТСЯ, и находкой
становится образец, которого он не несёт. Смена образца у производителя
автоматически меняет вердикт — послабление истекает само.

ПОЧЕМУ ШИРОКАЯ ОСЬ ОТВЕРГНУТА — ЗАМЕРЕНО, А НЕ ВЫБРАНО ПО ВКУСУ. Соблазн был
судить ВСЯКУЮ нерезолвящуюся координату в обратных кавычках. Замер по стволу:
273 различных координаты в 839 вхождениях при резолве от корня; 96 различных в
177 вхождениях при резолве от корня И от каталога набора. Законных среди них
большинство — координаты платформы и фундамента, названные в прозе о них же
(`internal/repohygiene`, `pkg/…`, `gateway/…`), плюс имена RPC вида
`UserService/Invite`, неотличимые от пути по форме. Такой гейт потребовал бы
ведомости прощённых в сотни записей — то есть ровно того, что запрещено:
каждая запись есть место, куда невидимость вносят незамеченной. Поэтому оси
УЗКИЕ и привязаны к УТВЕРЖДЕНИЮ («проводку держит X», «образец состава — X»),
либо к каталогу, который в этом дереве ЕСТЬ и потому читается как свой.

ЧТО ОСЬ B СЧИТАЕТ ЗАКОННЫМ. Координату, названную МЕЖРЕПОЗИТОРНОЙ: с
приставкой `<владелец>/<репозиторий>:`. Тогда утверждение перестаёт быть о
ЭТОМ дереве и становится верным. Это и есть предикат снятия задачи #30.

ПОЧЕМУ РАЗБОР, А НЕ ПОДСТРОКА. Координаты встречаются в прозе О КЛАССЕ — в этой
шапке, в README набора, в записи вендоринга. Проверка по подстроке краснела бы
на собственном объяснении. Судится ЕДИНИЦА ТЕКСТА по форме (общий слой
`kacholib/prose_forms.py`), и утверждение опознаётся оборотом, а не именем.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`, обходом дерева.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "kacholib"))

from prose_forms import prose_units, tracked_files  # noqa: E402

SELF = pathlib.Path(__file__).resolve()
ROOT = pathlib.Path(__file__).resolve().parents[3]
FIXTURES_DIR = "tests/authz-fixtures"

# ── УТВЕРЖДЕНИЯ, КОТОРЫЕ СУДЯТСЯ ────────────────────────────────────────────
#
# Ловится СЕМЬЯ оборота, а не один литерал: редакция меняет порядок слов, не
# меняя утверждения. Координата берётся из обратных кавычек — вне их это проза.
# Промежуток между оборотом и координатой ДОПУСКАЕТ ПЕРЕВОД СТРОКИ: шапка
# переносится по ширине, и утверждение, у которого оборот остался на одной
# строке, а координата уехала на следующую, — та же форма, а не другая. Без
# этого ось молчала бы на переносе: замер дал одно такое место из 24.
WIRING_CLAIM_RE = re.compile(
    r"[Пп]роводку\s+держит[^`]{0,40}`([^`\n]+)`")
PATTERN_CLAIM_RE = re.compile(
    r"по\s+образц[ауе][^`]{0,40}`([^`\n]+)`")
# Образец состава — предмет ПРОГОНЩИКА ПРОБ, а не всякий образец в дереве. Без
# этого сужения ось краснела бы на «по образцу `785001_*.sql`» в пробе миграций
# и на «по образцу `*_test.py`» в объявлении конвейера — утверждениях о ДРУГОМ
# предмете, верных по существу. Признак предмета — упоминание самого
# производителя в той же единице текста: он и есть тот, чей состав описывают.
RUNNER_MENTION_RE = re.compile(r"run-python-probes")
# Приставка дома: `владелец/репозиторий:путь`. Тогда координата межрепозиторная и
# утверждением об ЭТОМ дереве не является.
QUALIFIED_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:(?:[^\s`]+)")
# Хвостовая пунктуация в координату не входит: точка в конце предложения
# попадала в имя и находка называла файл, которого не бывает ни в одном дереве.
FIXTURE_COORD_RE = re.compile(
    r"(?<![A-Za-z0-9_/.:-])(" + re.escape(FIXTURES_DIR)
    + r"/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)")


def runner_patterns() -> tuple[str, ...]:
    """Образцы состава берутся У ПРОИЗВОДИТЕЛЯ, а не выписываются здесь."""
    path = ROOT / ".github" / "scripts" / "run-python-probes.py"
    spec = importlib.util.spec_from_file_location("run_python_probes", path)
    if not (spec and spec.loader):
        return ()
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_python_probes"] = mod
    spec.loader.exec_module(mod)
    return tuple(mod.DEFAULT_PATTERNS)


def tracked_set(root: pathlib.Path) -> tuple[set[str], set[str]]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         capture_output=True, check=True)
    rels = [r for r in out.stdout.decode("utf-8").split("\0") if r]
    dirs: set[str] = set()
    for rel in rels:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    return set(rels), dirs


def resolves(coord: str, files: set[str], dirs: set[str]) -> bool:
    """Резолв от корня дерева И от каталога набора.

    Второй корень обязателен: набор адресует своё содержимое относительно себя
    (`scripts/case_home_test.py`), и судить такие координаты от корня значило бы
    объявить находкой 41 законное вхождение.
    """
    c = coord.rstrip("/")
    for base in ("", "tests/newman/"):
        cand = (base + c).rstrip("/")
        if cand in files or cand in dirs:
            return True
    return False


def sweep(files_on_disk, *, root: pathlib.Path, tracked, patterns):
    """(находки A, находки A2, находки B, файлов прочитано, единиц, по формам)."""
    tset, tdirs = tracked
    hits_a: list[str] = []
    hits_a2: list[str] = []
    hits_b: list[str] = []
    volume: dict[str, int] = {}
    read = 0
    for path in files_on_disk:
        if not path.is_file() or path.resolve() == SELF:
            continue
        units = prose_units(path)
        read += 1
        try:
            where = path.relative_to(root)
        except ValueError:
            where = path
        for form, line, chunk in units:
            volume[form] = volume.get(form, 0) + 1
            for m in WIRING_CLAIM_RE.finditer(chunk):
                coord = m.group(1).strip()
                if QUALIFIED_RE.search(coord) or resolves(coord, tset, tdirs):
                    continue
                hits_a.append(f"{where}:{line} [{form}] проводку держит {coord!r} — "
                              f"в этом дереве такой координаты нет")
            if patterns and RUNNER_MENTION_RE.search(chunk):
                for m in PATTERN_CLAIM_RE.finditer(chunk):
                    pat = m.group(1).strip()
                    if "*" not in pat or pat in patterns:
                        continue
                    hits_a2.append(
                        f"{where}:{line} [{form}] образец состава {pat!r} — "
                        f"прогонщик такого не несёт: {list(patterns)}")
            # ОСЬ B СУДИТ ПРОЗУ, А НЕ ИСПОЛНЯЕМУЮ СТРОКУ. Форма 6 у скрипта —
            # это КОД: строка, СТРОЯЩАЯ путь, утверждением о дереве не является,
            # она его спрашивает, и отсутствие ответа там уже названо исходом
            # (`suite_root_ascent_test.py`, ось 2 — громкий отказ вместо
            # молчаливого пропуска). Требовать в коде межрепозиторную приставку
            # значило бы требовать путь, который не откроется.
            if form == "6-печатаемое":
                continue
            for m in FIXTURE_COORD_RE.finditer(chunk):
                coord = m.group(1)
                if resolves(coord, tset, tdirs):
                    continue
                span = chunk[max(0, m.start() - 60):m.end()]
                if QUALIFIED_RE.search(span):
                    continue
                hits_b.append(f"{where}:{line} [{form}] {coord} — файла в этом "
                              f"дереве нет, и дом не назван")
    return hits_a, hits_a2, hits_b, read, volume


FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def main() -> int:
    patterns = runner_patterns()
    print(f"образцы состава у производителя: {list(patterns)}")
    files = tracked_files(ROOT)
    tracked = tracked_set(ROOT)
    a, a2, b, read, volume = sweep(files, root=ROOT, tracked=tracked, patterns=patterns)
    total = sum(volume.values())
    print(f"ОБЪЁМ ОСМОТРЕННОГО: файлов {read}, единиц текста {total}; по формам: "
          + ", ".join(f"{f} {volume[f]}" for f in sorted(volume)))
    print(f"находок: проводка {len(a)} · образец состава {len(a2)} · "
          f"координата фикстуры {len(b)}")
    check("обход не пуст", bool(read and total),
          f"файлов {read}, единиц {total} — вердикта о дереве нет")
    check("образцы состава прочитаны у производителя", bool(patterns),
          "прогонщик проб не импортировался — ось A2 беспредметна, и её молчание "
          "неотличимо от её смерти")
    check("ось A: проводка названа координатой ЭТОГО дерева", not a,
          f"{len(a)} мест(а): " + "; ".join(a[:6]))
    check("ось A2: образец состава совпадает с производителем", not a2,
          f"{len(a2)} мест(а): " + "; ".join(a2[:6]))
    check("ось B: координата фикстуры либо резолвится, либо названа межрепозиторной",
          not b, f"{len(b)} мест(а): " + "; ".join(b[:8]))
    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)}", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: координат чужого дерева, названных своими, не осталось")
    return 0


if __name__ == "__main__":
    sys.exit(main())
