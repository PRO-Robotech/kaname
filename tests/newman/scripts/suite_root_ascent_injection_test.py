#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство, что держатель подъёма СПОСОБЕН упасть и способен смолчать.

Гоняются НАСТОЯЩИЕ судящие функции (`ascent_findings`, `branch_shape`,
`executable_part`), а не их пересказ. Вход синтетический; оси проверяются по
одной, у каждой инъекции — законный близнец, отличающийся ровно ОДНИМ фактом.

ФОРМЫ ЗАПИСИ ПРЕДМЕТА ПЕРЕЧИСЛЕНЫ, И ПО КАЖДОЙ ЕСТЬ ПАРА. Форма, о которой
распознаватель не знает, даёт не красное и не зелёное, а молчание, поэтому здесь
проверяется каждая:

  1 подъём в присваивании             `R="$(cd ../../../.. && pwd)"`
  2 подъём через переменную            `cd "$D/../../../.."`
  3 подъём глубже четырёх              `../../../../..`
  4 подъём в КОММЕНТАРИИ                       — законный близнец, молчание
  5 решётка ВНУТРИ кавычек — не комментарий, находка за ней обязана найтись
  6 подъём на два уровня `../..`               — законный близнец, молчание
  7 ветвь без `else`                            — находка
  8 ветвь с печатающим `else`                  — законный близнец, молчание
  9 `else` без печати                           — находка
 10 `fi`/`else` внутри строкового литерала — не ключевое слово

Проводку держит `.github/scripts/run-python-probes.py` обходом дерева; гейт
проводки с тем же предметом — координата ДЕРЕВА ПЛАТФОРМЫ, здесь его нет.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import suite_root_ascent_test as gate  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def ascent_of(body: str):
    """Находки по синтетическому скрипту оболочки."""
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "synth.sh").write_text(body, encoding="utf-8")
        return gate.ascent_findings(gate.shell_scripts(d))


GOOD_ASCENT = '''#!/usr/bin/env bash
_root() {
  local d="$PWD"
  while [[ "$d" != "/" ]]; do
    [[ -f "$d/go.mod" ]] && { printf '%s\\n' "$d"; return 0; }
    d="$(dirname "$d")"
  done
  return 1
}
ROOT="$(_root)"
'''

BRANCH_WITH_ELSE = '''#!/usr/bin/env bash
DECL="$ROOT/tests/authz-fixtures/ceremony_credentials.py"
if [[ -f "$DECL" ]]; then
  echo "[ceremony] волна активна"
else
  echo "[ceremony] волна НЕ активирована: нет объявления $DECL"
fi
'''


def main() -> int:
    print("ось 1 — подъём в присваивании")
    hits, read, seen = ascent_of('ROOT="$(cd ../../../.. && pwd)"\n')
    check("инъекция: находка", any("../../../.." in h for h in hits), str(hits))
    check("находка называет строку", any("synth.sh:1" in h for h in hits), str(hits))
    hits, _, _ = ascent_of(GOOD_ASCENT)
    check("контроль: подъём до признака — молчание", not hits, str(hits))

    print("ось 2 — подъём через переменную")
    hits, _, _ = ascent_of('ROOT="$(cd "$D/../../../.." && pwd)"\n')
    check("инъекция: находка", bool(hits), str(hits))

    print("ось 3 — подъём ГЛУБЖЕ четырёх")
    hits, _, _ = ascent_of('cd ../../../../..\n')
    check("инъекция: находка", bool(hits), str(hits))
    check("находка называет ВСЮ цепочку, а не её начало",
          any("../../../../.." in h for h in hits), str(hits))

    print("ось 4 — тот же подъём в КОММЕНТАРИИ (законный близнец)")
    hits, _, _ = ascent_of('# прежде здесь стояло ../../../.. — свойство раскладки\n')
    check("контроль: молчание", not hits, str(hits))
    hits, _, _ = ascent_of('ROOT=x   # было ../../../..\n')
    check("контроль: хвостовой комментарий — молчание", not hits, str(hits))

    print("ось 5 — решётка ВНУТРИ кавычек комментария не открывает")
    hits, _, _ = ascent_of('echo "цена #1: ../../../.. уезжает выше корня"\n')
    check("инъекция: находка за кавычкой найдена", bool(hits), str(hits))

    print("ось 6 — подъём на ДВА уровня (законный близнец)")
    hits, _, _ = ascent_of('cd "$(dirname "$0")/.."\ncd ../..\n')
    check("контроль: молчание", not hits, str(hits))

    print("ось 7 — перепись растёт вместе с обходом")
    _, read1, seen1 = ascent_of('a=1\n')
    _, read2, seen2 = ascent_of('a=1\nb=2\nc=3\n')
    check("строк-кода осмотрено больше на большем входе", seen2 > seen1,
          f"{seen1} против {seen2}")
    check("пустой обход отличим: файлов 0", gate.ascent_findings([])[1] == 0, "")

    print("ось 8 — ветвь БЕЗ else")
    shape = gate.branch_shape(BRANCH_WITH_ELSE.replace(
        'else\n  echo "[ceremony] волна НЕ активирована: нет объявления $DECL"\n', ''), "DECL")
    check("инъекция: находка — else отсутствует",
          shape.get("ветвь") and not shape.get("else"), str(shape))

    print("ось 9 — ветвь С ПЕЧАТАЮЩИМ else (законный близнец)")
    shape = gate.branch_shape(BRANCH_WITH_ELSE, "DECL")
    check("контроль: молчание", bool(shape.get("else") and shape.get("else печатает")),
          str(shape))
    check("ветвь опознана по УСЛОВИЮ, а не по присваиванию строкой выше",
          shape.get("строка if") == 3, str(shape))

    print("ось 10 — else БЕЗ печати")
    shape = gate.branch_shape(BRANCH_WITH_ELSE.replace(
        'echo "[ceremony] волна НЕ активирована: нет объявления $DECL"', ':'), "DECL")
    check("инъекция: находка — else есть, не печатает",
          shape.get("else") and not shape.get("else печатает"), str(shape))

    print("ось 11 — `fi`/`else` внутри литерала не ключевое слово")
    shape = gate.branch_shape(
        'if [[ -f "$DECL" ]]; then\n  echo "скажи fi и else"\n'
        '  echo "ещё"\nelse\n  echo "нет"\nfi\n', "DECL")
    check("ветвь дочитана до настоящего fi",
          shape.get("else") and shape.get("else печатает") and shape.get("строка fi") == 6,
          str(shape))

    print("ось 13 — признак корня РАЗОШЁЛСЯ между копиями")
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "a.sh").write_text(
            '_tree_root() {\n  local d="$1"\n  [[ -f "$d/go.mod" ]] && echo "$d"\n}\n',
            encoding="utf-8")
        (d / "b.sh").write_text(
            '_tree_root() {\n  local d="$1"\n  [[ -f "$d/Makefile" ]] && echo "$d"\n}\n',
            encoding="utf-8")
        markers, fns = gate.root_markers(gate.shell_scripts(d))
        check("инъекция: находка — признаков больше одного", len(markers) == 2, str(markers))
        check("находка называет ОБЕ координаты", fns == 2, str(fns))
        (d / "b.sh").write_text(
            '_tree_root() {\n  local d="$1"\n  [[ -f "$d/go.mod" ]] && echo "$d"\n}\n',
            encoding="utf-8")
        markers, fns = gate.root_markers(gate.shell_scripts(d))
        check("контроль: копии согласны — молчание", len(markers) == 1 and fns == 2,
              str(markers))

    print("ось 14 — `}` ВНУТРИ литерала не закрывает тело функции")
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "c.sh").write_text(
            '_tree_root() {\n  echo "фигурная скобка } в тексте"\n'
            '  [[ -f "$d/go.mod" ]] && echo "$d"\n}\n', encoding="utf-8")
        markers, fns = gate.root_markers(gate.shell_scripts(d))
        check("признак за литералом найден", markers.get("go.mod") is not None, str(markers))

    print("ось 15 — подъём БЕЗ признака (тело есть, признака нет)")
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "e.sh").write_text('_tree_root() {\n  echo "$1"\n}\n', encoding="utf-8")
        markers, fns = gate.root_markers(gate.shell_scripts(d))
        check("инъекция: находка — «признака нет», а не молчание",
              "<признака нет>" in markers, str(markers))

    print("ось 16 — объявлений НЕТ ВОВСЕ: ось беспредметна, а не чиста")
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "f.sh").write_text('echo привет\n', encoding="utf-8")
        markers, fns = gate.root_markers(gate.shell_scripts(d))
        check("объявлений 0 — отличимо от «все согласны»", fns == 0 and not markers,
              f"{fns} {markers}")

    print("ось 12 — предмет исчез: якорь не найден")
    shape = gate.branch_shape('echo привет\n', "DECL")
    check("инъекция: «не найден», а не молчаливое «всё хорошо»",
          shape == {"найден": False}, str(shape))

    print()
    if FAILURES:
        print(f"ОТКАЗ: провалено утверждений {len(FAILURES)} из 24", file=sys.stderr)
        for x in FAILURES:
            print("  " + x, file=sys.stderr)
        return 1
    print("ЧИСТО: 24 утверждения, держатель способен упасть и способен смолчать "
          "по каждой из шестнадцати осей")
    return 0


if __name__ == "__main__":
    sys.exit(main())
