#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доказательство: держатель вендоринга СПОСОБЕН упасть — по каждой оси, в обе стороны.

ПРЕДМЕТ. `vendor_provenance_test.py` утверждает, что копия общего слоя не правится
молча. Утверждение о способности проверки падать само требует доказательства:
проверка, потерявшая эту способность, на чистом дереве выглядит ТОЧНО ТАК ЖЕ.

ФОРМА. Гоняется НАСТОЯЩАЯ проба на синтетическом дереве: оригинал копируется в
временный каталог ВНЕ репозитория, вносится РОВНО ОДНО различие, читается код
возврата и текст. Рядом с каждой инъекцией стоит законный близнец — та же форма
без дефекта, на которой проба обязана молчать. Без близнеца красное могло бы
приходить от соседа.

Временный каталог берётся из `TMPDIR`/системного и НИКОГДА не заводится внутри
репозитория: инструмент, собирающий дерево под чужим индексом, находит его
обходом вверх и краснеет по ложной причине.

ИСХОДЫ: 0 — все утверждения сошлись; 1 — хотя бы одно нет; 2 — позван неверно.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` — обходом дерева
по образцу `tests/newman/scripts/*_test.py`, без называния файла по имени.
"""

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]
GATE_REL = "tests/newman/scripts/vendor_provenance_test.py"
RECORD_REL = "tests/newman/vendor-provenance.json"

FAILURES: list[str] = []


def build_tree(dst: pathlib.Path, only_identical: bool = False) -> None:
    """Синтетическое дерево: только то, что проба читает, и ничего больше.

    `only_identical` оставляет в записи ТОЛЬКО файлы без подстановок. Это нужно
    осям про оригинал: там синтетическое «дерево платформы» собирается копией
    местных файлов, и для файла БЕЗ подстановок копия равна оригиналу BY
    CONSTRUCTION — то есть предпосылка близнеца не вычисляется тем же кодом,
    который проба проверяет. Взять полную запись значило бы восстанавливать
    оригинал по её же объявлению, и близнец доказывал бы объявление, а не факт.
    """
    (dst / "tests/newman/scripts").mkdir(parents=True)
    (dst / "tests/newman/kacholib").mkdir(parents=True)
    shutil.copy2(REPO / GATE_REL, dst / GATE_REL)
    record = json.loads((REPO / RECORD_REL).read_text(encoding="utf-8"))
    if only_identical:
        record["files"] = [e for e in record["files"] if not e["rewrites"]]
    for entry in record["files"]:
        rel = entry["path"]
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst / rel)
    (dst / RECORD_REL).write_text(json.dumps(record, ensure_ascii=False, indent=1),
                                  encoding="utf-8")


def run(tree: pathlib.Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    import os
    env = dict(os.environ)
    env.pop("KANAME_VENDOR_UPSTREAM", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(tree / GATE_REL)],
                          capture_output=True, text=True, env=env)


def record_of(tree: pathlib.Path) -> dict:
    return json.loads((tree / RECORD_REL).read_text(encoding="utf-8"))


def write_record(tree: pathlib.Path, rec: dict) -> None:
    (tree / RECORD_REL).write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")


def check(name: str, want_rc: int, got: subprocess.CompletedProcess, needle: str = "") -> None:
    out = got.stdout + got.stderr
    ok = got.returncode == want_rc and (not needle or needle in out)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} (код {got.returncode})")
    if not ok:
        why = (f"ожидался код {want_rc}, получен {got.returncode}"
               if got.returncode != want_rc else f"в выводе нет «{needle}»")
        FAILURES.append(f"{name}: {why}")
        print("    --- вывод ---")
        for line in out.splitlines()[:14]:
            print(f"    {line}")


def main() -> int:
    print("держатель вендоринга: доказательство способности упасть")

    with tempfile.TemporaryDirectory(prefix="kaname-vendor-proof-") as tmp:
        base = pathlib.Path(tmp)

        # ── КОНТРОЛЬ: чистое дерево молчит. Без него всё ниже зеленело бы на
        #    пробе, которая краснеет всегда.
        t = base / "control"; build_tree(t)
        check("контроль: чистая копия — код 0", 0, run(t), "ЧИСТО")

        # ── ОСЬ 1: копию правили, запись не правили.
        t = base / "silent-edit"; build_tree(t)
        p = t / "tests/newman/kacholib/stems.sh"
        p.write_text(p.read_text(encoding="utf-8") + "\n# правка без записи\n", encoding="utf-8")
        check("правка копии без правки записи — находка с именем файла", 1, run(t),
              "kacholib/stems.sh")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: та же правка, но отпечаток в записи обновлён.
        #    Различие с оригиналом при этом обязано остаться НЕобъявленным, то
        #    есть проба всё равно краснеет — но ДРУГИМ обвинением. Это и есть
        #    вторая половина: обновление отпечатка не является способом замолчать.
        t = base / "silent-edit-twin"; build_tree(t)
        p = t / "tests/newman/kacholib/stems.sh"
        newtext = p.read_text(encoding="utf-8") + "\n# правка с записью\n"
        p.write_text(newtext, encoding="utf-8")
        rec = record_of(t)
        for e in rec["files"]:
            if e["path"].endswith("kacholib/stems.sh"):
                e["local_sha256"] = hashlib.sha256(newtext.encode()).hexdigest()
        write_record(t, rec)
        check("тот же файл с обновлённым отпечатком — уже НЕ про отпечаток, "
              "но различие не объявлено", 1, run(t),
              "различие, которого запись не называет")

        #    И третья форма того же: правка ОБЪЯВЛЕНА подстановкой — молчит.
        t = base / "declared-edit"; build_tree(t)
        p = t / "tests/newman/kacholib/stems.sh"
        up = p.read_text(encoding="utf-8")
        line = up.splitlines()[0]
        loc = line + "  # объявленная правка"
        p.write_text(up.replace(line, loc, 1), encoding="utf-8")
        rec = record_of(t)
        for e in rec["files"]:
            if e["path"].endswith("kacholib/stems.sh"):
                e["local_sha256"] = hashlib.sha256((t / e["path"]).read_bytes()).hexdigest()
                e["rewrites"] = [{"line": 1, "upstream": line, "local": loc, "why": "проба"}]
        write_record(t, rec)
        check("правка, ОБЪЯВЛЕННАЯ подстановкой — молчит", 0, run(t), "ЧИСТО")

        # ── ОСЬ 2: объявленная подстановка в копии не находится.
        t = base / "phantom-rewrite"; build_tree(t)
        rec = record_of(t)
        for e in rec["files"]:
            if e["rewrites"]:
                e["rewrites"][0]["local"] = "строки, которой в копии нет"
                break
        write_record(t, rec)
        check("объявленная подстановка не найдена в копии — находка", 1, run(t),
              "встречается в копии 0 раз")

        # ── ОСЬ 3: запись называет файл, которого нет.
        t = base / "missing-file"; build_tree(t)
        (t / "tests/newman/scripts/coverage.py").unlink()
        check("записанного файла нет в дереве — находка", 1, run(t),
              "называет файл, которого в дереве НЕТ")

        # ── ОСЬ 4: файл в целиком вендоренном каталоге без записи.
        t = base / "unlisted"; build_tree(t)
        (t / "tests/newman/kacholib/helper_extra.py").write_text("# без записи\n", encoding="utf-8")
        check("файл общего слоя без записи — находка", 1, run(t), "записи не имеет")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: файл не того вида (кэш интерпретатора) — молчит.
        t = base / "unlisted-twin"; build_tree(t)
        (t / "tests/newman/kacholib/__pycache__").mkdir()
        (t / "tests/newman/kacholib/__pycache__/x.cpython-312.pyc").write_bytes(b"\x00")
        check("кэш интерпретатора в общем слое — НЕ находка", 0, run(t), "ЧИСТО")

        # ── ОСЬ 5: оригинал ушёл вперёд (сверка по ручке).
        #    Обе стороны оси идут на записи ТОЛЬКО из побайтово равных файлов —
        #    см. `build_tree(only_identical=True)`: иначе предпосылку близнеца
        #    вычислял бы тот же разбор подстановок, который проба и проверяет.
        n_identical = sum(
            1 for e in json.loads((REPO / RECORD_REL).read_text(encoding="utf-8"))["files"]
            if not e["rewrites"])
        t = base / "upstream-moved"; build_tree(t, only_identical=True)
        up_tree = base / "upstream-moved-up"; build_tree(up_tree, only_identical=True)
        q = up_tree / "tests/newman/kacholib/stems.sh"
        q.write_text(q.read_text(encoding="utf-8") + "\n# оригинал ушёл вперёд\n", encoding="utf-8")
        check("оригинал ушёл вперёд — находка", 1,
              run(t, {"KANAME_VENDOR_UPSTREAM": str(up_tree)}), "ОРИГИНАЛ УШЁЛ ВПЕРЁД")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: тот же прогон на НЕтронутом оригинале — молчит и
        #    называет число сверенного.
        t = base / "upstream-same"; build_tree(t, only_identical=True)
        up_same = base / "upstream-same-up"; build_tree(up_same, only_identical=True)
        r = run(t, {"KANAME_VENDOR_UPSTREAM": str(up_same)})
        check("оригинал не двигался — молчит", 0, r, "ЧИСТО")
        check("и сверка НАЗВАНА числом, а не подразумевается", 0, r,
              f"сверено с оригиналом {n_identical}")

        # ── ОСЬ 6: беспредметность отличима от находки КОДОМ.
        t = base / "no-record"; build_tree(t)
        (t / RECORD_REL).unlink()
        check("записи нет — код 2, а НЕ 1 и НЕ 0", 2, run(t), "БЕСПРЕДМЕТНО")

        t = base / "empty-record"; build_tree(t)
        write_record(t, {"upstream": {}, "files": []})
        check("запись пуста — код 2, а НЕ 0", 2, run(t), "БЕСПРЕДМЕТНО")

        # ── ОСЬ 7: перепись печатается ВСЕГДА, в том числе на чистом.
        t = base / "census"; build_tree(t)
        check("перепись объёма осмотренного печатается на чистом дереве", 0, run(t),
              "перепись: файлов по записи")

        # ── ОСЬ 8: сверка не выполнялась — сказано словами, а не умолчанием.
        t = base / "no-upstream"; build_tree(t)
        check("несверенное названо прямо", 0, run(t),
              "KANAME_VENDOR_UPSTREAM не задан")

    if FAILURES:
        print(f"\nПРОВАЛЕНО утверждений: {len(FAILURES)}", file=sys.stderr)
        for f in FAILURES:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("\nВСЕ утверждения сошлись: держатель вендоринга падает там, где должен, "
          "и молчит на законных близнецах.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
