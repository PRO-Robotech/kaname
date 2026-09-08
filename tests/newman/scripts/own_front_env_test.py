#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: набор проб адресуется к собственному фронту СВОЕЙ переменной.

ПРЕДМЕТ. Край платформы и собственный REST-фронт службы — две разные
поверхности. Переопредели набор переменную края, чтобы «сэкономить» одну
запись, — и вердикт прогона станет функцией того, чей стенд поднят: те же
кейсы, тот же зелёный отчёт, проверено разное. Заметить это по отчёту нельзя.

Поэтому утверждается ТРИ вещи, и каждая своим предикатом:

  1. переменные собственных фронтов ОБЪЯВЛЕНЫ в шаблоне окружения;
  2. переменная края НЕ переопределена — её значение осталось прежним;
  3. кейсы собственного фронта адресуются именно к своим переменным.

Третье — не педантизм: объявить переменную и не читать её значит завести
координату, которой никто не пользуется, и «набор гоняется против своего
фронта» держалось бы одной прозой.

ПЕРЕПИСЬ печатает, сколько кейсов адресуется к какой переменной, — иначе «ноль
находок» неотличимо от «ноль прочитанного».

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `services/*/tests/newman/scripts/*_test.py` и
НИ ОДИН файл проб по имени не называет — поэтому отдельного шага в конвейере файл
не требует, а искать вызывающего предикатом `git grep <имя файла>` бесполезно:
вызова по имени нет ни у кого. Код возврата при этом доезжает до вердикта шага.
Проводку держит `tools/pythonprobes`.
"""

import json
import pathlib
import re
import sys

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
ENV_TEMPLATE = NEWMAN / "environments" / "local.postman_environment.template.json"
CASES_DIR = NEWMAN / "cases"

# Переменные собственных фронтов. Обе обязаны быть объявлены: без второй пара
# «тот же путь на соседнем фронте» распадается, и любой 404 на публичном фронте
# становится неотличим от мёртвого слушателя.
OWN_VARS = ("ownRestBaseUrl", "ownInternalRestBaseUrl")

# Переменная КРАЯ и её значение на момент заведения гейта. Сверяется дословно:
# переопределение здесь и есть предмет запрета.
EDGE_VAR = "baseUrl"
EDGE_VALUE = "http://localhost:18080"

RE_ENV_URL = re.compile(r'require_env_url\(\s*"([A-Za-z][A-Za-z0-9_]*)"')


def audit(env_path, cases_dir):
    findings, census = [], {}

    env = json.loads(env_path.read_text(encoding="utf-8"))
    declared = {v["key"]: v.get("value", "") for v in env.get("values", [])}
    census["переменных в шаблоне"] = len(declared)

    for var in OWN_VARS:
        if var not in declared:
            findings.append(
                f"переменная {var!r} не объявлена в шаблоне окружения: у собственного "
                f"фронта нет адреса, и кейсы проверяли бы край вместо предмета")

    if EDGE_VAR not in declared:
        findings.append(
            f"переменная края {EDGE_VAR!r} исчезла из шаблона — предмет сверки пропал, "
            f"и «край не переопределён» стало бы верно тривиально")
    elif declared[EDGE_VAR] != EDGE_VALUE:
        findings.append(
            f"переменная края {EDGE_VAR!r} переопределена ({declared[EDGE_VAR]!r} вместо "
            f"{EDGE_VALUE!r}): вердикт прогона станет функцией того, чей стенд поднят")

    # Кто к какой переменной адресуется.
    by_var = {}
    modules = 0
    for path in sorted(cases_dir.glob("*.py")):
        modules += 1
        for m in RE_ENV_URL.finditer(path.read_text(encoding="utf-8")):
            by_var.setdefault(m.group(1), set()).add(path.name)
    census["модулей кейсов"] = modules
    for var in sorted(by_var):
        census[f"адресуются к {var}"] = len(by_var[var])

    for var in OWN_VARS:
        if var not in by_var:
            findings.append(
                f"переменная {var!r} объявлена, но НИ ОДИН кейс к ней не адресуется: "
                f"координата заведена и не читается, а «набор гоняется против своего "
                f"фронта» держится одной прозой")
    return census, findings


def main():
    if not ENV_TEMPLATE.is_file():
        print(f"ОТКАЗ: шаблона окружения нет ({ENV_TEMPLATE}) — вердикт беспредметен",
              file=sys.stderr)
        return 1
    if not CASES_DIR.is_dir():
        print(f"ОТКАЗ: каталога кейсов нет ({CASES_DIR}) — вердикт беспредметен",
              file=sys.stderr)
        return 1
    census, findings = audit(ENV_TEMPLATE, CASES_DIR)
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if census.get("модулей кейсов", 0) == 0 or census.get("переменных в шаблоне", 0) == 0:
        print("ОТКАЗ: обход пуст — вердикт беспредметен", file=sys.stderr)
        return 1
    if findings:
        print(f"НАХОДКИ ({len(findings)}):", file=sys.stderr)
        for f in findings:
            print("  " + f, file=sys.stderr)
        return 1
    print("ЧИСТО: собственные фронты адресуются своими переменными, край не переопределён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
