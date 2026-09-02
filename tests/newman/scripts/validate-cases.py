#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""tests/newman/scripts/validate-cases.py — сверщик каталога кейсов iam.

ТЕЛО ОБЩЕЕ, ЗДЕСЬ — ТОЛЬКО РЕШЕНИЯ НАБОРА. Сверщик кейсов был у шести наборов из
семи, и шесть копий уже разошлись (по содержимому их четыре разных). Седьмая
копия сделала бы расхождение семикратным, поэтому общее живёт в
`tests/newman/kacholib/casesindex.py` — рядом с хребтом генератора, который эти
же наборы уже делят.

Решения iam, и каждое — под расхождение, которое в дереве ЕСТЬ:

  * `strip_segments=2`. Суффикс-паттерн у шести наборов режет один сегмент
    (`NLB-CR-CRUD-OK` → `*-CR-CRUD-OK`), потому что ресурс стоит первым. У iam
    сегментом больше (`IAM-WAI-GT-CRUD-OK`), и отрезание одного оставляет ресурс
    внутри паттерна, то есть не сворачивает НИЧЕГО: замер по дереву — 729
    идентификаторов дают 729 различных суффиксов при одном сегменте и 488 при
    двух. Двойка здесь — аналог соседской единицы, а не послабление.

  * Освобождённых модулей НЕТ. Шесть наборов освобождают `internal-*.py`
    (каталогизированы заметкой, а не таблицей). У iam модулей с таким именем в
    дереве ноль, и заводить освобождение «на будущее» нельзя: запись, которой
    нечего исключать, — находка, и она унаследует следующую слепую зону.

Запуск (чистый Python, без сети):

    python3 tests/newman/scripts/validate-cases.py
    python3 tests/newman/scripts/gen.py --validate   # то же самое

Конвейер находит этот файл ОБХОДОМ (`services/*/tests/newman/scripts/validate-cases.py`),
поэтому он попадает под гейт по построению, а не после того, как кто-то вспомнит;
что обход остаётся обходом, залочено `tools/newmancensus`.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
INDEX_FILE = ROOT / "docs" / "CASES-INDEX.md"

# Генератор набора кладёт общий слой на sys.path и объявляет связывание `_RUN`.
# Сверщик обязан видеть ровно то, что увидит генерация, поэтому модули и кейсы
# берутся ЕГО отбором и ЕГО загрузчиком — своих рук здесь нет намеренно
# (`TestNewmanConsumersReachTheSpineThroughTheSuiteBinding`).
sys.path.insert(0, str(SCRIPTS_DIR))

import gen  # noqa: E402 — после провязки sys.path
import casesindex  # noqa: E402 — общий слой, положен на путь генератором


if __name__ == "__main__":
    sys.exit(casesindex.main(gen._RUN, INDEX_FILE, strip_segments=2))
