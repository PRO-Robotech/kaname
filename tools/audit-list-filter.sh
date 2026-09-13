#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

# audit-list-filter.sh — CI gate for kaname's listing surface: every method that
# hands a page to a caller must narrow it, and must declare HOW.
#
# This is a THIN wrapper. What is checked, and why the analysis parses the tree
# instead of searching its text, is documented on pkg/listfiltergate; how this
# service is laid out is documented on services/iam/tools/auditlistfilter. Only the
# invocation lives here.
#
# Why this file is new. iam had no gate of this class at all, while having the widest
# listing surface in the repository — 30 methods. Nothing was red because the set of
# services to analyse was written by hand and iam was not in it.
#
# Arguments are forwarded as-is:
#   --root=<dir>        audit another tree (used by the gate's own tests).
#   --proto-root=<dir>  where to resolve the proto files and the authorization model.

set -euo pipefail

# The service root is resolved BEFORE changing directory, and passed explicitly:
# `go run ./services/…` has to be issued from the module root, so the default
# "audit the current directory" would otherwise audit the repository instead of this
# service. A --root given by the caller appears later on the command line and wins.
SERVICE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Пакет зовётся ОТНОСИТЕЛЬНО СВОЕГО МОДУЛЯ: служба несёт свой `go.mod`, и путь
# `./services/iam/…` из корня монорепо больше не резолвится — модуль-родитель
# кончается там, где начинается вложенный.
cd "$SERVICE_ROOT"

# КОНТРАКТЫ ЛЕЖАТ ЗДЕСЬ, И ПОСАДКИ У ЭТОГО ВОПРОСА БОЛЬШЕ НЕТ.
#
# Умолчание флага — относительный `proto`, то есть каталог рядом с РАБОЧИМ. Пока
# прогон шёл из корня монорепо, умолчание попадало в цель. Со сменой рабочего
# каталога на каталог службы оно стало указывать в никуда — и это НЕ дало
# отказа: проверка кромки честно объявила, что взяла свои объявления «на веру»,
# то есть форма контроля осталась, а содержания не стало. Ровно тот класс,
# который сама она и ловит. Поэтому каталог контрактов передаётся ЯВНО.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЗДЕСЬ БЫЛА РАЗВИЛКА ПО ПОСАДКЕ — У НЕЁ БОЛЬШЕ НЕТ ПРЕДМЕТА
#
# Развилка выбирала между рабочим деревом платформы и каталогом её МОДУЛЯ-пина
# (`go list -m -f '{{.Dir}}'`), потому что контракты службы публиковала платформа.
# Ступень S0a (kacho#2617, исход C) перенесла их дом: `proto/kaname/` этого дерева
# несёт 41 контракт и модель авторизации, а ребро `kaname → kacho` снято целиком —
# значит ветвь модуля-пина стала НЕИСПОЛНИМОЙ by construction: `go list -m`
# отвечает «module github.com/PRO-Robotech/kacho: not a known dependency», и
# проверка выходила бы кодом 2 на каждом прогоне, включая конвейерный.
#
# ЧТО ЭТО МЕНЯЕТ В ВЕРДИКТЕ — НИЧЕГО, И ЭТО ЗАМЕР, А НЕ ДОВОД. Вывод аудитора под
# обоими корнями контрактов ТОЖДЕСТВЕН побайтово (прогон на день правки: 165
# файлов в 27 пакетах, 19 ресурсов, 36 списочных методов, `OK`). Причина та же,
# по которой исход C назван «провод неизменен»: сорок один контракт службы
# отличается от копии платформы РОВНО строкой `option go_package`, а её аудитор
# не читает.
PROTO_ROOT="$SERVICE_ROOT/proto"

if [ ! -d "$PROTO_ROOT" ]; then
  echo "audit-list-filter: каталога контрактов нет по резолвленному пути: $PROTO_ROOT" >&2
  echo "  Это НЕ вердикт о дереве: проверка НЕ ИСПОЛНЯЛАСЬ." >&2
  exit 2
fi

exec go run ./tools/auditlistfilter/cmd/audit-list-filter \
  --root="$SERVICE_ROOT" --proto-root="$PROTO_ROOT" "$@"
