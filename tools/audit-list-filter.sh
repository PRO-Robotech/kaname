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

# КОНТРАКТЫ ЛЕЖАТ НЕ ЗДЕСЬ, И ЭТО НАЗЫВАЕТСЯ ЯВНО.
#
# Умолчание флага — относительный `proto`, то есть каталог рядом с РАБОЧИМ. Пока
# прогон шёл из корня монорепо, умолчание попадало в цель. Со сменой рабочего
# каталога на каталог службы оно стало указывать в никуда — и это НЕ дало
# отказа: проверка кромки честно объявила, что взяла свои объявления «на веру»,
# то есть форма контроля осталась, а содержания не стало. Ровно тот класс,
# который сама она и ловит. Поэтому каталог контрактов передаётся ЯВНО.
#
# ─────────────────────────────────────────────────────────────────────────────
# КАТАЛОГ КОНТРАКТОВ РЕЗОЛВИТСЯ ПО ПОСАДКЕ, А НЕ ПОДЪЁМОМ НА ДВА УРОВНЯ
#
# Здесь стоял безусловный подъём `$SERVICE_ROOT/../..`. В монорепо он попадал в
# корень платформы; в самостоятельном клоне те же два уровня выводят ВЫШЕ корня
# клона — в каталог, где лежит сам клон, — и проверка искала контракты там. Файла
# нет, кромочные объявления брались «на веру», и гейт краснел на КАЖДОМ, кто
# склонирует службу: остаток был назван прямо в этом файле («путь придётся брать
# у `go list -m`») и здесь закрывается.
#
# Посадку решает ПРИЗНАК, а не наличие файла: подъём, судящий по тому, нашёлся ли
# каталог, под чужим деревом с той же координатой нашёл бы ЧУЖИЕ контракты и вынес
# вердикт о них. Признак тот же, что у детектора посадки в Go
# (`internal/treeposture`): модуль лежит в каталоге модулей дерева платформы.
PLATFORM_ROOT="$(cd "$SERVICE_ROOT/../.." 2>/dev/null && pwd || true)"
if [ -n "$PLATFORM_ROOT" ] &&
   [ "$(basename "$(dirname "$SERVICE_ROOT")")" = "services" ] &&
   [ -d "$PLATFORM_ROOT/services" ]; then
  # Дерево платформы: контракты берутся из РАБОЧЕГО дерева — оно и есть предмет
  # суждения, и оно может быть впереди пина.
  PROTO_ROOT="$PLATFORM_ROOT/proto"
else
  # Самостоятельный клон: контракты приезжают модулем платформы. Спрашиваются у
  # `go list -m`, а не складываются путём: место модуля в кэше выбирает go, и
  # выписанный путь был бы верен ровно для одной машины.
  PLATFORM_MODULE_DIR="$(go list -m -f '{{.Dir}}' github.com/PRO-Robotech/kacho)"
  if [ -z "$PLATFORM_MODULE_DIR" ]; then
    echo "audit-list-filter: модуль платформы не резолвится — контракты спросить не у кого." >&2
    echo "  Это НЕ вердикт о дереве: проверка НЕ ИСПОЛНЯЛАСЬ. Прогоните go mod download." >&2
    exit 2
  fi
  PROTO_ROOT="$PLATFORM_MODULE_DIR/proto"
fi

if [ ! -d "$PROTO_ROOT" ]; then
  echo "audit-list-filter: каталога контрактов нет по резолвленному пути: $PROTO_ROOT" >&2
  echo "  Это НЕ вердикт о дереве: проверка НЕ ИСПОЛНЯЛАСЬ." >&2
  exit 2
fi

exec go run ./tools/auditlistfilter/cmd/audit-list-filter \
  --root="$SERVICE_ROOT" --proto-root="$PROTO_ROOT" "$@"
