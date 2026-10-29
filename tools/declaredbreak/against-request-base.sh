#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# against-request-base.sh — `buf breaking` против БАЗЫ ЗАПРОСА и адъюдикация его
# вывода (задача kaname#1055).
#
# ФОРМА
#   against-request-base.sh <адъюдикатор> <перечень объявленных разрывов>
# Зовётся из корня клона; контракты — каталог `proto`. Окружение:
#   GITHUB_BASE_REF — база запроса (конвейер ставит её на pull_request); пусто — `main`;
#   HEAD_SHA        — голова запроса (на pull_request клон стоит на коммите
#                     слияния, а не на ней); пусто — HEAD.
#
# ─────────────────────────────────────────────────────────────────────────────
# ПОЧЕМУ БАЗА ЗАПРОСА, А НЕ `main`
#
# Прежде шаг сравнивал с подвижным `main`. Для запроса в ветку эпика, отставшую
# от `main`, отставание базы читалось как удаление веткой: PR kaname#977 (848 → 942)
# с нулевым диффом контрактов против своей базы был красен шестью «разрывами»,
# которые внёс в `main` чужой запрос уже после ответвления 942. Разбор требовал
# записей перечня о чужих, ещё не догнанных изменениях, — то есть послабления
# без предмета у этой ветки.
#
# На pull_request клон — коммит слияния головы с базой, поэтому сравнение с
# базой видит ровно то, что внесла голова. Для запроса в `main` база и есть
# `main`, как прежде. На push в ствол базы запроса нет — сравнение с `main`
# (судьба этой ветви — kaname#243).
#
# ─────────────────────────────────────────────────────────────────────────────
# ОТКАЗ НАЗЫВАЕТ, ЕСТЬ ЛИ ПРЕДМЕТ В ОБЩЕМ ПРЕДКЕ
#
# Находка против базы бывает двух родов: предмет был в общем предке головы и
# базы, и голова его сняла; либо предмета в предке не было — его внесла база
# после ответвления. Различает их второй прогон `buf` против общего предка:
# находка с той же координатой там есть ⟺ предмет в предке есть. Прогон идёт
# только на красном: зелёному он ничего не добавляет, а история клона нужна ему
# целиком.
#
# Не вышло установить предка — красное остаётся красным, а у каждой находки
# напечатано «не установлен» с причиной: отсутствие ответа не выдаётся ни за
# «есть», ни за «нет».
#
# ─────────────────────────────────────────────────────────────────────────────
# ИСХОДОВ ТРИ: 0 — чисто · 1 — находка · 2 — гейт НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ.
# Код `buf` разбирается: 100 — «есть находки» (штатный вход адъюдикатора),
# 0 — «разрывов нет», ЛЮБОЙ ДРУГОЙ — третий исход, а не «разрывов нет».
set -uo pipefail

if [ "$#" -ne 2 ]; then
    echo "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: нужны два довода — адъюдикатор и перечень" >&2
    exit 2
fi
adjudicator="$1"
ledger="$2"
base="${GITHUB_BASE_REF:-main}"
head_sha="${HEAD_SHA:-}"
root="$(pwd)"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/against-base.XXXXXX")" || {
    echo "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не создан" >&2
    exit 2
}
trap 'rm -rf "$work"' EXIT

[ -n "$head_sha" ] || head_sha="$(git rev-parse HEAD)" || {
    echo "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: голова не установлена" >&2
    exit 2
}

# snapshot <ревизия> <каталог> — дерево `proto` ревизии в каталог.
snapshot() {
    mkdir -p "$2" && git archive --format=tar "$1" proto | tar -x -C "$2"
}

# breaking <каталог сравнения> <вывод> — 0 при коде buf 0 или 100, иначе 2; код buf — в
# buf_rc, текст отказа — в <вывод>.err. Печатает вызывающий: отказ против базы — третий
# исход шага, против предка — лишь «предок не установлен» при красном вердикте.
buf_rc=0
breaking() {
    (cd "$root/proto" && buf breaking --against "$1/proto" --error-format=json) >"$2" 2>"$2.err"
    buf_rc=$?
    case "$buf_rc" in
        0|100) return 0 ;;
        *) return 2 ;;
    esac
}

# oneline <файл> — первые 300 байт файла одной строкой: причина в строку отказа.
oneline() {
    head -c 300 "$1" 2>/dev/null | tr '\n' ' '
}

# База — снимком ровно одного коммита: истории для сравнения не нужно.
if ! git fetch --no-tags --quiet --depth=1 origin "+refs/heads/$base:refs/remotes/origin/$base" 2>"$work/fetch.err"; then
    echo "::error title=ГЕЙТ НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ::база запроса $base не получена"
    cat "$work/fetch.err" >&2
    exit 2
fi
base_sha="$(git rev-parse "refs/remotes/origin/$base")" || exit 2
echo "база сравнения: $base @$base_sha (база запроса; пусто — main) · голова @$head_sha"

snapshot "$base_sha" "$work/base" || {
    echo "::error title=ГЕЙТ НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ::снимок proto базы $base_sha не извлечён"
    exit 2
}
if ! breaking "$work/base" "$work/base.jsonl"; then
    echo "::error title=ГЕЙТ НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ::buf breaking против базы $base вышел кодом $buf_rc — это НЕ «разрывов нет»"
    cat "$work/base.jsonl.err" >&2
    exit 2
fi

"$adjudicator" "$ledger" <"$work/base.jsonl" >"$work/report"
rc=$?
if [ "$rc" -ne 1 ]; then
    cat "$work/report"
    exit "$rc"
fi

# КРАСНОЕ: где предмет каждой находки — в общем предке головы и базы.
ancestor_args=()
deepen=()
[ "$(git rev-parse --is-shallow-repository)" = true ] && deepen=(--unshallow)
if ! git fetch --no-tags --quiet "${deepen[@]}" origin \
        "+refs/heads/$base:refs/remotes/origin/$base" "$head_sha" 2>"$work/deepen.err"; then
    ancestor_args=(--ancestor-unknown "история головы и базы не получена: $(oneline "$work/deepen.err")")
elif ! anc="$(git merge-base "$head_sha" "$base_sha" 2>"$work/mb.err")"; then
    ancestor_args=(--ancestor-unknown "git merge-base $head_sha $base_sha: $(oneline "$work/mb.err")")
elif ! snapshot "$anc" "$work/ancestor" 2>"$work/anc-snap.err"; then
    ancestor_args=(--ancestor-unknown "снимок proto общего предка $anc не извлечён: $(oneline "$work/anc-snap.err")")
elif ! breaking "$work/ancestor" "$work/ancestor.jsonl"; then
    ancestor_args=(--ancestor-unknown "buf breaking против общего предка $anc вышел кодом $buf_rc: $(oneline "$work/ancestor.jsonl.err")")
else
    ancestor_args=(--ancestor-findings "$work/ancestor.jsonl" --ancestor-ref "$anc")
fi

"$adjudicator" "${ancestor_args[@]}" "$ledger" <"$work/base.jsonl"
