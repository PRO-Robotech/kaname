#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-inject.sh — ДОКАЗАТЕЛЬСТВО того, что хук отправки СПОСОБЕН отказать.
#
# Хук, потерявший способность отказывать, на чистом дереве выглядит ТОЧНО ТАК ЖЕ,
# как исправный: оба молчат и выпускают отправку. Прогон «на чистом дереве»
# поэтому не доказывает ничего, и проверяется здесь не он, а ПАРА — внесённый
# дефект обязан покраснеть, законный близнец обязан смолчать.
#
# ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ СВОЕГО ПОЛОЖИТЕЛЬНОГО БЛИЗНЕЦА. Иначе
# неизвестно, что именно дало красное, и вердикт недействителен, выглядя обычным.
#
# СИНТЕТИКА ЖИВЁТ ВНЕ ЛЮБОГО РЕПОЗИТОРИЯ. Временное дерево, заведённое ВНУТРИ
# рабочей копии, находит её индекс обходом вверх — и проба краснеет по причине,
# к предмету не относящейся.
set -uo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "инъекция: это не рабочая копия git." >&2; exit 2
}
hook="$root/scripts/hooks/pre-push"
inst="$root/scripts/hooks/install.sh"
[ -x "$hook" ] || { echo "инъекция: нет исполнимого $hook" >&2; exit 2; }
[ -x "$inst" ] || { echo "инъекция: нет исполнимого $inst" >&2; exit 2; }

base="$(TMPDIR="${TMPDIR:-/var/tmp}" mktemp -d)" || exit 2
case "$base" in
    "$root"/*) echo "инъекция: временное дерево оказалось ВНУТРИ рабочей копии ($base)." >&2
               echo "  Задайте TMPDIR вне любого репозитория и повторите." >&2
               rm -rf "$base"; exit 2 ;;
esac
trap 'rm -rf "$base"' EXIT

probes=0; failed=0

# want <ожидаемый код> <имя> — читается КОД ВОЗВРАТА, а не вид вывода.
want() {
    local exp="$1" name="$2"; shift 2
    local got=0
    probes=$((probes + 1))
    "$@" >/dev/null 2>&1 || got=$?
    if [ "$got" -ne "$exp" ]; then
        echo "  ПРОВАЛ $name — ждали $exp, получили $got" >&2
        failed=$((failed + 1)); return
    fi
    echo "  ok   $name (код $got)"
}

# синтетическое дерево: репозиторий с одним файлом Go
mkrepo() { # mkrepo <каталог> <содержимое main.go|->
    local d="$1" body="$2"
    mkdir -p "$d"
    git -C "$d" init -q 2>/dev/null
    git -C "$d" config user.email probe@example.invalid
    git -C "$d" config user.name probe
    if [ "$body" != "-" ]; then
        printf '%s' "$body" > "$d/main.go"
        git -C "$d" add main.go
    else
        printf 'заметка\n' > "$d/README.md"
        git -C "$d" add README.md
    fi
}

good=$'package main\n\nfunc main() {}\n'
bad=$'package main\n\nfunc  main()      {}\n'   # ровно один факт: форматирование

echo "=== хук отправки: доказательство инъекцией ==="

mkrepo "$base/clean" "$good"
mkrepo "$base/dirty" "$bad"
mkrepo "$base/empty" "-"

# (−) ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ. Без него всё нижеследующее зеленело бы на хуке,
# который отказывает ВСЕГДА, — а такой хук так же негоден, как немой.
want 0 "(−) отформатированное дерево — зелёное, отправка идёт" \
    env -C "$base/clean" KANAME_PREPUSH_GROUPS=gofmt "$hook"

# (+) один факт против близнеца: файл не отформатирован.
want 1 "(+) неотформатированный файл — КРАСНОЕ, отправка остановлена" \
    env -C "$base/dirty" KANAME_PREPUSH_GROUPS=gofmt "$hook"

# (+) третья категория: обход пуст. Это НЕ «находок нет».
want 2 "(+) ни одного файла Go — НЕ ВЫПОЛНЕНО, а не чисто" \
    env -C "$base/empty" KANAME_PREPUSH_GROUPS=gofmt "$hook"

# (+) группа, которой нет: нераспознанное имя не смеет пройти молча.
want 2 "(+) незнакомая группа — НЕ ВЫПОЛНЕНО, а не пропуск" \
    env -C "$base/clean" KANAME_PREPUSH_GROUPS=нетакой "$hook"

# (−) обход законен и явен — и об этом сказано вслух.
want 0 "(−) явный обход KANAME_SKIP_PREPUSH=1 — проходит" \
    env -C "$base/dirty" KANAME_SKIP_PREPUSH=1 KANAME_PREPUSH_GROUPS=gofmt "$hook"
probes=$((probes + 1))
if env -C "$base/dirty" KANAME_SKIP_PREPUSH=1 KANAME_PREPUSH_GROUPS=gofmt "$hook" 2>&1 |
       grep -q 'проверок НЕ БЫЛО'; then
    echo "  ok   (−) обход НАЗЫВАЕТ СЕБЯ: «проверок НЕ БЫЛО»"
else
    echo "  ПРОВАЛ обход молчит — обойти НЕ ЗАМЕТИВ стало возможно" >&2
    failed=$((failed + 1))
fi

# ── провязка: тот же приём на `install.sh` ───────────────────────────────────
# Здесь предмет другой и он НЕСУЩИЙ: переходник, зовущий несуществующий скрипт,
# выходит УСПЕХОМ, поэтому по исходу `git push` неотличим от исправного.
wire="$base/wire"
mkrepo "$wire" "$good"
mkdir -p "$wire/scripts/hooks"
cp "$hook" "$wire/scripts/hooks/pre-push"
cp "$inst" "$wire/scripts/hooks/install.sh"
chmod +x "$wire/scripts/hooks/pre-push" "$wire/scripts/hooks/install.sh"
git -C "$wire" add scripts/hooks/pre-push scripts/hooks/install.sh

want 1 "(+) клон без провязки — check ОТКАЗЫВАЕТ, а не молчит" \
    env -C "$wire" bash scripts/hooks/install.sh check

want 0 "(−) провязка исполняется" \
    env -C "$wire" bash scripts/hooks/install.sh install

want 0 "(−) провязанный клон — check молчит (законный близнец)" \
    env -C "$wire" bash scripts/hooks/install.sh check

# (+) ГЛАВНАЯ ОСЬ: переходник на месте, звать ему нечего.
chmod -x "$wire/scripts/hooks/pre-push"
want 1 "(+) провязан В ПУСТОТУ — check ОТКАЗЫВАЕТ" \
    env -C "$wire" bash scripts/hooks/install.sh check
probes=$((probes + 1))
if env -C "$wire" bash "$wire/.git/hooks/pre-push" </dev/null 2>&1 |
       grep -q 'проверок НЕ БЫЛО'; then
    echo "  ok   (+) переходник в пустоту НАЗЫВАЕТ СЕБЯ (и выходит успехом — потому и нужен check)"
else
    echo "  ПРОВАЛ переходник в пустоту молчит" >&2
    failed=$((failed + 1))
fi
chmod +x "$wire/scripts/hooks/pre-push"

# (+) чужой файл под нашим именем НЕ ЗАТИРАЕТСЯ.
printf '#!/bin/sh\necho чужой\n' > "$wire/.git/hooks/pre-push"
chmod +x "$wire/.git/hooks/pre-push"
want 1 "(+) посторонний хук — install ОТКАЗЫВАЕТ, не перезаписывает" \
    env -C "$wire" bash scripts/hooks/install.sh install
probes=$((probes + 1))
if grep -q 'чужой' "$wire/.git/hooks/pre-push"; then
    echo "  ok   (+) посторонний файл УЦЕЛЕЛ"
else
    echo "  ПРОВАЛ посторонний файл затёрт" >&2
    failed=$((failed + 1))
fi

echo
echo "prepush-inject: проб исполнено $probes, провалов $failed"
[ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
[ "$failed" -gt 0 ] && exit 1
exit 0
