#!/usr/bin/env bash
# shellcheck disable=SC2016  # выражения в кавычках — тело порождаемых файлов, раскрывать их нельзя
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Проба правила ветки и коммита: три потребителя одного предиката
# (scripts/hooks/branch-rule.sh) — хук коммита, страж отправки с настоящим
# pre-push и проверка запроса (.github/scripts/pr-rule-check.sh).
#
# Каждое нарушение — одно-фактный близнец законного случая: законный обязан
# пройти молча, нарушение — отказать и НАЗВАТЬ причину. Хук коммита гоняется
# настоящим `git commit`/`git merge` (вход хуку готовит сам git), отправка —
# настоящим `git push` в голый репозиторий, запрос — синтетическим диапазоном.
#
# Проба доказывает и свою способность упасть: тот же набор гоняется против
# пяти воссозданных дефектов — слепой атрибуции, старой формы ветки
# `issue-<N>`, потерянного T0, хука отправки без стража и обхода проверок,
# поставленного раньше стража, — и от каждого требует хотя бы одного провала.
#
# T0 выводится из истории (коммит, заведший scripts/hooks/commit-msg), поэтому в
# каждой фикстуре он ЗАКОММИЧЕН: история до правила — коммиты с датой автора
# раньше этого коммита, новая работа — после.
#
# Песочница: корневая учётная запись — её собственный ~/.gitconfig (HOME
# временный), а не переопределение; переопределения здесь — предмет проверки.
#
# КОПИЯ ПРОБЫ СОСЕДНЕГО ПРОДУКТА (PRO-Robotech/kacho#2793), И ЭТО ПРИЗНАНО — тем
# же долгом, что у предиката (шапка branch-rule.sh). Отличия — от устройства
# здешнего хука отправки. Он не делит прогон на группы по диффу и не спрашивает конвейер,
# поэтому «зелёная отправка» через настоящий pre-push снимается объявленным
# обходом проверок `KANAME_SKIP_PREPUSH=1` — страж им НЕ снимается, и это
# отдельное утверждение и отдельный воссозданный дефект («skipfirst»). Переходники
# в `.git/hooks` фикстур кладёт тот же производитель, что у клонов, —
# `install.sh stub <имя>`, а не рукописная копия.
#
# Исходы: 0 — все утверждения сошлись; 1 — провал; 2 — предпосылки нет.
set -uo pipefail

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_PREFIX \
      GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_AUTHOR_DATE \
      GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_COMMITTER_DATE \
      GIT_CONFIG_GLOBAL GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
unset KANAME_SKIP_PREPUSH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
for f in "$HERE/branch-rule.sh" "$HERE/commit-msg" "$HERE/prepush-rule.sh" "$HERE/pre-push" \
    "$HERE/prepush-classify.sh" "$HERE/install.sh" "$ROOT/.github/scripts/pr-rule-check.sh"; do
    [ -f "$f" ] || { echo "branch-rule-inject: нет $f — предпосылки нет" >&2; exit 2; }
done
command -v git > /dev/null || { echo "branch-rule-inject: нет git" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/xdg" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
printf '[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' > "$HOME/.gitconfig"
PRE=@1700000000 # 2023-11-14 — история до T0

# ── Набор оснастки под судом: настоящий либо с воссозданным дефектом ─────────
kit_from_tree() { # $1 — каталог набора
    mkdir -p "$1/scripts/hooks" "$1/.github/scripts"
    cp "$HERE/branch-rule.sh" "$HERE/commit-msg" "$HERE/prepush-rule.sh" "$HERE/pre-push" \
        "$HERE/prepush-classify.sh" "$HERE/install.sh" "$1/scripts/hooks/"
    cp "$ROOT/.github/scripts/pr-rule-check.sh" "$1/.github/scripts/"
    chmod +x "$1/scripts/hooks/"* "$1/.github/scripts/"*
}

# Копия оснастки в фикстуру: `scripts/` не отслеживается и не пачкает копию.
equip() { # $1 — репозиторий, $2 — набор
    mkdir -p "$1/scripts/hooks" "$1/.github/scripts"
    cp "$2/scripts/hooks/"* "$1/scripts/hooks/"
    cp "$2/.github/scripts/"* "$1/.github/scripts/"
    printf 'scripts/\n.github/\n' >> "$1/.git/info/exclude"
}

# Коммит правила: заводит scripts/hooks/commit-msg в историю — от него и берётся
# T0. Дата — настоящая: всё, что датировано раньше, фикстура объявляет историей.
rule_commit() { # $1 — репозиторий, $2 — набор
    mkdir -p "$1/scripts/hooks"
    cp "$2/scripts/hooks/commit-msg" "$1/scripts/hooks/commit-msg"
    git -C "$1" add -f scripts/hooks/commit-msg
    git -C "$1" commit -q -m "#1 правило ветки и коммита"
}

# ── Утверждения ──────────────────────────────────────────────────────────────
FAILS=0
CASES=0
TAG=""
ok()   { CASES=$((CASES + 1)); printf '  ok   [%s] %s\n' "$TAG" "$1"; }
fail() { CASES=$((CASES + 1)); FAILS=$((FAILS + 1)); printf '  FAIL [%s] %s\n' "$TAG" "$1"; }

# expect <метка> <ждём: pass|refuse|cannot> <причина или «-»> <код> <вывод>
expect() {
    local label="$1" want="$2" why="$3" rc="$4" out="$5"
    case "$want" in
        pass)
            if [ "$rc" = 0 ] && [[ "$out" != *"ОТКАЗ"* ]]; then ok "$label"
            else fail "$label: законный случай отвергнут (код $rc): $(printf '%s' "$out" | tr '\n' '|' | cut -c1-300)"; fi ;;
        refuse)
            if [ "$rc" = 1 ] && [[ "$out" == *"$why"* ]]; then ok "$label"
            else fail "$label: ждали отказ «$why», получили код $rc: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-300)"; fi ;;
        cannot)
            if [ "$rc" = 2 ] && [[ "$out" == *"$why"* ]]; then ok "$label"
            else fail "$label: ждали «не смог судить» «$why», получили код $rc: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-300)"; fi ;;
    esac
}

# ── Хук коммита: настоящий git ───────────────────────────────────────────────
commit_msg_cases() { # $1 — набор
    local r="$tmp/cm" out rc k c1 b8
    rm -rf "$r"; git init -q "$r"
    local G=(git -C "$r")
    "${G[@]}" commit -q --allow-empty --date="$PRE" --author='Old <old@example.invalid>' -m "история без номера"
    rule_commit "$r" "$1"
    k="$("${G[@]}" rev-parse HEAD)"
    "${G[@]}" checkout -q -b 7
    "${G[@]}" checkout -q -b 8 main
    "${G[@]}" commit -q --allow-empty -m "#8 восьмая"
    b8="$("${G[@]}" rev-parse HEAD)"
    "${G[@]}" checkout -q main
    "${G[@]}" commit -q --allow-empty -m "#1 ствол"
    # Ветка до правила: её коммит датирован раньше T0 (на ней уже влит ствол с правилом).
    "${G[@]}" checkout -q -b old "$k"
    "${G[@]}" commit -q --allow-empty --date="$PRE" --author='Old <old@example.invalid>' -m "история без номера" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    c1="$("${G[@]}" rev-parse HEAD)"
    "${G[@]}" checkout -q -b feature-old "$c1"
    equip "$r" "$1"
    ( cd "$r" && bash scripts/hooks/install.sh stub commit-msg ) > "$r/.git/hooks/commit-msg"
    chmod +x "$r/.git/hooks/commit-msg"

    at() { # $1 — ветка; сбрасывает её к исходной вершине
        "${G[@]}" checkout -q -f "$1" 2> /dev/null
        case "$1" in
            7) "${G[@]}" reset -q --hard "$k" ;;
            old) "${G[@]}" reset -q --hard "$c1" ;;
            feature-old) "${G[@]}" reset -q --hard "$c1" ;;
        esac
    }
    run() { out="$(cd "$r" && "$@" 2>&1)"; rc=$?; [ "$rc" = 0 ] || rc=1; }

    at 7; run git commit -q --allow-empty -m "#7 правка"
    expect "коммит: «#7 …» на ветке 7" pass - "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "правка"
    expect "коммит: первая строка без «#N »" refuse "первая строка не начинается" "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#8 правка"
    expect "коммит: «#8» на ветке 7" refuse "«#8» на ветке «7»" "$rc" "$out"

    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Co-authored-by: Ivan <ivan@example.invalid>"
    expect "коммит: законный соавтор" pass - "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    expect "коммит: трейлер Co-Authored-By с Claude" refuse "атрибуция" "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Claude-Session: https://example.invalid/s"
    expect "коммит: строка Claude-Session" refuse "атрибуция" "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Generated with [Claude Code](https://example.invalid)"
    expect "коммит: строка Generated with Claude Code" refuse "атрибуция" "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "https://claude.ai/code/session_x"
    expect "коммит: ссылка на сессию" refuse "атрибуция" "$rc" "$out"

    at 7; run git merge -q --no-ff "$b8" -m "#7 merge #8: восьмая"
    expect "слияние: «#7 merge #8: …»" pass - "$rc" "$out"
    at 7; run git merge -q --no-ff main -m "#7 merge main: ствол"
    expect "слияние: «#7 merge main: …»" pass - "$rc" "$out"
    at 7; run git merge -q --no-ff --no-edit "$b8"
    expect "слияние: сообщение git по умолчанию" refuse "первая строка не начинается" "$rc" "$out"
    "${G[@]}" merge --abort 2> /dev/null
    at 7; run git merge -q --no-ff "$b8" -m "#7 слияние восьмой"
    expect "слияние: не по форме" refuse "слияние —" "$rc" "$out"
    "${G[@]}" merge --abort 2> /dev/null

    at 7; run env GIT_EDITOR=true git -c core.commentChar=';' commit -q --allow-empty -e -m "#7 правка" -m "тело"
    expect "редактор: комментарий не «#» — строка уцелеет" pass - "$rc" "$out"
    at 7; run env GIT_EDITOR=true git commit -q --allow-empty -e -m "#7 правка" -m "тело"
    expect "редактор: «#7 …» будет вырезана" refuse "через редактор" "$rc" "$out"

    at 7; run git -c user.email=other@example.invalid commit -q --allow-empty -m "#7 правка"
    expect "подпись: -c user.email" refuse "не корневая учётная запись" "$rc" "$out"
    at 7; run env GIT_AUTHOR_EMAIL=other@example.invalid git commit -q --allow-empty -m "#7 правка"
    expect "подпись: GIT_AUTHOR_EMAIL" refuse "автор «probe <other@example.invalid>»" "$rc" "$out"
    at 7; run env GIT_COMMITTER_EMAIL=other@example.invalid git commit -q --allow-empty -m "#7 правка"
    expect "подпись: GIT_COMMITTER_EMAIL" refuse "окружением: GIT_COMMITTER_EMAIL" "$rc" "$out"
    at 7; run git commit -q --allow-empty --author="Other <other@example.invalid>" -m "#7 правка"
    expect "подпись: --author" refuse "автор «Other <other@example.invalid>»" "$rc" "$out"
    "${G[@]}" config --local user.email probe@example.invalid
    at 7; run git commit -q --allow-empty -m "#7 правка"
    expect "подпись: --local user.email, даже равный корневому" refuse "настройкой --local" "$rc" "$out"
    "${G[@]}" config --local --unset user.email

    at feature-old; run git commit -q --allow-empty -m "#12 правка старой ветки"
    expect "ветка до правила: «#12 …» на не-номере" pass - "$rc" "$out"
    at old; run git commit -q --amend --allow-empty -m "история без номера, трейлер снят"
    expect "переписывание истории: --amend коммита до T0" pass - "$rc" "$out"
    at old; run git commit -q --amend --allow-empty -m "история без номера" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    expect "переписывание истории: трейлер оставлен" refuse "атрибуция" "$rc" "$out"
    at old; run env GIT_COMMITTER_EMAIL=other@example.invalid git commit -q --amend --allow-empty -m "история без номера, трейлер снят"
    expect "переписывание истории: коммиттер не корневой" refuse "коммиттер «probe <other@example.invalid>»" "$rc" "$out"
    at 7; run git commit -q --allow-empty --date="$PRE" -m "#7 задним числом"
    expect "новый коммит с датой до T0" refuse "раньше T0" "$rc" "$out"

    printf '#7 правка\n' > "$tmp/msg"
    out="$(cd "$r" && env HOME="$tmp/nohome" GIT_AUTHOR_NAME=probe GIT_AUTHOR_EMAIL=probe@example.invalid \
        GIT_EDITOR=: bash scripts/hooks/commit-msg "$tmp/msg" 2>&1)"; rc=$?
    expect "корневая учётная запись не задана" refuse "корневая учётная запись не задана" "$rc" "$out"

    mv "$r/scripts/hooks/branch-rule.sh" "$tmp/lib.away"
    at 7; run git commit -q --allow-empty -m "#7 правка"
    expect "предиката нет — отказ, а не молчание" refuse "судить нечем" "$rc" "$out"
    mv "$tmp/lib.away" "$r/scripts/hooks/branch-rule.sh"
}

# ── Отправка: страж на входе git и настоящий pre-push ────────────────────────
PP="$tmp/pp"
push_fixture() { # $1 — набор
    rm -rf "$PP" "$tmp/origin.git"
    git init -q --bare "$tmp/origin.git"
    git init -q "$PP"
    local G=(git -C "$PP")
    "${G[@]}" remote add origin "$tmp/origin.git"
    "${G[@]}" commit -q --allow-empty --date="$PRE" --author='Old <old@example.invalid>' -m "история"
    rule_commit "$PP" "$1"
    "${G[@]}" checkout -q -b 20; "${G[@]}" commit -q --allow-empty -m "#20 волна: начало"
    "${G[@]}" checkout -q -b wip/old main; "${G[@]}" commit -q --allow-empty --date="$PRE" -m "черновик до правила"
    "${G[@]}" push -q origin main 20 wip/old
    "${G[@]}" commit -q --allow-empty -m "#34 доводка черновика"

    "${G[@]}" checkout -q -b 21 20; "${G[@]}" commit -q --allow-empty -m "#21 задача"
    "${G[@]}" checkout -q -b 20m 20; "${G[@]}" merge -q --no-ff 21 -m "#20 merge #21: задача"
    "${G[@]}" checkout -q -b 20d 20; "${G[@]}" merge -q --no-ff --no-edit 21
    "${G[@]}" checkout -q -b 20f 20; "${G[@]}" merge -q --no-ff 21 -m "#20 слияние 21"
    "${G[@]}" checkout -q -b 30 main; "${G[@]}" commit -q --allow-empty -m "#30 волна: начало"
    "${G[@]}" checkout -q -b 31 30; "${G[@]}" commit -q --allow-empty -m "#31 задача"
    "${G[@]}" checkout -q -b 22 20; "${G[@]}" commit -q --allow-empty -m "задача без номера"
    "${G[@]}" checkout -q -b 23 20; "${G[@]}" commit -q --allow-empty -m "#24 чужой номер"
    "${G[@]}" checkout -q -b 25 20; "${G[@]}" commit -q --allow-empty --author="Other <other@example.invalid>" -m "#25 чужой автор"
    "${G[@]}" checkout -q -b 26 20; GIT_COMMITTER_EMAIL=other@example.invalid "${G[@]}" commit -q --allow-empty -m "#26 чужой коммиттер"
    "${G[@]}" checkout -q -b old-feature main
    "${G[@]}" commit -q --allow-empty --date="$PRE" -m "старая работа"
    "${G[@]}" commit -q --allow-empty -m "#33 доводка"
    "${G[@]}" checkout -q -b old-trailer main
    "${G[@]}" commit -q --allow-empty --date="$PRE" -m "старая работа" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    "${G[@]}" checkout -q main
    "${G[@]}" fetch -q origin
    equip "$PP" "$1"
}

rule_run() { # $1 — строки входа git; дальше — окружение
    local input="$1"; shift
    out="$(cd "$PP" && env "$@" bash scripts/hooks/prepush-rule.sh origin <<< "$input" 2>&1)"; rc=$?
}
line() { # $1 — локальная ветка, $2 — удалённое имя (умолчание — то же)
    local rs z=0000000000000000000000000000000000000000
    rs="$(git -C "$PP" rev-parse -q --verify "refs/remotes/origin/${2:-$1}" || echo "$z")"
    printf 'refs/heads/%s %s refs/heads/%s %s' "$1" "$(git -C "$PP" rev-parse "$1")" "${2:-$1}" "$rs"
}

push_rule_cases() {
    rule_run "$(line 21)"
    expect "отправка: задача 21 от волны на удалённом" pass - "$rc" "$out"
    rule_run "$(line 21 issue-21)"
    expect "отправка: новая ветка issue-21" refuse "новая ветка называется номером" "$rc" "$out"
    rule_run "$(line 20m 20)"
    expect "отправка: волна с «#20 merge #21: …»" pass - "$rc" "$out"
    rule_run "$(line 20d 20)"
    expect "отправка: волна со слиянием по умолчанию" refuse "первая строка не начинается" "$rc" "$out"
    rule_run "$(line 20f 20)"
    expect "отправка: слияние не по форме" refuse "слияние не по форме" "$rc" "$out"
    rule_run "$(line 31)"
    expect "отправка: задача от волны, живущей только локально" pass - "$rc" "$out"
    rule_run "$(line 22)"
    expect "отправка: первая строка без «#N »" refuse "первая строка не начинается" "$rc" "$out"
    rule_run "$(line 23)"
    expect "отправка: «#24» на ветке 23" refuse "«#24» на ветке «23»" "$rc" "$out"
    rule_run "$(line 25)"
    expect "отправка: автор не корневой" refuse "автор «Other" "$rc" "$out"
    rule_run "$(line 26)"
    expect "отправка: коммиттер не корневой" refuse "коммиттер «probe <other@example.invalid>»" "$rc" "$out"
    rule_run "$(line old-feature)"
    expect "отправка: ветка до правила — имя не судится" pass - "$rc" "$out"
    rule_run "$(line old-trailer)"
    expect "отправка: неопубликованный коммит до T0 с трейлером" refuse "атрибуция" "$rc" "$out"
    rule_run "$(line wip/old)"
    expect "отправка: ветка до правила, уже лежащая на удалённом" pass - "$rc" "$out"
    rule_run "refs/heads/21 0000000000000000000000000000000000000000 refs/heads/21 $(git -C "$PP" rev-parse 21)"
    expect "отправка: удаление ссылки" pass - "$rc" "$out"
    rule_run "refs/tags/v1 $(git -C "$PP" rev-parse 22) refs/tags/v1 0000000000000000000000000000000000000000"
    expect "отправка: тег — не ветка" pass - "$rc" "$out"
    rule_run "$(line 21)" HOME="$tmp/nohome"
    expect "отправка: корневой нет — судить не с чем" cannot "подпись НЕ сверена" "$rc" "$out"
}

# Настоящий `git push` в голый репозиторий через настоящий pre-push. Проверки
# хука (сборка, пробы) фикстуре не по силам — Go-модуля в ней нет, — поэтому
# законная отправка идёт с объявленным обходом ПРОВЕРОК; страж им не снимается.
hook_cases() {
    local G=(git -C "$PP")
    ( cd "$PP" && bash scripts/hooks/install.sh stub pre-push ) > "$PP/.git/hooks/pre-push"
    chmod +x "$PP/.git/hooks/pre-push"

    "${G[@]}" checkout -q 31
    out="$(cd "$PP" && KANAME_SKIP_PREPUSH=1 git push origin 31 2>&1)"; rc=$?; [ "$rc" = 0 ] || rc=1
    expect "git push: ветка 31, проверки сняты обходом, страж пропускает" pass - "$rc" "$out"
    "${G[@]}" checkout -q -b issue-7 main; "${G[@]}" commit -q --allow-empty -m "#7 правка"
    out="$(cd "$PP" && git push origin issue-7 2>&1)"; rc=$?; [ "$rc" = 0 ] || rc=1
    expect "git push: ветка issue-7" refuse "pre-push ОТКАЗ: правило ветки и коммита нарушено" "$rc" "$out"
    out="$(cd "$PP" && KANAME_SKIP_PREPUSH=1 git push origin issue-7 2>&1)"; rc=$?; [ "$rc" = 0 ] || rc=1
    expect "git push: KANAME_SKIP_PREPUSH стража не снимает" refuse "новая ветка называется номером" "$rc" "$out"
    mv "$PP/scripts/hooks/prepush-rule.sh" "$tmp/guard.away"
    out="$(cd "$PP" && KANAME_SKIP_PREPUSH=1 git push origin issue-7 2>&1)"; rc=$?; [ "$rc" = 0 ] || rc=1
    expect "git push: стража нет — отказ, а не молчание" refuse "судить нечем" "$rc" "$out"
    mv "$tmp/guard.away" "$PP/scripts/hooks/prepush-rule.sh"
    "${G[@]}" checkout -q main
}

# ── Запрос на слияние ────────────────────────────────────────────────────────
pr_run() { # $1 голова, $2 база (ревизия), $3 вершина, $4 заголовок, $5 тело
    out="$(cd "$PP" && env PR_TITLE="$4" PR_BODY="$5" HEAD_REF="$1" \
        BASE_SHA="$(git rev-parse "$2")" HEAD_SHA="$(git rev-parse "$3")" \
        bash .github/scripts/pr-rule-check.sh 2>&1)"; rc=$?
}

pr_cases() {
    pr_run 21 origin/20 21 "#21 задача" "обычное тело"
    expect "запрос: 21 в волну 20" pass - "$rc" "$out"
    pr_run 21 origin/20 21 "задача" "обычное тело"
    expect "запрос: заголовок без «#N »" refuse "заголовок не начинается" "$rc" "$out"
    pr_run 21 origin/20 21 "#22 задача" "обычное тело"
    expect "запрос: заголовок «#22» у головы 21" refuse "заголовок «#22» у головы «21»" "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача, Generated with [Claude Code](https://example.invalid)" "обычное тело"
    expect "запрос: атрибуция в заголовке" refuse "заголовок: атрибуция" "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача" "тело"$'\n\n'"Co-authored-by: Ivan <ivan@example.invalid>"
    expect "запрос: законный соавтор в теле" pass - "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача" "тело"$'\n\n'"Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    expect "запрос: тело с трейлером Claude" refuse "тело: атрибуция" "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача" "тело"$'\n\n'"🤖 Generated with [Claude Code](https://example.invalid)"
    expect "запрос: тело с Generated with Claude Code" refuse "тело: атрибуция" "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача" "тело"$'\n\n'"https://claude.ai/code/session_x"
    expect "запрос: тело со ссылкой на сессию" refuse "тело: атрибуция" "$rc" "$out"
    pr_run 21 origin/20 21 "#21 задача" "тело"$'\n'"Claude-Session: https://example.invalid/s"
    expect "запрос: тело со строкой Claude-Session" refuse "тело: атрибуция" "$rc" "$out"
    pr_run issue-21 origin/20 21 "#21 задача" "обычное тело"
    expect "запрос: голова issue-21" refuse "голова «issue-21»: ветка называется номером" "$rc" "$out"
    pr_run 20 origin/main 20m "#20 волна" "обычное тело"
    expect "запрос: волна 20 со слиянием по форме" pass - "$rc" "$out"
    pr_run 20 origin/main 20d "#20 волна" "обычное тело"
    expect "запрос: волна со слиянием по умолчанию" refuse "первая строка не начинается" "$rc" "$out"
    pr_run old-feature origin/main old-feature "#33 доводка" "обычное тело"
    expect "запрос: голова, открытая до правила" pass - "$rc" "$out"
    pr_run old-trailer origin/main old-trailer "#33 доводка" "обычное тело"
    expect "запрос: коммит до T0 с трейлером в диапазоне" refuse "атрибуция в сообщении" "$rc" "$out"
    out="$(cd "$PP" && env -u PR_BODY PR_TITLE="#21 задача" HEAD_REF=21 BASE_SHA=x HEAD_SHA=y \
        bash .github/scripts/pr-rule-check.sh 2>&1)"; rc=$?
    expect "запрос: входа нет" cannot "не задан PR_BODY" "$rc" "$out"
    rm -rf "$tmp/not0"; git init -q "$tmp/not0"
    git -C "$tmp/not0" commit -q --allow-empty --date="$PRE" -m "история"
    git -C "$tmp/not0" commit -q --allow-empty -m "#1 правка"
    equip "$tmp/not0" "$PP"
    out="$(cd "$tmp/not0" && env PR_TITLE="#1 правка" PR_BODY="" HEAD_REF=1 \
        BASE_SHA="$(git rev-parse HEAD~1)" HEAD_SHA="$(git rev-parse HEAD)" \
        bash .github/scripts/pr-rule-check.sh 2>&1)"; rc=$?
    expect "запрос: коммита правила в истории нет" cannot "T0 не выведен" "$rc" "$out"
    rm -rf "$tmp/shallow"; git clone -q --depth 1 "file://$tmp/origin.git" "$tmp/shallow" 2> /dev/null
    out="$(cd "$tmp/shallow" && mkdir -p scripts/hooks && cp "$PP/scripts/hooks/branch-rule.sh" scripts/hooks/ &&
        env PR_TITLE="#21 задача" PR_BODY="" HEAD_REF=21 BASE_SHA=x HEAD_SHA=y \
        bash "$PP/.github/scripts/pr-rule-check.sh" 2>&1)"; rc=$?
    expect "запрос: мелкий клон" cannot "клон мелкий" "$rc" "$out"
    # Граница мелкого клона показывает свои файлы добавленными — T0 с неё не берётся.
    out="$(cd "$tmp/shallow" && bash -c '. scripts/hooks/branch-rule.sh
        if t="$(branch_rule_t0 HEAD)"; then echo "T0 $t"; exit 0; fi
        echo "T0 не выведен"; exit 2' 2>&1)"; rc=$?
    expect "мелкий клон: T0 не берётся с границы" cannot "T0 не выведен" "$rc" "$out"
}

suite() { # $1 — набор, $2 — метка
    TAG="$2"; FAILS=0; CASES=0
    commit_msg_cases "$1"
    push_fixture "$1"
    push_rule_cases
    pr_cases
    hook_cases
    printf '%s %s\n' "$FAILS" "$CASES" > "$tmp/result.$2"
}

# ── Прогоны ──────────────────────────────────────────────────────────────────
kit_from_tree "$tmp/kit-real"

defect() { # $1 — метка, $2 — описание; правит копию набора, печатает её путь
    local k="$tmp/kit-$1"
    kit_from_tree "$k"
    case "$1" in
        blind)  printf '\nbranch_rule_attribution() { return 1; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        issue)  printf '\nbranch_rule_is_number() { [[ "$1" =~ ^[0-9]+$ || "$1" =~ ^issue-[0-9]+$ ]]; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        t0)     printf '\nbranch_rule_t0() { printf 0; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        noguard) sed -i 's|^rule_out="$(bash "$rule_guard".*$|rule_out=""; true|' "$k/scripts/hooks/pre-push"
                grep -q '^rule_out=""; true$' "$k/scripts/hooks/pre-push" || return 1 ;;
        # Обход проверок, поставленный ДО стража, снял бы и страж.
        skipfirst) sed -i '0,/^set -uo pipefail$/s//set -uo pipefail\n[ "${KANAME_SKIP_PREPUSH:-0}" = 1 ] \&\& exit 0/' "$k/scripts/hooks/pre-push"
                grep -q '^\[ "${KANAME_SKIP_PREPUSH:-0}" = 1 \] && exit 0$' "$k/scripts/hooks/pre-push" || return 1 ;;
    esac
}

echo "── проба против настоящей оснастки (ждём ноль провалов)"
suite "$tmp/kit-real" настоящий
read -r real_fails real_cases < "$tmp/result.настоящий"

declare -A dfails
for d in blind issue t0 noguard skipfirst; do
    if defect "$d"; then
        echo
        echo "── проба против дефекта «$d» (ждём хотя бы один провал)"
        suite "$tmp/kit-$d" "дефект-$d" > "$tmp/out.$d"
        read -r dfails[$d] _ < "$tmp/result.дефект-$d"
        grep -c '^  FAIL' "$tmp/out.$d" | sed 's/^/   провалов: /'
        # Какие утверждения дефект уронил — чтобы красное было видно ПО ПРЕДМЕТУ.
        LC_ALL=C sed -n -E 's/^  FAIL \[[^]]*\] (.*): (законный случай отвергнут|ждали) .*/     · \1/p' "$tmp/out.$d"
    else
        dfails[$d]="н/д"
    fi
done

echo
echo "── итог"
printf '  утверждений у настоящего: %s, провалов %s (норма 0)\n' "$real_cases" "$real_fails"
rc=0
[ "$real_fails" = 0 ] || { echo "ОТКАЗ: настоящая оснастка нарушает свои утверждения" >&2; rc=1; }
[ "${real_cases:-0}" -gt 0 ] || { echo "ОТКАЗ: ни одного утверждения не исполнено" >&2; rc=1; }
for d in blind issue t0 noguard skipfirst; do
    printf '  дефект %-8s провалов %s (норма ≥1)\n' "$d" "${dfails[$d]}"
    if [ "${dfails[$d]}" = "н/д" ]; then
        echo "ОТКАЗ: дефект «$d» не воссоздан — форма оснастки изменилась" >&2; rc=1
    elif [ "${dfails[$d]}" -lt 1 ]; then
        echo "ОТКАЗ: проба ЗЕЛЁНАЯ на дефекте «$d» — она не держит свой предмет" >&2; rc=1
    fi
done
exit "$rc"
