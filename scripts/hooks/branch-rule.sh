#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ПРАВИЛО ВЕТКИ И КОММИТА — единственный источник предиката (решения владельца
# 2026-09-22, PRO-Robotech/kacho-workspace#770). Не исполняется сам: его читают
# три потребителя, и своей копии предиката нет ни у одного:
#
#   scripts/hooks/commit-msg          сообщение и подпись в момент коммита;
#   scripts/hooks/prepush-rule.sh     имя ветки и отправляемые коммиты (зовёт pre-push);
#   .github/scripts/pr-rule-check.sh  заголовок, голова, тело запроса и его коммиты.
#
# КОПИЯ, И ЭТО ПРИЗНАНО. Тот же предикат стоит у соседнего продукта
# (PRO-Robotech/kacho#2793, одноимённые пути): правило одно — решения владельца
# 2026-09-22, — а хук коммита и отправки исполняется из дерева той рабочей
# копии, где он лежит, и поставляемого артефакта, который оба репозитория брали
# бы пином, у правила нет. Предмет у пары ОДИН, поэтому её решение в ведомости
# пар воркспейса — `debt` с задачей (снятие: предикат переезжает в артефакт с
# пином), а не `own`; запись ложится тем же заходом, что и посадка в ствол.
#
# Правило:
#   · ветка — номер задачи ЭТОГО репозитория, `^[0-9]+$`; исключение одно — `main`;
#   · первая строка коммита — `#<N> `, N — задача ветки; коммит слияния —
#     `#<N> merge #<M>: …` либо `#<N> merge main: …`;
#   · подпись — только корневая учётная запись (`git config --global user.*`);
#     -c user.*, --local/--worktree user.*, GIT_AUTHOR_*/GIT_COMMITTER_* её не
#     переопределяют;
#   · атрибуции нет: трейлер Co-Authored-By с Claude/anthropic, строка
#     Claude-Session:, «Generated with [Claude Code]», ссылка claude.ai/code.
#
# T0 — граница истории. Коммит с датой автора до T0 по форме и подписи не
# судится: ветки, открытые до правила, не переименовываются, main не
# переписывается. Атрибуция судится у ЛЮБОГО коммита, который ещё не
# опубликован либо входит в запрос: опубликованные коммиты с трейлерами
# переписываются до вливания (только сообщения, дата автора сохраняется).
#
# T0 ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ — та же форма, что у стража воркспейса: время
# автора коммита, заведшего scripts/hooks/commit-msg в историю ревизии, то есть
# момент коммита правила в ЭТОМ репозитории. Литерал пришлось бы вписать до
# коммита, момент которого он называет. Потребитель зовёт branch_rule_load_t0
# до суждения; не выведен (коммита правила в истории нет) — T0 = 0, судится
# всё, и потребитель говорит об этом вслух.
BRANCH_RULE_T0_PATH=scripts/hooks/commit-msg
BRANCH_RULE_T0=0
BRANCH_RULE_T0_KNOWN=0

# branch_rule_t0 [ревизия] — печатает T0 эпохой; 1 — коммита правила в истории нет.
# `tail`: git log пишет новое первым, а правило вступило самым старым добавлением.
#
# Граница мелкого клона показывает ВСЕ свои файлы добавленными: найденный на ней
# «коммит правила» — время границы, а не правила, и такой T0 не выводится.
branch_rule_t0() {
    local rec h shallow
    rec="$(git log --no-color --diff-filter=A --format='%H %at' "${1:-HEAD}" -- "$BRANCH_RULE_T0_PATH" 2> /dev/null | tail -1)"
    [ -n "$rec" ] || return 1
    h="${rec%% *}"
    shallow="$(git rev-parse --git-path shallow 2> /dev/null)"
    if [ -n "$shallow" ] && [ -f "$shallow" ] && grep -qx "$h" "$shallow"; then
        return 1
    fi
    printf '%s' "${rec##* }"
}

# branch_rule_load_t0 [ревизия] — выставляет BRANCH_RULE_T0 и BRANCH_RULE_T0_KNOWN.
branch_rule_load_t0() {
    if BRANCH_RULE_T0="$(branch_rule_t0 "${1:-HEAD}")"; then
        BRANCH_RULE_T0_KNOWN=1
    else
        BRANCH_RULE_T0=0
        BRANCH_RULE_T0_KNOWN=0
    fi
}

branch_rule_t0_text() {
    [ "$BRANCH_RULE_T0_KNOWN" = 1 ] || { printf 'не выведен: коммита, заведшего %s, в истории нет — судится всё' "$BRANCH_RULE_T0_PATH"; return; }
    date -u -d "@$BRANCH_RULE_T0" '+%Y-%m-%dT%H:%M:%SZ' 2> /dev/null || printf '@%s' "$BRANCH_RULE_T0"
}

branch_rule_is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }

# branch_rule_subject_task <первая строка> — печатает N из `#<N> `; 1 — формы нет.
branch_rule_subject_task() {
    [[ "$1" =~ ^#([0-9]+)\  ]] || return 1
    printf '%s' "${BASH_REMATCH[1]}"
}

# branch_rule_merge_form <первая строка> — `#<N> merge #<M>…` либо `#<N> merge main…`.
branch_rule_merge_form() { [[ "$1" =~ ^#[0-9]+\ merge\ (#[0-9]+|main)([^0-9A-Za-z_]|$) ]]; }

# branch_rule_attribution <текст> — печатает первую строку атрибуции; 1 — её нет.
# Регистр не различается. Co-Authored-By без Claude/anthropic — законный соавтор.
branch_rule_attribution() {
    local line found=1 restore
    restore="$(shopt -p nocasematch)"
    shopt -s nocasematch
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*co-authored-by:.*(claude|anthropic) ]] ||
            [[ "$line" =~ ^[[:space:]]*claude-session: ]] ||
            [[ "$line" =~ generated[[:space:]]+with[[:space:]]+\[?claude[[:space:]]+code ]] ||
            [[ "$line" =~ claude\.ai/code ]]; then
            printf '%s' "$line"
            found=0
            break
        fi
    done <<< "$1"
    eval "$restore"
    return "$found"
}

# branch_rule_root_ident — «имя <адрес>» корневой учётной записи; 1 — не задана.
branch_rule_root_ident() {
    local n e
    n="$(git config --global --get user.name 2> /dev/null)" || return 1
    e="$(git config --global --get user.email 2> /dev/null)" || return 1
    [ -n "$n" ] && [ -n "$e" ] || return 1
    printf '%s <%s>' "$n" "$e"
}

# branch_rule_has_pre_t0 <аргументы rev-list> — есть ли в диапазоне коммит с
# датой автора до T0. Так узнаётся ветка, открытая до правила.
branch_rule_has_pre_t0() {
    local dates d
    dates="$(git log --no-color --format=%at "$@" 2> /dev/null)" || return 1
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        [ "$d" -lt "$BRANCH_RULE_T0" ] && return 0
    done <<< "$dates"
    return 1
}

# branch_rule_judge_commits <ветка> <владеемые sha> <подпись> <аргументы rev-list…>
#
# Судит каждый коммит диапазона. <владеемые sha> — первые родители, принадлежащие
# самой ветке (по строке): их первая строка обязана нести номер ветки-номера.
# <подпись> — «имя <адрес>» корневой учётной записи, «-» — подпись здесь не
# судится, «?» — судить не с чем (корневая не задана).
#
# Пополняет BR_FINDINGS; считает BR_SEEN (коммитов в диапазоне), BR_AFTER_T0
# (из них судимых по форме), BR_NO_ROOT (подпись не сверена: корневой нет).
BR_FINDINGS=()
BR_SEEN=0
BR_AFTER_T0=0
BR_NO_ROOT=0
branch_rule_judge_commits() {
    local name="$1" owned="$2" ident="$3" log rec h at parents author committer body subj n attr np
    shift 3
    log="$(git -c log.showSignature=false log --no-color --encoding=UTF-8 \
        --format='%H%x1f%at%x1f%P%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e' "$@")" || {
        BR_FINDINGS+=("диапазон «$*» не читается git log — судить нечем")
        return 1
    }
    # Запись завершается \x1e, git дописывает перевод строки после каждой.
    while IFS= read -r -d $'\x1e' rec; do
        rec="${rec#$'\n'}"
        [ -n "$rec" ] || continue
        IFS=$'\x1f' read -r -d '' h at parents author committer body <<< "$rec"
        [ -n "${h:-}" ] || continue
        BR_SEEN=$((BR_SEEN + 1))
        subj="${body%%$'\n'*}"
        if attr="$(branch_rule_attribution "$body")"; then
            BR_FINDINGS+=("${h:0:10} атрибуция в сообщении: «$attr»")
        fi
        [ "$at" -ge "$BRANCH_RULE_T0" ] || continue
        BR_AFTER_T0=$((BR_AFTER_T0 + 1))
        if ! n="$(branch_rule_subject_task "$subj")"; then
            BR_FINDINGS+=("${h:0:10} первая строка не начинается с «#<N> »: «$subj»")
        else
            np="$(wc -w <<< "$parents")"
            if [ "$np" -ge 2 ] && ! branch_rule_merge_form "$subj"; then
                BR_FINDINGS+=("${h:0:10} слияние не по форме «#<N> merge #<M>: …» / «#<N> merge main: …»: «$subj»")
            fi
            if branch_rule_is_number "$name" && [[ $'\n'"$owned"$'\n' == *$'\n'"$h"$'\n'* ]] && [ "$n" != "$name" ]; then
                BR_FINDINGS+=("${h:0:10} «#$n» на ветке «$name»: первая строка ветки-номера несёт её номер")
            fi
        fi
        case "$ident" in
            -) ;;
            \?) BR_NO_ROOT=$((BR_NO_ROOT + 1)) ;;
            *)
                [ "$author" = "$ident" ] ||
                    BR_FINDINGS+=("${h:0:10} автор «$author» — не корневая учётная запись «$ident»")
                [ "$committer" = "$ident" ] ||
                    BR_FINDINGS+=("${h:0:10} коммиттер «$committer» — не корневая учётная запись «$ident»")
                ;;
        esac
    done <<< "$log"
    return 0
}
