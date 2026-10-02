#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Страж правила ветки и коммита для ОТПРАВКИ. Предикат — scripts/hooks/branch-rule.sh.
#
# Вход — строки git `<local_ref> <local_sha> <remote_ref> <remote_sha>` на stdin,
# $1 — имя удалённого. Судятся только ветки (`refs/heads/*`); удаление ссылки не
# судится — вершины у него нет.
#
#   · имя: новая ветка — номер задачи; ветка, уже лежащая на удалённом, либо
#     несущая вне ствола коммит с датой автора до T0, открыта до правила и не
#     переименовывается;
#   · коммиты: новые — недостижимые ни с одной удалённой ссылки и с прежней
#     вершины этой. Первые родители, не достижимые и с других локальных веток, —
#     собственные коммиты ветки: у ветки-номера их первая строка несёт её номер.
#     Коммит, пришедший слиянием чужой ветки, несёт номер своей задачи.
#
# Исходы: 0 — нарушений нет; 1 — нарушения, названы поимённо; 2 — судить не
# смог (корневая учётная запись не задана, а коммиты после T0 есть).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=branch-rule.sh
. "$here/branch-rule.sh"

# T0 — из истории HEAD: хук исполняется из этой рабочей копии, и коммит правила
# в её истории есть всегда, кроме копии, где правило ещё не закоммичено.
branch_rule_load_t0 HEAD

remote="${1:-origin}"
zero="0000000000000000000000000000000000000000"
ident="$(branch_rule_root_ident)" || ident="?"
refs=0

while read -r local_ref local_sha remote_ref remote_sha; do
    [ -n "${remote_ref:-}" ] || continue
    case "$remote_ref" in refs/heads/*) ;; *) continue ;; esac
    [ -n "${local_sha:-}" ] && [ "$local_sha" != "$zero" ] || continue
    name="${remote_ref#refs/heads/}"
    refs=$((refs + 1))
    if ! tip="$(git rev-parse --verify --quiet "$local_sha^{commit}")"; then
        BR_FINDINGS+=("ветка «$name»: вершина $local_sha не разрешается в коммит")
        continue
    fi

    neg=(--not --remotes)
    existed=0
    if [ -n "${remote_sha:-}" ] && [ "$remote_sha" != "$zero" ]; then
        existed=1
        git cat-file -e "$remote_sha^{commit}" 2> /dev/null && neg+=("$remote_sha")
    fi

    if [ "$name" != main ] && ! branch_rule_is_number "$name" && [ "$existed" = 0 ]; then
        trunk="refs/remotes/$remote/main"
        if git rev-parse --verify --quiet "$trunk" > /dev/null; then
            pre=("$tip" --not "$trunk")
        else
            pre=("$tip" --not --remotes)
        fi
        branch_rule_has_pre_t0 "${pre[@]}" ||
            BR_FINDINGS+=("ветка «$name»: новая ветка называется номером задачи (^[0-9]+\$), исключение одно — main")
    fi

    # Свои первые родители: другие локальные ветки из отрицания исключаются по
    # имени отправляемой и по имени локальной ссылки.
    excl=(--exclude="$name")
    case "$local_ref" in
        refs/heads/*) excl+=(--exclude="${local_ref#refs/heads/}") ;;
        HEAD) hb="$(git symbolic-ref -q --short HEAD)" && excl+=(--exclude="$hb") ;;
    esac
    owned="$(git rev-list --first-parent "$tip" "${neg[@]}" "${excl[@]}" --branches)"
    branch_rule_judge_commits "$name" "$owned" "$ident" "$tip" "${neg[@]}"
done

echo "== правило ветки и коммита (T0 $(branch_rule_t0_text)): веток $refs, новых коммитов $BR_SEEN, из них после T0 $BR_AFTER_T0"
if [ "$refs" -eq 0 ]; then
    echo "   веток в отправке нет — судить нечего"
fi
if [ "${#BR_FINDINGS[@]}" -gt 0 ]; then
    echo "   нарушений: ${#BR_FINDINGS[@]}"
    printf '     %s\n' "${BR_FINDINGS[@]}"
    exit 1
fi
if [ "$BR_NO_ROOT" -gt 0 ]; then
    echo "   подпись НЕ сверена у $BR_NO_ROOT коммит(ов): корневая учётная запись не задана"
    echo "   (git config --global user.name / user.email) — сверять не с чем"
    exit 2
fi
echo "   нарушений нет"
exit 0
