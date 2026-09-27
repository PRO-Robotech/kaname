#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Проверка ЗАПРОСА на слияние по правилу ветки и коммита. Предикат —
# scripts/hooks/branch-rule.sh (тот же, что у хуков коммита и отправки).
#
# Хуки обходятся `--no-verify` и живут только в провязанном клоне; здесь —
# держатель, которого не обойти:
#   · заголовок — `#<N> `, у головы-номера N = голова; атрибуции нет;
#   · тело — без атрибуции;
#   · голова — номер задачи; исключения — `main` и ветка, открытая до правила
#     (в диапазоне есть коммит с датой автора до T0);
#   · коммиты base..head: атрибуция — у любого (п.9: опубликованное с
#     трейлерами переписывается до вливания), форма первой строки и слияния —
#     у коммитов после T0; свои первые родители головы-номера несут её номер.
# Подпись здесь НЕ судится: корневой учётной записи в конвейере нет, её держат
# хуки коммита и отправки.
#
# Вход — окружение: PR_TITLE, PR_BODY, HEAD_REF, BASE_SHA, HEAD_SHA. Заголовок и
# тело приходят переменными, а не подстановкой в текст шага: это ввод автора
# запроса.
#
# Исходы: 0 — нарушений нет; 1 — нарушения, названы поимённо; 2 — судить не
# смог (нет входа, мелкий клон, коммитов нет в клоне).
set -uo pipefail

for v in PR_TITLE PR_BODY HEAD_REF BASE_SHA HEAD_SHA; do
    if [ -z "${!v+x}" ]; then
        echo "pr-rule: не задан $v — судить нечего" >&2
        exit 2
    fi
done

root="$(git rev-parse --show-toplevel 2> /dev/null)" || {
    echo "pr-rule: это не рабочая копия git — диапазона запроса нет" >&2
    exit 2
}
lib="$root/scripts/hooks/branch-rule.sh"
[ -f "$lib" ] || {
    echo "pr-rule: нет $lib — предиката правила нет" >&2
    exit 2
}
# shellcheck source=../../scripts/hooks/branch-rule.sh
. "$lib"

if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    echo "pr-rule: клон мелкий — диапазон base..head неполон (нужен fetch-depth: 0)" >&2
    exit 2
fi
for s in "$BASE_SHA" "$HEAD_SHA"; do
    git cat-file -e "$s^{commit}" 2> /dev/null || {
        echo "pr-rule: коммита $s в клоне нет — диапазон не построить" >&2
        exit 2
    }
done

# T0 — из истории выкладки (в конвейере это ревизия слияния запроса, она несёт
# и базу, и голову). Не выведен — границы истории нет, и судить коммиты до
# правила как новые было бы ложным красным: исход «не смог».
branch_rule_load_t0 HEAD
if [ "$BRANCH_RULE_T0_KNOWN" != 1 ]; then
    echo "pr-rule: T0 не выведен — коммита, заведшего $BRANCH_RULE_T0_PATH, в истории выкладки нет; границы истории нет, судить не с чем" >&2
    exit 2
fi

head="$HEAD_REF"
range=("$HEAD_SHA" --not "$BASE_SHA")

if attr="$(branch_rule_attribution "$PR_TITLE")"; then
    BR_FINDINGS+=("заголовок: атрибуция «$attr»")
fi
if ! n="$(branch_rule_subject_task "$PR_TITLE")"; then
    BR_FINDINGS+=("заголовок не начинается с «#<N> »: «$PR_TITLE»")
elif branch_rule_is_number "$head" && [ "$n" != "$head" ]; then
    BR_FINDINGS+=("заголовок «#$n» у головы «$head»: заголовок несёт номер задачи ветки")
fi
if attr="$(branch_rule_attribution "$PR_BODY")"; then
    BR_FINDINGS+=("тело: атрибуция «$attr»")
fi
if [ "$head" != main ] && ! branch_rule_is_number "$head"; then
    branch_rule_has_pre_t0 "${range[@]}" ||
        BR_FINDINGS+=("голова «$head»: ветка называется номером задачи (^[0-9]+\$), исключение — main и ветки, открытые до правила")
fi

owned="$(git rev-list --first-parent "${range[@]}")"
branch_rule_judge_commits "$head" "$owned" - "${range[@]}"

echo "== правило запроса (T0 $(branch_rule_t0_text)): голова «$head», коммитов в диапазоне $BR_SEEN, из них после T0 $BR_AFTER_T0"
echo "   судилось: заголовок, тело, имя головы, сообщения коммитов; подпись — нет (её держат хуки)"
if [ "${#BR_FINDINGS[@]}" -gt 0 ]; then
    echo "   нарушений: ${#BR_FINDINGS[@]}"
    printf '     %s\n' "${BR_FINDINGS[@]}"
    exit 1
fi
echo "   нарушений нет"
exit 0
