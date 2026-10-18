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
# ВЕДОМОСТЬ ИЗВЕСТНЫХ ИСТОРИЧЕСКИХ НАРУШЕНИЙ (PRO-Robotech/kaname#482) —
# .github/scripts/pr-rule-known-violations.tsv. Её запись прощает нарушения
# ФОРМЫ первой строки ровно одному коммиту — тому, чей полный sha записан, и
# только потому, что историю не переписывают. Всё остальное судится как без неё:
# другой коммит той же формы, серверное слияние с другим sha, атрибуция у
# записанного коммита — нарушения. Сама ведомость тоже судится, и её находки
# ложатся в тот же перечень нарушений:
#   · полей ровно четыре через TAB: sha · день коммита · задача · причина;
#   · sha — 40 знаков [0-9a-f], префикс не прощает;
#   · день — ГГГГ-ММ-ДД коммита по времени коммиттера (UTC), и коммит в клоне есть;
#   · задача — `#<N>` либо `PRO-Robotech/<репозиторий>#<N>`; причина не пуста;
#   · sha не повторяется;
#   · запись, чей коммит в диапазоне, а нарушений формы у него нет, прощать
#     нечего — находка (самоистечение).
# Негодная запись не прощает ничего. Файла нет — прощённого нет, и это
# печатается. Запись, дописанная тем же запросом о своём же коммите, видна
# только в диффе ведомости: механизма против неё нет, держится ревью запроса.
#
# СЕРВЕРНОЕ СЛИЯНИЕ ЗАПРОСА (PRO-Robotech/kaname#716). Коммит слияния, который
# площадка сделала при вливании запроса волны в ветку-номер, несёт первую строку,
# заданную площадкой: заголовок запроса и « (#M)» (merge_commit_title=PR_TITLE)
# либо тему, переданную при вливании. Он попадает в диапазон только запроса
# следующего уровня (эпик → main), а коммиты влитого запроса уже судились его
# прогоном. Такое слияние узнаётся признаком ПЛОЩАДКИ, а не формой текста:
#   · у коммита ≥ 2 родителей, первая строка — «#<N> » (иначе судится как прежде);
#   · GET repos/$GITHUB_REPOSITORY/commits/<sha>/pulls называет запрос, который
#     влит (merged_at) и чей merge_commit_sha — этот sha;
#   · коммит первородительской цепочки головы — слияние В неё: база запроса —
#     голова;
#   · « (#M)» в конце первой строки — номер того же запроса.
# Узнанному снимаются два нарушения формы (форма слияния, номер ветки-номера);
# атрибуция и подпись — нет. Спрашивается только слияние, которое без признака
# было бы нарушением, — число спрошенного печатается. Нет GITHUB_REPOSITORY или
# `gh` — сверки нет, слияния судятся по форме, и это печатается; площадка не
# ответила — так же, с её ответом. Подделать признак коммитом нельзя: его даёт
# площадка, а не сообщение.
#
# Вход — окружение: PR_TITLE, PR_BODY, HEAD_REF, BASE_SHA, HEAD_SHA. Заголовок и
# тело приходят переменными, а не подстановкой в текст шага: это ввод автора
# запроса.
#
# `--commits-only` — для хука отправки (scripts/hooks/prepush-classes.py,
# kaname#822), когда запроса ещё нет: заголовка и тела не существует, судятся
# голова и коммиты диапазона, а «заголовок и тело — не судились» печатается
# строкой. Конвейер флага не передаёт: заголовок и тело у него есть всегда.
#
# Исходы: 0 — нарушений нет; 1 — нарушения, названы поимённо; 2 — судить не
# смог (нет входа, мелкий клон, коммитов нет в клоне).
set -uo pipefail

commits_only=0
if [ "${1:-}" = --commits-only ]; then
    commits_only=1
    shift
fi
if [ "$#" -gt 0 ]; then
    echo "pr-rule: неизвестный довод «$1»" >&2
    exit 2
fi
inputs=(HEAD_REF BASE_SHA HEAD_SHA)
[ "$commits_only" = 1 ] || inputs=(PR_TITLE PR_BODY "${inputs[@]}")
for v in "${inputs[@]}"; do
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

# ── Ведомость известных нарушений ───────────────────────────────────────────
ledger_rel=.github/scripts/pr-rule-known-violations.tsv
ledger="$root/$ledger_rel"

# ledger_split <строка> — поля по TAB в LV_F; пустое поле остаётся полем
# (`read` с IFS из пробельного TAB схлопнул бы соседние разделители).
ledger_split() {
    local s="$1"
    LV_F=()
    while [[ "$s" == *$'\t'* ]]; do
        LV_F+=("${s%%$'\t'*}")
        s="${s#*$'\t'}"
    done
    LV_F+=("$s")
}

# ledger_commit_day <sha> — день коммита по времени коммиттера (UTC); 1 — коммита
# в клоне нет. Читается сам объект: заголовок до первой пустой строки.
ledger_commit_day() {
    local raw ct
    raw="$(git cat-file commit "$1" 2> /dev/null)" || return 1
    ct="$(awk '/^$/ { exit } /^committer / { print $(NF - 1); exit }' <<< "$raw")"
    [[ "$ct" =~ ^[0-9]+$ ]] || return 1
    date -u -d "@$ct" +%F
}

LV_PRESENT=0
LV_ROWS=0
LV_SHAS=()
LV_META=()
exempt=""
declare -A lv_line=()
if [ -f "$ledger" ]; then
    LV_PRESENT=1
    lineno=0
    while IFS= read -r row || [ -n "$row" ]; do
        lineno=$((lineno + 1))
        case "$row" in '' | '#'*) continue ;; esac
        LV_ROWS=$((LV_ROWS + 1))
        where="ведомость $ledger_rel:$lineno"
        ledger_split "$row"
        if [ "${#LV_F[@]}" != 4 ]; then
            BR_FINDINGS+=("$where: полей ${#LV_F[@]}, а запись — ровно 4 через TAB: sha · день коммита · задача · причина")
            continue
        fi
        sha="${LV_F[0]}" day="${LV_F[1]}" task="${LV_F[2]}" reason="${LV_F[3]}"
        bad=()
        if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
            if ! real="$(ledger_commit_day "$sha")"; then
                bad+=("коммита $sha в клоне нет — прощать нечего")
            elif [ "$day" != "$real" ]; then
                bad+=("день «$day» не день коммита $sha ($real, UTC, время коммиттера)")
            fi
            if [ -n "${lv_line[$sha]+x}" ]; then
                bad+=("sha $sha записан повторно (первая запись — строка ${lv_line[$sha]})")
            else
                lv_line[$sha]="$lineno"
            fi
        else
            bad+=("sha «$sha» не полный: запись называет коммит ровно 40 знаками [0-9a-f], префикс не прощает")
        fi
        [[ "$task" =~ ^(PRO-Robotech/[A-Za-z0-9._-]+)?#[0-9]+$ ]] ||
            bad+=("задача «$task» не по форме «#<N>» либо «PRO-Robotech/<репозиторий>#<N>»")
        [[ "$reason" =~ [^[:space:]] ]] || bad+=("причина пуста: запись без довода не прощает")
        if [ "${#bad[@]}" -gt 0 ]; then
            for b in "${bad[@]}"; do
                BR_FINDINGS+=("$where: $b")
            done
            continue
        fi
        exempt+="$sha"$'\n'
        LV_SHAS+=("$sha")
        LV_META+=("$task, $day — $reason")
    done < "$ledger"
fi
# shellcheck disable=SC2034  # читает branch_rule_judge_commits (branch-rule.sh)
BR_EXEMPT="$exempt"

if [ "$commits_only" = 0 ]; then
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
fi
if [ "$head" != main ] && ! branch_rule_is_number "$head"; then
    branch_rule_has_pre_t0 "${range[@]}" ||
        BR_FINDINGS+=("голова «$head»: ветка называется номером задачи (^[0-9]+\$), исключение — main и ветки, открытые до правила")
fi

owned="$(git rev-list --first-parent "${range[@]}")"

# ── Серверные слияния запросов (kaname#716) ───────────────────────────────────────
# server_merge_confirmed <sha> <владеемый: 0|1> <первая строка> — 0: площадка
# называет влитой запрос с этим merge_commit_sha (номер — в SM_PR); 1: не
# называет; 2: площадка не ответила (ответ — в SM_ERR).
server_merge_confirmed() {
    local sha="$1" own="$2" subj="$3" ref="" rows row num merged mc base
    SM_PR="" SM_ERR=""
    [[ "$subj" =~ \ \(#([0-9]+)\)$ ]] && ref="${BASH_REMATCH[1]}"
    rows="$(gh api --paginate "repos/$GITHUB_REPOSITORY/commits/$sha/pulls" \
        --jq '.[] | [.number, (.merged_at // ""), (.merge_commit_sha // ""), .base.ref] | @tsv' 2>&1)" || {
        SM_ERR="$(printf '%s' "$rows" | tr '\n' ' ' | cut -c1-200)"
        return 2
    }
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        ledger_split "$row"
        [ "${#LV_F[@]}" = 4 ] || continue
        num="${LV_F[0]}" merged="${LV_F[1]}" mc="${LV_F[2]}" base="${LV_F[3]}"
        [[ "$num" =~ ^[0-9]+$ ]] && [ -n "$merged" ] && [ "$mc" = "$sha" ] || continue
        [ -z "$ref" ] || [ "$num" = "$ref" ] || continue
        [ "$own" = 0 ] || [ "$base" = "$head" ] || continue
        SM_PR="$num"
        return 0
    done <<< "$rows"
    return 1
}

server=""
SM_CAND=0 SM_ASKED=0 SM_OK=0
SM_REPORT=()
sm_why=""
if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    sm_why="нет GITHUB_REPOSITORY"
elif ! command -v gh > /dev/null 2>&1; then
    sm_why="нет gh"
fi
while IFS= read -r m; do
    [ -n "$m" ] || continue
    [ "$(git show -s --format=%at "$m")" -ge "$BRANCH_RULE_T0" ] || continue
    msubj="$(git show -s --format=%B "$m")"
    msubj="${msubj%%$'\n'*}"
    mn="$(branch_rule_subject_task "$msubj")" || continue
    mown=0
    [[ $'\n'"$owned"$'\n' == *$'\n'"$m"$'\n'* ]] && mown=1
    if branch_rule_merge_form "$msubj" &&
        ! { branch_rule_is_number "$head" && [ "$mown" = 1 ] && [ "$mn" != "$head" ]; }; then
        continue
    fi
    SM_CAND=$((SM_CAND + 1))
    [ -z "$sm_why" ] || continue
    SM_ASKED=$((SM_ASKED + 1))
    server_merge_confirmed "$m" "$mown" "$msubj"
    case $? in
        0) server+="$m"$'\n'
           SM_OK=$((SM_OK + 1))
           SM_REPORT+=("${m:0:10} — слияние запроса #$SM_PR, подтверждено площадкой") ;;
        1) SM_REPORT+=("${m:0:10} — площадка влитого запроса с этим merge_commit_sha не называет") ;;
        *) SM_REPORT+=("${m:0:10} — площадка не ответила: $SM_ERR") ;;
    esac
done < <(git rev-list --min-parents=2 "${range[@]}")
# shellcheck disable=SC2034  # читает branch_rule_judge_commits (branch-rule.sh)
BR_SERVER_MERGES="$server"

branch_rule_judge_commits "$head" "$owned" - "${range[@]}"

# Годная запись, чей коммит в диапазоне: прощённое печатается поимённо под
# полным sha; прощать нечего — находка. Коммита в диапазоне нет — запись молчит.
lv_in_range=0
LV_REPORT=()
for i in "${!LV_SHAS[@]}"; do
    s="${LV_SHAS[$i]}"
    [[ $'\n'"$BR_EXEMPT_SEEN" == *$'\n'"$s"$'\n'* ]] || continue
    lv_in_range=$((lv_in_range + 1))
    got=()
    for e in "${BR_EXCUSED[@]}"; do
        [ "${e%%$'\t'*}" = "$s" ] && got+=("${e#*$'\t'}")
    done
    if [ "${#got[@]}" -eq 0 ]; then
        BR_FINDINGS+=("ведомость $ledger_rel:${lv_line[$s]}: запись $s ничего не прощает — коммит в диапазоне, нарушений формы у него нет; снять запись")
        continue
    fi
    LV_REPORT+=("прощено ведомостью: $s (${LV_META[$i]}) — нарушений ${#got[@]}:")
    for g in "${got[@]}"; do
        LV_REPORT+=("  $g")
    done
done

echo "== правило запроса (T0 $(branch_rule_t0_text)): голова «$head», коммитов в диапазоне $BR_SEEN, из них после T0 $BR_AFTER_T0"
if [ "$commits_only" = 1 ]; then
    echo "   судилось: имя головы, сообщения коммитов; заголовок и тело — НЕ судились (запроса нет, --commits-only); подпись — нет"
else
    echo "   судилось: заголовок, тело, имя головы, сообщения коммитов; подпись — нет (её держат хуки)"
fi
if [ "$LV_PRESENT" = 1 ]; then
    echo "   ведомость известных нарушений ($ledger_rel): записей $LV_ROWS, годных ${#LV_SHAS[@]}, в диапазоне $lv_in_range, прощено нарушений ${#BR_EXCUSED[@]}"
else
    echo "   ведомость известных нарушений ($ledger_rel): файла нет — прощённого нет"
fi
if [ "${#LV_REPORT[@]}" -gt 0 ]; then
    printf '     %s\n' "${LV_REPORT[@]}"
fi
echo "   серверные слияния запросов (kaname#716): слияний не по форме $SM_CAND, спрошено $SM_ASKED, подтверждено площадкой $SM_OK"
if [ -n "$sm_why" ] && [ "$SM_CAND" -gt 0 ]; then
    echo "     не сверялись $SM_CAND — $sm_why: судятся по форме"
fi
if [ "${#SM_REPORT[@]}" -gt 0 ]; then
    printf '     %s\n' "${SM_REPORT[@]}"
fi
if [ "${#BR_FINDINGS[@]}" -gt 0 ]; then
    echo "   нарушений: ${#BR_FINDINGS[@]}"
    printf '     %s\n' "${BR_FINDINGS[@]}"
    exit 1
fi
echo "   нарушений нет"
exit 0
