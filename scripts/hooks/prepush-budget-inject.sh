#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-budget-inject.sh — доказательство опытом, что хук отправки держит
# СВОЙ БЮДЖЕТ ПАМЯТИ: тяжёлого он не гоняет, параллелизм Go ограничен, а весь
# прогон идёт под потолком памяти, когда машина умеет его выставить.
#
# ─────────────────────────────────────────────────────────────────────────────
# ПРЕДМЕТ
#
# Хук исполняется на КАЖДОЙ отправке и на машине, где параллельно идут другие
# полосы. Решение владельца 2026-09-24: память машины не переваливает за 45 ГБ,
# тяжёлое (детектор гонок, линтер, контейнеры) локально не гоняется — его
# гоняет конвейер на АГРЕГАТЕ волны. Прежняя редакция хука звала
# `go test ./... -race` с параллелизмом по числу ядер и `make lint` — без
# всякого потолка, на каждой отправке.
#
# Свойство держится не текстом шапки хука, а тем, ЧТО хук зовёт. Поэтому опыт
# гоняет НАСТОЯЩИЙ хук на синтетическом модуле, а в PATH кладёт записывающие
# переходники `go` и `systemd-run`: они фиксируют каждый вызов и передают его
# настоящему инструменту (переходник `systemd-run` исполняет команду после `--`
# сам, чтобы опыт не зависел от пользовательского systemd машины).
#
# ─────────────────────────────────────────────────────────────────────────────
# ОСИ
#
#  1. КОНТРОЛЬ С ПОТОЛКОМ. Отправка зелёного модуля проходит; каждый вызов
#     `go build|vet|test` идёт с параллелизмом 4 и ВНУТРИ потолка; `-race` нет
#     ни в одном `go test`; цель `lint` не зовётся ни разу (а сама она
#     достижима — это проверено прямым вызовом, иначе молчание журнала ничего
#     бы не доказывало); перечень непроверенного называет детектор гонок и
#     линтер; ровно ОДИН вызов `systemd-run` перезапускает хук, и опции области
#     именно у НЕГО несут `--user --scope`, `MemoryMax=10G` и `MemorySwapMax=0`
#     (пробный вызов `-- true` в зачёт не идёт — разбор у судьи потолка).
#  2. ЗАКОННЫЙ БЛИЗНЕЦ: ПОТОЛОК НЕДОСТУПЕН. `systemd-run` отказывает. Отправка
#     проходит тем же исходом, что контроль, а отсутствие потолка названо
#     строкой, а не умолчано.
#  3. ИНЪЕКЦИЯ: КРАСНАЯ ПРОБА ПОД ПОТОЛКОМ. Потолок — это повторный запуск хука
#     внутри области systemd; код возврата обязан пройти сквозь неё. Упавшая
#     проба роняет отправку, и красной названа группа проб.
#  4. ЗАКОННЫЙ БЛИЗНЕЦ: СВОЙ GOFLAGS У ОТПРАВЛЯЮЩЕГО. Отличается от контроля
#     одним фактом — снаружи выставлено `GOFLAGS=-p=32`. Отправка проходит, и
#     у каждого вызова go действует 4: хук ПЕРЕКРЫВАЕТ чужое `-p`, а не
#     становится перед ним. Предпосылка — внешнее значение дошло до хука (его
#     видит переходник `systemd-run`); не дошло — ось не исполнялась.
#  5. СУДЬИ НА СИНТЕТИКЕ. Судья `-p` и судья потолка — те же функции, что у
#     осей 1–4, — прогнаны на входах с заранее известным ответом: форма
#     дефекта обязана дать красное, законная форма записи — зелёное.
#
# Контроль и близнецы гоняются со СНЯТЫМ внешним GOFLAGS, кроме оси 4: иначе
# окружение того, кто гоняет опыт, решало бы исход вместо хука.
#
# Исходы: 0 — все оси исполнены и сошлись; 1 — хотя бы одно утверждение не
# сошлось; 2 — предпосылка не создана либо объём исполненного разошёлся с
# объявленным (вердикта нет).
#
# Прогон: `bash scripts/hooks/prepush-budget-inject.sh` (или `--self-test`).
set -uo pipefail

case "${1:-}" in
    ""|--self-test) ;;
    *) echo "prepush-budget-inject: неизвестный довод «$1»" >&2; exit 2 ;;
esac

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — это не рабочая копия git" >&2; exit 2; }
HOOK="$ROOT/scripts/hooks/pre-push"
CLASSIFY="$ROOT/scripts/hooks/prepush-classify.sh"
INSTALL="$ROOT/scripts/hooks/install.sh"
RUNNER="$ROOT/.github/scripts/go-test-verdict.py"
RULE_LIB="$ROOT/scripts/hooks/branch-rule.sh"
RULE_GUARD="$ROOT/scripts/hooks/prepush-rule.sh"
for f in "$HOOK" "$CLASSIFY" "$INSTALL" "$RUNNER" "$RULE_LIB" "$RULE_GUARD"; do
    [ -f "$f" ] || { echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — нет $f" >&2; exit 2; }
done

MARK='УСЛОВИЕ НЕ СОЗДАНО'
checks=0
failed=0
current_axis=0
orphan_checks=0
axis_seen=()
axis_short=()
unmet_reasons=()

note_check() {
    if [ "$current_axis" -gt 0 ]; then
        axis_seen[$current_axis]=$(( ${axis_seen[$current_axis]:-0} + 1 ))
    else
        orphan_checks=$((orphan_checks + 1))
    fi
}
ok()  { checks=$((checks + 1)); note_check; echo "  ok   — $1"; }
bad() { checks=$((checks + 1)); note_check; failed=$((failed + 1)); echo "  БЕДА — $1" >&2; }

# Ведомость осей — единственный источник перечня и числа утверждений КАЖДОЙ оси.
AXIS_NAME=(1 2 3 4 5)
AXIS_CHECKS=(9 4 3 2 15)
AXES_DECLARED=${#AXIS_CHECKS[@]}
axes_executed=0
expected_checks=0

axis_done() {
    local want="${AXIS_CHECKS[$1 - 1]}" seen="${axis_seen[$1]:-0}"
    axes_executed=$((axes_executed + 1))
    expected_checks=$((expected_checks + want))
    [ "$seen" -eq "$want" ] || \
        axis_short+=("ось ${AXIS_NAME[$1 - 1]}: объявлено $want, исполнено $seen")
}

axis_unmet() {
    unmet_reasons+=("ось ${AXIS_NAME[$1 - 1]}: $2")
    echo "  $MARK (не находка): ось ${AXIS_NAME[$1 - 1]} НЕ ИСПОЛНЯЛАСЬ — $2" >&2
}

missing=()
for tool in go make python3 gofmt; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — нет в PATH: ${missing[*]}" >&2
    exit 2
fi
REAL_GO="$(command -v go)"

work="$(mktemp -d)" || { echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — нет временного каталога" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT

# КОРНЕВАЯ УЧЁТНАЯ ЗАПИСЬ ФИКСТУРЫ — СВОЯ. Хук первым зовёт страж правила ветки
# и коммита, а тот сверяет подпись с `git config --global user.*`: у конвейера
# её нет вовсе, у человека она своя. Поэтому глобальный файл настройки git
# подменяется файлом фикстуры, а коммит и ветка фикстуры идут по правилу —
# первая строка `#1 `, ветка `1`: предмет этого опыта не правило, и страж
# обязан его пропустить.
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
printf '[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' > "$GIT_CONFIG_GLOBAL"

# Временный каталог вне всякого репозитория — физическим путём (форма та же,
# что у хука и соседних проб: подъём по тексту пропустил бы символьную ссылку).
probe_dir="$(cd "$work" 2>/dev/null && pwd -P)"
[ -n "$probe_dir" ] || { echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — физический путь временного каталога не установлен" >&2; exit 2; }
while :; do
    if [ -e "$probe_dir/.git" ]; then
        echo "prepush-budget-inject: НЕ ИСПОЛНЯЛОСЬ — временный каталог внутри репозитория ($probe_dir/.git)" >&2
        exit 2
    fi
    parent="$(dirname "$probe_dir")"
    [ "$parent" != "$probe_dir" ] || break
    probe_dir="$parent"
done

# make_bin <каталог> <режим systemd-run: ok|fail> — записывающие переходники.
#
# `go` пишет строку на КАЖДЫЙ вызов: подкоманда, GOFLAGS, доводы и признак
# «внутри потолка» (его выставляет только переходник `systemd-run`). На
# `go env CGO_ENABLED` он отвечает «1»: иначе на машине без компилятора C
# прежний хук снял бы `-race` сам, и опыт зависел бы от машины, а не от хука.
# `golangci-lint` отвечает версией пина фикстуры — чтобы прежний хук дошёл до
# цели `lint`, если он её зовёт.
make_bin() {
    local b="$1" mode="$2"
    mkdir -p "$b" || return 1
    cat > "$b/go" <<GO
#!/usr/bin/env bash
printf 'sub=%s scoped=%s goflags=[%s] args=[%s]\n' "\${1:-}" "\${BUDGET_PROBE_SCOPED:-0}" "\${GOFLAGS:-}" "\$*" >> "$b/go.log"
if [ "\${1:-}" = env ] && [ "\${2:-}" = CGO_ENABLED ] && [ "\$#" -eq 2 ]; then echo 1; exit 0; fi
exec "$REAL_GO" "\$@"
GO
    cat > "$b/golangci-lint" <<'LINT'
#!/usr/bin/env bash
case "${1:-}" in version) echo "golangci-lint has version 9.9.9 built with go" ;; *) exit 0 ;; esac
LINT
    if [ "$mode" = ok ]; then
        cat > "$b/systemd-run" <<SR
#!/usr/bin/env bash
printf '%s\n' "\${GOFLAGS-}" >> "$b/outer-goflags.log"
( IFS=\$'\\037'; printf '%s\n' "\$*" ) >> "$b/systemd-run.log"
while [ "\$#" -gt 0 ] && [ "\$1" != "--" ]; do shift; done
[ "\$#" -gt 0 ] || exit 64
shift
BUDGET_PROBE_SCOPED=1 exec "\$@"
SR
    else
        cat > "$b/systemd-run" <<SR
#!/usr/bin/env bash
printf '%s\n' "\${GOFLAGS-}" >> "$b/outer-goflags.log"
( IFS=\$'\\037'; printf '%s\n' "\$*" ) >> "$b/systemd-run.log"
echo "Failed to connect to bus: No medium found" >&2
exit 1
SR
    fi
    chmod +x "$b/go" "$b/golangci-lint" "$b/systemd-run"
    : > "$b/go.log"; : > "$b/systemd-run.log"; : > "$b/outer-goflags.log"
}

# build_module <каталог> <тело пробы> — синтетический модуль с НАСТОЯЩИМ хуком.
build_module() {
    local d="$1" body="$2"
    mkdir -p "$d/.github/scripts" "$d/scripts/hooks" || return 1
    cp "$RUNNER" "$d/.github/scripts/go-test-verdict.py" || return 1
    cp "$HOOK" "$d/scripts/hooks/pre-push" || return 1
    cp "$CLASSIFY" "$d/scripts/hooks/prepush-classify.sh" || return 1
    # Хук первым зовёт страж правила ветки и коммита — без него он отказывает.
    cp "$RULE_LIB" "$d/scripts/hooks/branch-rule.sh" || return 1
    cp "$RULE_GUARD" "$d/scripts/hooks/prepush-rule.sh" || return 1
    chmod +x "$d/scripts/hooks/pre-push" "$d/scripts/hooks/prepush-classify.sh"
    printf 'module probe.invalid/budget\n\ngo 1.21\n' > "$d/go.mod"
    cat > "$d/budget_test.go" <<GO
package budget

import "testing"

func TestBudgetProbe(t *testing.T) {
$body
}
GO
    gofmt -w "$d/budget_test.go" || return 1
    # Цель `lint` пишет в журнал — по нему видно, звал ли её хук.
    cat > "$d/Makefile" <<MK
.PHONY: vet lint audit-list-filter print-golangci-pin
vet:
	@go vet ./...
lint:
	@echo lint >> "$d.lint.log"
audit-list-filter:
	@echo "ok"
print-golangci-pin:
	@printf '%s\n' 'v9.9.9'
MK
    : > "$d.lint.log"
    git -C "$d" init -q .
    git -C "$d" add -A
    git -C "$d" commit -q -m "#1 фикстура опыта"
    git init --bare -q "$d.git"
    git -C "$d" remote add origin "$d.git"
    ( cd "$d" && bash "$INSTALL" install ) >/dev/null 2>&1
}

# push_case <имя> <режим systemd-run> <тело пробы> [<внешний GOFLAGS>] —
# выставляет d, b, out, rc. Без четвёртого довода GOFLAGS СНЯТ: окружение того,
# кто гоняет опыт, в фикстуру не протекает, и контроль отличается от близнеца
# ровно одним фактом — внешним GOFLAGS.
push_case() {
    d="$work/$1"; b="$work/$1.bin"
    if [ "$#" -ge 4 ]; then export GOFLAGS="$4"; else unset GOFLAGS; fi
    make_bin "$b" "$2" || return 1
    build_module "$d" "$3" || return 1
    out="$(PATH="$b:$PATH" git -C "$d" push origin HEAD:refs/heads/1 2>&1)"
    rc=$?
}

# go_heavy_lines <журнал> — вызовы go, которые компилируют или гоняют пробы.
go_heavy_lines() { grep -E '^sub=(build|vet|test) ' "$1"; }

# effective_p <строка журнала> — значение -p, которое ДЕЙСТВУЕТ у этого вызова.
#
# Порядок — тот, в каком его применяет сам go (`cmd/go/internal/base/goflags.go`,
# `SetFromGOFLAGS`): поля GOFLAGS по очереди, каждое следующее перекрывает
# прежнее; затем доводы командной строки, тоже по очереди. Проход ОДИН и по
# порядку: прежний судья сперва собирал все `-p=N`, а потом все `-p N`, и у
# `-p 4 -p=32` называл 4 при действующем 32.
#
# Законные формы. В GOFLAGS значение пишется только через `=` (иначе go
# отказывает сам): `-p=N`, `--p=N`, поле может стоять в кавычках. В доводах:
# `-p N`, `-p=N`, `--p N`, `--p=N`; после `-args` доводы принадлежат бинарю
# проб, а не go. Форма, которой судья не знает, даёт не 4 — то есть КРАСНОЕ с
# названным значением, а не молчание.
effective_p() {
    local line="$1" p="" goflags args tok
    goflags="$(printf '%s' "$line" | sed -n 's/.* goflags=\[\([^]]*\)\].*/\1/p')"
    args="$(printf '%s' "$line" | sed -n 's/.* args=\[\(.*\)\]$/\1/p')"
    for tok in $goflags; do
        case "$tok" in \'*\'|\"*\") tok="${tok:1:${#tok}-2}" ;; esac
        case "$tok" in -p=*) p="${tok#-p=}" ;; --p=*) p="${tok#--p=}" ;; esac
    done
    set -- $args
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -args|--args) break ;;
            -p|--p) [ "$#" -ge 2 ] && { p="$2"; shift; } ;;
            -p=*) p="${1#-p=}" ;;
            --p=*) p="${1#--p=}" ;;
        esac
        shift
    done
    printf '%s' "$p"
}

# ── СУДЬЯ ПОТОЛКА: ОДИН ВЫЗОВ, А НЕ ВЕСЬ ЖУРНАЛ ─────────────────────────────
#
# Переходник `systemd-run` пишет строку на каждый вызов, доводы — через \037.
# Хук зовёт его ДВАЖДЫ: пробный вызов `-- true` (выставима ли область вообще) и
# перезапуск самого себя. Потолок держит только ВТОРОЙ: прогон идёт в нём.
# Прежний судья искал четыре признака каждый по всему журналу — и засчитывал
# `MemorySwapMax=0` пробного вызова перезапуску, у которого его не было.
#
# Поэтому: перезапуск хука — вызов, у которого среди доводов ПОСЛЕ `--` есть
# путь `…/scripts/hooks/pre-push`; такой вызов обязан быть ровно один, и судится
# только он. Опции области — только ДО `--` (после — доводы хука). Свойство
# читается во всех формах, которые принимает systemd-run: `-p V`, `-pV`,
# `--property V`, `--property=V`; из двух значений одного свойства действует
# последнее. Форма, которой судья не знает, даёт отказ с названным вызовом, а
# не пропуск.
CAP_WANT='user=1 scope=1 MemoryMax=10G MemorySwapMax=0'

# restart_calls <журнал> — строки вызовов, перезапускающих хук.
restart_calls() {
    local line tok after hit
    local -a toks
    while IFS= read -r line; do
        IFS=$'\037' read -r -a toks <<< "$line"
        after=0; hit=0
        for tok in ${toks[@]+"${toks[@]}"}; do
            if [ "$after" -eq 0 ]; then [ "$tok" = -- ] && after=1; continue; fi
            case "$tok" in */scripts/hooks/pre-push|scripts/hooks/pre-push) hit=1 ;; esac
        done
        [ "$hit" -eq 1 ] && printf '%s\n' "$line"
    done < "$1"
    return 0
}

# scope_options <строка вызова> — действующие опции области ДО `--`.
scope_options() {
    local -a toks
    local i=0 n tok prop user=0 scope=0 mem="" swap=""
    IFS=$'\037' read -r -a toks <<< "$1"
    n=${#toks[@]}
    while [ "$i" -lt "$n" ]; do
        tok="${toks[$i]}"; prop=""
        case "$tok" in
            --) break ;;
            --user) user=1 ;;
            --system) user=0 ;;
            --scope) scope=1 ;;
            -p|--property) i=$((i + 1)); prop="${toks[$i]:-}" ;;
            --property=*) prop="${tok#--property=}" ;;
            -p?*) prop="${tok#-p}" ;;
        esac
        case "$prop" in
            MemoryMax=*) mem="${prop#MemoryMax=}" ;;
            MemorySwapMax=*) swap="${prop#MemorySwapMax=}" ;;
        esac
        i=$((i + 1))
    done
    printf 'user=%s scope=%s MemoryMax=%s MemorySwapMax=%s' "$user" "$scope" "$mem" "$swap"
}

# restart_verdict <журнал systemd-run> — «ok» либо причина отказа.
restart_verdict() {
    local calls n got
    calls="$(restart_calls "$1")"
    n="$(printf '%s' "$calls" | grep -c . || true)"
    if [ "$n" -ne 1 ]; then
        printf 'вызовов systemd-run, перезапускающих хук: %s, ожидался ровно один — журнал: %s' \
            "$n" "$(tr '\037' ' ' < "$1" | tr '\n' ';')"
        return 0
    fi
    got="$(scope_options "$calls")"
    if [ "$got" = "$CAP_WANT" ]; then printf 'ok'
    else printf 'у перезапуска хука опции области [%s], нужно [%s] — вызов: %s' \
        "$got" "$CAP_WANT" "$(printf '%s' "$calls" | tr '\037' ' ')"; fi
}

not_run_block() { printf '%s\n' "$1" | sed -n '/ЗДЕСЬ НЕ ГОНЯЛОСЬ/,/^$/p'; }

# ── ОСЬ 1: КОНТРОЛЬ С ПОТОЛКОМ ──────────────────────────────────────────────
echo "── ось 1: контроль — зелёный модуль, потолок доступен"
current_axis=1
if ! push_case control ok '	_ = t'; then
    axis_unmet 1 "фикстура не собрана"
else
    if [ "$rc" -eq 0 ]; then ok "контроль: отправка зелёного модуля прошла"
    else bad "контроль: отправка отказана (код $rc), хотя модуль зелёный: $(printf '%s' "$out" | tail -5)"; fi

    heavy="$(go_heavy_lines "$b/go.log")"
    n_heavy="$(printf '%s' "$heavy" | grep -c . || true)"
    if [ "$n_heavy" -gt 0 ]; then ok "вызовов go build|vet|test записано: $n_heavy (журнал не пуст)"
    else bad "ни одного вызова go build|vet|test не записано — судить параллелизм не по чему"; fi

    wide=0; unscoped=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$(effective_p "$line")" = 4 ] || wide=$((wide + 1))
        case "$line" in *" scoped=1 "*) ;; *) unscoped=$((unscoped + 1)) ;; esac
    done <<< "$heavy"
    if [ "$n_heavy" -gt 0 ] && [ "$wide" -eq 0 ]; then ok "каждый вызов идёт с параллелизмом 4"
    else bad "вызовов с параллелизмом не 4: $wide из $n_heavy"; fi
    if [ "$n_heavy" -gt 0 ] && [ "$unscoped" -eq 0 ]; then ok "каждый вызов идёт ВНУТРИ потолка памяти"
    else bad "вызовов вне потолка: $unscoped из $n_heavy"; fi

    n_test="$(grep -c '^sub=test ' "$b/go.log" || true)"
    n_race="$(grep '^sub=test ' "$b/go.log" | grep -c -- '-race' || true)"
    if [ "$n_test" -gt 0 ] && [ "$n_race" -eq 0 ]; then ok "go test звался $n_test раз, с -race — ни разу"
    else bad "go test: вызовов $n_test, из них с -race $n_race — детектор гонок гоняется локально"; fi

    if [ -s "$d.lint.log" ]; then bad "хук позвал цель lint — линтер гоняется локально"
    else ok "цель lint хуком не звалась"; fi
    # Положительный контроль журнала: цель достижима и пишет, иначе молчание
    # журнала выше ничего бы не доказывало.
    ( cd "$d" && make -s lint ) >/dev/null 2>&1
    if [ -s "$d.lint.log" ]; then ok "положительный контроль: прямой вызов цели lint пишет журнал"
    else bad "прямой вызов цели lint журнал не пишет — утверждение о молчании слепо"; fi

    block="$(not_run_block "$out")"
    if printf '%s' "$block" | grep -q -- '-race' && printf '%s' "$block" | grep -q 'golangci-lint'; then
        ok "перечень непроверенного называет детектор гонок и линтер"
    else
        bad "перечень непроверенного не называет -race и golangci-lint: $block"
    fi

    verdict="$(restart_verdict "$b/systemd-run.log")"
    if [ "$verdict" = ok ]; then ok "хук перезапущен в области systemd с MemoryMax=10G и MemorySwapMax=0"
    else bad "$verdict"; fi
    axis_done 1
fi

# ── ОСЬ 2: ЗАКОННЫЙ БЛИЗНЕЦ — ПОТОЛОК НЕДОСТУПЕН ────────────────────────────
echo "── ось 2: законный близнец — systemd-run отказывает"
current_axis=2
if ! push_case nocap fail '	_ = t'; then
    axis_unmet 2 "фикстура не собрана"
else
    if [ "$rc" -eq 0 ]; then ok "без потолка отправка проходит тем же исходом, что контроль"
    else bad "без потолка отправка отказана (код $rc): $(printf '%s' "$out" | tail -5)"; fi
    if printf '%s' "$out" | grep -q 'потолок памяти не выставлен'; then ok "отсутствие потолка названо строкой"
    else bad "отсутствие потолка не названо"; fi
    heavy="$(go_heavy_lines "$b/go.log")"
    n_heavy="$(printf '%s' "$heavy" | grep -c . || true)"
    wide=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$(effective_p "$line")" = 4 ] || wide=$((wide + 1))
    done <<< "$heavy"
    if [ "$n_heavy" -gt 0 ] && [ "$wide" -eq 0 ]; then ok "без потолка параллелизм всё равно 4 ($n_heavy вызовов)"
    else bad "без потолка вызовов с параллелизмом не 4: $wide из $n_heavy"; fi
    if [ -s "$d.lint.log" ]; then bad "без потолка хук позвал цель lint"
    else ok "без потолка цель lint не звалась"; fi
    axis_done 2
fi

# ── ОСЬ 3: ИНЪЕКЦИЯ — КРАСНАЯ ПРОБА ПОД ПОТОЛКОМ ────────────────────────────
echo "── ось 3: инъекция — упавшая проба внутри области systemd"
current_axis=3
if ! push_case red ok '	t.Errorf("проба упала внутри потолка")'; then
    axis_unmet 3 "фикстура не собрана"
else
    if [ "$rc" -ne 0 ]; then ok "упавшая проба роняет отправку (код $rc)"
    else bad "упавшая проба под потолком: отправка ПРОШЛА — область проглотила код"; fi
    if printf '%s' "$out" | grep -q 'красные.*пробы'; then ok "красной названа группа проб"
    else bad "отказ пришёл не от группы проб: $(printf '%s' "$out" | tail -5)"; fi
    verdict="$(restart_verdict "$b/systemd-run.log")"
    if [ "$verdict" = ok ]; then ok "красный прогон шёл внутри области systemd"
    else bad "красный прогон шёл мимо области systemd: $verdict"; fi
    axis_done 3
fi

# ── ОСЬ 4: ЗАКОННЫЙ БЛИЗНЕЦ — ВНЕШНИЙ GOFLAGS=-p=32 ─────────────────────────
echo "── ось 4: законный близнец — у отправляющего свой GOFLAGS=-p=32"
current_axis=4
if ! push_case outer ok '	_ = t' '-p=32'; then
    axis_unmet 4 "фикстура не собрана"
elif [ "$(head -n 1 "$b/outer-goflags.log")" != "-p=32" ]; then
    # Предпосылка: внешнее значение ДОШЛО до хука. Иначе близнец не отличается
    # от контроля, и его зелёное ничего не доказывает.
    axis_unmet 4 "внешний GOFLAGS не дошёл до хука: $(head -n 1 "$b/outer-goflags.log")"
else
    if [ "$rc" -eq 0 ]; then ok "с внешним GOFLAGS=-p=32 отправка зелёного модуля прошла"
    else bad "с внешним GOFLAGS=-p=32 отправка отказана (код $rc): $(printf '%s' "$out" | tail -5)"; fi
    heavy="$(go_heavy_lines "$b/go.log")"
    n_heavy="$(printf '%s' "$heavy" | grep -c . || true)"
    wide=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$(effective_p "$line")" = 4 ] || wide=$((wide + 1))
    done <<< "$heavy"
    if [ "$n_heavy" -gt 0 ] && [ "$wide" -eq 0 ]; then ok "внешний -p=32 перекрыт: параллелизм 4 у всех $n_heavy вызовов"
    else bad "внешний -p=32 не перекрыт: вызовов с параллелизмом не 4 — $wide из $n_heavy"; fi
    axis_done 4
fi

# ── ОСЬ 5: СУДЬИ ОПЫТА НА СИНТЕТИКЕ ─────────────────────────────────────────
#
# Судьи осей 1–4 — распознаватели, и слепой распознаватель молчит так же, как
# зелёный. Поэтому каждый проверен здесь на входе, где ответ известен заранее:
# на форме дефекта, который он обязан поймать, и на законном близнеце, который
# он обязан пропустить. Судьи — ТЕ ЖЕ функции, что у осей 1–4, не копии.
echo "── ось 5: судьи опыта на синтетике — дефект пойман, близнец пропущен"
current_axis=5

# p_case <ожидание> <GOFLAGS> <доводы go> <что за случай>
p_case() {
    local got
    got="$(effective_p "sub=test scoped=1 goflags=[$2] args=[$3]")"
    if [ "$got" = "$1" ]; then ok "судья -p: $4 → $got"
    else bad "судья -p: $4 — ожидалось $1, судья назвал «$got» (GOFLAGS=[$2] доводы=[$3])"; fi
}
p_case 4  '-p=4'           'test ./...'                'значение GOFLAGS'
p_case 4  '-p=32 -p=4'     'test ./...'                'в GOFLAGS действует последнее'
p_case 32 '-p=4 -p=32'     'test ./...'                '-p=4 ПЕРЕД чужим -p=32 не перекрывает его'
p_case 32 '-p=4'           'test -p 32 ./...'          'довод перекрывает GOFLAGS'
p_case 32 ''               'test -p 4 -p=32 ./...'     'из доводов действует последний, в любой форме'
p_case 32 ''               'test --p=32 ./...'         'форма --p=N в доводах'
p_case 32 ''               'test --p 32 ./...'         'форма --p N в доводах'
p_case 32 '--p=32'         'test ./...'                'форма --p=N в GOFLAGS'
p_case 32 "-p=4 '-p=32'"   'test ./...'                'поле GOFLAGS в кавычках'
p_case 32 '-p=32'          'test ./... -args -p 4'     'после -args — доводы бинаря проб, не go'

# cap_case <ожидание: ok|отказ> <что за случай> <вызов>... — вызов записан
# доводами через пробел; журнал собирается в той же форме, что пишет переходник.
cap_case() {
    local want="$1" what="$2" log got
    shift 2
    log="$work/synthetic-cap.$checks.log"
    : > "$log"
    for call in "$@"; do printf '%s\n' "$call" | tr ' ' '\037' >> "$log"; done
    got="$(restart_verdict "$log")"
    if { [ "$want" = ok ] && [ "$got" = ok ]; } || { [ "$want" != ok ] && [ "$got" != ok ]; }; then
        if [ "$got" = ok ]; then ok "судья потолка: $what → ok"
        else ok "судья потолка: $what → отказ"; fi
    else
        bad "судья потолка: $what — ожидалось «$want», судья назвал «$got»"
    fi
}
H=/x/scripts/hooks/pre-push
TRIAL='--user --scope --quiet -p MemoryMax=10G -p MemorySwapMax=0 -- true'
cap_case ok    'контроль: пробный вызов и перезапуск с обоими потолками' \
    "$TRIAL" "--user --scope --quiet -p MemoryMax=10G -p MemorySwapMax=0 -- bash $H --kaname-prepush-in-memory-scope"
cap_case ok    'законный близнец: формы --property= и -pЗНАЧЕНИЕ' \
    "$TRIAL" "--user --scope --property=MemorySwapMax=0 -pMemoryMax=10G -- bash $H --kaname-prepush-in-memory-scope"
cap_case отказ 'у перезапуска нет MemorySwapMax=0, у пробного вызова он есть' \
    "$TRIAL" "--user --scope --quiet -p MemoryMax=10G -- bash $H --kaname-prepush-in-memory-scope"
cap_case отказ 'последнее MemoryMax перезапуска — infinity' \
    "$TRIAL" "--user --scope -p MemoryMax=10G -p MemorySwapMax=0 -p MemoryMax=infinity -- bash $H --kaname-prepush-in-memory-scope"
cap_case отказ 'потолки стоят ПОСЛЕ --: это доводы хука, а не области' \
    "$TRIAL" "--user --scope -- bash $H --kaname-prepush-in-memory-scope -p MemoryMax=10G -p MemorySwapMax=0"
axis_done 5

echo
echo "=== prepush-budget-inject: перепись ==="
echo "осей объявлено        : $AXES_DECLARED"
echo "осей ИСПОЛНЕНО        : $axes_executed"
echo "условие не создано    : ${#unmet_reasons[@]}  (в зачёт прохода НЕ идёт)"
for r in ${unmet_reasons[@]+"${unmet_reasons[@]}"}; do echo "  предпосылка не создана: $r"; done
echo "утверждений объявлено : $expected_checks  (по ведомости ИСПОЛНЕННЫХ осей)"
echo "утверждений исполнено : $checks"
echo "из них не сошлось     : $failed"
echo "утверждений вне осей  : $orphan_checks"
for m in ${axis_short[@]+"${axis_short[@]}"}; do echo "  объём разошёлся     : $m"; done

if [ "$checks" -eq 0 ]; then
    echo "БЕСПРЕДМЕТНО: не исполнено ни одного утверждения — это не зелёное." >&2; exit 2
fi
if [ "$failed" -gt 0 ]; then
    echo "ОТКАЗ: хук отправки не держит свой бюджет памяти." >&2; exit 1
fi
if [ "${#unmet_reasons[@]}" -gt 0 ] || [ "$axes_executed" -ne "$AXES_DECLARED" ] \
    || [ "${#axis_short[@]}" -gt 0 ] || [ "$orphan_checks" -gt 0 ] || [ "$checks" -ne "$expected_checks" ]; then
    echo "НЕ ИСПОЛНЯЛОСЬ: объём исполненного разошёлся с ведомостью — вердикта нет." >&2; exit 2
fi
echo "ЗЕЛЁНОЕ: хук не гоняет тяжёлого, параллелизм Go — 4, прогон под потолком памяти, когда он доступен."
