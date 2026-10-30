#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-edge.sh — сверки, которым нужен ВТОРОЙ операнд из дерева платформы:
# каталог прав против копии края и канон модели доступов против манифестов
# остальных модулей. Зовёт хук отправки (scripts/hooks/pre-push) группой
# «сверка с краем», когда рядом лежит клон PRO-Robotech/kacho.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЗАЧЕМ (kaname#822)
#
# До этого файла хук печатал в перечне непроверенного «каталог прав и канон
# модели (нужен чекаут дерева платформы)» и не гонял их НИКОГДА — даже там, где
# клон платформы лежал рядом. Красное задания конвейера «каталог прав — копия
# сходится с копией края» на kaname#817 пришло только из конвейера.
#
# ─────────────────────────────────────────────────────────────────────────────
# ТЕ ЖЕ КОМАНДЫ, ЧТО У КОНВЕЙЕРА — И ГДЕ ОНИ РАСХОДЯТСЯ
#
# Задания `catalogparity` и `authzartifacts` (.github/workflows/ci.yml) создают
# операнд ВЫБОРКОЙ головы `PRO-Robotech/kacho`. Здесь операнд строится из
# `origin/main` соседнего клона, предварительно освежённого `git fetch origin
# main` (не дольше FETCH_TIMEOUT секунд): клон, простоявший неделю, иначе судил
# бы о стволе недельной давности (замер 2026-10-14: клон kaname стоял на одной
# ревизии с 10-03 по 10-14). Не удался fetch — сверка идёт на прежней ревизии,
# а несвежесть названа строкой оси (`--axis-file`), а не умолчана.
#
# Операнд — `git archive` ревизии, а не рабочая копия клона: незакоммиченное в
# клоне платформы о стволе ничего не говорит. Пути — те же, что у выборок
# конвейера; манифест ЭТОГО модуля достраивается в `services/iam/` и
# вносится в индекс операнда, как у действия `.github/actions/platform-tree`.
# Операнд лежит ПОД корнем дерева (`prepush-edge-operand.*`, снимается на выходе): цель
# `model-canon-check` выборку вне корня отвергает.
#
# Команды и разбор исхода — дословно те, что у конвейера:
#   make check-permission-catalog EDGE_TREE=…   (находка либо «условие не создано» — по тексту)
#   tools/module-manifest-check.sh              (напрямую: make схлопнул бы коды 1·2·3)
#   go test -count=1 -short <пять пакетов>      (PLATFORM_TREE=…)
#   .github/scripts/classify-canon-outcome.sh --self-test
#   make model-canon-check PLATFORM_TREE=…      (исход — classify-canon-outcome.sh)
# Строже конвейера в двух местах: «условие не создано» у сверки канона и
# любой ненулевой исход формы манифестов конвейер пропускает кодом 0 (у второго
# make схлопывает находку в ту же двойку, что «проверять нечего»), здесь это
# третий исход (код 3) либо красное, а не зелёное.
#
# ─────────────────────────────────────────────────────────────────────────────
# ВЫЗОВ И ИСХОДЫ
#
#   prepush-edge.sh --locate
#       печатает путь клона платформы и выходит 0; клона нет — перечень
#       осмотренных мест и код 4. Порядок поиска: KACHO_MONOREPO (названный —
#       принимается без проверки, судит его второй вызов) · `<корень>/../kacho` ·
#       `<основной клон>/../kacho` (для рабочей копии `git worktree`, лежащей
#       вдали от основного клона). Кандидат без ручки засчитывается, только если
#       это рабочая копия git с `origin` на PRO-Robotech/kacho.
#   prepush-edge.sh [--axis-file <файл>] <клон>
#       0 — все сверки зелёные · 1 — хотя бы одна красная · 3 — условие не
#       создано (клон негоден, ревизии нет, операнд не построен, сверка не
#       исполнялась), красных нет · 2 — довод вызова негоден.
#
# Опыт — scripts/hooks/prepush-edge-inject.sh.
set -uo pipefail

FETCH_TIMEOUT="${PREPUSH_EDGE_FETCH_TIMEOUT:-60}"
UNMET=3
MARK='УСЛОВИЕ НЕ СОЗДАНО'

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "prepush-edge: $MARK — корень рабочей копии не установлен"; exit "$UNMET"; }

is_kacho_clone() {
    local url
    git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
    url="$(git -C "$1" config --get remote.origin.url 2>/dev/null)" || return 1
    case "$url" in
        *[/:]PRO-Robotech/kacho|*[/:]PRO-Robotech/kacho.git) return 0 ;;
    esac
    return 1
}

locate() {
    local common main cand looked=()
    if [ -n "${KACHO_MONOREPO:-}" ]; then
        printf '%s\n' "$KACHO_MONOREPO"
        return 0
    fi
    common="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || common=""
    main=""
    [ -n "$common" ] && main="$(dirname "$common")"
    for cand in "$ROOT/../kacho" ${main:+"$main/../kacho"}; do
        looked+=("$cand")
        if [ -d "$cand" ] && is_kacho_clone "$cand"; then
            ( cd "$cand" && pwd -P )
            return 0
        fi
    done
    echo "клона PRO-Robotech/kacho нет: KACHO_MONOREPO не задан; осмотрено: ${looked[*]}"
    return 4
}

if [ "${1:-}" = --locate ]; then
    locate
    exit $?
fi

axis_file=""
if [ "${1:-}" = --axis-file ]; then
    [ "$#" -ge 2 ] || { echo "prepush-edge: --axis-file без значения" >&2; exit 2; }
    axis_file="$2"; shift 2
fi
[ "$#" -eq 1 ] || { echo "prepush-edge: ожидался один довод — путь клона платформы" >&2; exit 2; }
clone="$1"

axis() {
    echo "ОСЬ НЕ СПРОШЕНА: $1"
    [ -z "$axis_file" ] || printf '%s\n' "$1" >> "$axis_file"
}

if ! is_kacho_clone "$clone"; then
    echo "$MARK: «$clone» — не рабочая копия git с origin на PRO-Robotech/kacho; сверки НЕ исполнялись"
    exit "$UNMET"
fi

# ── СВЕЖЕСТЬ СТВОЛА ПЛАТФОРМЫ ───────────────────────────────────────────────
before="$(git -C "$clone" rev-parse -q --verify 'refs/remotes/origin/main^{commit}' 2>/dev/null)" || before=""
frc=0
GIT_TERMINAL_PROMPT=0 timeout "$FETCH_TIMEOUT" git -C "$clone" fetch -q origin main >/dev/null 2>&1 || frc=$?
rev="$(git -C "$clone" rev-parse -q --verify 'refs/remotes/origin/main^{commit}' 2>/dev/null)" || rev=""
if [ -z "$rev" ]; then
    echo "$MARK: у клона «$clone» нет origin/main (fetch: код $frc) — сверки НЕ исполнялись"
    exit "$UNMET"
fi
when="$(git -C "$clone" log -1 --format=%cI origin/main 2>/dev/null)"
if [ "$frc" -ne 0 ]; then
    axis "свежесть ствола платформы: git fetch origin main не удался (код $frc, предел ${FETCH_TIMEOUT} с) — судится прежний origin/main от $when"
    fetched="fetch НЕ удался"
elif [ "$before" = "$rev" ]; then
    fetched="fetch: ствол не сдвинулся"
else
    fetched="fetch: ${before:0:12} → ${rev:0:12}"
fi
echo "kacho: $clone @ ${rev:0:12} (origin/main от $when; $fetched)"

# ── ОПЕРАНДЫ ────────────────────────────────────────────────────────────────
# Не под скрытым каталогом: обход манифестов скрытые каталоги пропускает.
op="$(mktemp -d "$ROOT/prepush-edge-operand.XXXXXX")" || { echo "$MARK: каталог операнда не создан"; exit "$UNMET"; }
trap 'rm -rf "$op"' EXIT
mkdir -p "$op/edge" "$op/platform"
if ! git -C "$clone" archive "$rev" -- gateway/internal/middleware/embed | tar -x -C "$op/edge"; then
    echo "$MARK: копия края не выбрана из $clone@${rev:0:12} — сверки НЕ исполнялись"
    exit "$UNMET"
fi
if ! git -C "$clone" archive "$rev" -- ':(glob)services/*/manifest.yaml' deploy/stacks.txt deploy/helm/umbrella \
        | tar -x -C "$op/platform"; then
    echo "$MARK: дерево платформы не выбрано из $clone@${rev:0:12} — сверки НЕ исполнялись"
    exit "$UNMET"
fi
mkdir -p "$op/platform/services/iam"
if ! { cp "$ROOT/manifest.yaml" "$op/platform/services/iam/manifest.yaml" \
        && git -C "$op/platform" init -q . && git -C "$op/platform" add -A; }; then
    echo "$MARK: операнд канона не достроен манифестом модуля — сверки НЕ исполнялись"
    exit "$UNMET"
fi
echo "манифестов в операнде: $(git -C "$op/platform" ls-files 'services/*/manifest.yaml' | wc -l)"

red=0
unmet=0
log="$op/step.log"

# ── 1. КАТАЛОГ ПРАВ — КОПИЯ СХОДИТСЯ С КОПИЕЙ КРАЯ ──────────────────────────
rc=0
make check-permission-catalog EDGE_TREE="$op/edge" > "$log" 2>&1 || rc=$?
cat "$log"
if [ "$rc" -eq 0 ]; then
    echo "→ каталог прав: копии сходятся"
elif grep -q "$MARK" "$log"; then
    unmet=$((unmet + 1)); echo "→ каталог прав: $MARK — сверка не исполнялась"
else
    red=$((red + 1)); echo "→ каталог прав: КРАСНОЕ — вид и адресат названы строкой «НАХОДКА: …» выше"
fi

# ── 2. ФОРМА МАНИФЕСТОВ МОДУЛЕЙ ──────────────────────────────────────────
# Исполнитель зовётся НАПРЯМУЮ, а не целью make: make схлопывает его коды
# 1 (находка) · 2 (проверять нечего) · 3 (не исполнялась) в свою двойку.
rc=0
bash tools/module-manifest-check.sh || rc=$?
case "$rc" in
    0) echo "→ форма манифестов: годно" ;;
    2|3) unmet=$((unmet + 1)); echo "→ форма манифестов: $MARK — исполнитель вышел $rc (2 — проверять нечего, 3 — не исполнялась)" ;;
    *) red=$((red + 1)); echo "→ форма манифестов: КРАСНОЕ (код $rc) — названы файл, поле и строка" ;;
esac

# ── 3. ПРОБЫ, СУДЯЩИЕ МАНИФЕСТЫ ВСЕГО НАБОРА МОДУЛЕЙ ────────────────────────
rc=0
PLATFORM_TREE="$op/platform" go test -count=1 -short \
    ./internal/authzmapgen/ \
    ./internal/modelcompose/ \
    ./internal/manifest/... \
    ./internal/apps/kaname/modulecatalog/ \
    ./tools/ || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "→ платформенные артефакты: пробы зелёные"
else
    red=$((red + 1)); echo "→ платформенные артефакты: КРАСНОЕ — вывод выше называет пробу"
fi

# ── 4. РАЗБОР ИСХОДА КАНОНА — САМОПРОВЕРКА ДО ВЕРДИКТА ──────────────────────
rc=0
.github/scripts/classify-canon-outcome.sh --self-test || rc=$?
if [ "$rc" -ne 0 ]; then
    red=$((red + 1)); echo "→ разбор исхода канона: самопроверка КРАСНАЯ (код $rc)"
fi

# ── 5. КАНОН МОДЕЛИ ДОСТУПОВ ────────────────────────────────────────────────
rc=0
make model-canon-check PLATFORM_TREE="$op/platform" > "$log" 2>&1 || rc=$?
cat "$log"
crc=0
.github/scripts/classify-canon-outcome.sh "$rc" "$log" || crc=$?
if [ "$crc" -eq 1 ] || [ "$crc" -ge 2 ]; then
    red=$((red + 1)); echo "→ канон модели: КРАСНОЕ (разбор $crc)"
elif [ "$rc" -ne 0 ]; then
    unmet=$((unmet + 1)); echo "→ канон модели: $MARK — сверка не исполнялась (конвейер это пропускает, здесь — третий исход)"
else
    echo "→ канон модели: блоки сверены"
fi

echo "сверка с краем: kacho @ ${rev:0:12} · красных $red · без условия $unmet"
[ "$red" -eq 0 ] || exit 1
[ "$unmet" -eq 0 ] || exit "$UNMET"
exit 0
