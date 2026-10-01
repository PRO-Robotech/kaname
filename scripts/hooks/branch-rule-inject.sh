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
# девяти воссозданных дефектов — слепой атрибуции, старой формы ветки
# `issue-<N>`, забытой второй формы `<N>-<суть>` (Д59), потерянного T0, хука отправки без стража, обхода проверок,
# поставленного раньше стража, и трёх дефектов ведомости известных нарушений
# (#482): прощение не применено, прощение шире записи, причина не судится, —
# и от каждого требует хотя бы одного провала.
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

# ── НАСТОЯЩИЙ ВХОД (kacho-workspace#861) ─────────────────────────────────────
# Сообщения трёх коммитов, записанных с трейлерами: PRO-Robotech/kacho, ветка
# 2840-trailered-b81c695 (d838c9ce779, 82f0e455536, b81c69568a9); адрес сессии в
# фикстуре заменён. Близнец — то же сообщение без завершающего блока трейлеров,
# выведенный из него же: отличие ровно одно.
cat > "$tmp/real.all" <<'REAL'
#2840 deploy: проба порядка cert-manager исполняема в индексе

TestShebangScriptsAreExecutable на голове 82f0e455536: неисполняемых 1
(проба заведена с режимом 100644, в чистом клоне не запустится). После
git add --chmod=+x: неисполняемых 0 из 337 файлов с shebang.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01fixture
%%
#2840 deploy: состояние релиза cert-manager спрашивается без helm list -a

Живой stack-up на kind (helm v4.2.4) показал: у helm v4 флага -a нет,
и ветка «наш релиз» отказывала бы на каждом повторном подъёме. Проба
этого не видела: подставной helm принимал любой флаг.

Подставные kubectl и helm теперь сперва разбирают флаги настоящим
инструментом (<args> --help) и отказывают его текстом. До правки
рецепта: 10 из 10, находок 2 (Б2, Б3 — unknown shorthand flag 'a');
после: 10 из 10, находок 0.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01fixture
%%
#2840 deploy: stack-up ставит cert-manager тем же местом, что dev-up

Порядок «cert-manager отдельным релизом → его вебхук → продукт» жил
строками внутри dev-up; stack-up применял умбреллу с
cert-manager.enabled=false и релиза не ставил, поэтому на чистом
кластере цепочка упиралась в отсутствие CRD Certificate/Issuer.

Порядок вынесен в цель cert-manager-up (страж guard-declared-context),
её зовут оба пути подъёма раньше продукта. Исходы по владельцу CRD:
нет — ставит; наш той же версии — не переставляет; наш другой версии —
доводит; чужой (a8f60d) — не трогает; не прочитано — отказ.

Проба tests/helm/cert-manager-release-before-product-test.sh: до правки
10 из 10 исполнено, 9 находок; после — 10 из 10, находок 0.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01fixture
REAL
awk -v d="$tmp" '/^%%$/ { n++; next } { print > (d "/real-" (n + 1) ".msg") }' "$tmp/real.all"
REAL_N=0
for m in "$tmp"/real-*.msg; do
    [ -f "$m" ] || continue
    REAL_N=$((REAL_N + 1))
    sed '/^Co-Authored-By:/,$d' "$m" > "${m%.msg}.twin"
done
[ "$REAL_N" = 3 ] || { echo "branch-rule-inject: настоящий вход не разобран ($REAL_N из 3) — предпосылки нет" >&2; exit 2; }
REAL_TRAILER="Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"

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
    "${G[@]}" checkout -q -b 7-lane
    "${G[@]}" checkout -q -b 2840
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
            7 | 7-lane | 2840) "${G[@]}" reset -q --hard "$k" ;;
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
    # Вторая форма имени (Д59): `<N>-<суть>`, N — номер до первого дефиса.
    at 7-lane; run git commit -q --allow-empty -m "#7 правка"
    expect "коммит: «#7 …» на ветке 7-lane" pass - "$rc" "$out"
    at 7-lane; run git commit -q --allow-empty -m "#8 правка"
    expect "коммит: «#8» на ветке 7-lane" refuse "«#8» на ветке «7-lane»" "$rc" "$out"

    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Co-authored-by: Ivan <ivan@example.invalid>"
    expect "коммит: соавтор-человек — запрещён ключ, а не значение (#861)" refuse "атрибуция в сообщении: «Co-authored-by: Ivan <ivan@example.invalid>»" "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Снята строка шаблона Co-authored-by: Ivan <ivan@example.invalid> — подставлялась"
    expect "коммит: ключ Co-Authored-By в середине строки прозы — упоминание" pass - "$rc" "$out"
    at 7; run git commit -q --allow-empty -m "#7 правка" -m "Снята строка шаблона Claude-Session: https://example.invalid/s — подставлялась"
    expect "коммит: ключ Claude-Session в середине строки прозы — упоминание" pass - "$rc" "$out"
    for i in 1 2 3; do
        at 2840; run git commit -q --allow-empty -F "$tmp/real-$i.msg"
        expect "коммит: настоящий вход $i — отказ, названа строка" refuse "атрибуция в сообщении: «$REAL_TRAILER»" "$rc" "$out"
        at 2840; run git commit -q --allow-empty -F "$tmp/real-$i.twin"
        expect "коммит: близнец настоящего входа $i без блока трейлеров" pass - "$rc" "$out"
    done
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
    # Вторая форма имени (Д59) и её близнец вне формы — один факт: регистр и знак.
    "${G[@]}" checkout -q -b 21-lane 20; "${G[@]}" commit -q --allow-empty -m "#21 полоса"
    # Сообщения различны: одинаковое сообщение на той же вершине в ту же секунду
    # дало бы тот же sha, и коммит стал бы общим для двух веток.
    "${G[@]}" checkout -q -b 21_Lane 20; "${G[@]}" commit -q --allow-empty -m "#21 полоса вне формы"
    "${G[@]}" checkout -q -b 23-lane 20; "${G[@]}" commit -q --allow-empty -m "#24 чужой номер на полосе"
    "${G[@]}" checkout -q -b 25 20; "${G[@]}" commit -q --allow-empty --author="Other <other@example.invalid>" -m "#25 чужой автор"
    "${G[@]}" checkout -q -b 26 20; GIT_COMMITTER_EMAIL=other@example.invalid "${G[@]}" commit -q --allow-empty -m "#26 чужой коммиттер"
    # #861: коммиты записаны мимо хука коммита (в этой фикстуре его нет вовсе).
    "${G[@]}" checkout -q -b 2840 20; "${G[@]}" commit -q --allow-empty -F "$tmp/real-1.msg"
    "${G[@]}" checkout -q -b 2840t 20; "${G[@]}" commit -q --allow-empty -F "$tmp/real-1.twin"
    "${G[@]}" checkout -q -b 27 20; "${G[@]}" commit -q --allow-empty -m "#27 задача" -m "Co-authored-by: Ivan <ivan@example.invalid>"
    "${G[@]}" checkout -q -b 28 20; "${G[@]}" commit -q --allow-empty -m "#28 задача" -m "Снята строка шаблона Co-authored-by: Ivan <ivan@example.invalid> — подставлялась"
    "${G[@]}" checkout -q -b old-feature main
    "${G[@]}" commit -q --allow-empty --date="$PRE" -m "старая работа"
    "${G[@]}" commit -q --allow-empty -m "#33 доводка"
    "${G[@]}" checkout -q -b old-trailer main
    "${G[@]}" commit -q --allow-empty --date="$PRE" -m "старая работа" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
    ledger_fixture
    "${G[@]}" checkout -q main
    "${G[@]}" fetch -q origin
    equip "$PP" "$1"
}

# ── Ведомость известных нарушений (#482): НАСТОЯЩИЙ ВХОД ─────────────────────
# Серверное слияние запроса площадкой: коммиттер — она, тема — заголовок
# запроса, форма — у PRO-Robotech/kaname f2c8696bfa81 («#406 приёмка
# client-revoke в волну 366»), номера — фикстуры (задача 41, волна 20). У него
# два нарушения, как у настоящего: форма слияния и чужой номер на ветке-номере.
#
# Близнецы отличаются от записанного ОДНИМ фактом:
#   LV_TWIN  — то же сообщение, та же форма, тот же коммиттер, другой момент,
#              значит другой sha;
#   LV_OTHER — серверное слияние другой задачи, другой sha;
#   LV_ATTR  — записанная форма плюс трейлер атрибуции.
# Время — после T0 (коммит правила выше), разное у каждого: одинаковое дало бы
# один и тот же sha.
LV_SERVER=(GIT_COMMITTER_NAME=GitHub GIT_COMMITTER_EMAIL=noreply@github.com)
ledger_fixture() {
    local G=(git -C "$PP")
    local now
    now="$(date +%s)"
    LV_T_KNOWN=$((now + 100)) LV_T_TWIN=$((now + 200)) LV_T_OTHER=$((now + 300)) LV_T_ATTR=$((now + 400))
    "${G[@]}" checkout -q -b 41 20; "${G[@]}" commit -q --allow-empty -m "#41 приёмка client-revoke"
    "${G[@]}" checkout -q -b 42 20; "${G[@]}" commit -q --allow-empty -m "#42 приёмка другого"
    "${G[@]}" checkout -q -b 40k 20
    env "${LV_SERVER[@]}" GIT_AUTHOR_DATE="@$LV_T_KNOWN" GIT_COMMITTER_DATE="@$LV_T_KNOWN" \
        "${G[@]}" merge -q --no-ff 41 -m "#41 приёмка client-revoke в волну 20"
    "${G[@]}" checkout -q -b 40t 20
    env "${LV_SERVER[@]}" GIT_AUTHOR_DATE="@$LV_T_TWIN" GIT_COMMITTER_DATE="@$LV_T_TWIN" \
        "${G[@]}" merge -q --no-ff 41 -m "#41 приёмка client-revoke в волну 20"
    "${G[@]}" checkout -q -b 40o 20
    env "${LV_SERVER[@]}" GIT_AUTHOR_DATE="@$LV_T_OTHER" GIT_COMMITTER_DATE="@$LV_T_OTHER" \
        "${G[@]}" merge -q --no-ff 42 -m "#42 приёмка другого в волну 20"
    "${G[@]}" checkout -q -b 40a 20
    env "${LV_SERVER[@]}" GIT_AUTHOR_DATE="@$LV_T_ATTR" GIT_COMMITTER_DATE="@$LV_T_ATTR" \
        "${G[@]}" merge -q --no-ff 41 -m "#41 приёмка client-revoke в волну 20" -m "Co-authored-by: Ivan <ivan@example.invalid>"
    LV_KNOWN="$("${G[@]}" rev-parse 40k)" LV_TWIN="$("${G[@]}" rev-parse 40t)"
    LV_OTHER="$("${G[@]}" rev-parse 40o)" LV_ATTR="$("${G[@]}" rev-parse 40a)"
    LV_LAWFUL="$("${G[@]}" rev-parse 20m)"
}

# lv_row <sha> <день> <задача> <причина> — строка ведомости (поля через TAB).
lv_row() { printf '%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4"; }
lv_day() { date -u -d "@$1" +%F; }

# lv_ledger [строка…] — ведомость фикстуры; без строк — файла нет вовсе.
LV_FILE_REL=.github/scripts/pr-rule-known-violations.tsv
lv_ledger() {
    rm -f "$PP/$LV_FILE_REL"
    [ "$#" -gt 0 ] || return 0
    printf '# ведомость фикстуры\n' > "$PP/$LV_FILE_REL"
    local r
    for r in "$@"; do
        [ -n "$r" ] && printf '%s\n' "$r" >> "$PP/$LV_FILE_REL"
    done
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
    rule_run "$(line 21-lane)"
    expect "отправка: новая ветка 21-lane — вторая форма имени" pass - "$rc" "$out"
    rule_run "$(line 21_Lane)"
    expect "отправка: новая ветка 21_Lane — вне обеих форм" refuse "новая ветка называется номером" "$rc" "$out"
    rule_run "$(line 23-lane)"
    expect "отправка: «#24» на ветке 23-lane" refuse "«#24» на ветке «23-lane»" "$rc" "$out"
    rule_run "$(line 25)"
    expect "отправка: автор не корневой" refuse "автор «Other" "$rc" "$out"
    rule_run "$(line 26)"
    expect "отправка: коммиттер не корневой" refuse "коммиттер «probe <other@example.invalid>»" "$rc" "$out"
    rule_run "$(line old-feature)"
    expect "отправка: ветка до правила — имя не судится" pass - "$rc" "$out"
    rule_run "$(line 2840)"
    expect "отправка: настоящий вход мимо хука коммита — назван sha" refuse "$(git -C "$PP" rev-parse --short=10 2840) атрибуция в сообщении: «$REAL_TRAILER»" "$rc" "$out"
    rule_run "$(line 2840t 2840)"
    expect "отправка: близнец настоящего входа без блока трейлеров" pass - "$rc" "$out"
    rule_run "$(line 27)"
    expect "отправка: соавтор-человек — назван sha (#861)" refuse "$(git -C "$PP" rev-parse --short=10 27) атрибуция в сообщении: «Co-authored-by: Ivan <ivan@example.invalid>»" "$rc" "$out"
    rule_run "$(line 28)"
    expect "отправка: ключ в середине строки прозы — упоминание" pass - "$rc" "$out"
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
    expect "запрос: соавтор-человек в теле — запрещён ключ (#861)" refuse "тело: атрибуция" "$rc" "$out"
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
    pr_run 21-lane origin/20 21-lane "#21 полоса" "обычное тело"
    expect "запрос: голова 21-lane — вторая форма имени" pass - "$rc" "$out"
    pr_run 21-lane origin/20 21-lane "#22 полоса" "обычное тело"
    expect "запрос: заголовок «#22» у головы 21-lane" refuse "заголовок «#22» у головы «21-lane»" "$rc" "$out"
    pr_run 21_Lane origin/20 21_Lane "#21 полоса вне формы" "обычное тело"
    expect "запрос: голова 21_Lane — вне обеих форм" refuse "голова «21_Lane»: ветка называется номером" "$rc" "$out"
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

# expect_text <метка> <текст> <вывод> — вывод НАЗЫВАЕТ предмет, а не только краснеет.
expect_text() {
    if [[ "$3" == *"$2"* ]]; then ok "$1"
    else fail "$1: в выводе нет «$2»: $(printf '%s' "$3" | tr '\n' '|' | cut -c1-300)"; fi
}

# ── Ведомость известных нарушений на запросе (#482) ──────────────────────────
# Прощение — ровно полный sha из записи. Контроль: без записи записанный коммит
# красный тем же текстом, что и настоящий f2c8696bfa. Дальше каждое утверждение
# меняет один факт: коммит (близнец, чужое серверное слияние, атрибуция) либо
# запись (без причины, префикс, чужой день, нет в клоне, повтор, поля, задача,
# прощать нечего).
ledger_cases() {
    local why="серверное слияние запроса площадкой, тема из заголовка"
    local dk; dk="$(lv_day "$LV_T_KNOWN")"
    local W=(20 origin/main)

    lv_ledger
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: записи нет — записанный коммит красный (контроль)" refuse "${LV_KNOWN:0:10} слияние не по форме" "$rc" "$out"
    expect_text "ведомость: записи нет — второе нарушение того же коммита" "${LV_KNOWN:0:10} «#41» на ветке «20»" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "$why")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: записанный полный sha проходит" pass - "$rc" "$out"
    expect_text "ведомость: прощённое названо полным sha, а не умолчано" "прощено ведомостью: $LV_KNOWN" "$out"
    expect_text "ведомость: прощённое названо поимённо" "${LV_KNOWN:0:10} «#41» на ветке «20»" "$out"

    pr_run "${W[@]}" 40t "#20 волна" "обычное тело"
    expect "ведомость: тот же текст и форма, другой sha — красный" refuse "${LV_TWIN:0:10} слияние не по форме" "$rc" "$out"
    pr_run "${W[@]}" 40o "#20 волна" "обычное тело"
    expect "ведомость: серверное слияние с другим sha — красное" refuse "${LV_OTHER:0:10} слияние не по форме" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_ATTR" "$(lv_day "$LV_T_ATTR")" "#482" "$why")"
    pr_run "${W[@]}" 40a "#20 волна" "обычное тело"
    expect "ведомость: атрибуцию запись не прощает" refuse "${LV_ATTR:0:10} атрибуция в сообщении" "$rc" "$out"
    expect_text "ведомость: форма того же коммита прощена" "прощено ведомостью: $LV_ATTR" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: запись без причины — красная" refuse "причина пуста" "$rc" "$out"
    expect_text "ведомость: запись без причины ничего не прощает" "${LV_KNOWN:0:10} слияние не по форме" "$out"
    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "   ")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: причина из пробелов — красная" refuse "причина пуста" "$rc" "$out"

    lv_ledger "$(lv_row "${LV_KNOWN:0:10}" "$dk" "#482" "$why")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: префикс sha — красный" refuse "не полный" "$rc" "$out"
    expect_text "ведомость: префикс ничего не прощает" "${LV_KNOWN:0:10} слияние не по форме" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "2001-01-01" "#482" "$why")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: день не коммита — красный" refuse "не день коммита" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "задача" "$why")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: задача не по форме — красная" refuse "задача «задача»" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "$why")"$'\t'"лишнее"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: пятое поле — красное" refuse "полей 5" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "$why")" "$(lv_row "$LV_KNOWN" "$dk" "#482" "$why")"
    pr_run "${W[@]}" 40k "#20 волна" "обычное тело"
    expect "ведомость: повтор записи — красный" refuse "записан повторно" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_LAWFUL" "$(lv_day "$(git -C "$PP" show -s --format=%ct 20m)")" "#482" "$why")"
    pr_run "${W[@]}" 20m "#20 волна" "обычное тело"
    expect "ведомость: запись в диапазоне ничего не прощает — красная" refuse "ничего не прощает" "$rc" "$out"

    lv_ledger "$(lv_row 0123456789abcdef0123456789abcdef01234567 "$dk" "#482" "$why")"
    pr_run 21 origin/20 21 "#21 задача" "обычное тело"
    expect "ведомость: коммита записи в клоне нет — красная и вне диапазона" refuse "в клоне нет" "$rc" "$out"

    lv_ledger "$(lv_row "$LV_KNOWN" "$dk" "#482" "$why")"
    pr_run 21 origin/20 21 "#21 задача" "обычное тело"
    expect "ведомость: запись вне диапазона молчит" pass - "$rc" "$out"
    lv_ledger ""
    pr_run 21 origin/20 21 "#21 задача" "обычное тело"
    expect "ведомость: пустая ведомость — законный запрос проходит" pass - "$rc" "$out"
    lv_ledger
}

suite() { # $1 — набор, $2 — метка
    TAG="$2"; FAILS=0; CASES=0
    commit_msg_cases "$1"
    push_fixture "$1"
    push_rule_cases
    pr_cases
    ledger_cases
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
        # Вторая форма `<N>-<суть>` забыта: предикат знает только цифры (до Д59).
        suffix) printf '\nbranch_rule_is_number() { [[ "$1" =~ ^[0-9]+$ ]]; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        t0)     printf '\nbranch_rule_t0() { printf 0; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        noguard) sed -i 's|^rule_out="$(bash "$rule_guard".*$|rule_out=""; true|' "$k/scripts/hooks/pre-push"
                grep -q '^rule_out=""; true$' "$k/scripts/hooks/pre-push" || return 1 ;;
        # Обход проверок, поставленный ДО стража, снял бы и страж.
        skipfirst) sed -i '0,/^set -uo pipefail$/s//set -uo pipefail\n[ "${KANAME_SKIP_PREPUSH:-0}" = 1 ] \&\& exit 0/' "$k/scripts/hooks/pre-push"
                grep -q '^\[ "${KANAME_SKIP_PREPUSH:-0}" = 1 \] && exit 0$' "$k/scripts/hooks/pre-push" || return 1 ;;
        # Ведомость (#482): запись прочитана, но прощение не применено.
        ledgerblind) sed -i 's|^BR_EXEMPT="$exempt"$|BR_EXEMPT=""|' "$k/.github/scripts/pr-rule-check.sh"
                grep -q '^BR_EXEMPT=""$' "$k/.github/scripts/pr-rule-check.sh" || return 1 ;;
        # Прощение шире записи: непустая ведомость прощает любой коммит.
        ledgerwide) printf '\nbranch_rule_exempt() { [ -n "$BR_EXEMPT" ]; }\n' >> "$k/scripts/hooks/branch-rule.sh" ;;
        # Причина записи не судится.
        ledgerloose) grep -q 'причина пуста' "$k/.github/scripts/pr-rule-check.sh" || return 1
                sed -i '/причина пуста/d' "$k/.github/scripts/pr-rule-check.sh"
                ! grep -q 'причина пуста' "$k/.github/scripts/pr-rule-check.sh" || return 1 ;;
    esac
}

echo "── проба против настоящей оснастки (ждём ноль провалов)"
suite "$tmp/kit-real" настоящий
read -r real_fails real_cases < "$tmp/result.настоящий"

declare -A dfails
for d in blind issue suffix t0 noguard skipfirst ledgerblind ledgerwide ledgerloose; do
    if defect "$d"; then
        echo
        echo "── проба против дефекта «$d» (ждём хотя бы один провал)"
        suite "$tmp/kit-$d" "дефект-$d" > "$tmp/out.$d"
        read -r dfails[$d] _ < "$tmp/result.дефект-$d"
        grep -c '^  FAIL' "$tmp/out.$d" | sed 's/^/   провалов: /'
        # Какие утверждения дефект уронил — чтобы красное было видно ПО ПРЕДМЕТУ.
        LC_ALL=C sed -n -E 's/^  FAIL \[[^]]*\] (.*): (законный случай отвергнут|ждали|в выводе нет) .*/     · \1/p' "$tmp/out.$d"
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
for d in blind issue suffix t0 noguard skipfirst ledgerblind ledgerwide ledgerloose; do
    printf '  дефект %-11s провалов %s (норма ≥1)\n' "$d" "${dfails[$d]}"
    if [ "${dfails[$d]}" = "н/д" ]; then
        echo "ОТКАЗ: дефект «$d» не воссоздан — форма оснастки изменилась" >&2; rc=1
    elif [ "${dfails[$d]}" -lt 1 ]; then
        echo "ОТКАЗ: проба ЗЕЛЁНАЯ на дефекте «$d» — она не держит свой предмет" >&2; rc=1
    fi
done
exit "$rc"
