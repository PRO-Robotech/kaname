#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# install-inject.sh — доказательство ИНЪЕКЦИЕЙ, что провязка хука способна
# отказать, и что отказывает она ровно на своём предмете.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЗАЧЕМ ЭТОТ ФАЙЛ
#
# Предмет починки — механизм отправки, и он обладает свойством, которое делает
# его особенно опасным: НЕИСПРАВНЫЙ он молчит ровно так же, как исправный.
# Переходник `v1` находил отсутствие адресата, печатал одну строку и выходил
# нулём; отличить это от зелёного прогона по исходу `git push` было нечем, и
# оттого ни одна ветка этого репозитория ни разу не была проверена локально.
#
# Значит утверждение «теперь отказывает» обязано быть ДОКАЗАНО опытом, а не
# прочтением кода. Здесь оно доказывается в обе стороны: дефект — отказ с
# названной причиной, законный близнец той же формы — молчание и проход.
#
# ─────────────────────────────────────────────────────────────────────────────
# ЧТО ЗДЕСЬ НЕ ДЕЛАЕТСЯ
#
# Ни один опыт не трогает ни этот клон, ни его `.git/hooks`. Всё происходит в
# синтетическом репозитории во временном каталоге, и перед его заведением
# проверяется, что каталог не лежит ВНУТРИ чужого дерева: клон внутри чужого
# репозитория получает при обходе вверх чужой индекс, и опыт судил бы не то, что
# объявляет (тот же класс, что закрывает tools/standalonetargets).
#
# Адресатом в опытах служит ПОДСТАВНОЙ скрипт, а не боевой `scripts/hooks/pre-push`:
# предмет здесь — поведение ПЕРЕХОДНИКА (дошёл · отказал), а не содержание
# проверок. Что боевой адресат существует и отслеживается — отдельная ось ниже,
# и она спрашивает индекс git, а не диск.
#
# Прогон: `bash scripts/hooks/install-inject.sh` (или с `--self-test` — тем же).
set -uo pipefail

case "${1:-}" in
    ""|--self-test) ;;
    *) echo "install-inject: неизвестный довод «$1» (без доводов либо --self-test)" >&2; exit 2 ;;
esac

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "install-inject: НЕ ИСПОЛНЯЛОСЬ — это не рабочая копия git" >&2
    exit 2
}
INSTALL="$ROOT/scripts/hooks/install.sh"
[ -f "$INSTALL" ] || {
    echo "install-inject: НЕ ИСПОЛНЯЛОСЬ — не найден $INSTALL" >&2
    exit 2
}

checks=0
failed=0
ok()  { checks=$((checks + 1)); echo "  ok   — $1"; }
bad() { checks=$((checks + 1)); failed=$((failed + 1)); echo "  БЕДА — $1" >&2; }

# ── Фикстура ────────────────────────────────────────────────────────────────

work="$(mktemp -d)" || { echo "install-inject: НЕ ИСПОЛНЯЛОСЬ — нет временного каталога" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT

# Предпосылка фикстуры, проверяемая, а не подразумеваемая.
probe_dir="$work"
while :; do
    if [ -e "$probe_dir/.git" ]; then
        echo "install-inject: НЕ ИСПОЛНЯЛОСЬ — временный каталог лежит внутри репозитория ($probe_dir/.git)." >&2
        echo "  Фикстура получила бы при обходе вверх ЧУЖОЙ индекс, и опыт судил бы не свой предмет." >&2
        echo "  Назовите TMPDIR вне всякого репозитория." >&2
        exit 2
    fi
    parent="$(dirname "$probe_dir")"
    [ "$parent" != "$probe_dir" ] || break
    probe_dir="$parent"
done

# new_clone <каталог> — синтетическая рабочая копия с отслеживаемым хуком
# `scripts/hooks/pre-push` и своим удалённым назначением.
#
# Адресат ПОДСТАВНОЙ и устроен так, что его исполнение НАБЛЮДАЕМО: он оставляет
# файл-отметку. Без отметки «переходник дошёл» доказывалось бы кодом 0, который
# в точности и означал прежний молчаливый пропуск.
new_clone() {
    local d="$1"
    mkdir -p "$d/scripts/hooks" || return 1
    cat > "$d/scripts/hooks/pre-push" <<'STAND'
#!/usr/bin/env bash
set -uo pipefail
top="$(git rev-parse --show-toplevel)"
cat > "$top/.stand-in-stdin"
printf 'исполнен\n' > "$top/.stand-in-ran"
exit "${STAND_IN_RC:-0}"
STAND
    chmod +x "$d/scripts/hooks/pre-push"
    printf 'модуль опыта\n' > "$d/README"
    git -C "$d" init -q . || return 1
    git -C "$d" -c user.email=probe@example.invalid -c user.name=probe add -A || return 1
    git -C "$d" -c user.email=probe@example.invalid -c user.name=probe commit -q -m "фикстура опыта" || return 1
    git init --bare -q "$d.git" || return 1
    git -C "$d" remote add origin "$d.git" || return 1
}

# push_probe <каталог> — отправка в своё назначение; печатает код возврата.
push_probe() {
    local d="$1" out rc
    out="$(git -C "$d" push origin HEAD:refs/heads/probe-$RANDOM 2>&1)"
    rc=$?
    printf '%s\n' "$out"
    return "$rc"
}

echo "── ось 1: БОЕВОЙ АДРЕСАТ СУЩЕСТВУЕТ И ОТСЛЕЖИВАЕТСЯ (спрашиваем индекс, не диск)"
tracked="$(git -C "$ROOT" ls-files -s scripts/hooks/pre-push)"
if [ -z "$tracked" ]; then
    bad "scripts/hooks/pre-push не отслеживается: переходник поедет в клоны к адресату, которого нет"
else
    ok "scripts/hooks/pre-push отслеживается: $tracked"
    case "$tracked" in
        100755\ *) ok "он отслеживается ИСПОЛНЯЕМЫМ — иначе переходник не позвал бы его и у свежего клона" ;;
        *) bad "он отслеживается НЕ исполняемым: свежий клон получил бы адресата, которого переходник не позовёт" ;;
    esac
fi

echo "── ось 2: ПЕРЕХОДНИК ДОХОДИТ ДО АДРЕСАТА И ПРОПУСКАЕТ ЗЕЛЁНУЮ ОТПРАВКУ"
c="$work/reach"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 2 НЕ ИСПОЛНЯЛАСЬ"
else
    # install.sh берёт корень у git, поэтому зовётся ИЗ фикстуры — и только оттуда:
    # тот же вызов из этого клона писал бы в ЕГО служебный каталог.
    ( cd "$c" && bash "$INSTALL" install ) > "$c/.install.log" 2>&1
    if [ ! -x "$c/.git/hooks/pre-push" ]; then
        bad "переходник не положен либо не исполняемый — git его не позовёт"
    else
        ok "переходник положен и исполняемый"
        if out="$(push_probe "$c")"; then
            ok "отправка при зелёном адресате ПРОШЛА (код 0)"
        else
            bad "отправка при зелёном адресате отказала: $out"
        fi
        if [ -f "$c/.stand-in-ran" ]; then
            ok "адресат ИСПОЛНЕН — отметка на месте (код 0 сам по себе этого не доказывает)"
        else
            bad "адресат НЕ исполнялся, а отправка прошла — это ровно прежний молчаливый пропуск"
        fi
        if [ -s "$c/.stand-in-stdin" ]; then
            ok "переходник передал адресату вход git: $(wc -l < "$c/.stand-in-stdin") строк(и) ссылок"
        else
            bad "адресат получил пустой вход — «что уезжает» ему не досталось"
        fi
    fi
fi

echo "── ось 3: ИНЪЕКЦИЯ — АДРЕСАТА НЕТ, ОТПРАВКА ОБЯЗАНА ОТКАЗАТЬ"
c="$work/gone"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 3 НЕ ИСПОЛНЯЛАСЬ"
else
    ( cd "$c" && bash "$INSTALL" install ) > "$c/.install.log" 2>&1
    rm -f "$c/scripts/hooks/pre-push"
    if out="$(push_probe "$c")"; then
        bad "адресата НЕТ, а отправка ПРОШЛА — молчаливый пропуск жив: $out"
    else
        ok "адресата нет — отправка ОТКАЗАНА"
        # Текст отказа — часть свойства: находка обязана называть ПРИЧИНУ.
        if printf '%s' "$out" | grep -q 'проверок НЕ БЫЛО'; then
            ok "отказ называет причину: проверок не было"
        else
            bad "отказ не называет причину — читателю останется гадать: $out"
        fi
        if printf '%s' "$out" | grep -q 'scripts/hooks/pre-push'; then
            ok "отказ называет КООРДИНАТУ ненайденного адресата"
        else
            bad "отказ не называет координату адресата: $out"
        fi
        if printf '%s' "$out" | grep -q -- '--no-verify'; then
            ok "отказ называет законный выход — явный обход"
        else
            bad "отказ не называет законного выхода: человек обойдёт его непредсказуемо"
        fi
    fi
    if [ -f "$c/.stand-in-ran" ]; then
        bad "отметка адресата появилась при снятом адресате — опыт судит не свой предмет"
    else
        ok "отметки адресата нет — отказ пришёл именно от переходника"
    fi
fi

echo "── ось 4: ИНЪЕКЦИЯ — КРАСНЫЙ АДРЕСАТ РОНЯЕТ ОТПРАВКУ (переходник не глотает код)"
c="$work/red"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 4 НЕ ИСПОЛНЯЛАСЬ"
else
    ( cd "$c" && bash "$INSTALL" install ) > "$c/.install.log" 2>&1
    if out="$(STAND_IN_RC=1 push_probe "$c")"; then
        bad "адресат отказал кодом 1, а отправка ПРОШЛА — переходник теряет код возврата: $out"
    else
        ok "код отказа адресата доехал до git — отправка остановлена"
    fi
fi

echo "── ось 5: ПЕРЕХОДНИК ПРЕЖНЕЙ РЕДАКЦИИ ЧИСЛИТСЯ НЕПРОВЯЗАННЫМ"
c="$work/stale"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 5 НЕ ИСПОЛНЯЛАСЬ"
else
    # Дефект вносится в той самой форме, в какой он живёт в клонах СЕГОДНЯ:
    # наш маркер, прежний номер, выход нулём на ненайденном адресате.
    cat > "$c/.git/hooks/pre-push" <<'V1'
#!/usr/bin/env bash
# СГЕНЕРИРОВАН `make install-hooks` — правится НЕ здесь, а в scripts/hooks/pre-push.
# kaname-hook-stub v1
set -uo pipefail
top="$(git rev-parse --show-toplevel 2>/dev/null)" || top=""
[ -n "$top" ] || top="$PWD"
real="$top/scripts/hooks/pre-push"
if [ ! -x "$real" ]; then
    echo "pre-push: в этой рабочей копии нет $real — проверок НЕ БЫЛО" >&2
    exit 0
fi
exec "$real" "$@"
V1
    chmod +x "$c/.git/hooks/pre-push"
    if out="$( cd "$c" && bash "$INSTALL" check 2>&1 )"; then
        bad "переходник v1 принят за провязанный — починка не доедет до существующих клонов"
    else
        ok "переходник v1 объявлен непровязанным"
        if printf '%s' "$out" | grep -q 'прежней редакции'; then
            ok "причина названа отдельно от «нет файла» и «занято чужим»"
        else
            bad "причина не названа — читатель не отличит устаревший переходник от отсутствующего: $out"
        fi
    fi
    ( cd "$c" && bash "$INSTALL" install ) > "$c/.install2.log" 2>&1
    if grep -q 'kaname-hook-stub v2' "$c/.git/hooks/pre-push"; then
        ok "установка ПЕРЕПИСАЛА устаревший переходник"
    else
        bad "устаревший переходник пережил установку"
    fi
    # Законный близнец: после перезаписи `check` обязан МОЛЧАТЬ.
    if ( cd "$c" && bash "$INSTALL" check ) > /dev/null 2>&1; then
        ok "законный близнец: провязанный клон проходит check молча"
    else
        bad "провязанный клон не проходит check — проверка краснеет на своём же исходе"
    fi
fi

echo "── ось 6: ЧУЖОЙ ФАЙЛ ПОД ИМЕНЕМ ХУКА НЕ ЗАТИРАЕТСЯ"
c="$work/foreign"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 6 НЕ ИСПОЛНЯЛАСЬ"
else
    printf '#!/bin/sh\n# чужой хук, заведённый осознанно\nexit 0\n' > "$c/.git/hooks/pre-push"
    chmod +x "$c/.git/hooks/pre-push"
    before="$(sha256sum "$c/.git/hooks/pre-push" | cut -d' ' -f1)"
    if ( cd "$c" && bash "$INSTALL" install ) > /dev/null 2>&1; then
        bad "установка прошла поверх чужого файла — осознанно заведённый хук пропал бы молча"
    else
        ok "установка ОТКАЗАЛА, встретив чужой файл"
    fi
    after="$(sha256sum "$c/.git/hooks/pre-push" | cut -d' ' -f1)"
    if [ "$before" = "$after" ]; then
        ok "чужой файл не тронут (sha256 совпал)"
    else
        bad "чужой файл изменён — лекарство от молчаливого пропуска само что-то выключило"
    fi
fi

echo "── ось 7: ПУСТОЙ ОБХОД — ОТКАЗ, А НЕ «НЕЧЕГО ДЕЛАТЬ»"
c="$work/empty"
mkdir -p "$c" && printf 'без хуков\n' > "$c/README"
git -C "$c" init -q . >/dev/null 2>&1
git -C "$c" -c user.email=probe@example.invalid -c user.name=probe add -A >/dev/null 2>&1
git -C "$c" -c user.email=probe@example.invalid -c user.name=probe commit -q -m "дерево без хуков" >/dev/null 2>&1
if out="$( cd "$c" && bash "$INSTALL" install 2>&1 )"; then
    bad "дерево без отслеживаемых хуков дало ЗЕЛЁНУЮ установку — «провязано 0» неотличимо от работы"
else
    ok "дерево без отслеживаемых хуков — отказ"
    if printf '%s' "$out" | grep -q 'НИ ОДНОГО отслеживаемого хука'; then
        ok "отказ называет предмет: обход пуст"
    else
        bad "отказ не называет предмет пустого обхода: $out"
    fi
fi

echo "── ось 8: НАСТРОЙКА, ПЕРЕБИВАЮЩАЯ .git/hooks, ОСТАНАВЛИВАЕТ УСТАНОВКУ"
c="$work/hookspath"
if ! new_clone "$c"; then
    bad "фикстура не собрана — ось 8 НЕ ИСПОЛНЯЛАСЬ"
else
    git -C "$c" config core.hooksPath scripts/hooks
    if out="$( cd "$c" && bash "$INSTALL" install 2>&1 )"; then
        bad "установка объявила «провязано» туда, куда git не заглядывает"
    else
        ok "установка остановлена: переходники легли бы мимо взгляда git"
    fi
fi

echo "── ось 9: ТЕКСТ ПЕРЕХОДНИКА ИМЕЕТ ОДНОГО ПРОИЗВОДИТЕЛЯ"
gen="$(bash "$INSTALL" stub pre-push 2>/dev/null)"
if [ -z "$gen" ]; then
    bad "генератор не отдал текст переходника — опыт выше сверял бы копию, а не производимое"
else
    ok "текст переходника берётся у генератора (режим stub), копии в пробе нет"
    if printf '%s' "$gen" | grep -q 'exit 1'; then
        ok "производимый переходник отказывает ненулём"
    else
        bad "производимый переходник не отказывает — ось 3 доказывала бы что-то другое"
    fi
fi

echo
echo "=== install-inject: перепись ==="
echo "утверждений исполнено : $checks"
echo "из них не сошлось     : $failed"
if [ "$checks" -eq 0 ]; then
    echo "БЕСПРЕДМЕТНО: не исполнено ни одного утверждения — это не зелёное." >&2
    exit 2
fi
if [ "$failed" -gt 0 ]; then
    echo "ОТКАЗ: провязка хука не обладает заявленными свойствами." >&2
    exit 1
fi
echo "ЗЕЛЁНОЕ: переходник доходит до адресата, а без адресата ОТКАЗЫВАЕТ."
