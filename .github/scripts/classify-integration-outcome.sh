#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# classify-integration-outcome.sh <код-возврата-go-test> <файл-с-выводом>
#
# Различает ТРИ исхода контейнерного прогона и печатает свой вердикт:
#
#   0  — зелёный;
#   1  — КРАСНЫЙ: проба упала, в коде есть что чинить;
#   75 — УСЛОВИЕ НЕ СОЗДАНО: Postgres для контейнерных проб не поднялся, и
#        вердикта нет НИ У ОДНОЙ пробы пакета, включая те, что успели пройти.
#
# Третий исход НЕ зелёный: не исполнено ничего. Он ненулевой ровно затем, чтобы
# «не выполнилось» не читалось как «прошло»; отличается он ТЕКСТОМ и кодом, а не
# снисходительностью — прощать он не прощает ничего.
#
# Зачем отдельным файлом, а не веткой внутри шага конвейера: ветку в шаге нечем
# доказать инъекцией, а недоказанная ветка сама становится тем классом, который
# она ловит, — формой без содержания. Здесь вход подаётся файлом, поэтому обе
# стороны проверяются за миллисекунды (`--self-test` ниже).
set -uo pipefail

# Признак недоступности контейнерного Postgres. Узкий НАМЕРЕННО: широкий превратил
# бы третий исход в маску для настоящих падений.
readonly UNAVAILABLE_RE='integration Postgres unavailable|could not start postgres|wait for reaper|Cannot connect to the Docker daemon|docker: command not found'

classify() {
    local rc="$1" log="$2"
    if [ "$rc" -eq 0 ]; then
        echo "интеграция: зелёный (код go test 0)"
        return 0
    fi
    # Отказ окружения решает признак В ЛОГЕ, но ТОЛЬКО при ненулевом коде: иначе
    # строка из прошлого прогона перекрасила бы зелёный.
    if [ "$rc" -eq 1 ] && grep -qE "$UNAVAILABLE_RE" "$log"; then
        echo "интеграция: УСЛОВИЕ НЕ СОЗДАНО — Postgres для контейнерных проб не поднялся." >&2
        echo "Вердикта нет ни у одной пробы, включая успевшие пройти. Это не дефект кода;" >&2
        echo "прогон недействителен и повторяется после устранения причины." >&2
        return 75
    fi
    # Иной ненулевой код (снятие по времени, паника харнесса) третьим исходом НЕ
    # становится: у него нет признака, и подавать его как «условие не создано»
    # значило бы прощать настоящую поломку.
    echo "интеграция: КРАСНЫЙ (код go test $rc)" >&2
    return "$rc"
}

# --- самопроверка: доказательство инъекцией в обе стороны ---------------------
#
# Живёт ФЛАГОМ этого же файла, а не соседним: отдельный файл в перечень шагов
# конвейера не попал бы сам, то есть не исполнялся бы никогда.
if [ "${1:-}" = "--self-test" ]; then
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    probes=0; failed=0
    run() { # run <ожидаемый-код> <имя> <код-go-test> <тело-лога>
        local want="$1" name="$2" rc="$3" body="$4" got=0
        probes=$((probes + 1))
        printf '%s\n' "$body" > "$TMP/log"
        classify "$rc" "$TMP/log" >/dev/null 2>&1 || got=$?
        if [ "$got" -ne "$want" ]; then
            echo "  ПРОВАЛ $name — ждали код $want, получили $got" >&2
            failed=$((failed + 1)); return
        fi
        echo "  ok   $name (код $got)"
    }

    echo "=== различение трёх исходов контейнерного прогона ==="

    run 75 "(+) Postgres не поднялся — УСЛОВИЕ НЕ СОЗДАНО, а не красное" 1 \
        'ok  	github.com/PRO-Robotech/kaname/internal/clients	14.4s
integration Postgres unavailable: start postgres: run postgres: reaper: wait for reaper
FAIL	github.com/PRO-Robotech/kaname/internal/repo/kaname/pg	60.3s'

    run 75 "(+) демона докера нет вовсе — тот же третий исход" 1 \
        'Cannot connect to the Docker daemon at unix:///var/run/docker.sock.
FAIL	github.com/PRO-Robotech/kaname/internal/repo/kaname/pg	1.1s'

    # ЗАКОННЫЙ БЛИЗНЕЦ: настоящее падение пробы обязано остаться красным. Без него
    # правило выродилось бы в «любое падение — не наша вина».
    run 1 "(−) упавшее утверждение — по-прежнему красное" 1 \
        '--- FAIL: TestAccessBindingUniqueness (0.21s)
    access_binding_integration_test.go:88: ожидали 23505, получили nil
FAIL	github.com/PRO-Robotech/kaname/internal/repo/kaname/pg	31.0s'

    run 0 "(−) зелёный прогон — зелёный" 0 \
        'ok  	github.com/PRO-Robotech/kaname/internal/repo/kaname/pg	138.9s'

    run 0 "(−) признак в логе при НУЛЕВОМ коде зелёного не меняет" 0 \
        'integration Postgres unavailable: (строка из прошлого прогона)
ok  	github.com/PRO-Robotech/kaname/internal/repo/kaname/pg	138.9s'

    run 2 "(−) чужой ненулевой код проходит как есть, третьим исходом не становится" 2 \
        'panic: test timed out after 20m0s'

    echo
    echo "classify-integration-outcome --self-test: проб исполнено $probes, провалов $failed"
    [ "$probes" -eq 0 ] && { echo "ПРОВАЛ: ни одной пробы не исполнено" >&2; exit 2; }
    [ "$failed" -gt 0 ] && exit 1
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "нужно два довода: <код-возврата-go-test> <файл-с-выводом>" >&2
    exit 2
fi
classify "$1" "$2"
