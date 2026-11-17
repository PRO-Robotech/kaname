#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# run-integration.sh — контейнерные пробы службы (testcontainers + Postgres).
#
# ОТБОР ВЫВОДИТСЯ ПРИЗНАКОМ, А НЕ ВЫПИСАН ОБРАЗЦОМ ПУТИ.
#
# Здесь стоял образец, повторявший раскладку монорепо:
# `/internal/(repo|clients|reconciler|subscriptionjournal)`. Он отбирал 9
# пакетов, тогда как пробы на базе поднимают 29, — то есть 20 пакетов не
# исполнялись НИ В ОДНОМ задании: под `-short` они пропускают себя сами, а
# контейнерное задание до них не доходило. Красное такого пакета не видел никто;
# в одном из них (`internal/moduleseedparity`) оно и лежало.
#
# Признак — ТОТ ЖЕ, по которому пробу считают контейнерной: её сборка импортирует
# `corelib/pgtest` либо `testcontainers`. Он берётся у `go list`, то есть у
# РАЗБОРА импортов, а не у поиска по тексту: слова `pgtest` и `testcontainers`
# стоят в этом дереве и в прозе (комментарий «использует фейки, НЕ
# testcontainers» — дословный пример), и текстовый предикат зачёл бы объяснение
# за предмет.
#
# Перепись печатает ОБЕ величины — «с пробами на базе N · отобрано M» — и
# отказывает при N ≠ M. Одно число скрывало бы ровно тот случай, ради которого
# отбор переписан: сузившийся отбор выглядел бы как поредевшее дерево.
#
# Замер 2026-09-16 на стволе: пакетов всего 153, с пробами на базе 29, прежним
# образцом отбиралось 9. Задача kaname#19 называла 21 пакет вне отбора на
# ревизии 5303cebd; на сегодняшнем стволе их 20, и оба предиката — её
# статический обход и этот разбор импортов — дают ОДИН И ТОТ ЖЕ набор.
#
# Приёмка MRW-1 (S1 п. 10, kaname#106) требует, чтобы `internal/moduleseedparity`
# (держатель атрибуции посева) и `internal/migrations` (прецеденты отката с
# повторным накатом) исполнялись контейнерным заданием. Ветка #106 держала это
# ДОПИСКОЙ в образец пути; после переписи отбора на признак импорта дописка
# беспредметна: оба пакета импортируют `corelib/pgtest` и отбираются признаком,
# а не перечнем. Перемерено при слиянии ветки с линией (2026-09-16):
# `go list -f '{{.ImportPath}}::{{join .TestImports " "}}' ./internal/moduleseedparity/
# ./internal/migrations/` — оба со строкой `corelib/pgtest`.
#
# «НЕЧЕГО ЗАПУСКАТЬ» И «НЕ СМОГ СПРОСИТЬ» — РАЗНЫЕ ИСХОДЫ, и различать их
# обязательно. Форма `go list … | grep … || true` покрывает ОБА одним нулём:
# отбор получает пустой список, печатает «нечего запускать» и выходит успехом —
# задание зелёное, проб исполнено ноль. Поэтому код `go list` читается ОТДЕЛЬНО
# от кода `grep`, у которого «ничего не нашлось» — законный исход (код 1).
#
# ГРАНИЦА ЭТОГО СТРАЖА НАЗВАНА, ПОТОМУ ЧТО ОНА УЖЕ МЕНЯЛАСЬ ПОД ЗАМЕРОМ. Здесь
# стояло «сломанная сборка роняет `go list`» — и это неправда: инъекция пакетом
# с синтаксической ошибкой дала код 0, чистый stderr и пакет в выводе. `go list`
# роняется на МОДУЛЬНОМ уровне (битый `go.mod`, нерезолвимый шаблон), а тела
# пакетов он не разбирает. Проверено обеими сторонами:
#
#   пакет с `var x = `            → код 0, пакет перечислен   (страж молчит)
#   зависимость не скачивается    → код 0, пакет перечислен   (страж молчит)
#   `go.mod` не разбирается       → код 1                     (страж срабатывает)
#
# Значит несобирающийся код ловит НЕ этот страж, а два других места, и оба
# блокирующие: задание сборки (`go build ./...`) и сам `go test`, который на
# несобравшемся пакете отдаёт ненулевой код без признака третьего исхода, то
# есть уходит в красное. Страж здесь закрывает свой, узкий класс — и написано
# ровно это, а не то, что звучало бы внушительнее.
#
# `-p 1` ВНУТРИ прогона: пакеты сериализуются. Под `-race` и состязание за Docker
# параллельные контейнерные пакеты голодают друг у друга ресурсы, и кейсы на
# конкуренцию (CAS/UNIQUE/EXCLUDE/SKIP LOCKED) начинают флакать — то есть давать
# красное там, где ничего не сломано.
#
# `-tags=integration` СЕГОДНЯ НЕ ИМЕЕТ ПРЕДМЕТА, и это сказано числом, а не
# обещанием: файлов под `//go:build integration` в дереве НОЛЬ —
#
#   git grep -l '//go:build.*integration' -- '*_test.go' | wc -l   → 0
#
# Здесь стояло «`-tags=integration` ОБЯЗАТЕЛЕН», и утверждение было ложным:
# обязательным флаг называть нельзя там, где обязывать нечего. Флаг оставлен
# потому, что его снятие сделало бы появление такого файла МОЛЧАЛИВЫМ выпадением
# из прогона — тем же классом, который эта правка и закрывает. Появится файл под
# тегом — предикат выше перестанет давать ноль, и абзац обязан быть переписан
# тем же изменением.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# DB_MARKERS — признак пробы, поднимающей базу. Обе записи законны и обе
# распространены: общий помощник фундамента и контейнер напрямую.
DB_MARKERS='(corelib/pgtest|testcontainers)'
TIMEOUT="${INTEGRATION_TIMEOUT:-25m}"

cd "$ROOT" || exit 2

# Только CI включает сохранение событий; обычный локальный вызов остаётся прежним.
evidence="${INTEGRATION_EVIDENCE_DIR:-}"
if [ -n "$evidence" ]; then
    mkdir -p -- "$evidence" || exit 2
    python3 - "$evidence" <<'PYENV'
import json, os, pathlib, sys
keys = ("GITHUB_SHA", "INTEGRATION_TIMEOUT", "INTEGRATION_SHARD", "PLATFORM_TREE",
        "TESTCONTAINERS_RYUK_DISABLED", "TESTCONTAINERS_HOST_OVERRIDE", "KANAME_REQUIRE_INTEGRATION",
        "KACHO_DERIVE_PARENT_COST", "KACHO_PERMANENT_PROJECT_COST", "KACHO_MATRIX_VOLUME",
        "KACHO_SCALEGRID_FULL", "KACHO_STRENGTH_FULL", "KACHO_STRENGTH_WRITE", "KACHO_RECOVERY_TIMING")
# Отсутствующая ручка сохраняется как null: условие нельзя выводить из имени задания.
pathlib.Path(sys.argv[1], "environment.json").write_text(
    json.dumps({key: os.environ.get(key) for key in keys}, indent=2, sort_keys=True) + "\n")
PYENV
    [ "$?" -eq 0 ] || exit 2
fi

# ШАРД: `INTEGRATION_SHARD=<k>/<N>`, k от 0 — ровно `strategy.job-index` и
# `strategy.job-total` задания, то есть число шардов берётся у самой матрицы и
# разойтись с ней не может. `--plan` печатает раскладку всех N шардов и выходит,
# не исполняя проб (`INTEGRATION_SHARD=0/4 run-integration.sh --plan`).
# DEFAULT_WEIGHT — вес пакета, которого ведомость весов не знает (секунды).
DEFAULT_WEIGHT=10
# Два дорогих TOP делятся одним взаимодополняющим фильтром (kaname#1034).
partition_package='github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding'
partition_pattern='^(TestFullBind_FB21_GroupAdditionChecksTheLastBindingPage|TestFullBind_FB31_SourceExpiryAfterHeldWriterClockDoesNotShortenGrant)$'
partition_mode=''
plan_only=0
case "${1:-}" in
    "") ;;
    --plan) plan_only=1 ;;
    *) echo "аргумент не предусмотрен: $1 (знаю только --plan)" >&2; exit 2 ;;
esac
shard_index=""
shard_total=""
if [ -n "${INTEGRATION_SHARD:-}" ]; then
    if ! [[ "$INTEGRATION_SHARD" =~ ^(0|[1-9][0-9]*)/([1-9][0-9]*)$ ]]; then
        echo "INTEGRATION_SHARD=$INTEGRATION_SHARD не в форме <k>/<N> (k от 0) — это отказ" >&2
        exit 2
    fi
    shard_index="${BASH_REMATCH[1]}"
    shard_total="${BASH_REMATCH[2]}"
    if [ "$shard_index" -ge "$shard_total" ]; then
        echo "INTEGRATION_SHARD=$INTEGRATION_SHARD: номер шарда вне 0..$((shard_total - 1)) — это отказ" >&2
        exit 2
    fi
elif [ "$plan_only" -eq 1 ]; then
    echo "--plan без INTEGRATION_SHARD: число шардов не названо — это отказ" >&2
    exit 2
fi

# ВРЕМЕННЫЕ ФАЙЛЫ ЖИВУТ В ОДНОМ КАТАЛОГЕ, И ЛОВУШКА СНЯТИЯ — ОДНА (kaname#671).
#
# Здесь стояли три ловушки `EXIT`, по одной на временный файл, и каждая
# следующая ЗАМЕНЯЛА предыдущую: `trap` не дописывает, а переставляет. Ловушка
# журнала забыла файл ошибок разбора импортов, и он оставался во временном
# каталоге на каждом прогоне, дошедшем до `go test`. Перечень снимаемого,
# который надо повторять при каждой новой ловушке, — ровно та форма, что
# устаревает молча; поэтому снимается КАТАЛОГ, а новый файл заводится в нём и
# в снятие попадает сам.
#
# Прерывание переводится в выход с кодом 128+номер сигнала: без своей ловушки
# SIGINT, пришедший процессу во время трубы, bash переживает, если `go test` сам
# от него не умер, — и прерванный прогон уходил в классификатор и мог выйти
# ЗЕЛЁНЫМ. Выход из ловушки сигнала исполняет ловушку `EXIT`, то есть снятие.
#
# Держится пробой `internal/check/run_integration_cleanup_unix_test.go`: она
# исполняет этот сценарий по каждому пути выхода, с прерыванием и без, и
# требует пустого `TMPDIR` после.
work="$(mktemp -d)" || exit 2
trap 'rm -rf -- "$work"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ПОТОКИ РАЗВЕДЕНЫ. При `2>&1` диагностика `go list` попадает в тот же поток, что
# и имена пакетов, и строка ошибки становится «пакетом»: отбор считал бы её в
# перепись, а `grep` мог бы на ней и совпасть.
list_err="$work/list.err"
list_rc=0
all="$(go list ./... 2>"$list_err")" || list_rc=$?
if [ "$list_rc" -ne 0 ]; then
    echo "go list по пакетам сорвался — состав пакетов НЕ ИЗМЕРЕН." >&2
    echo "Это отказ, а не «нечего запускать»: пустой список здесь означал бы" >&2
    echo "зелёное задание с нулём выполненных проб." >&2
    tail -20 "$list_err" >&2
    exit 2
fi
if [ -z "$all" ]; then
    echo "не найдено НИ ОДНОГО пакета — обход пуст, это отказ" >&2
    exit 2
fi

total="$(printf '%s\n' "$all" | wc -l)"

# ИМПОРТЫ ПРОБ СПРАШИВАЮТСЯ У `go list`, А НЕ У ТЕКСТА. Разделитель `::` выбран
# потому, что в путях импорта он не встречается: разбор по нему однозначен.
imports_err="$work/imports.err"
imports_rc=0
imports="$(go list -f '{{.ImportPath}}::{{join .TestImports " "}} {{join .XTestImports " "}}' ./... 2>"$imports_err")" || imports_rc=$?
if [ "$imports_rc" -ne 0 ]; then
    echo "go list по импортам проб сорвался — признак НЕ ИЗМЕРЕН." >&2
    echo "Это отказ, а не «нечего запускать»: пустой отбор здесь означал бы" >&2
    echo "зелёное задание с нулём выполненных проб." >&2
    tail -20 "$imports_err" >&2
    exit 2
fi

raised="$(printf '%s\n' "$imports" | awk -F'::' -v re="$DB_MARKERS" '$2 ~ re {print $1}')"
if [ -z "$raised" ]; then
    echo "пакетов с пробами на базе не найдено — обход пуст, это отказ" >&2
    echo "(осмотрено пакетов: $total). Ноль здесь означал бы либо исчезнувший" >&2
    echo "предмет, либо распознаватель, переставший знать признак." >&2
    exit 2
fi
pkgs="$raised"
if [ -n "$evidence" ]; then
    printf '%s\n' "$pkgs" > "$evidence/selected-packages.txt" || exit 2
fi
with_db="$(printf '%s\n' "$raised" | wc -l)"
selected="$(printf '%s\n' "$pkgs" | wc -l)"

echo "=== ОТБОР ==="
echo "осмотрено пакетов     : $total"
echo "с пробами на базе     : $with_db  (признак: импорт $DB_MARKERS в сборке проб)"
echo "отобрано              : $selected"
if [ "$with_db" -ne "$selected" ]; then
    echo "ОТБОР УЖЕ ПРИЗНАКА: с пробами на базе $with_db, отобрано $selected." >&2
    echo "Разница — пакеты, чьи пробы не исполняет НИ ОДНО задание: под -short они" >&2
    echo "пропускают себя сами, а сюда не доходят. Их красное не видит никто." >&2
    exit 2
fi
echo ""

# РАСКЛАДКА ПО ШАРДАМ (kaname#840). Пакеты внутри прогона идут по одному (`-p 1`,
# довод выше), поэтому срок задания — СУММА времён пакетов: замер 2026-10-15 —
# 1549 с на прогоне 38766280699 и 2133 с без четырёх недошедших пакетов на
# 38781486845 (тот же состав из 36 пакетов, другой пул исполнителей), и второй
# снят пределом задания без единого FAIL. Предел поднимать — значит отложить ту
# же отсечку до следующего роста; поэтому сумма делится между машинами.
#
# Раскладка ДЕТЕРМИНИРОВАНА и выводится из того же отбора на каждом шарде:
# пакеты по убыванию замеренного веса (`.github/integration-shard-weights.txt`),
# каждый — в наименее загруженный шард. Каждый шард строит ПОЛНЫЙ план и
# проверяет его: каждый отобранный пакет ровно в одном шарде, ни один шард не
# пуст. Иначе код 2 — выпавший пакет был бы ровно тем молчаливым выпадением,
# против которого переписан отбор.
#
# Без `INTEGRATION_SHARD` прогон — весь отбор, как прежде (локально и в пробах).
if [ -n "$shard_total" ]; then
    weights="$ROOT/.github/integration-shard-weights.txt"
    if [ ! -r "$weights" ]; then
        echo "ведомость весов $weights не прочитана — раскладка не из чего, это отказ" >&2
        exit 2
    fi
    plan_err="$work/plan.err"
    plan_rc=0
    plan="$(printf '%s\n' "$pkgs" | awk -v n="$shard_total" -v wf="$weights" -v dflt="$DEFAULT_WEIGHT" '
        BEGIN {
            while ((getline line < wf) > 0) {
                if (line ~ /^[[:space:]]*(#|$)/) continue
                if (split(line, f, " ") != 2 || f[1] !~ /^[0-9]+$/) {
                    print "строка ведомости весов не разобрана: " line > "/dev/stderr"; bad = 1; continue
                }
                if (f[2] in w) { print "пакет дважды в ведомости весов: " f[2] > "/dev/stderr"; bad = 1 }
                w[f[2]] = f[1] + 0
            }
            close(wf)
        }
        NF { p[++np] = $1; sel[$1] = 1 }
        END {
            for (k in w) if (!(k in sel)) { print "в ведомости весов пакет, которого отбор не дал (запись без предмета): " k > "/dev/stderr"; bad = 1 }
            if (bad) exit 3
            for (i = 1; i <= np; i++) {
                if (p[i] in w) pw[i] = w[p[i]]
                else { pw[i] = dflt; print "вес не замерен, взят по умолчанию " dflt " с: " p[i] > "/dev/stderr" }
            }
            # Порядок: вес по убыванию, при равенстве — путь по возрастанию.
            for (i = 2; i <= np; i++) {
                ki = p[i]; kw = pw[i]; j = i - 1
                while (j >= 1 && (pw[j] < kw || (pw[j] == kw && p[j] > ki))) { p[j+1] = p[j]; pw[j+1] = pw[j]; j-- }
                p[j+1] = ki; pw[j+1] = kw
            }
            for (s = 0; s < n; s++) load[s] = 0
            for (i = 1; i <= np; i++) {
                best = 0
                for (s = 1; s < n; s++) if (load[s] < load[best]) best = s
                load[best] += pw[i]
                print best "\t" pw[i] "\t" p[i]
            }
        }' 2>"$plan_err")" || plan_rc=$?
    cat "$plan_err" >&2
    if [ "$plan_rc" -ne 0 ]; then
        echo "раскладка по шардам НЕ ПОСТРОЕНА (код $plan_rc) — это отказ" >&2
        exit 2
    fi

    # Проверка плана — отдельно от построения: каждый отобранный пакет ровно
    # в одном шарде, ни один шард не пуст.
    planned="$(printf '%s\n' "$plan" | awk -F'\t' 'NF' | wc -l)"
    distinct="$(printf '%s\n' "$plan" | awk -F'\t' 'NF {print $3}' | sort -u | wc -l)"
    missing="$(comm -23 <(printf '%s\n' "$pkgs" | sort -u) <(printf '%s\n' "$plan" | awk -F'\t' 'NF {print $3}' | sort -u))"
    if [ "$planned" -ne "$selected" ] || [ "$distinct" -ne "$selected" ] || [ -n "$missing" ]; then
        echo "РАСКЛАДКА НЕПОЛНА: отобрано $selected, в плане строк $planned, различных $distinct." >&2
        # shellcheck disable=SC2086
        [ -n "$missing" ] && printf 'вне плана: %s\n' $missing >&2
        exit 2
    fi

    echo "=== РАСКЛАДКА ПО ШАРДАМ ($shard_total) ==="
    for ((s = 0; s < shard_total; s++)); do
        n_s="$(printf '%s\n' "$plan" | awk -F'\t' -v s="$s" '$1 == s' | wc -l)"
        sum_s="$(printf '%s\n' "$plan" | awk -F'\t' -v s="$s" '$1 == s {t += $2} END {print t + 0}')"
        mark=""
        [ "$s" = "$shard_index" ] && mark="  ← этот"
        echo "шард $s: пакетов $n_s · замеренный вес $sum_s с$mark"
        if [ "$n_s" -eq 0 ]; then
            echo "шард $s пуст: шардов больше, чем пакетов, — это отказ" >&2
            exit 2
        fi
    done
    echo "в плане пакетов       : $planned из $selected, каждый ровно в одном шарде"
    if [ -n "$evidence" ]; then
        printf '%s\n' "$plan" > "$evidence/shard-plan.tsv" || exit 2
    fi
    # LPT и его проверка остаются пакетными. Исполнение делит только один пакет.
    # Получатель — index 1: CI 44180113004, шард 2 SUCCESS за 10m22s;
    # минимальный старый вес шарда 5 скрывал фактические 25m53s.
    execution_plan="$work/execution-plan.tsv"
    printf '%s\n' "$plan" > "$work/shard-plan.tsv" || exit 2
    python3 - "$work/shard-plan.tsv" "$execution_plan" "$partition_package" "$partition_pattern" "$shard_total" <<'PYPLAN' || exit 2
import pathlib, sys
source, target, package, pattern, total = sys.argv[1:]
total = int(total)
original = [(int(s), p) for s, _, p in
            (line.split("\t") for line in pathlib.Path(source).read_text().splitlines())]
owner = next((s for s, p in original if p == package), None)
recipient = None
if owner is not None and total > 1:
    recipient = 1 if owner != 1 else next(s for s in range(total) if s != owner)
rows = [(s, p, "skip" if p == package and recipient is not None else "all",
         pattern if p == package and recipient is not None else "-") for s, p in original]
if recipient is not None:
    rows.append((recipient, package, "run", pattern))
# Отдельный валидатор проверяет полноту, владельцев, фильтры и отсутствие дублей.
expected = {p: s for s, p in original}
for p, owner_index in expected.items():
    actual = [(s, mode, regex) for s, pkg, mode, regex in rows if pkg == p]
    wanted = [(owner_index, "all", "-")]
    if p == package and recipient is not None:
        wanted = [(owner_index, "skip", pattern), (recipient, "run", pattern)]
    if sorted(actual) != sorted(wanted):
        raise SystemExit("неполное или повторное исполнение пакета: " + p)
if any(p not in expected or not 0 <= s < total for s, p, _, _ in rows):
    raise SystemExit("неизвестный пакет или шард в плане исполнения")
pathlib.Path(target).write_text("".join("\t".join(map(str, row)) + "\n" for row in rows))
PYPLAN
    if [ -n "$evidence" ]; then
        cp "$execution_plan" "$evidence/execution-plan.tsv" || exit 2
    fi
    if [ "$plan_only" -eq 1 ]; then
        cat "$execution_plan"
        exit 0
    fi
    pkgs="$(awk -F'\t' -v s="$shard_index" '$1 == s && $3 == "all" {print $2}' "$execution_plan")"
    partition_mode="$(awk -F'\t' -v s="$shard_index" '$1 == s && $3 != "all" {print $3}' "$execution_plan")"
    echo "исполняется в шарде $shard_index: $(printf '%s\n' "$pkgs" | wc -l)"
    echo ""
fi

if [ -n "$evidence" ]; then
    { [ -z "$pkgs" ] || printf '%s\n' "$pkgs"; [ -z "$partition_mode" ] || printf '%s\n' "$partition_package"; } > "$evidence/executed-packages.txt" || exit 2
    # Последовательная склейка команд; их первичные коды лежат отдельно.
    : > "$evidence/test.json" || exit 2
    : > "$evidence/go-test.log" || exit 2
fi

# Один вызов получает собственные сырой поток, текст и первичный код Go.
# Обычный непартиционированный прогон сохраняет прежние имена свидетельств.
run_tests() {
    local packages="$1" mode="$2" label="$3" raw log rc out decode_rc verdict_rc
    local destination="${evidence:-$work}" filter=()
    [ -z "$mode" ] || filter=("-$mode" "$partition_pattern")
    raw="$destination/$label.json"
    log="$destination/$label.log"
    if [ -n "$evidence" ] || [ -n "$partition_mode" ]; then
        rc=0
        # shellcheck disable=SC2086
        go test -tags=integration -race -count=1 -timeout "$TIMEOUT" -p 1 -json "${filter[@]}" $packages > "$raw" 2>&1 || rc=$?
        printf '%s\n' "$rc" > "$destination/$label-exit-code.txt" || return 2
        decode_rc=0
        python3 - "$raw" "$log" "$mode" "$partition_package" "$partition_pattern" <<'PYDECODE' || decode_rc=$?
import collections, json, pathlib, re, sys
raw, log, mode, package, pattern = sys.argv[1:]
bad = False
tops = collections.defaultdict(list)
with pathlib.Path(raw).open() as source, pathlib.Path(log).open("w") as target:
    for line in source:
        try:
            event = json.loads(line)
        except ValueError:
            target.write(line)
            # Обычная диагностика Go законна; оборванный JSON — потерянное событие.
            if line.lstrip().startswith("{"):
                bad = True
            continue
        if not isinstance(event, dict):
            bad = True
            continue
        text = event.get("Output")
        if isinstance(text, str):
            target.write(text)
        name = event.get("Test", "")
        action = event.get("Action")
        if mode and event.get("Package") == package and name and "/" not in name:
            if action in ("run", "pass", "fail", "skip"):
                tops[name].append(action)
if mode:
    # Package PASS без исполненного именованного TOP не свидетельствует о части.
    if mode == "run":
        required = pattern[2:-2].split("|")
        if any(tops[name] != ["run", "pass"] for name in required):
            bad = True
    elif not any(actions == ["run", "pass"] for actions in tops.values()):
        bad = True
    if any(bool(re.fullmatch(pattern, name)) != (mode == "run") for name in tops):
        bad = True
    if bad:
        print("часть access_binding не подтверждена именованными TOP", file=sys.stderr)
sys.exit(2 if bad else 0)
PYDECODE
        if [ -n "$evidence" ]; then
            cat "$raw" >> "$evidence/test.json" || return 2
            cat "$log" >> "$evidence/go-test.log" || return 2
        fi
        verdict_rc=0
        python3 "$ROOT/.github/scripts/go-test-verdict.py" < "$raw" || verdict_rc=$?
        out=0
        "$ROOT/.github/scripts/classify-integration-outcome.sh" "$rc" "$log" || out=$?
        # Исход окружения/Go старше ошибки свидетельства и не теряется.
        [ "$out" -eq 0 ] || return "$out"
        [ "$decode_rc" -eq 0 ] || return "$decode_rc"
        return "$verdict_rc"
    else
        log="$work/go-test.log"
        # shellcheck disable=SC2086
        go test -tags=integration -race -count=1 -timeout "$TIMEOUT" -p 1 $packages 2>&1 | tee "$log"
        rc="${PIPESTATUS[0]}"
        "$ROOT/.github/scripts/classify-integration-outcome.sh" "$rc" "$log"
    fi
}

# Первый отказ не отменяет вторую запланированную команду. Сигнал по-прежнему
# завершает весь сценарий общей ловушкой, поэтому прерывание не даёт PASS.
result=0
if [ -n "$pkgs" ]; then
    run_tests "$pkgs" "" go-test-packages || result=$?
fi
if [ -n "$partition_mode" ]; then
    part_rc=0
    run_tests "$partition_package" "$partition_mode" go-test-access-binding || part_rc=$?
    [ "$result" -ne 0 ] || result="$part_rc"
fi
if [ -n "$evidence" ]; then
    printf '%s\n' "$result" > "$evidence/runner-exit-code.txt" || exit 2
    # Обратная совместимость только там, где действительно был один вызов Go.
    if [ -z "$partition_mode" ]; then
        cp "$evidence/go-test-packages-exit-code.txt" "$evidence/go-test-exit-code.txt" || exit 2
    fi
fi
exit "$result"
