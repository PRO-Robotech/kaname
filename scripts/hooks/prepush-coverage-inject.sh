#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-coverage-inject.sh — опыт: перечень непроверенного хука отправки
# ВЫВЕДЕН из конвейера и ПЕЧАТАЕТСЯ на пути обхода (kaname#273).
#
# ─────────────────────────────────────────────────────────────────────────────
# ПРЕДМЕТ
#
# Хук печатает, чего он НЕ гонял, — иначе «хук зелен» читается как «конвейер
# зелен». Прежний перечень был выписан руками и молчал о четырёх проверках
# конвейера (buf lint · proto-gen-diff · module-manifest-check ·
# review-event-silence): приёмка нашла это чтением, а не проверкой. Громкость
# обхода `KANAME_SKIP_PREPUSH=1` была доказана тоже лишь чтением кода; проба по
# коду 0 её не держит — молчаливый `exit 0` даёт тот же код.
#
# ─────────────────────────────────────────────────────────────────────────────
# ОСИ
#
#  A. ВЕДОМОСТЬ ПРОТИВ КОНВЕЙЕРА, в обе стороны. Шаги с `run:` выводятся
#     разбором `.github/workflows/ci.yml` (YAML, не текст), ведомость — режимом
#     хука `--kaname-prepush-coverage`. Находки: шаг без строки (класс #273),
#     строка без шага (ведомость пережила предмет), исход не из словаря, группа,
#     которой у хука нет, дубль ключа. Объём печатается всегда; ноль шагов
#     либо ноль строк — «не исполнялось», а не зелёное.
#  B. ОБХОД ГРОМОК — ПО ТЕКСТУ. Настоящий хук провязан в песочнице установщиком
#     и зовётся настоящим `git push` с `KANAME_SKIP_PREPUSH=1`. Утверждения: код
#     0; строка обхода; «исполнено групп проверок: 0»; КАЖДАЯ пара «задание ·
#     метка» исхода «не-гоняется» ведомости ТОГО ЖЕ хука стоит в перечне строкой
#     задания; ссылка доехала до удалённого (обход действует).
#  C. НЕОТФОРМАТИРОВАННОЕ ОТВЕРГНУТО (предикат #273, п. 4). Настоящий хук без
#     обхода на синтетическом модуле, пара одно-фактных близнецов: файл Go
#     отформатирован — отправка проходит, «исполнено 6 из 6»; тот же файл без
#     отступа — отказ, красная ровно группа gofmt, файл назван.
#  D. СЛУЖЕБНЫЙ РЕЖИМ НЕДОСТИЖИМ ОТПРАВКОЙ (SEC-942-k1-1). Имя удалённого git
#     подаёт хуку первым доводом, и выбирает его отправляющий. Настоящий хук,
#     настоящий `git push -- <имя> …` на удалённый, названный доводом служебного
#     режима: «--kaname-prepush-coverage» — проверки исполнены (6 из 6, таблицы
#     ведомости нет); «--kaname-prepush-in-memory-scope» — то же, и потолок не
#     объявлен выставленным, когда области нет.
#
# Судья подписи хука (tools/clagate) собирается из исходников ЭТОГО дерева:
# переходник `go` песочниц уводит сборку судьи в корень дерева (форма соседей —
# prepush-added-files-inject.sh, prepush-budget-inject.sh), а ведомость
# `cla-ledger.yaml` песочницы объявляет её учётную запись своей. Оси от этого не
# слабеют: судья настоящий и судит каждую отправку опыта.
#
# --self-test добавляет инъекции на копиях настоящих входов, по одному факту:
#  A1 в копию ci.yml дописан шаг с `run:` без строки ведомости — красное, ключ назван;
#  A2 законный близнец — дописан шаг `uses:` без `run:` — молчание;
#  A3 в копию хука дописана строка ведомости без шага — красное, ключ назван;
#  B1 копия хука выходит на обходе молча (`exit 0` до перечня) — красное при коде 0;
#  B2 копия хука печатает лишь две строки перечня — красное, недостающая метка названа;
#  D1 копия хука узнаёт режим ведомости по одному тексту первого довода — красное:
#     отправка на удалённый с таким именем ушла в режим ведомости без проверок;
#  D2 копия хука узнаёт перезапуск в области по одному тексту первого довода —
#     красное: напечатан потолок памяти, которого нет.
# Контроль (настоящий хук, настоящий ci.yml) обязан быть зелёным в том же прогоне.
#
# Исходы: 0 — всё исполнено и сошлось; 1 — находка либо инъекция не поймана;
# 2 — предпосылка не создана (нет python3/yaml, пустой разбор, песочница не
# провязана) — вердикта нет.
#
# Прогон: `bash scripts/hooks/prepush-coverage-inject.sh [--self-test]`.
set -uo pipefail

SELF_TEST=0
case "${1:-}" in
    "") ;;
    --self-test) SELF_TEST=1 ;;
    *) echo "prepush-coverage-inject: неизвестный довод «$1»" >&2; exit 2 ;;
esac

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — это не рабочая копия git" >&2; exit 2; }
HOOK="$ROOT/scripts/hooks/pre-push"
CI="$ROOT/.github/workflows/ci.yml"
for f in "$HOOK" "$CI" "$ROOT/scripts/hooks/install.sh" "$ROOT/scripts/hooks/prepush-rule.sh" \
         "$ROOT/scripts/hooks/branch-rule.sh" "$ROOT/scripts/hooks/prepush-added-files.sh" \
         "$ROOT/scripts/hooks/prepush-classify.sh"; do
    [ -f "$f" ] || { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — нет $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — нет python3" >&2; exit 2; }
python3 -c 'import yaml' 2>/dev/null || { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — нет модуля yaml у python3" >&2; exit 2; }

work="$(mktemp -d)" || { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — нет временного каталога" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT

checks=0
failed=0
unmet=0
ok()   { checks=$((checks + 1)); echo "  ok   — $1"; }
bad()  { checks=$((checks + 1)); failed=$((failed + 1)); echo "  БЕДА — $1" >&2; }
void() { unmet=$((unmet + 1)); echo "  УСЛОВИЕ НЕ СОЗДАНО (не находка): $1" >&2; }

# ── ОСЬ A: СУДЬЯ ВЕДОМОСТИ ──────────────────────────────────────────────────
#
# judge_ledger <хук> <ci.yml> — печатает перепись и находки, код 0 · 1 · 2.
judge_ledger() {
    local hook="$1" ci="$2" cov="$work/cov.$RANDOM"
    if ! bash "$hook" --kaname-prepush-coverage > "$cov" 2>"$cov.err"; then
        echo "режим ведомости хука отказал: $(head -3 "$cov.err")"; return 2
    fi
    python3 - "$ci" "$cov" <<'PY'
import sys, yaml

ci_path, cov_path = sys.argv[1], sys.argv[2]
with open(ci_path, encoding="utf-8") as f:
    wf = yaml.safe_load(f)
steps = []
for job, body in (wf.get("jobs") or {}).items():
    for st in (body or {}).get("steps") or []:
        if "run" not in st:
            continue
        name = st.get("name")
        key = name if name else "run:" + str(st["run"]).strip().splitlines()[0].strip()
        steps.append((job, key))

groups, rows = set(), []
with open(cov_path, encoding="utf-8") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if parts[0] == "группа" and len(parts) == 2:
            groups.add(parts[1])
        elif parts[0] == "шаг" and len(parts) == 4:
            rows.append((parts[1], parts[2], parts[3]))
        elif line.strip():
            print(f"НАХОДКА строка режима ведомости не разобрана: {line.rstrip()}")
            rows.append(("?", "?", "?"))

print(f"шагов с run в конвейере: {len(steps)} · строк ведомости: {len(rows)} · групп хука: {len(groups)}")
if not steps or not rows or not groups:
    print("ПРЕДПОСЫЛКА: пустой разбор — судить нечего")
    sys.exit(2)

findings = 0
step_set = set(steps)
for s in sorted(set(x for x in steps if steps.count(x) > 1)):
    print(f"НАХОДКА шаг конвейера неразличим по ключу: {s[0]}|{s[1]}"); findings += 1
seen = set()
for job, key, out in rows:
    if (job, key) in seen:
        print(f"НАХОДКА дубль строки ведомости: {job}|{key}"); findings += 1
    seen.add((job, key))
    kind, _, arg = out.partition(":")
    if kind not in ("группа", "не-гоняется", "не-проверка") or not arg:
        print(f"НАХОДКА исход не из словаря: {job}|{key}|{out}"); findings += 1
    elif kind == "группа" and arg not in groups:
        print(f"НАХОДКА группы «{arg}» у хука нет: {job}|{key}"); findings += 1
    if (job, key) not in step_set:
        print(f"НАХОДКА строка ведомости без шага конвейера: {job}|{key}"); findings += 1
for job, key in steps:
    if (job, key) not in seen:
        print(f"НАХОДКА шаг конвейера без строки ведомости: {job}|{key}"); findings += 1
print(f"находок: {findings}")
sys.exit(1 if findings else 0)
PY
}

# ── ОСЬ B: ПЕСОЧНИЦА И СУДЬЯ ТЕКСТА ОБХОДА ──────────────────────────────────
#
# Подпись и правило ветки судит страж до обхода — учётная запись фикстуры
# своя, коммит `#1 …`, ветка `1` (форма та же, что у соседних проб).
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
printf '[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' > "$GIT_CONFIG_GLOBAL"
unset KANAME_SKIP_PREPUSH GOFLAGS

# Временный каталог вне всякого репозитория — физическим путём.
probe_dir="$(cd "$work" 2>/dev/null && pwd -P)"
while [ -n "$probe_dir" ]; do
    [ -e "$probe_dir/.git" ] && { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — временный каталог внутри репозитория ($probe_dir)" >&2; exit 2; }
    parent="$(dirname "$probe_dir")"; [ "$parent" != "$probe_dir" ] || break; probe_dir="$parent"
done

# Потолок памяти песочнице не нужен: на пути обхода групп нет. `systemd-run`
# отказывает — хук печатает «потолок не выставлен» и идёт дальше сам.
stub="$work/bin"
mkdir -p "$stub"
printf '#!/usr/bin/env bash\nexit 1\n' > "$stub/systemd-run"
chmod +x "$stub/systemd-run"

# Судья подписи — НАСТОЯЩИЙ (kaname#459): хук до обхода собирает его
# `go build ./tools/clagate/cmd/clagate`, а исходников судьи в песочнице нет.
# Переходник уводит в корень ЭТОГО дерева ровно эту сборку, без VCS-отметки;
# прочие вызовы go идут настоящему go как есть. Нет go — песочницы не собрать.
REAL_GO="$(command -v go 2>/dev/null || true)"
if [ -n "$REAL_GO" ]; then
    [ -d "$ROOT/tools/clagate/cmd/clagate" ] || { echo "prepush-coverage-inject: НЕ ИСПОЛНЯЛОСЬ — нет $ROOT/tools/clagate/cmd/clagate" >&2; exit 2; }
    cat > "$stub/go" <<GO
#!/usr/bin/env bash
case " \$* " in
    *" ./tools/clagate/cmd/clagate "*)
        cd '$ROOT' || exit 97
        export GOFLAGS="\${GOFLAGS:+\$GOFLAGS }-buildvcs=false" ;;
esac
exec '$REAL_GO' "\$@"
GO
    chmod +x "$stub/go"
fi

# sandbox_ledger <каталог> — ведомость подписи песочницы: её учётная запись своя.
sandbox_ledger() {
    printf 'scope:\n  - .\nowners:\n  - email: probe@example.invalid\n    note: корневая учётная запись песочницы — подпись опыта\nsignatories: []\nwaivers: []\n' \
        > "$1/cla-ledger.yaml"
}

# bypass_case <имя> <хук> — выставляет out, rc, pushed.
bypass_case() {
    local d="$work/$1"
    [ -n "$REAL_GO" ] || return 1
    mkdir -p "$d/scripts/hooks" || return 1
    cp "$2" "$d/scripts/hooks/pre-push" || return 1
    local f
    for f in install.sh prepush-rule.sh branch-rule.sh prepush-added-files.sh prepush-classify.sh; do
        cp "$ROOT/scripts/hooks/$f" "$d/scripts/hooks/$f" || return 1
    done
    # Перечень исключений стража blob'ов НЕ копируется: его строки судят дерево
    # продукта, в песочнице им исключать нечего, и страж отверг бы их как
    # пережившие предмет — отказ пришёл бы от соседа, а не от обхода.
    chmod +x "$d/scripts/hooks/"*
    echo probe > "$d/README.txt"
    sandbox_ledger "$d"
    git -C "$d" init -q . && git -C "$d" add -A && git -C "$d" commit -q -m "#1 фикстура опыта" || return 1
    git init --bare -q "$d.git" && git -C "$d" remote add origin "$d.git" || return 1
    ( cd "$d" && bash scripts/hooks/install.sh install ) >/dev/null 2>&1 || return 1
    out="$(cd "$d" && KANAME_SKIP_PREPUSH=1 PATH="$stub:$PATH" git push origin HEAD:refs/heads/1 2>&1)"
    rc=$?
    pushed=0
    # Наличие ссылки на удалённом песочницы — перечнем ссылок, а не вопросом
    # об истории: вершины здесь нет, есть «доехала ли ссылка».
    [ -n "$(git -C "$d.git" for-each-ref --format='%(refname)' refs/heads/1)" ] && pushed=1
    return 0
}

# judge_bypass <хук> — по выводу out (вызывать после bypass_case тем же хуком):
# печатает недостачи строкой «НЕТ …», код 0 — всё на месте.
judge_bypass() {
    local hook="$1" miss=0 block l_job l_key l_out label line
    printf '%s' "$out" | grep -q 'pre-push:' || { echo "ПРЕДПОСЫЛКА: хук не исполнялся — ни одной строки «pre-push:»"; return 2; }
    if [ "$rc" -ne 0 ]; then
        echo "НЕТ кода 0 на обходе: код $rc — хвост вывода хука:"
        printf '%s\n' "$out" | grep -v '^  [a-z]*: ' | tail -n 15 | sed 's/^/       | /'
        miss=$((miss + 1))
    fi
    [ "$pushed" -eq 1 ] || { echo "НЕТ ссылки на удалённом: обход не пропустил отправку"; miss=$((miss + 1)); }
    printf '%s' "$out" | grep -q 'проверки пропущены по KANAME_SKIP_PREPUSH=1' \
        || { echo "НЕТ строки обхода «проверки пропущены по KANAME_SKIP_PREPUSH=1»"; miss=$((miss + 1)); }
    printf '%s' "$out" | grep -q 'исполнено групп проверок: 0$' \
        || { echo "НЕТ строки «исполнено групп проверок: 0»"; miss=$((miss + 1)); }
    block="$(printf '%s\n' "$out" | sed -n '/ЗДЕСЬ НЕ ГОНЯЛОСЬ/,/^$/p')"
    [ -n "$block" ] || { echo "НЕТ перечня «ЗДЕСЬ НЕ ГОНЯЛОСЬ»"; miss=$((miss + 1)); }
    local pairs=0
    while IFS=$'\t' read -r kind l_job l_key l_out; do
        [ "$kind" = шаг ] || continue
        case "$l_out" in не-гоняется:*) label="${l_out#не-гоняется:}" ;; *) continue ;; esac
        pairs=$((pairs + 1))
        line="$(printf '%s\n' "$block" | grep -F -- "  $l_job: " || true)"
        printf '%s' "$line" | grep -qF -- "$label" \
            || { echo "НЕТ в перечне: $l_job — $label"; miss=$((miss + 1)); }
    done < <(bash "$hook" --kaname-prepush-coverage 2>/dev/null)
    [ "$pairs" -gt 0 ] || { echo "ПРЕДПОСЫЛКА: у ведомости хука ни одного шага «не-гоняется»"; return 2; }
    echo "пар «задание · метка» сверено: $pairs · недостач: $miss"
    [ "$miss" -eq 0 ]
}

# ── КОНТРОЛЬ: настоящий хук, настоящий конвейер ─────────────────────────────
echo "── ось A: ведомость хука против ci.yml"
res="$(judge_ledger "$HOOK" "$CI")"; jrc=$?
printf '%s\n' "$res" | sed 's/^/     /'
case "$jrc" in
    0) ok "ведомость сошлась с конвейером в обе стороны" ;;
    1) bad "ведомость разошлась с конвейером (находки выше)" ;;
    *) void "ось A не исполнялась: $(printf '%s' "$res" | tail -1)" ;;
esac

echo "── ось B: обход громок — по тексту вывода настоящего хука"
if ! bypass_case control "$HOOK"; then
    void "песочница контроля не собрана$([ -n "$REAL_GO" ] || echo ' — нет go: судью подписи хука не собрать')"
else
    res="$(judge_bypass "$HOOK")"; brc=$?
    printf '%s\n' "$res" | sed 's/^/     /'
    case "$brc" in
        0) ok "обход: код 0, строка обхода, ноль исполненного и перечень всех меток ведомости" ;;
        1) bad "обход молчит о части непроверенного (недостачи выше)" ;;
        *) void "ось B не исполнялась: $(printf '%s' "$res" | tail -1)" ;;
    esac
fi

# ── ОСЬ C: НЕОТФОРМАТИРОВАННОЕ ОТВЕРГНУТО, БЛИЗНЕЦ ПРОХОДИТ ─────────────────
#
# module_case <имя> <тело fmt.go> [<хук> [<имя удалённого>]] — синтетический
# модуль с хуком (по умолчанию настоящим) и всеми его группами; отправка без
# обхода настоящим `git push -- <имя> …` (по умолчанию origin). Выставляет out, rc.
module_case() {
    local d="$work/$1" f hook="${3:-$HOOK}" rname="${4:-origin}"
    mkdir -p "$d/scripts/hooks" "$d/.github/scripts" || return 1
    cp "$hook" "$d/scripts/hooks/pre-push" || return 1
    for f in install.sh prepush-rule.sh branch-rule.sh prepush-added-files.sh prepush-classify.sh; do
        cp "$ROOT/scripts/hooks/$f" "$d/scripts/hooks/$f" || return 1
    done
    cp "$ROOT/.github/scripts/go-test-verdict.py" "$d/.github/scripts/" || return 1
    chmod +x "$d/scripts/hooks/"*
    printf 'module probe.invalid/fmtprobe\n\ngo 1.21\n' > "$d/go.mod"
    printf '%s\n' "$2" > "$d/fmt.go"
    printf 'package fmtprobe\n\nimport "testing"\n\nfunc TestFmtProbe(t *testing.T) {\n\tif Probe() != 1 {\n\t\tt.Fatal("Probe")\n\t}\n}\n' > "$d/fmt_test.go"
    printf '.PHONY: vet audit-list-filter\nvet:\n\t@go vet ./...\naudit-list-filter:\n\t@echo ok\n' > "$d/Makefile"
    sandbox_ledger "$d"
    git -C "$d" init -q . && git -C "$d" add -A && git -C "$d" commit -q -m "#1 фикстура опыта" || return 1
    git init --bare -q "$d.git" && git -C "$d" remote add -- "$rname" "$d.git" || return 1
    ( cd "$d" && bash scripts/hooks/install.sh install ) >/dev/null 2>&1 || return 1
    out="$(cd "$d" && PATH="$stub:$PATH" git push -- "$rname" HEAD:refs/heads/1 2>&1)"
    rc=$?
    return 0
}

echo "── ось C: неотформатированный файл отвергнут, отформатированный близнец проходит"
c_missing=""
for tool in go make gofmt; do command -v "$tool" >/dev/null 2>&1 || c_missing="$c_missing $tool"; done
if [ -n "$c_missing" ]; then
    void "ось C не исполнялась — нет в PATH:$c_missing"
    void "ось C (инъекция) не исполнялась — нет в PATH:$c_missing"
else
    if module_case fmt-twin "$(printf 'package fmtprobe\n\nfunc Probe() int {\n\treturn 1\n}')"; then
        if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'зелёное — исполнено 6 из 6 групп'; then
            ok "близнец C: отформатированный модуль проходит — исполнено 6 из 6"
        else
            bad "близнец C: отформатированный модуль отвергнут (код $rc): $(printf '%s' "$out" | grep -E 'красные|ОТКАЗ|НЕ ВЫПОЛНИЛОСЬ' | head -3)"
        fi
    else void "песочница близнеца C не собрана"; fi
    if module_case fmt-red "$(printf 'package fmtprobe\n\nfunc Probe() int {\nreturn    1\n}')"; then
        if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qE '^красные +: gofmt$' \
            && printf '%s' "$out" | grep -qx 'fmt.go'; then
            ok "инъекция C: неотформатированный fmt.go — отказ (код $rc), красная ровно группа gofmt, файл назван"
        else
            bad "инъекция C НЕ ПОЙМАНА как ждали (код $rc): $(printf '%s' "$out" | grep -E 'красные|требуется|ОТКАЗ|зелёное' | head -4)"
        fi
    else void "песочница инъекции C не собрана"; fi
fi

# ── ОСЬ D: СЛУЖЕБНЫЙ РЕЖИМ НЕДОСТИЖИМ ОТПРАВКОЙ (SEC-942-k1-1) ───────────────
#
# judge_gitform <coverage|scope> — по выводу out и коду rc отправки настоящим
# git на удалённый, названный доводом служебного режима; печатает недостачи
# строкой «НЕТ …» либо «ЛОЖЬ …», код 0 — проверки исполнены и о потолке не солгано.
judge_gitform() {
    local miss=0
    if ! printf '%s\n' "$out" | grep -qE '^(pre-push:|группа	)'; then
        echo "ПРЕДПОСЫЛКА: хук не исполнялся — ни строки «pre-push:», ни строки режима ведомости"; return 2
    fi
    if printf '%s\n' "$out" | grep -qE '^(группа|шаг)	'; then
        echo "ЛОЖЬ: отправка ушла в режим ведомости — стражи и проверки не исполнены (код $rc)"; miss=$((miss + 1))
    fi
    [ "$rc" -eq 0 ] || { echo "НЕТ кода 0: код $rc — $(printf '%s\n' "$out" | grep -E 'красные|ОТКАЗ|НЕ ВЫПОЛНИЛОСЬ' | head -3 | tr '\n' ';')"; miss=$((miss + 1)); }
    printf '%s' "$out" | grep -q 'зелёное — исполнено 6 из 6 групп' \
        || { echo "НЕТ строки «зелёное — исполнено 6 из 6 групп»: проверки не исполнены"; miss=$((miss + 1)); }
    if [ "$1" = scope ]; then
        # Переходник systemd-run песочницы отказывает: области нет, и хук обязан
        # сказать «не выставлен», а не напечатать потолок.
        if printf '%s' "$out" | grep -q 'pre-push: память — MemoryMax='; then
            echo "ЛОЖЬ: напечатан потолок памяти, а области нет (systemd-run песочницы отказывает)"; miss=$((miss + 1))
        fi
        printf '%s' "$out" | grep -q 'pre-push: память — потолок памяти не выставлен' \
            || { echo "НЕТ строки «потолок памяти не выставлен»"; miss=$((miss + 1)); }
    fi
    echo "недостач: $miss"
    [ "$miss" -eq 0 ]
}

# gitform_case <имя> <coverage|scope> <хук> — выставляет res и jrc.
FMT_OK="$(printf 'package fmtprobe\n\nfunc Probe() int {\n\treturn 1\n}')"
gitform_case() {
    local rname='--kaname-prepush-coverage'
    [ "$2" = scope ] && rname='--kaname-prepush-in-memory-scope'
    module_case "$1" "$FMT_OK" "$3" "$rname" || return 1
    res="$(judge_gitform "$2")"; jrc=$?
    return 0
}

echo "── ось D: служебный режим хука недостижим отправкой на удалённый с таким именем"
if [ -n "$c_missing" ]; then
    void "ось D (режим ведомости) не исполнялась — нет в PATH:$c_missing"
    void "ось D (область памяти) не исполнялась — нет в PATH:$c_missing"
else
    for mode in coverage scope; do
        if gitform_case "gitform-$mode" "$mode" "$HOOK"; then
            printf '%s\n' "$res" | sed 's/^/     /'
            case "$jrc" in
                0) ok "D/$mode: отправка на удалённый с именем служебного довода — проверки исполнены (6 из 6)$([ "$mode" = scope ] && echo ', потолок не объявлен ложно')" ;;
                1) bad "D/$mode: служебный режим достижим отправкой (недостачи выше)" ;;
                *) void "D/$mode не исполнялась: $(printf '%s' "$res" | tail -1)" ;;
            esac
        else void "песочница D/$mode не собрана"; fi
    done
fi

if [ "$SELF_TEST" -eq 1 ]; then
    # expect_red <имя> <код судьи> <вывод судьи> <обязательная подстрока>
    expect_red() {
        if [ "$2" -eq 1 ] && printf '%s' "$3" | grep -qF -- "$4"; then ok "инъекция $1: красное, названо «$4»"
        elif [ "$2" -eq 2 ]; then void "инъекция $1: судья не исполнялся — $(printf '%s' "$3" | tail -1)"
        else bad "инъекция $1 НЕ ПОЙМАНА (код $2), ждали «$4»: $(printf '%s' "$3" | tail -3)"; fi
    }

    echo "── A1: шаг конвейера с run: без строки ведомости"
    cp "$CI" "$work/ci-a1.yml"
    python3 - "$work/ci-a1.yml" <<'PY'
import sys, yaml
p = sys.argv[1]
wf = yaml.safe_load(open(p, encoding="utf-8"))
wf["jobs"]["proto"]["steps"].append({"name": "инъекция — проверка без строки ведомости", "run": "true"})
yaml.safe_dump(wf, open(p, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)
PY
    res="$(judge_ledger "$HOOK" "$work/ci-a1.yml")"; expect_red A1 $? "$res" "без строки ведомости: proto|инъекция — проверка без строки ведомости"

    echo "── A2: законный близнец — шаг uses: без run:"
    cp "$CI" "$work/ci-a2.yml"
    python3 - "$work/ci-a2.yml" <<'PY'
import sys, yaml
p = sys.argv[1]
wf = yaml.safe_load(open(p, encoding="utf-8"))
wf["jobs"]["proto"]["steps"].append({"name": "близнец — действие", "uses": "actions/checkout@v7"})
yaml.safe_dump(wf, open(p, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False)
PY
    res="$(judge_ledger "$HOOK" "$work/ci-a2.yml")"; r=$?
    if [ "$r" -eq 0 ]; then ok "близнец A2: шаг uses: в предмет не входит — молчание"
    else bad "близнец A2: код $r — судья судит не предмет: $(printf '%s' "$res" | tail -3)"; fi

    echo "── A3: строка ведомости без шага конвейера"
    cp "$HOOK" "$work/hook-a3"
    sed -i "s/^CI_LEDGER='/CI_LEDGER='proto|инъекция — шага нет|не-гоняется:инъекция\n/" "$work/hook-a3"
    if grep -q '^CI_LEDGER=.proto|инъекция — шага нет' "$work/hook-a3"; then
        res="$(judge_ledger "$work/hook-a3" "$CI")"; expect_red A3 $? "$res" "без шага конвейера: proto|инъекция — шага нет"
    else void "инъекция A3 не легла в копию хука"; fi

    echo "── B1: обход молчит — exit 0 до перечня"
    cp "$HOOK" "$work/hook-b1"
    sed -i 's/^\( *\)finish 0 "pre-push: проверки пропущены/\1exit 0; finish 0 "pre-push: проверки пропущены/' "$work/hook-b1"
    if grep -q 'exit 0; finish 0 "pre-push: проверки пропущены' "$work/hook-b1"; then
        if bypass_case b1 "$work/hook-b1"; then
            res="$(judge_bypass "$work/hook-b1")"; r=$?
            if [ "$rc" -eq 0 ]; then ok "B1: молчаливый обход дал тот же код 0 — код его не отличает"
            else bad "B1: молчаливый обход дал код $rc — инъекция легла не туда"; fi
            expect_red B1 "$r" "$res" "НЕТ строки обхода"
        else void "песочница B1 не собрана"; fi
    else void "инъекция B1 не легла в копию хука"; fi

    echo "── B2: перечень обрезан до двух строк"
    cp "$HOOK" "$work/hook-b2"
    sed -i 's/^\( *\)ledger_not_run_lines$/\1ledger_not_run_lines | head -n 2/' "$work/hook-b2"
    if grep -q 'ledger_not_run_lines | head -n 2$' "$work/hook-b2"; then
        if bypass_case b2 "$work/hook-b2"; then
            res="$(judge_bypass "$work/hook-b2")"; expect_red B2 $? "$res" "НЕТ в перечне: proto — buf lint"
        else void "песочница B2 не собрана"; fi
    else void "инъекция B2 не легла в копию хука"; fi

    # D1, D2 — прежняя форма признака служебного режима: один текст первого
    # довода, без числа доводов. Каждая инъекция роняет ровно свой признак.
    echo "── D1: режим ведомости узнаётся по одному тексту первого довода"
    cp "$HOOK" "$work/hook-d1"
    sed -i "s/^if \[ \"\$#\" -eq 1 \] && \[ \"\$1\" = '--kaname-prepush-coverage' \]; then\$/if [ \"\${1:-}\" = '--kaname-prepush-coverage' ]; then/" "$work/hook-d1"
    if grep -q "^if \[ \"\${1:-}\" = '--kaname-prepush-coverage' \]; then\$" "$work/hook-d1"; then
        if [ -n "$c_missing" ]; then void "D1 не исполнялась — нет в PATH:$c_missing"
        elif gitform_case d1 coverage "$work/hook-d1"; then expect_red D1 "$jrc" "$res" "ЛОЖЬ: отправка ушла в режим ведомости"
        else void "песочница D1 не собрана"; fi
    else void "инъекция D1 не легла в копию хука"; fi

    echo "── D2: перезапуск в области узнаётся по одному тексту первого довода"
    cp "$HOOK" "$work/hook-d2"
    sed -i 's/^if \[ "\$#" -eq 3 \] && \[ "\$1" = "\$SCOPE_ARG" \]; then$/if [ "${1:-}" = "$SCOPE_ARG" ]; then/' "$work/hook-d2"
    if grep -q '^if \[ "${1:-}" = "\$SCOPE_ARG" \]; then$' "$work/hook-d2"; then
        if [ -n "$c_missing" ]; then void "D2 не исполнялась — нет в PATH:$c_missing"
        elif gitform_case d2 scope "$work/hook-d2"; then expect_red D2 "$jrc" "$res" "ЛОЖЬ: напечатан потолок памяти"
        else void "песочница D2 не собрана"; fi
    else void "инъекция D2 не легла в копию хука"; fi
fi

echo
echo "=== prepush-coverage-inject: перепись ==="
echo "утверждений исполнено : $checks"
echo "из них не сошлось     : $failed"
echo "условие не создано    : $unmet  (в зачёт прохода НЕ идёт)"
want=6; [ "$SELF_TEST" -eq 1 ] && want=14
echo "утверждений объявлено : $want"
if [ "$failed" -gt 0 ]; then
    echo "ОТКАЗ: перечень непроверенного хука разошёлся с конвейером либо обход молчит." >&2; exit 1
fi
if [ "$unmet" -gt 0 ] || [ "$checks" -ne "$want" ]; then
    echo "НЕ ИСПОЛНЯЛОСЬ: объём исполненного разошёлся с объявленным — вердикта нет." >&2; exit 2
fi
echo "ЗЕЛЁНОЕ: перечень непроверенного выведен из конвейера и печатается на пути обхода."
