#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-classes-inject.sh — опыт над классами до отправки
# (scripts/hooks/prepush-classes.py и его провязкой в scripts/hooks/pre-push,
# kaname#822). Каждая инъекция отличается от своего законного близнеца ОДНИМ
# фактом; судят настоящие файлы конвейера, подменён только трекер — переходником
# `gh` в PATH, отвечающим захваченными либо заданными ответами.
#
# ─────────────────────────────────────────────────────────────────────────────
# ОСИ
#
#  P. ВЫБОР ПО ТРОНУТЫМ ПУТЯМ. Синтетический репозиторий, `origin` — голый
#     репозиторий за адресом площадки (insteadOf), на нём `main` с оснасткой:
#     (P1) тронут Dockerfile — выбрано ровно «правило запроса»; (P2) запись ревью —
#     и «записи ревью»; (P3) коллекция набора — «долг набора»; (P4) объявление
#     e2e-newman.yml — «долг набора», (P4b) близнец: ci.yml — не выбран; (P5) копия каталога прав — «сверка с
#     краем»; (P6) ветка от головы эпика с открытым запросом в main — база —
#     эпик, а не main; (P7) открытый запрос ветки — база и заголовок из запроса;
#     (P8) строка переписи хука — ОДНА и при пустом выборе (отправка только
#     снимает ветку): «0 из 4», а не «0\n0 из 4»; (P8b) близнец — выбор из одного
#     класса назван по имени.
#  R. ПРАВИЛО ЗАПРОСА. (R1) свои коммиты «#51 …» — зелёное; (R2) инъекция: свой
#     коммит «#52 …» на ветке 51 — красное с текстом конвейера; (R3) инъекция:
#     заголовок запроса «[#51] …» — красное «заголовок не начинается»; (R4)
#     близнец: заголовок «#51 …» — зелёное, и «заголовок и тело судятся»;
#     (R5) инъекция: базы ветки нет в клоне — pr-rule-check.sh выходит 2, а
#     правило запроса — 3, не зелёное; (R6) вторая ветка зелёная — третий исход
#     первой ею не прощается; (R7) вторая ветка красная — красное старше третьего
#     исхода (код 1).
#  S. ЗАПИСИ РЕВЬЮ. Запись — форма самопробы гейта (`silent_record`), ответ
#     трекера — захваченный гейтом: (S1) событие опубликовано, блока event нет —
#     красное «без блока event»; (S2) близнец: события в ответе нет — зелёное;
#     (S3) трекер не ответил — третий исход (код 3), а не зелёное.
#  D. ДОЛГ НАБОРА. Рабочая копия ствола этого дерева, держатели — открыты по
#     ответу переходника: (D1) близнец — зелёное; (D2) инъекция: коллекция без
#     записи ведомости — красное «разошлась с деревом»; (D3) трекер не ответил —
#     код 3.
#  H. ПРОВЯЗКА В ХУК. Настоящий хук на синтетическом модуле: (H2) близнец — 0,
#     группа «правило запроса» исполнена, строка переписи «классы до отправки»
#     есть; (H3) помощника нет — код 2, а не тишина; (H1) форма круга kaname#829:
#     коммит «#52 …» уже на удалённом, ветка 51 его продолжает — страж правила
#     (только новые коммиты) молчит, хук выходит 1 и называет «правило запроса»;
#     (H4) тронута запись ревью, событие на трекере не опубликовано — группа
#     «записи ревью» исполнена, хук 0, класс назван в строке переписи; (H5)
#     тронута коллекция набора, гейта долга в дереве нет — группа «долг набора»
#     исполнена и дала третий исход: хук 2, «без условия: долг набора»; (H6)
#     инъекция к H4: нет pr-rule-check.sh — код 3 класса в хуке даёт «без
#     условия: правило запроса» и код 2, а не зелёное.
#     Каждая группа, которую добавляет выбор, держится своей осью H: снятая
#     строка `groups+=` роняет ровно её.
#  T. ЦЕНА. Время выбора и правила запроса на нетронутых классах (P1) — числом;
#     потолок — 10 % от 215 с прежнего хука (замер kaname#822 @9ccdc8d86), то
#     есть 21 с. Сетевую цену ось НЕ меряет: переходник `gh` отвечает
#     мгновенно, fetch идёт в локальный голый репозиторий. На настоящем
#     репозитории выбор стоит 3,4–3,7 с (три прогона check-verifier, kaname#822
#     круг 2) — тоже в потолке, но этим числом, а не числом оси.
#
# Провязан в задание сборки конвейера (`ci.yml`, шаг «классы до отправки»).
#
# Исходы: 0 — все оси исполнены и сошлись · 1 — хотя бы одно утверждение не
# сошлось · 2 — предпосылка не создана.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "prepush-classes-inject: НЕ ИСПОЛНЯЛОСЬ — не рабочая копия git" >&2; exit 2; }
cd "$ROOT" || exit 2
CLS="$ROOT/scripts/hooks/prepush-classes.py"
need_files=("$CLS" "$ROOT/scripts/hooks/pre-push" "$ROOT/scripts/hooks/prepush-classify.sh"
    "$ROOT/scripts/hooks/prepush-rule.sh" "$ROOT/scripts/hooks/branch-rule.sh" "$ROOT/scripts/hooks/commit-msg"
    "$ROOT/scripts/hooks/prepush-edge.sh" "$ROOT/.github/scripts/go-test-verdict.py"
    "$ROOT/.github/scripts/affected.py" "$ROOT/.github/ci-paths.json" "$ROOT/.github/scripts/pr-rule-check.sh"
    "$ROOT/.github/scripts/review-event-silence.py" "$ROOT/.github/scripts/newman-suite-debt.py")
need_files+=("$ROOT/.gitignore")
for f in "${need_files[@]}"; do
    [ -f "$f" ] || { echo "prepush-classes-inject: НЕ ИСПОЛНЯЛОСЬ — нет $f" >&2; exit 2; }
done
for t in git python3 go; do
    command -v "$t" >/dev/null 2>&1 || { echo "prepush-classes-inject: НЕ ИСПОЛНЯЛОСЬ — нет $t в PATH" >&2; exit 2; }
done

checks=0; failed=0
ok()  { checks=$((checks + 1)); echo "  ok   — $1"; }
bad() { checks=$((checks + 1)); failed=$((failed + 1)); echo "  БЕДА — $1" >&2; }
unmet() { echo "prepush-classes-inject: УСЛОВИЕ НЕ СОЗДАНО — $1" >&2; exit 2; }

work="$(mktemp -d)" || unmet "временный каталог не создан"
wt=""
cleanup() {
    [ -z "$wt" ] || git -C "$ROOT" worktree remove --force "$wt" >/dev/null 2>&1
    rm -rf "$work"
}
trap cleanup EXIT
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
unset KACHO_MONOREPO GITHUB_REPOSITORY PR_TITLE PR_BODY
cat > "$GIT_CONFIG_GLOBAL" <<CFG
[user]
	name = probe
	email = probe@example.invalid
[commit]
	gpgsign = false
[init]
	defaultBranch = main
[url "$work/origin.git"]
	insteadOf = https://github.com/PRO-Robotech/probe.git
CFG

# ── Переходник трекера ──────────────────────────────────────────────────────
# Отвечает из $FAKE_GH_DIR: pr-head-<ветка>.json, pr-base-<база>.json,
# api/<путь с «_» вместо / ? = &>.json; состояние задачи — $FAKE_GH_STATE
# («none» — трекер не ответил). Всякий иной вызов — отказ: опыт не должен
# дойти до настоящей площадки.
mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'GH'
#!/usr/bin/env bash
d="${FAKE_GH_DIR:?}"
printf '%s\n' "$*" >> "$d/calls.log"
if [ "${1:-}" = pr ] && [ "${2:-}" = list ]; then
    head=""; base=""
    while [ "$#" -gt 0 ]; do
        case "$1" in --head) head="$2"; shift ;; --base) base="$2"; shift ;; esac
        shift
    done
    if [ -n "$head" ]; then f="$d/pr-head-$head.json"; else f="$d/pr-base-$base.json"; fi
    if [ -f "$f" ]; then cat "$f"; else echo '[]'; fi
    exit 0
fi
if [ "${1:-}" = api ] && [ "${2:-}" = --paginate ]; then
    # С `--jq` площадка печатает по объекту на строку — так и отвечаем.
    f="$d/api/$(printf '%s' "$3" | tr '/?=&' '____').json"
    [ -f "$f" ] && { python3 -c 'import json,sys; [print(json.dumps(x, ensure_ascii=False)) for x in json.load(open(sys.argv[1]))]' "$f"; exit 0; }
    echo "gh: Not Found (HTTP 404)" >&2; exit 1
fi
if [ "${1:-}" = api ] && [ "${3:-}" = --jq ]; then
    [ "${FAKE_GH_STATE:-open}" = none ] && { echo "gh: connection refused" >&2; exit 1; }
    echo "${FAKE_GH_STATE:-open}"; exit 0
fi
echo "fake gh: вызов не предусмотрен опытом: $*" >&2
exit 1
GH
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"
fresh_gh() { export FAKE_GH_DIR="$work/gh.$1"; mkdir -p "$FAKE_GH_DIR/api"; : > "$FAKE_GH_DIR/calls.log"; }

# ── Синтетический репозиторий с оснасткой на main ───────────────────────────
# Коммит правила (scripts/hooks/commit-msg) датирован раньше прочих: от него
# T0, и коммиты ветки судятся как новые.
tool() { # $1 — каталог репозитория
    mkdir -p "$1/scripts/hooks" "$1/.github/scripts"
    for f in pre-push prepush-classify.sh prepush-rule.sh branch-rule.sh commit-msg prepush-edge.sh prepush-classes.py; do
        cp "$ROOT/scripts/hooks/$f" "$1/scripts/hooks/"
    done
    for f in go-test-verdict.py affected.py pr-rule-check.sh review-event-silence.py; do
        cp "$ROOT/.github/scripts/$f" "$1/.github/scripts/"
    done
    cp "$ROOT/.github/ci-paths.json" "$1/.github/"
    # .gitignore ствола: без него `git add -A` фикстуры уносит в коммит
    # __pycache__ помощника, и неопознанный путь делает выбор полным.
    cp "$ROOT/.gitignore" "$1/"
    chmod +x "$1/scripts/hooks/"*
}
at() { GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" "${@:2}"; }
make_repo() { # $1 — каталог; голый origin общий для оси
    local d="$1"
    mkdir -p "$d" && git -C "$d" init -q . || return 1
    tool "$d"
    printf 'module probe.invalid/classes\n\ngo 1.21\n' > "$d/go.mod"
    printf 'package classes\n\nimport "testing"\n\nfunc TestClassesProbe(t *testing.T) {}\n' > "$d/classes_test.go"
    printf '.PHONY: vet audit-list-filter\nvet:\n\t@go vet ./...\naudit-list-filter:\n\t@echo ok\n' > "$d/Makefile"
    printf 'probe\n' > "$d/README.md"
    git -C "$d" add -A
    at "2026-01-01T00:00:00Z" git -C "$d" commit -q -m "#1 оснастка фикстуры" || return 1
    rm -rf "$work/origin.git"
    git init --bare -q "$work/origin.git"
    git -C "$d" remote add origin https://github.com/PRO-Robotech/probe.git
    git -C "$d" push -q --no-verify origin main 2>/dev/null || return 1
    git -C "$d" fetch -q origin
}
# commit_on <каталог> <путь> <первая строка> — правка файла и коммит датой после T0.
commit_on() {
    mkdir -p "$(dirname "$1/$2")"
    printf '%s\n' "$3 $RANDOM" >> "$1/$2"
    git -C "$1" add -A && at "2026-02-01T00:00:00Z" git -C "$1" commit -q -m "$3"
}
plan_of() { # $1 — каталог, $2 — ветка; выставляет pout, prc, pdir
    pdir="$work/plan.$RANDOM"
    pout="$(cd "$1" && printf 'refs/heads/%s %s refs/heads/%s %s\n' "$2" "$(git rev-parse HEAD)" "$2" "0000000000000000000000000000000000000000" \
        | python3 scripts/hooks/prepush-classes.py plan --out "$pdir" --remote origin 2>&1)"; prc=$?
}
classes_of() { tr '\n' ' ' < "$pdir/classes" | sed 's/ $//'; }

# ── ОСЬ P ───────────────────────────────────────────────────────────────────
echo "ось P — выбор по тронутым путям"
fresh_gh P
R="$work/P"; make_repo "$R" || unmet "синтетический репозиторий не построен"
git -C "$R" checkout -q -b 51
# Dockerfile карта относит к образу и стенду — не к четырём классам; README не
# опознаёт ни одна группа, и выбор стал бы полным (неопознанное — целиком).
commit_on "$R" Dockerfile "#51 правка Dockerfile"
t0=$(date +%s.%N); plan_of "$R" 51; t1=$(date +%s.%N)
[ "$prc" -eq 0 ] && [ "$(classes_of)" = "request" ] && ok "P1: тронут Dockerfile — выбрано только правило запроса" || bad "P1: код $prc, классы «$(classes_of)»: $pout"
plan_secs="$(python3 -c "print(round($t1-$t0,2))")"
for c in "docs/specs/reviews/x/y.yaml:reviews:P2 запись ревью" "tests/newman/collections/x.postman_collection.json:debt:P3 коллекция набора" \
         ".github/workflows/e2e-newman.yml:debt:P4 объявление e2e-newman.yml" \
         "internal/apps/kaname/seed/embedded/permission_catalog.json:edge:P5 копия каталога прав"; do
    IFS=: read -r path cls label <<< "$c"
    git -C "$R" checkout -q -B 51 origin/main
    commit_on "$R" "$path" "#51 правка"
    plan_of "$R" 51
    grep -qx "$cls" "$pdir/classes" 2>/dev/null && grep -qx request "$pdir/classes" \
        && ok "$label — выбран «$cls»" || bad "$label: код $prc, классы «$(classes_of)»"
done
# P4b — законный близнец P4: объявление ДРУГОГО процесса долга не выбирает.
git -C "$R" checkout -q -B 51 origin/main
commit_on "$R" .github/workflows/ci.yml "#51 правка"
plan_of "$R" 51
! grep -qx debt "$pdir/classes" && ok "P4b: объявление ci.yml — долг не выбран" || bad "P4b: классы «$(classes_of)»"
# P6: голова эпика 50 с открытым запросом в main; ветка 51 — от неё.
git -C "$R" checkout -q -B 50 origin/main
commit_on "$R" README.md "#50 эпик"
git -C "$R" push -q --no-verify origin 50 2>/dev/null && git -C "$R" fetch -q origin
printf '[{"headRefName":"50"}]\n' > "$FAKE_GH_DIR/pr-base-main.json"
git -C "$R" checkout -q -B 51 50
commit_on "$R" README.md "#51 полоса"
plan_of "$R" 51
printf '%s' "$pout" | grep -q 'ветка 51 @ .* → база 50 @' && ok "P6: база — голова эпика, а не main" || bad "P6: $pout"
printf '[{"number":7,"title":"#51 полоса","body":"тело","baseRefName":"main","isDraft":true}]\n' > "$FAKE_GH_DIR/pr-head-51.json"
plan_of "$R" 51
printf '%s' "$pout" | grep -q 'база main @.*база запроса #7 · заголовок и тело судятся' && ok "P7: база и заголовок — из открытого запроса" || bad "P7: $pout"
# P8 — отправка только снимает ветку: выбирать нечего, строка переписи одна.
p8="$work/plan.P8"
(cd "$R" && printf 'refs/heads/51 %s refs/heads/51 %s\n' "0000000000000000000000000000000000000000" "$(git rev-parse HEAD)" \
    | python3 scripts/hooks/prepush-classes.py plan --out "$p8" --remote origin >/dev/null 2>&1); p8rc=$?
[ "$p8rc" -eq 0 ] && [ ! -s "$p8/classes" ] && [ "$(wc -l < "$p8/note")" -eq 1 ] \
    && grep -qx '0 из 4 выбрано по тронутым путям — строки «классы до отправки» выше' "$p8/note" \
    && ok "P8: пустой выбор — строка переписи одна, «0 из 4»" || bad "P8: код $p8rc, строка «$(cat -A "$p8/note" 2>&1)»"
git -C "$R" checkout -q -B 51 origin/main
commit_on "$R" Dockerfile "#51 правка Dockerfile"
plan_of "$R" 51
[ "$(wc -l < "$pdir/note")" -eq 1 ] && grep -qx '1 из 4 выбрано по тронутым путям: правило запроса — строки «классы до отправки» выше' "$pdir/note" \
    && ok "P8b: близнец — один класс назван по имени" || bad "P8b: строка «$(cat "$pdir/note" 2>&1)»: $pout"

# ── ОСЬ R ───────────────────────────────────────────────────────────────────
echo "ось R — правило запроса"
fresh_gh R
R="$work/R"; make_repo "$R" || unmet "синтетический репозиторий не построен"
git -C "$R" checkout -q -b 51
commit_on "$R" README.md "#51 правка"
req() { plan_of "$R" 51; rout="$(cd "$R" && python3 scripts/hooks/prepush-classes.py request "$pdir" 2>&1)"; rrc=$?; }
req
[ "$rrc" -eq 0 ] && printf '%s' "$rout" | grep -q 'заголовок и тело — НЕ судились' && ok "R1: свои коммиты по форме — зелёное, неспрошенное названо" || bad "R1: код $rrc: $rout"
commit_on "$R" README.md "#52 чужой номер"
req
[ "$rrc" -eq 1 ] && printf '%s' "$rout" | grep -q '«#52» на ветке «51»: первая строка ветки-номера несёт её номер' && ok "R2: чужой номер у своего коммита — красное текстом конвейера" || bad "R2: код $rrc: $rout"
git -C "$R" reset -q --hard HEAD~1
printf '[{"number":8,"title":"[#51] правка","body":"тело","baseRefName":"main","isDraft":false}]\n' > "$FAKE_GH_DIR/pr-head-51.json"
req
[ "$rrc" -eq 1 ] && printf '%s' "$rout" | grep -q 'заголовок не начинается с «#<N> »: «\[#51\] правка»' && ok "R3: заголовок «[#51]» — красное" || bad "R3: код $rrc: $rout"
printf '[{"number":8,"title":"#51 правка","body":"тело","baseRefName":"main","isDraft":false}]\n' > "$FAKE_GH_DIR/pr-head-51.json"
req
[ "$rrc" -eq 0 ] && printf '%s' "$rout" | grep -q 'судилось: заголовок, тело' && ok "R4: заголовок «#51 » — зелёное, заголовок судился" || bad "R4: код $rrc: $rout"
# R5–R7: план R4 с одним изменённым фактом — базы ветки нет в клоне. Судит
# настоящий pr-rule-check.sh, его код 2 («коммита … в клоне нет») — вход оси.
absent="ffffffffffffffffffffffffffffffffffffffff"
# reqv <ветки>: «g» — ветка как в плане, «u» — та же с базой вне клона.
reqv() {
    python3 - "$pdir/plan.json" "$absent" "$@" <<'PY'
import json, sys
f, absent, kinds = sys.argv[1], sys.argv[2], sys.argv[3:]
doc = json.load(open(f))
one = doc["refs"][0]
doc["refs"] = [dict(one, base_sha=absent) if k == "u" else dict(one) for k in kinds]
json.dump(doc, open(f, "w"), ensure_ascii=False)
PY
    rout="$(cd "$R" && python3 scripts/hooks/prepush-classes.py request "$pdir" 2>&1)"; rrc=$?
}
plan_of "$R" 51; reqv u
[ "$rrc" -eq 3 ] && printf '%s' "$rout" | grep -q "коммита $absent в клоне нет" && printf '%s' "$rout" | grep -q 'не выполнилось 1' \
    && ok "R5: pr-rule-check не смог судить (код 2) — правило запроса 3, не зелёное" || bad "R5: код $rrc: $rout"
plan_of "$R" 51; reqv g u
[ "$rrc" -eq 3 ] && printf '%s' "$rout" | grep -q 'судилось веток 2 · красных 0 · не выполнилось 1' \
    && ok "R6: зелёная соседняя ветка третий исход не прощает — код 3" || bad "R6: код $rrc: $rout"
commit_on "$R" README.md "#52 чужой номер"
plan_of "$R" 51; reqv g u
[ "$rrc" -eq 1 ] && printf '%s' "$rout" | grep -q 'судилось веток 2 · красных 1 · не выполнилось 1' \
    && ok "R7: красная соседняя ветка старше третьего исхода — код 1" || bad "R7: код $rrc: $rout"
git -C "$R" reset -q --hard HEAD~1

# ── ОСЬ S ───────────────────────────────────────────────────────────────────
echo "ось S — записи ревью"
fresh_gh S
R="$work/S"; make_repo "$R" || unmet "синтетический репозиторий не построен"
git -C "$R" checkout -q -b 51
rec="$(cd "$ROOT/.github/scripts" && python3 -c '
import importlib.util, json, sys
s = importlib.util.spec_from_file_location("s", "review-event-silence.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
json.dump({"path": m.RECORD_PATH, "text": m.silent_record(), "event": m.CAPTURED_EVENT, "other": m.CAPTURED_OTHER}, sys.stdout, ensure_ascii=False)')" \
    || unmet "форма записи из самопробы гейта не получена"
rec_path="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["path"])' "$rec")"
mkdir -p "$R/$(dirname "$rec_path")"
python3 -c 'import json,sys; open(sys.argv[2],"w").write(json.loads(sys.argv[1])["text"])' "$rec" "$R/$rec_path"
git -C "$R" add -A && at "2026-02-01T00:00:00Z" git -C "$R" commit -q -m "#51 запись ревью"
api_file="$FAKE_GH_DIR/api/repos_PRO-Robotech_kacho_issues_1271_comments_per_page_100.json"
sil() { plan_of "$R" 51; sout="$(cd "$R" && python3 scripts/hooks/prepush-classes.py reviews "$pdir" 2>&1)"; src=$?; }
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); json.dump([d["other"], d["event"]], open(sys.argv[2],"w"), ensure_ascii=False)' "$rec" "$api_file"
sil
grep -qx reviews "$pdir/classes" && [ "$src" -eq 1 ] && printf '%s' "$sout" | grep -q 'без блока event' && ok "S1: событие опубликовано, запись молчит — красное" || bad "S1: код $src: $sout"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); json.dump([d["other"]], open(sys.argv[2],"w"), ensure_ascii=False)' "$rec" "$api_file"
sil
[ "$src" -eq 0 ] && printf '%s' "$sout" | grep -q 'расхождений              : 0' && ok "S2: события нет — зелёное" || bad "S2: код $src: $sout"
rm -f "$api_file"
sil
[ "$src" -eq 3 ] && ok "S3: трекер не ответил — код 3, не зелёное" || bad "S3: код $src: $sout"

# ── ОСЬ D ───────────────────────────────────────────────────────────────────
echo "ось D — долг набора"
fresh_gh D
wt="$work/D"
git -C "$ROOT" worktree add -q --detach "$wt" HEAD 2>/dev/null || unmet "рабочая копия ствола для оси D не создана"
mkdir -p "$work/Dplan"
printf '{"slug":"","refs":[],"touched":["tests/newman/x"],"classes":{},"notes":[]}\n' > "$work/Dplan/plan.json"
debt() { dout="$(cd "$wt" && python3 "$CLS" debt "$work/Dplan" 2>&1)"; drc=$?; }
FAKE_GH_STATE=open debt
# Близнец — ствол как он есть. Красный ствол — не дефект выбора, а состояние
# дерева: близнеца тогда нет, и это «условие не создано», а не «сошлось».
[ "$drc" -eq 0 ] || unmet "D1: ствол красен по долгу и без инъекции (код $drc) — близнеца нет: $(printf '%s' "$dout" | grep -E 'ОТКАЗ|·' | head -3 | tr '\n' ' ')"
ok "D1: ведомость сходится с деревом, держатели открыты — зелёное"
cp "$wt/tests/newman/collections/authz-deny.postman_collection.json" "$wt/tests/newman/collections/probe-extra.postman_collection.json"
FAKE_GH_STATE=open debt
[ "$drc" -eq 1 ] && printf '%s' "$dout" | grep -q 'разошлась с деревом' && printf '%s' "$dout" | grep -q 'probe-extra' && ok "D2: коллекция без записи — красное с её именем" || bad "D2: код $drc: $(printf '%s' "$dout" | grep -E 'ОТКАЗ|probe' | head -3)"
rm -f "$wt/tests/newman/collections/probe-extra.postman_collection.json"
FAKE_GH_STATE=none debt
[ "$drc" -eq 3 ] && ok "D3: трекер не ответил — код 3" || bad "D3: код $drc"

# ── ОСЬ H ───────────────────────────────────────────────────────────────────
echo "ось H — провязка в хук"
fresh_gh H
R="$work/H"; make_repo "$R" || unmet "синтетический модуль не построен"
git -C "$R" checkout -q -b 51
commit_on "$R" README.md "#51 правка"
hook() { hout="$(cd "$R" && printf 'refs/heads/51 %s refs/heads/51 %s\n' "$(git rev-parse HEAD)" "0000000000000000000000000000000000000000" \
    | GOFLAGS='' bash scripts/hooks/pre-push origin "https://github.com/PRO-Robotech/probe.git" 2>&1)"; hrc=$?; }
hook
[ "$hrc" -eq 0 ] && printf '%s' "$hout" | grep -q '^── правило запроса' && printf '%s' "$hout" | grep -q '^классы до отправки  :' \
    && ok "H2: близнец — хук 0, группа «правило запроса» исполнена, строка переписи есть" || bad "H2: код $hrc: $(printf '%s' "$hout" | tail -15)"
mv "$R/scripts/hooks/prepush-classes.py" "$work/classes.away"
hook
[ "$hrc" -eq 2 ] && printf '%s' "$hout" | grep -q 'классы до отправки выбирать нечем' && ok "H3: помощника нет — код 2" || bad "H3: код $hrc"
mv "$work/classes.away" "$R/scripts/hooks/prepush-classes.py"
# H1 — форма красного круга kaname#829: коммит «#52 …» уже лежит на удалённом
# (ветка 52), ветка 51 продолжает его. Страж правила судит только НОВЫЕ коммиты
# и его не видит; конвейер судит диапазон main..51 — и хук обязан тоже.
git -C "$R" checkout -q -B 52 origin/main
commit_on "$R" README.md "#52 чужой номер"
git -C "$R" push -q --no-verify origin 52 2>/dev/null && git -C "$R" fetch -q origin
git -C "$R" checkout -q -B 51 52
commit_on "$R" README.md "#51 правка"
hook
[ "$hrc" -eq 1 ] && printf '%s' "$hout" | grep -q '^красные             : .*правило запроса' \
    && printf '%s' "$hout" | grep -q '«#52» на ветке «51»' && ok "H1: чужой номер на удалённом — страж молчит, хук 1, красная группа названа" || bad "H1: код $hrc: $(printf '%s' "$hout" | tail -15)"
# H4 — запись ревью тронута, событие не опубликовано: группа исполнена и зелёная.
fresh_gh H4
R="$work/H4"; make_repo "$R" || unmet "синтетический модуль H4 не построен"
git -C "$R" checkout -q -b 51
mkdir -p "$R/$(dirname "$rec_path")"
python3 -c 'import json,sys; open(sys.argv[2],"w").write(json.loads(sys.argv[1])["text"])' "$rec" "$R/$rec_path"
git -C "$R" add -A && at "2026-02-01T00:00:00Z" git -C "$R" commit -q -m "#51 запись ревью"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); json.dump([d["other"]], open(sys.argv[2],"w"), ensure_ascii=False)' \
    "$rec" "$FAKE_GH_DIR/api/repos_PRO-Robotech_kacho_issues_1271_comments_per_page_100.json"
hook
[ "$hrc" -eq 0 ] && printf '%s' "$hout" | grep -q '^── записи ревью' && printf '%s' "$hout" | grep -q 'расхождений              : 0' \
    && printf '%s' "$hout" | grep -q '^классы до отправки  : 2 из 4 выбрано по тронутым путям: правило запроса, записи ревью' \
    && ok "H4: запись ревью тронута — группа исполнена, хук 0, класс назван в переписи" || bad "H4: код $hrc: $(printf '%s' "$hout" | tail -15)"
# H5 — коллекция набора тронута, гейта долга в синтетическом дереве нет:
# группа исполнена и дала третий исход, хук его в зелёное не зачитывает.
fresh_gh H5
R="$work/H5"; make_repo "$R" || unmet "синтетический модуль H5 не построен"
git -C "$R" checkout -q -b 51
commit_on "$R" tests/newman/collections/x.postman_collection.json "#51 правка"
hook
[ "$hrc" -eq 2 ] && printf '%s' "$hout" | grep -q '^── долг набора' && printf '%s' "$hout" | grep -q '^без условия         : .*долг набора' \
    && printf '%s' "$hout" | grep -q '^классы до отправки  : .*долг набора' \
    && ok "H5: коллекция тронута — группа «долг набора» исполнена, третий исход: хук 2" || bad "H5: код $hrc: $(printf '%s' "$hout" | tail -15)"
# H6 — инъекция к H4: тот же модуль (зелёный), нет pr-rule-check.sh.
R="$work/H4"; fresh_gh H6
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); json.dump([d["other"]], open(sys.argv[2],"w"), ensure_ascii=False)' \
    "$rec" "$FAKE_GH_DIR/api/repos_PRO-Robotech_kacho_issues_1271_comments_per_page_100.json"
mv "$R/.github/scripts/pr-rule-check.sh" "$work/pr-rule.away"
hook
mv "$work/pr-rule.away" "$R/.github/scripts/pr-rule-check.sh"
[ "$hrc" -eq 2 ] && printf '%s' "$hout" | grep -q '^без условия         : правило запроса$' && printf '%s' "$hout" | grep -q 'правило запроса: суд не исполнялся' \
    && ok "H6: код 3 класса в хуке — «без условия», хук 2, а не зелёное" || bad "H6: код $hrc: $(printf '%s' "$hout" | tail -15)"

# ── ОСЬ T ───────────────────────────────────────────────────────────────────
echo "ось T — цена на нетронутых классах"
python3 -c "import sys; sys.exit(0 if $plan_secs <= 21 else 1)" && ok "T: выбор на нетронутом без сети — $plan_secs с (потолок 21 с = 10 % от 215 с)" || bad "T: выбор $plan_secs с > 21 с"

# Объём исполненного сверяется с объявленным: утверждение, до которого опыт не
# дошёл, — не «сошлось», а «не исполнялось».
declared=30
echo
echo "prepush-classes-inject: утверждений объявлено $declared · исполнено $checks · не сошлось $failed"
[ "$failed" -eq 0 ] || exit 1
[ "$checks" -eq "$declared" ] || { echo "prepush-classes-inject: НЕ ВЫПОЛНИЛОСЬ — исполнено $checks из $declared" >&2; exit 2; }
exit 0
