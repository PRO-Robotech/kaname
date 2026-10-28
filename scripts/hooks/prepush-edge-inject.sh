#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# prepush-edge-inject.sh — опыт над сверкой с краем хука отправки
# (scripts/hooks/prepush-edge.sh и её провязкой в scripts/hooks/pre-push,
# kaname#822).
#
# ─────────────────────────────────────────────────────────────────────────────
# ОСИ
#
#  L. ПОИСК КЛОНА. В синтетическом дереве: (L1) соседний `../kacho` с `origin`
#     на PRO-Robotech/kacho найден; (L2) законный близнец — тот же каталог с
#     `origin` на ДРУГОЙ репозиторий не засчитан, код 4 и перечень осмотренного;
#     (L3) названный KACHO_MONOREPO возвращается как есть.
#  C. КОНТРОЛЬ — СОВПАДЕНИЕ МОЛЧИТ. Синтетический «ствол платформы» (голый
#     репозиторий) несёт копию края, на которой сама цель
#     `make check-permission-catalog` — оракул, зовётся напрямую — зелёная.
#     Сверка обязана сказать «каталог прав: копии сходятся» и назвать ревизию.
#  I. ИНЪЕКЦИЯ — РАСХОЖДЕНИЕ КРАСНЕЕТ. Ствол платформы сдвигается коммитом,
#     дописывающим в копию края метод, которого у службы нет. Клон при этом
#     НЕ освежён руками: красное обязано прийти через `git fetch` сверки, и
#     названа должна быть НОВАЯ ревизия — так держится свежесть ствола.
#  F. ЗАКОННЫЙ БЛИЗНЕЦ — FETCH НЕ УДАЛСЯ. `origin` клона ведёт в никуда: сверка
#     идёт на прежней (зелёной) ревизии, выходит 0, а несвежесть записана в файл
#     оси — не умолчана.
#  H. ХУК БЕЗ КЛОНА. Настоящий хук на синтетическом модуле, клона нет: исход
#     прежний (0), а строка «сверка с краем : НЕ ВЫПОЛНИЛОСЬ» есть и в
#     переписи, и в перечне непроверенного. Близнец (H2): KACHO_MONOREPO назван
#     негодным путём — группа заведена, и хук выходит 2 («не выполнилось»), а
#     не 0.
#
# Предпосылка осей C, I, F — клон PRO-Robotech/kacho, найденный тем же поиском
# (`prepush-edge.sh --locate`): копия края и манифесты платформы берутся из
# его `origin/main`. Нет клона — код 2. Зелёного близнеца нет (копия края
# ствола платформы и своя копия расходятся, и своя копия тоже не зелёная) —
# код 2 с названной причиной: это состояние стволов, а не дефект сверки.
#
# В конвейер опыт НЕ провязан: в задании хука отправки клона платформы нет, и
# его созданием платилось бы заданию выборкой на каждый прогон. Держится он
# прогоном автора и приёмкой (`check-verifier`) — сказано здесь, а не умолчано.
#
# Исходы: 0 — все оси исполнены и сошлись · 1 — хотя бы одно утверждение не
# сошлось · 2 — предпосылка не создана.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "prepush-edge-inject: НЕ ИСПОЛНЯЛОСЬ — не рабочая копия git" >&2; exit 2; }
cd "$ROOT" || exit 2
EDGE="$ROOT/scripts/hooks/prepush-edge.sh"
HOOK="$ROOT/scripts/hooks/pre-push"
for f in "$EDGE" "$HOOK" "$ROOT/scripts/hooks/prepush-classify.sh" "$ROOT/scripts/hooks/prepush-rule.sh" \
         "$ROOT/scripts/hooks/branch-rule.sh" "$ROOT/scripts/hooks/install.sh" "$ROOT/.github/scripts/go-test-verdict.py"; do
    [ -f "$f" ] || { echo "prepush-edge-inject: НЕ ИСПОЛНЯЛОСЬ — нет $f" >&2; exit 2; }
done
CAT_REL=gateway/internal/middleware/embed/permission_catalog.json
OWN_CAT="$ROOT/internal/apps/kaname/seed/embedded/permission_catalog.json"

checks=0; failed=0
ok()  { checks=$((checks + 1)); echo "  ok   — $1"; }
bad() { checks=$((checks + 1)); failed=$((failed + 1)); echo "  БЕДА — $1" >&2; }
unmet() { echo "prepush-edge-inject: УСЛОВИЕ НЕ СОЗДАНО — $1" >&2; exit 2; }

real_clone="$(bash "$EDGE" --locate 2>/dev/null)" || unmet "клона PRO-Robotech/kacho нет (KACHO_MONOREPO, ../kacho) — осям C, I, F не из чего строить ствол"
real_rev="$(git -C "$real_clone" rev-parse -q --verify 'refs/remotes/origin/main^{commit}')" || unmet "у $real_clone нет origin/main"

work="$(mktemp -d)" || unmet "временный каталог не создан"
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
printf '[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' > "$GIT_CONFIG_GLOBAL"
unset KACHO_MONOREPO

# ── ОСЬ L ───────────────────────────────────────────────────────────────────
echo "ось L — поиск клона"
mkdir -p "$work/L/svc/scripts/hooks" "$work/L/kacho"
cp "$EDGE" "$work/L/svc/scripts/hooks/"
git -C "$work/L/svc" init -q . && git -C "$work/L/kacho" init -q .
git -C "$work/L/kacho" remote add origin git@github.com:PRO-Robotech/kacho.git
out="$(cd "$work/L/svc" && bash scripts/hooks/prepush-edge.sh --locate)"; rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(cd "$work/L/kacho" && pwd -P)" ] && ok "L1: соседний клон найден" || bad "L1: rc=$rc, «$out»"
git -C "$work/L/kacho" remote set-url origin git@github.com:PRO-Robotech/kaname.git
out="$(cd "$work/L/svc" && bash scripts/hooks/prepush-edge.sh --locate)"; rc=$?
[ "$rc" -eq 4 ] && printf '%s' "$out" | grep -q 'осмотрено' && ok "L2: чужой репозиторий не засчитан, код 4 с перечнем" || bad "L2: rc=$rc, «$out»"
out="$(cd "$work/L/svc" && KACHO_MONOREPO=/nonexistent/probe bash scripts/hooks/prepush-edge.sh --locate)"; rc=$?
[ "$rc" -eq 0 ] && [ "$out" = /nonexistent/probe ] && ok "L3: названный KACHO_MONOREPO возвращён как есть" || bad "L3: rc=$rc, «$out»"

# ── СИНТЕТИЧЕСКИЙ СТВОЛ ПЛАТФОРМЫ ───────────────────────────────────────────
oracle() { make -s check-permission-catalog EDGE_TREE="$1" >/dev/null 2>&1; }
seed="$work/seed"
mkdir -p "$seed"
git -C "$real_clone" archive "$real_rev" -- "$CAT_REL" ':(glob)services/*/manifest.yaml' deploy/stacks.txt deploy/helm/umbrella \
    | tar -x -C "$seed" || unmet "выборка из $real_clone@${real_rev:0:12} не удалась"
twin=""
if oracle "$seed"; then
    twin="копия края ствола платформы ${real_rev:0:12}"
else
    cp "$OWN_CAT" "$seed/$CAT_REL"
    oracle "$seed" && twin="своя копия каталога"
fi
[ -n "$twin" ] || unmet "зелёного близнеца нет: ни копия края ${real_rev:0:12}, ни своя копия не сходятся по самой цели сверки — это состояние стволов (строка «НАХОДКА» у make check-permission-catalog), а не дефект хука"
echo "зелёный близнец: $twin"

upstream="$work/kacho-upstream.git"
git init -q --bare "$upstream"
git -C "$seed" init -q . && git -C "$seed" add -A && git -C "$seed" commit -q -m control
git -C "$seed" push -q "$upstream" HEAD:refs/heads/main
clone="$work/platform-clone"
git clone -q "$upstream" "$clone"
git -C "$clone" remote set-url origin "$upstream"
# Поиск засчитывает лишь origin на PRO-Robotech/kacho — подмена адреса через
# insteadOf оставляет ДЕЙСТВУЮЩИЙ адрес локальным.
git config --global url."$upstream".insteadOf git@github.com:PRO-Robotech/kacho.git
git -C "$clone" remote set-url origin git@github.com:PRO-Robotech/kacho.git
control_rev="$(git -C "$seed" rev-parse HEAD)"

# ── ОСЬ C ───────────────────────────────────────────────────────────────────
echo "ось C — совпадение молчит"
out="$(bash "$EDGE" "$clone" 2>&1)"; rc=$?
printf '%s' "$out" | grep -q '→ каталог прав: копии сходятся' && ok "C: каталог прав — копии сходятся" || bad "C: строки «копии сходятся» нет (rc=$rc): $(printf '%s' "$out" | grep '→' | tr '\n' ' ')"
printf '%s' "$out" | grep -q "kacho: .* @ ${control_rev:0:12}" && ok "C: ревизия ствола названа" || bad "C: ревизия ${control_rev:0:12} не названа"

# ── ОСЬ I ───────────────────────────────────────────────────────────────────
echo "ось I — расхождение краснеет через fetch"
# Строка дописывается ТЕКСТОМ, по форме файла (`[`, записи через `,`, `]` и
# перевод строки): сверка судит и форму, и переписанный сериализатором файл она
# назвала бы «условие не создано», а не расхождением.
python3 - "$seed/$CAT_REL" <<'PY' || unmet "копия края не той формы, что ждёт опыт"
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
if not (s.startswith("[\n  {") and s.endswith("\n  }\n]\n")):
    sys.exit(1)
first = s[2:s.index("\n  },\n") + len("\n  }")]
key = '"fqn": "'
i = first.index(key) + len(key)
row = first[:i] + "kacho.cloud.probe.v1.ProbeService/Inject" + first[first.index('"', i):]
open(p, "w", encoding="utf-8").write(s[:-len("\n]\n")] + ",\n" + row + "\n]\n")
PY
git -C "$seed" commit -q -am "inject: метод, которого у службы нет"
git -C "$seed" push -q "$upstream" HEAD:refs/heads/main
inj_rev="$(git -C "$seed" rev-parse HEAD)"
out="$(bash "$EDGE" "$clone" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && ok "I: сверка красная, код 1" || bad "I: код $rc, ожидался 1"
printf '%s' "$out" | grep -q '→ каталог прав: КРАСНОЕ' && ok "I: красной названа сверка каталога" || bad "I: красное не от каталога: $(printf '%s' "$out" | grep '→' | tr '\n' ' ')"
printf '%s' "$out" | grep -q 'ProbeService/Inject' && ok "I: находка называет внесённый метод" || bad "I: внесённый метод в находке не назван"
printf '%s' "$out" | grep -q "kacho: .* @ ${inj_rev:0:12}" && ok "I: судится освежённая fetch ревизия" || bad "I: ревизия ${inj_rev:0:12} не названа — fetch не освежил ствол"

# ── ОСЬ F ───────────────────────────────────────────────────────────────────
echo "ось F — fetch не удался"
git -C "$clone" update-ref refs/remotes/origin/main "$control_rev"
git config --global --unset url."$upstream".insteadOf
git config --global url."$work/nowhere.git".insteadOf git@github.com:PRO-Robotech/kacho.git
: > "$work/axis"
out="$(PREPUSH_EDGE_FETCH_TIMEOUT=10 bash "$EDGE" --axis-file "$work/axis" "$clone" 2>&1)"; rc=$?
printf '%s' "$out" | grep -q '→ каталог прав: копии сходятся' && ok "F: судится прежняя ревизия, каталог сходится" || bad "F: каталог не сошёлся на прежней ревизии (rc=$rc)"
grep -q 'свежесть ствола платформы' "$work/axis" && ok "F: несвежесть записана в файл оси" || bad "F: файл оси пуст"
git config --global --unset url."$work/nowhere.git".insteadOf

# ── ОСЬ H ───────────────────────────────────────────────────────────────────
echo "ось H — хук без клона"
mod="$work/mod"
mkdir -p "$mod/.github/scripts" "$mod/scripts/hooks"
cp "$ROOT/.github/scripts/go-test-verdict.py" "$mod/.github/scripts/"
for f in pre-push prepush-classify.sh prepush-rule.sh branch-rule.sh prepush-edge.sh prepush-classes.py; do cp "$ROOT/scripts/hooks/$f" "$mod/scripts/hooks/"; done
# Выбор классов (kaname#822): карта и её читатель. Модуль без удалённого —
# тронутым считается всё дерево, и сверка с краем выбирается.
cp "$ROOT/.github/scripts/affected.py" "$mod/.github/scripts/" && cp "$ROOT/.github/ci-paths.json" "$mod/.github/"
chmod +x "$mod/scripts/hooks/"*
printf 'module probe.invalid/edge\n\ngo 1.21\n' > "$mod/go.mod"
printf 'package edge\n\nimport "testing"\n\nfunc TestEdgeProbe(t *testing.T) {}\n' > "$mod/edge_test.go"
printf '.PHONY: vet audit-list-filter\nvet:\n\t@go vet ./...\naudit-list-filter:\n\t@echo ok\n' > "$mod/Makefile"
git -C "$mod" init -q . && git -C "$mod" add -A && git -C "$mod" commit -q -m "#1 фикстура опыта"
git -C "$mod" checkout -q -b 1
hook_run() { ( cd "$mod" && printf '' | env -u KACHO_MONOREPO "$@" bash scripts/hooks/pre-push "--kaname-prepush-in-memory-scope" 2>&1 ); }
out="$(hook_run)"; rc=$?
[ "$rc" -eq 0 ] && ok "H1: без клона исход прежний (0)" || bad "H1: код $rc, ожидался 0: $(printf '%s' "$out" | grep -E "условие не создано|УСЛОВИЕ|без условия" | tr '\n' ' ')"
printf '%s' "$out" | grep -q '^сверка с краем      : НЕ ВЫПОЛНИЛОСЬ' && ok "H1: строка в переписи" || bad "H1: строки переписи нет"
printf '%s' "$out" | grep -q '^  сверка с краем: НЕ ВЫПОЛНИЛОСЬ' && ok "H1: строка в перечне непроверенного" || bad "H1: строки перечня нет"
out="$(hook_run KACHO_MONOREPO="$work/not-a-clone")"; rc=$?
[ "$rc" -eq 2 ] && ok "H2: негодный KACHO_MONOREPO — код 2, не тишина" || bad "H2: код $rc, ожидался 2"
printf '%s' "$out" | grep -q 'без условия *: .*сверка с краем' && ok "H2: группа названа «без условия»" || bad "H2: группа не названа"

echo
echo "prepush-edge-inject: утверждений $checks · не сошлось $failed"
[ "$failed" -eq 0 ] || exit 1
exit 0
