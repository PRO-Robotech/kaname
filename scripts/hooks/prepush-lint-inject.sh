#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# Настоящий хук и настоящий линтер: одна ошибка errcheck отличает близнецов.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/hook-temp"
export TMPDIR="$work/hook-temp"
for tool in bash git go gofmt make python3 golangci-lint grep sed cp mkdir rm chmod dirname wc tail head cat mv date; do
    command -v "$tool" >/dev/null || { echo "НЕ ВЫПОЛНИЛОСЬ: нет $tool"; exit 2; }
done
# Полный вход копии: Makefile включает provenance.mk; его внешний include мягкий.
# lint не имеет зависимых целей, vet зовёт go; listfilter заменён пустым предметом.
# Python-прогонщик использует только стандартную библиотеку и git.
inputs=(Makefile provenance.mk .github/golangci.yml .github/scripts/go-test-verdict.py
    scripts/hooks/pre-push scripts/hooks/prepush-rule.sh scripts/hooks/branch-rule.sh
    scripts/hooks/prepush-classify.sh scripts/hooks/install.sh)
for input in "${inputs[@]}"; do
    [ -f "$ROOT/$input" ] || { echo "НЕ ВЫПОЛНИЛОСЬ: нет входа $input"; exit 2; }
done
printf 'fixture-input: %s\n' "${inputs[@]}"
echo "fixture-input: рассмотрено ${#inputs[@]} исходных файлов"
# Тот же изолированный способ identity, что у существующих budget/classify проб.
# Пользовательский global и HOME не меняются; branch guard читает этот файл.
export GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1
printf '[user]\n\tname = probe\n\temail = probe@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n' > "$GIT_CONFIG_GLOBAL"
mkdir -p "$work/repo/scripts/hooks" "$work/repo/.github/scripts" "$work/repo/.github"
cp "$ROOT"/scripts/hooks/{pre-push,prepush-rule.sh,branch-rule.sh,prepush-classify.sh,install.sh} "$work/repo/scripts/hooks/"
cp "$ROOT/.github/scripts/go-test-verdict.py" "$work/repo/.github/scripts/"
cp "$ROOT/.github/golangci.yml" "$work/repo/.github/"
cp "$ROOT/Makefile" "$work/repo/Makefile"
cp "$ROOT/provenance.mk" "$work/repo/provenance.mk"
[ -x "$work/repo/scripts/hooks/prepush-classify.sh" ] || {
    echo 'НЕ ВЫПОЛНИЛОСЬ: определитель категорий не исполним'; exit 2;
}
# Прочие цели выполняют реальные build/vet/test; listfilter предмета здесь не имеет.
cat >> "$work/repo/Makefile" <<'MK'
audit-list-filter:
	@echo "фикстура без списков"
MK
cd "$work/repo"
printf 'module probe.invalid/lint\n\ngo 1.25.0\n' > go.mod
cat > probe.go <<'GO'
package probe

import "errors"

func result() error { return errors.New("probe") }

func Probe() {
	_ = result()
}
GO
cat > probe_test.go <<'GO'
package probe

import "testing"

func TestProbe(t *testing.T) {
	Probe()
	result()
}
GO
git init -q -b 1
git add scripts/hooks .github Makefile provenance.mk go.mod probe.go probe_test.go
git commit -qm '#1 законный близнец'
base="$(git rev-parse HEAD)"
# Цель lint сама сверяет пин. Ненулевой oracle — негодная фикстура, а не RED хука.
golangci-lint version
if make lint > "$work/twin-lint.log" 2>&1; then
    cat "$work/twin-lint.log"
    echo 'ORACLE PASS: pinned lint законного близнеца, код 0'
else
    cat "$work/twin-lint.log"; echo 'НЕ ВЫПОЛНИЛОСЬ: lawful oracle не зелёный'; exit 2
fi
sed -i 's/_ = result()/result()/' probe.go
git add probe.go
git commit -qm '#1 инъекция errcheck'
mutant="$(git rev-parse HEAD)"
# Предпосылка отдельно: ошибка компилируется, vet/gofmt чисты.
go build ./...
go vet ./...
[ -z "$(gofmt -l probe.go)" ]
echo 'PRECONDITION PASS: mutant build/vet/gofmt чисты'
if make lint > "$work/mutant-lint.log" 2>&1; then
    cat "$work/mutant-lint.log"; echo 'НЕ ВЫПОЛНИЛОСЬ: mutant oracle не увидел дефект'; exit 2
fi
cat "$work/mutant-lint.log"
if ! grep -q 'probe.go:.*errcheck' "$work/mutant-lint.log"; then
    echo 'НЕ ВЫПОЛНИЛОСЬ: mutant oracle отказал без errcheck'; exit 2
fi
echo 'ORACLE PASS: pinned lint назвал errcheck в probe.go'
git checkout -q --detach "$base"
git init -q --bare "$work/remote.git"
git remote add origin "$work/remote.git"
bash scripts/hooks/install.sh install >/dev/null
# Настоящий branch push проходит неизменённый страж с изолированной identity.
# Обе фикстурные ревизии созданы до установки хуков, которые не отключаются.
bash scripts/hooks/install.sh check
if git push origin HEAD:refs/heads/1 > "$work/twin.log" 2>&1; then
    cat "$work/twin.log"
    echo 'PASS: законный близнец — настоящий push прошёл'
else
    cat "$work/twin.log"; exit 1
fi
git checkout -q --detach "$mutant"
if git push origin HEAD:refs/heads/1 > "$work/defect.log" 2>&1; then
    cat "$work/defect.log"
    echo 'FAIL: настоящий push пропустил errcheck в затронутом пакете'
    exit 1
fi
cat "$work/defect.log"
grep -q 'probe.go:.*errcheck' "$work/defect.log"
grep -q 'красные.*golangci-lint' "$work/defect.log"
echo "PASS: errcheck назван, push отказал; база диапазона $base"
checks=2
failed=0
matches_status() {
    case "$1:$2" in
        green:0) return 0 ;;
        green:*|refuse:0) return 1 ;;
        refuse:*) return 0 ;;
        *) return 1 ;;
    esac
}
# Таблица судьи проверяется отдельно: && и || в shell имеют равный приоритет.
for row in 'green 0 yes' 'green 1 no' 'refuse 0 no' 'refuse 1 yes' 'refuse 2 yes'; do
    read -r expected code want <<< "$row"
    actual=no
    if matches_status "$expected" "$code"; then actual=yes; fi
    checks=$((checks + 1))
    if [ "$actual" = "$want" ]; then echo "PASS: judge $row"
    else failed=$((failed + 1)); echo "FAIL: judge $row → $actual"; fi
done
check_result() {
    local name="$1" expected="$2" pattern="$3" rc="$4" log="$5"
    checks=$((checks + 1))
    if matches_status "$expected" "$rc" && grep -q -- "$pattern" "$log"; then
        echo "PASS: $name"
    else
        failed=$((failed + 1))
        echo "FAIL: $name, код $rc, ожидается $expected / $pattern"
        cat "$log"
    fi
}
push_check() {
    local name="$1" expected="$2" pattern="$3" rc=0
    git push origin HEAD:refs/heads/2 > "$work/$name.log" 2>&1 || rc=$?
    check_result "$name" "$expected" "$pattern" "$rc" "$work/$name.log"
}
commit_case() { git add "$@"; git commit -qm '#2 граница области lint'; }
hook_check() {
    local name="$1" expected="$2" pattern="$3" input="$4"
    hook_rc=0
    printf '%s\n' "$input" | bash scripts/hooks/pre-push origin > "$work/$name.log" 2>&1 || hook_rc=$?
    check_result "$name" "$expected" "$pattern" "$hook_rc" "$work/$name.log"
}
ref_push_check() {
    local name="$1" expected="$2" pattern="$3" sent="$4" rc=0
    git push origin "$sent:refs/heads/main" > "$work/$name.log" 2>&1 || rc=$?
    check_result "$name" "$expected" "$pattern" "$rc" "$work/$name.log"
}

# Прямой RED независимого опыта: хороший checkout не подменяет плохой ref.
# Это настоящие branch pushes; main допускает корректные commits задачи #1.
git checkout -q --detach "$base"
git update-ref refs/remotes/origin/main "$base"
ref_push_check nonhead-twin green 'зелёное — исполнено 7 из 7' "$base"
ref_push_check nonhead-mutant refuse 'probe.go:.*errcheck' "$mutant"
git checkout -q --detach "$mutant"
git checkout "$base" -- probe.go
before_status="$(git status --porcelain)"
before_head="$(git rev-parse HEAD)"
before_blob="$(git hash-object probe.go)"
ref_push_check dirty-hides-mutant refuse 'probe.go:.*errcheck' "$mutant"
printf '%s\n' "$(git rev-parse HEAD) $(git hash-object probe.go)" > "$work/dirty-state.log"
state_rc=0
if [ "$before_status" != "$(git status --porcelain)" ]; then state_rc=1; fi
check_result dirty-state green "^$before_head $before_blob$" "$state_rc" "$work/dirty-state.log"
git restore --source=HEAD --staged --worktree -- probe.go
git checkout -q --detach "$base"
printf '\n// Закоммиченный законный близнец.\n' >> probe.go
git add probe.go
git commit -qm '#1 законный tip для dirty checkout'
lawful_tip="$(git rev-parse HEAD)"
sed -i 's/_ = result()/result()/' probe.go
before_status="$(git status --porcelain)"
before_head="$(git rev-parse HEAD)"
before_blob="$(git hash-object probe.go)"
ref_push_check dirty-cannot-red-lawful green 'зелёное — исполнено 7 из 7' "$lawful_tip"
printf '%s\n' "$(git rev-parse HEAD) $(git hash-object probe.go)" > "$work/lawful-dirty-state.log"
state_rc=0
if [ "$before_status" != "$(git status --porcelain)" ]; then state_rc=1; fi
check_result lawful-dirty-state green "^$before_head $before_blob$" "$state_rc" "$work/lawful-dirty-state.log"
git restore --source=HEAD --staged --worktree -- probe.go

# На main есть старый lint-дефект в другом пакете. Новый чистый push должен
# судить только изменённый пакет: full-module и пустой обход здесь различимы.
git checkout -q --detach "$base"
mkdir untouched
cat > untouched/bad.go <<'GO'
package untouched

import "errors"

func result() error { return errors.New("untouched") }

func Probe() { result() }
GO
commit_case untouched/bad.go
main_snapshot="$(git rev-parse HEAD)"
git -C "$work/remote.git" fetch -q "$PWD" "$main_snapshot"
git -C "$work/remote.git" update-ref refs/heads/main "$main_snapshot"
git update-ref refs/remotes/origin/main "$main_snapshot"
printf '\n// Изменён только корневой пакет.\n' >> probe.go
commit_case probe.go
tip="$(git rev-parse HEAD)"
push_check new-branch green "lint: диапазон $main_snapshot..$tip"
check_result captured-main green "lint: main snapshot=$main_snapshot" 0 "$work/new-branch.log"
printf 'описание\n' > notes.txt
commit_case notes.txt
push_check no-go green 'затронутых существующих пакетов Go 0'
git mv probe.go renamed.go
git commit -qm '#2 перенос файла Go'
push_check renamed-file green 'lint: областей 1 — .'
mkdir moved
printf 'package moved\n\nfunc Valid() {}\n' > moved/valid.go
commit_case moved/valid.go
push_check new-package green 'lint: областей 1 — ./moved'
git mv moved renamed
git commit -qm '#2 перенос пакета Go'
push_check moved-package green 'lint: областей 1 — ./renamed'
git rm -q renamed/valid.go
git commit -qm '#2 удаление пакета Go'
push_check deleted-package green 'затронутых существующих пакетов Go 0'
tip="$(git rev-parse HEAD)"
rc=0
printf 'HEAD %s refs/heads/2 %s\nHEAD %s refs/heads/2 %s\n' "$tip" "$tip" "$tip" "$main_snapshot" | bash scripts/hooks/pre-push origin > "$work/multi-ref.log" 2>&1 || rc=$?
check_result multi-ref green 'lint: областей 1 — .' "$rc" "$work/multi-ref.log"
check_result multi-ref-dedup green 'lint: distinct tips 1, красных 0' "$rc" "$work/multi-ref.log"
rc=0
printf 'refs/heads/2 0000000000000000000000000000000000000000 refs/heads/2 %s\n' "$tip" | bash scripts/hooks/pre-push origin > "$work/delete-ref.log" 2>&1 || rc=$?
check_result delete-ref green 'содержимого не уезжает — проверять нечего' "$rc" "$work/delete-ref.log"

# Два РАЗНЫХ tips меняют разные пакеты. Каждый проверяется по своим bytes;
# дефект A обязан сохраниться при любом порядке live refs.
mkdir uniona unionb
cat > uniona/a.go <<'GO'
package uniona

import "errors"

func result() error { return errors.New("union") }

func Probe() { _ = result() }
GO
printf 'package unionb\n\nfunc Value() int { return 0 }\n' > unionb/b.go
commit_case uniona/a.go unionb/b.go
union_base="$(git rev-parse HEAD)"
sed -i 's/_ = result()/result()/' uniona/a.go
commit_case uniona/a.go
tip_a="$(git rev-parse HEAD)"
git checkout -q --detach "$union_base"
printf '\n// Изменение второго пакета.\n' >> unionb/b.go
commit_case unionb/b.go
tip_b="$(git rev-parse HEAD)"
[ "$tip_a" != "$tip_b" ]
git checkout -q --detach "$tip_a"
git checkout "$tip_b" -- unionb/b.go
git commit -qm '#2 объединённый checkout разных tips'
input_a="HEAD $tip_a refs/heads/2 $union_base"
input_b="HEAD $tip_b refs/heads/main $union_base"
hook_check different-tips-ab refuse 'uniona/a.go:.*errcheck' "$input_a"$'\n'"$input_b"
check_result different-tips-ab-argv-a refuse '^lint: областей 1 — ./uniona$' "$hook_rc" "$work/different-tips-ab.log"
check_result different-tips-ab-argv-b refuse '^lint: областей 1 — ./unionb$' "$hook_rc" "$work/different-tips-ab.log"
hook_check different-tips-ba refuse 'uniona/a.go:.*errcheck' "$input_b"$'\n'"$input_a"
check_result different-tips-ba-argv-a refuse '^lint: областей 1 — ./uniona$' "$hook_rc" "$work/different-tips-ba.log"
check_result different-tips-ba-argv-b refuse '^lint: областей 1 — ./unionb$' "$hook_rc" "$work/different-tips-ba.log"
git checkout -q --detach "$union_base"
printf '\n// Законный близнец первого пакета.\n' >> uniona/a.go
commit_case uniona/a.go
tip_a_clean="$(git rev-parse HEAD)"
git checkout "$tip_b" -- unionb/b.go
git commit -qm '#2 законный checkout разных tips'
hook_check different-tips-twin green 'lint: distinct tips 2, красных 0' "HEAD $tip_a_clean refs/heads/2 $union_base"$'\n'"$input_b"

# После перемещения исходный пакет выживает и несёт старый дефект. Проверка
# только destination пропустила бы его; изменяются обе стороны rename.
mkdir renameold renamenew
cat > renameold/keep.go <<'GO'
package renameold

import "errors"

func result() error { return errors.New("source") }

func Probe() { result() }
GO
printf 'package renameold\n\nfunc Moved() {}\n' > renameold/move.go
printf 'package renamenew\n\nfunc Kept() {}\n' > renamenew/keep.go
commit_case renameold/keep.go renameold/move.go renamenew/keep.go
rename_base="$(git rev-parse HEAD)"
git mv renameold/move.go renamenew/move.go
sed -i 's/package renameold/package renamenew/' renamenew/move.go
git add renamenew/move.go
git commit -qm '#2 перенос файла из выживающего пакета'
tip="$(git rev-parse HEAD)"
hook_check surviving-source refuse 'renameold/keep.go:.*errcheck' "HEAD $tip refs/heads/2 $rename_base"
check_result surviving-source-argv refuse '^lint: областей 2 — ./renamenew ./renameold$' "$hook_rc" "$work/surviving-source.log"
sed -i 's/result() }/_ = result() }/' renameold/keep.go
commit_case renameold/keep.go
tip="$(git rev-parse HEAD)"
hook_check surviving-source-twin green '^lint: областей 2 — ./renamenew ./renameold$' "HEAD $tip refs/heads/2 $rename_base"

printf '\n# Граница конфигурации.\n' >> .github/golangci.yml
commit_case .github/golangci.yml
push_check config-full refuse 'untouched/bad.go:.*errcheck'
check_result config-reason refuse 'полный модуль — изменена конфигурация' 1 "$work/config-full.log"
tip="$(git rev-parse HEAD)"
rc=0
printf 'HEAD %s refs/heads/2 ffffffffffffffffffffffffffffffffffffffff\n' "$tip" | bash scripts/hooks/pre-push origin > "$work/unknown-base.log" 2>&1 || rc=$?
check_result unknown-base refuse 'полный модуль — база отправки недоступна' "$rc" "$work/unknown-base.log"
rc=0
bash scripts/hooks/pre-push origin </dev/null > "$work/no-input.log" 2>&1 || rc=$?
check_result no-input refuse 'полный модуль — нет входа git push' "$rc" "$work/no-input.log"

# Расхождение версии и отсутствующее объявление — третья категория и отказ,
# без запасного hardcode пина. Пользовательский binary и config не меняются.
sed -i 's/^GOLANGCI_LINT_VERSION := .*/GOLANGCI_LINT_VERSION := v0.0.0/' Makefile
commit_case Makefile
push_check wrong-pin refuse 'golangci-lint не отвечает пину v0.0.0'
sed -i 's/^GOLANGCI_LINT_VERSION := .*/GOLANGCI_LINT_VERSION :=/' Makefile
commit_case Makefile
push_check missing-pin refuse 'golangci-lint не отвечает пину'

shopt -s nullglob dotglob
residue=("$TMPDIR"/*)
printf 'temporary entries %s\n' "${#residue[@]}" > "$work/cleanup.log"
check_result temporary-cleanup green '^temporary entries 0$' 0 "$work/cleanup.log"
echo "prepush-lint-inject: рассмотрено $checks утверждений о hook, исполнено $checks, отказов $failed"
[ "$failed" -eq 0 ]
