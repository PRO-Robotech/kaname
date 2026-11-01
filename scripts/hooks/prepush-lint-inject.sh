#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# Настоящий хук и настоящий линтер: одна ошибка errcheck отличает близнецов.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
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

func TestProbe(t *testing.T) { Probe() }
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
echo 'prepush-lint-inject: рассмотрено 2 сценария, исполнено 2, отказов 0'
