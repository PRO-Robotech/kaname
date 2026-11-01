#!/usr/bin/env bash
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
# Настоящий хук и настоящий линтер: одна ошибка errcheck отличает близнецов.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for tool in git go gofmt make python3 golangci-lint grep sed; do
    command -v "$tool" >/dev/null || { echo "НЕ ВЫПОЛНИЛОСЬ: нет $tool"; exit 2; }
done
mkdir -p "$work/repo/scripts/hooks" "$work/repo/.github/scripts" "$work/repo/.github"
cp "$ROOT"/scripts/hooks/{pre-push,prepush-rule.sh,branch-rule.sh,prepush-classify.sh,install.sh} "$work/repo/scripts/hooks/"
cp "$ROOT/.github/scripts/go-test-verdict.py" "$work/repo/.github/scripts/"
cp "$ROOT/.github/golangci.yml" "$work/repo/.github/"
cp "$ROOT/Makefile" "$work/repo/Makefile"
# Прочие цели выполняют реальные build/vet/test; listfilter предмета здесь не имеет.
cat >> "$work/repo/Makefile" <<'MK'
vet:
	go vet ./...
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
git init -q
git config --local user.name 'Prepush Lint Fixture'
git config --local user.email 'prepush-lint@fixture.invalid'
git add scripts/hooks .github Makefile go.mod probe.go probe_test.go
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
# Теги несут Go-код и судятся всеми группами хука. Правило имён веток здесь
# предмета не имеет; глобальная identity владельца для изолированной пробы не нужна.
# Обе фикстурные ревизии созданы до установки хуков, которые не отключаются.
if git push origin HEAD:refs/tags/lint-probe > "$work/twin.log" 2>&1; then
    echo 'PASS: законный близнец — настоящий push прошёл'
else
    cat "$work/twin.log"; exit 1
fi
git checkout -q --detach "$mutant"
if git push --force origin HEAD:refs/tags/lint-probe > "$work/defect.log" 2>&1; then
    cat "$work/defect.log"
    echo 'FAIL: настоящий push пропустил errcheck в затронутом пакете'
    exit 1
fi
cat "$work/defect.log"
grep -q 'probe.go:.*errcheck' "$work/defect.log"
grep -q 'красные.*golangci-lint' "$work/defect.log"
echo "PASS: errcheck назван, push отказал; база диапазона $base"
echo 'prepush-lint-inject: рассмотрено 2 сценария, исполнено 2, отказов 0'
