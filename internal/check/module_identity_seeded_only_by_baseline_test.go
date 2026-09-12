// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_identity_seeded_only_by_baseline_test.go — ГЕЙТ: рост долга ПР-5
// запрещён (задача продукта #2098).
//
// Порт с монорепо (`internal/repohygiene/moduleidentityseededonlybythebaseline_test.go`,
// снят вынесением службы — `kacho#2597`). Имя функции сохранено ДОСЛОВНО.
// Изменилось: обход дерева (`repoRootFor(t)` монорепо →
// `platformtree.RequireCorpus` + `treecorpus.UnderWithSuffix`, см. образец
// `derived_id_single_source_test.go`), путь миграций
// (`services/iam/internal/migrations` → `internal/migrations`), пакет
// (`repohygiene_test` → `check_test`), помощники разбора вынесены в
// не-тестовый файл `seeded_service_accounts.go` (см. его шапку — нужны
// ДВУМ семействам монорепо).
//
// Предмет, текущее состояние на день переноса (долг #2098 закрыт задачей
// #2452, гейт стережёт РЕГРЕСС) — в шапке `module_identity_seeded_only_by_baseline.go`.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `module_identity_seeded_only_by_baseline_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// migrationsDir — единственный дом миграций службы.
const migrationsDir = "internal/migrations"

// TestOnlyTheAppliedBaselineSeedsAModuleIdentity — сам гейт.
func TestOnlyTheAppliedBaselineSeedsAModuleIdentity(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	sqlFiles, err := treecorpus.UnderWithSuffix(filepath.Join(ownDir, migrationsDir), ".sql")
	if err != nil {
		t.Fatalf("перечень миграций берётся у индекса дерева, а не обходом диска: %v", err)
	}

	bodies := map[string]string{}
	ordered := make([]string, 0, len(sqlFiles))
	for _, f := range sqlFiles {
		raw, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatalf("чтение %s: %v", f, rerr)
		}
		name := filepath.Base(f)
		bodies[name] = string(raw)
		ordered = append(ordered, name)
	}
	sort.Strings(ordered) // порядок применения goose = лексикографический порядок имён

	alive, unknown, stmts := check.FoldSeededServiceAccounts(ordered, bodies)
	if len(unknown) != 0 {
		t.Fatalf("форма посева служебных учёток, неизвестная разбору:\n%s", strings.Join(unknown, "\n"))
	}
	if why := check.SeedScopeUnfit(ordered, alive); why != "" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s", why)
	}

	baseline := check.BaselineMigrationOf(ordered)
	findings := check.ModuleIdentitiesSeededOutsideTheBaseline(alive, baseline)

	modules, byBaseline := 0, 0
	for _, sa := range alive {
		if !sa.IsModule() {
			continue
		}
		modules++
		if sa.Where == baseline {
			byBaseline++
		}
	}

	t.Logf("перепись: миграций прочитано %d · базовая (первая в порядке применения) %s · "+
		"операторов о служебных учётках %d · живых учёток посева %d · из них модульных %d · "+
		"находок %d",
		len(ordered), baseline, stmts, len(alive), modules, len(findings))
	t.Logf("перепись долга ПР-5/#2098: личностей модулей, живых в дереве сегодня, %d — все "+
		"посеяны базовой миграцией (%d из %d). Основной объём долга закрыт задачей #2452 "+
		"(пять из семи личностей сняты, применитель заведён); этот гейт стережёт РЕГРЕСС — "+
		"появление новой миграции, сеющей модульную личность мимо применителя",
		modules, byBaseline, modules)

	if len(findings) != 0 {
		t.Fatalf("%s", strings.Join(findings, "\n"))
	}
}
