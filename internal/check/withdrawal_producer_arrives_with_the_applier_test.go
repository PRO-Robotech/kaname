// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// withdrawal_producer_arrives_with_the_applier_test.go — гейт задачи #1913:
// применитель ролей модуля не приводится в действие БЕЗ производителя отзыва
// роли (порт с монорепо
// `internal/repohygiene/withdrawalproducerarriveswiththeapplier_test.go`,
// держатель `TestWithdrawalProducerArrivesWithTheApplier`, снят вынесением
// службы доступа — `kacho#2597`).
//
// # Триггер #1034/#2010 УЖЕ СРАБОТАЛ В KANAME — это надо сказать прямо
//
// Монорепошный предок был написан как САМОИСТЕКАЮЩЕЕ послабление: на день его
// заведения применитель в проде не вызывался, и гейт молчал по построению
// (первая строка таблицы согласия). Порт застаёт дерево kaname В ДРУГОЙ
// клетке той же таблицы: `cmd/kaname/serve.go` зовёт `moduleroles.NewApplier`
// (задача #2010, файл `cmd/kaname/module_roles_apply.go`), а
// `internal/repo/kaname/pg/role_withdrawal_repo.go` несёт
// `UPDATE kaname.roles SET live = false, retired_at = now(), …` — оператор
// формы, которую сам этот гейт распознаёт производителем. Обе половины
// заполнены — состояние «норма, работа сделана», не находка.
//
// Гейт порта РАВНО способен обнаружить и эту клетку: он проверяется на ней тем
// же прогоном на настоящем дереве, а не только инъекцией на синтетике.
//
// Способность гейта упасть и смолчать по каждой клетке таблицы согласия
// доказана инъекцией —
// withdrawal_producer_arrives_with_the_applier_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	withdrawalCensusFloor = 300
	// reconcileDeclFileRel — файл, объявляющий вид расхождения без исхода, от
	// корня модуля.
	reconcileDeclFileRel = "internal/apps/kaname/moduleroles/reconcile.go"
	liveNotDeclaredKind  = "LiveNotDeclared"
)

// roleWithdrawalFinding — предикат находки: НЕСОГЛАСИЕ, а не любая половина.
func roleWithdrawalFinding(drive, mark []check.RoleWithdrawalSite) bool {
	return len(drive) > 0 && len(mark) == 0
}

func withdrawalSiteLines(sites []check.RoleWithdrawalSite) []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s:%d  %s", s.File, s.Line, s.What))
	}
	sort.Strings(out)
	return out
}

// TestWithdrawalProducerArrivesWithTheApplier — сам гейт.
func TestWithdrawalProducerArrivesWithTheApplier(t *testing.T) {
	t.Parallel()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	declPath := platformtree.Under(modulePrefix, reconcileDeclFileRel)

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var (
		parsed      int
		census      check.RoleWithdrawalCensus
		drive, mark []check.RoleWithdrawalSite
		declSeen    bool
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if rel == declPath {
			declSeen = true
		}
		if strings.HasSuffix(rel, "_test.go") {
			// Тесты исключены НАМЕРЕННО: применитель импортируют тестовые
			// файлы, и ни один из них применителя в проде не приводит.
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		d, m, c, serr := check.ScanRoleWithdrawalWiring(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		drive = append(drive, d...)
		mark = append(mark, m...)
		census.AppliedImports += c.AppliedImports
		census.Selectors += c.Selectors
		census.StringLiterals += c.StringLiterals
		census.Comments += c.Comments
		census.WritesOverRoles += c.WritesOverRoles
	}

	t.Logf("перепись: прод-файлов Go разобрано %d, обращений вида `пакет.Имя` %d, "+
		"импортов применителя %d, приведений применителя в действие %d, "+
		"строковых литералов %d, операторов записи над `roles` %d, "+
		"производителей отзыва %d, комментариев %d",
		parsed, census.Selectors, census.AppliedImports, len(drive),
		census.StringLiterals, census.WritesOverRoles, len(mark), census.Comments)

	if parsed < withdrawalCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d",
			parsed, withdrawalCensusFloor)
	}
	if census.Selectors == 0 || census.StringLiterals == 0 || census.Comments == 0 {
		t.Fatalf("прочитано обращений %d, литералов %d, комментариев %d — обе половины "+
			"гейта беспредметны", census.Selectors, census.StringLiterals, census.Comments)
	}

	if !declSeen {
		t.Fatalf("файла сверки %s в составе дерева нет — предмет гейта переехал либо снят", declPath)
	}
	decl, derr := os.ReadFile(filepath.Join(corpusRoot, filepath.FromSlash(declPath))) // #nosec G304 -- путь из состава дерева этого модуля
	if derr != nil {
		t.Fatalf("чтение %s: %v", declPath, derr)
	}
	if !strings.Contains(string(decl), liveNotDeclaredKind) {
		t.Fatalf("сверка больше не объявляет вид расхождения %s (%s) — предмет гейта "+
			"исчез. Снимайте гейт вместе с видом", liveNotDeclaredKind, declPath)
	}

	if roleWithdrawalFinding(drive, mark) {
		t.Fatalf("применитель ролей модуля приводится в действие, а производителя отзыва "+
			"роли нет — %d приведение(й), производителей 0:\n  %s\n\n"+
			"Роль, объявленная манифестом и потом из него убранная, остаётся живой "+
			"НАВСЕГДА, и право, выданное через неё, продолжает действовать: сверка "+
			"объявляет вид %s, а исход у него не производится ничем.\n"+
			"Форма отзыва — ПОМЕТКА, удаления не допускает:\n"+
			"docs/engineering/architecture/role-withdrawal-is-a-mark.md.",
			len(drive), strings.Join(withdrawalSiteLines(drive), "\n  "), liveNotDeclaredKind)
	}
}
