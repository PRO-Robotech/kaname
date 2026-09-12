// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_scope_chain_stays_empty_test.go — решение «меточную ось сужать не
// надо» ИСТЕКАЕТ в день, когда у `iam_role` появляется третий производитель
// звена цепи областей.
//
// Порт с монорепо (`internal/repohygiene/rolescopechainstaysempty_test.go`,
// снят вынесением службы — `kacho#2597`). Изменилось: обход дерева
// (`repoRoot`/`newTrackedTree` монорепо → `treecorpus.UnderWithSuffix` этого
// модуля), приставка обхода (`services/iam/` снята — в kaname всё дерево
// СВОЁ, приставки не нужно). Предмет и довод — в шапке
// `role_scope_chain_stays_empty.go`.
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

// TestRoleScopeChainOfAModuleRoleStaysEmpty — сам гейт.
func TestRoleScopeChainOfAModuleRoleStaysEmpty(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	goFiles, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}
	sqlFiles, err := treecorpus.UnderWithSuffix(ownDir, ".sql")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}
	all := append(append([]string{}, goFiles...), sqlFiles...)
	sort.Strings(all)

	var (
		filesRead int
		census    check.RoleScopeChainCensus
		found     []check.RoleScopeChainSite
	)
	for _, abs := range all {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(abs)
		if rerr != nil {
			continue
		}
		filesRead++
		rel, _ := filepath.Rel(ownDir, abs)
		f, c := check.ScanRoleScopeChain(filepath.ToSlash(rel), string(b))
		found = append(found, f...)
		census.Statements += c.Statements
		census.Branches += c.Branches
		census.TierSourced += c.TierSourced
	}

	t.Logf("перепись: файлов осмотрено %d, упоминаний таблицы звеньев %d, "+
		"ветвей, производящих звено для %s — %d, из них взявших его у ярусного столбца %d",
		filesRead, census.Statements, check.RoleScopeChainType, census.Branches, census.TierSourced)

	if filesRead == 0 {
		t.Fatal("осмотрено ноль файлов: обход беспредметен, и его молчание ничего не значит")
	}
	if census.Branches == 0 {
		t.Fatalf("ветвей, производящих звено для %s, не найдено НИ ОДНОЙ — распознаватель "+
			"потерял предмет: сегодня их две (роль аккаунта и роль проекта), и обе "+
			"обязаны быть видны. Пустой перечень здесь означает, что форма ветви "+
			"изменилась, а не что дерево чисто", check.RoleScopeChainType)
	}

	for _, s := range found {
		t.Errorf(`%s:%d — заведён производитель звена цепи областей для %s, не берущий его
    ни у %s: %s

    ЧТО ЭТО ЗНАЧИТ. Решение приёмки role-withdrawal-has-a-producer.md §2.8 —
    «меточную ось выдачи сужать по живости роли НЕ НАДО» — стояло на факте: у
    роли МОДУЛЯ цепь областей пуста, поэтому выдача её не достаёт ни живую, ни
    снятую. С этим производителем факт перестал быть верным, и снятая роль снова
    может стать достижимой — МОЛЧА.

    ЧТО ЗАКРЫВАТЬ. Цепью объекта гейтятся ВСЕ ТРИ АРМА выдачи — якорь, имена и
    метки, — а не только меточный. Сузив один, вы не сузите две трети и решите,
    что закрыли: закрывать надо по всем трём, и проба обязана утверждать каждый
    отдельно.

    ЕСЛИ ЭТО ЗАКОННО. Ветвь, берущая звено у ярусного столбца роли (%s), законна
    и молчания гейта не нарушает: роль аккаунта и роль проекта предка обязаны
    иметь. Судить по имени типа нельзя — у %s есть и такие роли.`,
			s.File, s.Line, check.RoleScopeChainType,
			strings.Join(check.RoleScopeChainTierSources, " ни у "), s.What,
			strings.Join(check.RoleScopeChainTierSources, ", "), check.RoleScopeChainType)
	}
}
