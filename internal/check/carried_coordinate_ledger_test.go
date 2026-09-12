// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// carried_coordinate_ledger_test.go — ведомость координат ИСТЕКАЕТ САМА.
// Порт с монорепо, см. годок `carried_coordinate_ledger.go`.
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// carriedLedgerPath — единственный дом ведомости, ОТ КОРНЯ своего модуля.
	carriedLedgerPath = "docs/engineering/architecture/" +
		"client-assertion-carried-over-coordinates.md"
)

// carriedMirrorTokens — чем зеркальная колонка себя называет.
var carriedMirrorTokens = []string{"hydra_client_id", "HydraClientID"}

// carriedOwnRoots — первые сегменты путей своего дерева, выведенные ОБХОДОМ
// (а не выписанные): координата ведомости в скоупе, если её первый сегмент
// входит в это множество. Держит кросс-репо путь (`services/registry/...`,
// принадлежащий монорепо продукта) вне суждения обеих сторон гейта — этот
// репозиторий не может ни подтвердить, ни опровергнуть существование файла в
// чужом дереве.
func carriedOwnRoots(files map[string]bool) map[string]bool {
	roots := map[string]bool{}
	for rel := range files {
		if i := strings.IndexByte(rel, '/'); i > 0 {
			roots[rel[:i]] = true
		}
	}
	return roots
}

// TestCarriedCoordinateLedgerExpiresOnItsOwn — сам гейт. Имя сохранено
// дословно из монорепо.
func TestCarriedCoordinateLedgerExpiresOnItsOwn(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	tree := gateTree(t, root)

	if !tree.has(carriedLedgerPath) {
		t.Fatalf("ведомости переносимых координат (%s) в составе дерева НЕТ.\n\n"+
			"Отсутствие ведомости — не пустая ведомость: пустая говорит «переносить "+
			"нечего», отсутствующая не говорит ничего.", carriedLedgerPath)
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(carriedLedgerPath)))
	if err != nil {
		t.Fatalf("чтение ведомости %s: %v", carriedLedgerPath, err)
	}

	rows, sections, census := check.ParseCarriedCoordinateLedger(string(body))

	var kept, removed, rewritten, notSubject, unknown int
	for _, r := range rows {
		switch r.Outcome {
		case check.CarriedOutcomeKept:
			kept++
		case check.CarriedOutcomeRemoved:
			removed++
		case check.CarriedOutcomeRewritten:
			rewritten++
		case check.CarriedOutcomeNotSubject:
			notSubject++
		default:
			unknown++
		}
	}

	mirrorFiles := carriedMirrorReaders(t, root, tree)
	ownRoots := carriedOwnRoots(tree.files)
	inScope := func(coord string) bool {
		i := strings.IndexByte(coord, '/')
		if i < 0 {
			return true
		}
		return ownRoots[coord[:i]]
	}

	t.Logf("перепись ведомости: строк документа %d, разделов %d, таблиц %d, строк таблиц %d "+
		"(без координаты %d); исходы — оставлено %d, снято %d, переписано %d, не предмет %d, "+
		"не опознано %d", census.Lines, census.Sections, census.Tables, census.Rows,
		census.RowsWithoutCoordinate, kept, removed, rewritten, notSubject, unknown)
	t.Logf("перепись дерева: файлов состава %d, из них читающих зеркальную колонку в %d",
		len(tree.files), len(mirrorFiles))

	if census.Tables == 0 {
		t.Fatalf("в %s (%d строк, %d разделов) не найдено НИ ОДНОЙ таблицы с колонками "+
			"координаты и исхода.", carriedLedgerPath, census.Lines, census.Sections)
	}

	findings := check.AdjudicateCarriedLedger(carriedLedgerPath, rows, sections, tree.has, inScope, mirrorFiles)
	if len(findings) > 0 {
		t.Fatalf("ведомость переносимых координат разошлась с деревом — %d находка(и):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}

	if kept == 0 {
		t.Logf("оставленных координат НОЛЬ: ведомость пуста, и это её ЦЕЛЬ.")
		return
	}
	t.Logf("оставлено %d координат(ы), у каждой назван раздел с предикатом снятия; "+
		"координат зеркальной колонки в дереве %d, и все названы", kept, len(mirrorFiles))
}

// carriedMirrorReaders — файлы состава, читающие зеркальную колонку.
func carriedMirrorReaders(t *testing.T, root string, tree gateFileTree) []string {
	t.Helper()
	var out []string
	for rel := range tree.files {
		if strings.HasSuffix(rel, "_test.go") || rel == carriedLedgerPath {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		text := string(body)
		for _, tok := range carriedMirrorTokens {
			if strings.Contains(text, tok) {
				out = append(out, rel)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
