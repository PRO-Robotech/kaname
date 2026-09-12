// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_writer_lock_test.go — держатель Г1. Порт с монорепо, см. годок
// `catalog_writer_lock.go`. Имя гейта сохранено дословно
// (`TestIAM1034_EveryCatalogRowWriterTakesTheCatalogLock`).
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

// catalogWriterCensusFloor — прод-файлов, ниже которого обход беспредметен.
const catalogWriterCensusFloor = 200

func catalogWriteFindings(sites []check.CatalogWriteFinding) []string {
	var out []string
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s:%d  [%s] %s — %s", s.File, s.Line, s.Unit, s.What, s.Why))
	}
	sort.Strings(out)
	return out
}

// TestIAM1034_EveryCatalogRowWriterTakesTheCatalogLock — сам гейт Г1.
func TestIAM1034_EveryCatalogRowWriterTakesTheCatalogLock(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	all, err := treecorpus.Under(root)
	if err != nil {
		t.Fatalf("состав дерева: %v", err)
	}
	var rels []string
	for _, abs := range all {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var sources []check.CatalogSource
	for _, rel := range rels {
		src, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("прочитать %s: %v — непрочитанное есть НАХОДКА, а не пропуск", rel, rerr)
		}
		sources = append(sources, check.CatalogSource{Path: rel, Src: src})
	}

	findings, census, err := check.ScanCatalogWriteLocking(sources)
	if err != nil {
		t.Fatalf("разбор прод-дерева: %v", err)
	}

	t.Logf("перепись: прод-файлов подано %d, разобрано %d · функций %d, из них "+
		"исполнителей %d · строковых литералов %d, комментариев %d · ТЕКСТОМ совпало "+
		"операторов записи %d в %d файле(ах) · ИСПОЛНЯЕТСЯ из них %d в %d файле(ах) · "+
		"пишущих единиц %d, из них запирающих %d · мест взятия замка %d · находок %d",
		census.Files, census.Parsed, census.Funcs, census.Executors,
		census.StringLiterals, census.Comments,
		census.TextMatches, census.TextFiles, census.Executed, census.ExecutingFiles,
		census.WriteUnits, census.LockedUnits, census.LockSites, len(findings))

	if census.Parsed < catalogWriterCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d",
			census.Parsed, catalogWriterCensusFloor)
	}
	if census.Executed == 0 {
		t.Fatalf("в прод-дереве НЕ НАЙДЕНО ни одного исполняемого оператора записи строк "+
			"каталога (текстом совпало %d в %d файле(ах), разобрано %d файлов) — писатель "+
			"переехал либо сменил форму запроса", census.TextMatches, census.TextFiles, census.Parsed)
	}
	if census.LockSites == 0 {
		t.Fatalf("в прод-дереве не найдено НИ ОДНОГО взятия консультативного замка при %d "+
			"исполняемых операторах записи каталога — либо замок снят целиком, либо разбор "+
			"перестал его опознавать; в обоих случаях подтверждение применения перестало "+
			"быть CAS", census.Executed)
	}

	if f := catalogWriteFindings(findings); len(f) > 0 {
		t.Fatalf("строки каталога пишет %d единица(ы), не запирающая каталог:\n  %s\n\n"+
			"Подтверждение применения (отпечаток состояния модуля) есть CAS ТОЛЬКО потому, "+
			"что между чтением отпечатка и записью строк не может встать второй писатель. "+
			"Обеспечивает это `pg_advisory_xact_lock(hashtext(%s))`, а не само сравнение.\n"+
			"Приёмка: docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md §7, "+
			"держатель Г1 (kacho#1034)",
			len(f), strings.Join(f, "\n  "), check.CatalogLockKeyIdent)
	}
}
