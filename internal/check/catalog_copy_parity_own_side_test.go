// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity_own_side_test.go — ведомость окон сверки копий говорит о
// НАШЕЙ копии правду, и это проверяется без дерева платформы.
//
// Сверка копий (`CompareCatalogCopies`) судит ведомость в обе стороны, но
// исполняется только при выборке копии края — в конвейере, заданием
// `catalogparity`. Половина утверждений ведомости — о нашем дереве: запись,
// ждущая края, называет глагол, который у нас ЕСТЬ; переаннотированная запись
// называет нашу запись ДОСЛОВНО. Эта половина проверяема в самостоятельном
// клоне, и ждать ради неё конвейера незачем: опечатка в объявленной записи
// (замер kaname#986 — экранирование `<` в дословной записи, снятое при
// правке файла) иначе всплывает лишь красным заданием после отправки.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestDeclaredCatalogWindowsTellTheTruthAboutOurCopy — каждое окно ведомости,
// утверждающее о нашей копии, истинно на ней: запись, ждущая края, называет
// глагол, который в нашей копии стоит ровно один раз; переаннотированная —
// нашу запись, которая стоит в копии дословно и ровно один раз.
func TestDeclaredCatalogWindowsTellTheTruthAboutOurCopy(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownCatalogCopyPath)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: своя копия каталога не прочитана: %v", err)
	}
	own := string(raw)
	if !strings.Contains(own, `"fqn": `) {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в своей копии нет ни одной записи (%d байт)", len(raw))
	}

	pending := check.CatalogPendingEntries()
	reannotated := check.CatalogReannotatedEntries()
	t.Logf("перепись: ждущих края %d · переаннотированных %d · копия %d байт", len(pending), len(reannotated), len(raw))

	for _, e := range pending {
		if n := strings.Count(own, `"fqn": "`+e.OwnFQN+`"`); n != 1 {
			t.Errorf("запись, ждущая края, называет глагол %q, который в нашей копии стоит %d раз (нужно 1). %s",
				e.OwnFQN, n, e.Refs)
		}
	}
	for _, e := range reannotated {
		if n := strings.Count(own, e.OwnBody); n != 1 {
			t.Errorf("переаннотированная запись %q: объявленная наша запись стоит в копии %d раз (нужно 1 дословно). %s",
				e.FQN, n, e.Refs)
		}
	}
}
