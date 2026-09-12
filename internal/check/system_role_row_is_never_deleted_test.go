// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_role_row_is_never_deleted_test.go — гейт решения «отзыв роли модуля —
// это ПОМЕТКА, а не удаление строки» (порт с монорепо
// `internal/repohygiene/systemrolerowisneverdeleted_test.go`, держатель
// `TestSystemRoleRowIsNeverDeleted`, снят вынесением службы доступа —
// `kacho#2597`; запись решения
// `docs/engineering/architecture/role-withdrawal-is-a-mark.md`, задача
// продукта #1913).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// system_role_row_is_never_deleted_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// roleDeleteCensusFloor — прод-файлов Go, ниже которого обход беспредметен.
const roleDeleteCensusFloor = 300

// roleDeleteFindings — предикат находки. Тот же зовёт инъекция.
func roleDeleteFindings(sites []check.RoleDeleteSite) []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s:%d  %s", s.File, s.Line, s.What))
	}
	sort.Strings(out)
	return out
}

// TestSystemRoleRowIsNeverDeleted — сам гейт.
func TestSystemRoleRowIsNeverDeleted(t *testing.T) {
	t.Parallel()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var (
		parsed     int
		lits       int
		comments   int
		statements int
		guarded    int
		sites      []check.RoleDeleteSite
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		s, census, serr := check.ScanRoleDeletes(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		lits += census.StringLiterals
		comments += census.Comments
		statements += census.Statements
		guarded += census.Guarded
		sites = append(sites, s...)
	}

	t.Logf("перепись: прод-файлов Go разобрано %d, строковых литералов %d, "+
		"комментариев %d, операторов удаления над `roles` прочитано %d, "+
		"из них сужены на пользовательскую роль %d, находок %d",
		parsed, lits, comments, statements, guarded, len(sites))

	if parsed < roleDeleteCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d — обход "+
			"читает не то дерево, и «ноль находок» здесь неотличимо от «ноль прочитанного»",
			parsed, roleDeleteCensusFloor)
	}
	if lits == 0 || comments == 0 {
		t.Fatalf("прочитано литералов %d, комментариев %d — различение «код против прозы» "+
			"беспредметно, а вместе с ним и обе половины гейта", lits, comments)
	}

	if statements == 0 {
		t.Fatalf("операторов удаления над `roles` в прод-коде прочитано НОЛЬ — предмет "+
			"гейта исчез (прочитано файлов %d, литералов %d). Это отказ, а не чистота: "+
			"проверка, которой нечего искать, неотличима от проверки, ничего не нашедшей",
			parsed, lits)
	}

	if findings := roleDeleteFindings(sites); len(findings) > 0 {
		t.Fatalf("строку СИСТЕМНОЙ роли удаляет прод-код — %d место(а):\n  %s\n\n"+
			"Всякая роль, объявленная манифестом модуля, системная by construction "+
			"(`moduleroles/apply.go` ставит `IsSystem: true`, а `roles.is_system` "+
			"вычисляется из `cluster_id`). Оператор удаления, не сужённый на "+
			"пользовательскую роль, делает отзыв роли модуля выразимым УДАЛЕНИЕМ "+
			"строки — а решение линии обратное: отзыв есть ПОМЕТКА, строка остаётся.\n"+
			"Решение и его довод: docs/engineering/architecture/role-withdrawal-is-a-mark.md",
			len(findings), strings.Join(findings, "\n  "))
	}
}
