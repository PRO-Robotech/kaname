// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_foreign_brand_test.go — клеймо выпущенного токена не называет
// ЧУЖОЙ платформенный бренд (порт-ось-А с монорепо
// `internal/repohygiene/tokenclaimforeignbrand_test.go`, снят вынесением
// службы доступа — `kacho#2597`; задача продукта #2127).
//
// Разбор сужения до одной оси — в шапке `token_claim_foreign_brand.go`.
// Способность гейта упасть и смолчать доказана инъекцией —
// token_claim_foreign_brand_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// tokenClaimGoCensusFloor — прод-файлов Go, ниже которого обход беспредметен.
const tokenClaimGoCensusFloor = 300

func TestTokenClaimNamesDoNotCarryTheForeignBrand(t *testing.T) {
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
		parsed    int
		literals  int
		shaped    int
		positions int
		uses      []check.TokenClaimUse
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		u, census, serr := check.ScanTokenClaimForeignBrand(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		literals += census.Literals
		shaped += census.Shaped
		positions += census.Positions
		uses = append(uses, u...)
	}

	sort.Slice(uses, func(i, j int) bool {
		if uses[i].File != uses[j].File {
			return uses[i].File < uses[j].File
		}
		return uses[i].Line < uses[j].Line
	})

	t.Logf("перепись: прод-файлов Go разобрано %d, строковых литералов %d, "+
		"имеющих форму имени клейма %d, стоящих в позиции чеканки/чтения %d, "+
		"из чужого словаря %q %d",
		parsed, literals, shaped, positions, check.TokenClaimForeignNamespace, len(uses))

	if parsed < tokenClaimGoCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d",
			parsed, tokenClaimGoCensusFloor)
	}
	if literals == 0 {
		t.Fatalf("прочитано ноль строковых литералов — вердикт беспредметен")
	}

	for _, u := range uses {
		t.Errorf("%s:%d %s — клеймо %q названо словарём чужой платформы %q (%s). "+
			"Клеймо читает предъявитель токена БЕЗ нашего исходного кода — приставка "+
			"имени есть идентичность, а не код (kacho#2076): свой словарь — %q.",
			u.File, u.Line, u.Func, u.Name, u.Namespace, u.Form, check.TokenClaimOwnNamespace)
	}
}
