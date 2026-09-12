// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_single_source_test.go — состав утверждений выданного токена
// объявлен В ОДНОМ месте, которым пользуются обе стороны выдачи (порт с
// монорепо `internal/repohygiene/tokenclaimsinglesource_test.go`, держатель
// `TestTokenClaimsAreAssembledInOnePlace`, снят вынесением службы доступа —
// `kacho#2597`; приёмка F2, сценарий F2-42, §2.11).
//
// Ведомость вторых сборок (`claimDebt` предка) сюда НЕ перенесена: на дату
// переноса она была пуста в монорепо, а перемер по дереву kaname (ниже)
// подтверждает то же — сборок вне владельца нет. Появится вторая сборка —
// заводить ведомость тем же изменением, а не постфактум.
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
	// claimOwnerFileRel — единственный дом сборки состава, от корня модуля.
	claimOwnerFileRel = "internal/service/token_enrichment_service.go"
	// claimKeyPrefix — префикс имени утверждения продукта.
	claimKeyPrefix = "kaname_"
	claimMinKeys   = 3
	// claimLanesFloor — сколько РАЗНЫХ функций обязаны звать сборщики.
	claimLanesFloor  = 2
	claimCensusFloor = 300
)

// claimBuilders — сборщики состава: то, чем состав ПОТРЕБЛЯЕТСЯ. Перечень
// закрыт и живёт рядом с владельцем.
var claimBuilders = map[string]bool{
	"userClaims":      true,
	"saClaims":        true,
	"federatedClaims": true,
	"userTokenClaims": true,
	"MinimalClaims":   true,
}

type claimTreeScan struct {
	Assemblies []check.ClaimAssembly
	Calls      []check.ClaimBuilderCall
	Parsed     int
	Census     check.ClaimAssemblyCensus
}

func scanClaimTree(t *testing.T) (claimTreeScan, string) {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var out claimTreeScan
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
		out.Parsed++
		as, c1, aerr := check.ScanClaimAssemblies(rel, src, claimKeyPrefix, claimMinKeys)
		if aerr != nil {
			t.Fatalf("разбор сборок %s: %v", rel, aerr)
		}
		cs, c2, cerr := check.ScanClaimBuilderCalls(rel, src, claimBuilders)
		if cerr != nil {
			t.Fatalf("разбор вызовов %s: %v", rel, cerr)
		}
		out.Assemblies = append(out.Assemblies, as...)
		out.Calls = append(out.Calls, cs...)
		out.Census.MapLiterals += c1.MapLiterals
		out.Census.EmptyMapLiterals += c1.EmptyMapLiterals
		out.Census.KeyedLiterals += c1.KeyedLiterals
		out.Census.Calls += c2.Calls
	}
	return out, corpusRoot
}

// TestTokenClaimsAreAssembledInOnePlace — сам гейт.
func TestTokenClaimsAreAssembledInOnePlace(t *testing.T) {
	t.Parallel()
	scan, _ := scanClaimTree(t)

	lanes := map[string]bool{}
	for _, c := range scan.Calls {
		lanes[c.Func] = true
	}
	var ownerAssemblies, outside []check.ClaimAssembly
	for _, a := range scan.Assemblies {
		if a.File == claimOwnerFileRel {
			ownerAssemblies = append(ownerAssemblies, a)
			continue
		}
		outside = append(outside, a)
	}

	t.Logf("перепись: файлов Go разобрано %d, литералов отображения %d (пустых %d, с "+
		"ключами состава %d), вызовов осмотрено %d; сборок состава найдено %d — у "+
		"владельца %d, вне его %d; полос, зовущих сборщики, %d",
		scan.Parsed, scan.Census.MapLiterals, scan.Census.EmptyMapLiterals,
		scan.Census.KeyedLiterals, scan.Census.Calls, len(scan.Assemblies),
		len(ownerAssemblies), len(outside), len(lanes))

	if scan.Parsed < claimCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", scan.Parsed, claimCensusFloor)
	}
	if scan.Census.KeyedLiterals == 0 {
		t.Fatalf("на %d файлах не найдено НИ ОДНОГО литерала с ключами состава", scan.Parsed)
	}

	if len(ownerAssemblies) == 0 {
		t.Fatalf("сборок состава у владельца (%s) НОЛЬ при %d сборках в дереве — состав "+
			"переехал, и гейт стережёт координату, которой больше не существует",
			claimOwnerFileRel, len(scan.Assemblies))
	}

	if len(lanes) < claimLanesFloor {
		var where []string
		for l := range lanes {
			where = append(where, l)
		}
		sort.Strings(where)
		t.Fatalf("сборщики состава зовутся из %d полосы (%s) при пороге %d: «одним местом "+
			"пользуются ОБЕ стороны» проверяемо только тогда, когда сторон две",
			len(lanes), strings.Join(where, ", "), claimLanesFloor)
	}

	var fresh []string
	for _, a := range outside {
		fresh = append(fresh, fmt.Sprintf("%s:%d  %s — %d ключей", a.File, a.Line, a.Func, len(a.Keys)))
	}
	sort.Strings(fresh)
	if len(fresh) > 0 {
		t.Fatalf("состав утверждений собирается ВНЕ %s — %d место(а):\n  %s\n\n"+
			"Пока перечень живёт в двух местах, различие между ними не выражено и не может "+
			"покраснеть. Первая же правка одной стороны разойдётся с другой молча.",
			claimOwnerFileRel, len(fresh), strings.Join(fresh, "\n  "))
	}
}
