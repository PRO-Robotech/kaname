// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_retired_provider_test.go — держатель гейта класса: ни одна
// сборка состава утверждений в дереве не называет прежнего поставщика ключом
// (kaname#375). Обход — тот же, что у гейта единственности состава
// (`scanClaimTree`), поэтому их переписи сравнимы.
package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestNoTokenClaimNameNamesTheRetiredProvider — сам гейт.
func TestNoTokenClaimNameNamesTheRetiredProvider(t *testing.T) {
	t.Parallel()
	scan, _ := scanClaimTree(t)
	if scan.Parsed < claimCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", scan.Parsed, claimCensusFloor)
	}

	findings, census, err := check.JudgeClaimNamesNamingRetiredIssuer(scan.Assemblies)
	t.Logf("файлов Go разобрано %d · %s", scan.Parsed, census)
	if errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("на %d файлах не найдено НИ ОДНОЙ сборки состава — гейт ничего не осмотрел: %v", scan.Parsed, err)
	}
	if err != nil {
		t.Fatalf("гейт: %v", err)
	}
	if len(findings) > 0 {
		lines := make([]string, 0, len(findings))
		for _, f := range findings {
			lines = append(lines, f.String())
		}
		t.Fatalf("утверждений, названных по прежнему поставщику, %d:\n  %s", len(findings), strings.Join(lines, "\n  "))
	}
}
