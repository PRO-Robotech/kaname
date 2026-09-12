// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_single_source_injection_test.go — доказательство падучести в
// ОБЕ стороны (порт одноимённой пробы репозитория платформы, снят там
// вынесением службы доступа — `kacho#2597`).
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestClaimAssembly_RedOnASecondAssemblySite — ИНЪЕКЦИЯ: составной литерал с
// >= 3 ключами claimKeyPrefix ВНЕ владельца — вторая сборка.
func TestClaimAssembly_RedOnASecondAssemblySite(t *testing.T) {
	t.Parallel()
	src := `package internal_iam

func fallbackClaims(subject string) map[string]any {
	return map[string]any{
		"kaname_user_id":    subject,
		"kaname_account_id": "acc-x",
		"kaname_mfa_at":      0,
	}
}
`
	got, census, err := check.ScanClaimAssemblies("internal_iam/fallback.go", []byte(src), claimKeyPrefix, claimMinKeys)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.KeyedLiterals != 1 {
		t.Fatalf("литерал с ключами состава не распознан: %+v", census)
	}
	if len(got) != 1 {
		t.Fatalf("вторая сборка НЕ стала находкой: %d", len(got))
	}
	if got[0].Func != "fallbackClaims" || len(got[0].Keys) != 3 {
		t.Errorf("находка не называет функцию/ключи верно: %+v", got[0])
	}
}

// TestClaimAssembly_SilentBelowTheKeyThreshold — ЗАКОННЫЙ БЛИЗНЕЦ: два ключа —
// это чтение/правка значения, а не сборка состава.
func TestClaimAssembly_SilentBelowTheKeyThreshold(t *testing.T) {
	t.Parallel()
	src := `package edge

func ctxFields(subject string) map[string]any {
	return map[string]any{"kaname_user_id": subject, "kaname_trace": "x"}
}
`
	got, _, err := check.ScanClaimAssemblies("edge/ctx.go", []byte(src), claimKeyPrefix, claimMinKeys)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("литерал НИЖЕ порога ключей объявлен сборкой: %+v", got)
	}
}

// TestClaimAssembly_SilentOnAssignmentForm — распознаватель не видит форму
// «присвоение по одному ключу», и это ГРАНИЦА, названная честно, а не
// молчаливая слепота: пустой литерал считается отдельно (EmptyMapLiterals).
func TestClaimAssembly_SilentOnAssignmentForm(t *testing.T) {
	t.Parallel()
	src := `package internal_iam

func byAssignment(subject string) map[string]any {
	m := map[string]any{}
	m["kaname_user_id"] = subject
	m["kaname_account_id"] = "acc-x"
	m["kaname_mfa_at"] = 0
	return m
}
`
	got, census, err := check.ScanClaimAssemblies("internal_iam/assign.go", []byte(src), claimKeyPrefix, claimMinKeys)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("форма присваиваниями распознана как сборка (граница нарушена): %+v", got)
	}
	if census.EmptyMapLiterals != 1 {
		t.Fatalf("пустой литерал не засчитан отдельно: %+v", census)
	}
}

// TestClaimBuilderCalls_CountsDistinctCallingFunctions — вызовы одного
// сборщика из ДВУХ разных функций — это ДВЕ полосы, не одна.
func TestClaimBuilderCalls_CountsDistinctCallingFunctions(t *testing.T) {
	t.Parallel()
	builders := map[string]bool{"userClaims": true}
	src := `package service

func (s *TokenEnrichmentService) EnrichClaims() {
	_ = s.userClaims(nil, "", nil)
}

func (o *ownLane) Issue() {
	_ = o.svc.userClaims(nil, "", nil)
}
`
	got, _, err := check.ScanClaimBuilderCalls("service/x.go", []byte(src), builders)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	lanes := map[string]bool{}
	for _, c := range got {
		lanes[c.Func] = true
	}
	if len(lanes) != 2 {
		t.Fatalf("две функции, зовущие сборщик, засчитаны как %d полос(ы): %+v", len(lanes), got)
	}
}

// TestClaimBuilderCalls_SilentOnUnlistedCallee — вызов функции, НЕ входящей в
// закрытый перечень сборщиков, не находка.
func TestClaimBuilderCalls_SilentOnUnlistedCallee(t *testing.T) {
	t.Parallel()
	builders := map[string]bool{"userClaims": true}
	src := `package service

func other() {
	_ = notABuilder()
}
`
	got, _, err := check.ScanClaimBuilderCalls("service/y.go", []byte(src), builders)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("вызов ВНЕ закрытого перечня засчитан сборщиком: %+v", got)
	}
}
