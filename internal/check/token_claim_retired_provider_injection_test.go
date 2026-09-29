// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_retired_provider_injection_test.go — падучесть гейта в ОБЕ
// стороны: дефект краснеет и называет координату, законный близнец той же
// формы молчит, пустой обход — не зелёный.
package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// claimNamingJudge — разбор синтетического файла ТЕМ ЖЕ разбором, что у гейта
// на дереве, и суд над ним тем же телом.
func claimNamingJudge(t *testing.T, src string) ([]check.ClaimNamingRetiredIssuer, check.ClaimNamingRetiredIssuerCensus) {
	t.Helper()
	as, _, err := check.ScanClaimAssemblies("internal/service/lane.go", []byte(src), claimKeyPrefix, claimMinKeys)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(as) != 1 {
		t.Fatalf("предпосылка: синтетика обязана давать ровно одну сборку состава, дала %d", len(as))
	}
	got, census, err := check.JudgeClaimNamesNamingRetiredIssuer(as)
	if err != nil {
		t.Fatalf("гейт: %v", err)
	}
	return got, census
}

// TestClaimNaming_RedOnAKeyNamingTheProvider — ИНЪЕКЦИЯ: ключ сборки,
// названный по поставщику, — находка с координатой и именем ключа.
func TestClaimNaming_RedOnAKeyNamingTheProvider(t *testing.T) {
	t.Parallel()
	got, census := claimNamingJudge(t, `package service

func saClaims(subject string) map[string]any {
	return map[string]any{
		"kaname_external_id":     subject,
		"kaname_hydra_client_id": subject,
		"kaname_audience":        "api.test.cloud",
	}
}
`)
	if len(got) != 1 {
		t.Fatalf("ключ, названный по поставщику, НЕ стал находкой: %+v (%s)", got, census)
	}
	f := got[0]
	if f.File != "internal/service/lane.go" || f.Line != 4 || f.Func != "saClaims" || f.Key != "kaname_hydra_client_id" {
		t.Errorf("находка не называет координату, функцию и ключ: %+v", f)
	}
	if !strings.Contains(f.String(), "kaname_hydra_client_id") || !strings.Contains(f.String(), "internal/service/lane.go:4") {
		t.Errorf("текст находки не называет причину: %s", f)
	}
	if census.Assemblies != 1 || census.Keys != 3 || census.Findings != 1 {
		t.Errorf("перепись не сходится с осмотренным: %s", census)
	}
}

// TestClaimNaming_RedOnAnyLetterCase — ИНЪЕКЦИЯ: имя поставщика в ином
// регистре — тоже находка.
func TestClaimNaming_RedOnAnyLetterCase(t *testing.T) {
	t.Parallel()
	got, _ := claimNamingJudge(t, `package service

func userClaims(subject string) map[string]any {
	return map[string]any{
		"kaname_external_id": subject,
		"kaname_Hydra_Sub":   subject,
		"kaname_audience":    "api.test.cloud",
	}
}
`)
	if len(got) != 1 || got[0].Key != "kaname_Hydra_Sub" {
		t.Fatalf("имя поставщика в ином регистре НЕ стало находкой: %+v", got)
	}
}

// TestClaimNaming_SilentOnTheOwnNameTwin — ЗАКОННЫЙ БЛИЗНЕЦ той же формы:
// утверждение названо в наших терминах, а имя поставщика несёт только
// ЗНАЧЕНИЕ — предмет гейта имя, значение судят пробы полос.
func TestClaimNaming_SilentOnTheOwnNameTwin(t *testing.T) {
	t.Parallel()
	got, census := claimNamingJudge(t, `package service

func saClaims(subject string) map[string]any {
	return map[string]any{
		"kaname_external_id": subject,
		"kaname_client_id":   "hydra-mirror-client",
		"kaname_audience":    "api.test.cloud",
	}
}
`)
	if len(got) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %+v", got)
	}
	if census.Keys != 3 {
		t.Errorf("близнец молчит, потому что НЕ ОСМОТРЕН, а не потому что чист: %s", census)
	}
}

// TestClaimNaming_EmptyAssemblySetIsNotAVerdict — пустой перечень сборок —
// отказ, а не зелёное.
func TestClaimNaming_EmptyAssemblySetIsNotAVerdict(t *testing.T) {
	t.Parallel()
	got, _, err := check.JudgeClaimNamesNamingRetiredIssuer(nil)
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой перечень сборок принят за вердикт: находок %d, ошибка %v", len(got), err)
	}
}
