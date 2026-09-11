// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_foreign_brand_injection_test.go — доказательство падучести в
// ОБЕ стороны (порт-ось-А монорепошного предшественника-инъекции для гейта
// `tokenclaimforeignbrand`, снят вынесением службы доступа — `kacho#2597`;
// координата предшественника не воспроизводится здесь буквально — путь
// `internal/repohygiene/` в дереве kaname не существует, и цитата читалась
// бы этим же гейтом как необещанное).
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestTokenClaimForeignBrand_RedOnMintedKey — ИНЪЕКЦИЯ: клеймо чужого словаря
// стоит ключом СОСТАВА — место, где токен ЧЕКАНЯТ.
func TestTokenClaimForeignBrand_RedOnMintedKey(t *testing.T) {
	t.Parallel()
	src := `package domain

func mint() map[string]any {
	return map[string]any{"kacho_user_id": "usr-x"}
}
`
	uses, census, err := check.ScanTokenClaimForeignBrand("mint.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Positions != 1 {
		t.Fatalf("позиций найдено %d из одной", census.Positions)
	}
	if len(uses) != 1 {
		t.Fatalf("ожидалась 1 находка, получено %d", len(uses))
	}
	if uses[0].Form != check.TokenClaimFormKey {
		t.Errorf("форма не распознана как ключ состава: %q", uses[0].Form)
	}
	if uses[0].Name != "kacho_user_id" {
		t.Errorf("имя не распознано: %q", uses[0].Name)
	}
}

// TestTokenClaimForeignBrand_RedOnReadAndCaseAndArg — три остальные позиции.
func TestTokenClaimForeignBrand_RedOnReadAndCaseAndArg(t *testing.T) {
	t.Parallel()
	src := `package domain

func read(claims map[string]any) {
	pt, _ := claims["kacho_principal_type"].(string)
	switch pt {
	case "kacho_mfa_at":
	}
	verifiedClaim(pt, "kacho_principal_display_name")
}
`
	uses, _, err := check.ScanTokenClaimForeignBrand("read.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(uses) != 3 {
		t.Fatalf("ожидались 3 находки (чтение, разбор, вызов), получено %d: %+v", len(uses), uses)
	}
	forms := map[check.TokenClaimForm]bool{}
	for _, u := range uses {
		forms[u.Form] = true
	}
	for _, want := range []check.TokenClaimForm{
		check.TokenClaimFormRead, check.TokenClaimFormCase, check.TokenClaimFormArg,
	} {
		if !forms[want] {
			t.Errorf("форма %q не распознана: %+v", want, uses)
		}
	}
}

// TestTokenClaimForeignBrand_SilentOnOwnNamespace — ЗАКОННЫЙ БЛИЗНЕЦ: та же
// форма, свой словарь.
func TestTokenClaimForeignBrand_SilentOnOwnNamespace(t *testing.T) {
	t.Parallel()
	src := `package domain

const ClaimPrincipalType = "kaname_principal_type"

func read(claims map[string]any) {
	_, _ = claims["kaname_principal_id"].(string)
}
`
	uses, _, err := check.ScanTokenClaimForeignBrand("own.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(uses) != 0 {
		t.Errorf("гейт краснеет на СВОЁМ словаре: %+v", uses)
	}
}

// TestTokenClaimForeignBrand_SilentOnLegitimateForeignDictionaries — ЗАКОННЫЙ
// БЛИЗНЕЦ, НАЙДЕННЫЙ НЕ ЧТЕНИЕМ, А ПРОГОНОМ НА НАСТОЯЩЕМ ДЕРЕВЕ: приставка
// чужой платформы законна у схем, метрик и типов ресурсов. Первая редакция
// этого гейта краснела на РЕАЛЬНОМ коде —
// `cmd/kaname/schema_guard.go` (константа `schemaOfThePreviousInstall`, имя
// схемы прежней установки; значение не выписывается — его стережёт свой
// гейт) — потому что объявление константы формы
// «словарь_тело» само по себе считалось позицией клейма. Сужение (см. шапку
// `token_claim_foreign_brand.go`) требует, чтобы идентификатор Go НАЗЫВАЛ
// клеймо (содержит «claim», как `ClaimPrincipalType`).
func TestTokenClaimForeignBrand_SilentOnLegitimateForeignDictionaries(t *testing.T) {
	t.Parallel()
	src := `package main

const schemaOfThePreviousInstall = "kacho_former_schema_synthetic"
const backlogDepthMetric = "kacho_vpc_outbox_backlog_depth"
`
	uses, census, err := check.ScanTokenClaimForeignBrand("schema_guard.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Positions != 0 {
		t.Fatalf("объявление НЕ-клейменой константы засчитано позицией клейма: %d — "+
			"гейт покраснел бы на верном коде дерева kaname", census.Positions)
	}
	if len(uses) != 0 {
		t.Fatalf("законная схема/метрика объявлена находкой: %+v", uses)
	}
}

// TestTokenClaimForeignBrand_RedOnConstNamedAsAClaim — КОНТРОЛЬ узкого
// сужения: без него оно молчало бы на ВСЯКОЙ константе, а не только на
// схемах/метриках. Идентификатор, называющий клеймо явно, обязан
// распознаваться.
func TestTokenClaimForeignBrand_RedOnConstNamedAsAClaim(t *testing.T) {
	t.Parallel()
	src := `package domain

const ClaimLegacyPrincipalType = "kacho_principal_type"
`
	uses, census, err := check.ScanTokenClaimForeignBrand("legacy.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Positions != 1 {
		t.Fatalf("константа, названная клеймом, не засчитана позицией: %d", census.Positions)
	}
	if len(uses) != 1 || uses[0].Form != check.TokenClaimFormConst {
		t.Fatalf("находка не распознана как объявление константы: %+v", uses)
	}
}

// TestTokenClaimForeignBrand_SilentOnItsOwnExplanation — ЗАКОННЫЙ БЛИЗНЕЦ:
// слово `kacho_user_id` в КОММЕНТАРИИ, объясняющем эту же проверку.
func TestTokenClaimForeignBrand_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	src := `package check

// Предмет: клеймо "kacho_user_id" из чужого словаря — находка.
func explain() {}
`
	uses, _, err := check.ScanTokenClaimForeignBrand("doc.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(uses) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем проверку: %+v", uses)
	}
}

// TestTokenClaimForeignBrand_SilentOnUnshapedString — законный близнец: строка
// без формы имени клейма (нет подчёркивания либо словарь не строчный).
func TestTokenClaimForeignBrand_SilentOnUnshapedString(t *testing.T) {
	t.Parallel()
	src := `package domain

func f(claims map[string]any) {
	_, _ = claims["principal"].(string)
	_, _ = claims["Kacho_User_Id"].(string)
}
`
	uses, _, err := check.ScanTokenClaimForeignBrand("f.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(uses) != 0 {
		t.Errorf("строка без формы имени клейма распознана как клеймо: %+v", uses)
	}
}
