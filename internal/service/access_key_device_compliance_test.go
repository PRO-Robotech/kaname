// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// access_key_device_compliance_test.go — Ф7-39 (задача PRO-Robotech/kacho#1273,
// приёмка `access-keys-are-ours.md` §1.8, Р4): значение согласия устройства в
// утверждениях токена НЕ выводится из наличия ключа доступа. Продукт утверждал
// «аттестованность устройства» на основании области `webauthn`/`passkey` среди
// выданных — ровно ту проверку, которую Р4 решает не строить. Второй носитель
// того же обещания — строка публичной страницы — снимается Ф7-32.
//
// Две половины: поведение (значение с ключом равно значению без ключа) и
// перепись по исходнику (полос выдачи, ставящих значение, 5 · выводящих
// аттестованность из наличия ключа 0). Одна величина скрыла бы, какая из двух
// о чём: «поля больше нет» и «полоса исчезла» дают другой знаменатель.

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessKey_F7_39_DeviceComplianceIsNotDerivedFromTheKey(t *testing.T) {
	svc := NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"}, nil)
	svc.now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	user := domain.User{ID: "usr-abc", AccountID: "acc-xyz"}

	withKey := svc.userClaims(user, "ext-1", TokenHookContext{GrantedScopes: []string{"openid", "webauthn"}})
	without := svc.userClaims(user, "ext-1", TokenHookContext{GrantedScopes: []string{"openid"}})

	// Положительный контроль: значение по-прежнему ВЫСТАВЛЯЕТСЯ — «не
	// выводится» отличимо от «поля больше нет».
	require.Contains(t, withKey, "kaname_device_compliance")
	require.Contains(t, without, "kaname_device_compliance")
	require.Equal(t, "unknown", without["kaname_device_compliance"])
	require.Equal(t, without["kaname_device_compliance"], withKey["kaname_device_compliance"],
		"наличие ключа среди выданных областей не есть доказательство аттестации устройства (Р4)")
	for _, sc := range []string{"passkey", "webauthn"} {
		got := svc.userClaims(user, "ext-1", TokenHookContext{GrantedScopes: []string{sc}})
		require.Equal(t, "unknown", got["kaname_device_compliance"], "область %s", sc)
	}
}

var (
	reComplianceSet     = regexp.MustCompile(`"kaname_device_compliance":\s*"unknown"`)
	reComplianceDerived = regexp.MustCompile(`\["kaname_device_compliance"\]\s*=\s*"attested"|"kaname_device_compliance":\s*"attested"`)
)

// TestAccessKey_F7_39_IssuanceLanesCensus — перепись по исходнику производителя:
// «полос выдачи, ставящих значение, N · из них выводящих аттестованность из
// наличия ключа M» — обязано быть `5 · 0`. Знаменатель — пять полос — не
// двигается снятием деривации; исчезновение полосы и исчезновение поля дали бы
// другой знаменатель, и различить их одной величиной было бы нельзя.
func TestAccessKey_F7_39_IssuanceLanesCensus(t *testing.T) {
	raw, err := os.ReadFile("token_enrichment_service.go")
	require.NoError(t, err)
	lanes := len(reComplianceSet.FindAll(raw, -1))
	derived := len(reComplianceDerived.FindAll(raw, -1))
	t.Logf("перепись: полос выдачи, ставящих kaname_device_compliance, %d · из них выводящих аттестованность из наличия ключа %d", lanes, derived)
	require.Equal(t, 5, lanes, "полос выдачи ровно пять (userClaims · saClaims · federatedClaims · userTokenClaims · MinimalClaims)")
	require.Equal(t, 0, derived, "деривация «attested» из наличия области ключа снята (Ф7-39, Р4)")
}
