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
	svc := NewTokenEnrichmentService(TokenEnrichmentConfig{Domain: "kacho.cloud"})
	svc.now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	user := domain.User{ID: "usr-abc", AccountID: "acc-xyz"}
	uoc := domain.UserOAuthClient{ID: "uoc-1", UserID: user.ID}
	sa := domain.ServiceAccount{ID: "sva-1", AccountID: "acc-xyz"}
	soc := domain.ServiceAccountOAuthClient{ID: "soc-1", SvaID: sa.ID}

	// Вход полос собственной выдачи областей не несёт вовсе: деривации «область
	// ключа ⇒ устройство аттестовано» неоткуда взять предмет. Прежде вход нёс
	// выданные области (обратный вызов поставщика), и проба сравнивала состав с
	// областью ключа и без неё; вход снят вместе с хуками (kaname#363).
	for name, claims := range map[string]map[string]any{
		"персональный токен":    svc.userTokenClaims(uoc, user, string(uoc.ID), TokenHookContext{}),
		"ключ служебной учётки": svc.saClaims(soc, sa, string(soc.ID), TokenHookContext{}),
	} {
		// Положительный контроль: значение по-прежнему ВЫСТАВЛЯЕТСЯ — «не
		// выводится» отличимо от «поля больше нет».
		require.Contains(t, claims, "kaname_device_compliance", name)
		require.Equal(t, "unknown", claims["kaname_device_compliance"], name)
	}
}

var (
	reComplianceSet     = regexp.MustCompile(`"kaname_device_compliance":\s*"unknown"`)
	reComplianceDerived = regexp.MustCompile(`\["kaname_device_compliance"\]\s*=\s*"attested"|"kaname_device_compliance":\s*"attested"`)
)

// TestAccessKey_F7_39_IssuanceLanesCensus — перепись по исходнику производителя:
// «полос выдачи, ставящих значение, N · из них выводящих аттестованность из
// наличия ключа M» — обязано быть `2 · 0`. Прежде знаменатель был пять
// (userClaims · saClaims · federatedClaims · userTokenClaims · MinimalClaims);
// три полосы обратного вызова поставщика сняты вместе с хуками (kaname#363), и
// знаменатель сдвинулся исчезновением полос, а не поля — ровно то различение,
// ради которого величин две.
func TestAccessKey_F7_39_IssuanceLanesCensus(t *testing.T) {
	raw, err := os.ReadFile("token_enrichment_service.go")
	require.NoError(t, err)
	lanes := len(reComplianceSet.FindAll(raw, -1))
	derived := len(reComplianceDerived.FindAll(raw, -1))
	t.Logf("перепись: полос выдачи, ставящих kaname_device_compliance, %d · из них выводящих аттестованность из наличия ключа %d", lanes, derived)
	require.Equal(t, 2, lanes, "полос выдачи ровно две (saClaims · userTokenClaims)")
	require.Equal(t, 0, derived, "деривация «attested» из наличия области ключа снята (Ф7-39, Р4)")
}
