// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// token_claims_no_provider_test.go — сборка состава утверждений, которую корень
// отдаёт полосам нашей чеканки (токен-эндпоинт платформы и бутстрап-
// удостоверение), при НЕЗАДАННОЙ настройке поставщика не кладёт в токен его
// адреса (kaname#364).
//
// # Почему через корень, а не через службу
//
// Проба службы подаёт ей настройку сама и потому молчит о том, что подаёт
// корень. Адрес прежнего поставщика в токен приносила именно сборка корня: она
// выводила издателя из настройки, и незаданная настройка давала
// `https://hydra.<Domain>`. Здесь сборка получает настройку в том виде, в каком
// её читает процесс, — домен объявлен, настройки поставщика нет, — и судится
// то, что она отдаёт.
//
// # Чего проба НЕ делает
//
// Строки реестра без базы не читаются, поэтому спрашиваются входы сборки, базы
// не требующие: уменьшенный состав и состав человека. Настройка у сборки одна
// на все её входы, и составы остальных видов клиента судит проба службы
// (`TestNoIssuanceLaneStampsTheIssuerClaim`).

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// TestOwnLaneClaimsCarryNoProviderAddressWithTheSettingUnset — сборка корня
// при незаданной настройке поставщика не несёт ни утверждения издателя, ни
// значения с именем поставщика.
func TestOwnLaneClaimsCarryNoProviderAddressWithTheSettingUnset(t *testing.T) {
	t.Setenv("KANAME_HYDRA_ISSUER", "")
	cfg := config.Config{}
	cfg.AuthN.Domain = "api.own.test"
	if strings.Contains(strings.ToLower(cfg.AuthN.Domain), check.RetiredIssuerName) {
		t.Fatalf("предпосылка: домен %q несёт имя поставщика — проба судила бы то, что подала сама", cfg.AuthN.Domain)
	}

	composer := newAssertionClaimsComposer(nil, cfg)
	human := domain.User{ID: "usr_own0000000000001", AccountID: "acc_own0000000000001", InviteStatus: domain.InviteStatusActive}
	lanes := []struct {
		name   string
		claims map[string]any
	}{
		{"уменьшенный состав", composer.MinimalClaims("own-external-sub")},
		{"состав человека", composer.UserClaims(human, "own-external-sub", service.TokenHookContext{ACR: "1"})},
	}

	var values, findings int
	for _, l := range lanes {
		if len(l.claims) == 0 {
			t.Fatalf("%s: состав пуст — «утверждения нет» неотличимо от «состава нет»", l.name)
		}
		if v, ok := l.claims["kaname_issuer"]; ok {
			findings++
			t.Errorf("%s: сборка корня кладёт утверждение издателя kaname_issuer = %v", l.name, v)
		}
		for k, v := range l.claims {
			s, ok := v.(string)
			if !ok {
				continue
			}
			values++
			if strings.Contains(strings.ToLower(s), check.RetiredIssuerName) {
				findings++
				t.Errorf("%s: значение утверждения %s = %q называет прежнего поставщика", l.name, k, s)
			}
		}
	}
	t.Logf("перепись: входов сборки %d · строковых значений %d · находок %d", len(lanes), values, findings)
}
