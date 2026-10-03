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
// Строки реестра без базы не читаются, поэтому порты чтения сборки корня
// подменяются заглушками, а настройка — та, что подаёт корень. Входов у сборки
// после снятия хуков поставщика (kaname#363) один — клиент утверждения, — и он
// спрашивается обоими видами клиента: человека и служебной учётки. Составы по
// каждому виду выдачи судит проба службы (`TestNoIssuanceLaneStampsTheIssuerClaim`).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// rootClaimsRows — строки реестра, которые заглушки портов отдают сборке.
type rootClaimsRows struct {
	user domain.User
	sa   domain.ServiceAccount
	uoc  domain.UserOAuthClient
	soc  domain.ServiceAccountOAuthClient
}

func (r rootClaimsRows) GetUser(_ context.Context, id domain.UserID) (domain.User, error) {
	if id != r.user.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
	}
	return r.user, nil
}

func (r rootClaimsRows) GetServiceAccount(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if id != r.sa.ID {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "no service account %s", id)
	}
	return r.sa, nil
}

func (r rootClaimsRows) GetUserToken(_ context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	if id != r.uoc.ID {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user token %s", id)
	}
	return r.uoc, nil
}

func (r rootClaimsRows) GetSAKey(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != r.soc.ID {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa key %s", id)
	}
	return r.soc, nil
}

// TestOwnLaneClaimsCarryNoProviderAddressWithTheSettingUnset — сборка корня
// при незаданной настройке поставщика не несёт ни утверждения издателя, ни
// значения с именем поставщика.
//
// Переменная издателя поставщика снята вместе с дорогой обмена (kaname#494), и
// процесс её не читает. Проба задаёт её МАРКЕРОМ и утверждает, что маркер не
// доезжает ни до одного утверждения: снятая переменная, оставленная в
// окружении пода, не меняет состава. Имя собирается из словаря класса —
// выписанное литералом, оно было бы новой привязкой к поставщику.
func TestOwnLaneClaimsCarryNoProviderAddressWithTheSettingUnset(t *testing.T) {
	const marker = "https://retired-provider-issuer.marker.invalid"
	t.Setenv("KANAME_"+strings.ToUpper(check.RetiredIssuerName)+"_ISSUER", marker)
	cfg := config.Config{}
	cfg.AuthN.Domain = "api.own.test"
	if strings.Contains(strings.ToLower(cfg.AuthN.Domain), check.RetiredIssuerName) {
		t.Fatalf("предпосылка: домен %q несёт имя поставщика — проба судила бы то, что подала сама", cfg.AuthN.Domain)
	}

	rows := rootClaimsRows{
		user: domain.User{ID: "usr_own0000000000001", AccountID: "acc_own0000000000001", InviteStatus: domain.InviteStatusActive},
		sa:   domain.ServiceAccount{ID: "sva_own0000000000001", AccountID: "acc_own0000000000001", Enabled: true},
		uoc: domain.UserOAuthClient{ID: "uoc_own0000000000001", UserID: "usr_own0000000000001",
			CredentialKind: domain.CredentialKindKeypair, CreatedAt: time.Unix(1_700_000_000, 0).UTC()},
		soc: domain.ServiceAccountOAuthClient{ID: "soc_own0000000000001", SvaID: "sva_own0000000000001",
			CredentialKind: domain.CredentialKindKeypair},
	}
	composer := newAssertionClaimsComposer(nil, cfg).
		WithSAPort(rows).WithUserTokenPort(rows).WithOwnClientPort(rows)

	var lanes []struct {
		name   string
		claims map[string]any
	}
	for _, c := range []struct {
		name   string
		client domain.AssertionClient
	}{
		{"клиент человека", domain.AssertionClient{ID: string(rows.uoc.ID), Kind: domain.AssertionClientUser}},
		{"клиент служебной учётки", domain.AssertionClient{ID: string(rows.soc.ID), Kind: domain.AssertionClientServiceAccount}},
	} {
		claims, _, err := composer.ClaimsForAssertionClient(context.Background(), c.client, service.TokenHookContext{ACR: "1"})
		if err != nil {
			t.Fatalf("%s: сборка корня отказала на исправной строке — «утверждения нет» неотличимо "+
				"от «состава нет»: %v", c.name, err)
		}
		lanes = append(lanes, struct {
			name   string
			claims map[string]any
		}{c.name, claims})
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
			if strings.Contains(s, marker) {
				findings++
				t.Errorf("%s: значение утверждения %s = %q несёт значение снятой переменной издателя", l.name, k, s)
			}
			if strings.Contains(strings.ToLower(s), check.RetiredIssuerName) {
				findings++
				t.Errorf("%s: значение утверждения %s = %q называет прежнего поставщика", l.name, k, s)
			}
		}
	}
	t.Logf("перепись: входов сборки %d · строковых значений %d · находок %d", len(lanes), values, findings)
}
