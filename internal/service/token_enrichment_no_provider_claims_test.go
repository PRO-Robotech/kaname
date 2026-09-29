// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_test

// token_enrichment_no_provider_claims_test.go — состав утверждений НЕ называет
// прежнего поставщика ни одной полосой выдачи (kaname#364, kaname#375).
//
// # Что здесь утверждается
//
// Полос, получающих состав от этой службы, семь: три ветви обратного вызова
// поставщика (интерактивная сессия, ключ служебной учётки, федеративное
// утверждение), уменьшенный состав первого входа, состав полосы обновления и
// два вида клиента НАШЕГО токен-эндпоинта. Ветви персонального токена у
// обратного вызова нет: поставщик персональных токенов не регистрирует, и она
// снята вместе со столбцом имени клиента у него (kaname#362). Каждая
// спрашивается здесь своим входом, и каждая обязана отдать непустой состав —
// иначе «утверждения нет» неотличимо от «состава нет».
//
// Утверждения издателя (`kaname_issuer`) нет ни у одной полосы: читателей у
// него не было ни в службе, ни в платформе, ни в фундаменте, а значением его
// был адрес прежнего поставщика. Ни одно имя утверждения не содержит имени
// поставщика, и ни одно строковое значение его не несёт.
//
// # Чем проба защищена от собственной снисходительности
//
// Строки фикстуры проверяются ДО состава: фикстура, несущая имя поставщика,
// краснела бы значением, которое подала сама, и зелёное на исправленном
// продукте ничего бы не значило в обратную сторону. Имя поставщика берётся из
// одного источника с гейтом прозы (`check.RetiredIssuerName`), а не выписано
// здесь второй раз.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Фикстура принципалов: у каждого вида — своя строка, ключуемая своим
// идентификатором, как у настоящего реестра.
const (
	npDomain       = "api.test.cloud"
	npHumanSubject = "np-human-external-sub"
	npFedIssuer    = "https://ci.example.org"
	npFedSubject   = "repo:acme/infra:ref:refs/heads/main"
	npUserID       = "usr_np0000000000000001"
	npAccountID    = "acc_np0000000000000001"
	npSAID         = "sva_np0000000000000001"
	npSAKeyID      = "soc_np0000000000000001"
	npFedKeyID     = "soc_np0000000000000002"
	npUserTokenID  = "uoc_np0000000000000001"
)

type npUsers struct{ user domain.User }

func (p npUsers) FindByExternalID(_ context.Context, ext domain.ExternalSubject) ([]domain.User, error) {
	if ext != p.user.ExternalID {
		return nil, nil
	}
	return []domain.User{p.user}, nil
}

type npSAs struct {
	byClient, byFed domain.ServiceAccountOAuthClient
	sa              domain.ServiceAccount
}

func (p npSAs) LookupByClientID(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != p.byClient.ID {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa client %s", id)
	}
	return p.byClient, nil
}

func (p npSAs) GetServiceAccount(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if id != p.sa.ID {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa %s", id)
	}
	return p.sa, nil
}

func (p npSAs) FindByExternalSubject(_ context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	if issuer != npFedIssuer || sub != npFedSubject {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject")
	}
	return p.byFed, nil
}

type npUserTokens struct {
	user domain.User
}

func (p npUserTokens) GetUser(_ context.Context, id domain.UserID) (domain.User, error) {
	if id != p.user.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
	}
	return p.user, nil
}

type npOwnClients struct {
	uoc domain.UserOAuthClient
	soc domain.ServiceAccountOAuthClient
}

func (p npOwnClients) GetUserToken(_ context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	if id != p.uoc.ID {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user token %s", id)
	}
	return p.uoc, nil
}

func (p npOwnClients) GetSAKey(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != p.soc.ID {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa key %s", id)
	}
	return p.soc, nil
}

// npLane — состав одной полосы выдачи.
type npLane struct {
	name   string
	claims map[string]any
}

// npIssuanceLanes спрашивает КАЖДУЮ полосу выдачи её собственным входом и
// возвращает составы вместе со строками фикстуры, из которых они собраны.
func npIssuanceLanes(t *testing.T) ([]npLane, []string) {
	t.Helper()
	fixed := time.Unix(1_700_000_000, 0).UTC()

	user := domain.User{
		ID: npUserID, AccountID: npAccountID, ExternalID: npHumanSubject,
		InviteStatus: domain.InviteStatusActive,
	}
	sa := domain.ServiceAccount{ID: npSAID, AccountID: npAccountID, Enabled: true}
	socKey := domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             npSAKeyID, SvaID: npSAID,
	}
	socFed := domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindFederated,
		ID:             npFedKeyID, SvaID: npSAID,
	}
	uoc := domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             npUserTokenID, UserID: npUserID,
		CreatedAt: fixed.Add(-time.Hour),
	}

	svc := service.NewTokenEnrichmentService(service.TokenEnrichmentConfig{Domain: npDomain}, npUsers{user: user}).
		WithSAPort(npSAs{byClient: socKey, byFed: socFed, sa: sa}).
		WithUserTokenPort(npUserTokens{user: user}).
		WithOwnClientPort(npOwnClients{uoc: uoc, soc: socKey}).
		WithClock(func() time.Time { return fixed })

	// Привязка — НЕПУСТАЯ: пустые значения не несли бы ничего, что можно
	// судить.
	bound := service.TokenHookContext{
		ACR: "1", CnfJkt: "np-jkt-thumb", CnfX5tS256: "np-x5t-thumb",
		AuthTime: fixed.Add(-time.Minute).Unix(),
	}
	ctx := context.Background()

	enrich := func(name, subject string, hc service.TokenHookContext) npLane {
		t.Helper()
		claims, _, err := svc.EnrichClaims(ctx, subject, hc)
		if err != nil {
			t.Fatalf("полоса %q: состав не выдан (%v) — сценарий прошёл не той дорогой, ради которой заведён", name, err)
		}
		return npLane{name: name, claims: claims}
	}
	assertion := func(name string, client domain.AssertionClient) npLane {
		t.Helper()
		claims, _, err := svc.ClaimsForAssertionClient(ctx, client, bound)
		if err != nil {
			t.Fatalf("полоса %q: состав не выдан (%v) — сценарий прошёл не той дорогой, ради которой заведён", name, err)
		}
		return npLane{name: name, claims: claims}
	}

	cc := bound
	cc.GrantType = tokenpolicy.GrantTypeClientCredentials
	fed := bound
	fed.GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	fed.ExternalIssuer = npFedIssuer
	fed.OAuthClientID = npFedKeyID

	lanes := []npLane{
		enrich("обратный вызов: интерактивная сессия", npHumanSubject, bound),
		enrich("обратный вызов: ключ служебной учётки", npSAKeyID, cc),
		enrich("обратный вызов: федеративное утверждение", npFedSubject, fed),
		{name: "уменьшенный состав первого входа", claims: svc.MinimalClaims(npHumanSubject)},
		{name: "полоса обновления", claims: svc.UserClaims(user, npHumanSubject, bound)},
		assertion("наш эндпоинт: клиент персонального токена", domain.AssertionClient{
			ID: npUserTokenID, Kind: domain.AssertionClientUser, OwnerID: npUserID, OwnerActive: true,
		}),
		assertion("наш эндпоинт: клиент ключа служебной учётки", domain.AssertionClient{
			ID: npSAKeyID, Kind: domain.AssertionClientServiceAccount, OwnerID: npSAID, OwnerActive: true,
		}),
	}

	fixture := []string{
		npDomain, npHumanSubject, npFedIssuer, npFedSubject,
		npUserID, npAccountID, npSAID, npSAKeyID, npFedKeyID, npUserTokenID,
		bound.ACR, bound.CnfJkt, bound.CnfX5tS256,
	}
	return lanes, fixture
}

// npRequireFixtureFreeOfProvider — предпосылка: фикстура сама имени поставщика
// не несёт.
func npRequireFixtureFreeOfProvider(t *testing.T, fixture []string) {
	t.Helper()
	for _, s := range fixture {
		if strings.Contains(strings.ToLower(s), check.RetiredIssuerName) {
			t.Fatalf("предпосылка: строка фикстуры %q несёт имя поставщика — проба судила бы то, что подала сама", s)
		}
	}
}

// npRequireLanesAnswered — положительный контроль: каждая полоса отдала
// непустой состав.
func npRequireLanesAnswered(t *testing.T, lanes []npLane) {
	t.Helper()
	if len(lanes) == 0 {
		t.Fatal("предпосылка: полос выдачи ноль — судить нечего")
	}
	for _, l := range lanes {
		if len(l.claims) == 0 {
			t.Fatalf("полоса %q отдала пустой состав — «утверждения нет» неотличимо от «состава нет»", l.name)
		}
	}
}

// TestNoIssuanceLaneStampsTheIssuerClaim — kaname#364: утверждения издателя
// нет ни у одной полосы.
func TestNoIssuanceLaneStampsTheIssuerClaim(t *testing.T) {
	lanes, fixture := npIssuanceLanes(t)
	npRequireFixtureFreeOfProvider(t, fixture)
	npRequireLanesAnswered(t, lanes)

	const issuerClaim = "kaname_issuer"
	var carrying int
	for _, l := range lanes {
		if v, ok := l.claims[issuerClaim]; ok {
			carrying++
			t.Errorf("полоса %q несёт утверждение %s = %q: читателей у него нет, а значением был адрес прежнего поставщика",
				l.name, issuerClaim, fmt.Sprint(v))
		}
	}
	t.Logf("перепись: полос %d · непустых составов %d · несут %s — %d", len(lanes), len(lanes), issuerClaim, carrying)
}

// TestNoIssuanceLaneNamesTheRetiredProvider — kaname#375: ни одно имя
// утверждения не содержит имени поставщика, ни одно строковое значение его не
// несёт.
func TestNoIssuanceLaneNamesTheRetiredProvider(t *testing.T) {
	lanes, fixture := npIssuanceLanes(t)
	npRequireFixtureFreeOfProvider(t, fixture)
	npRequireLanesAnswered(t, lanes)

	var names, values, byName, byValue int
	for _, l := range lanes {
		keys := make([]string, 0, len(l.claims))
		for k := range l.claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			names++
			if strings.Contains(strings.ToLower(k), check.RetiredIssuerName) {
				byName++
				t.Errorf("полоса %q: имя утверждения %s называет прежнего поставщика", l.name, k)
			}
			s, ok := l.claims[k].(string)
			if !ok {
				continue
			}
			values++
			if strings.Contains(strings.ToLower(s), check.RetiredIssuerName) {
				byValue++
				t.Errorf("полоса %q: значение утверждения %s = %q называет прежнего поставщика", l.name, k, s)
			}
		}
	}
	t.Logf("перепись: полос %d · имён утверждений %d · строковых значений %d · находок по имени %d, по значению %d",
		len(lanes), names, values, byName, byValue)
}
