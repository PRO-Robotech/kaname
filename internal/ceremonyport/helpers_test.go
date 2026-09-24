// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// helpers_test.go — общие подставки проб адаптеров портов церемонии.
//
// Подпись в пробах НАСТОЯЩАЯ: подписант службы (`tokensigner`) над ключом,
// порождённым тем же генератором, что у ключницы (`signingkeygen`). Подставной
// здесь только источник материала — он отдаёт ровно то, что ключница отдала бы
// после разворачивания обёртки, и тот же ключ публикует в наборе.
package ceremonyport_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

const (
	testIssuer   = "https://iam.kacho.local"
	testKID      = "kaname-a"
	testAudience = "api.kacho.local"
	testClientID = "svc-console"
	testSubject  = "usr-0123456789abcdefg"
	testFamily   = "tfm-0123456789abcdefg"
	// Контекст входа сеанса: сессия, уровень и момент аутентификации — поля
	// записи сеанса, а не ключи её карты утверждений.
	testSessionID = "hss0123456789abcdefg"
	testACR       = "2"
)

// testAuthTime — момент аутентификации сессии, из которой выдан грант.
var testAuthTime = time.Date(2026, 9, 24, 8, 30, 15, 0, time.UTC)

// keyRing — подписной материал и публикуемый набор одного ключа.
type keyRing struct {
	mat       tokensigner.SigningMaterial
	published []domain.PublishedKey
	setErr    error
}

func newKeyRing(t *testing.T, kid string) *keyRing {
	t.Helper()
	m, err := signingkeygen.Generate(domain.SigningAlgES256)
	require.NoError(t, err)
	mat := tokensigner.SigningMaterial{
		KID: domain.KeyID(kid), Algorithm: domain.SigningAlgES256,
		PrivateKeyPEM: m.PrivateKeyPEM, PublicKeyPEM: m.PublicKeyPEM,
	}
	return &keyRing{
		mat: mat,
		published: []domain.PublishedKey{{
			KID: mat.KID, Algorithm: mat.Algorithm, PublicKeyPEM: mat.PublicKeyPEM,
		}},
	}
}

func (k *keyRing) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

func (k *keyRing) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	if k.setErr != nil {
		return nil, k.setErr
	}
	return append([]domain.PublishedKey(nil), k.published...), nil
}

// newSigner — подписант службы над кольцом, с переданными часами.
func newSigner(t *testing.T, ring tokensigner.KeyProvider, clock func() time.Time) *tokensigner.Signer {
	t.Helper()
	s, err := tokensigner.New(tokensigner.Config{
		Issuer: testIssuer, Clock: clock, MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ring)
	require.NoError(t, err)
	return s
}

// newAccessTokens — адаптер порта выпуска над настоящим подписантом.
func newAccessTokens(t *testing.T, ring *keyRing, clock func() time.Time) *ceremonyport.AccessTokens {
	t.Helper()
	a, err := ceremonyport.NewAccessTokens(newSigner(t, ring, clock), ring)
	require.NoError(t, err)
	return a
}

// grantWithin — грант так, как его назовёт церемония: согласие УЖЕ просьбы,
// в форме — протокольные поля запроса, в сеансе — утверждения службы.
func grantWithin(bound time.Time) oauthceremony.GrantRecord {
	return oauthceremony.GrantRecord{
		GrantID:            testFamily,
		ClientID:           testClientID,
		IssuedAt:           bound.Add(-10 * time.Minute),
		RequestedScopes:    []string{"openid", "offline", "requested-only-scope"},
		GrantedScopes:      []string{"openid", "offline"},
		RequestedAudiences: []string{testAudience, "requested-only.kacho.local"},
		GrantedAudiences:   []string{testAudience},
		Form: map[string][]string{
			"redirect_uri":   {"https://console.kacho.local/oauth2/callback"},
			"code_challenge": {"form-only-challenge-value-0000000000000000"},
			"form_only":      {"form-only-marker"},
		},
		Session: oauthceremony.SessionRecord{
			Subject:   testSubject,
			Username:  "session-only-username",
			SessionID: testSessionID,
			ACR:       testACR,
			AuthTime:  testAuthTime,
			ExpiresAt: map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindAccess: bound},
			Claims:    map[string]any{"session_only_claim": "session-only-value"},
		},
	}
}
