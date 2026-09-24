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
	"sync"
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
)

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

// issuanceRecord — одна запись выпуска так, как её получил писатель.
type issuanceRecord struct {
	jti, family         string
	issuedAt, expiresAt time.Time
}

// issuanceLog — писатель записи выпуска пробы: помнит каждую запись и
// отказывает, когда проба велит (`refuse`).
type issuanceLog struct {
	mu      sync.Mutex
	records []issuanceRecord
	refuse  error
}

func (l *issuanceLog) RecordAccessToken(_ context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refuse != nil {
		return l.refuse
	}
	l.records = append(l.records, issuanceRecord{jti: jti, family: familyID, issuedAt: issuedAt, expiresAt: expiresAt})
	return nil
}

func (l *issuanceLog) all() []issuanceRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]issuanceRecord(nil), l.records...)
}

// newAccessTokens — адаптер порта выпуска над настоящим подписантом; записи
// выпуска ложатся в писатель пробы, которого проба не читает.
func newAccessTokens(t *testing.T, ring *keyRing, clock func() time.Time) *ceremonyport.AccessTokens {
	t.Helper()
	return newRecordingAccessTokens(t, ring, clock, &issuanceLog{})
}

// newRecordingAccessTokens — то же над названным писателем записи выпуска.
func newRecordingAccessTokens(t *testing.T, ring *keyRing, clock func() time.Time, rec ceremonyport.IssuanceRecorder) *ceremonyport.AccessTokens {
	t.Helper()
	a, err := ceremonyport.NewAccessTokens(newSigner(t, ring, clock), ring, rec)
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
			ExpiresAt: map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindAccess: bound},
			Claims:    map[string]any{"session_only_claim": "session-only-value"},
		},
	}
}
