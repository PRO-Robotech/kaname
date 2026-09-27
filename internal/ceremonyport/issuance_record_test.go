// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuance_record_test.go — выпуск токена доступа церемонии ЗАПИСЫВАЕТ себя в
// семейство (задача PRO-Robotech/kaname#319, решение К10 вариант А; обязанность
// адаптера порта выпуска, задача PRO-Robotech/kaname#396, K1).
//
// Отзыв семейства доезжает до предъявления только через запись выпуска
// jti → семейство: ответ о семействе дают `IsRevoked` службы отзыва и правило
// отзыва, и оба спрашивают по идентификатору выпуска. Выпуск без записи —
// токен, который отзыв семейства не снимает, поэтому запись — часть выпуска, а
// не его следствие: она ложится ДО того, как токен уедет, и её отказ роняет
// выпуск.
package ceremonyport_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Запись несёт ровно то, что лежит в выданном токене: его jti, семейство
// гранта, iat и exp. Более ранний exp снял бы запись уборкой, пока токен ещё
// принимается; чужой jti оставил бы выданный токен без записи.
func TestIssue_RecordsTheIssuanceInItsFamilyBeforeTheTokenLeaves(t *testing.T) {
	ring := newKeyRing(t, testKID)
	rec := &issuanceLog{}
	a := newRecordingAccessTokens(t, ring, time.Now, rec)

	issued, err := a.IssueAccessToken(context.Background(), grantWithin(time.Now().Add(10*time.Minute)))
	require.NoError(t, err)

	records := rec.all()
	require.Len(t, records, 1, "выпуск не записал себя в семейство ровно один раз")
	got := records[0]
	require.Equal(t, issued.ID, got.jti, "запись выпуска ключована не jti выданного токена")
	require.Equal(t, testFamily, got.family, "запись выпуска легла не в семейство гранта")
	require.True(t, got.issuedAt.Equal(issued.IssuedAt), "момент выпуска записи %s ≠ iat токена %s", got.issuedAt, issued.IssuedAt)
	require.True(t, got.expiresAt.Equal(issued.ExpiresAt), "срок записи %s ≠ exp токена %s", got.expiresAt, issued.ExpiresAt)
}

// Отказ записи роняет выпуск: токен, не записанный в семейство, клиенту не
// уезжает. Исходов записи два, и оба роняют выпуск: семейство не живо —
// исход заведения, дефект службы — фиксированный INTERNAL; вызывающий
// отличает их по ошибке. Близнец — тот же выпуск при принятой записи.
func TestIssue_RecordRefusalRefusesTheIssuance(t *testing.T) {
	ring := newKeyRing(t, testKID)
	bound := time.Now().Add(10 * time.Minute)

	for _, refusal := range []error{domain.ErrAccessTokenFamilyNotLive, iamerr.ErrInternal} {
		t.Run(refusal.Error(), func(t *testing.T) {
			a := newRecordingAccessTokens(t, ring, time.Now, &issuanceLog{refuse: refusal})
			issued, err := a.IssueAccessToken(context.Background(), grantWithin(bound))
			require.ErrorIs(t, err, refusal, "отказ записи выпуска не дошёл до вызывающего")
			require.Empty(t, issued.Token, "при отказе записи выпуска уехал токен")
			require.Empty(t, issued.ID, "при отказе записи выпуска назван идентификатор выпуска")
		})
	}

	t.Run("близнец: запись принята — выпуск состоялся", func(t *testing.T) {
		a := newRecordingAccessTokens(t, ring, time.Now, &issuanceLog{})
		issued, err := a.IssueAccessToken(context.Background(), grantWithin(bound))
		require.NoError(t, err)
		require.NotEmpty(t, issued.Token)
	})
}

// Без писателя записи адаптер не собирается: выпуск, которому некуда записать
// себя, выдавал бы токены, неснимаемые отзывом семейства, — и выдавал бы их
// молча, до первого отзыва.
func TestNewAccessTokens_RefusesWithoutTheIssuanceRecorder(t *testing.T) {
	ring := newKeyRing(t, testKID)
	signer := newSigner(t, ring, time.Now)

	_, err := ceremonyport.NewAccessTokens(signer, ring, nil)
	require.Error(t, err, "адаптер выпуска собран без писателя записи выпуска")

	a, err := ceremonyport.NewAccessTokens(signer, ring, &issuanceLog{})
	require.NoError(t, err, "близнец: с писателем записи адаптер не собран")
	require.NotNil(t, a)
}
