// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_key_revoke_writer_integration_test.go — транзакция снятия ключа
// доступа (`AccessKeyRepo.RevokeWriter`, задача PRO-Robotech/kaname#669, Ф13
// Р8): текущая сессия вызывающего находится по выпуску предъявленного токена
// (выпуск → семейство → сессия церемонии) и остаётся; прочие записи человека
// сняты причиной `access-key-revoked` той же дверью, что у полосы входа, — с
// записью снято и выданное ею; выпуск текущей принимают все три поверхности
// предъявления.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedSecondSession — ещё одна запись сессии человека сцены (вход другим
// устройством); идентификатор возвращается.
func seedSecondSession(t *testing.T, ctx context.Context, f familyRig, scene domain.CeremonyContext, tag string) string {
	t.Helper()
	id := "hs-" + ceremonyPad(tag)
	_, err := f.pool.Exec(ctx, `
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '3', ARRAY['webauthn'])`,
		id, scene.UserID, ceremonyDigest(len(tag)*7919+13))
	require.NoError(t, err, "Дано: вторая сессия человека")
	return id
}

// sessionEnd — причина конца записи; "" — жива.
func sessionEnd(t *testing.T, ctx context.Context, f familyRig, id string) string {
	t.Helper()
	var reason *string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT ended_reason FROM kaname.human_sessions WHERE id = $1`, id).Scan(&reason))
	if reason == nil {
		return ""
	}
	return *reason
}

func TestF13_21_RevokeWriterKeepsTheSessionOfThePresentedCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	f := newFamilyRig(t, pool)

	current := ceremonyScene(t, ctx, pool, "akr")
	a := f.exchangeIn(t, current, 0x6690)
	other := seedSecondSession(t, ctx, f, current, "akr1")
	stranger := ceremonyScene(t, ctx, pool, "akx")
	b := f.exchangeIn(t, stranger, 0x6698)

	// Положительный контроль: до снятия выпуски обоих людей принимаются.
	f.requireAccepted(t, a.at, "до снятия, выпуск текущей сессии")
	f.requireAccepted(t, b.at, "до снятия, выпуск другого человека")

	user := domain.UserID(current.UserID)
	w, err := kanamepg.NewAccessKeyRepo(pool).RevokeWriter(ctx, user)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()

	keep, found, err := w.SessionOfCredential(ctx, user, a.at.JTI)
	require.NoError(t, err)
	require.True(t, found, "выпуск предъявленного называет сессию церемонии")
	require.Equal(t, domain.HumanSessionID(current.SessionID), keep)

	// Близнецы одного факта: выпуск ДРУГОГО человека и неизвестный выпуск
	// текущей сессии не называют.
	_, found, err = w.SessionOfCredential(ctx, user, b.at.JTI)
	require.NoError(t, err)
	require.False(t, found, "чужой выпуск сессию этого человека не называет")
	_, found, err = w.SessionOfCredential(ctx, user, "tok0000000000000000zz")
	require.NoError(t, err)
	require.False(t, found)

	ended, err := w.EndOtherSessions(ctx, user, keep, time.Now().UTC(), domain.RevokeReasonAccessKeyRevoked)
	require.NoError(t, err, "причина `access-key-revoked` принята словарём базы")
	require.Equal(t, 1, ended, "снята ровно прочая запись")
	require.NoError(t, w.Commit(ctx))

	require.Equal(t, domain.RevokeReasonAccessKeyRevoked, sessionEnd(t, ctx, f, other), "прочая сессия снята причиной снятия ключа")
	require.Empty(t, sessionEnd(t, ctx, f, current.SessionID), "текущая сессия жива")
	require.Empty(t, sessionEnd(t, ctx, f, stranger.SessionID), "сессия другого человека жива")
	f.requireAccepted(t, a.at, "после снятия: выпуск текущей сессии принимается")
	f.requireAccepted(t, b.at, "после снятия: выпуск другого человека принимается")
}
