// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reset_own_sessions_list_integration_test.go — после сброса распорядителем
// перечень своих сессий человека не показывает отсечённые записи живыми
// (задача PRO-Robotech/kaname#681) — на НАСТОЯЩЕЙ базе, настоящими глаголами
// сброса над адаптерами, которые провязывает корень композиции.
//
// Сцена одна на оба сброса: сессия выдана до сброса → сброс исполнен →
// перечень (`HumanSessionRepo.SessionsOf`, оператор перечня `GET
// /iam/v1/auth/sessions`). Записи сессии сброс не снимает — отсекает, и
// перечень, не судящий отсечку, показывал бы отсечённую запись живой, хотя
// край её носитель отвергает. Близнец — вход после сброса: его запись в
// перечне есть.
//
// Run: `go test ./internal/apps/kaname/api/user/ -run ResetThenOwnSessionsList -count=1` (Docker).
// Skipped under -short.

package user

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// akResetStore — порт писателя сброса ключей над адаптером базы, как в корне.
type akResetStore struct{ keys *kanamepg.AccessKeyRepo }

func (s akResetStore) ResetWriter(ctx context.Context, userID domain.UserID) (AccessKeysResetWriter, error) {
	w, err := s.keys.AccessKeysResetWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// enrollAccessKey — строка ключа доступа писателем продукта.
func (r *rsfRace) enrollAccessKey(t *testing.T) {
	t.Helper()
	_, err := r.pool.Exec(r.ctx, `INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 8)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): потолок вида ключа")
	keys := kanamepg.NewAccessKeyRepo(r.pool)
	auth := webauthntest.New(t, webauthntest.AlgES256)
	w, err := keys.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(r.ctx) }()
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	handle, err := w.EnsureCeremonyHandle(r.ctx, r.subject, minted)
	require.NoError(t, err)
	_, err = w.InsertKey(r.ctx, domain.AccessKey{
		ID: domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)), UserID: r.subject,
		CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t), Algorithm: auth.Algorithm(),
		UserHandle: handle.Bytes(), Name: "list-scene-key", CreatedAt: time.Now().UTC(), Discoverability: domain.DiscoverabilityConfirmed,
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка ключа писателем продукта")
	require.NoError(t, w.Commit(r.ctx))
}

// ownList — идентификаторы записей перечня своих сессий человека (первая
// страница умолчания) на момент общего источника.
func (r *rsfRace) ownList(t *testing.T) []string {
	t.Helper()
	now, err := r.clock.Now(r.ctx)
	require.NoError(t, err)
	rows, _, err := r.sessions.SessionsOf(r.ctx, r.subject, now, 0, "")
	require.NoError(t, err)
	out := make([]string, 0, len(rows))
	for _, s := range rows {
		out = append(out, string(s.ID))
	}
	return out
}

// sessionIDAt — запись сессии человека с моментом аутентификации at.
func (r *rsfRace) sessionIDAt(t *testing.T, at time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, r.pool.QueryRow(r.ctx,
		`SELECT id FROM human_sessions WHERE user_id = $1 AND authenticated_at = $2`, string(r.subject), at).Scan(&id))
	return id
}

func TestResetThenOwnSessionsList_CutRecordsAreNotListedAsLive(t *testing.T) {
	for name, reset := range map[string]func(t *testing.T, r *rsfRace){
		"сброс второго фактора": func(t *testing.T, r *rsfRace) {
			r.awaitResetDone(t, r.startReset(t, rsfRaceStore{}))
		},
		"сброс ключей доступа": func(t *testing.T, r *rsfRace) {
			r.enrollAccessKey(t)
			uc := NewResetAccessKeysUseCase(kanamepg.New(r.pool, nil), operations.NewRepo(r.pool, "kaname"),
				kanamepg.NewLoginMethodRepo(r.pool), akResetStore{keys: kanamepg.NewAccessKeyRepo(r.pool)})
			op, err := uc.Execute(operations.WithPrincipal(r.ctx,
				operations.Principal{Type: "user", ID: string(r.admin)}), r.subject)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сброс ключей прошёл синхронную сверку")
			r.awaitResetDone(t, op.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRSFRace(t)
			beforeLogin := r.openLogin(t, nil)
			require.False(t, beforeLogin.refused)
			beforeLogin.finish(t, r.ctx)
			before := r.sessionIDAt(t, beforeLogin.at)
			require.Contains(t, r.ownList(t), before, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): до сброса запись в перечне")

			reset(t, r)
			isCut, cutoff := r.cut(t, beforeLogin.at)
			require.Truef(t, isCut, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сброс отсёк запись (момент %s, отсечка %s)", beforeLogin.at, cutoff)

			require.NotContainsf(t, r.ownList(t), before,
				"kaname#681 (%s): отсечённая сбросом запись показана в перечне своих сессий живой", name)

			afterLogin := r.openLogin(t, nil)
			require.False(t, afterLogin.refused, "близнец: вход после сброса не отказывает")
			afterLogin.finish(t, r.ctx)
			require.Contains(t, r.ownList(t), r.sessionIDAt(t, afterLogin.at), "близнец: запись после сброса в перечне")
		})
	}
}
