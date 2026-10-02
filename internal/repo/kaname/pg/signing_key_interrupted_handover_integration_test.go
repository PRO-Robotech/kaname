// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// signing_key_interrupted_handover_integration_test.go — передача подписи,
// оборванная концом прохода, не оставляет порождённый ключ опубликованным без
// будущего (#314).
//
// Сцена — воспроизведение ревьюера system-design: строку подписывающего держит
// чужая транзакция, и проход ротации кончается своим пределом, пока передача
// ждёт её замка. Судится на настоящей базе: отказ приходит отменой запроса
// сервером, и именно после неё ключница обязана вывести то, что успела
// породить. Дублёр мог бы лишь изобразить отмену.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// signingKeyStates — сколько строк ключницы в каждом состоянии.
func signingKeyStates(t *testing.T, pool *pgxpool.Pool) map[domain.SigningKeyState]int {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT state, count(*) FROM kaname.token_signing_keys GROUP BY state`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[domain.SigningKeyState]int{}
	for rows.Next() {
		var (
			state string
			n     int
		)
		require.NoError(t, rows.Scan(&state, &n))
		out[domain.SigningKeyState(state)] = n
	}
	require.NoError(t, rows.Err())
	return out
}

// TestSigningKey_RotationEndedByItsPassLimitRetiresTheKeyItGenerated — проход
// ротации кончается своим пределом посреди передачи: подписывающий прежний, а
// порождённый для передачи ключ ВЫВЕДЕН и уходит из набора через отсрочку, —
// а не остаётся опубликованным, доверенным и с хранимой приватной половиной
// навсегда. Законный близнец в той же пробе — обычная ротация: строку
// подписывающего никто не держит, и подпись переходит.
func TestSigningKey_RotationEndedByItsPassLimitRetiresTheKeyItGenerated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	const (
		lifetime, lead = 48 * time.Hour, time.Hour
		passLimit      = 2 * time.Second
	)
	for _, tc := range []struct {
		name string
		hold bool
	}{
		{"обычная ротация: строку подписывающего никто не держит", false},
		{"строку подписывающего держат до конца предела прохода", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool, repo := signingKeyPool(t)
			wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
			require.NoError(t, err)
			start := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
			newKS := func(at time.Time) *signingkeys.Keystore {
				ks, err := signingkeys.New(signingkeys.Config{
					Algorithm: domain.SigningAlgES256, KeyLifetime: lifetime,
					RemovalGrace: tokenpolicy.KeyRemovalGrace, RotationLead: lead,
					HandoverLimit: time.Minute, StrandedAfter: 2 * time.Minute,
					Clock: func() time.Time { return at },
				}, repo, repo, wrapper)
				require.NoError(t, err)
				return ks
			}
			require.NoError(t, newKS(start).EnsureSigningKey(ctx))
			first, err := repo.Active(ctx)
			require.NoError(t, err)
			due := first.NotAfter.Add(-lead)

			release := func() {}
			if tc.hold {
				tx, err := pool.Begin(ctx)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `SELECT kid FROM kaname.token_signing_keys WHERE kid = $1 FOR UPDATE`, string(first.KID))
				require.NoError(t, err)
				release = func() { require.NoError(t, tx.Rollback(ctx)) }
			}
			passCtx, cancel := context.WithTimeout(ctx, passLimit)
			rotated, rerr := newKS(due).RotateIfDue(passCtx)
			passEnded := passCtx.Err()
			cancel()
			release()
			t.Logf("проход: rotated=%v err=%v; состояния после прохода: %v", rotated, rerr, signingKeyStates(t, pool))

			active, err := repo.Active(ctx)
			require.NoError(t, err)
			states := signingKeyStates(t, pool)
			if tc.hold {
				require.ErrorIs(t, passEnded, context.DeadlineExceeded, "предпосылка: проход кончился своим пределом")
				require.Error(t, rerr)
				require.False(t, rotated)
				require.Equal(t, 2, states[domain.SigningKeyActive]+states[domain.SigningKeyPublished]+states[domain.SigningKeyRetired],
					"предпосылка: ключ для передачи порождён")
				require.Equal(t, first.KID, active.KID, "оборванная передача не трогает подписывающего")
				require.Zero(t, states[domain.SigningKeyPublished],
					"ключ, порождённый для оборванной передачи, не остаётся опубликованным без будущего")
				require.Equal(t, 1, states[domain.SigningKeyRetired], "он выведен и уходит из набора через отсрочку")
			} else {
				require.NoError(t, rerr)
				require.True(t, rotated)
				require.NotEqual(t, first.KID, active.KID, "обычная ротация передаёт подпись")
				require.Zero(t, states[domain.SigningKeyPublished])
				require.Equal(t, 1, states[domain.SigningKeyRetired], "прежний подписывающий выведен")
			}

			// Далеко за отсрочкой в наборе остаётся только подписывающий.
			far := due.Add(100 * lifetime)
			_, err = newKS(far).SweepRemovable(ctx)
			require.NoError(t, err)
			set, err := newKS(far).PublishedSet(ctx)
			require.NoError(t, err)
			require.Len(t, set, 1, "за отсрочкой в наборе только подписывающий: %v", set)
			require.Equal(t, active.KID, set[0].KID)
			require.Zero(t, signingKeyStates(t, pool)[domain.SigningKeyPublished])
		})
	}
}
