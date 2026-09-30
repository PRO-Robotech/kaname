// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_method_totp_rewrap_integration_test.go — операторы переобёртки
// секретов второго фактора (kaname#259 п.3) против настоящего Postgres.
//
// # Что утверждают пробы этого файла
//
//   - страница строк `totp` — только этот вид, обоих состояний, по
//     возрастанию человека, строго после курсора; прочие виды не выходят;
//   - замена материала — CAS по ПРОЧИТАННОМУ значению: ложится, пока материал
//     тот же, и меняет ТОЛЬКО материал (состояние, момент, принятый шаг
//     целы); на устаревшем значении, на чужом виде, на снятой строке — ноль;
//   - под конкуренцией с писателем, зафиксировавшим новое значение раньше,
//     замена ждёт замка строки и НЕ ложится поверх него; законный близнец —
//     писатель откатился, и замена ложится.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/secondfactorwrap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Адаптер исполняет порт прохода переобёртки — иначе порт есть обещание без
// исполнителя.
var _ secondfactorwrap.Store = (*pg.LoginMethodRepo)(nil)

func lmTOTP(t *testing.T, repo *pg.LoginMethodRepo, user domain.UserID, material string, state domain.LoginMethodState) {
	t.Helper()
	_, err := repo.Create(context.Background(), domain.LoginMethod{
		UserID: user, Kind: domain.LoginMethodTOTP, Verifier: lmVerifier(t, material), State: state,
	})
	require.NoError(t, err, "посев строки totp")
}

func lmMaterial(t *testing.T, pool *pgxpool.Pool, user domain.UserID, kind domain.LoginMethodKind) string {
	t.Helper()
	var material string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT verifier FROM user_login_methods WHERE user_id = $1 AND kind = $2`, string(user), string(kind)).Scan(&material))
	return material
}

// TestLoginMethodRepo_TOTPSecretsAfterPagesOnlyTOTPRowsInPersonOrder — страница
// несёт только строки `totp` (подтверждённые и заведения), по возрастанию
// человека, строго после курсора; пароль и набор запасных кодов не выходят.
func TestLoginMethodRepo_TOTPSecretsAfterPagesOnlyTOTPRowsInPersonOrder(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "lmpage", 4)

	for _, p := range people {
		_, err := repo.Create(ctx, domain.LoginMethod{
			UserID: p, Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmpage.password"), State: domain.LoginMethodStateActive,
		})
		require.NoError(t, err)
	}
	// Второй человек — без фактора; у третьего фактор только заведён.
	lmTOTP(t, repo, people[0], "wrapped-0", domain.LoginMethodStateActive)
	lmTOTP(t, repo, people[2], "wrapped-2", domain.LoginMethodStatePending)
	lmTOTP(t, repo, people[3], "wrapped-3", domain.LoginMethodStateActive)
	_, err := repo.Create(ctx, domain.LoginMethod{
		UserID: people[3], Kind: domain.LoginMethodLookupSecret, Verifier: lmVerifier(t, ",set,"), State: domain.LoginMethodStateActive,
	})
	require.NoError(t, err)

	first, err := repo.TOTPSecretsAfter(ctx, "", 2)
	require.NoError(t, err)
	require.Len(t, first, 2)
	require.Equal(t, people[0], first[0].UserID)
	require.Equal(t, "wrapped-0", first[0].Verifier.Reveal())
	require.Equal(t, domain.LoginMethodStateActive, first[0].State)
	require.Equal(t, people[2], first[1].UserID)
	require.Equal(t, domain.LoginMethodStatePending, first[1].State, "заведение — тоже секрет под ключом обёртки")
	for _, m := range first {
		require.Equal(t, domain.LoginMethodTOTP, m.Kind)
	}

	second, err := repo.TOTPSecretsAfter(ctx, first[1].UserID, 2)
	require.NoError(t, err)
	require.Len(t, second, 1, "набор запасных кодов и пароль не выходят")
	require.Equal(t, people[3], second[0].UserID)
	require.Equal(t, "wrapped-3", second[0].Verifier.Reveal())

	rest, err := repo.TOTPSecretsAfter(ctx, second[0].UserID, 2)
	require.NoError(t, err)
	require.Empty(t, rest)
}

// TestLoginMethodRepo_SwapTOTPSecretReplacesOnlyTheMaterialItWasShown — замена
// ложится на прочитанное значение и меняет только материал; на устаревшем
// значении, у человека без фактора и у чужого вида — ноль, и ничего не тронуто.
func TestLoginMethodRepo_SwapTOTPSecretReplacesOnlyTheMaterialItWasShown(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "lmswap", 2)

	lmTOTP(t, repo, people[0], "wrapped-old", domain.LoginMethodStateActive)
	_, err := pool.Exec(ctx, `UPDATE user_login_methods SET last_accepted_step = 41 WHERE user_id = $1 AND kind = 'totp'`, string(people[0]))
	require.NoError(t, err)
	before, err := repo.Get(ctx, people[0], domain.LoginMethodTOTP)
	require.NoError(t, err)

	// Устаревшее значение — ноль, материал цел.
	ok, err := repo.SwapTOTPSecret(ctx, people[0], lmVerifier(t, "wrapped-stale"), lmVerifier(t, "wrapped-new"))
	require.NoError(t, err)
	require.False(t, ok, "замена легла на значение, которого в строке нет")
	require.Equal(t, "wrapped-old", lmMaterial(t, pool, people[0], domain.LoginMethodTOTP))

	// Прочитанное значение — ложится.
	ok, err = repo.SwapTOTPSecret(ctx, people[0], before.Verifier, lmVerifier(t, "wrapped-new"))
	require.NoError(t, err)
	require.True(t, ok)
	after, err := repo.Get(ctx, people[0], domain.LoginMethodTOTP)
	require.NoError(t, err)
	require.Equal(t, "wrapped-new", after.Verifier.Reveal())
	require.Equal(t, before.State, after.State, "состояние цело")
	require.True(t, before.CreatedAt.Equal(after.CreatedAt), "момент цел")
	require.True(t, after.StepAccepted)
	require.EqualValues(t, 41, after.AcceptedStep, "принятый шаг цел: повтор кода не открывается переобёрткой")

	// Человек без фактора и пароль того же значения — ноль, пароль цел.
	_, err = repo.Create(ctx, domain.LoginMethod{
		UserID: people[1], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "wrapped-new"), State: domain.LoginMethodStateActive,
	})
	require.NoError(t, err)
	ok, err = repo.SwapTOTPSecret(ctx, people[1], lmVerifier(t, "wrapped-new"), lmVerifier(t, "wrapped-newer"))
	require.NoError(t, err)
	require.False(t, ok, "замена достала чужой вид")
	require.Equal(t, "wrapped-new", lmMaterial(t, pool, people[1], domain.LoginMethodPassword))
}

// TestLoginMethodRepo_SwapTOTPSecretLosesToAWriterThatCommittedFirst — служба
// заводит фактор заново, пока проход держит прежнее значение. Писатель держит
// строку незафиксированной; замена ждёт его замка; писатель фиксирует — замена
// НЕ ложится, в строке его значение. Близнец — писатель откатился: замена
// ложится, потому что материал остался прочитанным.
func TestLoginMethodRepo_SwapTOTPSecretLosesToAWriterThatCommittedFirst(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commit   bool
		swapped  bool
		material string
	}{
		{"писатель зафиксировал", true, false, "wrapped-enrolled"},
		{"близнец: писатель откатился", false, true, "wrapped-rewrapped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := lmPool(t)
			repo := pg.NewLoginMethodRepo(pool)
			ctx := context.Background()
			people := lmPeople(t, pool, "lmrace", 1)
			lmTOTP(t, repo, people[0], "wrapped-old", domain.LoginMethodStatePending)
			shown, err := repo.Get(ctx, people[0], domain.LoginMethodTOTP)
			require.NoError(t, err)

			writer, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback(ctx) }()
			_, err = writer.Exec(ctx, `UPDATE user_login_methods SET verifier = 'wrapped-enrolled' WHERE user_id = $1 AND kind = 'totp'`, string(people[0]))
			require.NoError(t, err)

			type result struct {
				ok  bool
				err error
			}
			done := make(chan result, 1)
			go func() {
				callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()
				ok, err := repo.SwapTOTPSecret(callCtx, people[0], shown.Verifier, lmVerifier(t, "wrapped-rewrapped"))
				done <- result{ok, err}
			}()
			lmWaitForALockWaiter(t, pool)

			if tc.commit {
				require.NoError(t, writer.Commit(ctx))
			} else {
				require.NoError(t, writer.Rollback(ctx))
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("замена не вернулась после снятия замка писателя")
			}
			require.NoError(t, got.err)
			require.Equal(t, tc.swapped, got.ok)
			require.Equal(t, tc.material, lmMaterial(t, pool, people[0], domain.LoginMethodTOTP))
		})
	}
}

// lmWaitForALockWaiter — сцена построена: хоть один процесс базы ждёт замка.
func lmWaitForALockWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ни один процесс базы не ждёт замка за 10 с — сцена конкуренции не построена")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
