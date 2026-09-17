// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// registration_materialization_integration_test.go — ГОДНОСТЬ СЕССИИ НЕ ЖДЁТ
// МАТЕРИАЛИЗАЦИИ ПРАВ (приёмка Ф4 Р2; Ф4-20, Ф4-21, Ф4-22; ban #9).
//
// # Что доказывается — и чего нет
//
// Три следствия регистрации — зеркало, адрес, сессия — закоммичены одной
// транзакцией; намерения материализации лежат в очереди ТОЙ ЖЕ транзакцией
// (форма Ф-б), а доезжают ограниченным окном. Здесь:
//
//   - Ф4-20: сессия резолвится сразу после регистрации, пока пообъектный
//     доступ к содержимому собственного аккаунта ещё НЕ материализован —
//     годность не гейтится на видимость (ban #9);
//   - Ф4-21: в окне до доставки доступ к своему проекту ещё не выдан — это
//     состояние «ещё не доехало», а не «не разрешено»: намерение лежит в
//     очереди, и следующий шаг — повторить. Текст отказа, называющий этот шаг,
//     производит КРАЙ (bounded client-retry, `api-conventions.md`), не служба —
//     служба производит различимость: намерение в очереди при закоммиченной
//     сессии;
//   - Ф4-22: после доставки (тот же реконсайлер, что у пути запроса) доступ
//     к своему проекту материализован — положительный контроль.
//
// Реконсайлер здесь НЕ провязан в глагол намеренно: так окно «до доставки»
// наблюдаемо, а не схлопывается синхронной материализацией. В композиционном
// корне он провязан, и окно короче, — но окна не исключает ничто (уборка по
// намерениям — at-least-once).
//
// Run: `make test` (Docker). Skipped under -short.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// regStore — адаптер хранилища регистрации к порту (тем же способом, что
// композиционный корень).
type regStore struct{ inner *kanamepg.RegistrationStore }

func (s regStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := s.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return regWriter{RegistrationWriter: w}, nil
}

type regWriter struct{ *kanamepg.RegistrationWriter }

func (w regWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	return userapp.RegisterMirrorTx(ctx, w.MirrorWriter(), in)
}

func TestRegistrationMaterialization_F4_20_22_SessionIsValidBeforeDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	uc, err := registration.NewRegisterUseCase(registration.Deps{
		Store: regStore{inner: kanamepg.NewRegistrationStore(pool)}, Rule: rule, Hasher: hasher, Lane: lane,
		TTL: 24 * time.Hour, Now: time.Now, Logger: slog.New(slog.DiscardHandler),
		// Реконсайлер НЕ провязан: окно до доставки наблюдаемо.
	})
	require.NoError(t, err)

	email := "mat-" + ids.NewID("tst")[3:11] + "@example.invalid"
	out, err := uc.Execute(ctx, registration.Input{Email: email, Password: "correct-horse-battery-staple-9"})
	require.NoError(t, err)
	uid := out.View.User.ID

	var accID, prjID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE owner_user_id = $1`, string(uid)).Scan(&accID))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.projects WHERE account_id = $1 AND name = 'default'`, accID).Scan(&prjID))
	ownerBID := ownerBindingFor(t, ctx, pool, domain.AccountID(accID))
	ownerUser := "user:" + string(uid)

	// Ф4-20: сессия годна немедленно — резолв по носителю находит запись…
	sessions := kanamepg.NewHumanSessionRepo(pool)
	resolved, reason, err := sessions.Resolve(ctx, out.Bearer.Digest(), time.Now())
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason)
	require.Equal(t, uid, resolved.User.ID)
	// …пока пообъектный доступ к своему проекту ещё НЕ материализован: годность
	// на видимость доставки не гейтится (ban #9).
	require.False(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "v_get", "project:"+prjID),
		"окно до доставки: доступ к своему проекту ещё не материализован — и сессия при этом годна")

	// Ф4-21: намерение лежит в очереди ТОЙ ЖЕ транзакцией — «ещё не доехало»
	// отличимо от «не разрешено»: есть что доставить, следующий шаг — повторить.
	var intents, reconcileEvents int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox WHERE payload::text LIKE '%' || $1 || '%'`, string(uid)).Scan(&intents))
	require.Positive(t, intents, "намерения материализации прав лежат в очереди")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1 AND revoked_at IS NULL`, string(ownerBID)).Scan(&reconcileEvents))
	require.Equal(t, 1, reconcileEvents, "собственническая выдача закоммичена — материализовать есть что")

	// Ф4-22: после доставки — тем же реконсайлером, что у пути запроса, —
	// доступ к своему проекту материализован: действие проходит.
	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBID))
	require.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "v_get", "project:"+prjID),
		"после доставки доступ к своему проекту материализован")
	require.True(t, ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "project:"+prjID))
	// Сессия при этом та же и по-прежнему годна.
	_, reason, err = sessions.Resolve(ctx, out.Bearer.Digest(), time.Now())
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason)
}
