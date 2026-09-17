// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_repo_integration_test.go — операторы хранилища второго фактора
// над таблицей способов входа, против настоящего Postgres (фаза Ф12, задача
// PRO-Robotech/kacho#1281; приёмка `second-factor-totp-and-recovery-codes.md`).
//
// # Что утверждают пробы этого файла — ИСХОД под конкуренцией, а не текст запроса
//
//   - Ф12-40: словарь вида, состояние и «pending — только у totp» держит БАЗА
//     ограничениями схемы; словарь домена побайтово равен ограничению;
//   - Ф12-05: заведение — ОДИН оператор под ключом «человек, вид»: при `active`
//     ноль изменённых строк, при `pending` и при отсутствии — одна; два
//     одновременных заведения — оба проходят, строка одна, секрет позднего;
//   - Ф12-07: активация — CAS на `pending` тем же моментом заведения: из двух
//     одновременных проходит ровно одна;
//   - Ф12-22: запись принятого шага — условная («старше последнего принятого»)
//     и она же арбитр: два одновременных предъявления одной ступени проходят
//     ровно одним; шаг принадлежит строке;
//   - Ф12-24: потребление запасного кода сериализуется на строке набора: один
//     код — ровно один из двух; два разных — оба;
//   - Ф12-28/30: снятие — обе строки одним оператором; `pending` не трогается;
//   - Ф12-44: уборка снимает истёкшие `pending`, не трогает `active` и `pending`
//     в сроке.
package pg_test

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Адаптер обязан исполнять порт уборки заведений — иначе строка `pending`
// живёт вечно (Ф12-44).
var _ humansession.EnrollmentSweeper = (*pg.LoginMethodRepo)(nil)

var sfBase = time.Date(2026, 9, 17, 10, 0, 0, 123456000, time.UTC)

func sfWriter(t *testing.T, pool *pgxpool.Pool) humansession.Writer {
	t.Helper()
	w, err := pg.NewHumanSessionRepo(pool).Writer(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Rollback(context.Background()) })
	return w
}

// sfSetMaterial — материал набора в форме, которую читает потребление: элементы
// между запятыми, запятая по краям (форма Ф12 Р6; сам хеш здесь — заглушка,
// адаптер материала не судит).
func sfSetMaterial(elements ...string) string {
	const head = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdC1vZi10aGUtc2V0$,"
	if len(elements) == 0 {
		return head // пустой набор — одна запятая: ни одного элемента между
	}
	return head + strings.Join(elements, ",") + ","
}

func sfConstraint(t *testing.T, err error) string {
	t.Helper()
	var pgErr *pgconn.PgError
	require.True(t, stderrors.As(err, &pgErr), "ждали отказ базы, получили %v", err)
	return pgErr.ConstraintName
}

func sfRow(t *testing.T, pool *pgxpool.Pool, user domain.UserID, kind domain.LoginMethodKind) (state string, material string, step *int64, found bool) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT state, verifier, last_accepted_step FROM user_login_methods WHERE user_id = $1 AND kind = $2`,
		string(user), string(kind)).Scan(&state, &material, &step)
	if err != nil {
		require.Contains(t, err.Error(), "no rows")
		return "", "", nil, false
	}
	return state, material, step, true
}

// TestSecondFactorSchema_KindStateAndPendingAreHeldByTheBase — Ф12-40.
func TestSecondFactorSchema_KindStateAndPendingAreHeldByTheBase(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfsch", 1)
	ctx := context.Background()
	insert := func(kind, state string) error {
		_, err := pool.Exec(ctx, `INSERT INTO user_login_methods (user_id, kind, verifier, state) VALUES ($1, $2, 'material', $3)`,
			string(people[0]), kind, state)
		return err
	}

	// Близнец: `active` `totp` и `active` `lookup_secret` проходят.
	require.NoError(t, insert("totp", "active"))
	require.NoError(t, insert("lookup_secret", "active"))
	_, err := pool.Exec(ctx, `DELETE FROM user_login_methods WHERE user_id = $1`, string(people[0]))
	require.NoError(t, err)
	require.NoError(t, insert("totp", "pending"), "pending у totp — законно")

	require.Equal(t, "user_login_methods_kind_check", sfConstraint(t, insert("sms", "active")), "вид вне словаря отвергает база")
	require.Equal(t, "user_login_methods_state_check", sfConstraint(t, insert("totp", "enrolled")), "состояние вне словаря отвергает база")
	require.Equal(t, "user_login_methods_pending_only_totp_check", sfConstraint(t, insert("lookup_secret", "pending")), "pending у набора отвергает база")
	require.Equal(t, "user_login_methods_pending_only_totp_check", sfConstraint(t, insert("password", "pending")), "pending у пароля отвергает база")

	// Словарь домена побайтово равен ограничению схемы.
	var def string
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'user_login_methods_kind_check'`).Scan(&def))
	quoted := 0
	for _, part := range strings.Split(def, "'") {
		for _, k := range domain.LoginMethodKinds() {
			if part == string(k) {
				quoted++
			}
		}
	}
	require.Equal(t, len(domain.LoginMethodKinds()), quoted, "в ограничении ровно словарь домена: %s", def)
	require.Equal(t, 3, len(domain.LoginMethodKinds()))

	// Умолчание состояния — `active`: строки пароля, лежавшие до миграции,
	// получили его без переноса.
	var state string
	require.NoError(t, pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_name = 'user_login_methods' AND column_name = 'state'`).Scan(&state))
	require.Contains(t, state, "active")
	t.Logf("перепись: видов %d, ограничений схемы второго фактора 3", len(domain.LoginMethodKinds()))
}

// TestSecondFactor_UpsertPendingIsOneOperator — Ф12-05: при `active` ноль
// строк, при `pending` — замена, при отсутствии — вставка; всё одним оператором.
func TestSecondFactor_UpsertPendingIsOneOperator(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfup", 3)
	ctx := context.Background()

	pending := func(user domain.UserID, material string, at time.Time) domain.LoginMethod {
		return domain.LoginMethod{UserID: user, Kind: domain.LoginMethodTOTP, Verifier: lmVerifier(t, material),
			State: domain.LoginMethodStatePending, CreatedAt: at}
	}

	// (в) строки нет → вставка.
	w := sfWriter(t, pool)
	accepted, err := w.UpsertPendingTOTP(ctx, pending(people[0], "wrapped-1", sfBase))
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, w.Commit(ctx))
	state, material, step, found := sfRow(t, pool, people[0], domain.LoginMethodTOTP)
	require.True(t, found)
	require.Equal(t, "pending", state)
	require.Equal(t, "wrapped-1", material)
	require.Nil(t, step)

	// (б) `pending` → замена секрета и момента, шага нет.
	w = sfWriter(t, pool)
	accepted, err = w.UpsertPendingTOTP(ctx, pending(people[0], "wrapped-2", sfBase.Add(time.Minute)))
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, w.Commit(ctx))
	state, material, _, _ = sfRow(t, pool, people[0], domain.LoginMethodTOTP)
	require.Equal(t, "pending", state)
	require.Equal(t, "wrapped-2", material)
	var created time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT created_at FROM user_login_methods WHERE user_id = $1 AND kind = 'totp'`, string(people[0])).Scan(&created))
	require.True(t, created.Equal(sfBase.Add(time.Minute)), "момент заведения — момент замены")

	// (а) `active` → ноль изменённых строк, строка не тронута.
	w = sfWriter(t, pool)
	activated, err := w.ActivateTOTP(ctx, people[0], sfBase.Add(time.Minute), 100, sfBase.Add(2*time.Minute))
	require.NoError(t, err)
	require.True(t, activated)
	require.NoError(t, w.Commit(ctx))
	w = sfWriter(t, pool)
	accepted, err = w.UpsertPendingTOTP(ctx, pending(people[0], "wrapped-3", sfBase.Add(3*time.Minute)))
	require.NoError(t, err)
	require.False(t, accepted, "при active заведение не проходит")
	require.NoError(t, w.Commit(ctx))
	state, material, step, _ = sfRow(t, pool, people[0], domain.LoginMethodTOTP)
	require.Equal(t, "active", state)
	require.Equal(t, "wrapped-2", material, "строка не изменена")
	require.NotNil(t, step)
	require.EqualValues(t, 100, *step)

	// Конкуренция (в): два одновременных первых заведения — оба проходят,
	// строка одна, секрет позднего ответа; ни один не получает отказа
	// уникальности.
	for _, person := range people[1:] {
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
				if err != nil {
					results[i] = err
					return
				}
				defer func() { _ = w.Rollback(ctx) }()
				ok, err := w.UpsertPendingTOTP(ctx, pending(person, "race-"+string(rune('a'+i)), sfBase.Add(time.Duration(i)*time.Second)))
				if err == nil && !ok {
					err = stderrors.New("заведение при отсутствии строки не прошло")
				}
				if err == nil {
					err = w.Commit(ctx)
				}
				results[i] = err
			}(i)
		}
		close(start)
		wg.Wait()
		require.NoError(t, results[0])
		require.NoError(t, results[1])
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM user_login_methods WHERE user_id = $1`, string(person)).Scan(&n))
		require.Equal(t, 1, n, "строка pending одна")
		_, material, _, _ = sfRow(t, pool, person, domain.LoginMethodTOTP)
		require.Contains(t, []string{"race-a", "race-b"}, material)
	}
}

// TestSecondFactor_ActivateIsACASOnPending — Ф12-07 (а): из двух одновременных
// активаций проходит ровно одна; активация чужого момента заведения — ноль.
func TestSecondFactor_ActivateIsACASOnPending(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfact", 2)
	ctx := context.Background()

	w := sfWriter(t, pool)
	_, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "wrapped"), State: domain.LoginMethodStatePending, CreatedAt: sfBase})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Момент заведения — версия строки: активация по прежнему моменту, когда
	// строка уже заменена, не проходит.
	w = sfWriter(t, pool)
	activated, err := w.ActivateTOTP(ctx, people[0], sfBase.Add(-time.Second), 7, sfBase.Add(time.Minute))
	require.NoError(t, err)
	require.False(t, activated, "чужой момент заведения — не та строка")
	require.NoError(t, w.Rollback(ctx))

	start := make(chan struct{})
	var wg sync.WaitGroup
	wins := make([]bool, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			ok, err := w.ActivateTOTP(ctx, people[0], sfBase, 42, sfBase.Add(time.Minute))
			if err == nil {
				err = w.Commit(ctx)
			}
			wins[i], errs[i] = ok, err
		}(i)
	}
	close(start)
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.NotEqual(t, wins[0], wins[1], "ровно одна активация проходит")
	state, _, step, _ := sfRow(t, pool, people[0], domain.LoginMethodTOTP)
	require.Equal(t, "active", state)
	require.EqualValues(t, 42, *step)

	// Личности без строки активировать нечего.
	w = sfWriter(t, pool)
	activated, err = w.ActivateTOTP(ctx, people[1], sfBase, 1, sfBase)
	require.NoError(t, err)
	require.False(t, activated)
}

// TestSecondFactor_AcceptedStepIsConditionalAndBelongsToTheRow — Ф12-22:
// запись шага условная («старше последнего принятого») и она же арбитр.
func TestSecondFactor_AcceptedStepIsConditionalAndBelongsToTheRow(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfstep", 1)
	ctx := context.Background()

	w := sfWriter(t, pool)
	_, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "wrapped"), State: domain.LoginMethodStatePending, CreatedAt: sfBase})
	require.NoError(t, err)
	// Шаг у `pending` не записывается: строка не способ.
	recorded, err := w.RecordAcceptedStep(ctx, people[0], 10)
	require.NoError(t, err)
	require.False(t, recorded)
	ok, err := w.ActivateTOTP(ctx, people[0], sfBase, 10, sfBase.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, w.Commit(ctx))

	w = sfWriter(t, pool)
	recorded, err = w.RecordAcceptedStep(ctx, people[0], 10)
	require.NoError(t, err)
	require.False(t, recorded, "повтор шага подтверждения — отказ")
	recorded, err = w.RecordAcceptedStep(ctx, people[0], 9)
	require.NoError(t, err)
	require.False(t, recorded, "младший шаг — отказ")
	recorded, err = w.RecordAcceptedStep(ctx, people[0], 11)
	require.NoError(t, err)
	require.True(t, recorded)
	require.NoError(t, w.Commit(ctx))

	// Два одновременных предъявления ступени 12 — ровно одно.
	start := make(chan struct{})
	var wg sync.WaitGroup
	wins := make([]bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
			require.NoError(t, err)
			defer func() { _ = w.Rollback(ctx) }()
			ok, err := w.RecordAcceptedStep(ctx, people[0], 12)
			require.NoError(t, err)
			require.NoError(t, w.Commit(ctx))
			wins[i] = ok
		}(i)
	}
	close(start)
	wg.Wait()
	require.NotEqual(t, wins[0], wins[1], "ровно одно из двух одновременных")
	_, _, step, _ := sfRow(t, pool, people[0], domain.LoginMethodTOTP)
	require.EqualValues(t, 12, *step)
}

// TestSecondFactor_LookupSetConsumptionIsSerialisedOnTheRow — Ф12-24: один код
// — ровно один; два разных — оба; при любом чередовании.
func TestSecondFactor_LookupSetConsumptionIsSerialisedOnTheRow(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfset", 1)
	ctx := context.Background()

	w := sfWriter(t, pool)
	require.NoError(t, w.ReplaceLookupSet(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodLookupSecret,
		Verifier: lmVerifier(t, sfSetMaterial("h1", "h2", "h3", "h4")), State: domain.LoginMethodStateActive, CreatedAt: sfBase}))
	require.NoError(t, w.Commit(ctx))

	// Замок + потребление одним писателем.
	w = sfWriter(t, pool)
	set, found, err := w.LockLookupSet(ctx, people[0])
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, domain.LoginMethodStateActive, set.State)
	consumed, err := w.ConsumeLookupElement(ctx, people[0], "h1")
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, err = w.ConsumeLookupElement(ctx, people[0], "h1")
	require.NoError(t, err)
	require.False(t, consumed, "второй раз тот же — нет в наборе")
	consumed, err = w.ConsumeLookupElement(ctx, people[0], "h")
	require.NoError(t, err)
	require.False(t, consumed, "подстрока элемента — не элемент")
	require.NoError(t, w.Commit(ctx))
	_, material, _, _ := sfRow(t, pool, people[0], domain.LoginMethodLookupSecret)
	require.Equal(t, sfSetMaterial("h2", "h3", "h4"), material, "код снят из набора, а не помечен в памяти")

	race := func(a, b string) (bool, bool) {
		start := make(chan struct{})
		var wg sync.WaitGroup
		got := make([]bool, 2)
		for i, el := range []string{a, b} {
			wg.Add(1)
			go func(i int, el string) {
				defer wg.Done()
				<-start
				w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
				require.NoError(t, err)
				defer func() { _ = w.Rollback(ctx) }()
				_, found, err := w.LockLookupSet(ctx, people[0])
				require.NoError(t, err)
				require.True(t, found)
				ok, err := w.ConsumeLookupElement(ctx, people[0], el)
				require.NoError(t, err)
				require.NoError(t, w.Commit(ctx))
				got[i] = ok
			}(i, el)
		}
		close(start)
		wg.Wait()
		return got[0], got[1]
	}
	a, b := race("h2", "h2")
	require.NotEqual(t, a, b, "(а) один код — ровно один")
	a, b = race("h3", "h4")
	require.True(t, a && b, "(б) два разных — оба")
	_, material, _, _ = sfRow(t, pool, people[0], domain.LoginMethodLookupSecret)
	require.Equal(t, sfSetMaterial(), material, "остаток ноль — набор пуст, строка на месте")

	// Личность без набора: замок ничего не находит.
	w = sfWriter(t, pool)
	_, found, err = w.LockLookupSet(ctx, "usr0000000000000nobody")
	require.NoError(t, err)
	require.False(t, found)
}

// TestSecondFactor_RemoveTakesBothRowsAndLeavesPendingAlone — Ф12-28/30.
func TestSecondFactor_RemoveTakesBothRowsAndLeavesPendingAlone(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfrm", 3)
	ctx := context.Background()

	w := sfWriter(t, pool)
	_, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "wrapped"), State: domain.LoginMethodStatePending, CreatedAt: sfBase})
	require.NoError(t, err)
	_, err = w.ActivateTOTP(ctx, people[0], sfBase, 1, sfBase)
	require.NoError(t, err)
	require.NoError(t, w.ReplaceLookupSet(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodLookupSecret,
		Verifier: lmVerifier(t, sfSetMaterial("h1")), State: domain.LoginMethodStateActive, CreatedAt: sfBase}))
	// У второго — только `pending`; у третьего — ничего.
	_, err = w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[1], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "wrapped-2"), State: domain.LoginMethodStatePending, CreatedAt: sfBase})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w = sfWriter(t, pool)
	removed, err := w.RemoveSecondFactor(ctx, people[0])
	require.NoError(t, err)
	require.True(t, removed)
	removed, err = w.RemoveSecondFactor(ctx, people[1])
	require.NoError(t, err)
	require.False(t, removed, "pending — не фактор: снимать нечего")
	removed, err = w.RemoveSecondFactor(ctx, people[2])
	require.NoError(t, err)
	require.False(t, removed)
	require.NoError(t, w.Commit(ctx))

	require.Zero(t, lmCount(t, pool, people[0]), "обе строки сняты")
	state, _, _, found := sfRow(t, pool, people[1], domain.LoginMethodTOTP)
	require.True(t, found, "pending не тронута")
	require.Equal(t, "pending", state)
}

// TestSecondFactor_SweepTakesOnlyExpiredPending — Ф12-44.
func TestSecondFactor_SweepTakesOnlyExpiredPending(t *testing.T) {
	pool := lmPool(t)
	people := lmPeople(t, pool, "sfsw", 3)
	ctx := context.Background()
	repo := pg.NewLoginMethodRepo(pool)
	const window = 15 * time.Minute

	w := sfWriter(t, pool)
	// истёкшая pending: заведена давно (часы базы — `now()`).
	_, err := w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "old"), State: domain.LoginMethodStatePending, CreatedAt: time.Now().Add(-window - time.Minute)})
	require.NoError(t, err)
	// pending в сроке.
	_, err = w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[1], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "fresh"), State: domain.LoginMethodStatePending, CreatedAt: time.Now()})
	require.NoError(t, err)
	// active, заведённая давно.
	long := time.Now().Add(-2 * window)
	_, err = w.UpsertPendingTOTP(ctx, domain.LoginMethod{UserID: people[2], Kind: domain.LoginMethodTOTP,
		Verifier: lmVerifier(t, "active"), State: domain.LoginMethodStatePending, CreatedAt: long})
	require.NoError(t, err)
	activated, err := w.ActivateTOTP(ctx, people[2], long, 1, long)
	require.NoError(t, err)
	require.True(t, activated)
	require.NoError(t, w.Commit(ctx))

	removed, full, err := repo.SweepExpiredEnrollments(ctx, window, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята ровно истёкшая")
	require.False(t, full)
	require.Zero(t, lmCount(t, pool, people[0]))
	require.Equal(t, 1, lmCount(t, pool, people[1]))
	require.Equal(t, 1, lmCount(t, pool, people[2]))
	t.Logf("перепись: осмотрено 3 · снято %d", removed)
}
