// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_method_repo_integration_test.go — адаптер хранилища способа входа и
// подтверждённости адреса (фаза Ф2, `kacho#1268`), против настоящего Postgres.
//
// # Что утверждают пробы этого файла
//
//   - сторона хранилища Ф1-04 (Р1): материал, созданный ПРЕЖНЕЙ функцией,
//     читается обратно побайтово — без перехеширования, обрезки и нормализации.
//     Сам вход прежним паролем — Ф3; проверка по хешу — часть П2;
//   - F4d-14: второй способ того же вида — `ALREADY_EXISTS` с контрактным тоном,
//     и первый не тронут;
//   - F4d-15: под конкуренцией проходит ровно одна вставка, остальные получают
//     `ALREADY_EXISTS`, произведённый базой; положительный контроль — разные
//     люди одновременно проходят все;
//   - негодный вход отвергается ТИПОМ до базы (`INVALID_ARGUMENT`), а не
//     ограничением таблицы (`INTERNAL`);
//   - подтверждённость записывается ТОЛЬКО на то значение адреса, которое
//     подтверждали; под гонкой со сменой адреса инвариант «новый адрес не
//     бывает подтверждённым без своей записи» держится на каждом прогоне.
package pg_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Адаптер обязан исполнять порт use-case — иначе порт есть обещание без
// исполнителя, а адаптер — код без вызывающего.
var _ loginmethod.Store = (*pg.LoginMethodRepo)(nil)

func lmPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// lmPeople заводит аккаунт и n его членов; первый — владелец аккаунта.
func lmPeople(t *testing.T, pool *pgxpool.Pool, tag string, n int) []domain.UserID {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)

	account := "acc" + fmt.Sprintf("%017s", tag)
	ids := make([]domain.UserID, 0, n)
	for i := 0; i < n; i++ {
		id := "usr" + fmt.Sprintf("%017s", fmt.Sprintf("%s%02d", tag, i))
		_, err = tx.Exec(ctx, `
			INSERT INTO users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
			id, fmt.Sprintf("ext-%s-%02d", tag, i), fmt.Sprintf("%s-%02d@example.invalid", tag, i),
			fmt.Sprintf("person %02d", i), account)
		require.NoError(t, err, "посев человека %d", i)
		ids = append(ids, domain.UserID(id))
	}
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, string(ids[0]))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return ids
}

func lmVerifier(t *testing.T, material string) domain.LoginVerifier {
	t.Helper()
	v, err := domain.NewLoginVerifier(material)
	require.NoError(t, err)
	return v
}

func lmCount(t *testing.T, pool *pgxpool.Pool, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_login_methods WHERE user_id = $1`, string(user)).Scan(&n))
	return n
}

// TestLoginMethodRepo_MaterialRoundTripsVerbatim — сторона хранилища Ф1-04.
//
// Прежний поставщик хранит хеши в своих форматах; перенос кладёт их как есть, и
// вход прежним паролем держится ровно на том, что хранилище возвращает
// положенное побайтово. Перехешировать нельзя — пароля у нас нет; обрезать и
// нормализовать нельзя — изменённый хеш перестаёт совпадать.
func TestLoginMethodRepo_MaterialRoundTripsVerbatim(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()

	materials := []string{
		// Форма прежнего поставщика: bcrypt, стоимость 12. Значение синтетическое
		// и выглядит ЧУЖИМ — хранилище формы не судит, судит проверяющий (П2).
		"$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
		// Форма нынешней функции: argon2id с параметрами прежнего поставщика.
		"$argon2id$v=19$m=65536,t=3,p=4$cHJvYmUtc2FsdC1mMnAx$cHJvYmUtaGFzaC1mMnAxLXJvdW5kdHJpcA",
		// Края значения — часть значения.
		" $2a$12$edge.whitespace.is.part.of.the.value ",
	}
	people := lmPeople(t, pool, "lmrt", len(materials))

	for i, material := range materials {
		created, err := repo.Create(ctx, domain.LoginMethod{
			UserID: people[i], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, material),
		})
		require.NoError(t, err, "формат %d", i)
		require.False(t, created.CreatedAt.IsZero(), "момент заведения назначает запись")

		got, err := repo.Get(ctx, people[i], domain.LoginMethodPassword)
		require.NoError(t, err)
		require.Equal(t, material, got.Verifier.Reveal(),
			"Ф1-04 (хранилище): материал обязан вернуться побайтово тем, что положили")
		require.Equal(t, people[i], got.UserID)
		require.Equal(t, domain.LoginMethodPassword, got.Kind)
	}
	t.Logf("перепись: форм материала проверено %d, все вернулись побайтово", len(materials))
}

func TestLoginMethodRepo_GetOfAnAbsentMethodIsNotFound(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	people := lmPeople(t, pool, "lmget", 1)

	_, err := repo.Get(context.Background(), people[0], domain.LoginMethodPassword)
	require.ErrorIs(t, err, iamerr.ErrNotFound, "способа нет — NOT_FOUND своей полосы")
	require.Equal(t, fmt.Sprintf("Login method password of user %s not found", people[0]),
		iamerr.StripSentinel(err))

	// Положительный контроль: заведённый — находится.
	_, err = repo.Create(context.Background(), domain.LoginMethod{
		UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmget.present"),
	})
	require.NoError(t, err)
	_, err = repo.Get(context.Background(), people[0], domain.LoginMethodPassword)
	require.NoError(t, err)
}

// TestLoginMethodRepo_SecondMethodOfTheSameKindIsAlreadyExists — F4d-14.
func TestLoginMethodRepo_SecondMethodOfTheSameKindIsAlreadyExists(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "lmdup", 2)

	first, err := repo.Create(ctx, domain.LoginMethod{
		UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmdup.first"),
	})
	require.NoError(t, err)

	_, err = repo.Create(ctx, domain.LoginMethod{
		UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmdup.second"),
	})
	require.ErrorIs(t, err, iamerr.ErrAlreadyExists, "F4d-14: ALREADY_EXISTS, произведённый базой")
	require.Equal(t, fmt.Sprintf("Login method password of user %s already exists", people[0]),
		iamerr.StripSentinel(err), "F4d-14: контрактный тон отказа")
	require.NotContains(t, err.Error(), "lmdup.second", "отказ не вправе нести материал")

	got, err := repo.Get(ctx, people[0], domain.LoginMethodPassword)
	require.NoError(t, err)
	require.Equal(t, "$2a$12$lmdup.first", got.Verifier.Reveal(), "первый способ не тронут попыткой второго")
	require.Equal(t, first.CreatedAt, got.CreatedAt)

	// Положительный контроль: тот же вид ДРУГОМУ человеку проходит.
	_, err = repo.Create(ctx, domain.LoginMethod{
		UserID: people[1], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmdup.other"),
	})
	require.NoError(t, err)
}

func TestLoginMethodRepo_MethodOfAMissingPersonIsFailedPrecondition(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)

	_, err := repo.Create(context.Background(), domain.LoginMethod{
		UserID: "usr0000000000000nobody", Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lmfk.ghost"),
	})
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.ErrorIs(t, err, iamerr.ErrReferenceMissing)
	require.Equal(t, "User usr0000000000000nobody not found", iamerr.StripSentinel(err))
}

// TestLoginMethodRepo_InvalidInputIsRefusedBeforeTheBase — тип судит вход, база
// держит последний рубеж. Различимо это КОДОМ: отказ типа — `INVALID_ARGUMENT`,
// отказ ограничения таблицы — `INTERNAL`. Совпади коды, пробе нечем было бы
// отличить одно от другого.
func TestLoginMethodRepo_InvalidInputIsRefusedBeforeTheBase(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	people := lmPeople(t, pool, "lminv", 1)

	for name, m := range map[string]domain.LoginMethod{
		"материала нет": {UserID: people[0], Kind: domain.LoginMethodPassword},
		"вид чужой":     {UserID: people[0], Kind: "totp", Verifier: lmVerifier(t, "$2a$12$lminv.kind")},
		"человека нет":  {Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$lminv.user")},
	} {
		_, err := repo.Create(context.Background(), m)
		require.ErrorIs(t, err, iamerr.ErrInvalidArg, "%s: отказ обязан прийти от типа", name)
		require.NotErrorIs(t, err, iamerr.ErrInternal, "%s: до ограничения таблицы вход дойти не должен", name)
	}
	require.Zero(t, lmCount(t, pool, people[0]), "ни одна негодная строка не легла")
}

// TestLoginMethodRepo_ConcurrentCreatesOneWins — F4d-15.
//
// Одновременный старт держит барьер: все горутины ждут закрытия одного канала,
// и первая вставка не успевает зафиксироваться раньше, чем стартуют остальные.
// Без барьера «ровно одна прошла» было бы верно и о последовательных вставках,
// где отказ производит чтение, а не ограничение.
func TestLoginMethodRepo_ConcurrentCreatesOneWins(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	const racers = 16

	run := func(people []domain.UserID) (ok, dup int, other []error) {
		start := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := 0; i < racers; i++ {
			user := people[0]
			if len(people) > 1 {
				user = people[i]
			}
			verifier := lmVerifier(t, fmt.Sprintf("$2a$12$lmrace.%02d", i))
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := repo.Create(ctx, domain.LoginMethod{
					UserID: user, Kind: domain.LoginMethodPassword, Verifier: verifier,
				})
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case stderrors.Is(err, iamerr.ErrAlreadyExists):
					dup++
				default:
					other = append(other, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		return ok, dup, other
	}

	one := lmPeople(t, pool, "lmrace", 1)
	ok, dup, other := run(one)
	t.Logf("гонка одного человека: гонщиков %d, прошло %d, ALREADY_EXISTS %d, иных %d", racers, ok, dup, len(other))
	require.Empty(t, other, "F4d-15: иных исходов быть не должно")
	require.Equal(t, 1, ok, "F4d-15: проходит РОВНО один")
	require.Equal(t, racers-1, dup, "F4d-15: остальные получают ALREADY_EXISTS")
	require.Equal(t, 1, lmCount(t, pool, one[0]), "в таблице ровно одна строка")

	// Положительный контроль: разные люди одновременно — проходят все. Иначе
	// «проходит ровно один» было бы верно и о хранилище, пропускающем одну
	// вставку за раз на всех.
	many := lmPeople(t, pool, "lmmany", racers)
	ok, dup, other = run(many)
	t.Logf("гонка разных людей: гонщиков %d, прошло %d, ALREADY_EXISTS %d, иных %d", racers, ok, dup, len(other))
	require.Empty(t, other)
	require.Equal(t, racers, ok, "разные люди не конкурируют за один ключ")
}

func lmEmailOf(t *testing.T, pool *pgxpool.Pool, user domain.UserID) domain.Email {
	t.Helper()
	var e string
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, string(user)).Scan(&e))
	return domain.Email(e)
}

// TestLoginMethodRepo_VerificationLandsOnlyOnTheVerifiedValue — Д2, путь записи.
//
// Триггер снимает отметку, когда адрес меняется ПОСЛЕ подтверждения. Обратный
// порядок — подтверждение записывается ПОСЛЕ смены — триггер не видит: к моменту
// записи отметки адрес уже новый. Этот порядок закрывает сверка значения в том
// же операторе, что и запись.
func TestLoginMethodRepo_VerificationLandsOnlyOnTheVerifiedValue(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "lmmark", 1)
	user := people[0]
	current := lmEmailOf(t, pool, user)

	_, verified, err := repo.EmailVerification(ctx, user)
	require.NoError(t, err)
	require.False(t, verified, "новый человек не подтверждён")

	// Подтверждено УСТАРЕВШЕЕ значение — отказ, отметки нет.
	err = repo.MarkEmailVerified(ctx, user, "someone-else@example.invalid", time.Now())
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.Equal(t, fmt.Sprintf("User %s email does not match the address being verified", user),
		iamerr.StripSentinel(err))
	require.NotContains(t, err.Error(), string(current), "отказ не раскрывает текущий адрес")
	_, verified, err = repo.EmailVerification(ctx, user)
	require.NoError(t, err)
	require.False(t, verified, "подтверждение чужого значения не легло")

	// Положительный контроль: подтверждено ТЕКУЩЕЕ значение — ложится.
	at := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.MarkEmailVerified(ctx, user, current, at))
	gotAt, verified, err := repo.EmailVerification(ctx, user)
	require.NoError(t, err)
	require.True(t, verified)
	require.True(t, at.Equal(gotAt), "момент подтверждения хранится тем, что записали: %v против %v", at, gotAt)

	// Несуществующий человек — своя полоса.
	err = repo.MarkEmailVerified(ctx, "usr0000000000000nobody", current, time.Now())
	require.ErrorIs(t, err, iamerr.ErrNotFound)
	_, _, err = repo.EmailVerification(ctx, "usr0000000000000nobody")
	require.ErrorIs(t, err, iamerr.ErrNotFound)

	// Нулевой момент — не «подтверждено в первом году», а отсутствие значения.
	err = repo.MarkEmailVerified(ctx, user, current, time.Time{})
	require.ErrorIs(t, err, iamerr.ErrInvalidArg)
}

// TestLoginMethodRepo_VerificationRacesAnAddressChange — инвариант привязки под
// гонкой: подтверждение старого значения и смена адреса идут одновременно.
//
// Какой бы порядок ни выпал, итог один из двух законных:
//   - смена первой → сверка значения не находит старого адреса, отметка не
//     ложится;
//   - подтверждение первым → отметка ложится и снимается сменой в её же
//     операторе.
//
// Незаконный итог ровно один: новый адрес с отметкой. Он проверяется на КАЖДОМ
// раунде. Какой порядок выпадал, печатает перепись: гонка не обязана выдать оба,
// и каждый из двух порядков по отдельности утверждён последовательной пробой —
// `TestLoginMethodRepo_VerificationLandsOnlyOnTheVerifiedValue` (сверка значения)
// и пробой схемы `TestIntegration_AddressVerificationIsBoundToTheValue` (снятие
// сменой).
func TestLoginMethodRepo_VerificationRacesAnAddressChange(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "lmvrace", 1)
	user := people[0]
	const rounds = 60

	var markWon, changeWon int
	for r := 0; r < rounds; r++ {
		oldAddr := domain.Email(fmt.Sprintf("lmvrace-old-%02d@example.invalid", r))
		newAddr := fmt.Sprintf("lmvrace-new-%02d@example.invalid", r)
		_, err := pool.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, string(user), string(oldAddr))
		require.NoError(t, err)

		// Смещение старта чередуется: без него на этой машине всякий раз первой
		// выигрывала смена (замер: 60 из 60), и второй порядок гонкой не
		// сэмплировался. Смещение не ожидание условия — оно выбирает, КАКОЙ
		// порядок исследовать, а исход по-прежнему решает замок строки.
		var markLag, changeLag time.Duration
		switch r % 3 {
		case 1:
			changeLag = time.Millisecond
		case 2:
			markLag = time.Millisecond
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var markErr, changeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(markLag)
			markErr = repo.MarkEmailVerified(ctx, user, oldAddr, time.Now())
		}()
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(changeLag)
			_, changeErr = pool.Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, string(user), newAddr)
		}()
		close(start)
		wg.Wait()
		require.NoError(t, changeErr)

		var email string
		var at *time.Time
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT email, email_verified_at FROM users WHERE id = $1`, string(user)).Scan(&email, &at))
		require.Equal(t, newAddr, email)
		require.Nil(t, at, "раунд %d: новый адрес не бывает подтверждённым без своей записи", r)

		switch {
		case markErr == nil:
			markWon++
		case stderrors.Is(markErr, iamerr.ErrFailedPrecondition):
			changeWon++
		default:
			t.Fatalf("раунд %d: неожиданный исход подтверждения: %v", r, markErr)
		}
	}
	t.Logf("перепись гонки: раундов %d, подтверждение первым %d, смена первой %d", rounds, markWon, changeWon)
	require.Equal(t, rounds, markWon+changeWon)
}
