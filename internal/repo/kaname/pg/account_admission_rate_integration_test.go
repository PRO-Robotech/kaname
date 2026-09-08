// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_admission_rate_integration_test.go — потолок ТЕМПА заведения аккаунтов
// одной личностью.
//
// # Чем это отличается от потолка объёма
//
// Потолок объёма (484002) отвечает на «сколько их у неё сейчас» и держится
// числом. Он не мешает завести все пять за секунду, а затем ещё пять с новой
// подтверждённой почты: стоимость обхода равна стоимости нового адреса.
//
// Потолок темпа отвечает на «сколько их она завела за окно» и требует ВРЕМЕНИ, а
// не только числа. Строка учёта объёма для него не годится — времени в ней нет, —
// и дописать в неё столбец нельзя: та таблица общая на шесть владельцев.
//
// # Почему первый аккаунт не отвергается никогда
//
// Личная область заводится сама при первом входе. Отказ по темпу на первом входе
// есть отказ во входе, а такого исхода у самообслуживания быть не может. Поэтому
// первая запись личности проходит ветвью вставки — то есть безусловно, — и
// величина потолка на неё не влияет вовсе.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// newAccountRateDB — своя база и пул на пробу.
func newAccountRateDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, ctx
}

// setAccountRateCeiling меняет действующую величину темпа — тем же способом,
// каким её меняет администратор облака: правкой строки авторитета.
//
// Проба делает это НЕ ради удобства: «величина меняется и доезжает до живого
// проекта» есть отдельное утверждение, и проверить его можно только изменив её.
func setAccountRateCeiling(t *testing.T, ctx context.Context, pool *pgxpool.Pool, maxEvents, windowSeconds int64) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		UPDATE kaname.account_admission_rate_limits
		   SET max_events = $1, window_seconds = $2
		 WHERE kind = 'iam.account' AND withdrawn_at IS NULL`,
		maxEvents, windowSeconds)
	require.NoError(t, err, "правка величины темпа")
	require.EqualValues(t, 1, tag.RowsAffected(),
		"действующей величины темпа в авторитете нет: менять администратору нечего, "+
			"и потолок держится не величиной, а кодом")
}

// rewindAdmissionWindow отматывает начало окна назад — так наступление
// СЛЕДУЮЩЕГО окна проверяется детерминированно, а не ожиданием.
func rewindAdmissionWindow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, identity string, seconds int64) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		UPDATE kaname.identity_admission_windows
		   SET window_started_at = window_started_at - make_interval(secs => $2)
		 WHERE carrier_id = $1 AND kind = 'iam.account'`,
		identity, seconds)
	require.NoError(t, err, "отмотка окна")
	require.EqualValues(t, 1, tag.RowsAffected(), "ряда окна у личности нет")
}

// TestAccountRate_CreationsBeyondTheWindowCeilingAreRefused — потолок темпа,
// который ОГРАНИЧИВАЕТ.
//
// Положительный контроль стоит первым и он обязателен: потолок, отвергающий
// разрешённое, — не потолок, а поломка, и отрицание без него зеленеет на
// механизме, отвергающем всё.
func TestAccountRate_CreationsBeyondTheWindowCeilingAreRefused(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	identity, userID := accountQuotaFixture(t, ctx, pool, "rate-ceiling")

	// Три за окно: первый уже заведён фикстурой, значит проходят ещё два.
	setAccountRateCeiling(t, ctx, pool, 3, 3600)

	for i := 2; i <= 3; i++ {
		require.NoErrorf(t, insertAccount(ctx, pool, fmt.Sprintf("rate-acc-ceiling-%d", i), userID),
			"аккаунт %d из трёх отвергнут: потолок темпа отвергает разрешённое", i)
	}

	err := insertAccount(ctx, pool, "rate-acc-ceiling-4", userID)
	require.Error(t, err,
		"четвёртый аккаунт за окно прошёл: потолка на СКОРОСТЬ заведения нет, и предел "+
			"объёма обходится темпом — пять за секунду, затем ещё пять с нового адреса")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ004", pgErr.Code,
		"отказ по темпу пришёл не своим кодом: клиент не отличит «подожди» от "+
			"«подними предел», а действия у них разные")
	require.Contains(t, pgErr.Message, "iam.account",
		"текст отказа не называет вида: арендатор не узнает, чего именно он завёл слишком быстро")
	require.Contains(t, pgErr.Message, identity,
		"текст отказа не называет носителя: у отказа по темпу носитель — личность, "+
			"и не назвать его значит отправить администратора искать не тот предмет")
}

// TestAccountRate_TheFirstAccountOfAnIdentityIsNeverRefused — первый вход не
// ломается НИ ПРИ КАКОЙ величине потолка.
//
// Проба ставит величину в НОЛЬ — самый враждебный вход, какой авторитет
// допускает, — и требует, чтобы личная область всё равно завелась. Отказ здесь
// был бы отказом во входе, а самообслуживаемая регистрация такого исхода не
// имеет.
func TestAccountRate_TheFirstAccountOfAnIdentityIsNeverRefused(t *testing.T) {
	pool, ctx := newAccountRateDB(t)

	setAccountRateCeiling(t, ctx, pool, 0, 3600)

	// Фикстура заводит личность вместе с её ПЕРВЫМ аккаунтом — то есть ровно тот
	// путь, который обязан пережить нулевую величину.
	_, userID := accountQuotaFixture(t, ctx, pool, "rate-first")

	// А второй — уже нет: исключение относится к первому и только к нему.
	err := insertAccount(ctx, pool, "rate-acc-first-2", userID)
	require.Error(t, err,
		"второй аккаунт прошёл при нулевом потолке темпа: исключение для первого входа "+
			"распространилось на всё, и потолка нет вовсе")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ004", pgErr.Code)
}

// TestAccountRate_NextWindowAdmitsAgain — окно КОНЧАЕТСЯ.
//
// Без этой пробы потолок темпа неотличим от потолка объёма с другим числом:
// исчерпав окно, личность была бы заблокирована навсегда, и «подожди» стало бы
// ложью в тексте отказа.
func TestAccountRate_NextWindowAdmitsAgain(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	identity, userID := accountQuotaFixture(t, ctx, pool, "rate-window")

	setAccountRateCeiling(t, ctx, pool, 2, 3600)

	require.NoError(t, insertAccount(ctx, pool, "rate-acc-window-2", userID),
		"второй аккаунт из двух отвергнут")
	require.Error(t, insertAccount(ctx, pool, "rate-acc-window-3", userID),
		"третий за окно прошёл: окна нет")

	rewindAdmissionWindow(t, ctx, pool, identity, 7200)

	require.NoError(t, insertAccount(ctx, pool, "rate-acc-window-next", userID),
		"следующее окно не приняло ни одного: потолок темпа блокирует навсегда, то есть "+
			"«подожди» в тексте отказа — неправда")
}

// TestAccountRate_ChangingTheCeilingReachesTheLivePath — величина, изменённая
// администратором, действует НЕМЕДЛЕННО.
//
// Это не самоочевидно: у пяти прочих владельцев величина приезжает снимком и
// может отставать. Здесь авторитет лежит в той же базе и читается тем же
// оператором, что и списывает, — отставать нечему, и проба это закрепляет.
func TestAccountRate_ChangingTheCeilingReachesTheLivePath(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	_, userID := accountQuotaFixture(t, ctx, pool, "rate-change")

	setAccountRateCeiling(t, ctx, pool, 1, 3600)
	require.Error(t, insertAccount(ctx, pool, "rate-acc-change-2", userID),
		"второй аккаунт прошёл при потолке в один: величина не читается на пути записи")

	setAccountRateCeiling(t, ctx, pool, 4, 3600)
	require.NoError(t, insertAccount(ctx, pool, "rate-acc-change-2b", userID),
		"поднятая величина не доехала до живого пути: администратор облака меняет "+
			"строку, а решение принимается по прежнему числу")
}

// TestAccountRate_ConcurrentCreationAtTheLastSlotAdmitsExactlyOne — гонка
// разрешается оператором БД, а не проверкой в коде.
//
// Проба несущая: «посчитал за окно → вставил» проходит все юнит-проверки и
// ломается ровно здесь — два создателя видят одно и то же свободное место окна и
// оба его занимают.
func TestAccountRate_ConcurrentCreationAtTheLastSlotAdmitsExactlyOne(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	_, userID := accountQuotaFixture(t, ctx, pool, "rate-race")

	// Окно на двоих: первый занят фикстурой, свободно РОВНО ОДНО место.
	setAccountRateCeiling(t, ctx, pool, 2, 3600)

	// Барьер обязателен: без него участники стартуют по мере планирования, и
	// первый успевает закоммитить раньше, чем последний вошёл в оператор. Проба
	// осталась бы верной по утверждению и слабее по СИЛЕ — она мерила бы разброс
	// планировщика, а не разрешение гонки. `close` отпускает всех разом.
	const racers = 8
	var (
		wg      sync.WaitGroup
		ready   sync.WaitGroup
		mu      sync.Mutex
		okCount int
		codes   []string
	)
	start := make(chan struct{})
	wg.Add(racers)
	ready.Add(racers)
	for i := 0; i < racers; i++ {
		go func(idx int) {
			defer wg.Done()
			ready.Done()
			<-start
			err := insertAccount(ctx, pool, fmt.Sprintf("rate-acc-race-%d", idx), userID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
				return
			}
			var pgErr *pgconn.PgError
			if stderrors.As(err, &pgErr) {
				codes = append(codes, pgErr.Code)
			} else {
				codes = append(codes, err.Error())
			}
		}(i)
	}
	ready.Wait() // все участники запланированы и стоят на барьере
	close(start)
	wg.Wait()

	require.Equal(t, 1, okCount,
		"свободное место окна занято %d раз при одном свободном: решение принимает "+
			"не единственный атомарный оператор, и потолок темпа проходим гонкой", okCount)
	require.Len(t, codes, racers-1)
	for _, code := range codes {
		require.Equal(t, "KQ004", code,
			"проигравший получил не отказ по темпу: под гонкой контракт отказа меняется")
	}
}

// TestAccountRate_DeletingAnAccountDoesNotReturnARateSlot — снятие аккаунта
// возвращает место ОБЪЁМА и не возвращает место ТЕМПА.
//
// Различие не педантское, и без него потолок темпа обходится тривиально: заводим
// и тут же снимаем, пока не наберётся нужное число живых. Объём считает ЗАНЯТЫЕ
// МЕСТА и потому обязан возвращать; темп считает СОБЫТИЯ, а событие снятием не
// отменяется — оно уже произошло.
//
// Положительный контроль здесь же: место объёма всё-таки возвращается, иначе
// проба зеленела бы на схеме, не возвращающей ничего.
func TestAccountRate_DeletingAnAccountDoesNotReturnARateSlot(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	identity, userID := accountQuotaFixture(t, ctx, pool, "rate-delete")

	setAccountRateCeiling(t, ctx, pool, 2, 3600)

	require.NoError(t, insertAccount(ctx, pool, "rate-acc-delete-2", userID),
		"второй аккаунт из двух отвергнут")

	// Снимаем его же: место объёма обязано вернуться, место окна — нет.
	var doomed string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.accounts WHERE name = $1`, "rate-acc-delete-2").Scan(&doomed))
	_, err := pool.Exec(ctx, `DELETE FROM kaname.accounts WHERE id = $1`, doomed)
	require.NoError(t, err, "снятие аккаунта")

	var used int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT used FROM kaname.project_resource_quotas
		 WHERE carrier_type = 'identity' AND carrier_id = $1 AND kind = 'iam.account'`,
		identity).Scan(&used))
	require.EqualValues(t, 1, used,
		"место ОБЪЁМА не вернулось на снятии: положительный контроль не выполнен, и "+
			"утверждение ниже ничего не различает")

	require.Error(t, insertAccount(ctx, pool, "rate-acc-delete-3", userID),
		"место ОКНА вернулось вместе со снятым аккаунтом: потолок темпа обходится "+
			"заведением и снятием подряд, то есть не ограничивает ничего")
}

// liftRateCeilingOutOfTheWay поднимает потолок ТЕМПА так, чтобы он не участвовал
// в пробе, предмет которой — НЕ темп: потолок ОБЪЁМА либо любое другое
// утверждение, которому по дороге нужно завести больше трёх аккаунтов одной
// личности (например страница списка).
//
// # Почему это не ослабление пробы
//
// Умолчание темпа — три заведения в час, умолчание объёма — пять аккаунтов.
// Значит проба объёма, заводящая пятый аккаунт подряд, упирается СНАЧАЛА в темп и
// получает отказ той полосы, о которой она ничего не утверждает. Оставить как
// есть значило бы, что проба объёма зеленеет либо краснеет по причине, к объёму
// отношения не имеющей, — а это и есть проба, судящая не свой предмет.
//
// Пробы темпа, наоборот, поднимают потолок объёма из-под ног не поднимая ничего:
// им хватает того, что темп бьёт раньше. Взаимодействие двух потолков названо в
// собственной пробе (`TestAccountRate_*`) и в миграции задачи #618, а не размазано по
// чужим утверждениям.
func liftRateCeilingOutOfTheWay(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	setAccountRateCeiling(t, ctx, pool, 1000, 3600)
}
