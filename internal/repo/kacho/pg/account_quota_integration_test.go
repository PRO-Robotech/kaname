// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_quota_integration_test.go — потолок на число аккаунтов ОДНОЙ личности.
//
// # Почему это свойство базы, а не use-case'а
//
// Аккаунт — корень аренды, и заводит его себе сам свежеаутентифицированный
// человек. Значит любое ограничение ВНУТРИ аккаунта обходится заведением второго
// аккаунта: второй комплект пределов достаётся тем же действием, которым получен
// первый. Потолок над самим аккаунтом — единственное, что этот обход закрывает.
//
// Держать его проверкой в use-case нельзя: «посчитал → вставил» есть
// check-then-act через границу оператора, и между чтением и вставкой помещается
// чужая запись (ban #10). Поэтому вход подаётся ВСТАВКОЙ в ту же таблицу, в
// которую пишет продукт, а решение принимает единственный атомарный оператор.
//
// # Почему носитель — ЛИЧНОСТЬ, а не аккаунт и не проект
//
// Носитель обязан быть внешним по отношению к предмету счёта. Проект и аккаунт
// этому не удовлетворяют by construction: аккаунт нельзя считать в аккаунте.
// Личность — единственное, что существует ДО аккаунта и переживает его.
//
// Личность здесь — внешний идентификатор входа (`users.external_id`), а не строка
// пользователя: строка пользователя сегодня привязана к аккаунту, и после снятия
// этой сцепки одна личность будет держать их сколько угодно. Считать по строке
// значило бы дать обход ровно тем изменением, ради которого потолок и заводится.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// accountQuotaFixture — одна личность, её строка пользователя и её первый
// аккаунт.
//
// Первый аккаунт нужен потому, что строка пользователя ссылается на аккаунт
// (сцепка, которую снимает отдельная работа): личности без аккаунта в схеме
// сегодня не существует. Возвращается внешний идентификатор — то, по чему ведётся
// счёт, — и идентификатор строки пользователя, которым владеют аккаунты.
func accountQuotaFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (externalID, userID string) {
	t.Helper()
	userID = ids.NewID(domain.PrefixUser)
	accountID := ids.NewID(domain.PrefixAccount)
	externalID = "ext-quota-" + suffix + "-" + userID

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		userID, accountID, externalID, "quota-"+suffix+"@example.com", "Quota Fixture "+suffix)
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accountID, "quota-acc-"+suffix, userID)
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx), "commit account quota fixture")
	return externalID, userID
}

// insertAccount заводит ещё один аккаунт той же личности — тем же оператором,
// каким это делает продукт.
func insertAccount(ctx context.Context, pool *pgxpool.Pool, name, ownerUserID string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		ids.NewID(domain.PrefixAccount), name, ownerUserID)
	return err
}

// newAccountQuotaDB — своя база и пул на пробу.
func newAccountQuotaDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, ctx
}

// TestAccountQuota_SixthAccountOfOneIdentityIsRefused — потолок, который
// ОГРАНИЧИВАЕТ.
//
// Предел умолчания — пять. Фикстура уже завела первый аккаунт, поэтому проходят
// ещё четыре, а шестой отвергается. Отказ приходит ДО записи и тем же контрактом,
// что у прочих видов: код `KQ001` единственного производителя отказа.
func TestAccountQuota_SixthAccountOfOneIdentityIsRefused(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "sixth")

	for i := 2; i <= 5; i++ {
		require.NoErrorf(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-sixth-%d", i), userID),
			"аккаунт %d из пяти обязан пройти — потолок, отвергающий разрешённое, "+
				"это не потолок, а поломка", i)
	}

	err := insertAccount(ctx, pool, "quota-acc-sixth-6", userID)
	require.Error(t, err,
		"шестой аккаунт одной личности прошёл: потолка над аккаунтом нет, и всякое "+
			"ограничение внутри аккаунта обходится заведением следующего")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ001", pgErr.Code,
		"отказ обязан приходить ЕДИНСТВЕННЫМ производителем платформы: свой текст "+
			"здесь означал бы шестую копию контракта отказа")
	require.Contains(t, pgErr.Message, "has reached its limit of 5 iam.account",
		"текст отказа — часть контракта: он называет носителя, предел и вид")
}

// TestAccountQuota_ConcurrentCreationAtTheLastSlotAdmitsExactlyOne — гонка
// разрешается оператором БД, а не проверкой в коде.
//
// Проба несущая: «посчитал → вставил» проходит все юнит-проверки и ломается ровно
// здесь — два создателя видят одно и то же свободное место и оба его занимают.
func TestAccountQuota_ConcurrentCreationAtTheLastSlotAdmitsExactlyOne(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "race")

	// Фикстура завела первый; добираем до четырёх, оставляя РОВНО ОДНО место.
	for i := 2; i <= 4; i++ {
		require.NoError(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-race-%d", i), userID))
	}

	const racers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		okCount int
		errs    []error
	)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(idx int) {
			defer wg.Done()
			err := insertAccount(ctx, pool, fmt.Sprintf("quota-acc-race-r%d", idx), userID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
				return
			}
			errs = append(errs, err)
		}(i)
	}
	wg.Wait()

	require.Equal(t, 1, okCount,
		"место было одно, а прошло %d: решение принимает не атомарный оператор, "+
			"и потолок протекает ровно под той нагрузкой, ради которой он заведён", okCount)
	require.Len(t, errs, racers-1)
	for _, err := range errs {
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "KQ001", pgErr.Code,
			"проигравший в гонке обязан получить ТОТ ЖЕ отказ, что и обычное исчерпание")
	}

	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM accounts WHERE owner_user_id = $1`, userID).Scan(&total))
	require.Equal(t, 5, total, "строк аккаунта больше предела: списание разошлось с тем, что оно считает")
}

// TestAccountQuota_DeletingAnAccountReturnsTheSlot — возврат в той же
// транзакции, что удаление.
//
// Положительный контроль к отрицаниям выше: без него «шестой отвергнут» зеленело
// бы и на потолке, который не отпускает НИКОГДА, — то есть на счётчике, который
// только растёт.
func TestAccountQuota_DeletingAnAccountReturnsTheSlot(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "refund")

	for i := 2; i <= 5; i++ {
		require.NoError(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-refund-%d", i), userID))
	}
	require.Error(t, insertAccount(ctx, pool, "quota-acc-refund-6", userID))

	_, err := pool.Exec(ctx, `DELETE FROM accounts WHERE name = $1`, "quota-acc-refund-5")
	require.NoError(t, err)

	require.NoError(t, insertAccount(ctx, pool, "quota-acc-refund-6", userID),
		"место, освобождённое удалением, не вернулось: потолок превращается в счётчик "+
			"заведённых за всё время, а это другое ограничение")
}

// TestAccountQuota_AnotherIdentityHasItsOwnCeiling — отрицание к общему счётчику.
//
// Без него «шестой отвергнут» зеленело бы и на ПЛАТФОРМЕННОМ потолке, где отказ
// приходит следующему честному человеку, а не тому, кто исчерпал.
func TestAccountQuota_AnotherIdentityHasItsOwnCeiling(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, mine := accountQuotaFixture(t, ctx, pool, "mine")
	_, theirs := accountQuotaFixture(t, ctx, pool, "theirs")

	for i := 2; i <= 5; i++ {
		require.NoError(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-mine-%d", i), mine))
	}
	require.Error(t, insertAccount(ctx, pool, "quota-acc-mine-6", mine))

	require.NoError(t, insertAccount(ctx, pool, "quota-acc-theirs-2", theirs),
		"исчерпание одной личности отказало другой: счёт ведётся не по личности, "+
			"и отказ достаётся невиновному")
}

// TestAccountQuota_AnOwnerWithoutALoginIdentityIsNotCounted — мягкий пропуск,
// названный решением.
//
// Строка пользователя в состоянии приглашения внешнего идентификатора не несёт
// (этого требует ограничение схемы), и аккаунт такого владельца схема принимает.
// Счётчик не вправе запрещать состояния, которых схема не запрещает: отвергнуть
// его значило бы изменить то, ЧТО ПЛАТФОРМА ПРИНИМАЕТ, под видом счёта.
//
// Обходом это не является, и проба говорит почему: аккаунт без личности НЕ
// прибавляется ни к чьему счёту, поэтому им нельзя ни исчерпать чужой потолок,
// ни освободить свой.
func TestAccountQuota_AnOwnerWithoutALoginIdentityIsNotCounted(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	// Предмет этой пробы — потолок ОБЪЁМА. Потолок ТЕМПА (задача #618) по умолчанию
	// бьёт раньше — три заведения в час против пяти аккаунтов, — поэтому он
	// поднимается из-под ног: иначе проба судила бы не свою полосу.
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "pending")

	// Приглашённый владелец: личности нет, и схема этого не запрещает.
	pendingUser := ids.NewID(domain.PrefixUser)
	pendingAcc := ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Откат ОТЛОЖЕН немедленно: проба, упавшая внутри открытой транзакции, не
	// вернёт соединение в пул никогда, и закрытие пула унесёт вердикт всего
	// пакета вместе с собой.
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, 'Pending Owner', 'PENDING')`,
		pendingUser, pendingAcc, "pending-quota@example.com")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, 'quota-acc-pending-owner', $2, '{}'::jsonb)`,
		pendingAcc, pendingUser)
	require.NoError(t, err, "аккаунт приглашённого владельца обязан вставляться: "+
		"счётчик не вправе запрещать то, чего не запрещает схема")
	require.NoError(t, tx.Commit(ctx))

	// Он не прибавился НИ К ЧЬЕМУ счёту: у личности из фикстуры по-прежнему
	// остаются её четыре свободных места.
	for i := 2; i <= 5; i++ {
		require.NoErrorf(t, insertAccount(ctx, pool, fmt.Sprintf("quota-acc-pending-%d", i), userID),
			"аккаунт %d из пяти отвергнут: неотнесённый аккаунт занял чужое место", i)
	}
	require.Error(t, insertAccount(ctx, pool, "quota-acc-pending-6", userID),
		"положительный контроль: потолок на месте, значит «не считается» выше "+
			"означает работу отбора, а не отключённый учёт")
}
