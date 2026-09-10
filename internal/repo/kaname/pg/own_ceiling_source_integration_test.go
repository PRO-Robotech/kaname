// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// own_ceiling_source_integration_test.go — ВЕЛИЧИНА ТРЁХ СОБСТВЕННЫХ ПОТОЛКОВ
// БЕРЁТСЯ ИЗ ПРОЕКЦИИ ПОСАДКИ, а не у авторитета величин.
//
// Задача продукта #2117, приёмка `KAN-QUOTA-1`, `П25`, сценарии `KAN-Q3-01`,
// `KAN-Q3-02`, `KAN-Q3-06`; условие готовности `DoD S3` пп. 1-2.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ПРОБА НА ЖИВОМ POSTGRES, А НЕ ЧТЕНИЕ ТЕКСТА МИГРАЦИИ
//
// Списание — единственный атомарный оператор, и решение принимает он. Текст
// миграции скажет, ЧТО она объявляет; он не скажет, читает ли списание новый
// источник, и не скажет, что старый перестал влиять. Оба утверждения проверяются
// только вызовом.
//
// ─────────────────────────────────────────────────────────────────────────────
// РЕШАЮЩЕЕ УТВЕРЖДЕНИЕ — ОДНО-ФАКТНОЕ, И ОНО ЗДЕСЬ ЕСТЬ
//
// «Величина берётся из посадки» доказывается не тем, что потолок наступает (он
// наступал и прежде), а тем, что при РАСХОЖДЕНИИ двух источников выигрывает
// проекция посадки. Поэтому решающая проба меняет РОВНО ОДИН факт: заводит у
// авторитета величину, отличную от проекции, и требует, чтобы отказ назвал
// величину ПРОЕКЦИИ. Без этой пары «читает посадку» зеленело бы на дереве, где
// списание по-прежнему читает авторитет.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// setOwnCeiling — величина проекции посадки. Ровно тот оператор, которым её
// пишет композиционный корень при пуске.
func setOwnCeiling(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kind string, value int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.own_ceilings (kind, limit_value, stated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (kind) DO UPDATE
		   SET limit_value = EXCLUDED.limit_value, stated_at = now()`, kind, value)
	require.NoErrorf(t, err, "проекция посадки для вида %s не записана", kind)
}

// TestOwnCeiling_MigrationCarriedTheAuthorityValueIntoThePosture — накат НЕ
// МЕНЯЕТ наблюдаемого: величина перенесена, у авторитета её больше нет.
//
// Пара, а не одно утверждение: «у авторитета нет» зеленело бы на базе, где посев
// величин не применился вовсе, поэтому рядом стоит перенесённое значение.
func TestOwnCeiling_MigrationCarriedTheAuthorityValueIntoThePosture(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)

	// Величины посева `0001_initial.sql`: их и обязан перенести накат.
	want := map[string]int64{
		"iam.account":                   5,
		"iam.user.credential":           12,
		"iam.serviceAccount.credential": 24,
	}
	for kind, value := range want {
		var got int64
		require.NoErrorf(t, pool.QueryRow(ctx,
			`SELECT limit_value FROM kaname.own_ceilings WHERE kind = $1`, kind).Scan(&got),
			"величина вида %s не перенесена в проекцию посадки: до первого пуска "+
				"новой версии создание этого вида отвергалось бы, хотя до наката проходило", kind)
		require.Equalf(t, value, got,
			"величина вида %s перенесена искажённой: накат обязан не менять "+
				"наблюдаемого, а перенести ровно объявленное", kind)

		var atAuthority int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.limits WHERE kind = $1`, kind).Scan(&atAuthority))
		require.Zerof(t, atAuthority,
			"величина вида %s осталась у авторитета: администратор назначил бы её, "+
				"продукт сохранил бы и НЕ ПРИМЕНИЛ — списание читает проекцию посадки", kind)
	}

	// Положительный контроль: у ЧУЖОГО вида величина у авторитета остаётся. Без
	// него «у авторитета нет» зеленело бы на пустой таблице величин.
	var foreign int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.limits WHERE kind = 'vpc.network'`).Scan(&foreign))
	require.NotZero(t, foreign,
		"величина чужого вида снята вместе с собственными: роль потребителя сломана, "+
			"а её снятие — предмет стадии S4, не этой")

	t.Logf("перепись: видов посадки сверено %d, чужих контрольных 1", len(want))
}

// TestOwnCeiling_PostureBeatsTheAuthorityOnTheChargingPath — РЕШАЮЩАЯ проба.
//
// Один изменённый факт против положительного близнеца
// `TestAccountQuota_SixthAccountOfOneIdentityIsRefused`: у авторитета заведена
// величина, ОТЛИЧНАЯ от проекции посадки. Отказ обязан назвать величину проекции.
func TestOwnCeiling_PostureBeatsTheAuthorityOnTheChargingPath(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	// Проекция посадки: одна личность держит два аккаунта.
	setOwnCeiling(t, ctx, pool, "iam.account", 2)

	// АВТОРИТЕТ ГОВОРИТ ДРУГОЕ. Строка заводится в обход входного отказа — прямо
	// в таблицу: предмет пробы здесь не вход авторитета, а то, ЧТО ЧИТАЕТ
	// СПИСАНИЕ. Величина выбрана заведомо щедрой: если списание читает авторитет,
	// девятый аккаунт пройдёт, и проба покраснеет на своём предмете.
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision)
		VALUES ('lim-0000000000000000a', now(), 'DEFAULT', '', 'iam.account', 9, NULL, 99)`)
	require.NoError(t, err, "величина авторитета не заведена — расхождения источников нет, "+
		"и решающее утверждение стало бы вакуумным")

	_, userID := accountQuotaFixture(t, ctx, pool, "posture-wins")

	// Фикстура завела первый аккаунт; проекция говорит «два», значит проходит
	// ровно один и третий отвергается.
	require.NoError(t, insertAccount(ctx, pool, "own-ceiling-posture-2", userID),
		"второй аккаунт обязан пройти: потолок проекции — два, а потолок, "+
			"отвергающий разрешённое, есть поломка, а не потолок")

	err = insertAccount(ctx, pool, "own-ceiling-posture-3", userID)
	require.Error(t, err,
		"третий аккаунт прошёл: значит списание читает величину АВТОРИТЕТА (9), "+
			"а не проекцию посадки (2) — источник величины не переехал")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ001", pgErr.Code,
		"отказ обязан приходить единственным производителем платформы")
	require.Contains(t, pgErr.Message, "has reached its limit of 2 iam.account",
		"текст отказа обязан называть величину ПРОЕКЦИИ ПОСАДКИ: величина в тексте — "+
			"часть контракта, и по ней арендатор узнаёт действующий предел")
	require.NotContains(t, pgErr.Message, "limit of 9",
		"отказ назвал величину авторитета: она больше не действует, и называть её "+
			"значило бы отправить арендатора менять то, что ни на что не влияет")
}

// TestOwnCeiling_ExplicitZeroRefusesTheFirstResourceByTheCeiling — явный ноль
// ОТЛИЧИМ от «величина не названа».
//
// Оба состояния отвергают создание, и различие несущее: ноль есть решение
// оператора («этого вида не заводить»), а отсутствие — ошибка посадки. Клиент
// различает их машинным признаком, поэтому проба утверждает КОД, а не только отказ.
func TestOwnCeiling_ExplicitZeroRefusesTheFirstResourceByTheCeiling(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	_, userID := accountQuotaFixture(t, ctx, pool, "explicit-zero")
	setOwnCeiling(t, ctx, pool, "iam.account", 0)

	err := insertAccount(ctx, pool, "own-ceiling-zero-2", userID)
	require.Error(t, err, "при потолке ноль создание обязано быть отвергнуто")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ001", pgErr.Code,
		"ноль — ВЕЛИЧИНА, поэтому отказ по нему есть отказ ПО ПОТОЛКУ (KQ001), а не "+
			"«потолок не назван» (KQ002): второе означало бы ошибку посадки, и "+
			"оператор пошёл бы искать несуществующую опечатку")
	require.Contains(t, pgErr.Message, "has reached its limit of 0 iam.account",
		"текст отказа обязан называть ноль величиной, а не молчать о нём")
}

// TestOwnCeiling_LoweringBelowConsumptionKeepsTheRowsAndRefusesTheNext —
// понижение величины ниже потребления НЕ УДАЛЯЕТ существующего.
//
// Сценарий `KAN-Q3-07`: оператор вправе сузить потолок, и это не даёт ему права
// снести уже созданное. Проба на уровне базы, потому что решение принимает
// оператор базы: `used = limit` и `limit < used` — законные состояния строки.
func TestOwnCeiling_LoweringBelowConsumptionKeepsTheRowsAndRefusesTheNext(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	setOwnCeiling(t, ctx, pool, "iam.account", 3)
	external, userID := accountQuotaFixture(t, ctx, pool, "lowered")
	for i := 2; i <= 3; i++ {
		require.NoErrorf(t, insertAccount(ctx, pool, fmt.Sprintf("own-ceiling-lowered-%d", i), userID),
			"аккаунт %d из трёх обязан пройти", i)
	}

	// ПЕРЕЗАПУСК С НОВОЙ ВЕЛИЧИНОЙ — ровно то, что делает пуск процесса.
	setOwnCeiling(t, ctx, pool, "iam.account", 1)

	var accounts, used int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM accounts WHERE owner_user_id = $1`, userID).Scan(&accounts))
	require.EqualValues(t, 3, accounts,
		"понижение величины удалило аккаунты: потолок ограничивает СОЗДАНИЕ, "+
			"а не хранение, и снос созданного не заказывал никто")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT used FROM kaname.project_resource_quotas
		  WHERE carrier_type = 'identity' AND carrier_id = $1 AND kind = 'iam.account'`,
		external).Scan(&used))
	require.EqualValues(t, 3, used,
		"потребление сброшено сменой величины: счёт обязан пережить и смену "+
			"величины, и перезапуск — иначе понижение потолка ПОДАРИЛО бы место")

	err := insertAccount(ctx, pool, "own-ceiling-lowered-4", userID)
	require.Error(t, err,
		"после понижения величины создание обязано отвергаться, пока потребление "+
			"не станет меньше её")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ001", pgErr.Code)
	require.Contains(t, pgErr.Message, "has reached its limit of 1 iam.account",
		"отказ обязан называть ДЕЙСТВУЮЩУЮ величину, а не ту, при которой ресурсы создавались")
}

// TestOwnCeiling_ForeignKindStillTakesItsValueFromTheAuthority — ПОЛОЖИТЕЛЬНЫЙ
// БЛИЗНЕЦ всего файла: роль потребителя не тронута.
//
// Без него «величина берётся из проекции» зеленело бы на дереве, где авторитет
// перестал читаться ВООБЩЕ, — то есть где пять потребителей потеряли свои потолки.
func TestOwnCeiling_ForeignKindStillTakesItsValueFromTheAuthority(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)

	// Чужой вид в проекции посадки НЕВЫРАЗИМ: множество закрыто схемой, а не
	// соглашением. Это и есть доказательство, что проекция не стала авторитетом.
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('vpc.network', 1)`)
	require.Error(t, err,
		"чужой вид принят проекцией посадки: значит она стала вторым авторитетом, "+
			"и величина на вид, которого служба не считает, была бы принята молча")

	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23514", pgErr.Code,
		"закрытость множества обязана держать СХЕМА (CHECK), а не проверка в коде: "+
			"вторая пропускает всякого, кто пишет в таблицу мимо неё")

	// И величина чужого вида по-прежнему объявляется авторитетом.
	var value int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT limit_value FROM kaname.limits
		  WHERE kind = 'vpc.network' AND scope = 'DEFAULT' AND withdrawn_at IS NULL`).Scan(&value))
	require.NotZero(t, value,
		"величина чужого вида исчезла: снятие ушло шире своего предмета")
}

// TestOwnCeiling_TenantReadTakesTheValueFromThePostureNotTheStaleSnapshot —
// АРЕНДАТОРСКОЕ ЧТЕНИЕ берёт величину у посадки (сценарий `KAN-Q3-05`).
//
// # Почему снимок строки учёта читать нельзя
//
// Он обновляется СПИСАНИЕМ, значит между сменой величины и следующим созданием
// ресурса отстаёт. Отдать его арендатору значило бы назвать потолок, который уже
// не действует, — то есть отправить его менять поведение, которое уже изменено.
//
// # Пара, а не одно утверждение
//
// Отрицание («снимок не отдаётся») зеленело бы на ответе, где величины нет вовсе,
// поэтому рядом стоит положительный контроль: ответ НЕ ПУСТ ни при каком
// состоянии, и потребление в нём — фактическое.
func TestOwnCeiling_TenantReadTakesTheValueFromThePostureNotTheStaleSnapshot(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	setOwnCeiling(t, ctx, pool, "iam.account", 3)
	external, _ := accountQuotaFixture(t, ctx, pool, "tenant-read")

	// Снимок в строке учёта зафиксирован списанием при величине ТРИ; посадка
	// объявляет ОДИН. Один изменённый факт — и он же решающий.
	setOwnCeiling(t, ctx, pool, "iam.account", 1)

	var snapshot int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT limit_value FROM kaname.project_resource_quotas
		  WHERE carrier_type = 'identity' AND carrier_id = $1 AND kind = 'iam.account'`,
		external).Scan(&snapshot))
	require.EqualValues(t, 3, snapshot,
		"снимок уже совпал с посадкой — решающее утверждение стало вакуумным: "+
			"расхождения источников нет, и «читает посадку» ничем не отличается от "+
			"«читает снимок»")

	states, err := pg.NewIdentityQuotaRepo(pool).States(ctx, external)
	require.NoError(t, err)
	require.NotEmpty(t, states,
		"ответ пуст: арендатор заключил бы, что он не ограничен, а он ограничен — "+
			"пустой массив зарезервирован под утверждение, которого эта служба не делает")

	var found bool
	for _, st := range states {
		if st.Kind != "iam.account" {
			continue
		}
		found = true
		require.EqualValues(t, 1, st.Limit,
			"чтение отдало ОТСТАВШИЙ снимок (%d) вместо величины посадки: арендатор "+
				"читает потолок, который уже не действует", snapshot)
		require.EqualValues(t, 1, st.Used,
			"потребление не фактическое: фикстура завела ровно один аккаунт")
		require.Equal(t, "DEFAULT", st.SourceScope,
			"область ответа обязана называть установку: величина объявлена посадкой, "+
				"а не аккаунтом и не проектом арендатора")
		require.Empty(t, st.SourceScopeID,
			"идентификатор области непуст при `DEFAULT` — контракт объявляет его пустым "+
				"и только тогда")
	}
	require.True(t, found,
		"вида `iam.account` в ответе нет вовсе: потолок, который наступает, стал "+
			"невидим арендатору — отказ по нему читался бы как поломка платформы")
}
