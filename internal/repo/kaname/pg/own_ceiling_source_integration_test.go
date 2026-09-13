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

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
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

// ЗДЕСЬ СТОЯЛИ ТРИ ПРОБЫ АВТОРИТЕТА ВЕЛИЧИН — сняты ВМЕСТЕ С ПРЕДМЕТОМ.
//
// Они утверждали: миграция перенесла величину из авторитета в посадку · посадка
// бьёт авторитет на пути списания · чужой вид всё ещё берёт величину у
// авторитета. Последняя была БЛИЗНЕЦОМ всего файла: без неё «величина берётся
// из проекции» зеленело бы на дереве, где авторитет перестал читаться вовсе.
//
// Авторитет ушёл из продукта целиком (kacho#2117), таблица снята миграцией. Все
// три стали недостижимыми: сравнивать источники не с чем, а близнецу нечего
// различать — источник теперь ОДИН by construction, и это сильнее, чем проба.
//
// Что осталось держать свойство: четыре пробы ниже судят величину из посадки —
// явный ноль, понижение ниже потребления, чтение арендатором и учётная строка.
// Перенос как исторический факт держит roundtrip миграций, применяющий их до
// точки снятия и обратно.

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

// TestOwnCeiling_IdentityWithoutACountingRowStillReadsItsCeiling — ДОБОР
// недостающего, и он берётся у ПОСАДКИ.
//
// # Предмет
//
// Строка учёта заводится триггером на первом аккаунте. До него её нет — и ответ
// обязан быть НЕ ПУСТЫМ: пустой прочитался бы как «предела нет», ровно наоборот
// действительности, и человек, которому первый же аккаунт откажут, не нашёл бы в
// продукте ни числа, ни причины.
//
// # Почему проба заведена ИМЕННО ЭТИМ изменением
//
// Ветвь добора перевязана стадией S4 (`PRO-Robotech/kacho#2117`): прежде перечень
// видов носителя брался из закрытого каталога авторитета величин, а величина —
// из `kaname.limits` для всякого не-посадочного вида. Каталог снят, ветвь читает
// словарь посадки, и другого источника у неё не осталось ни одного.
//
// НАБЛЮДАЕМОЕ ПОВЕДЕНИЕ ПРИ ЭТОМ НЕ МЕНЯЛОСЬ, и это сказано прямо, а не
// умолчано: единственный вид носителя — `iam.account` — объявлялся посадкой и до
// перевязки, поэтому проба НЕ была бы красной на прежнем коде. Она заведена не
// как доказательство исправления, а как держатель ветви, у которой держателя не
// было: до неё добор не исполнялся ни одной пробой дерева, и его отказ был бы
// виден только арендатору, у которого ещё нет ни одного аккаунта.
//
// # Отрицание в паре с положительным
//
// Величина посадки ставится ОТЛИЧНОЙ от умолчания цепи (5), иначе «прочитано из
// посадки» и «прочитано из посева» давали бы одно число и проба не различала бы
// источники.
func TestOwnCeiling_IdentityWithoutACountingRowStillReadsItsCeiling(t *testing.T) {
	pool, ctx := newAccountQuotaDB(t)
	liftRateCeilingOutOfTheWay(t, ctx, pool)

	// Величина, которой нет ни в посеве цепи, ни в снимке: совпади она с
	// умолчанием — ответ не сказал бы, откуда взят.
	const stated int64 = 7
	setOwnCeiling(t, ctx, pool, "iam.account", stated)

	// ЛИЧНОСТЬ, НЕ ЗАВОДИВШАЯ НИ ОДНОГО АККАУНТА, — и такая бывает не в теории:
	// это приглашённый участник чужого аккаунта. Строка пользователя есть
	// ЧЛЕНСТВО в одном аккаунте, поэтому личность без членства в схеме
	// невыразима вовсе (внешний ключ `users_account_fk`), а вот членство без
	// СВОЕГО аккаунта — обычное состояние.
	//
	// Прежняя редакция этой фикстуры заводила пользователя с несуществующим
	// аккаунтом и падала на внешнем ключе. Мир, которого не бывает, — негодная
	// предпосылка: проба о нём утверждала бы что угодно.
	_, ownerID := accountQuotaFixture(t, ctx, pool, "host-of-the-invited")
	var hostAccount string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT account_id FROM users WHERE id = $1`, ownerID).Scan(&hostAccount))

	external := "ext-quota-no-row-" + ids.NewID(domain.PrefixUser)
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		ids.NewID(domain.PrefixUser), hostAccount, external,
		"quota-no-row@example.com", "Quota No Row")
	require.NoError(t, err, "seed invited member")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.project_resource_quotas
		  WHERE carrier_type = 'identity' AND carrier_id = $1`, external).Scan(&rows))
	require.Zerof(t, rows, "у личности уже есть строка учёта: ветвь ДОБОРА не исполнится, "+
		"и проба утверждала бы о соседней полосе")

	states, err := pg.NewIdentityQuotaRepo(pool).States(ctx, external)
	require.NoError(t, err)
	require.NotEmpty(t, states,
		"ответ пуст при отсутствующей строке учёта: арендатор заключил бы, что он не "+
			"ограничен, — и упёрся бы в отказ на первом же аккаунте, не найдя ни числа, "+
			"ни причины")

	var found bool
	for _, st := range states {
		if st.Kind != "iam.account" {
			continue
		}
		found = true
		require.EqualValues(t, stated, st.Limit,
			"добор взял величину не из посадки: другого источника у него больше нет, "+
				"значит прочитано что-то, чего не существует")
		require.Zero(t, st.Used,
			"потребление ненулевое при отсутствующей строке учёта: ни одна вставка ещё "+
				"не списывала место")
		require.Equal(t, "DEFAULT", st.SourceScope,
			"область ответа обязана называть установку: величина объявлена посадкой")
		require.Empty(t, st.SourceScopeID)
	}
	require.True(t, found,
		"вида `iam.account` в ответе нет: перечень видов носителя разошёлся со словарём "+
			"посадки, и потолок стал невидим ровно тому, кто в него упрётся первым")
}
