// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// retired_operator_identity_integration_test.go — снятая личность сетевого
// оператора отсутствует в ПРИМЕНЁННОЙ схеме, а её соседи целы.
//
// # Что здесь стояло раньше и почему снято
//
// Тот же предмет держали ПЯТЬ проб, и каждая спрашивала о СТУПЕНИ цепочки:
// посев кортежа на версии 10, посев трёх читателей на версии 14, снятие
// личности переходом 80 → 81. Они поднимали пустую базу, доигрывали до
// названной версии и шагали ровно один раз.
//
// Сведение цепочки iam в одну первичную миграцию (2026-09-04) унесло лестницу:
// у свода нет ни версии 10, ни 80 — есть одно состояние. Спрашивать у него о
// ступени нельзя не потому, что ответ изменился, а потому, что вопрос перестал
// быть задаваемым by construction.
//
// Предмет при этом ЖИВ и стал проверяться СИЛЬНЕЕ. Прежние пробы утверждали,
// что переход снял личность; здесь утверждается, что личности НЕТ — а это
// верно и тогда, когда её кто-нибудь заведёт снова, тогда как «переход её
// снимал» осталось бы верным навсегда.
//
// Решение о самой личности принял владелец 2026-08-09: рёбра сетевого
// оператора сняты, компонента с таким именем в дереве нет. Здесь проверяется
// только следствие для схемы.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// operatorSubjectSQL — детерминированный идентификатор снятой учётки, тем же
// выражением, каким его выводила снявшая миграция. Выражение сохранено
// НАМЕРЕННО: искать надо ту строку, которая появилась бы при возврате посева,
// а не имя, под которым о ней писали.
const operatorSubjectSQL = `'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17))`

// readerSvcs — модульные учётки, которым кластерный `system_viewer` принадлежит
// ЗАКОННО. Они и есть положительный контроль: без них «оператора нет» зеленело
// бы на схеме, из которой вынесли всё.
var readerSvcs = []string{"api-gateway", "vpc", "compute"}

// countSQL — одно число одним запросом. Переехал сюда вместе с предметом: его
// прежний дом (проба перехода 80 → 81) снят, а вызывающий остался один.
func countSQL(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, q, args...).Scan(&n))
	return n
}

func TestRetiredOperatorIdentityIsAbsentFromTheAppliedSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err, "соединение с применённой схемой")
	defer pool.Close()

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Отрицание без него ничего не утверждает:
	//    на пустой схеме «оператора нет» верно тождественно.
	totalSAs := countSQL(t, ctx, pool, `SELECT count(*) FROM kacho_iam.service_accounts`)
	require.NotZero(t, totalSAs,
		"служебных учёток ноль — схема не применена либо посев не отработал, и "+
			"отсутствие оператора ниже было бы отсутствием чтения, а не фактом")

	for _, svc := range readerSvcs {
		subject := `'service_account:' || ('sva' || substr(md5('kacho-` + svc + `'), 1, 17))`
		require.Equal(t, 1, countSQL(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.service_accounts
			  WHERE id = 'sva' || substr(md5('kacho-`+svc+`'), 1, 17)`),
			"учётка модуля %q обязана быть: снят ОДИН субъект, а не класс", svc)
		require.Equal(t, 1, countSQL(t, ctx, pool,
			`SELECT count(*) FROM kacho_iam.relation_fact
			  WHERE object_type = 'cluster' AND relation = 'system_viewer'
			    AND subject = `+subject),
			"модуль %q обязан держать кластерный system_viewer — он ЕГО, а не оператора", svc)
	}

	// ── СНЯТАЯ ЛИЧНОСТЬ: её нет ни как строки, ни как намерения, ни как факта.
	//    Три полосы, а не одна: строку можно снять, оставив кортеж, и наоборот —
	//    ровно так и выглядело бы неполное снятие.
	require.Zero(t, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.service_accounts
		  WHERE id = 'sva' || substr(md5('kacho-vpc-operator'), 1, 17)`),
		"учётка снятого сетевого оператора жива")
	// Судится ВЫДАЧА, а не всякое упоминание, и различие здесь несущее.
	//
	// Свод несёт очередь такой, какой её накопила цепочка, — то есть ЖУРНАЛОМ
	// намерений, а не чистым остатком. Среди них есть отзыв кортежа снятой
	// личности: его выписала миграция, снявшая учётку, и он пережил её вместе
	// со всей очередью. На свежей установке этот отзыв снимает кортеж, которого
	// никто не выдавал, — то есть он безвреден by construction (снятие
	// идемпотентно), но и бессмыслен.
	//
	// Требовать его отсутствия значило бы требовать, чтобы свод хранил ЧИСТЫЙ
	// остаток очереди вместо её журнала. Это отдельное решение с последствиями
	// для прав (пять из шести отзывов гасят более ранние выдачи того же
	// кортежа), и принимается оно не здесь. Названо, чтобы следующий не принял
	// остаток за недосмотр: см. отчёт линии сведения.
	require.Zero(t, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write' AND payload->>'user' = `+operatorSubjectSQL),
		"снятой личности ВЫДАЁТСЯ кортеж: субъекта нет, а право ему пишется")
	require.Zero(t, countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.relation_fact WHERE subject = `+operatorSubjectSQL),
		"за снятой личностью числится отношение")

	// ── НАИМЕНЬШЕЕ ПРАВО у живых читателей: только `system_viewer` на кластере
	//    и ничего сверх. Утверждение не про оператора, но снималось оно вместе
	//    с ним, и потерять его при переносе было бы тихой утратой.
	over := countSQL(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.relation_fact
		  WHERE object_type = 'cluster' AND relation <> 'system_viewer'
		    AND subject IN (`+
			`'service_account:' || ('sva' || substr(md5('kacho-api-gateway'), 1, 17)),`+
			`'service_account:' || ('sva' || substr(md5('kacho-vpc'), 1, 17)),`+
			`'service_account:' || ('sva' || substr(md5('kacho-compute'), 1, 17)))`)
	require.Zero(t, over,
		"учётке-читателю выдано на кластере отношение сверх system_viewer — "+
			"наименьшее право нарушено")

	t.Logf("осмотрено: служебных учёток %d · читателей проверено %d · "+
		"полос отсутствия снятой личности 3 (учётка · выдача · отношение); "+
		"отзывов в очереди %d, из них о снятой личности %d — журнал, а не остаток",
		totalSAs, len(readerSvcs),
		countSQL(t, ctx, pool, `SELECT count(*) FROM kacho_iam.fga_outbox WHERE event_type = 'fga.tuple.delete'`),
		countSQL(t, ctx, pool, `SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.delete' AND payload->>'user' = `+operatorSubjectSQL))
}
