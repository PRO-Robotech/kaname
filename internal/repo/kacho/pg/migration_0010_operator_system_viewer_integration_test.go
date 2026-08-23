// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0010_operator_system_viewer_integration_test.go — SEC-L.
//
// Migration 0010 seeds, via kacho_iam.fga_outbox, the operator-SA relation
// tuple `service_account:<op>#system_viewer@cluster:cluster_kacho_root` so the
// FGA-relation-driven AccountService.List / ProjectService.List return ALL
// accounts/projects to the kacho-vpc-operator ns-syncer.
//
// Asserts:
//   - the outbox row exists with exactly the SEC-L payload (relation
//     `system_viewer`, NOT `viewer`; object cluster:cluster_kacho_root; subject
//     = the deterministic operator-SA id, same expression as 0009).
//   - re-applying the migration set leaves exactly ONE such row (idempotent
//     ON CONFLICT DO NOTHING).
//   - the down migration removes it.
//   - 0009's fga_writer tuples are untouched (ban #5 — 0009 not edited).

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// operatorSysViewerSQL — the exact subject expression mirrored from 0009/0010
// so the test pins the deterministic operator-SA id.
const operatorSysViewerSubjectSQL = `'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17))`

// TestMigration0010_SECL_SeedsOperatorSystemViewerTuple меряет посев 0010 НА ЕГО
// СОБСТВЕННОЙ версии.
//
// Прежняя редакция звала setupTestDB и читала состояние ГОЛОВЫ, а комментарий
// рядом утверждал «applies migrations 0001..0010» — проба называла один предмет
// и измеряла другой, и это было незаметно ровно до того дня, когда голова
// разошлась с версией 10. Разошлась она миграцией 0081, снявшей учётку
// оператора вместе с этим кортежем. Про сам посев 0010 утверждение осталось
// верным — но спрашивать о нём надо у версии 10.
func TestMigration0010_SECL_SeedsOperatorSystemViewerTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, _, _ := startPostgresUpTo(t, 10)

	// Exactly one outbox row with the SEC-L operator system_viewer tuple.
	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write'
		    AND payload->>'relation' = 'system_viewer'
		    AND payload->>'object'   = 'cluster:cluster_kacho_root'
		    AND payload->>'user'     = `+operatorSysViewerSubjectSQL).Scan(&cnt))
	require.Equal(t, 1, cnt,
		"migration 0010 must seed exactly one operator system_viewer@cluster tuple")

	// It must be `system_viewer`, never `viewer` (INV-6 over-exposure fix).
	var relCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = 'cluster:cluster_kacho_root'
		    AND payload->>'user'   = `+operatorSysViewerSubjectSQL+`
		    AND payload->>'relation' = 'viewer'`).Scan(&relCnt))
	require.Equal(t, 0, relCnt,
		"operator must be seeded system_viewer (NON-wildcard), never viewer (INV-6)")
}

// TestMigration0010_SECL_Idempotent_DownReverts гоняет цикл goose НА ГОЛОВЕ:
// откат 0010 обязан снять свой посев, не тронув кортежи 0009 (ban #5).
//
// Счётчик РАЗЛИЧАЕТ событие. Прежняя редакция считала строки только по
// отношению/объекту/субъекту — и после того как 0081 сняла у оператора выдачу и
// поставила в очередь ОТЗЫВ того же кортежа, «одна строка» продолжала сходиться,
// но означала уже противоположное: не выдачу, а её снятие. Утверждение, которое
// одинаково зеленеет на выдаче и на отзыве, о выдаче не говорит ничего.
func TestMigration0010_SECL_Idempotent_DownReverts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // голова
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	countOf := func(eventType string) int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.fga_outbox
			  WHERE event_type = $1
			    AND payload->>'relation' = 'system_viewer'
			    AND payload->>'object'   = 'cluster:cluster_kacho_root'
			    AND payload->>'user'     = `+operatorSysViewerSubjectSQL, eventType).Scan(&c))
		return c
	}
	// Считаются РАЗНЫЕ СУБЪЕКТЫ намерения ВЫДАЧИ, а не строки журнала.
	//
	// Утверждение здесь одно: посев 0009/0044/0057 никакой поздней миграцией не
	// отредактирован (ban #5). Журнал при этом append-only, и по одному ключу
	// кортежа в нём законно лежит НЕСКОЛЬКО строк: выдача, отзыв, восстановление
	// на откате. Счёт строк без события смешал бы их в одно число — тот же
	// промах, который соседнее утверждение об операторе уже называет вслух
	// («счёт без event_type не отличил бы одно от другого»), — и покраснел бы от
	// переезда права на кластер (#914), к посеву 0009 отношения не имеющего.
	fgaWriterCount := func() int {
		var c int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(DISTINCT payload->>'user') FROM kacho_iam.fga_outbox
			  WHERE event_type = 'fga.tuple.write'
			    AND payload->>'relation' = 'fga_writer'
			    AND payload->>'object'   = 'iam_fgaproxy:system'`).Scan(&c))
		return c
	}

	// На голове выдачи у оператора НЕТ, а отзыв поставлен в очередь — 0081.
	require.Equal(t, 0, countOf("fga.tuple.write"),
		"на голове у оператора не должно остаться намерения ВЫДАЧИ: 0081 сняла его учётку")
	require.Equal(t, 1, countOf("fga.tuple.delete"),
		"на голове у оператора обязан стоять ОТЗЫВ кортежа: удаление строки посева стёрло бы "+
			"запись о намерении, а не сам кортеж в хранилище отношений")
	require.Equal(t, 5, fgaWriterCount(),
		"at HEAD: 0009 seeds 3 fga_writer tuples (vpc/compute/nlb) + 0044 registry-SA + 0057 storage-SA tuples")

	// Прогон раннера на голове ничего не применяет — проверяем, что он и не
	// добавляет строк.
	require.NoError(t, goose.Up(db, "."))
	require.Equal(t, 0, countOf("fga.tuple.write"), "повтор раннера воскресил выдачу")
	require.Equal(t, 1, countOf("fga.tuple.delete"), "повтор раннера задвоил отзыв")

	// Down to version 9 → reverts every migration stacked at/above 0010 (0010
	// itself, plus any later migration that seeds onto the same fga_outbox, e.g.
	// 5.1's 0014). DownTo(9) is robust to head drift: a single goose.Down would
	// only revert the current HEAD (no longer 0010 once newer migrations land),
	// so it could not assert 0010's own down. Собственный откат 0010 снимает СВОЙ
	// субъект по отношению и объекту, не разбирая события, — поэтому после него
	// у оператора не остаётся ни выдачи, ни отзыва; кортежи fga_writer из 0009
	// (версия 9, пол отката) остаются.
	require.NoError(t, goose.DownTo(db, ".", 9))
	require.Equal(t, 0, countOf("fga.tuple.write"), "down 0010 must remove the operator system_viewer tuple")
	require.Equal(t, 0, countOf("fga.tuple.delete"),
		"откат 0010 снимает свой субъект целиком — отзыв, поставленный 0081, уходит вместе с ним")
	require.Equal(t, 3, fgaWriterCount(),
		"0009 fga_writer tuples must remain untouched after 0010 down (ban #5)")
}
