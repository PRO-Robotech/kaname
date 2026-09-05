// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// emitter_integration_test.go — integration tests for the fga_outbox emit-in-tx helper.
//
// Mirror of SubjectChangeEmitter tests. Verifies:
//
//   - EmitWriteTx INSERTs `event_type='fga.tuple.write'` rows with the
//     canonical {user,relation,object} payload, in caller-supplied tx;
//   - EmitDeleteTx mirrors with `event_type='fga.tuple.delete'`;
//   - rollback of the caller-tx removes the outbox rows (atomic emit-in-tx,
//     ban #10);
//   - len(tuples)==0 is a graceful no-op;
//   - malformed RelationTuple → error (we marshal user/relation/object, so this
//     mostly means defensive coverage).
//
// Skipped under `go test -short`.
package fga_outbox_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

func TestFGAOutboxEmitter_EmitWriteTx_AppendsRowsAtomically(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tuples := []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "viewer", Object: "project:prj_x"},
		{User: "project:prj_x", Relation: "project", Object: "iam_access_binding:acb_t"},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, tuples))
	require.NoError(t, tx.Commit(ctx))

	// Read back: expect 2 rows, event_type='fga.tuple.write', payload matches input.
	// Scope to test-created rows: exclude every migration-seeded relation-tuple —
	// the SEC-C fga_writer tuples (object `iam_fgaproxy:system`, 0009) and the
	// cluster-root seeds (object `cluster:cluster_kacho_root`: SEC-L operator
	// 0010, 5.1 reader SAs 0014).
	// Отбор ПО СВОИМ объектам, а не «всё, кроме известного посева».
	//
	// Прежняя форма перечисляла посевные объекты списком, а список стареет молча:
	// первый же новый посев (членство служебной учётки в группе) в него не попал, и
	// проба покраснела на чужой законной строке. Положительный отбор этой слепой
	// зоны не имеет by construction — фикстура знает свои объекты.
	rows, err := pool.Query(ctx, `
		SELECT event_type, payload::text
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = ANY($1::text[])
		 ORDER BY id ASC`, []string{tuples[0].Object, tuples[1].Object})
	require.NoError(t, err)
	defer rows.Close()

	var seen []struct {
		EventType string
		Payload   map[string]string
	}
	for rows.Next() {
		var et, raw string
		require.NoError(t, rows.Scan(&et, &raw))
		m := map[string]string{}
		require.NoError(t, json.Unmarshal([]byte(raw), &m))
		seen = append(seen, struct {
			EventType string
			Payload   map[string]string
		}{et, m})
	}
	require.Len(t, seen, 2)
	for i, s := range seen {
		require.Equal(t, "fga.tuple.write", s.EventType, "row %d event_type", i)
		require.Equal(t, tuples[i].User, s.Payload["user"], "row %d user", i)
		require.Equal(t, tuples[i].Relation, s.Payload["relation"], "row %d relation", i)
		require.Equal(t, tuples[i].Object, s.Payload["object"], "row %d object", i)
	}
}

func TestFGAOutboxEmitter_EmitDeleteTx_AppendsRevokeRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	tuples := []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "viewer", Object: "project:prj_x"},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, tuples))
	require.NoError(t, tx.Commit(ctx))

	var et string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = $1 LIMIT 1`, tuples[0].Object).Scan(&et))
	require.Equal(t, "fga.tuple.delete", et)
}

// TestFGAOutboxEmitter_RollbackRemovesRows — ban #10:
// rolling back the caller tx MUST also discard the outbox rows.
func TestFGAOutboxEmitter_RollbackRemovesRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&before))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: "user:usr_b", Relation: "viewer", Object: "project:prj_y"},
	}))
	require.NoError(t, tx.Rollback(ctx))

	// Считается ДЕЛЬТА, а не абсолютное число: таблицу наполняют посевные миграции,
	// и «должно быть ноль» — утверждение о них, а не об откате.
	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&after))
	require.Equal(t, before, after, "rollback must discard outbox rows (atomic emit-in-tx)")
}

func TestFGAOutboxEmitter_EmitWriteTx_EmptyTuplesIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&before))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, nil))
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{}))
	require.NoError(t, tx.Commit(ctx))

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&after))
	require.Equal(t, before, after, "empty tuples is no-op")
}

// Порядок ОДНОГО КЛЮЧА переживает переход на набор.
//
// Выдача и отзыв одного (субъект, отношение, объект) НЕ коммутативны: переставь их —
// и кортеж останется жив, то есть право не будет отозвано. Дренаж держит поголовный
// FIFO партиции по возрастанию id, поэтому всё, на чём стоит эта гарантия, — что id
// назначаются в том порядке, в каком вызывающий перечислил события. Вставка набором
// (`unnest` в FROM) обязана сохранять это дословно.
//
// Проба утверждает ИСХОД (какой id у какого события), а не «позвали ли набор», и несёт
// парный контроль: тот же набор, перечисленный в обратном порядке, обязан дать обратный
// порядок id — иначе утверждение было бы тождественно истинным на любой реализации.
func TestFGAOutboxEmitter_SetInsertPreservesPerKeyOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	key := clients.RelationTuple{User: "user:usr_order", Relation: "admin", Object: "account:acc_order"}
	other := clients.RelationTuple{User: "user:usr_order", Relation: "viewer", Object: "account:acc_order"}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	// Набор из трёх — тот же ключ едет ПЕРВЫМ, затем два соседних, чтобы «первый в
	// массиве» и «первый по id» проверялись на наборе, а не на одиночке.
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{key, other,
		{User: "user:usr_order2", Relation: "admin", Object: "account:acc_order"}}))
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, []clients.RelationTuple{key}))
	require.NoError(t, tx.Commit(ctx))

	type ev struct {
		id  int64
		typ string
	}
	// Отбор по КЛЮЧУ СТРОКИ — (субъект, объект): строка несёт набор отношений субъекта
	// на объекте, поэтому отношение в отборе не участвует (см. fga_outbox.emitTx).
	rows, err := pool.Query(ctx, `
		SELECT id, event_type FROM kacho_iam.fga_outbox
		 WHERE payload->>'user'=$1 AND payload->>'object'=$2
		 ORDER BY id ASC`, key.User, key.Object)
	require.NoError(t, err)
	defer rows.Close()
	var evs []ev
	for rows.Next() {
		var e ev
		require.NoError(t, rows.Scan(&e.id, &e.typ))
		evs = append(evs, e)
	}
	require.Len(t, evs, 2, "у ключа ровно два события: выдача и её отзыв")
	require.Equal(t, "fga.tuple.write", evs[0].typ, "выдача обязана быть первой по id")
	require.Equal(t, "fga.tuple.delete", evs[1].typ, "отзыв обязан быть строго после неё")
	require.Greater(t, evs[1].id, evs[0].id)

	// ВНУТРИ одного набора порядок обязан следовать порядку массива — на ОБОИХ уровнях,
	// потому что уровней теперь два: строки идут в порядке первого упоминания субъекта, а
	// отношения внутри строки — в порядке перечисления. Без этого утверждения проба
	// покрывала бы только соседство двух ВЫЗОВОВ и оставалась зелёной на реализации,
	// которая переставляет элементы внутри набора, — а именно перестановка внутри набора и
	// есть то, что вставка через `unnest` могла бы потерять (проверено инъекцией: без этой
	// части проба на развороте набора не краснела).
	inner, err := pool.Query(ctx, `
		SELECT payload->>'user' || '|' ||
		       coalesce((SELECT string_agg(r, '+') FROM jsonb_array_elements_text(payload->'relations') AS t(r)),
		                payload->>'relation')
		  FROM kacho_iam.fga_outbox
		 WHERE event_type='fga.tuple.write' AND payload->>'object'=$1
		 ORDER BY id ASC`, key.Object)
	require.NoError(t, err)
	defer inner.Close()
	var got []string
	for inner.Next() {
		var s string
		require.NoError(t, inner.Scan(&s))
		got = append(got, s)
	}
	require.Equal(t, []string{
		key.User + "|" + key.Relation + "+" + other.Relation,
		"user:usr_order2|admin",
	}, got, "порядок строк и порядок отношений внутри строки обязаны совпасть с порядком, в котором их перечислил вызывающий")

	// Парный контроль: обратный порядок перечисления даёт обратный порядок id.
	// Без него утверждение выше зеленело бы на реализации, которая сортирует как угодно.
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx2.Rollback(ctx) })
	rev := clients.RelationTuple{User: "user:usr_rev", Relation: "admin", Object: "account:acc_order"}
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx2, []clients.RelationTuple{rev}))
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx2, []clients.RelationTuple{rev}))
	require.NoError(t, tx2.Commit(ctx))

	rows2, err := pool.Query(ctx, `
		SELECT event_type FROM kacho_iam.fga_outbox
		 WHERE payload->>'user'=$1 AND payload->>'relation'=$2 AND payload->>'object'=$3
		 ORDER BY id ASC`, rev.User, rev.Relation, rev.Object)
	require.NoError(t, err)
	defer rows2.Close()
	var typs []string
	for rows2.Next() {
		var s string
		require.NoError(t, rows2.Scan(&s))
		typs = append(typs, s)
	}
	require.Equal(t, []string{"fga.tuple.delete", "fga.tuple.write"}, typs,
		"порядок id следует порядку вызовов, а не какой-то внутренней сортировке")
}
