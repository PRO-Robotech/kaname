// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Только native reader seam. Owner seeding pending не заменяет signed writer
// acceptance и не объявляется тестом двух реплик. Требует freshness migration.
func TestNativeReadersKeepPendingFactsUnavailable(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		const reader = "user:usr-freshness-reader"
		exec(t, ctx, tx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
   VALUES('project','prj-1','v_get',$1)`, reader)
		q := relverdict.Query{Subject: reader, ObjectType: "project", ObjectID: "prj-1", Relation: "v_get"}
		check := func(want relverdict.Verdict) {
			t.Helper()
			got, _, err := relverdict.Ask(ctx, tx, q)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
		check(relverdict.Allow)
		exec(t, ctx, tx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
   VALUES('iam.project','prj-1','00000000-0000-4000-8000-000000000001','{}')`)
		exec(t, ctx, tx, `INSERT INTO kaname.authority_access_label_dirty_fact
   (root_type,root_id,generation,object_type,object_id,relation,subject)
   VALUES('iam.project','prj-1','00000000-0000-4000-8000-000000000001','project','prj-1','v_get',$1)`, reader)
		got, _, err := relverdict.Ask(ctx, tx, q)
		require.ErrorIs(t, err, relverdict.ErrAccessLabelProjectionPending)
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
		require.Equal(t, relverdict.Unknown, got)
		answers, _, err := relverdict.AskMany(ctx, tx, relverdict.QueryMany{
			Subject: reader, ObjectType: "project", ObjectIDs: []string{"missing", "prj-1"}, Relation: "v_get"})
		require.ErrorIs(t, err, relverdict.ErrAccessLabelProjectionPending)
		require.Nil(t, answers, "pending batch must not publish a successful prefix")
		ids, cursor, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: reader, ObjectType: "project", Relation: "v_get", Limit: 10})
		require.ErrorIs(t, err, relverdict.ErrAccessLabelProjectionPending)
		require.Nil(t, ids)
		require.Empty(t, cursor)
		// Курсор после всех субъектов не должен спрятать unknown за пустой страницей.
		subjects, cursor, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "project", ObjectID: "prj-1", Relation: "v_get", AfterID: "zzzz", Limit: 1})
		require.ErrorIs(t, err, relverdict.ErrAccessLabelProjectionPending)
		require.Nil(t, subjects)
		require.Empty(t, cursor)
		sources, err := relverdict.Expand(ctx, tx, "project", "prj-1", "v_get")
		require.ErrorIs(t, err, relverdict.ErrAccessLabelProjectionPending)
		require.Nil(t, sources)
		// Независимый свежий источник разрешает Check/List, pending не есть global deny.
		exec(t, ctx, tx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
   VALUES('account','acc-1','admin',$1)`, reader)
		check(relverdict.Allow)
		ids, _, err = relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: reader, ObjectType: "project", Relation: "v_get", Limit: 10})
		require.NoError(t, err)
		require.Contains(t, ids, "prj-1")
		answers, _, err = relverdict.AskMany(ctx, tx, relverdict.QueryMany{
			Subject: reader, ObjectType: "project", ObjectIDs: []string{"prj-1"}, Relation: "v_get"})
		require.NoError(t, err)
		require.Equal(t, []relverdict.Verdict{relverdict.Allow}, answers)
		exec(t, ctx, tx, `DELETE FROM kaname.relation_fact WHERE subject=$1
   AND (object_type,object_id,relation) IN (('project','prj-1','v_get'),('account','acc-1','admin'))`, reader)
		// Тестовый owner имитирует только атомарный post-retirement read state.
		exec(t, ctx, tx, `DELETE FROM kaname.authority_access_label_dirty_root
   WHERE root_type='iam.project' AND root_id='prj-1'`)
		check(relverdict.Deny)
		ids, _, err = relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: reader, ObjectType: "project", Relation: "v_get", Limit: 10})
		require.NoError(t, err)
		require.NotContains(t, ids, "prj-1")
	})
}

func TestAccessLabelFreshnessStorageAndRegrant(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		const reader = "kaname_access_label_freshness_reader"
		const getter = `SELECT kaname.authority_access_label_fact_fresh_v1('project','prj-1','v_get','user:usr-1')`
		const closure = `SELECT kaname._authority_access_label_freshness_storage_v1()
			AND kaname._authority_full_contract_storage_v3()`
		var good bool
		require.NoError(t, tx.QueryRow(ctx, closure).Scan(&good))
		require.True(t, good)
		exec(t, ctx, tx, `CREATE ROLE `+reader+` NOLOGIN NOINHERIT`)
		exec(t, ctx, tx, `GRANT USAGE ON SCHEMA kaname TO `+reader)

		withoutSelect, err := tx.Begin(ctx)
		require.NoError(t, err)
		exec(t, ctx, withoutSelect, `SET LOCAL ROLE `+reader)
		err = withoutSelect.QueryRow(ctx, getter).Scan(&good)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "42501", pgErr.Code)
		require.NoError(t, withoutSelect.Rollback(ctx))

		exec(t, ctx, tx, `SELECT kaname._authority_protocol_grant_runtime_generation1($1::regrole)`, reader)
		asReader, err := tx.Begin(ctx)
		require.NoError(t, err)
		exec(t, ctx, asReader, `SET LOCAL ROLE `+reader)
		for _, name := range []string{"authority_access_label_dirty_root", "authority_access_label_dirty_fact"} {
			require.NoError(t, asReader.QueryRow(ctx,
				`SELECT has_table_privilege(current_user,'kaname.'||$1,'SELECT, INSERT, UPDATE, DELETE')`, name).Scan(&good))
			require.False(t, good, "перевыдача runtime не открывает таблицу %s", name)
		}
		require.NoError(t, asReader.QueryRow(ctx, getter).Scan(&good))
		require.True(t, good)
		require.NoError(t, asReader.Rollback(ctx))
	})
}

func TestAccessLabelFreshnessMigrationRefusesPendingAndRestoresClosure(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	raw, err := migrations.FS.ReadFile("20261124210000_access_label_fact_freshness.sql")
	require.NoError(t, err)
	up, down, found := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, found)

	// Как у Goose, каждый DDL шаг начинает свою транзакцию до любых записей.
	_, err = pool.Exec(ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
		VALUES('iam.project','prj-1','00000000-0000-4000-8000-000000000001','{}')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, down)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "55000", pgErr.Code, pgErr.Message)
	require.ErrorContains(t, err, "pending access label freshness cannot be rolled back")

	_, err = pool.Exec(ctx, `DELETE FROM kaname.authority_access_label_dirty_root
		WHERE root_type='iam.project' AND root_id='prj-1'`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, down)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, up)
	require.NoError(t, err)
	var good bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT kaname._authority_access_label_freshness_storage_v1()
		AND kaname._authority_full_contract_storage_v3()`).Scan(&good))
	require.True(t, good)
}
