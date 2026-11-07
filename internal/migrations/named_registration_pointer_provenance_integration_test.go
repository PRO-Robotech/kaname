// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

const namedPointerProvenanceVersion int64 = 20261104190000

func TestNamedPointerProvenance_DowngradeRefusesHistory(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired-history", true: "live-holder"}[active], func(t *testing.T) {
			db := serOpenAt(t, namedPointerProvenanceVersion)
			_, err := db.Exec(`INSERT INTO kaname.resource_registration_pointer(module,object_type,object_id,relation,subject,source_version,active) VALUES('probemod','probemod_item','i1','box','probemod_box:b1','2000-01-01', $1)`, active)
			require.NoError(t, err)
			err = goose.DownTo(db, ".", namedPointerProvenanceVersion-1)
			require.ErrorContains(t, err, "named registration provenance requires explicit quiescence and reconciliation")
			version, err := goose.GetDBVersion(db)
			require.NoError(t, err)
			require.Equal(t, namedPointerProvenanceVersion, version)
			var n int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_pointer`).Scan(&n))
			require.Equal(t, 1, n, "отказ не теряет даже неактивную историю")
		})
	}
}

func TestNamedPointerProvenance_EmptyDowngradeAndReapply(t *testing.T) {
	db := serOpenAt(t, namedPointerProvenanceVersion-1)
	_, err := db.Exec(`INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write','{"user":"probemod_box:b1","relation":"box","object":"probemod_item:unproven"}'::jsonb)`)
	require.NoError(t, err, "стоящий tuple сам по себе не является registrar provenance")
	require.NoError(t, goose.UpTo(db, ".", namedPointerProvenanceVersion))
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_pointer`).Scan(&n))
	require.Zero(t, n, "накат не присваивает standing facts из прежней схемы")
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_item' AND object_id='unproven' AND relation='box'`).Scan(&n))
	require.Equal(t, 1, n, "неподтверждённый факт не присваивается и не удаляется накатом")
	require.NoError(t, goose.DownTo(db, ".", namedPointerProvenanceVersion-1))
	require.NoError(t, goose.UpTo(db, ".", namedPointerProvenanceVersion))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_pointer`).Scan(&n))
	require.Zero(t, n)
}

func TestNamedPointerProvenance_ConcurrentWriterCommitOrRollbackBeforeDown(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer-rollback", true: "writer-commit"}[commit], func(t *testing.T) {
			db := serOpenAt(t, namedPointerProvenanceVersion)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var originalFunction string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_functiondef('kaname.relation_fact_fold_row(text,jsonb,timestamptz)'::regprocedure)`).Scan(&originalFunction))
			writerReady := make(chan error, 1)
			writerDone := make(chan error, 1)
			proceed := make(chan struct{})
			tuple := service.RelationTuple{User: "probemod_box:b1", Relation: "box", Object: "probemod_item:concurrent-down"}
			// Raw ограничен жизнью выделенного database/sql Conn. Настоящий PG adapter
			// получает настоящую pgx TX; она не покидает callback до commit/rollback.
			go func() {
				conn, err := db.Conn(ctx)
				if err != nil {
					writerReady <- err
					writerDone <- err
					return
				}
				defer conn.Close()
				err = conn.Raw(func(raw any) error {
					actual, ok := raw.(*stdlib.Conn)
					if !ok {
						err := fmt.Errorf("expected pgx stdlib connection, got %T", raw)
						writerReady <- err
						return err
					}
					tx, err := actual.Conn().Begin(ctx)
					if err != nil {
						writerReady <- err
						return err
					}
					defer func() { _ = tx.Rollback(context.Background()) }()
					_, err = tx.Exec(ctx, `LOCK TABLE kaname.resource_registration_pointer IN ROW EXCLUSIVE MODE`)
					writerReady <- err
					if err != nil {
						return err
					}
					select {
					case <-proceed:
					case <-ctx.Done():
						return ctx.Err()
					}
					applied, err := kanamepg.NewRegistrationScopeReader().SaveRegistrationPointerTx(ctx, tx, "probemod", tuple, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
					if err != nil {
						return err
					}
					if !applied {
						return fmt.Errorf("fresh claim was not applied")
					}
					if err := kanamepg.NewFGAOutboxEmitter().EmitOrderedWriteTx(ctx, tx, []service.RelationTuple{tuple}, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
						return err
					}
					if commit {
						return tx.Commit(ctx)
					}
					return tx.Rollback(ctx)
				})
				writerDone <- err
			}()
			require.NoError(t, <-writerReady)
			downDone := make(chan error, 1)
			go func() { downDone <- goose.DownToContext(ctx, db, ".", namedPointerProvenanceVersion-1) }()
			require.Eventually(t, func() bool {
				var blocked bool
				err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='kaname.resource_registration_pointer'::regclass AND mode='AccessExclusiveLock' AND NOT granted)`).Scan(&blocked)
				return err == nil && blocked
			}, 10*time.Second, 10*time.Millisecond, "настоящий Down ждёт незавершённого writer")
			close(proceed)
			require.NoError(t, <-writerDone)
			downErr := <-downDone
			if commit {
				require.ErrorContains(t, downErr, "named registration provenance requires explicit quiescence and reconciliation")
				version, err := goose.GetDBVersion(db)
				require.NoError(t, err)
				require.Equal(t, namedPointerProvenanceVersion, version)
				var claims, facts, journal int
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.resource_registration_pointer WHERE module='probemod' AND object_type='probemod_item' AND object_id='concurrent-down' AND relation='box' AND subject='probemod_box:b1' AND active`).Scan(&claims))
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_item' AND object_id='concurrent-down' AND relation='box' AND subject='probemod_box:b1'`).Scan(&facts))
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='probemod_item:concurrent-down' AND event_type='fga.tuple.write'`).Scan(&journal))
				require.Equal(t, 1, claims)
				require.Equal(t, 1, facts)
				require.Equal(t, 1, journal)
				var after string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_functiondef('kaname.relation_fact_fold_row(text,jsonb,timestamptz)'::regprocedure)`).Scan(&after))
				require.Equal(t, originalFunction, after, "отказ откатывает замену свёртки вместе с migration version")
			} else {
				require.NoError(t, downErr)
				var absent bool
				require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('kaname.resource_registration_pointer') IS NULL`).Scan(&absent))
				require.True(t, absent)
				require.NoError(t, goose.UpToContext(ctx, db, ".", namedPointerProvenanceVersion))
				var n int
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.resource_registration_pointer`).Scan(&n))
				require.Zero(t, n)
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_item' AND object_id='concurrent-down'`).Scan(&n))
				require.Zero(t, n)
				var after string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_functiondef('kaname.relation_fact_fold_row(text,jsonb,timestamptz)'::regprocedure)`).Scan(&after))
				require.Equal(t, originalFunction, after)
			}
		})
	}
}
