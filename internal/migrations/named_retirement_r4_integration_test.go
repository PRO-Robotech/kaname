// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

func TestNamedRetirementMigration_NoBackfillEmptyDownAndReapply(t *testing.T) {
	db := serOpenAt(t, namedPointerProvenancePreviousVersion)
	_, err := db.Exec(`INSERT INTO kaname.fga_outbox(event_type,payload) VALUES('fga.tuple.write','{"user":"user:old","relation":"owner","object":"probemod_item:unproven-retirement","source_version":"2999-01-01T00:00:00Z"}')`)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db, ".", namedPointerProvenanceVersion))
	var receipts, facts int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_retirement`).Scan(&receipts))
	require.Zero(t, receipts)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.relation_fact WHERE object_id='unproven-retirement'`).Scan(&facts))
	require.Equal(t, 1, facts)
	require.NoError(t, goose.DownTo(db, ".", namedPointerProvenancePreviousVersion))
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, namedPointerProvenancePreviousVersion, version)
	require.NoError(t, goose.UpTo(db, ".", namedPointerProvenanceVersion))
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, namedPointerProvenanceVersion, version)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_retirement`).Scan(&receipts))
	require.Zero(t, receipts)
}

func TestNamedRetirementMigration_ReceiptOnlyHistoryRefusesDown(t *testing.T) {
	db := serOpenAt(t, namedPointerProvenanceVersion)
	_, err := db.Exec(`BEGIN; LOCK TABLE kaname.resource_registration_pointer IN ACCESS SHARE MODE; INSERT INTO kaname.resource_registration_retirement(object_type,object_id,relation,subject,delete_through) VALUES('probemod_item','receipt-only','owner','user:old','2999-01-01'); COMMIT`)
	require.NoError(t, err)
	var before string
	require.NoError(t, db.QueryRow(`SELECT pg_get_functiondef('kaname.relation_fact_fold_row(text,jsonb,timestamptz)'::regprocedure)`).Scan(&before))
	require.ErrorContains(t, goose.DownTo(db, ".", namedPointerProvenancePreviousVersion), "named registration provenance requires explicit quiescence and reconciliation")
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_retirement`).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_pointer`).Scan(&n))
	require.Zero(t, n)
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, namedPointerProvenanceVersion, version)
	var after string
	require.NoError(t, db.QueryRow(`SELECT pg_get_functiondef('kaname.relation_fact_fold_row(text,jsonb,timestamptz)'::regprocedure)`).Scan(&after))
	require.Equal(t, before, after)
}

func TestNamedRetirementMigration_ConcurrentReceiptWriterCommitOrRollback(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			db := serOpenAt(t, namedPointerProvenanceVersion)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// Текущему production emitter нужна новая producer receipt-схема.
			// Берём её настоящий Up как отдельную prerequisite, не двигая goose:
			// предмет ниже — именно старый named-pointer Down и его table lock.
			raw, err := migrations.FS.ReadFile("20261112220000_registration_producers_keep_current_receipts.sql")
			require.NoError(t, err)
			up, _, hasDown := strings.Cut(string(raw), "-- +goose Down")
			require.True(t, hasDown, "prerequisite должна содержать отделённый Down")
			_, up, hasUp := strings.Cut(up, "-- +goose Up")
			require.True(t, hasUp, "prerequisite должна содержать настоящий Up")
			prerequisite, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer prerequisite.Rollback()
			_, err = prerequisite.ExecContext(ctx, up)
			require.NoError(t, err)
			require.NoError(t, prerequisite.Commit())
			version, err := goose.GetDBVersion(db)
			require.NoError(t, err)
			require.Equal(t, namedPointerProvenanceVersion, version, "проверяемая историческая goose-граница не сдвинута")
			ready := make(chan error, 1)
			done := make(chan error, 1)
			proceed := make(chan struct{})
			defer func() {
				select {
				case <-proceed:
				default:
					close(proceed)
				}
			}()
			go func() {
				conn, err := db.Conn(ctx)
				if err != nil {
					ready <- err
					done <- err
					return
				}
				defer conn.Close()
				err = conn.Raw(func(raw any) error {
					actual, ok := raw.(*stdlib.Conn)
					if !ok {
						err := fmt.Errorf("expected pgx connection, got %T", raw)
						ready <- err
						return err
					}
					tx, err := actual.Conn().Begin(ctx)
					if err != nil {
						ready <- err
						return err
					}
					defer func() { _ = tx.Rollback(context.Background()) }()
					// Тот же фактический table order, что у invalidator/combined writer/Down.
					_, err = tx.Exec(ctx, `LOCK TABLE kaname.resource_registration_pointer IN ACCESS SHARE MODE`)
					ready <- err
					if err != nil {
						return err
					}
					select {
					case <-proceed:
					case <-ctx.Done():
						return ctx.Err()
					}
					err = kanamepg.NewFGAOutboxEmitter().EmitVersionedDeleteTx(ctx, tx, []service.VersionedRelationTuple{{Tuple: service.RelationTuple{User: "user:old", Relation: "owner", Object: "probemod_item:receipt-writer"}, SourceVersion: time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)}})
					if err != nil {
						return err
					}
					if commit {
						return tx.Commit(ctx)
					}
					return tx.Rollback(ctx)
				})
				done <- err
			}()
			require.NoError(t, <-ready)
			down := make(chan error, 1)
			go func() { down <- goose.DownToContext(ctx, db, ".", namedPointerProvenancePreviousVersion) }()
			require.Eventually(t, func() bool {
				var waiting bool
				err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='kaname.resource_registration_pointer'::regclass AND mode='AccessExclusiveLock' AND NOT granted)`).Scan(&waiting)
				return err == nil && waiting
			}, 10*time.Second, 10*time.Millisecond)
			close(proceed)
			require.NoError(t, <-done)
			downErr := <-down
			if commit {
				require.ErrorContains(t, downErr, "named registration provenance requires explicit quiescence and reconciliation")
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_retirement WHERE object_id='receipt-writer'`).Scan(&n))
				require.Equal(t, 1, n)
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='probemod_item:receipt-writer'`).Scan(&n))
				require.Equal(t, 1, n)
			} else {
				require.NoError(t, downErr)
				require.NoError(t, goose.UpToContext(ctx, db, ".", namedPointerProvenanceVersion))
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_registration_retirement`).Scan(&n))
				require.Zero(t, n)
			}
		})
	}
}
