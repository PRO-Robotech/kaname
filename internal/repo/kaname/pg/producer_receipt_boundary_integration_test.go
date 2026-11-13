// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func receiptWaitForBlocker(t *testing.T, ctx context.Context, pool *pgxpool.Pool, blocker int) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		err := pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1`, blocker).Scan(&pid)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "должно наблюдаться ожидание конкретного blocker")
	return pid
}

func TestProducerReceiptZeroUnregisterAfterWriterFence(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	scene := registrationscene.Seed(t, ctx, pool)
	const object = "registry_registry:receipt-fence"
	var uid string
	require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, scene.Account).Scan(&uid))
	old := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: object, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain(), SourceVersion: timestamppb.New(old)}))
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer holder.Rollback(ctx)
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0))`)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		done <- uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{SubjectId: "user:" + uid, Relation: "owner", Object: object})
	}()
	waiter := receiptWaitForBlocker(t, ctx, pool, int(holder.Conn().PgConn().PID()))
	var start, version time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT xact_start FROM pg_stat_activity WHERE pid=$1`, waiter).Scan(&start))
	require.NoError(t, holder.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&version))
	require.True(t, version.After(start))
	// Это applied producer в удерживающей fence TX, после начала снимающей TX.
	applied, _, err := kanamepg.NewResourceMirrorEmitter().UpsertTx(ctx, holder, service.ResourceMirrorRow{ObjectType: "registry.registries", ObjectID: "receipt-fence", ParentProjectID: scene.Project, ParentAccountID: scene.Account, ParentChain: scene.ProjectChain(), SourceVersion: version})
	require.NoError(t, err)
	require.True(t, applied)
	r := domain.ProducerReceipt{Kind: domain.RegistrationOwnerReceipt, Module: "registry", CatalogType: "registry.registries", ObjectType: "registry_registry", ObjectID: "receipt-fence", Relation: "owner", Subject: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}, Scopes: []domain.ContainerScope{{Registered: true, ProjectID: scene.Project, AccountID: scene.Account}}, SourceVersion: version}
	emitter := kanamepg.NewFGAOutboxEmitter()
	for _, typ := range []domain.SubjectType{domain.SubjectTypeUser, domain.SubjectTypeServiceAccount} {
		r.Subject.Type = typ
		require.NoError(t, kanamepg.NewRegistrationScopeReader().SaveProducerReceiptTx(ctx, holder, r))
		require.NoError(t, emitter.EmitOrderedWriteTx(ctx, holder, []service.RelationTuple{{User: string(typ) + ":" + uid, Relation: "owner", Object: object}}, version))
	}
	require.NoError(t, holder.Commit(ctx))
	select {
	case err = <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='registry.registries' AND object_id='receipt-fence' AND source_version=$1`, version).Scan(&n))
	require.Equal(t, 1, n)
	for _, typ := range []string{"user", "service_account"} {
		var active bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT active FROM kaname.producer_source_receipt WHERE object_id='receipt-fence' AND subject_type=$1`, typ).Scan(&active))
		require.Equal(t, typ == "service_account", active)
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_registry' AND object_id='receipt-fence' AND relation='owner' AND subject=$1`, typ+":"+uid).Scan(&n))
		if typ == "user" {
			require.Zero(t, n)
		} else {
			require.Equal(t, 1, n)
		}
	}
	var hasVersion bool
	var created time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload?'source_version',created_at FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND payload->>'user'=$2 ORDER BY id DESC LIMIT 1`, object, "user:"+uid).Scan(&hasVersion, &created))
	require.False(t, hasVersion)
	require.True(t, !created.Before(version))
}

// Управляем только единственным чтением часов; UPDATE, журнал и свёртка —
// настоящие PG операции. Так equality cutoff проверяется без вероятностного sleep.
type receiptBoundaryTx struct {
	pgx.Tx
	at     time.Time
	clocks int
}

func (tx *receiptBoundaryTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if sql == `SELECT clock_timestamp()` {
		tx.clocks++
		return tx.Tx.QueryRow(ctx, `SELECT $1::timestamptz`, tx.at)
	}
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func TestProducerReceiptSharedBoundaryAndHolderProtection(t *testing.T) {
	for _, mode := range []string{"legacy", "combined_zero", "combined_ordered"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, repo := authorityTestDB(t)
			scene := registrationscene.Seed(t, ctx, pool)
			var uid string
			require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, scene.Account).Scan(&uid))
			binding := seedABForEmitted(t, ctx, repo, domain.UserID(uid), domain.AccountID(scene.Account))
			const object = "registry_registry:receipt-boundary"
			_, err := pool.Exec(ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object) VALUES($1,$2,'owner',$3)`, string(binding.ID), "user:"+uid, object)
			require.NoError(t, err)
			raw, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer raw.Rollback(ctx)
			at := time.Now().UTC().Truncate(time.Microsecond)
			tx := &receiptBoundaryTx{Tx: raw, at: at}
			store, emitter := kanamepg.NewRegistrationScopeReader(), kanamepg.NewFGAOutboxEmitter()
			subjects := []string{"user:" + uid, "service_account:" + uid, "user:unheld", "user:newer"}
			for i, subject := range subjects {
				typ, id := domain.SubjectTypeUser, uid
				if i == 1 {
					typ = domain.SubjectTypeServiceAccount
				}
				if i == 2 {
					id = "unheld"
				}
				if i == 3 {
					id = "newer"
				}
				v := at
				if i == 3 {
					v = at.Add(time.Microsecond)
				}
				r := domain.ProducerReceipt{Kind: domain.RegistrationOwnerReceipt, Module: "registry", CatalogType: "registry.registries", ObjectType: "registry_registry", ObjectID: "receipt-boundary", Relation: "owner", Subject: domain.Subject{Type: typ, ID: domain.SubjectID(id)}, Scopes: []domain.ContainerScope{{Registered: true, ProjectID: scene.Project, AccountID: scene.Account}}, SourceVersion: v}
				require.NoError(t, store.SaveProducerReceiptTx(ctx, tx, r))
				require.NoError(t, emitter.EmitOrderedWriteTx(ctx, tx, []service.RelationTuple{{User: subject, Relation: "owner", Object: object}}, v))
			}
			// Общий AB delete не вправе снимать registration provenance.
			require.NoError(t, emitter.EmitDeleteTx(ctx, tx, []service.RelationTuple{{User: subjects[0], Relation: "owner", Object: object}}))
			var stillActive bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT active FROM kaname.producer_source_receipt WHERE object_id='receipt-boundary' AND subject_type='user' AND subject_id=$1`, uid).Scan(&stillActive))
			require.True(t, stillActive)
			var beforeID int64
			require.NoError(t, raw.QueryRow(ctx, `SELECT max(id) FROM kaname.fga_outbox`).Scan(&beforeID))
			tuples := []service.RelationTuple{{User: subjects[0], Relation: "owner", Object: object}, {User: subjects[2], Relation: "owner", Object: object}, {User: subjects[3], Relation: "owner", Object: object}}
			if mode == "legacy" {
				err = emitter.EmitOrderedDeleteTx(ctx, tx, tuples, time.Time{})
			} else {
				rows := make([]service.VersionedRelationTuple, len(tuples))
				for i, tuple := range tuples {
					rows[i].Tuple = tuple
					if mode == "combined_ordered" {
						rows[i].SourceVersion = at
					}
				}
				err = emitter.EmitVersionedDeleteTx(ctx, tx, rows)
			}
			require.NoError(t, err)
			require.Equal(t, 1, tx.clocks)
			for i, subject := range subjects {
				var active bool
				typ, id := "user", uid
				if i == 1 {
					typ = "service_account"
				}
				if i == 2 {
					id = "unheld"
				}
				if i == 3 {
					id = "newer"
				}
				require.NoError(t, raw.QueryRow(ctx, `SELECT active FROM kaname.producer_source_receipt WHERE object_id='receipt-boundary' AND subject_type=$1 AND subject_id=$2`, typ, id).Scan(&active))
				require.Equal(t, i == 1 || i == 3, active)
				var fact bool
				require.NoError(t, raw.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='registry_registry' AND object_id='receipt-boundary' AND relation='owner' AND subject=$1)`, subject).Scan(&fact))
				require.Equal(t, i != 2, fact, "independent holder и более новая версия сохраняются")
			}
			var n int
			var same, versioned, protected bool
			require.NoError(t, raw.QueryRow(ctx, `SELECT count(*),bool_and(created_at=$2),bool_and(payload?'source_version'),bool_and(coalesce(payload->'protect_holders'='true'::jsonb,false)) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND id>$3`, object, at, beforeID).Scan(&n, &same, &versioned, &protected))
			require.Equal(t, 3, n)
			require.True(t, same)
			require.Equal(t, mode == "combined_ordered", versioned)
			require.Equal(t, mode != "legacy", protected)
		})
	}
}
