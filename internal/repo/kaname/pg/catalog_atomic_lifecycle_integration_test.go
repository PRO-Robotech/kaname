// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func catalogAtomicManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(`apiVersion: iam/v1
module: probemod
resources:
  - name: catalogAtomicOne
    objectType: probemod_catalog_atomic_one
    parents: [project]
    producer: derived
    verbs: [get, list, update]
  - name: catalogAtomicTwo
    objectType: probemod_catalog_atomic_two
    parents: [project]
    producer: derived
    verbs: [get, list, delete]
`))
	require.NoError(t, err)
	return m
}
func catalogAtomicBundle(t *testing.T, r protocolRig, m *manifest.Manifest) *granteffect.Bundle {
	t.Helper()
	model, report, err := modelcompose.Compose(r.bundle.ModelSource(), []*manifest.Manifest{m})
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(r.ctx, model, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	return bundle
}
func catalogIdentityPhase(t *testing.T, r protocolRig) string {
	t.Helper()
	var phase string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase))
	return phase
}

// Reproduces the former common prepared-generation1 fixture boundary. ApplyAll
// here has ONE manifest, whose real applier issues multiple catalog DMLs.
func TestCatalogPreparedGenerationOneChangesWholeManifestBeforeClose(t *testing.T) {
	r := writerProtocolRig(t)
	require.Equal(t, "prepared", catalogIdentityPhase(t, r))
	before := stateFingerprint(t, r.ctx, r.admin)
	m := catalogAtomicManifest(t)
	census, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(r.runtime)).ApplyAll(r.ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	require.Equal(t, 1, census.Applied)
	// RowsOf includes the non-object create tier in addition to each resource's
	// three declared object verbs. Compare the entire canonical multiset.
	require.ElementsMatch(t, []string{
		"r:catalogAtomicOne",
		"r:catalogAtomicTwo",
		"v:catalogAtomicOne.create:false",
		"v:catalogAtomicOne.get:true",
		"v:catalogAtomicOne.list:true",
		"v:catalogAtomicOne.update:true",
		"v:catalogAtomicTwo.create:false",
		"v:catalogAtomicTwo.delete:true",
		"v:catalogAtomicTwo.get:true",
		"v:catalogAtomicTwo.list:true",
	}, moduleCensus(t, r.ctx, r.admin, m.Module), "both resources and every declared/tier verb must commit together")
	require.NotEqual(t, before, stateFingerprint(t, r.ctx, r.admin))
	require.Equal(t, "transition", catalogIdentityPhase(t, r))
	old, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.Error(t, err)
	require.Nil(t, old)
	// Prepared generation1 is preserved; only owner restages its new exact bundle.
	next := catalogAtomicBundle(t, r, m)
	require.NoError(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, next))
	require.Equal(t, "prepared", catalogIdentityPhase(t, r))
	var generation int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT required_contract FROM kaname.authority_writer_contract WHERE singleton`).Scan(&generation))
	require.Equal(t, 1, generation)
}

func TestCatalogCommitClosesBeforeQueuedOrdinaryWriterAndRollbackPreservesProfile(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[commit], func(t *testing.T) {
			r := writerProtocolRig(t)
			repo, contract := fullContractActivate(t, r)
			catalog, err := kanamepg.NewCatalogWriteRepo(r.runtime).WithFullWriterContract(contract)
			require.NoError(t, err)
			before := stateFingerprint(t, r.ctx, r.admin)
			held, release := make(chan struct{}), make(chan struct{})
			releaseOnce := false
			defer func() {
				if !releaseOnce {
					close(release)
				}
			}()
			rejected := errors.New("catalog body rollback")
			changed := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
				return catalog.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
					if _, e := w.UpsertModule(ctx, "atomicfirst"); e != nil {
						return e
					}
					if _, e := w.UpsertModule(ctx, "atomicsecond"); e != nil {
						return e
					}
					close(held)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					if !commit {
						return rejected
					}
					return nil
				})
			})
			select {
			case <-held:
			case <-time.After(10 * time.Second):
				t.Fatal("multi-row catalog body did not reach held TX")
			}
			require.Equal(t, "active", catalogIdentityPhase(t, r), "uncommitted catalog cannot publish transition")
			var blocker int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.usename=$1 AND l.locktype='advisory' AND l.classid=1262569283::oid AND l.objid=0::oid AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted`, r.role).Scan(&blocker))
			queued := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
				w, e := repo.ParticipantAuthorityWriter(ctx, r.intent(r.a))
				if w != nil {
					_ = w.Rollback(context.WithoutCancel(ctx))
				}
				return e
			})
			receiptWaitForBlocker(t, r.ctx, r.admin, blocker)
			close(release)
			releaseOnce = true
			catalogErr := lifecycleResult(t, r.ctx, changed)
			queuedErr := lifecycleResult(t, r.ctx, queued)
			if commit {
				require.NoError(t, catalogErr)
				var pge *pgconn.PgError
				require.ErrorAs(t, queuedErr, &pge)
				require.Equal(t, "P1036", pge.Code)
				require.Equal(t, "transition", catalogIdentityPhase(t, r))
				require.NotEqual(t, before, stateFingerprint(t, r.ctx, r.admin))
			} else {
				require.ErrorIs(t, catalogErr, rejected)
				require.NoError(t, queuedErr)
				require.Equal(t, "active", catalogIdentityPhase(t, r))
				require.Equal(t, before, stateFingerprint(t, r.ctx, r.admin))
				called := false
				require.NoError(t, catalog.RunInWriteTx(r.ctx, func(context.Context, modulecatalog.CatalogWriter) error { called = true; return nil }))
				require.True(t, called, "old retained profile remains usable after rollback")
			}
		})
	}
}

// Every adversarial change is inside an owner TX and rolled back. The real
// readiness function must see its own altered graph and refuse it.
func TestCatalogCommitReadinessPinsPrivateFunctionAndActualDeferredGraph(t *testing.T) {
	r := writerProtocolRig(t)
	full, _ := fullContractActivate(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	var executable bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT has_function_privilege($1,'kaname._authority_protocol_catalog_changed_v3()','EXECUTE')`, r.role).Scan(&executable))
	require.False(t, executable)
	for _, sql := range []string{
		`ALTER TABLE kaname.catalog_resource DISABLE TRIGGER authority_catalog_changed`,
		`DROP TRIGGER authority_catalog_changed ON kaname.catalog_resource; CREATE CONSTRAINT TRIGGER authority_catalog_changed AFTER INSERT OR UPDATE OR DELETE ON kaname.catalog_resource DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION kaname._authority_protocol_catalog_changed_v3()`,
		`CREATE OR REPLACE FUNCTION kaname._authority_protocol_catalog_changed_v3() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'BEGIN RETURN NULL; END;'`,
		`GRANT EXECUTE ON FUNCTION kaname._authority_protocol_catalog_changed_v3() TO ` + pgx.Identifier{r.role}.Sanitize(),
		`ALTER TABLE kaname.catalog_verb DISABLE TRIGGER authority_catalog_truncated`,
	} {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, sql)
		require.NoError(t, err)
		var ready bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
		require.False(t, ready)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

func TestCatalogCommitMigrationDownRefusesActivatedFullGeneration(t *testing.T) {
	r := writerProtocolRig(t)
	full, _ := fullContractActivate(t, r)
	before := stateFingerprint(t, r.ctx, r.admin)
	source, err := migrations.FS.ReadFile("20261115110000_catalog_identity_closes_at_transaction_commit.sql")
	require.NoError(t, err)
	_, down, found := strings.Cut(string(source), "-- +goose Down")
	require.True(t, found)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, down)
	var pge *pgconn.PgError
	require.ErrorAs(t, err, &pge)
	require.Equal(t, "P1036", pge.Code)
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	require.Equal(t, "active", catalogIdentityPhase(t, r))
	require.Equal(t, before, stateFingerprint(t, r.ctx, r.admin))
}
