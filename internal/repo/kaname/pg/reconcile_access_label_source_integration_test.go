// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestReconcileAccessLabelReaderUsesOwnAndMirrorColumn(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	protected := kac127SeedProject(t, r.ctx, r.admin, r.a, "alc-prot")
	ordinary := kac127SeedProject(t, r.ctx, r.admin, r.a, "alc-plain")
	seed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, seed)
	// Установочная фикстура создаёт два разных источника для чтения. Guard
	// включён до commit и до входа обычной роли БД в ReconcileAdapter.
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.projects DISABLE TRIGGER access_labels_immutable;
 ALTER TABLE kaname.projects DISABLE TRIGGER access_labels_000_commit_freshness;
 ALTER TABLE kaname.resource_mirror DISABLE TRIGGER access_labels_immutable`)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `UPDATE kaname.projects SET labels='{"team":"blue"}' WHERE id=$1`, ordinary)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `UPDATE kaname.projects SET access_labels='{"team":"blue"}' WHERE id=$1`, protected)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,labels,access_labels) VALUES
 ('compute.instance','mirror-ordinary',$1,'{"team":"blue"}','{}'),('compute.instance','mirror-protected',$1,'{}','{"team":"blue"}')`, r.a)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.projects ENABLE TRIGGER access_labels_immutable;
 ALTER TABLE kaname.projects ENABLE TRIGGER access_labels_000_commit_freshness;
 ALTER TABLE kaname.resource_mirror ENABLE TRIGGER access_labels_immutable`)
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))

	reader := kanamepg.NewReconcileAdapter(r.runtime, rolePolicyCatalog(t, r))
	require.NoError(t, reader.WithTx(r.ctx, func(ctx context.Context, store reconcile.ReconcileStore) error {
		labels := map[string]string{"team": "blue"}
		view := store.(interface {
			ReadOnlyRuleMemberStore() reconcile.ReconcileStore
		}).ReadOnlyRuleMemberStore()
		for _, candidate := range []reconcile.ReconcileStore{store, view} {
			protectedReader, ok := candidate.(interface {
				MatchAccessLabelObjects(context.Context, []string, map[string]string, bool) ([]domain.MirrorObject, error)
			})
			require.True(t, ok)
			projects, err := protectedReader.MatchAccessLabelObjects(ctx, []string{"iam.project"}, labels, true)
			require.NoError(t, err)
			require.Len(t, projects, 1)
			require.Equal(t, protected, projects[0].ObjectID)
			require.True(t, projects[0].MatchesAccessLabels(labels))
			mirrors, err := protectedReader.MatchAccessLabelObjects(ctx, []string{"compute.instance"}, labels, false)
			require.NoError(t, err)
			require.Len(t, mirrors, 1)
			require.Equal(t, "mirror-protected", mirrors[0].ObjectID)
			require.True(t, mirrors[0].MatchesAccessLabels(labels))
		}
		p, found, err := store.GetIAMDirectObject(ctx, "iam.project", protected)
		require.NoError(t, err)
		require.True(t, found)
		require.True(t, p.MatchesAccessLabels(labels))
		require.False(t, p.MatchesLabels(labels))
		ordinaryProjects, err := store.MatchIAMDirect(ctx, []string{"iam.project"}, labels)
		require.NoError(t, err)
		require.Len(t, ordinaryProjects, 1)
		require.Equal(t, ordinary, ordinaryProjects[0].ObjectID)
		return nil
	}))
}
