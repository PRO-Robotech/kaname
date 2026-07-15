// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_cluster_scope_integration_test.go — Item #5 integration tests
// for the cluster scope on AccessBinding (Phase A: unify cluster admin into
// AccessBinding(resource_type=cluster)).
//
// Scope:
//   - Insert AccessBinding(resource_type='cluster', resource_id=ClusterSingletonID,
//     role_id=<roles/admin>) succeeds and lands in kacho_iam.access_bindings.
//   - The atomic emit-in-tx flow produces an fga_outbox row with relation
//     'system_admin' (NOT 'admin' -- cluster's direct-FGA-relation is
//     system_admin per the OpenFGA model in openfga-model-stub-configmap.yaml).
//   - Insert AccessBinding(resource_type='cluster', resource_id != ClusterSingletonID)
//     does NOT panic at the SQL layer -- the use-case layer rejects via Validate(),
//     but if a caller bypasses Validate the row CAN technically land. This test
//     documents that the SQL CHECK access_bindings_resource_ck DOES allow
//     'cluster' as resource_type (lowercase, alpha-numeric), so the singleton
//     invariant is enforced at the domain/use-case layer.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestAB_ClusterScope_InsertEmitsSystemAdminTuple — end-to-end emit-in-tx
// flow for cluster-scope AccessBinding.
//
// Production path:
//
//	w.AccessBindingsW().Insert(binding{resource_type='cluster', ...})
//	w.AccessBindingsW().EmitRelationWrite(tuples{system_admin@cluster:cluster_kacho_root})
//	w.Commit(ctx)
//
// Asserts the binding row is visible AND the fga_outbox row carries the
// canonical direct-relation 'system_admin' (the relation mapping happens in
// the use-case layer via tuplesForBinding+mapClusterRelations; this test
// exercises the repo write contract with the already-mapped tuples).
func TestAB_ClusterScope_InsertEmitsSystemAdminTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "clus-grant")

	// Look up the seeded global "admin" role id (deterministic md5-based seed).
	var roleID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM kacho_iam.roles
		 WHERE name = 'admin' AND cluster_id = 'cluster_kacho_root' AND is_system = true`).
		Scan(&roleID))

	binding := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "cluster",
		ResourceID:   domain.ClusterSingletonID,
	}
	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid),
			Relation: "system_admin",
			Object:   "cluster:" + domain.ClusterSingletonID},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, binding)
	require.NoError(t, err, "Insert AccessBinding(cluster, ...) must succeed")
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.Commit(ctx))

	// Verify binding row.
	var (
		gotResType string
		gotResID   string
	)
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT resource_type, resource_id
		  FROM kacho_iam.access_bindings WHERE id = $1`, string(binding.ID)).
		Scan(&gotResType, &gotResID))
	assert.Equal(t, "cluster", gotResType)
	assert.Equal(t, domain.ClusterSingletonID, gotResID)

	// Verify fga_outbox row.
	var et, payloadRaw string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT event_type, payload::text
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'user' = $1 AND payload->>'object' = $2
		 ORDER BY id DESC LIMIT 1`,
		"user:"+string(uid),
		"cluster:"+domain.ClusterSingletonID).Scan(&et, &payloadRaw))
	assert.Equal(t, "fga.tuple.write", et)
	var p map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &p))
	assert.Equal(t, "system_admin", p["relation"],
		"cluster-scope binding must emit system_admin tuple (NOT 'admin' -- "+
			"that's a computed relation on cluster, not directly assignable)")
}
