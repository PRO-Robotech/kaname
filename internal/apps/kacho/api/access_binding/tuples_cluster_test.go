// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// tuples_cluster_test.go — unit tests for the cluster-scope relation mapping
// added in Item #5 (unify cluster admin into AccessBinding).
//
// Scope:
//   - mapClusterRelations({admin}) → {system_admin}
//   - mapClusterRelations({editor}) → {system_admin}   (cluster editor == system_admin)
//   - mapClusterRelations({viewer}) → {system_viewer}
//   - mapClusterRelations({admin, viewer}) → {system_admin, system_viewer}
//   - tuplesForBinding for resource_type=cluster emits the canonical
//     direct relation, NOT the computed-relation alias.
//
// These tests are pure-Go (no testcontainers) — they exercise the tuple
// builder in isolation against in-memory inputs.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

func TestMapClusterRelations_AdminToSystemAdmin(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"admin"})
	assert.Equal(t, []authzmap.Relation{"system_admin"}, got)
}

func TestMapClusterRelations_EditorToSystemAdmin(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"editor"})
	assert.Equal(t, []authzmap.Relation{"system_admin"}, got,
		"cluster editor tier == system_admin (no separate editor direct relation)")
}

func TestMapClusterRelations_ViewerToSystemViewer(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"viewer"})
	assert.Equal(t, []authzmap.Relation{"system_viewer"}, got)
}

func TestMapClusterRelations_AdminAndViewerDedupAndKeepBoth(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"admin", "viewer"})
	// admin+viewer → system_admin + system_viewer. Order preserved
	// (sort just for deterministic compare).
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	assert.Equal(t, []authzmap.Relation{"system_admin", "system_viewer"}, got)
}

func TestMapClusterRelations_AdminEditorDedupToOne(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"admin", "editor"})
	assert.Equal(t, []authzmap.Relation{"system_admin"}, got,
		"admin AND editor both map to system_admin — must dedup to a single tuple")
}

func TestMapClusterRelations_UnknownPassesThrough(t *testing.T) {
	got := mapClusterRelations([]authzmap.Relation{"billing_admin"})
	assert.Equal(t, []authzmap.Relation{"billing_admin"}, got)
}

func TestTuplesForBinding_ClusterScope_EmitsSystemAdmin(t *testing.T) {
	b := domain.AccessBinding{
		ID:           "abc_test_binding00000",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_test_subject0001",
		ResourceType: "cluster",
		ResourceID:   domain.ClusterSingletonID,
	}
	got := tuplesForBinding(b, []authzmap.Relation{"admin"})
	// With a binding ID present, cluster scope emits the direct-relation tuple
	// PLUS the `cluster`-parent hierarchy tuple (cascade readability).
	require.Len(t, got, 2,
		"cluster scope (with id) → direct-relation tuple + cluster-parent hierarchy tuple")
	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "user:usr_test_subject0001",
		Relation: "system_admin",
		Object:   "cluster:" + domain.ClusterSingletonID,
	}, "admin on cluster → system_admin direct-relation tuple (NOT 'admin' — that's computed)")
	assert.Contains(t, got, abrepo.RelationTuple{
		User:     "cluster:" + domain.ClusterSingletonID,
		Relation: "cluster",
		Object:   "iam_access_binding:abc_test_binding00000",
	}, "cluster-scoped binding must emit the cluster-parent hierarchy tuple")
}

func TestTuplesForBinding_ClusterScope_ServiceAccountSubject(t *testing.T) {
	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeServiceAccount,
		SubjectID:    "sva_test_sa00000001",
		ResourceType: "cluster",
		ResourceID:   domain.ClusterSingletonID,
	}
	got := tuplesForBinding(b, []authzmap.Relation{"admin"})
	require.Len(t, got, 1)
	assert.Equal(t, "service_account:sva_test_sa00000001", got[0].User)
	assert.Equal(t, "system_admin", got[0].Relation)
}

func TestTuplesForBinding_ClusterScope_ViewerEmitsSystemViewer(t *testing.T) {
	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_test_viewer0001",
		ResourceType: "cluster",
		ResourceID:   domain.ClusterSingletonID,
	}
	got := tuplesForBinding(b, []authzmap.Relation{"viewer"})
	require.Len(t, got, 1)
	assert.Equal(t, "system_viewer", got[0].Relation,
		"viewer on cluster → system_viewer tuple")
}

func TestTuplesForBinding_NonCluster_UnchangedRelation(t *testing.T) {
	// Regression: account-scope must still emit "admin"/"viewer" verbatim
	// (the mapping is cluster-scope only).
	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_test_sub00000001",
		ResourceType: "account",
		ResourceID:   "acc_test_account001",
	}
	got := tuplesForBinding(b, []authzmap.Relation{"admin"})
	require.Len(t, got, 1)
	assert.Equal(t, "admin", got[0].Relation,
		"account scope must NOT remap admin→system_admin")
	assert.Equal(t, "account:acc_test_account001", got[0].Object)
}
