// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// f8_target_test.go — redesign-2026 F8 (IAM-1-21/22/23): AccessBinding.target is
// REINTRODUCED as a REQUIRED first-class oneof {resources[] ResourceRef |
// allInScope{}} (least-privilege spine). ResourceRef is the closed-table {type,id}
// (no name); the type is validated against the closed dotted type-registry.
//
// Pure parse-path + domain unit tests (no Docker).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// IAM-1-22: Create WITHOUT target → sync INVALID_ARGUMENT, first statement,
// actionable text (least-privilege by default; broadest grant only via explicit
// allInScope{} opt-in).
func TestAB_IAM_1_22_TargetRequired(t *testing.T) {
	_, err := targetFromProto(nil)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "target is required")
	assert.Contains(t, st.Message(), "allInScope")
}

// IAM-1-21: allInScope{} maps to the whole-anchor grant.
func TestAB_IAM_1_21_TargetAllInScope(t *testing.T) {
	tgt, err := targetFromProto(&iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}},
	})
	require.NoError(t, err)
	assert.True(t, tgt.AllInScope)
	assert.Empty(t, tgt.Resources)
	assert.Equal(t, "all", tgt.Digest())
}

// IAM-1-21: per-object resources map to domain ResourceRefs.
func TestAB_IAM_1_21_TargetResources(t *testing.T) {
	tgt, err := targetFromProto(&iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
			Resources: []*iamv1.ResourceRef{
				{Type: "compute.instance", Id: "ins-abc"},
			},
		}},
	})
	require.NoError(t, err)
	assert.False(t, tgt.AllInScope)
	require.Len(t, tgt.Resources, 1)
	assert.Equal(t, "compute.instance", tgt.Resources[0].Type)
	assert.Equal(t, "ins-abc", tgt.Resources[0].ID)
}

// IAM-1-23: ResourceRef is a closed table — unknown type → sync INVALID_ARGUMENT.
func TestAB_IAM_1_23_UnknownTargetType(t *testing.T) {
	_, err := targetFromProto(&iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
			Resources: []*iamv1.ResourceRef{{Type: "unknown.thing", Id: "x"}},
		}},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "target.resources[].type")
}

// domain closed type-registry: dotted <module>.<resource> resolved against the
// existing bare vocabulary.
func TestAB_IAM_1_23_ValidTargetType(t *testing.T) {
	for _, ok := range []string{"compute.instance", "vpc.network", "vpc.route_table", "iam.account"} {
		assert.True(t, domain.ValidTargetType(ok), ok)
	}
	for _, bad := range []string{"unknown.thing", "compute", "", ".instance", "compute."} {
		assert.False(t, domain.ValidTargetType(bad), bad)
	}
}

// IAM-1-21 (output): the dto projects a per-object target back as resources[]
// ResourceRef{type,id}; a whole-anchor / empty target projects as allInScope.
func TestAB_IAM_1_21_DtoEmitsTarget(t *testing.T) {
	// per-object.
	pb, err := abToPb(domain.AccessBinding{
		ID: "acb-x", SubjectType: "user", SubjectID: "usr-1", RoleID: "rol-r",
		ResourceType: "account", ResourceID: "acc-A", Scope: domain.ScopeAccount,
		Status: domain.AccessBindingStatusActive,
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-abc"}}},
	})
	require.NoError(t, err)
	refs := pb.GetTarget().GetResources().GetResources()
	require.Len(t, refs, 1)
	assert.Equal(t, "compute.instance", refs[0].GetType())
	assert.Equal(t, "ins-abc", refs[0].GetId())
	assert.Nil(t, pb.GetTarget().GetAllInScope())

	// whole-anchor / empty → allInScope projection.
	pb2, err := abToPb(domain.AccessBinding{
		ID: "acb-y", SubjectType: "user", SubjectID: "usr-1", RoleID: "rol-r",
		ResourceType: "account", ResourceID: "acc-A", Scope: domain.ScopeAccount,
		Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	assert.NotNil(t, pb2.GetTarget().GetAllInScope())
	assert.Empty(t, pb2.GetTarget().GetResources().GetResources())
}

// Digest is order-independent over the resource set (set-based canonicalization —
// the same set in a different order collides on the active-grant UNIQUE).
func TestAB_IAM_1_29_TargetDigestOrderIndependent(t *testing.T) {
	a := domain.AccessTarget{Resources: []domain.ResourceRef{
		{Type: "compute.instance", ID: "ins-1"},
		{Type: "compute.disk", ID: "dsk-9"},
	}}
	b := domain.AccessTarget{Resources: []domain.ResourceRef{
		{Type: "compute.disk", ID: "dsk-9"},
		{Type: "compute.instance", ID: "ins-1"},
	}}
	assert.Equal(t, a.Digest(), b.Digest(), "same set, different order → same digest")

	c := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-2"}}}
	assert.NotEqual(t, a.Digest(), c.Digest(), "different set → different digest")
	assert.NotEqual(t, "all", a.Digest())
}
