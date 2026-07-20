// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// f7_scope_anchor_test.go — redesign-2026 F7 (IAM-1-18/19/20): the AccessBinding
// scope-anchor is renamed resource_type/resource_id → scopeType/scopeId, with the
// word "resource" freed for the reintroduced `target` (F8). The WIRE form is dotted
// (iam.cluster | iam.account | iam.project); the DB column / domain field stay bare
// (account | project | cluster) as a within-service implementation detail, mapped at
// the API boundary (Clean-Architecture translation). Pre-Phase-0 the scopeType is
// REQUIRED on input (prefix-derivation is B3-gated).
//
// Pure parse-path + dto + update-mask unit tests (no Docker).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// IAM-1-18 (input): dotted scopeType is normalized to the bare within-service
// anchor kind; the empty / unknown / non-dotted-bare forms are rejected sync.
func TestAB_IAM_1_18_ScopeTypeToBare(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantBare string
		wantCode codes.Code
		wantMsg  string
	}{
		{name: "iam.project → project", in: "iam.project", wantBare: "project", wantCode: codes.OK},
		{name: "iam.account → account", in: "iam.account", wantBare: "account", wantCode: codes.OK},
		{name: "iam.cluster → cluster", in: "iam.cluster", wantBare: "cluster", wantCode: codes.OK},
		{name: "empty → required (pre-Phase-0 explicit)", in: "", wantCode: codes.InvalidArgument, wantMsg: "scopeType is required"},
		{name: "unknown dotted → invalid", in: "iam.folder", wantCode: codes.InvalidArgument, wantMsg: "Illegal argument scopeType"},
		{name: "bare (non-dotted) rejected", in: "account", wantCode: codes.InvalidArgument, wantMsg: "Illegal argument scopeType"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scopeTypeToBare(tc.in)
			if tc.wantCode == codes.OK {
				require.NoError(t, err)
				assert.Equal(t, tc.wantBare, got)
				return
			}
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tc.wantCode, st.Code())
			assert.Contains(t, st.Message(), tc.wantMsg)
		})
	}
}

// IAM-1-18 (output): the domain→proto transfer emits the dotted scopeType/scopeId
// as the SOLE scope projection — no legacy resource-named fields on the wire.
func TestAB_IAM_1_18_DtoEmitsDottedScope(t *testing.T) {
	b := domain.AccessBinding{
		ID:           "acb-x",
		SubjectType:  "user",
		SubjectID:    "usr-1",
		RoleID:       "rol-editor",
		ResourceType: "account",
		ResourceID:   "acc-A",
		Scope:        domain.ScopeAccount,
		Status:       domain.AccessBindingStatusActive,
	}
	pb, err := abToPb(b)
	require.NoError(t, err)
	assert.Equal(t, "iam.account", pb.GetScopeType())
	assert.Equal(t, "acc-A", pb.GetScopeId())
}

// IAM-1-18: cluster/project round-trip on the dotted projection.
func TestAB_IAM_1_18_DtoDottedProjection_AllTiers(t *testing.T) {
	tiers := []struct {
		bare       string
		scope      domain.Scope
		rid        string
		wantDotted string
	}{
		{"cluster", domain.ScopeCluster, domain.ClusterSingletonID, "iam.cluster"},
		{"account", domain.ScopeAccount, "acc-A", "iam.account"},
		{"project", domain.ScopeProject, "prj-P", "iam.project"},
	}
	for _, tt := range tiers {
		b := domain.AccessBinding{
			ID: "acb-x", SubjectType: "user", SubjectID: "usr-1", RoleID: "rol-r",
			ResourceType: domain.ResourceType(tt.bare), ResourceID: tt.rid,
			Scope: tt.scope, Status: domain.AccessBindingStatusActive,
		}
		pb, err := abToPb(b)
		require.NoError(t, err)
		assert.Equal(t, tt.wantDotted, pb.GetScopeType(), tt.bare)
		assert.Equal(t, tt.rid, pb.GetScopeId(), tt.bare)
	}
}

// IAM-1-19: scopeType/scopeId are immutable — an update_mask referencing either
// (camelCase or snake_case) is rejected sync with the immutable-switch text.
func TestAB_IAM_1_19_ScopeAnchorImmutable(t *testing.T) {
	for _, f := range []string{"scopeId", "scopeType", "scope_id", "scope_type"} {
		err := shared.ValidateUpdateMask([]string{f}, abMutableFields, abImmutableFields)
		require.Error(t, err, f)
		st, ok := status.FromError(err)
		require.True(t, ok, f)
		assert.Equal(t, codes.InvalidArgument, st.Code(), f)
		assert.Contains(t, st.Message(), "is immutable after AccessBinding.Create", f)
	}
}

// domain helper round-trip: dotted ⟷ bare, both directions total over the 3 tiers.
func TestAB_IAM_1_18_DomainScopeTypeDottedRoundTrip(t *testing.T) {
	for bare, dotted := range map[string]string{
		"cluster": "iam.cluster",
		"account": "iam.account",
		"project": "iam.project",
	} {
		assert.Equal(t, dotted, domain.ScopeTypeToDotted(bare), bare)
		gotBare, ok := domain.ScopeTypeFromDotted(dotted)
		require.True(t, ok, dotted)
		assert.Equal(t, bare, gotBare, dotted)
	}
	if _, ok := domain.ScopeTypeFromDotted("iam.folder"); ok {
		t.Fatal("iam.folder must not resolve")
	}
}
