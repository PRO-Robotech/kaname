// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// delta_input_test.go — resource-scoped AccessBinding input normalization
// (additive, non-breaking). Pure parse-path unit tests (no Docker, no
// use-case) for the TWO-WAY INPUT NORMALIZATION of the scope + target dimensions
// on AccessBinding.Create:
//
//   - scope:  legacy flat resource_type/resource_id  ⟷  canonical scope_ref{tier,id}
//   - target: legacy AccessTarget oneof              ⟷  canonical AccessTargetRef
//
// The contract:
//   - only legacy set        → used as-is.
//   - only canonical set     → used, equivalent.
//   - both, derived-equiv.   → OK, not a conflict.
//   - both, disagree         → sync INVALID_ARGUMENT (conflict branch).
//   - canonical scope invalid (tier↔id mismatch / unspecified tier) → sync
//     INVALID_ARGUMENT, re-using Scope.ValidateAgainst.
//
// These assert the FIRST-statement sync-error contract — the conflict/format
// failures are gRPC errors BEFORE any Operation is created.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ── scope normalization ──────────────────────────────────────────────────────

func TestDelta_NormalizeScope(t *testing.T) {
	tests := []struct {
		name     string
		resType  string
		resID    string
		scopeRef *iamv1.ScopeRef
		wantType string
		wantID   string
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "only legacy → used as-is",
			resType:  "project",
			resID:    "prj_prod",
			scopeRef: nil,
			wantType: "project",
			wantID:   "prj_prod",
			wantCode: codes.OK,
		},
		{
			name:     "only canonical scope_ref → derived to legacy",
			resType:  "",
			resID:    "",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_PROJECT, Id: "prj_prod"},
			wantType: "project",
			wantID:   "prj_prod",
			wantCode: codes.OK,
		},
		{
			name:     "both, derived-equivalent → OK (not a conflict)",
			resType:  "project",
			resID:    "prj_prod",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_PROJECT, Id: "prj_prod"},
			wantType: "project",
			wantID:   "prj_prod",
			wantCode: codes.OK,
		},
		{
			name:     "both, conflicting tier → INVALID_ARGUMENT",
			resType:  "project",
			resID:    "prj_prod",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_ACCOUNT, Id: "acc-A"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "scope conflicts with resource_type/resource_id",
		},
		{
			name:     "both, conflicting id → INVALID_ARGUMENT",
			resType:  "project",
			resID:    "prj_prod",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_PROJECT, Id: "prj_other"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "scope conflicts with resource_type/resource_id",
		},
		{
			name:     "canonical scope tier↔id mismatch → INVALID_ARGUMENT (ValidateAgainst reuse)",
			resType:  "",
			resID:    "",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_PROJECT, Id: "acc-A"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "scope",
		},
		{
			name:     "canonical scope tier unspecified → INVALID_ARGUMENT",
			resType:  "",
			resID:    "",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_SCOPE_UNSPECIFIED, Id: "prj_prod"},
			wantCode: codes.InvalidArgument,
			wantMsg:  "scope.tier is required",
		},
		{
			name:     "account derived from scope_ref",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_ACCOUNT, Id: "acc-A"},
			wantType: "account",
			wantID:   "acc-A",
			wantCode: codes.OK,
		},
		{
			name:     "cluster derived from scope_ref",
			scopeRef: &iamv1.ScopeRef{Tier: iamv1.AccessBinding_CLUSTER, Id: domain.ClusterSingletonID},
			wantType: "cluster",
			wantID:   domain.ClusterSingletonID,
			wantCode: codes.OK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotID, err := normalizeScopeInput(tc.resType, tc.resID, tc.scopeRef)
			if tc.wantCode == codes.OK {
				require.NoError(t, err)
				assert.Equal(t, tc.wantType, gotType)
				assert.Equal(t, tc.wantID, gotID)
				return
			}
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "must be a gRPC status error")
			assert.Equal(t, tc.wantCode, st.Code())
			if tc.wantMsg != "" {
				assert.Contains(t, st.Message(), tc.wantMsg)
			}
		})
	}
}
