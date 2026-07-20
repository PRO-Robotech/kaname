// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// f9_structural_gates_test.go — redesign-2026 F9 gate 1 (IAM-1-26): scope-id
// well-formedness. Pure unit (no Docker).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestAB_IAM_1_26_ValidateScopeID(t *testing.T) {
	cases := []struct {
		name    string
		rt, rid string
		wantErr bool
	}{
		{"account real-shaped id ok", "account", "acc7fq2m8k3rd0xwabc", false},
		{"account synthetic id ok", "account", "acc_target_account", false},
		{"project ok", "project", "prj-staging", false},
		{"cluster singleton ok", "cluster", domain.ClusterSingletonID, false},
		{"cluster wrong id rejected", "cluster", "cluster_other", true},
		{"account malformed bang rejected", "account", "!!!", true},
		{"account empty rejected", "account", "", true},
		{"project malformed rejected", "project", "prj/../x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScopeID(tc.rt, tc.rid)
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "invalid access binding scope id")
		})
	}
}
