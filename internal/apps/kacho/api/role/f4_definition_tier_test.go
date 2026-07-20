// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// f4_definition_tier_test.go — redesign-2026 F4 (IAM-1-10/11): the Role carries a
// `definitionTier{tierType,tierId}` dotted wire projection over the within-service
// typed scope columns; `isSystem` is DERIVED from the tier (tierType==iam.cluster),
// not a stored flag; the word "scope" never names a field on the role. Pre-Phase-0
// tierType is REQUIRED on input (prefix-derivation is B3-gated).
//
// Pure parse-path + dto unit tests (no Docker).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func f4Rules() domain.Rules {
	return domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
}

// IAM-1-10 (output): domain.Role → *iamv1.Role emits the dotted definitionTier
// projection and DERIVES is_system from the tier (cluster ⇒ true), independent of
// the stored IsSystem flag.
func TestRole_IAM_1_10_DtoEmitsDefinitionTier(t *testing.T) {
	cases := []struct {
		name       string
		role       domain.Role
		wantType   string
		wantID     string
		wantSystem bool
	}{
		{"account-tier custom", domain.Role{ID: "rol-x", AccountID: "acc-A", Name: "app-deployer", Rules: f4Rules()}, "iam.account", "acc-A", false},
		{"project-tier custom", domain.Role{ID: "rol-y", ProjectID: "prj-P", Name: "p", Rules: f4Rules()}, "iam.project", "prj-P", false},
		// Stored IsSystem is intentionally left false to prove the projection derives
		// system-ness from the cluster tier, not the stored flag.
		{"cluster-tier system (derived)", domain.Role{ID: "rol-z", ClusterID: "cluster_kacho_root", Name: "admin", Rules: f4Rules(), IsSystem: false}, "iam.cluster", "cluster_kacho_root", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pb, err := roleToPb(tc.role)
			require.NoError(t, err)
			require.NotNil(t, pb.GetDefinitionTier(), "definitionTier must be populated")
			assert.Equal(t, tc.wantType, pb.GetDefinitionTier().GetTierType())
			assert.Equal(t, tc.wantID, pb.GetDefinitionTier().GetTierId())
			assert.Equal(t, tc.wantSystem, pb.GetIsSystem(), "is_system must be derived from the tier")
		})
	}
}

// IAM-1-10: the Role message exposes no field whose name contains "scope" — the
// word is reserved for the AccessBinding anchor.
func TestRole_IAM_1_10_NoScopeNamedField(t *testing.T) {
	fields := (&iamv1.Role{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		assert.NotContains(t, name, "scope", "role field %q must not carry the reserved word 'scope'", name)
	}
	// sanity: definition_tier IS present.
	require.NotNil(t, fieldByName(fields, "definition_tier"))
}

func fieldByName(fs protoreflect.FieldDescriptors, n string) protoreflect.FieldDescriptor {
	return fs.ByName(protoreflect.Name(n))
}

// IAM-1-10 (input): CreateRoleRequest.definitionTier is translated into the domain
// role's account/project scope. iam.account → AccountID; iam.project → ProjectID.
func TestRole_IAM_1_10_CreateReqMapsDefinitionTier(t *testing.T) {
	t.Run("account tier", func(t *testing.T) {
		r, err := roleFromCreateReq(&iamv1.CreateRoleRequest{
			Name:           "app-deployer",
			DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: "acc-A"},
			Rules:          []*iamv1.Rule{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}},
		})
		require.NoError(t, err)
		assert.Equal(t, domain.AccountID("acc-A"), r.AccountID)
		assert.Equal(t, domain.ProjectID(""), r.ProjectID)
	})
	t.Run("project tier", func(t *testing.T) {
		r, err := roleFromCreateReq(&iamv1.CreateRoleRequest{
			Name:           "p",
			DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.project", TierId: "prj-P"},
		})
		require.NoError(t, err)
		assert.Equal(t, domain.ProjectID("prj-P"), r.ProjectID)
		assert.Equal(t, domain.AccountID(""), r.AccountID)
	})
}

// IAM-1-11 (negative): a malformed definitionTier is rejected sync with
// INVALID_ARGUMENT "Illegal argument definitionTier" — empty tierType (pre-Phase-0
// required), the cluster tier (system roles are seeded, not API-created), and an
// unknown tierType all reject.
func TestRole_IAM_1_11_CreateReqDefinitionTierNegative(t *testing.T) {
	for _, tc := range []struct{ name, tt, tid string }{
		{"empty tierType (pre-Phase-0 required)", "", "acc-A"},
		{"cluster tier rejected (seeded, not API)", "iam.cluster", "cluster_kacho_root"},
		{"unknown tierType", "iam.folder", "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := roleFromCreateReq(&iamv1.CreateRoleRequest{
				Name:           "r",
				DefinitionTier: &iamv1.DefinitionTier{TierType: tc.tt, TierId: tc.tid},
			})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "Illegal argument definitionTier")
		})
	}
}
