// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// f5_compiled_projection_test.go — redesign-2026 F5 (IAM-1-13). Two-projection:
//   - the PUBLIC RoleService.Get/List projection NEVER carries compiled
//     `permissions` (only authored `rules[]`);
//   - the compiled set is read ONLY via the Internal GetRoleCompiledUseCase
//     (surfaced by InternalIAMService.GetRoleCompiled on :9091).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// IAM-1-13: the public domain→proto projection omits compiled permissions even
// when the role carries them.
func TestRole_IAM_1_13_PublicProjectionOmitsPermissions(t *testing.T) {
	r := domain.Role{
		ID:          "rol-app",
		AccountID:   "acc-A",
		Name:        "app-deployer",
		Rules:       f4Rules(),
		Permissions: domain.Permissions{"compute.instance.*.get", "compute.disk.*.get"},
	}
	pb, err := roleToPb(r)
	require.NoError(t, err)
	assert.Empty(t, pb.GetPermissions(), "public Role projection must not carry compiled permissions") //nolint:staticcheck // asserts deprecated field stays empty
}

// IAM-1-13: the Internal GetRoleCompiledUseCase returns the compiled set.
func TestRole_IAM_1_13_GetRoleCompiledReturnsCompiled(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000app1"] = domain.Role{
		ID:          "rol0000000000000app1",
		AccountID:   "acc-A",
		Name:        "app-deployer",
		Rules:       f4Rules(),
		Permissions: domain.Permissions{"compute.instance.*.get", "compute.disk.*.get"},
	}
	uc := NewGetRoleCompiledUseCase(repo)

	perms, err := uc.Execute(context.Background(), "rol0000000000000app1")
	require.NoError(t, err)
	assert.Equal(t, []string{"compute.instance.*.get", "compute.disk.*.get"}, perms)
}

// IAM-1-13 (edge): malformed role id → sync InvalidArgument (before repo work).
func TestRole_IAM_1_13_GetRoleCompiledMalformedID(t *testing.T) {
	uc := NewGetRoleCompiledUseCase(newRoleListFakeRepo())
	_, err := uc.Execute(context.Background(), "!!!")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}
