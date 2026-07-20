// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// get_role_compiled_test.go — redesign-2026 F5 (IAM-1-13). Handler wiring for the
// Internal compiled-permission projection: returns the use-case's set; fails closed
// Unavailable when the reader is not configured.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type fakeRoleCompiled struct {
	perms []string
	err   error
	last  domain.RoleID
}

func (f *fakeRoleCompiled) Execute(_ context.Context, id domain.RoleID) ([]string, error) {
	f.last = id
	return f.perms, f.err
}

func TestGetRoleCompiled_ReturnsPermissions(t *testing.T) {
	fake := &fakeRoleCompiled{perms: []string{"compute.instance.*.get", "compute.disk.*.get"}}
	h := (&Handler{}).WithRoleCompiledReader(fake)

	resp, err := h.GetRoleCompiled(context.Background(), &iamv1.GetRoleCompiledRequest{RoleId: "rol-app"})
	require.NoError(t, err)
	assert.Equal(t, "rol-app", resp.GetRoleId())
	assert.Equal(t, []string{"compute.instance.*.get", "compute.disk.*.get"}, resp.GetPermissions())
	assert.Equal(t, domain.RoleID("rol-app"), fake.last)
}

func TestGetRoleCompiled_NilReader_Unavailable(t *testing.T) {
	h := &Handler{}
	_, err := h.GetRoleCompiled(context.Background(), &iamv1.GetRoleCompiledRequest{RoleId: "rol-app"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestGetRoleCompiled_PropagatesUseCaseError(t *testing.T) {
	h := (&Handler{}).WithRoleCompiledReader(&fakeRoleCompiled{err: status.Error(codes.NotFound, "Role rol-x not found")})
	_, err := h.GetRoleCompiled(context.Background(), &iamv1.GetRoleCompiledRequest{RoleId: "rol-x"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())

	// non-status error is still surfaced (not swallowed).
	h2 := (&Handler{}).WithRoleCompiledReader(&fakeRoleCompiled{err: stderrors.New("boom")})
	_, err2 := h2.GetRoleCompiled(context.Background(), &iamv1.GetRoleCompiledRequest{RoleId: "rol-x"})
	require.Error(t, err2)
}
