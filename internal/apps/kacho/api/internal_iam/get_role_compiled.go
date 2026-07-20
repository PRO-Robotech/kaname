// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// get_role_compiled.go — redesign-2026 F5 (IAM-1-13). InternalIAMService.GetRoleCompiled
// serves a Role's COMPILED permission projection (`module.resource.resourceName.verb`)
// on the cluster-internal listener (:9091). Two-projection: the public RoleService
// never carries compiled `permissions` (only authored `rules[]`); admin-tooling reads
// the compiled set here. Thin transport — the use-case owns id-validation, not-found
// and error-opacity.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// WithRoleCompiledReader attaches the F5 compiled-permission read use-case. nil →
// GetRoleCompiled fails closed (Unavailable).
func (h *Handler) WithRoleCompiledReader(r roleCompiledReader) *Handler {
	h.roleCompiled = r
	return h
}

func (h *Handler) GetRoleCompiled(ctx context.Context, req *iamv1.GetRoleCompiledRequest) (*iamv1.GetRoleCompiledResponse, error) {
	if h.roleCompiled == nil {
		return nil, status.Error(codes.Unavailable, "role-compiled reader not configured")
	}
	perms, err := h.roleCompiled.Execute(ctx, domain.RoleID(req.GetRoleId()))
	if err != nil {
		return nil, err
	}
	return &iamv1.GetRoleCompiledResponse{
		RoleId:      req.GetRoleId(),
		Permissions: perms,
	}, nil
}
