// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// scope_test.go — RequireScopeRelation defense-in-depth authority gate.
//
// The gate must distinguish a transient FGA backend failure (Check err != nil)
// from an explicit deny (allowed==false, nil err), mirroring RelationWriteGate /
// SystemViewerFloor: a backend outage during the redundant relation check is a
// retryable codes.Unavailable, NOT a terminal codes.PermissionDenied (which the
// client would not retry, wrongly turning an FGA flap into a hard 403 for a
// delegated editor).
package authzguard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
)

func scopeUserCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "user"})
}

// TestRequireScopeRelation_BackendError_Unavailable — a non-owner delegated
// editor: Path-1 (owner) does not apply, so the gate consults FGA. When the
// Check backend fails (5xx / network / timeout), the gate must return retryable
// Unavailable, NOT PermissionDenied.
func TestRequireScopeRelation_BackendError_Unavailable(t *testing.T) {
	ctx := scopeUserCtx("usr_delegate00001")
	checker := &fakeChecker{err: errors.New("fga backend 503")}

	err := authzguard.RequireScopeRelation(ctx, checker, "project", "prj_dev00000001", "owner_other0001")

	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err),
		"backend Check failure must be Unavailable (retryable), never PermissionDenied — "+
			"an FGA outage must not turn a delegated editor mutation into a hard 403")
}

// TestRequireScopeRelation_ExplicitDeny_PermissionDenied — a real deny
// (allowed==false, nil err) stays a terminal PermissionDenied, so a legitimate
// non-member deny is not disguised as a retryable Unavailable.
func TestRequireScopeRelation_ExplicitDeny_PermissionDenied(t *testing.T) {
	ctx := scopeUserCtx("usr_stranger00001")
	checker := &fakeChecker{allowSubjects: map[string]bool{}} // nil err, nobody allowed

	err := authzguard.RequireScopeRelation(ctx, checker, "project", "prj_dev00000001", "owner_other0001")

	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"explicit deny (allowed=false, nil err) must be PermissionDenied, not Unavailable")
}

// TestRequireScopeRelation_DelegatedEditor_Allowed — a delegated editor whose
// FGA relation Check succeeds is authorised (nil error), unchanged by the fix.
func TestRequireScopeRelation_DelegatedEditor_Allowed(t *testing.T) {
	subject := "user:usr_editor000001"
	ctx := scopeUserCtx("usr_editor000001")
	checker := &fakeChecker{allowSubjects: map[string]bool{subject: true}}

	err := authzguard.RequireScopeRelation(ctx, checker, "project", "prj_dev00000001", "owner_other0001")

	require.NoError(t, err)
}
