// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// expand_access_authz_test.go — per-object authz on ExpandAccess (В3) +
// relation closed-set validation (В2).
//
// В3: ExpandAccess used to gate only the authenticated-floor (anti-anon),
// so ANY authenticated principal could expand "who can do X" on ANY object —
// including a foreign account / instance they have no authority over. That leaks
// the authz topology + group membership to an unauthorized caller (an
// under-authorized method). ExpandAccess MUST require grant-authority/admin on the
// target object's scope BEFORE walking the userset — the SAME requireGrantAuthority
// gate ListByResource/ListByRole already enforce (read==enforce).
//
// В2: the `relation` field was forwarded verbatim into the FGA Read.
// It MUST be validated against the closed known-relation set (per-verb v_* + tier
// viewer/editor/admin + member); an unknown relation → INVALID_ARGUMENT (no probing
// of arbitrary strings).

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// foreignCtx returns a context for an authenticated, NON-owner, NON-admin
// principal (passes RequireAuthenticated but fails requireGrantAuthority unless
// FGA grants admin on the object).
func foreignCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr_foreign", Type: "user"})
}

// ── В3: per-object authz ──────────────────────────────────────────────────────

// TestExpandAccess_В3_ForeignObject_Denied — an authenticated caller WITHOUT
// grant-authority on the target object's scope must be DENIED before the userset is
// expanded (no leak of effective principals). FGA Check denies (no admin); the
// owner-account lookup returns a DIFFERENT owner (the caller is not the owner).
func TestExpandAccess_В3_ForeignObject_Denied(t *testing.T) {
	// Owner of acc_foreign is usr_owner; caller is usr_foreign (not the owner).
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{
		"account:acc_foreign#viewer": {"user:usr_secret_member"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, &denyingFGA{}, nil)

	res, _, err := uc.Execute(foreignCtx(), "account", "acc_foreign", "viewer", 0)
	require.Error(t, err, "ExpandAccess on a foreign object MUST be denied (В3)")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"unauthorized expand → PERMISSION_DENIED (parity with ListByResource)")
	assert.Empty(t, res, "no principals leaked when denied")
	assert.Equal(t, 0, exp.calls, "the userset must NOT be walked before authority is verified")
}

// TestExpandAccess_В3_OwnObject_Allowed — the account OWNER (grant-authority via the
// owner path) may expand their own object's userset.
func TestExpandAccess_В3_OwnObject_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{
		"account:acc_mine#viewer": {"user:usr_a", "user:usr_b"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, &denyingFGA{}, nil)

	ctx := newOwnerContext("usr_owner")
	res, _, err := uc.Execute(ctx, "account", "acc_mine", "viewer", 0)
	require.NoError(t, err, "the owner has grant-authority on their own object")
	require.Len(t, res, 2)
}

// TestExpandAccess_В3_DelegatedAdmin_Allowed — a non-owner who holds FGA `admin`
// on the object (delegated administration, Path 2) may expand it.
func TestExpandAccess_В3_DelegatedAdmin_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_x", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{
		"compute.instance:inst_x#v_delete": {"user:usr_a"},
	}}
	// recordingFGA.Check returns true → delegated admin path passes.
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)

	res, _, err := uc.Execute(foreignCtx(), "compute.instance", "inst_x", "v_delete", 0)
	require.NoError(t, err, "a delegated FGA admin may expand the object")
	require.Len(t, res, 1)
}

// ── В2: relation closed-set ───────────────────────────────────────────────────

// TestExpandAccess_В2_UnknownRelation_Rejected — an unknown relation string must be
// rejected with INVALID_ARGUMENT, before any FGA probe.
func TestExpandAccess_В2_UnknownRelation_Rejected(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)

	ctx := newOwnerContext("usr_owner")
	for _, rel := range []string{"sg_compute_instance", "owner", "g_admin_compute_instance", "totally_bogus", "v_teleport"} {
		_, _, err := uc.Execute(ctx, "account", "acc_mine", rel, 0)
		require.Error(t, err, "unknown relation %q must be rejected", rel)
		assert.Equal(t, codes.InvalidArgument, status.Code(err),
			"unknown relation %q → INVALID_ARGUMENT", rel)
	}
	assert.Equal(t, 0, exp.calls, "no FGA Read probe for an invalid relation")
}

// TestExpandAccess_В2_KnownRelations_Accepted — every relation in the closed set
// (per-verb v_*, tier viewer/editor/admin, group member) passes validation.
func TestExpandAccess_В2_KnownRelations_Accepted(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	ctx := newOwnerContext("usr_owner")
	known := []string{"v_get", "v_list", "v_create", "v_update", "v_delete", "viewer", "editor", "admin", "member"}
	for _, rel := range known {
		exp := &fakeLister{byNode: map[string][]string{
			"account:acc_mine#" + rel: {"user:usr_a"},
		}}
		uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)
		_, _, err := uc.Execute(ctx, "account", "acc_mine", rel, 0)
		require.NoError(t, err, "known relation %q must be accepted", rel)
	}
}
