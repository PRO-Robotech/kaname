// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_expiry_test.go — a binding created with a TTL must actually carry it.
//
// The lifetime is enforced end-to-end: the reconcile worker's sweep lists
// bindings whose expiry has elapsed and eager-revokes them (ExpireBinding →
// status REVOKED + tuple removal). The only thing missing was the request field
// reaching the object, which made every "temporary access" grant permanent while
// the API accepted the parameter and reported success.
//
// The floor is deliberate: access materialises asynchronously (bounded, seconds),
// so a grant that expires sooner than that could be revoked before it is ever
// usable — accepted, paid for, never delivered. Such a request is refused by
// name instead.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

const (
	expOwnerID   = "usr0000000000000expo"
	expAccountID = "acc0000000000000expa"
	expRoleID    = "rol0000000000000expr"
)

// expiryRig builds the real transport→use-case path: the request enters as the
// proto message a client sends, and the resource is read back the same way.
func expiryRig(t *testing.T) (*Handler, *abFakeRepo, context.Context) {
	t.Helper()
	repo := newABFakeRepo(expOwnerID, expAccountID, "prj0000000000000expp", expRoleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.AddUser(expOwnerID, expAccountID)
	opsRepo := newStrictFakeOpsRepo()
	create := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)
	get := NewGetAccessBindingUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	h := NewHandler(create, nil, get, nil, nil, nil, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: expOwnerID})
	return h, repo, ctx
}

func expiryReq(expiresAt *time.Time) *iamv1.CreateAccessBindingRequest {
	req := &iamv1.CreateAccessBindingRequest{
		SubjectType: string(domain.SubjectTypeUser),
		SubjectId:   expOwnerID,
		RoleId:      expRoleID,
		ScopeType:   "iam.account",
		ScopeId:     expAccountID,
		Target: &iamv1.AccessTarget{
			Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}},
		},
	}
	if expiresAt != nil {
		req.ExpiresAt = timestamppb.New(*expiresAt)
	}
	return req
}

// TestCreateAccessBinding_ExpiresAt_IsCarriedByTheBinding — what the caller asked
// for is what the caller reads back.
func TestCreateAccessBinding_ExpiresAt_IsCarriedByTheBinding(t *testing.T) {
	h, repo, ctx := expiryRig(t)

	want := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	op, err := h.Create(ctx, expiryReq(&want))
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	got, gerr := h.Get(ctx, &iamv1.GetAccessBindingRequest{AccessBindingId: string(repo.lastInsertedID())})
	require.NoError(t, gerr)
	require.NotNil(t, got.GetExpiresAt(), "a binding created with a lifetime must carry it; otherwise the grant is permanent while the API reported the TTL accepted")
	assert.True(t, want.Equal(got.GetExpiresAt().AsTime().UTC()),
		"expiry read back = %v, requested %v", got.GetExpiresAt().AsTime().UTC(), want)
}

// TestCreateAccessBinding_ExpiresAt_Absent_StaysPermanent — no TTL requested, no
// TTL invented.
func TestCreateAccessBinding_ExpiresAt_Absent_StaysPermanent(t *testing.T) {
	h, repo, ctx := expiryRig(t)

	op, err := h.Create(ctx, expiryReq(nil))
	require.NoError(t, err)
	require.NotNil(t, op)

	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	got, gerr := h.Get(ctx, &iamv1.GetAccessBindingRequest{AccessBindingId: string(repo.lastInsertedID())})
	require.NoError(t, gerr)
	assert.Nil(t, got.GetExpiresAt(), "a binding created without a lifetime must not acquire one")
}

// TestCreateAccessBinding_ExpiresAt_TooSoon_RejectedByName — refused
// synchronously, naming the field, before any Operation is minted.
func TestCreateAccessBinding_ExpiresAt_TooSoon_RejectedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"already past", time.Now().UTC().Add(-time.Minute)},
		{"now", time.Now().UTC()},
		{"inside the materialisation window", time.Now().UTC().Add(30 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, ctx := expiryRig(t)
			at := tc.at
			op, err := h.Create(ctx, expiryReq(&at))
			require.Nil(t, op, "no Operation may be minted for a request refused synchronously")
			require.Error(t, err)
			st := status.Convert(err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.True(t, strings.Contains(st.Message(), "expires_at"),
				"the refusal must name the field it refuses, got %q", st.Message())
		})
	}
}

// TestListSubjectPrivileges_ExpiresAt_Surfaces — the TTL is visible on the read
// surface a caller uses to audit its own grants (the enriched privilege row).
func TestListSubjectPrivileges_ExpiresAt_Surfaces(t *testing.T) {
	repo := spRepo()
	at := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	p := spPriv("acb00000000000bind01", "rol_v", "viewer", "account", spAccA, domain.ScopeAccount)
	p.ExpiresAt = &at
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{p})

	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(&denyingFGA{}, nil)
	out, _, err := uc.Execute(userCtxAB(spMemberID), domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{})
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.NotNil(t, out[0].ExpiresAt)
	assert.True(t, at.Equal(out[0].ExpiresAt.UTC()))
}
