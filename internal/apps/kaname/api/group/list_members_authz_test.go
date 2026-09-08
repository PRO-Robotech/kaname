// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// list_members_authz_test.go — ListMembers names a group in the request and
// answers with that group's roster, so it re-asks the model about that group,
// exactly as its two siblings do.
//
// Standing before this file: `Get` and `List` on this same resource each ask the
// model in-service (get.go — `v_get` on `iam_group:<id>`; list.go — the per-object
// page filter). `ListMembers` asked nothing. It was not an open door — the front
// door narrows it on the same `group_id` (`v_list`, a relation no wildcard tuple
// satisfies) and no other module may dial this RPC — but it was the one method of
// the resource resting on a single layer, and it is also the one method whose name
// the List-surface analyser cannot see, since that analyser keys on the exact name
// `List`. A layer missing precisely where nothing is looking is worth restoring on
// its own.
//
// So this is defense-in-depth on top of the front-door decision, deliberately the
// SAME relation and not a second, coarser policy: a caller the front door admits
// is admitted here too.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const membersGroupID = "grp00000000000000001"

// memberRosterChecker answers a fixed set of (subject, relation, object)
// questions; anything unscripted answers "no".
type memberRosterChecker struct {
	allow map[string]bool
	err   error
}

func (c *memberRosterChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	return c.allow[subject+"|"+relation+"|"+object], nil
}

func rosterGrants(keys ...string) *memberRosterChecker {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return &memberRosterChecker{allow: m}
}

func asRosterUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

func rosterHandler(repo *memberPageRepo, relations *memberRosterChecker) *Handler {
	uc := NewListMembersUseCase(repo)
	if relations != nil {
		uc = uc.WithRelationStore(relations)
	}
	return NewHandler(nil, nil, nil, nil, nil, nil, nil, uc)
}

func listMembersOf(h *Handler, ctx context.Context) (*iamv1.ListGroupMembersResponse, error) {
	return h.ListMembers(ctx, &iamv1.ListGroupMembersRequest{GroupId: membersGroupID})
}

// A caller with no standing on the group does not receive its roster — and is
// told the group is not there, in the wording the resource's own miss uses, so
// the refusal does not confirm the group exists.
func TestListMembers_WithoutStandingOnTheGroup_IsRefused(t *testing.T) {
	repo := &memberPageRepo{members: []domain.GroupMember{
		{MemberType: "user", MemberID: "usr_member0000000000"},
	}}

	resp, err := listMembersOf(rosterHandler(repo, rosterGrants()), asRosterUser("usr_outsider"))

	require.Error(t, err, "an outsider asked for a group's roster and was served it")
	assert.Nil(t, resp.GetMembers())
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "Group "+membersGroupID+" not found", status.Convert(err).Message())
}

// The paired positive: a caller holding the same relation the front door requires
// is served. Without this the refusal above would also be satisfied by a gate
// that denies everyone, which is the shape that reads greenest when broken.
func TestListMembers_WithTheGrantedRelation_IsServed(t *testing.T) {
	repo := &memberPageRepo{members: []domain.GroupMember{
		{MemberType: "user", MemberID: "usr_member0000000000"},
	}}
	h := rosterHandler(repo, rosterGrants(
		"user:usr_delegate|v_list|iam_group:"+membersGroupID))

	resp, err := listMembersOf(h, asRosterUser("usr_delegate"))

	require.NoError(t, err)
	require.Len(t, resp.GetMembers(), 1)
}

// The cloud administrator reads any roster without a per-object grant having been
// materialised — the same super-gate the sibling reads carry.
func TestListMembers_ClusterAdmin_IsServed(t *testing.T) {
	repo := &memberPageRepo{members: []domain.GroupMember{
		{MemberType: "user", MemberID: "usr_member0000000000"},
	}}
	h := rosterHandler(repo, rosterGrants(
		"user:usr_root|system_admin|cluster:"+domain.ClusterSingletonID))

	resp, err := listMembersOf(h, asRosterUser("usr_root"))

	require.NoError(t, err)
	require.Len(t, resp.GetMembers(), 1)
}

// An unidentified caller is refused whether or not the relation port is wired.
func TestListMembers_Anonymous_IsRefusedWithAndWithoutRelationPort(t *testing.T) {
	for name, wire := range map[string]bool{"port wired": true, "port absent": false} {
		t.Run(name, func(t *testing.T) {
			repo := &memberPageRepo{members: []domain.GroupMember{
				{MemberType: "user", MemberID: "usr_member0000000000"},
			}}
			var relations *memberRosterChecker
			if wire {
				relations = rosterGrants()
			}

			_, err := listMembersOf(rosterHandler(repo, relations), context.Background())

			require.Error(t, err, "an unidentified caller was served a group's roster")
			assert.Equal(t, codes.NotFound, status.Code(err))
		})
	}
}

// A model that could not be asked is an outage, not a denial: reporting it as
// NotFound would tell the caller the group is gone while it plainly is not.
func TestListMembers_RelationStoreError_IsUnavailable(t *testing.T) {
	repo := &memberPageRepo{}
	h := rosterHandler(repo, &memberRosterChecker{err: errors.New("dial tcp: connection refused")})

	_, err := listMembersOf(h, asRosterUser("usr_delegate"))

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.NotContains(t, status.Convert(err).Message(), "connection refused")
}

// The caller's own errors keep their own answer: a malformed page_size stays an
// InvalidArgument rather than being swallowed into the authorization refusal, or
// a caller who IS allowed can never learn why their page was rejected.
func TestListMembers_PageValidationStillPrecedesAuthorization(t *testing.T) {
	repo := &memberPageRepo{}
	h := rosterHandler(repo, rosterGrants())

	_, err := h.ListMembers(asRosterUser("usr_outsider"), &iamv1.ListGroupMembersRequest{
		GroupId:  membersGroupID,
		PageSize: 100_000,
	})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
