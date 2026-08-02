// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// list_vlist_union_test.go — Design-B (flat-authz verb-bearing complete). The
// custom-role List visibility is the UNION of the principal's FGA `viewer`-set
// AND `v_list`-set on iam_role:
//
//	visible(iam_role) = ListObjects(subject, "viewer", "iam_role")
//	                  ∪ ListObjects(subject, "v_list", "iam_role")
//
// Rationale (parity with account/project List, D-6a): on the decoupled model a
// grant of `iam.roles.{get,list}` with a names/labels selector materializes ONLY
// an object-only `iam_role:<id> # v_list/v_get @ subj` tuple with NO viewer-tier
// cascade. The pre-existing viewer-only filter (the stale #193 path) hid such a
// v_list-only grant from its grantee. The union surfaces it (selector-visible)
// while content (v_get) remains gated.
//
// RED until ListRolesUseCase unions viewer ∪ v_list on iam_role.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

// roleUnionFGAStub — relation-aware ListObjects stub: distinguishes viewer vs
// v_list so the union and dedup are observable.
type roleUnionFGAStub struct {
	clients.RelationQueries
	mu    sync.Mutex                     // the per-object Check port is called concurrently
	idsBy map[string]map[string][]string // [relation][subject] = ids
	err   error
	calls map[string]int
}

func newRoleUnionFGAStub() *roleUnionFGAStub {
	return &roleUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *roleUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *roleUnionFGAStub) ListObjects(_ context.Context, subject, relation, _ string,
	_ map[string]any, _ int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[relation]++
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

// CheckWithContext — the DIRECT per-object oracle the use-case now asks instead
// of enumerating (internal/authzfilter), answering from the SAME (relation,
// subject) id-sets, so these tests' fixtures and intent are unchanged.
func (s *roleUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[relation]++
	if s.err != nil {
		return false, s.err
	}
	id := fgaObjectID(object)
	for _, got := range s.idsBy[relation][subject] {
		if got == id {
			return true, nil
		}
	}
	return false, nil
}

// v_list-only grant on a custom role → role VISIBLE in List (selector-without-
// content). The viewer-only pre-Design-B filter hid it.
func TestListRoles_Union_VListOnlyGrant_CustomVisible(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol-sys1")
	seedCustomRole(repo, "rol-c1", "acc-A")
	seedCustomRole(repo, "rol-c2", "acc-A") // ungranted

	fga := newRoleUnionFGAStub()
	fga.set("v_list", "user:usr-u1", []string{"rol-c1"}) // object-only v_list grant
	fga.set("viewer", "user:usr-u1", nil)

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-sys1", "rol-c1"}, roleIDs(out),
		"v_list-only grant makes rol-c1 visible (selector-without-content); rol-c2 ungranted hidden")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1,
		"List must query the v_list relation in addition to viewer (union)")
	require.GreaterOrEqual(t, fga.calls["viewer"], 1,
		"List must still query the viewer relation (account-admin sees own role via account-tier)")
}

// viewer grant still surfaces the role (regression: viewer branch retained — the
// account-admin resolves viewer via the account-tier cascade).
func TestListRoles_Union_ViewerGrant_StillVisible(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A")

	fga := newRoleUnionFGAStub()
	fga.set("viewer", "user:usr-u1", []string{"rol-c1"})
	fga.set("v_list", "user:usr-u1", nil)

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-c1"}, roleIDs(out),
		"viewer grant keeps the role visible (regression — viewer branch retained)")
}

// UNION + dedup: a role in BOTH sets appears once.
func TestListRoles_Union_Dedup(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A")
	seedCustomRole(repo, "rol-c2", "acc-A")

	fga := newRoleUnionFGAStub()
	fga.set("viewer", "user:usr-u1", []string{"rol-c1", "rol-c2"})
	fga.set("v_list", "user:usr-u1", []string{"rol-c2"}) // dedup

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"rol-c1", "rol-c2"}, roleIDs(out),
		"union of viewer ∪ v_list, deduplicated (rol-c2 once)")
}

// fail-closed: an FGA error on EITHER relation → Unavailable.
func TestListRoles_Union_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedCustomRole(repo, "rol-c1", "acc-A")

	fga := newRoleUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	_, _, err := uc.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage on either relation → UNAVAILABLE fail-closed")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (s *roleUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}
