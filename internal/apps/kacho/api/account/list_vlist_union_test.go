// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_vlist_union_test.go — what makes an account a member of a List page.
//
// A row belongs on the page exactly when its holder may read that row by id. The
// gateway gates AccountService/Get on `v_get`, so that is the page predicate too
// (internal/authzfilter).
//
// It used to be the union `viewer ∪ v_list`, argued as "see the account in the
// selector without access to its contents". That argument does not survive the
// payload: List returns the same Account message Get does, so a row on the page IS
// its contents. What the union actually produced was a divergence — the tier holder
// was handed an account its own Get refused, and a `v_get` holder did not find its
// own readable account in its own list. The tests below therefore assert the
// predicate in BOTH directions rather than the union.

package account

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
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// ───────────── relation-aware FGA stub (viewer vs v_list distinguished) ──────

type acctUnionFGAStub struct {
	clients.RelationQueries
	mu sync.Mutex // the per-object Check port is called concurrently
	// idsBy[relation][subject] = ids resolved for that (relation, subject).
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int // per-relation call count
}

func newAcctUnionFGAStub() *acctUnionFGAStub {
	return &acctUnionFGAStub{
		idsBy: map[string]map[string][]string{},
		calls: map[string]int{},
	}
}

func (s *acctUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *acctUnionFGAStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
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
// subject) id-sets, so the union/fail-closed intent of these tests is unchanged.
func (s *acctUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
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

// The page cannot be WIDER than the read: a holder of the tier (or of the
// object-only `v_list` selector grant) must NOT be handed an account whose Get it
// cannot obtain. Paired with the positive arm in the same table, because a lone
// "is hidden" goes green most convincingly when the filter shows nothing at all.
func TestListAccounts_PageMembershipRequiresReadRelation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		relation  string
		wantVisib bool
	}{
		{name: "tier only — Get would refuse it", relation: "viewer", wantVisib: false},
		{name: "object-only selector grant", relation: "v_list", wantVisib: false},
		{name: "the relation that gates Get", relation: "v_get", wantVisib: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newAcctListFakeRepo()
			seedAcct(repo, "acc-1", "usr-owner")
			seedAcct(repo, "acc-2", "usr-other")

			fga := newAcctUnionFGAStub()
			fga.set(tc.relation, "user:usr-u1", []string{"acc-1"})

			uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

			out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
			require.NoError(t, err)
			if tc.wantVisib {
				require.ElementsMatch(t, []string{"acc-1"}, acctIDs(out),
					"a holder of the read relation must find its own readable account in its own list")
				return
			}
			require.Empty(t, acctIDs(out),
				"the page must not name an account the caller's own Get refuses — and, since List "+
					"returns the same message Get does, must not hand over its contents either")
		})
	}
}

// Dedup: an id repeated on the page is resolved once and appears once.
func TestListAccounts_ReadRelationDedup(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u1")
	seedAcct(repo, "acc-3", "usr-other")

	fga := newAcctUnionFGAStub()
	fga.set("v_get", "user:usr-u1", []string{"acc-1", "acc-2"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1", "acc-2"}, acctIDs(out),
		"each granted account appears exactly once; the ungranted one stays hidden")
}

// P7-D — no-leak: a foreign account in NEITHER set stays hidden.
func TestListAccounts_P7_ForeignAccount_NoLeak(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-foreign", "usr-other")

	fga := newAcctUnionFGAStub()
	fga.set("v_list", "user:usr-u1", []string{"acc-1"})
	fga.set("viewer", "user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.NotContains(t, acctIDs(out), "acc-foreign",
		"foreign account in neither viewer nor v_list set must stay hidden (no-leak)")
}

// A machine principal is filtered by the SAME relation as a human one — there is no
// tier back door for service accounts.
//
// This replaces a case that asserted an "operator system_viewer floor": it stubbed a
// `viewer` grant on every account and concluded the operator sees them all. The seed
// produces no such grant. kacho-vpc-operator's backing role authors its iam rule on
// the resource name `projectses`, which the closed object-type table does not carry
// (`iam.project` does), so that rule resolves to no FGA type and materializes no
// tuple at all — the floor the case described was a property of its own fixture.
func TestListAccounts_ServiceAccountFilteredByTheSameRelation(t *testing.T) {
	op := "sva-operator"

	for _, tc := range []struct {
		relation string
		wantSeen []string
	}{
		{relation: "viewer", wantSeen: nil},
		{relation: "v_get", wantSeen: []string{"acc-1", "acc-2"}},
	} {
		t.Run(tc.relation, func(t *testing.T) {
			repo := newAcctListFakeRepo()
			seedAcct(repo, "acc-1", "usr-u1")
			seedAcct(repo, "acc-2", "usr-u2")

			fga := newAcctUnionFGAStub()
			fga.set(tc.relation, "service_account:"+op, []string{"acc-1", "acc-2"})

			uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

			out, _, err := uc.Execute(ctxSA(op), repoaccount.ListFilter{PageSize: 100})
			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantSeen, acctIDs(out),
				"a service account is subject to the read relation exactly as a user is")
		})
	}
}

// P7-F — fail-closed: an FGA error on EITHER relation query → Unavailable,
// never a degraded/partial list (INV-7 preserved under the union).
func TestListAccounts_P7_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage on either relation → UNAVAILABLE fail-closed (INV-7 under union)")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (s *acctUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
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
