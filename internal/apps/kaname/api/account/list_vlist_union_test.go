// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
)

// ───────────── relation-aware stub (viewer vs v_list vs v_get distinguished) ──

// acctUnionFGAStub — stub clients.RelationQueries, keyed by relation so a test can
// grant one relation and assert what the page does with it.
//
// The name says "Union" for historical reasons and does NOT describe the predicate:
// the page is judged by ONE relation, `v_get` (see the file header). The identifier
// is left alone because renaming a live stub is churn; what was false lived in the
// comments, and that is what is corrected.
//
// It carried a per-relation call counter that nothing in this file ever read: it was
// written by an enumeration door which no longer exists, and by the per-object door,
// and consulted by neither. A counter nobody reads states nothing, so it is removed
// rather than left looking like evidence. The counting that IS asserted lives in
// list_authz_test.go (acctFGAStub.calls) and in the page-cost tests.
type acctUnionFGAStub struct {
	clients.RelationQueries
	mu sync.Mutex // the per-object Check port is called concurrently
	// idsBy[relation][subject] = ids resolved for that (relation, subject).
	idsBy map[string]map[string][]string
	err   error
}

func newAcctUnionFGAStub() *acctUnionFGAStub {
	return &acctUnionFGAStub{idsBy: map[string]map[string][]string{}}
}

func (s *acctUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

// CheckWithContext — the DIRECT per-object question the use-case asks
// (internal/authzfilter), answering from the seeded (relation, subject) id-sets, so
// the predicate/fail-closed intent of these tests is unchanged by the removal of
// the enumeration door.
func (s *acctUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
			seedAcct(repo, "acc-2", "usr-other00000000000")

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
	seedAcct(repo, "acc-3", "usr-other00000000000")

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
	seedAcct(repo, "acc-foreign", "usr-other00000000000")

	fga := newAcctUnionFGAStub()
	fga.set("v_list", "user:usr-u1", []string{"acc-1"})
	fga.set("viewer", "user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.NotContains(t, acctIDs(out), "acc-foreign",
		"foreign account in no set at all must stay hidden (no-leak)")
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

// P7-F — fail-closed: a question that could not be answered → Unavailable, never a
// degraded/partial list (INV-7).
//
// "Could not ask" and "not allowed" are different worlds: a page returned here would
// pass a database that did not answer off as a lawful denial.
func TestListAccounts_P7_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctUnionFGAStub()
	fga.err = stderrors.New("relation form did not answer: connection closed")

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"an unanswered question → UNAVAILABLE fail-closed (INV-7)")
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take.
//
// The refusal above authzfilter.MaxBatchChecksPerRequest keeps the stub from being
// SLACKER than the declaration it stands behind: that constant is the partition size
// authzfilter itself declares and splits a page against, so a filter that stopped
// honouring its own declaration goes red here instead of quietly changing the shape
// of the request. An error, never a trim — a short answer is indistinguishable from
// a page of denials.
func (s *acctUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batch of %d objects exceeds the declared partition size %d",
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
