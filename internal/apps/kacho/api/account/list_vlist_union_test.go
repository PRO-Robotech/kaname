// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_vlist_union_test.go — rbac-2026 P7 (D-6 / acceptance rbac-B-01).
//
// P7 makes AccountService.List visibility the UNION of the principal's FGA
// `viewer`-set AND `v_list`-set on `account`:
//
//	visible(account) = ListObjects(subject, "viewer", "account")
//	                 ∪ ListObjects(subject, "v_list", "account")
//
// Rationale (the owner's original goal): on the flat explicit model (P2/P3),
// a grant of `iam.account.{get,list}` with names/labels materializes ONLY
// `account:<id> # v_list/v_get @ subj` — an OBJECT-ONLY tuple with NO cascade
// into the account's contents (D-2). Before P7 the List filtered by `viewer`
// alone, so such a grant left the account INVISIBLE in the selector even
// though the subject was explicitly granted list on it. P7 adds the `v_list`
// branch so "see the account in the selector WITHOUT access to its contents"
// works — while a Check on the contents (project/network inside) still DENIES.
//
// These are RED until ListAccountsUseCase unions the two ListObjects calls.
package account

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// ───────────── relation-aware FGA stub (viewer vs v_list distinguished) ──────

type acctUnionFGAStub struct {
	clients.RelationQueries
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
	s.calls[relation]++
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

// P7-A — v_list-only grant (object-only, no viewer cascade) → account VISIBLE.
// This is the literal "see account in selector without contents" goal: the
// subject has v_list on acc-1 but NOT viewer (no cascade to contents).
func TestListAccounts_P7_VListOnlyGrant_AccountVisible(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-owner")
	seedAcct(repo, "acc-2", "usr-other")

	fga := newAcctUnionFGAStub()
	// usr-u1 holds ONLY v_list on acc-1 (object-only grant, no viewer).
	fga.set("v_list", "user:usr-u1", []string{"acc-1"})
	fga.set("viewer", "user:usr-u1", nil)

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1"}, acctIDs(out),
		"v_list-only grant makes acc-1 VISIBLE in the selector (see-without-contents, D-6/B-01)")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1,
		"P7 must query the v_list relation in addition to viewer")
}

// P7-B — viewer grant still surfaces the account (regression: viewer branch
// retained; a viewer grant implies full access including contents elsewhere).
func TestListAccounts_P7_ViewerGrant_StillVisible(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-other")

	fga := newAcctUnionFGAStub()
	fga.set("viewer", "user:usr-u1", []string{"acc-1"})
	fga.set("v_list", "user:usr-u1", nil)

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1"}, acctIDs(out),
		"viewer grant keeps the account visible (regression — viewer branch retained)")
}

// P7-C — UNION + dedup: an account present in BOTH sets appears EXACTLY once.
func TestListAccounts_P7_UnionDedup(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u1")
	seedAcct(repo, "acc-3", "usr-other")

	fga := newAcctUnionFGAStub()
	fga.set("viewer", "user:usr-u1", []string{"acc-1", "acc-2"})
	fga.set("v_list", "user:usr-u1", []string{"acc-2"}) // acc-2 in both → dedup

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1", "acc-2"}, acctIDs(out),
		"union of viewer ∪ v_list, deduplicated (acc-2 once, acc-3 hidden)")
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

// P7-E — operator-SA system_viewer floor not broken: the operator resolves
// viewer on every account → sees ALL even with empty v_list.
func TestListAccounts_P7_OperatorFloor_Unbroken(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedAcct(repo, "acc-1", "usr-u1")
	seedAcct(repo, "acc-2", "usr-u2")

	op := "sva-operator"
	fga := newAcctUnionFGAStub()
	fga.set("viewer", "service_account:"+op, []string{"acc-1", "acc-2"})
	fga.set("v_list", "service_account:"+op, nil)

	uc := NewListAccountsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxSA(op), repoaccount.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"acc-1", "acc-2"}, acctIDs(out),
		"operator system_viewer floor (SEC-L INV-2) still sees ALL accounts under the union")
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
