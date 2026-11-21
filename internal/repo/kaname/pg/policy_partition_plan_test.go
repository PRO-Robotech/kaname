// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type policyRows struct {
	pgx.Rows
	start, n, i int
	lastErr     error
	afterScan   func()
}

func (r *policyRows) Next() bool {
	if r.i >= r.n {
		return false
	}
	r.i++
	return true
}
func (r *policyRows) Scan(dest ...any) error {
	index := r.start + r.i
	*dest[0].(*string) = fmt.Sprintf("%09d", index)
	*dest[1].(*string) = "local"
	*dest[2].(*string) = "user:actor"
	*dest[3].(*bool) = false
	if index == 513 {
		*dest[1].(*string) = "foreign-last"
	}
	if r.afterScan != nil {
		r.afterScan()
	}
	return nil
}
func (r *policyRows) Close()     {}
func (r *policyRows) Err() error { return r.lastErr }

type policyScanTx struct {
	pgx.Tx
	remaining, returned, pages int
	failPage                   int
	late                       error
	cancel                     context.CancelFunc
}

func (t *policyScanTx) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	t.pages++
	if t.failPage == t.pages {
		return nil, t.late
	}
	n := min(t.remaining, args[1].(int))
	out := &policyRows{start: t.returned, n: n}
	t.remaining -= n
	t.returned += n
	if t.remaining == 0 {
		out.lastErr = t.late
		out.afterScan = t.cancel
	}
	return out, nil
}
func scanPlan() *policyPlan {
	return &policyPlan{accounts: map[string]bool{}, guards: map[string]bool{"*": true}}
}
func TestPolicyDiscoveryReadsForeignLastPageAndClosesLateFailures(t *testing.T) {
	p := scanPlan()
	tx := &policyScanTx{remaining: 513}
	require.NoError(t, p.scan(context.Background(), tx, "source"))
	require.True(t, p.accounts["foreign-last"])
	require.Equal(t, 3, tx.pages)
	boom := errors.New("native source unavailable")
	p = scanPlan()
	tx = &policyScanTx{remaining: 513, late: boom}
	require.ErrorIs(t, p.scan(context.Background(), tx, "source"), boom)
	p = scanPlan()
	tx = &policyScanTx{remaining: 513, failPage: 3, late: boom}
	require.ErrorIs(t, p.scan(context.Background(), tx, "source"), boom)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p = scanPlan()
	tx = &policyScanTx{remaining: 513, cancel: cancel}
	require.ErrorIs(t, p.scan(ctx, tx, "source"), context.Canceled)
}
func TestPolicyDiscoveryPhysicalReadBudgetExactBoundary(t *testing.T) {
	for _, n := range []int{policyDiscoveryRows, policyDiscoveryRows + 1} {
		p := scanPlan()
		tx := &policyScanTx{remaining: n}
		err := p.scan(context.Background(), tx, "source")
		if n == policyDiscoveryRows {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errPolicyDiscoveryBudget)
		}
		require.Equal(t, n, p.rows)
	}
}
func TestPolicyPlanIndependentAccountsAndConservativeGlobal(t *testing.T) {
	a, b := scanPlan(), scanPlan()
	a.add("a", "user:alice", false)
	b.add("b", "user:bob", false)
	require.Equal(t, kaname.AuthorityFenceAccounts, a.intent(nil).Plan.Mode)
	require.NotEqual(t, a.intent(nil).Plan.Accounts, b.intent(nil).Plan.Accounts)
	a.add("", "", true)
	require.Equal(t, kaname.AuthorityFenceGlobal, a.intent(nil).Plan.Mode)
	require.Empty(t, a.intent(nil).Plan.Accounts)
	p := scanPlan()
	for i := 0; i <= kaname.MaxAuthorityFenceAccounts; i++ {
		p.add(fmt.Sprint(i), "", false)
	}
	require.True(t, p.global)
	for _, code := range []string{"40001", "40P01", "P1034"} {
		require.True(t, policyRetry(&pgconn.PgError{Code: code}))
	}
	require.False(t, policyRetry(&pgconn.PgError{Code: "42501"}))
	require.False(t, policyRetry(context.Canceled))
}

func TestPolicyPlanAccountOwnersCoverForeignSourcesWithoutChangingMutationRefs(t *testing.T) {
	p := scanPlan()
	p.request.kind = kaname.AuthorityRole
	p.request.owners = []kaname.AuthorityOwnerRef{{Kind: "role", ID: "old-role"}, {Kind: "account", ID: "target"}, {Kind: "account", ID: "target"}}
	original := append([]kaname.AuthorityOwnerRef{}, p.request.owners...)
	p.add("target", "", false)
	p.add("actor-home", "", false)
	p.add("foreign-last", "", false)
	p.finishClassification()
	in := p.intent(nil)
	require.False(t, p.global)
	require.Equal(t, kaname.AuthorityFenceAccounts, in.Plan.Mode)
	require.Equal(t, []domain.AccountID{"actor-home", "foreign-last", "target"}, in.Plan.Accounts)
	require.Equal(t, []kaname.AuthorityOwnerRef{{Kind: "role", ID: "old-role"}, {Kind: "account", ID: "target"}, {Kind: "account", ID: "actor-home"}, {Kind: "account", ID: "foreign-last"}}, in.Owners)
	require.Equal(t, original, p.request.owners)
	in.Owners[0].ID = "caller-mutated-copy"
	require.Equal(t, original, p.request.owners)
}

func TestPolicyPlanCombinedOwnerRefBudgetSelectsGlobalBeforeEpochRead(t *testing.T) {
	for _, n := range []int{kaname.MaxAuthorityOwnershipRefs - 1, kaname.MaxAuthorityOwnershipRefs} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			p := scanPlan()
			for i := 0; i < n; i++ {
				p.request.owners = append(p.request.owners, kaname.AuthorityOwnerRef{Kind: "role", ID: fmt.Sprintf("role-%03d", i)})
			}
			p.add("source-account", "", false)
			p.finishClassification()
			in := p.intent(nil)
			if n == kaname.MaxAuthorityOwnershipRefs-1 {
				require.False(t, p.global)
				require.Equal(t, kaname.AuthorityFenceAccounts, in.Plan.Mode)
				require.Len(t, in.Owners, kaname.MaxAuthorityOwnershipRefs)
			} else {
				require.True(t, p.global, "epoch selection must already use the global root token")
				require.Equal(t, kaname.AuthorityFenceGlobal, in.Plan.Mode)
				require.Empty(t, in.Plan.Accounts)
				require.Equal(t, p.request.owners, in.Owners, "global entry preserves all original mutation refs without oversized supplements")
			}
		})
	}
	// 256 уже названных account refs не становятся 512 refs при дополнении.
	p := scanPlan()
	for i := 0; i < kaname.MaxAuthorityOwnershipRefs; i++ {
		a := fmt.Sprintf("account-%03d", i)
		p.request.owners = append(p.request.owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		p.add(a, "", false)
	}
	p.finishClassification()
	require.False(t, p.global)
	require.Len(t, p.intent(nil).Owners, kaname.MaxAuthorityOwnershipRefs)
	require.Equal(t, kaname.AuthorityFenceAccounts, p.intent(nil).Plan.Mode)
}
