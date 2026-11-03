// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// renewOperator performs another actual ceremony/code exchange for the SAME O.
// A one-hour RID08 wait must not substitute a different actor or reuse an expired
// bearer. The initial session and interactive client are the approved F0 Given.
func (f *installationBootstrapWorld) renewOperator(t *testing.T, ctx context.Context) context.Context {
	t.Helper()
	fresh := f.world.redeem(f.world.issueCode(f.world.ic1, lineA1R))
	f.operatorToken = fresh.AccessToken
	return f.verifyOperator(t, ctx)
}

func (f *installationStandingWorld) createTenant(t *testing.T, ctx context.Context, name string) domain.AccountID {
	t.Helper()
	verified := f.verifyOperator(t, ctx)
	require.NoError(t, authzguard.RequireClusterAdmin(verified, f.relations))
	create := accountapp.NewCreateAccountUseCase(kanamepg.New(f.world.pool, nil), f.ops).WithRelationStore(f.relations, quietLogger())
	op, err := create.Execute(verified, domain.Account{Name: domain.AccountName(name)})
	require.NoError(t, err, "same O ordinary Account.Create must satisfy actual admission policy")
	require.NoError(t, waitInstallationOperation(verified, f.ops, op.ID))
	saved, err := f.ops.Get(verified, op.ID)
	require.NoError(t, err)
	var account iamv1.Account
	require.NoError(t, saved.Response.UnmarshalTo(&account))
	actor, ok := operations.PrincipalFromContextOK(verified)
	require.True(t, ok)
	require.Equal(t, string(f.world.user), actor.ID)
	return domain.AccountID(account.Id)
}

// threeTenants consumes precisely the legitimate 1(initial A)+2(B,T) budget.
// The tenant named system-tenant is not the canonical system account.
func (f *installationStandingWorld) threeTenants(t *testing.T, ctx context.Context) []domain.AccountID {
	t.Helper()
	reader := kanamepg.NewInstallationReader(f.world.pool)
	initial, system, err := reader.InstallationAccounts(ctx, "", 2)
	require.NoError(t, err)
	require.Len(t, initial, 1, "fresh F0 must have only O's initial tenant")
	admitted, limit, window, _ := f.admissionWindow(t, ctx)
	require.Equal(t, 1, admitted)
	require.Equal(t, 3, limit)
	require.Equal(t, 3600, window)
	got := append([]domain.AccountID{}, initial...)
	got = append(got, f.createTenant(t, ctx, "rid-b"), f.createTenant(t, ctx, "system-tenant"))
	require.NotContains(t, got, system)
	admitted, limit, _, _ = f.admissionWindow(t, ctx)
	require.Equal(t, limit, admitted)
	return got
}

// Read-only observation of the REAL trigger/window, never a clock override or
// admission mutation. remaining is measured by the database's own clock.
func (f *installationStandingWorld) admissionWindow(t *testing.T, ctx context.Context) (admitted, limit, seconds int, remaining time.Duration) {
	t.Helper()
	var nanos float64
	err := f.world.pool.QueryRow(ctx, `SELECT w.admitted,l.max_events,l.window_seconds,
 GREATEST(0,EXTRACT(EPOCH FROM (w.window_started_at + make_interval(secs=>l.window_seconds) - clock_timestamp())))
 FROM kaname.identity_admission_windows w
 JOIN kaname.users u ON u.external_id=w.carrier_id
 JOIN kaname.account_admission_rate_limits l ON l.kind=w.kind AND l.withdrawn_at IS NULL
 WHERE u.id=$1 AND w.kind='iam.account'`, string(f.world.user)).Scan(&admitted, &limit, &seconds, &nanos)
	require.NoError(t, err)
	return admitted, limit, seconds, time.Duration(nanos * float64(time.Second))
}

// awaitAdmissionWindow is called BEFORE the RID08 snapshot/first-pair barrier,
// so a writer transaction or normal Operation never sits blocked for an hour.
// Other already-frozen cases may run while the controller waits. After return,
// freeze N3, prove the barrier arrival, then same O creates D normally.
func (f *installationStandingWorld) awaitAdmissionWindow(t *testing.T, ctx context.Context) {
	t.Helper()
	for {
		admitted, limit, seconds, remaining := f.admissionWindow(t, ctx)
		require.Equal(t, 3, limit)
		require.Equal(t, 3600, seconds)
		require.Equal(t, 3, admitted)
		if remaining <= 0 {
			f.renewOperator(t, ctx)
			return
		}
		timer := time.NewTimer(remaining + 20*time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatalf("NOT_EXECUTED: actual O admission window did not expire within leased deadline: %v", ctx.Err())
		case <-timer.C:
		}
	}
}
