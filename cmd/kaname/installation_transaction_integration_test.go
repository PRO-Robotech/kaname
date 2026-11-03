// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

type installationTransactionControl interface {
	LockPendingInstallationOperation(context.Context, string, string, string) error
	RequireInstallationAuthority(context.Context, *authzmodel.Plans) error
	BindInstallationOperation(context.Context, string, *anypb.Any, string) error
}

type installationFailPage struct {
	calls int
	fail  int
	cause error
}

func (p *installationFailPage) BeginTx(ctx context.Context, tx pgx.Tx, options pgx.TxOptions) (pgx.Tx, error) {
	p.calls++
	if p.calls == p.fail {
		return nil, p.cause
	}
	return (kanamepg.NestedInstallationPages{}).BeginTx(ctx, tx, options)
}

// This is a real SQL/transaction control using the initial verified O Given.
// It deliberately does not claim standing C or public edge acceptance coverage.
func TestInstallationTransactionRepairPoolOne(t *testing.T) {
	f := newInstallationBootstrapWorld(t, withPoolWidth(1))
	ctx, cancel := context.WithTimeout(f.principal, 30*time.Second)
	defer cancel()
	repo := kanamepg.New(f.world.pool, nil)
	ops := operations.NewRepo(f.world.pool, "kaname")
	create := accountapp.NewCreateAccountUseCase(repo, ops).WithRelationStore(f.relations, quietLogger())
	reads := kanamepg.NewInstallationReader(f.world.pool)
	_, system, err := reads.InstallationAccounts(ctx, "", 1)
	require.NoError(t, err, "initial migration supplies canonical system account")
	var tenants []domain.AccountID
	// The initial ceremony account already charged one of the three admission
	// events. Two ordinary creates respect that unchanged production policy.
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("repair-tenant-%d", i)
		op, err := create.Execute(ctx, domain.Account{Name: domain.AccountName(name)})
		require.NoError(t, err)
		require.NoError(t, waitInstallationOperation(ctx, ops, op.ID))
		done, err := ops.Get(ctx, op.ID)
		require.NoError(t, err)
		var result iamv1.Account
		require.NoError(t, done.Response.UnmarshalTo(&result))
		tenants = append(tenants, domain.AccountID(result.Id))
	}
	t.Run("one connection full census and single target", func(t *testing.T) {
		page := &installationFailPage{}
		got, sys, err := reads.WithPageFactory(page).InstallationAccounts(ctx, "", 1)
		require.NoError(t, err)
		require.Equal(t, system, sys)
		require.GreaterOrEqual(t, page.calls, 5)
		for _, id := range tenants {
			require.Contains(t, got, id)
		}
		require.NotContains(t, got, system)
		require.IsIncreasing(t, got)
		one, _, err := reads.InstallationAccounts(ctx, string(tenants[0]), 2)
		require.NoError(t, err)
		require.Equal(t, []domain.AccountID{tenants[0]}, one)
		require.Zero(t, f.world.pool.Stat().AcquiredConns())
	})
	t.Run("late nested BeginTx fault releases coordinator", func(t *testing.T) {
		cause := errors.New("unknown page BeginTx failure")
		pages := &installationFailPage{fail: 3, cause: cause}
		got, _, err := reads.WithPageFactory(pages).InstallationAccounts(ctx, "", 1)
		require.ErrorIs(t, err, cause)
		require.Nil(t, got)
		require.Equal(t, 3, pages.calls)
		require.Zero(t, f.world.pool.Stat().AcquiredConns())
	})
	t.Run("incompatible nested transaction options refused", func(t *testing.T) {
		tx, err := f.world.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		_, err = (kanamepg.NestedInstallationPages{}).BeginTx(ctx, tx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
		require.Error(t, err)
		require.NoError(t, tx.Rollback(ctx))
	})
	t.Run("authority and operation bind share held writer", func(t *testing.T) {
		proposed := ids.NewID(domain.PrefixGrantDelegation)
		winning := ids.NewID(domain.PrefixGrantDelegation)
		metadata, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{AccountId: string(tenants[0]), GrantDelegationId: proposed})
		op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM, "installation SQL boundary control", &iamv1.CreateGrantDelegationMetadata{AccountId: string(tenants[0]), GrantDelegationId: proposed})
		require.NoError(t, err)
		require.NoError(t, ops.Create(ctx, op)) // ordinary producer before writer boundary
		writer, err := repo.Writer(ctx)
		require.NoError(t, err)
		cap, ok := writer.(installationTransactionControl)
		require.True(t, ok)
		require.NoError(t, cap.LockPendingInstallationOperation(ctx, op.ID, string(tenants[0]), proposed))
		require.NoError(t, cap.RequireInstallationAuthority(ctx, f.model.plans), "pool1 must progress with actual admitted O guard")
		metadata.Value = nil // mismatched/corrupt metadata must never bind
		require.Error(t, cap.BindInstallationOperation(ctx, op.ID, metadata, winning))
		actual, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{AccountId: string(tenants[0]), GrantDelegationId: winning})
		require.NoError(t, cap.BindInstallationOperation(ctx, op.ID, actual, winning))
		require.NoError(t, writer.Commit(ctx))
		stored, err := ops.Get(ctx, op.ID)
		require.NoError(t, err)
		require.False(t, stored.Done)
		require.Equal(t, winning, stored.ResourceID)
		require.Equal(t, op.Principal, stored.Principal)
		var value iamv1.CreateGrantDelegationMetadata
		require.NoError(t, stored.Metadata.UnmarshalTo(&value))
		require.Equal(t, winning, value.GrantDelegationId)
		// A restart reading the normal Operation now sees the actual resource identity;
		// terminalization is still the normal operations writer's responsibility.
		require.NoError(t, ops.MarkDone(ctx, op.ID, nil))
		writer, err = repo.Writer(ctx)
		require.NoError(t, err)
		cap = writer.(installationTransactionControl)
		require.Error(t, cap.LockPendingInstallationOperation(ctx, op.ID, string(tenants[0]), winning), "terminal operation cannot authorize GD writes")
		require.NoError(t, writer.Rollback(ctx))
	})
}
