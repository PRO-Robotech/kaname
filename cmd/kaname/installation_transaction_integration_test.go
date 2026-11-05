// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	"google.golang.org/protobuf/proto"
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

// Это настоящий контроль SQL/транзакции с начальным проверенным Given O.
// Он намеренно не заявляет покрытие действующего C или публичной краевой приёмки.
func TestInstallationTransactionRepairPoolOne(t *testing.T) {
	f := newInstallationBootstrapWorld(t, withPoolWidth(1))
	ctx, cancel := context.WithTimeout(f.principal, 30*time.Second)
	defer cancel()
	repo := kanamepg.New(f.world.pool, nil)
	ops := operations.NewRepo(f.world.pool, "kaname")
	create := accountapp.NewCreateAccountUseCase(repo, ops).WithRelationStore(f.relations, quietLogger())
	reads := kanamepg.NewInstallationReader(f.world.pool)
	initial, system, err := reads.InstallationAccounts(ctx, "", 1)
	require.NoError(t, err, "initial migration supplies canonical system account")
	require.EqualValues(t, 1, f.world.pool.Config().MaxConns)
	require.Len(t, initial, 1, "SETUP_FAILED: only O's initial tenant may precede ordinary creates")
	var admitted, maximum, windowSeconds int
	require.NoError(t, f.world.pool.QueryRow(ctx, `SELECT w.admitted,l.max_events,l.window_seconds
 FROM kaname.identity_admission_windows w JOIN kaname.users u ON u.external_id=w.carrier_id
 JOIN kaname.account_admission_rate_limits l ON l.kind=w.kind AND l.withdrawn_at IS NULL
 WHERE u.id=$1 AND w.kind='iam.account'`, string(f.world.user)).Scan(&admitted, &maximum, &windowSeconds))
	require.Equal(t, 1, admitted, "SETUP_FAILED: initial ceremony account charges the real trigger")
	require.Equal(t, 3, maximum, "SETUP_FAILED: fixture must preserve production admission policy")
	require.Equal(t, 3600, windowSeconds)
	t.Logf("fixture census: initial tenants=%d canonical system=1 admission=%d/%d window=%ds remaining=%d", len(initial), admitted, maximum, windowSeconds, maximum-admitted)
	var tenants []domain.AccountID
	// Начальная учётная запись церемонии уже израсходовала одно из трёх событий
	// допуска. Два штатных создания соблюдают эту неизменную производственную политику.
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("repair-tenant-%d", i)
		op, err := create.Execute(ctx, domain.Account{Name: domain.AccountName(name)})
		require.NoError(t, err, "SETUP_FAILED: ordinary account create index=%d", i)
		require.NoError(t, waitInstallationOperation(ctx, ops, op.ID), "SETUP_FAILED: account operation index=%d", i)
		done, err := ops.Get(ctx, op.ID)
		require.NoError(t, err)
		var result iamv1.Account
		require.NoError(t, done.Response.UnmarshalTo(&result))
		tenants = append(tenants, domain.AccountID(result.Id))
	}
	expected := append(append([]domain.AccountID{}, initial...), tenants...)
	sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
	require.NoError(t, f.world.pool.QueryRow(ctx, `SELECT w.admitted FROM kaname.identity_admission_windows w JOIN kaname.users u ON u.external_id=w.carrier_id WHERE u.id=$1 AND w.kind='iam.account'`, string(f.world.user)).Scan(&admitted))
	require.Equal(t, maximum, admitted, "both normal completed account operations must charge actual admission")
	t.Run("one connection full census and single target", func(t *testing.T) {
		page := &installationFailPage{}
		got, sys, err := reads.WithPageFactory(page).InstallationAccounts(ctx, "", 1)
		require.NoError(t, err)
		require.Equal(t, system, sys)
		require.Equal(t, 5, page.calls, "four rows plus terminal empty page")
		require.Equal(t, expected, got, "complete canonical membership, not a subset assertion")
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
		require.NoError(t, ops.Create(ctx, op)) // штатный производитель до границы записи
		writer, err := repo.Writer(ctx)
		require.NoError(t, err)
		cap, ok := writer.(installationTransactionControl)
		require.True(t, ok)
		require.NoError(t, cap.LockPendingInstallationOperation(ctx, op.ID, string(tenants[0]), proposed))
		require.NoError(t, cap.RequireInstallationAuthority(ctx, f.model.plans), "pool1 must progress with actual admitted O guard")
		metadata.Value = nil // несовпадающие/повреждённые метаданные никогда не должны привязываться
		require.Error(t, cap.BindInstallationOperation(ctx, op.ID, metadata, winning))
		actual, _ := anypb.New(&iamv1.CreateGrantDelegationMetadata{AccountId: string(tenants[0]), GrantDelegationId: winning})
		require.NoError(t, cap.BindInstallationOperation(ctx, op.ID, actual, winning))
		require.NoError(t, writer.Commit(ctx))
		stored, err := ops.Get(ctx, op.ID)
		require.NoError(t, err)
		require.False(t, stored.Done)
		require.Equal(t, op.Principal, stored.Principal)
		var value iamv1.CreateGrantDelegationMetadata
		require.NoError(t, stored.Metadata.UnmarshalTo(&value))
		require.Equal(t, winning, value.GrantDelegationId)
		var rawType, indexedResource, indexedAccount string
		var rawValue []byte
		require.NoError(t, f.world.pool.QueryRow(ctx, `SELECT metadata_type,metadata_data,resource_id,account_id FROM kaname.operations WHERE id=$1`, op.ID).Scan(&rawType, &rawValue, &indexedResource, &indexedAccount))
		require.Equal(t, actual.TypeUrl, rawType)
		require.Equal(t, actual.Value, rawValue)
		require.Equal(t, winning, indexedResource)
		require.Equal(t, string(tenants[0]), indexedAccount)
		var decoded iamv1.CreateGrantDelegationMetadata
		require.NoError(t, proto.Unmarshal(rawValue, &decoded))
		require.Equal(t, winning, decoded.GrantDelegationId)
		// Перезапуск, читающий штатную Operation, теперь видит настоящую идентичность ресурса;
		// За запись конечного состояния по-прежнему отвечает штатный механизм записи операций.
		require.NoError(t, ops.MarkDone(ctx, op.ID, nil))
		writer, err = repo.Writer(ctx)
		require.NoError(t, err)
		cap = writer.(installationTransactionControl)
		require.Error(t, cap.LockPendingInstallationOperation(ctx, op.ID, string(tenants[0]), winning), "terminal operation cannot authorize GD writes")
		require.NoError(t, writer.Rollback(ctx))
	})
}
