// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

func TestAccountListLabelFilterBeforePagination(t *testing.T) {
	if testing.Short() {
		t.Skip("проверка требует PostgreSQL")
	}
	const labelKey = "team/platform@v2"
	r, installer := writerProtocolRigBeforePreparation(t)
	ctx := r.ctx

	owner := mustSeedUser(t, ctx, r.admin, "l1043")
	otherOwner := mustSeedUser(t, ctx, r.admin, "l1043-other")
	var missing domain.AccountID
	require.NoError(t, r.admin.QueryRow(ctx, "SELECT account_id FROM users WHERE id = $1", owner).Scan(&missing))
	wr, err := installer.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(ctx) }()
	insert := func(owner domain.UserID, name, value string) domain.AccountID {
		account := newAccount(name, owner)
		account.Labels = domain.Labels{labelKey: domain.LabelVal(value), "env": "dev"}
		out, err := wr.AccountsW().Insert(ctx, account)
		require.NoError(t, err)
		return out.ID
	}
	first := insert(owner, "acc-l1043-first", "")
	second := insert(owner, "acc-l1043-second", "")
	nonempty := insert(otherOwner, "acc-l1043-nonempty", "dev")
	insert(otherOwner, "acc-l1043-outside", "")
	require.NoError(t, wr.Commit(ctx))

	// Установщик объявляет точную пару и выдаёт Apply владельцу аккаунта.
	// Саму метку фиксирует штатный защищённый Account.Update.
	definition, err := installer.AddAccessLabelValues(ctx, kanamepg.AccessLabelDeclaration{
		Account: r.a, Module: "iam", Resource: "account", Key: labelKey, Values: []string{""},
	})
	require.NoError(t, err)
	require.NoError(t, installer.PrepareAuthorityBundle(ctx, r.bundle))
	world := metadataFixtureModeWithRig(t, false, "full", r)
	_, err = installer.IssueInitialAccessLabelApply(ctx, kanamepg.InitialAccessLabelApply{
		Account: r.a, DefinitionID: domain.AccessLabelDefinitionID(definition.ID), ExpectedRevision: definition.Revision,
	}, r.bundle)
	require.NoError(t, err)
	ports, err := world.factory.WithInstalledAccessLabels(ctx)
	require.NoError(t, err)
	update := accountapp.NewUpdateAccountUseCase(world.full, world.ops).
		WithRelationStore(world.door, nil).WithAccountMetadataWriter(ports)
	op, err := update.Execute(declarerCtx(ctx, bindingPublicOwner(t, r)), accountapp.UpdateAccountInput{
		ID: world.account.ID, UpdateMask: []string{"access_labels"}, AccessLabels: domain.Labels{labelKey: ""},
	})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, ctx, world.ops, op.ID).Error)

	rd, err := world.full.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	protected, err := rd.Accounts().Get(ctx, world.account.ID)
	require.NoError(t, err)
	require.Equal(t, domain.Labels{labelKey: ""}, protected.AccessLabels)
	require.NotContains(t, protected.Labels, domain.LabelKey(labelKey))

	f := repoaccount.ListFilter{
		Filter:   `labels.` + labelKey + ` = ""`,
		PageSize: 1,
		Candidates: &visibility.PageScope{
			ObjectIDs: []string{string(missing), string(first), string(second), string(nonempty), string(protected.ID)},
		},
	}
	out, next, err := rd.Accounts().List(ctx, f)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.NotEmpty(t, next)
	got := []domain.AccountID{out[0].ID}

	f.PageToken = next
	out, next, err = rd.Accounts().List(ctx, f)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Empty(t, next)
	require.ElementsMatch(t, []domain.AccountID{first, second}, append(got, out[0].ID))

	f.Filter = `accessLabels.` + labelKey + ` = ""`
	f.PageToken = ""
	out, next, err = rd.Accounts().List(ctx, f)
	require.ErrorIs(t, err, iamerr.ErrInvalidArg)
	require.Empty(t, out)
	require.Empty(t, next)
}
