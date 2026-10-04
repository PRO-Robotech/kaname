// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
)

func initiatorIn(t *testing.T, ctx context.Context) string {
	t.Helper()
	p, ok := operations.PrincipalFromContextOK(ctx)
	require.True(t, ok, "в контексте нет принципала")
	i, err := auth.InitiatorOf(p)
	require.NoError(t, err)
	return i.String()
}

// TestJournalComponentRolesAreInitiators — каждая роль закрытого перечня даёт
// инициатора формы `system:kaname-<роль>`, принимаемой CHECK колонки.
func TestJournalComponentRolesAreInitiators(t *testing.T) {
	for _, role := range []string{
		shared.JournalComponentSeed, shared.JournalComponentReconciler, shared.JournalComponentSweeper,
		shared.JournalComponentRegistration, shared.JournalComponentProvisioning,
	} {
		ctx, err := shared.AsJournalComponent(context.Background(), role)
		require.NoError(t, err, role)
		require.Equal(t, "system:kaname-"+role, initiatorIn(t, ctx))
	}
}

func TestInitiatedOrJournalComponent(t *testing.T) {
	const role = shared.JournalComponentProvisioning
	usr := ids.NewID(ids.PrefixUser)

	t.Run("без принципала — компонент", func(t *testing.T) {
		ctx, err := shared.InitiatedOrJournalComponent(context.Background(), role)
		require.NoError(t, err)
		require.Equal(t, "system:kaname-"+role, initiatorIn(t, ctx))
	})
	t.Run("удостоверенный субъект — он и инициатор, контекст прежний", func(t *testing.T) {
		in := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: usr})
		ctx, err := shared.InitiatedOrJournalComponent(in, role)
		require.NoError(t, err)
		require.Equal(t, "user:"+usr, initiatorIn(t, ctx))
	})
	t.Run("отметка отсутствия субъекта {system, bootstrap} — компонент", func(t *testing.T) {
		in := operations.WithPrincipal(context.Background(), operations.SystemPrincipal())
		ctx, err := shared.InitiatedOrJournalComponent(in, role)
		require.NoError(t, err)
		require.Equal(t, "system:kaname-"+role, initiatorIn(t, ctx))
	})
	t.Run("снятый принципал — отказ", func(t *testing.T) {
		in := operations.WithoutPrincipal(operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: usr}))
		_, err := shared.InitiatedOrJournalComponent(in, role)
		require.Error(t, err)
		require.True(t, errors.Is(err, journaltx.ErrComponentOverPrincipal), "%v", err)
	})
	t.Run("строгий компонент поверх удостоверенного субъекта — отказ", func(t *testing.T) {
		in := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: usr})
		_, err := shared.AsJournalComponent(in, shared.JournalComponentRegistration)
		require.ErrorIs(t, err, journaltx.ErrComponentOverPrincipal)
	})
}
