// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// В тестовом каталоге владелец аккаунта имеет прямое право. Выдачу для
// пользователя создаёт штатный писатель, который записывает факт и его источник.
func TestUserChildAuthorizationRRRequiresCurrentHumanGrant(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	actor := seedMemberUser(t, r.ctx, r.admin, r.a, "child-authorization")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	binding := sevenCRUDSystemRelation(t, r, actor, "account", r.a, "owner")
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.admin).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		_, err := w.UpsertResource(ctx, catalog.ResourceRow{Module: "iam", Resource: "authorizationChild", ObjectType: "authorization_child", ParentNames: []string{"parent"}, ParentTypes: []string{"account"}, ChildRegistration: &catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 4, MaxCreates: 2, WindowSeconds: 60}})
		if err != nil {
			return err
		}
		_, err = w.UpsertVerb(ctx, catalog.VerbRow{Module: "iam", Resource: "authorizationChild", Verb: "registerchild", ContainerParent: "account", ContainerRelation: "owner"})
		return err
	}))
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(r.ctx, r.bundle.ModelSource()+"\ntype authorization_child\n  relations\n    define parent: [account]\n", halves, granteffect.ProjectorVersion)
	require.NoError(t, err)
	input := kaname.UserChildRegistrationInput{ResourceType: "iam.authorizationChild", ResourceID: r.a + "/candidate"}
	principal := operations.Principal{Type: "user", ID: actor}
	ctx := operations.WithPrincipal(r.ctx, principal)
	open := func(t *testing.T) pgx.Tx {
		t.Helper()
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(r.ctx)) })
		return tx
	}
	assertNoRegistrationReads := func(t *testing.T, queries []string) {
		t.Helper()
		for _, sql := range queries {
			require.NotContains(t, sql, "_authority_child_registration_capture")
			require.NotContains(t, sql, "authority_child_creation")
			require.NotContains(t, sql, "authority_child_parent_state")
		}
	}
	t.Run("unbound or mismatched identity is refused before SQL", func(t *testing.T) {
		cases := []struct {
			name      string
			ctx       context.Context
			principal operations.Principal
		}{
			{"absent", r.ctx, principal},
			{"machine", operations.WithPrincipal(r.ctx, operations.Principal{Type: "service_account", ID: actor}), operations.Principal{Type: "service_account", ID: actor}},
			{"mismatched", ctx, operations.Principal{Type: "user", ID: actor + "other"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, queries, err := kanamepg.ProbeUserChildAuthorization(tc.ctx, open(t), bundle, input, tc.principal)
				require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
				require.Empty(t, queries)
			})
		}
	})
	t.Run("authorized exact parent captures native guards", func(t *testing.T) {
		target, guards, queries, err := kanamepg.ProbeUserChildAuthorization(ctx, open(t), bundle, input, principal)
		require.NoError(t, err)
		require.Equal(t, "account:"+r.a, target.ParentObject)
		require.Equal(t, "owner", target.ParentAction)
		require.NotEmpty(t, guards)
		require.NotEmpty(t, queries)
		assertNoRegistrationReads(t, queries)
	})
	t.Run("unverified address is denied before registration capture", func(t *testing.T) {
		_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, actor)
		require.NoError(t, err)
		_, _, queries, err := kanamepg.ProbeUserChildAuthorization(ctx, open(t), bundle, input, principal)
		require.Error(t, err)
		assertNoRegistrationReads(t, queries)
		for _, sql := range queries {
			require.NotContains(t, sql, "authority_policy_epoch_read")
		}
		_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
		require.NoError(t, err)
	})
	t.Run("expired source cannot use a stale positive relation fact", func(t *testing.T) {
		_, err := r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 day' WHERE id=$1`, binding)
		require.NoError(t, err)
		tx := open(t)
		var at time.Time
		require.NoError(t, tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at))
		ordinary := authzcascade.WrapAdmitted(relverdict.NewSemanticTransactionAsker(tx, bundle, at), personmarks.NewTransaction(tx))
		allowed, err := ordinary.Check(ctx, "user:"+actor, "owner", "account:"+r.a)
		require.NoError(t, err)
		require.True(t, allowed, "the emitted fact remains a stale positive in this exact RR snapshot")
		_, _, queries, err := kanamepg.ProbeUserChildAuthorization(ctx, tx, bundle, input, principal)
		require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
		assertNoRegistrationReads(t, queries)
		require.True(t, strings.Contains(strings.Join(queries, "\n"), "access_bindings"), "the production helper checked the current binding source")
	})
}
