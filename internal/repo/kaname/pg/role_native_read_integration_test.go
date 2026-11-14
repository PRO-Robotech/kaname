// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

// Observer возвращает ORIGINAL writer: optional prepared ports не теряются.
// Проверка native ответа не подменяет policy; обычный UC затем исполняет её сам.
type roleNativeObservedFactory struct {
	*kanamepg.GrantPolicyWriters
	account, foreign string
	opened           atomic.Int32
}

func (f *roleNativeObservedFactory) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	w, err := f.GrantPolicyWriters.RoleMutationWriter(ctx, request, actor)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (kaname.SemanticAuthorityWriter, error) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, w.Rollback(cleanup))
	}
	if w.AuthorityFence().Mode() != kaname.AuthorityFenceAccounts {
		return fail(fmt.Errorf("ROLE native boundary unexpectedly GLOBAL"))
	}
	subject := string(actor.Type) + ":" + string(actor.ID)
	ok, err := w.SemanticRelationChecker().Check(ctx, subject, "admin", "account:"+f.account)
	if err != nil || !ok {
		return fail(fmt.Errorf("declared native admin: allowed=%v err=%v", ok, err))
	}
	ok, err = w.SemanticRelationChecker().Check(ctx, subject, "admin", "account:"+f.foreign)
	if ok || !errors.Is(err, kaname.ErrSourceUnconfirmed) {
		return fail(fmt.Errorf("undeclared ROLE root: allowed=%v err=%v", ok, err))
	}
	f.opened.Add(1)
	return w, nil
}
func TestRoleNativeBoundaryActualCreateRulesMetadataAndLowerFactory(t *testing.T) {
	r := writerProtocolRig(t)
	actorID := seedMemberUser(t, r.ctx, r.admin, r.a, "role-native-boundary-admin")
	require.NotEqual(t, bindingPublicOwner(t, r), actorID)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actorID)
	require.NoError(t, err)
	adminBinding := groupLifecycleBinding(t, r, r.a, actorID, "role_native_boundary_admin", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}})
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, adminBinding))
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND relation='admin' AND object=$2 AND fga_user=$3`, adminBinding, "account:"+r.a, "user:"+actorID).Scan(&holders))
	require.Positive(t, holders, "actual materialized source, не raw allow")
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	observer := &roleNativeObservedFactory{GrantPolicyWriters: writers, account: r.a, foreign: r.b}
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	ops := operations.NewRepo(r.runtime, "kaname")
	create := roleapp.NewCreateRoleUseCase(r.repo, ops, source).WithRoleAuthorityWriter(observer)
	update := roleapp.NewUpdateRoleUseCase(r.repo, ops, source).WithRoleAuthorityWriter(observer)
	ordinary := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	op, err := create.Execute(declarerCtx(r.ctx, actorID), domain.Role{AccountID: domain.AccountID(r.a), Name: "native_role_boundary", Rules: ordinary})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	var id domain.RoleID
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name='native_role_boundary'`, r.a).Scan(&id))
	description := domain.Description("native metadata")
	op, err = update.Execute(declarerCtx(r.ctx, actorID), roleapp.UpdateRoleInput{ID: id, Description: &description, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	changed := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}}}
	op, err = update.Execute(declarerCtx(r.ctx, actorID), roleapp.UpdateRoleInput{ID: id, Rules: changed, UpdateMask: []string{"rules"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.EqualValues(t, 3, observer.opened.Load(), "все три actual UC используют protected question boundary")
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actorID)}
	full := domain.Role{ID: id, AccountID: domain.AccountID(r.a), Rules: changed}
	w, err := writers.RoleAuthorityWriter(r.ctx, full, false, actor)
	if w != nil {
		roleFinalCleanup(t, w)
	}
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode())
	ok, err := w.SemanticRelationChecker().Check(r.ctx, "user:"+actorID, "admin", "account:"+r.b)
	require.False(t, ok)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.Rollback(r.ctx))
	// Старый incomplete factory не объявляет nil Rules полным NEW contract.
	full.Rules = nil
	w, err = writers.RoleAuthorityWriter(r.ctx, full, false, actor)
	if w != nil {
		roleFinalCleanup(t, w)
	}
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode())
	require.NoError(t, w.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
