// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestNativeBoundaryActualBindingCreateAndMissingQuestion(t *testing.T) {
	r := writerProtocolRig(t)
	seed := stageBinding(t, r, r.a, false)
	template := bindingRow(t, r, seed)
	// Получатель нового Create отличается от уже активного seed; actor не owner.
	recipient := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(seedSAID(t, r.ctx, r.admin, r.a, "native-boundary-recipient"))}
	require.NotContains(t, template.Subjects, recipient)
	actorID := seedMemberUser(t, r.ctx, r.admin, r.a, "native-boundary-admin")
	require.NotEqual(t, bindingPublicOwner(t, r), actorID)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actorID)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actorID)}
	// Настоящие role/selector/verb projection и binding создаются до activation.
	// Узкий account wildcard выводит scope-self admin без container/global правил.
	adminBinding := groupLifecycleBinding(t, r, r.a, actorID, "native_boundary_admin", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}})
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, adminBinding))
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_type='iam.account' AND member_object_id=$2 AND fga_user=$3 AND relation='admin' AND object=$4`, string(adminBinding), r.a, "user:"+actorID, "account:"+r.a).Scan(&holders))
	require.Positive(t, holders, "Дано: admin материализован production reconciler из живого binding")
	allowed, err := (delegationNativeDoor{r: r}).Check(r.ctx, "user:"+actorID, "admin", "account:"+r.a)
	require.NoError(t, err)
	require.True(t, allowed)
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	ops := operations.NewRepo(r.runtime, "kaname")
	uc := bindingapp.NewCreateAccessBindingUseCase(r.repo, ops, rolePolicyCatalog(t, r)).WithBindingDecisions(writers)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{recipient}, Target: domain.AccessTarget{AllInScope: true}}
	// Новый proposal ещё не записан: create=true выбирает локальный план.
	// Callback только читает; последующий public Create выполняет реальные gates
	// и запись той же выдачи, поэтому здесь не появляется duplicate ACTIVE grant.
	proposed := input
	proposed.ID = domain.AccessBindingID(ids.NewID("acb"))
	err = writers.RunBindingDecision(r.ctx, actor, proposed, true, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, _ domain.AccessBinding, _ domain.Role) error {
		require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode(), "create native вопрос проходит локальный captured scope SQL")
		ok, e := w.SemanticRelationChecker().Check(ctx, "user:"+actorID, "admin", "account:"+r.a)
		require.NoError(t, e)
		require.True(t, ok)
		ok, e = w.SemanticRelationChecker().Check(ctx, "user:"+actorID, "admin", "account:"+r.b)
		require.False(t, ok)
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		return nil
	})
	require.NoError(t, err)
	op, err := uc.Execute(declarerCtx(r.ctx, actorID), input)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	// Metadata runner открывает настоящий protected writer. Разрешённый вопрос
	// остаётся native, отсутствующий root не дополняет граф после coordinator.
	err = writers.RunBindingDecision(r.ctx, actor, template, false, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, _ domain.AccessBinding, _ domain.Role) error {
		require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode(), "metadata заранее выбирает GLOBAL для binding-AS-OBJECT")
		ok, e := w.SemanticRelationChecker().Check(ctx, "user:"+actorID, "admin", "account:"+r.a)
		require.NoError(t, e)
		require.True(t, ok)
		ok, e = w.SemanticRelationChecker().Check(ctx, "user:"+actorID, "admin", "account:"+r.b)
		require.False(t, ok)
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		return nil
	})
	require.NoError(t, err)
	authorityWaitReleased(t, r.runtime)
}
