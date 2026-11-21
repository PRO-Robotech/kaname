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
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type groupNativeObservedFactory struct {
	*kanamepg.GrantPolicyWriters
	account, foreign string
	opened           atomic.Int32
}

func (f *groupNativeObservedFactory) GroupAdditionAuthorityWriter(ctx context.Context, m domain.GroupMember, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	w, err := f.GrantPolicyWriters.GroupAdditionAuthorityWriter(ctx, m, actor)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (kaname.SemanticAuthorityWriter, error) {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, w.Rollback(c))
	}
	if w.AuthorityFence().Mode() != kaname.AuthorityFenceAccounts {
		return fail(fmt.Errorf("GROUP boundary unexpectedly GLOBAL"))
	}
	subject := string(actor.Type) + ":" + string(actor.ID)
	ok, err := w.SemanticRelationChecker().Check(ctx, subject, "admin", "account:"+f.account)
	if err != nil || !ok {
		return fail(fmt.Errorf("declared live native admin allowed=%v err=%v", ok, err))
	}
	_, err = w.SemanticRelationChecker().Check(ctx, subject, "v_update", "iam_group:"+string(m.GroupID))
	if err != nil {
		return fail(err)
	}
	ok, err = w.SemanticRelationChecker().Check(ctx, subject, "admin", "account:"+f.foreign)
	if ok || !errors.Is(err, kaname.ErrSourceUnconfirmed) {
		return fail(fmt.Errorf("undeclared GROUP root allowed=%v err=%v", ok, err))
	}
	f.opened.Add(1)
	return w, nil
}
func TestGroupNativeBoundaryActualAdditionAndTypedRecipient(t *testing.T) {
	r := writerProtocolRig(t)
	g, _, sa := membershipFixture(t, r)
	actorID := seedMemberUser(t, r.ctx, r.admin, r.a, "group-native-admin")
	require.NotEqual(t, bindingPublicOwner(t, r), actorID)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actorID)
	require.NoError(t, err)
	bid := groupLifecycleBinding(t, r, r.a, actorID, "group_native_admin", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}})
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, bid))
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND relation='admin' AND object=$2 AND fga_user=$3`, bid, "account:"+r.a, "user:"+actorID).Scan(&holders))
	require.Positive(t, holders)
	membershipBinding(t, r, string(g.ID), r.a, "ACTIVE", false)
	membershipBinding(t, r, string(g.ID), r.a, "PENDING", true)
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	observer := &groupNativeObservedFactory{GrantPolicyWriters: writers, account: r.a, foreign: r.b}
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	ops := operations.NewRepo(r.runtime, "kaname")
	add := groupapp.NewAddMemberUseCase(r.repo, ops).WithGroupAdditionAuthorityWriter(observer)
	op, err := add.Execute(declarerCtx(r.ctx, actorID), groupapp.AddMemberInput{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(sa)})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
	require.EqualValues(t, 1, observer.opened.Load())
	membershipCounts(t, r, string(g.ID), "service_account:"+sa, 1)
	authorityWaitReleased(t, r.runtime)
}

// Поздний дополнительный субъект обязан объявить scope и exact role даже в
// PENDING. Проверяем реальный SQL keyset, защищённый checker и итоговый UC deny.
func TestGroupNativeBoundaryPendingAdditionalCarrierAfterPage(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, sa := membershipFixture(t, r)
	// Batch seed разных source roles сохраняет active-grant uniqueness:
	// deferred subject CHECK исполняется при атомарном COMMIT.
	membershipBinding(t, r, string(g.ID), r.a, "ACTIVE", false)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) SELECT 'rol'||lpad(n::text,16,'0'),$1,'group_native_'||n,'[]','[{"module":"iam","resources":["account"],"verbs":["get"]}]' FROM generate_series(1,256) n`, r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) SELECT 'acb'||lpad(n::text,16,'0'),'group',$1,'rol'||lpad(n::text,16,'0'),'account',$2,'ACTIVE' FROM generate_series(1,256) n`, string(g.ID), r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) SELECT id,subject_type,subject_id FROM kaname.access_bindings WHERE id BETWEEN 'acb0000000000000001' AND 'acb0000000000000256'`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
	late := membershipBinding(t, r, string(g.ID), r.b, "PENDING", true)
	require.True(t, late > "acb0000000000000256", "late carrier должен следовать за полной страницей")
	var role domain.RoleID
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT role_id FROM kaname.access_bindings WHERE id=$1`, late).Scan(&role))
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	m := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(sa)}
	w, err := writers.GroupAdditionAuthorityWriter(r.ctx, m, actor)
	require.NoError(t, err)
	roleFinalCleanup(t, w)
	require.Equal(t, kaname.AuthorityFenceAccounts, w.AuthorityFence().Mode())
	require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, w.AuthorityFence().Accounts())
	// Нет grant на B: false без unconfirmed доказывает declared negative root.
	ok, err := w.SemanticRelationChecker().Check(r.ctx, "user:"+uid, "admin", "account:"+r.b)
	require.NoError(t, err)
	require.False(t, ok)
	ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, Anchor: domain.ScopeAnchor{Type: "account", ID: r.b}, RoleID: role})
	require.NoError(t, err)
	ok, err = w.SemanticRelationChecker().Check(r.ctx, "user:"+uid, ref.Relation, ref.ObjectType+":"+ref.ObjectID)
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, w.Rollback(r.ctx))
	ops := operations.NewRepo(r.runtime, "kaname")
	add := groupapp.NewAddMemberUseCase(r.repo, ops).WithGroupAdditionAuthorityWriter(writers)
	op, err := add.Execute(declarerCtx(r.ctx, uid), groupapp.AddMemberInput{GroupID: g.ID, MemberType: m.MemberType, MemberID: m.MemberID})
	require.NoError(t, err)
	done := awaitOperation(t, r.ctx, ops, op.ID)
	require.NotNil(t, done.Error)
	require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
	membershipCounts(t, r, string(g.ID), "service_account:"+sa, 0)
	authorityWaitReleased(t, r.runtime)
}
