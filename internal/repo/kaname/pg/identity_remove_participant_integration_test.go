// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func identityRemoveMember(t *testing.T, r protocolRig, suffix string) domain.UserID {
	t.Helper()
	uid := seedMemberUser(t, r.ctx, r.admin, r.a, suffix)
	// Дополнительное членство создаётся до активации; идентификатор выдаёт
	// тот же серверный канон, что и обычное приглашение существующей личности.
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.memberships (id,user_id,account_id,state)
 VALUES (kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE')`, uid, r.b)
	require.NoError(t, err)
	return domain.UserID(uid)
}

func identityRemoveExecute(t *testing.T, r protocolRig, f kaname.IdentityLifecycleWriterFactory, uid domain.UserID, account string) *operations.Operation {
	t.Helper()
	ops := operations.NewRepo(r.runtime, "kaname")
	ctx := declarerCtx(r.ctx, bindingPublicOwner(t, r))
	op, err := userapp.NewRemoveFromAccountUseCase(r.repo, ops).WithIdentityLifecycleWriter(f).
		Execute(ctx, uid, domain.AccountID(account))
	require.NoError(t, err)
	return awaitOperation(t, ctx, ops, op.ID)
}

// Полные строки сохраняют поля личности и обоих членств. Структурное намерение
// удаления ищется по object, а не только по user: у него user обозначает аккаунт.
func identityRemoveSnapshot(t *testing.T, r protocolRig, uid domain.UserID) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'user',(SELECT to_jsonb(u) FROM kaname.users u WHERE id=$1),
 'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.account_id),'[]'::jsonb) FROM kaname.memberships m WHERE user_id=$1),
 'identity_cutoff',(SELECT to_jsonb(c) FROM kaname.user_token_revocations c WHERE user_id=$1),
 'minted_cutoff',(SELECT to_jsonb(c) FROM kaname.minted_token_revocations c WHERE subject=$1),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM kaname.audit_outbox a WHERE event_payload->>'resource_id'=$1),
 'reconcile',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]'::jsonb) FROM kaname.resource_reconcile_outbox o WHERE object_id=$1),
 'fga',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.id),'[]'::jsonb) FROM kaname.fga_outbox f WHERE payload->>'user'='user:'||$1 OR payload->>'object'='iam_user:'||$1)
 )::text`, string(uid)).Scan(&snapshot))
	return snapshot
}

func identityRemoveUserRow(t *testing.T, r protocolRig, uid domain.UserID) string {
	t.Helper()
	var row string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(u)::text FROM kaname.users u WHERE id=$1`, string(uid)).Scan(&row))
	return row
}

// Обычный LOGIN, MaxConns=1 и настоящий worker в обоих режимах протокола.
// Исключение из B сохраняет личность и членство в A; повтор не пишет ложный аудит.
func TestIdentityRemoveFromAccountActualWorkersPreparedAndStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := identityLifecycleSingle(t, writerProtocolRig(t))
			uid := identityRemoveMember(t, r, "identity-remove")
			before := identityRemoveUserRow(t, r, uid)
			p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
			require.NoError(t, err)
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			require.Nil(t, identityRemoveExecute(t, r, p, uid, r.b).Error)
			require.Equal(t, before, identityRemoveUserRow(t, r, uid))
			var remaining []string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT array_agg(account_id ORDER BY account_id) FROM kaname.memberships WHERE user_id=$1`, string(uid)).Scan(&remaining))
			require.Equal(t, []string{r.a}, remaining)
			var audits, deletes int
			query := `SELECT
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.user.removed_from_account' AND event_payload->>'resource_id'=$1 AND event_payload->>'account_id'=$2),
 (SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'user'='account:'||$2 AND ` + fga_outbox.RelationPredicate("payload", "'account'") + ` AND payload->>'object'='iam_user:'||$1)`
			require.NoError(t, r.admin.QueryRow(r.ctx, query, string(uid), r.b).Scan(&audits, &deletes))
			require.Equal(t, 1, audits)
			require.Equal(t, 1, deletes)
			after := identityRemoveSnapshot(t, r, uid)
			require.Nil(t, identityRemoveExecute(t, r, p, uid, r.b).Error)
			require.Equal(t, after, identityRemoveSnapshot(t, r, uid))
			authorityWaitReleased(t, r.runtime)
		})
	}
}

func TestIdentityRemoveFromAccountActualAuditFailureRollsBack(t *testing.T) {
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	uid := identityRemoveMember(t, r, "identity-remove-rollback")
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	before := identityRemoveSnapshot(t, r, uid)
	f := &identityAuditFailure{IdentityLifecycleWriterFactory: p}
	require.NotNil(t, identityRemoveExecute(t, r, f, uid, r.b).Error)
	require.True(t, f.reached, "сначала настоящие DELETE, FGA intent и INSERT аудита, затем контролируемый отказ")
	require.Equal(t, before, identityRemoveSnapshot(t, r, uid))
	authorityWaitReleased(t, r.runtime)
	require.Nil(t, identityRemoveExecute(t, r, p, uid, r.b).Error)
	authorityWaitReleased(t, r.runtime)
}

// Отложенный отказ приходит на COMMIT после тела. Его последующее чтение
// обязано получить освобождённый единственный slot и назвать только местную выдачу.
func TestIdentityRemoveFromAccountCommitRefusalNamesOnlyLocalGrants(t *testing.T) {
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	uid := identityRemoveMember(t, r, "identity-remove-carrying")
	rule := domain.Rule{Module: "iam", Resources: []string{"user"}, Verbs: []string{"get"}}
	local := groupLifecycleBinding(t, r, r.a, string(uid), "identity_remove_local", rule)
	foreign := groupLifecycleBinding(t, r, r.b, string(uid), "identity_remove_foreign", rule)
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	before := identityRemoveSnapshot(t, r, uid)
	localBefore, foreignBefore := bindingRow(t, r, local), bindingRow(t, r, foreign)
	op := identityRemoveExecute(t, r, p, uid, r.a)
	require.NotNil(t, op.Error)
	require.Equal(t, int32(codes.FailedPrecondition), op.Error.Code)
	require.Contains(t, op.Error.Message, string(local))
	require.NotContains(t, op.Error.Message, string(foreign))
	require.Equal(t, before, identityRemoveSnapshot(t, r, uid))
	require.Equal(t, localBefore, bindingRow(t, r, local))
	require.Equal(t, foreignBefore, bindingRow(t, r, foreign))
	authorityWaitReleased(t, r.runtime)
}
