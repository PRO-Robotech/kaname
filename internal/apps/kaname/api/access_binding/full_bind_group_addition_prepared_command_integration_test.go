// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Мир использует полный runtime LOGIN, реальные group participant и factory
// из FB22. Право actor и выдача группе создаются публичными API до измерения.
func fbGroupCommandWorld(t *testing.T, identityFixtures ...func(*atcWorld)) (*fbRemainingWorld, domain.GroupID) {
	t.Helper()
	w := newFBRemainingWorld(t, func(a *atcWorld) {
		gdSeedMembership(t, a.ctx, a.pool, a.usrC, a.accB, "ACTIVE")
		for _, setup := range identityFixtures {
			setup(a)
		}
	})
	g := w.group("prepared-group-command")
	w.groupMethod(g)
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	role := w.role("prepared_group_command_get", fullBindBoxRule("get"))
	w.grant(fbStructuredRequest(userSubject(w.usrD), role, "project", string(w.prjA)))
	id := w.createDone(asUser(w.ctx, w.usrA), fbStructuredRequest(
		&iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: string(g)},
		role, "project", string(w.prjA)), "подготовка настоящей выдачи группе")
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", id))
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)))
	actor := "user:" + string(w.usrD)
	w.noScopeAdmin(actor)
	w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	return w, g
}

// Ожидание не создаёт goroutine. Deadline ограничивает страховочное ожидание
// результата worker, а ticker только опрашивает Operation, не синхронизирует lock.
func fbGroupCommandAwait(ctx context.Context, w *fbRemainingWorld, id string) (*operations.Operation, error) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		op, err := w.ops.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if op.Done {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

func fbGroupCommandAdd(t *testing.T, w *fbRemainingWorld, req *iamv1.AddGroupMemberRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, 20*time.Second)
	defer cancel()
	op, err := w.groups.AddMember(asUser(ctx, w.usrD), req)
	require.NoError(t, err)
	require.NotNil(t, op)
	done, err := fbGroupCommandAwait(ctx, w, op.GetId())
	require.NoError(t, err)
	require.Nil(t, done.Error)
}

type fbGroupCommandState struct {
	members, facts, journal, fga, changes int
	member, fact, bindingEpochs           string
	policy                                map[string]int64
}

func fbGroupCommandSnapshot(t *testing.T, w *fbRemainingWorld, req *iamv1.AddGroupMemberRequest) fbGroupCommandState {
	t.Helper()
	var s fbGroupCommandState
	var policy string
	require.NoError(t, w.observer.QueryRow(w.ctx, `SELECT
 (SELECT count(*) FROM kaname.group_members WHERE group_id=$1 AND member_type=$2 AND member_id=$3),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject=$4),
 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_group' AND resource_id=$1 AND event_type='UPDATED'),
 (SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'object'='group:'||$1 AND payload->>'user'=$4 AND payload->>'relation'='member'),
 (SELECT count(*) FROM kaname.subject_change_outbox WHERE subject_id=$3 AND event_type='group_member_change' AND op='group_member_change' AND payload->>'subject_type'=$2 AND payload->>'subject_id'=$3 AND payload->>'op'='group_member_change' AND payload->>'event_type'='group_member_change'),
 (SELECT coalesce(jsonb_agg(to_jsonb(m)),'[]'::jsonb)::text FROM kaname.group_members m WHERE group_id=$1 AND member_type=$2 AND member_id=$3),
 (SELECT coalesce(jsonb_agg(to_jsonb(f)),'[]'::jsonb)::text FROM kaname.relation_fact f WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject=$4),
 (SELECT coalesce(jsonb_object_agg(key,revision),'{}'::jsonb)::text FROM kaname.authority_policy_epoch),
 (SELECT coalesce(jsonb_object_agg(scope,revision),'{}'::jsonb)::text FROM kaname.authority_binding_epoch)`,
		req.GetGroupId(), req.GetMemberType(), req.GetMemberId(), req.GetMemberType()+":"+req.GetMemberId()).
		Scan(&s.members, &s.facts, &s.journal, &s.fga, &s.changes, &s.member, &s.fact, &policy, &s.bindingEpochs))
	require.NoError(t, json.Unmarshal([]byte(policy), &s.policy))
	return s
}

func fbGroupCommandEpochs(t *testing.T, before, after fbGroupCommandState, deltas map[string]int64) {
	t.Helper()
	want := make(map[string]int64, len(before.policy))
	for key, revision := range before.policy {
		want[key] = revision
	}
	for key, delta := range deltas {
		want[key] += delta
	}
	require.Equal(t, want, after.policy, "только исходные policy epochs меняются от фактически записанных строк")
	require.Equal(t, before.bindingEpochs, after.bindingEpochs, "AddMember не переписывает источники binding epochs")
}

func TestFullBind_GroupAdditionPreparedCommandPreservesRepeatedEffects(t *testing.T) {
	var futureGroup domain.GroupID
	w, g := fbGroupCommandWorld(t, func(a *atcWorld) {
		// Канонический bootstrap hook выполняется до Prepare/activation.
		// Отдельная группа сохраняет исходный fresh/repeat сценарий целиком.
		futureGroup = domain.GroupID(seedGroup(t, a.ctx, a.pool, a.accA, "prepared-future-group"))
		_, err := a.pool.Exec(a.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'user',$2),($1,'service_account',$3)`, futureGroup, a.usrE, a.svaA)
		require.NoError(t, err)
		// Group.Create также записывает owning account pointer; fixture
		// сохраняет тот же настоящий источник области группы до FULL2.
		_, err = a.pool.Exec(a.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('iam_group',$1,'account','account:'||$2)`, futureGroup, a.accA)
		require.NoError(t, err)
		_, err = a.pool.Exec(a.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 SELECT 'group',group_id,'member',member_type||':'||member_id,transaction_timestamp()+interval '1 day'
 FROM kaname.group_members WHERE group_id=$1`, futureGroup)
		require.NoError(t, err)
	})
	// После активации только настоящие API создают метод actor и выдачу
	// fixture группе. Проверяемая операция использует прежний runtime FULL2.
	futureMethod := w.role("prepared_future_group_update", &iamv1.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"update"}, ResourceNames: []string{string(futureGroup)}})
	w.grant(fbStructuredRequest(userSubject(w.usrD), futureMethod, "account", string(w.accA)))
	w.native("user:"+string(w.usrD), "v_update", "iam_group", string(futureGroup), relverdict.Allow)
	w.native("user:"+string(w.usrD), "admin", "iam_group", string(futureGroup), relverdict.Deny)
	// Отдельный update не выводит get: fixture не маскирует fresh grant.
	futureRole := w.role("prepared_future_group_update_effect", fullBindBoxRule("update"))
	w.grant(fbStructuredRequest(userSubject(w.usrD), futureRole, "project", string(w.prjA)))
	w.native("user:"+string(w.usrD), "v_update", atcBoxType, atcB1, relverdict.Allow)
	futureBinding := w.createDone(asUser(w.ctx, w.usrA), fbStructuredRequest(
		&iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: string(futureGroup)},
		futureRole, "project", string(w.prjA)), "подготовка настоящей выдачи future группе")
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", futureBinding))
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(futureBinding)))
	for _, member := range []struct {
		name, typ, id string
	}{
		{"human_active_membership", "user", string(w.usrE)},
		{"direct_service_account", "service_account", w.svaA},
	} {
		t.Run(member.name, func(t *testing.T) {
			req := &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: member.typ, MemberId: member.id}
			before := fbGroupCommandSnapshot(t, w, req)
			require.Zero(t, before.members)
			require.Zero(t, before.facts)
			w.native(member.typ+":"+member.id, "v_get", atcBoxType, atcB1, relverdict.Deny)
			fbGroupCommandAdd(t, w, req)
			fresh := fbGroupCommandSnapshot(t, w, req)
			require.Equal(t, 1, fresh.members)
			require.Equal(t, 1, fresh.facts)
			require.Equal(t, before.journal+1, fresh.journal)
			require.Equal(t, before.fga+1, fresh.fga)
			require.Equal(t, before.changes+1, fresh.changes)
			// group_members инвалидирует group и member; реальная вставка
			// relation_fact отдельно инвалидирует member и область объекта.
			fbGroupCommandEpochs(t, before, fresh, map[string]int64{
				"group:" + string(g): 1, member.typ + ":" + member.id: 2, "scope:" + string(w.accA): 1,
			})
			w.native(member.typ+":"+member.id, "member", "group", string(g), relverdict.Allow)
			w.native(member.typ+":"+member.id, "v_get", atcBoxType, atcB1, relverdict.Allow)

			fbGroupCommandAdd(t, w, req)
			repeated := fbGroupCommandSnapshot(t, w, req)
			require.Equal(t, 1, repeated.members)
			require.Equal(t, 1, repeated.facts)
			require.Equal(t, fresh.member, repeated.member, "повтор не меняет added_at")
			require.Equal(t, fresh.journal, repeated.journal, "ON CONFLICT DO NOTHING не эмитит member journal")
			require.Equal(t, fresh.fga+1, repeated.fga, "исходный UC пишет FGA intent на каждый вызов")
			require.Equal(t, fresh.changes+1, repeated.changes, "исходный UC пишет subject change на каждый вызов")
			require.NotEqual(t, fresh.fact, repeated.fact, "более новый FGA intent обновляет source_version одного факта")
			fbGroupCommandEpochs(t, fresh, repeated, map[string]int64{
				member.typ + ":" + member.id: 1, "scope:" + string(w.accA): 1,
			})

			// Будущий факт подготовлен до FULL2 вместе с owning membership.
			// После активации observer читает только premise; When остаётся API.
			req.GroupId = string(futureGroup)
			var finiteFuture bool
			require.NoError(t, w.observer.QueryRow(w.ctx, `SELECT isfinite(source_version) AND source_version>transaction_timestamp() FROM kaname.relation_fact WHERE object_type='group' AND object_id=$1 AND relation='member' AND subject=$2`, futureGroup, member.typ+":"+member.id).Scan(&finiteFuture))
			require.True(t, finiteFuture)
			future := fbGroupCommandSnapshot(t, w, req)
			fbGroupCommandAdd(t, w, req)
			afterFuture := fbGroupCommandSnapshot(t, w, req)
			require.Equal(t, 1, afterFuture.members)
			require.Equal(t, 1, afterFuture.facts)
			require.Equal(t, future.member, afterFuture.member)
			require.Equal(t, future.fact, afterFuture.fact, "UPSERT WHERE source_version<EXCLUDED сохраняет будущий факт целиком")
			require.Equal(t, future.journal, afterFuture.journal)
			require.Equal(t, future.fga+1, afterFuture.fga)
			require.Equal(t, future.changes+1, afterFuture.changes)
			fbGroupCommandEpochs(t, future, afterFuture, nil)
		})
	}
}

func TestFullBind_GroupAdditionPreparedCommandRefusesForeignBeforeRowLockRelease(t *testing.T) {
	w, g := fbGroupCommandWorld(t)
	for _, member := range []struct {
		name, typ, foreign, missing string
	}{
		{"human_active_membership", "user", string(w.usrC), ids.NewID(domain.PrefixUser)},
		{"direct_service_account", "service_account", w.svaB, ids.NewID(domain.PrefixServiceAccount)},
	} {
		t.Run(member.name, func(t *testing.T) {
			// Подтверждаем D3 premises независимо от результата команды.
			var foreignExists, foreignInA, foreignInB, missingExists bool
			premise := `SELECT EXISTS(SELECT 1 FROM kaname.users WHERE id=$1), EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='ACTIVE'), EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$3 AND state='ACTIVE'), EXISTS(SELECT 1 FROM kaname.users WHERE id=$4)`
			if member.typ == "service_account" {
				premise = `SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1), EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1 AND account_id=$2), EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1 AND account_id=$3), EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$4)`
			}
			require.NoError(t, w.observer.QueryRow(w.ctx, premise, member.foreign, w.accA, w.accB, member.missing).Scan(&foreignExists, &foreignInA, &foreignInB, &missingExists))
			require.True(t, foreignExists)
			require.False(t, foreignInA)
			require.True(t, foreignInB)
			require.False(t, missingExists)

			holderCtx, holderCancel := context.WithTimeout(w.ctx, 60*time.Second)
			defer holderCancel()
			holder, err := w.observer.Begin(holderCtx)
			require.NoError(t, err)
			var operationID string
			defer func() {
				// Сначала освобождаем locks даже при Fatal; затем дожидаемся
				// настоящего worker перед cleanup мира, без утечки фоновой операции.
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				require.NoError(t, holder.Rollback(ctx))
				if operationID != "" {
					_, joinErr := fbGroupCommandAwait(ctx, w, operationID)
					require.NoError(t, joinErr)
				}
			}()
			var locked string
			if member.typ == "service_account" {
				require.NoError(t, holder.QueryRow(holderCtx, `SELECT id FROM kaname.service_accounts WHERE id=$1 AND account_id=$2 FOR UPDATE`, member.foreign, w.accB).Scan(&locked))
			} else {
				require.NoError(t, holder.QueryRow(holderCtx, `SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE`, member.foreign).Scan(&locked))
				var foreignMembership string
				require.NoError(t, holder.QueryRow(holderCtx, `SELECT id FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='ACTIVE' FOR UPDATE`, member.foreign, w.accB).Scan(&foreignMembership))
				require.NotEmpty(t, foreignMembership)
			}
			require.Equal(t, member.foreign, locked)
			// Успешный ответ SELECT FOR UPDATE — барьер: holder уже держит
			// чужую строку до запуска команды. Release только в defer после отказов.
			before := w.business()
			for _, id := range []string{member.foreign, member.missing} {
				ctx, cancel := context.WithTimeout(w.ctx, 15*time.Second)
				op, callErr := w.groups.AddMember(asUser(ctx, w.usrD), &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: member.typ, MemberId: id})
				if op != nil {
					operationID = op.GetId()
				}
				if callErr != nil || op == nil {
					cancel()
					require.NoError(t, callErr)
					require.NotNil(t, op)
				}
				done, waitErr := fbGroupCommandAwait(ctx, w, operationID)
				cancel()
				require.NoError(t, waitErr, "D3 обязан завершиться, пока чужой FOR UPDATE ещё удержан")
				require.NotNil(t, done.Error)
				require.Equal(t, int32(codes.FailedPrecondition), done.Error.Code)
				require.Equal(t, "referenced resource does not exist; create it or correct the reference before retrying", done.Error.Message)
				require.Equal(t, before, w.business(), "чужой и отсутствующий reference сохраняют бизнес/FGA/audit одинаково")
				var holderAlive int
				require.NoError(t, holder.QueryRow(holderCtx, `SELECT 1`).Scan(&holderAlive))
				require.Equal(t, 1, holderAlive, "отказ наблюдается до release живой holder TX")
				operationID = ""
			}
		})
	}
}
