// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	childregistration "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func childParentCloseCurrentInput(t *testing.T, r protocolRig) kaname.ChildParentCloseInput {
	t.Helper()
	input := kaname.ChildParentCloseInput{ResourceType: "childstage.container", ResourceID: "container-one"}
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT source_version FROM kaname.resource_mirror
 WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&input.SourceVersion))
	return input
}

func childParentCloseSnapshot(t *testing.T, r protocolRig) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'mirror',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_mirror x),
 'scope',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_scope x),
 'facts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.relation_fact x),
 'edges',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_parent_edge x),
 'state',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.authority_child_parent_state x),
 'receipts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.authority_child_creation x),
 'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.audit_outbox x WHERE event_type<>'iam.child_registration.refused'),
 'fga',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.fga_outbox x),
 'reconcile',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.resource_reconcile_outbox x))`).Scan(&raw))
	return raw
}

func TestChildParentCloseRuntimeCurrentVersionReplayAndChildOrdering(t *testing.T) {
	for _, childFirst := range []bool{false, true} {
		name := "close-before-child"
		if childFirst {
			name = "child-before-close"
		}
		t.Run(name, func(t *testing.T) {
			r, runner, moduleCtx, scene, principal := childRuntimeModuleFixture(t)
			input := childParentCloseCurrentInput(t, r)
			child := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/close-ordering"}
			userCtx := operations.WithPrincipal(r.ctx, principal)
			var childVersion time.Time
			var err error
			if childFirst {
				childVersion, err = runner.RunUserChildRegistration(userCtx, child, principal)
				resourcePublicEntryCause(t, err)
				require.NoError(t, err)
				require.False(t, childVersion.IsZero())
			}
			beforeInvalid := childParentCloseSnapshot(t, r)
			for _, invalid := range []kaname.ChildParentCloseInput{
				{ResourceType: input.ResourceType, ResourceID: input.ResourceID, SourceVersion: input.SourceVersion.Add(-time.Microsecond)},
				{ResourceType: input.ResourceType, ResourceID: input.ResourceID, SourceVersion: input.SourceVersion.Add(time.Microsecond)},
				{ResourceType: input.ResourceType, ResourceID: "missing-parent", SourceVersion: input.SourceVersion},
			} {
				at, callErr := runner.RunChildParentClose(moduleCtx, invalid)
				answer := status.Convert(callErr)
				require.Equal(t, codes.PermissionDenied, answer.Code())
				require.Equal(t, "permission denied", answer.Message())
				require.Empty(t, answer.Details())
				require.True(t, at.IsZero())
				require.JSONEq(t, string(beforeInvalid), string(childParentCloseSnapshot(t, r)), "stale/future close не меняет состояние")
			}
			closedAt, err := runner.RunChildParentClose(moduleCtx, input)
			resourcePublicEntryCause(t, err)
			require.NoError(t, err)
			require.False(t, closedAt.IsZero())
			var persistedClose time.Time
			var incarnation string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT incarnation::text,closed_at FROM kaname.authority_child_parent_state
 WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&incarnation, &persistedClose))
			require.NotEmpty(t, incarnation)
			require.True(t, closedAt.Equal(persistedClose))
			var closeAudits int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type='iam.resource_registration.parent_closed' AND event_payload#>>'{object,id}'=$1`, input.ResourceID).Scan(&closeAudits))
			require.Equal(t, 1, closeAudits, "первое закрытие пишет один owner-module audit")
			afterClose := childParentCloseSnapshot(t, r)
			replay, err := runner.RunChildParentClose(moduleCtx, input)
			resourcePublicEntryCause(t, err)
			require.NoError(t, err)
			require.True(t, closedAt.Equal(replay), "повтор возвращает время первоначального закрытия")
			require.JSONEq(t, string(afterClose), string(childParentCloseSnapshot(t, r)), "точный replay не добавляет эффектов")
			refused := child
			if childFirst {
				refused.ResourceID = "container-one/after-close"
			}
			handler := childregistration.NewHandler(internaliam.NewUserChildRegistration(runner))
			rejected, err := handler.Register(userCtx, &iamv1.RegisterChildRequest{ResourceType: refused.ResourceType, ResourceId: refused.ResourceID})
			require.Nil(t, rejected)
			answer := status.Convert(err)
			require.Equal(t, codes.PermissionDenied, answer.Code())
			require.Equal(t, "permission denied", answer.Message())
			require.Empty(t, answer.Details())
			require.JSONEq(t, string(afterClose), string(childParentCloseSnapshot(t, r)), "закрытый родитель сохраняет состояние регистрации при durable refusal audit")
			var denialAudits int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox
 WHERE event_type='iam.child_registration.refused' AND event_payload->>'reason'='parent_closed'
 AND event_payload->>'actor'=$1`, "user:"+principal.ID).Scan(&denialAudits))
			require.Equal(t, 1, denialAudits, "единственный отказ сохраняет точную внутреннюю причину parent_closed")
			var parentPresent, childPresent bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2),
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type=$3 AND object_id=$4)`, input.ResourceType, input.ResourceID, child.ResourceType, child.ResourceID).Scan(&parentPresent, &childPresent))
			require.True(t, parentPresent, "close не снимает регистрацию родителя")
			require.Equal(t, childFirst, childPresent, "ранее принятый потомок сохраняется до ordinary Unregister")
			var immutable json.RawMessage
			if childFirst {
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(c) FROM kaname.authority_child_creation c
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3 AND parent_incarnation=$4::uuid`, child.ResourceType, child.ResourceID, childVersion, incarnation).Scan(&immutable))
			}
			intent := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister,
				Tuple:  outboxtypes.RelationTuple{User: "project:" + scene.Project, Relation: "project", Object: "childstage_container:container-one"},
				Mirror: outboxtypes.ResourceMirrorRow{ObjectType: "childstage_container", ObjectID: input.ResourceID}}
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&intent.Mirror.SourceVersion))
			removed, err := runner.RunResourceDecision(moduleCtx, intent)
			resourcePublicEntryCause(t, err)
			require.NoError(t, err)
			require.True(t, removed.Changed)
			var mirrors, states int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE (object_type=$1 AND object_id=$2) OR (object_type=$3 AND object_id=$4)),
 (SELECT count(*) FROM kaname.authority_child_parent_state WHERE object_type=$1 AND object_id=$2)`, input.ResourceType, input.ResourceID, child.ResourceType, child.ResourceID).Scan(&mirrors, &states))
			require.Zero(t, mirrors)
			require.Zero(t, states)
			if childFirst {
				var retained json.RawMessage
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(c) FROM kaname.authority_child_creation c
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3`, child.ResourceType, child.ResourceID, childVersion).Scan(&retained))
				require.JSONEq(t, string(immutable), string(retained))
			}
			for _, table := range []string{"kaname.authority_child_parent_state", "kaname.authority_child_creation"} {
				var allowed bool
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`, table).Scan(&allowed))
				require.False(t, allowed)
			}
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// SHARE удерживает первый runner в prewait ПОСЛЕ parent epoch. Второй
// запускается только после наблюдения этого ожидания и сам обязан ждать
// первый backend. Освобождение owner-барьера фиксирует выбранный порядок;
// очередность goroutine и задержки по времени доказательством не служат.
func TestChildParentCloseRuntimeConcurrentChildSerializes(t *testing.T) {
	for _, childFirst := range []bool{false, true} {
		name := "close-before-child"
		if childFirst {
			name = "child-before-close"
		}
		t.Run(name, func(t *testing.T) {
			r, runner, moduleCtx, scene, principal := childRuntimeModuleFixture(t)
			input := childParentCloseCurrentInput(t, r)
			child := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/concurrent-close"}
			userCtx := operations.WithPrincipal(r.ctx, principal)
			before := childParentCloseSnapshot(t, r)
			held := resourcePublicHold(t, r, `LOCK TABLE ONLY kaname.authority_child_parent_state IN SHARE MODE`)
			var closedAt, childVersion time.Time
			startClose := func() *resourcePublicCall {
				return resourcePublicStart(t, moduleCtx, func(ctx context.Context) error {
					var err error
					closedAt, err = runner.RunChildParentClose(ctx, input)
					return err
				})
			}
			startChild := func() *resourcePublicCall {
				return resourcePublicStart(t, userCtx, func(ctx context.Context) error {
					var err error
					childVersion, err = runner.RunUserChildRegistration(ctx, child, principal)
					return err
				})
			}
			var closeCall, childCall *resourcePublicCall
			if childFirst {
				childCall = startChild()
			} else {
				closeCall = startClose()
			}
			firstPID := resourcePublicWaitBlocked(t, r, held.Conn().PgConn().PID(), r.role, "authority_resource_prewait_v2")
			var relationWait bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
 WHERE pid=$1 AND locktype='relation' AND relation='kaname.authority_child_parent_state'::regclass
 AND mode='RowExclusiveLock' AND NOT granted)`, firstPID).Scan(&relationWait))
			require.True(t, relationWait, "первый runner остановлен на private lifecycle relation до finalize")
			if childFirst {
				closeCall = startClose()
			} else {
				childCall = startChild()
			}
			secondPID := resourcePublicWaitBlocked(t, r, firstPID, r.role, "authority_resource_prewait_v2")
			require.NotEqual(t, firstPID, secondPID)
			resourcePublicBlockedBy(t, r, firstPID, held.Conn().PgConn().PID())
			resourcePublicBlockedBy(t, r, secondPID, firstPID)
			require.JSONEq(t, string(before), string(childParentCloseSnapshot(t, r)), "оба runner дошли до настоящих locks, но ещё не применили effects")
			require.NoError(t, held.Rollback(r.ctx))

			closeErr := resourcePublicAwait(t, closeCall)
			childErr := resourcePublicAwait(t, childCall)
			resourcePublicEntryCause(t, closeErr)
			require.NoError(t, closeErr)
			require.False(t, closedAt.IsZero())
			var persistedClose time.Time
			var incarnation string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT incarnation::text,closed_at
 FROM kaname.authority_child_parent_state WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&incarnation, &persistedClose))
			require.True(t, closedAt.Equal(persistedClose))
			wantChildren := 0
			if childFirst {
				resourcePublicEntryCause(t, childErr)
				require.NoError(t, childErr)
				require.False(t, childVersion.IsZero())
				require.False(t, childVersion.After(closedAt), "принятый ребёнок предшествует закрытию")
				wantChildren = 1
			} else {
				require.ErrorIs(t, childErr, domain.ErrUserChildRegistrationRefused)
				require.True(t, childVersion.IsZero())
			}
			var parentCount, mirrorCount, receiptCount, scopeCount, parentFacts, childWrites, childAudits, closeAudits, refusalAudits int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2),
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$3 AND object_id=$4),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type=$3 AND child_id=$4),
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='childstage_child' AND object_id=$4 AND account_id=$5 AND project_id=$6),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='childstage_child' AND object_id=$4 AND relation='parent' AND subject='childstage_container:'||$2),
 (SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'object'='childstage_child:'||$4),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$4),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.resource_registration.parent_closed' AND event_payload#>>'{object,id}'=$2),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.child_registration.refused'
  AND event_payload->>'reason'='parent_closed' AND event_payload->>'actor'=$7)`,
				input.ResourceType, input.ResourceID, child.ResourceType, child.ResourceID, scene.Account, scene.Project, "user:"+principal.ID).
				Scan(&parentCount, &mirrorCount, &receiptCount, &scopeCount, &parentFacts, &childWrites, &childAudits, &closeAudits, &refusalAudits))
			require.Equal(t, 1, parentCount, "close сохраняет регистрацию родителя до ordinary Unregister")
			for _, count := range []int{mirrorCount, receiptCount, scopeCount, parentFacts, childWrites, childAudits} {
				require.Equal(t, wantChildren, count, "ровно выбранный порядок определяет все effects ребёнка")
			}
			require.Equal(t, 1, closeAudits)
			require.Equal(t, 1-wantChildren, refusalAudits, "отказ оставляет только durable audit с причиной parent_closed")
			receipts := func() json.RawMessage {
				var raw json.RawMessage
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]')
 FROM kaname.authority_child_creation c WHERE child_type=$1 AND child_id=$2`, child.ResourceType, child.ResourceID).Scan(&raw))
				return raw
			}
			scopes := func() json.RawMessage {
				var raw json.RawMessage
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]')
 FROM kaname.resource_registration_scope s WHERE (object_type='childstage_container' AND object_id=$1)
 OR (object_type='childstage_child' AND object_id=$2)`, input.ResourceID, child.ResourceID).Scan(&raw))
				return raw
			}
			immutableReceipts, savedScopes := receipts(), scopes()
			if childFirst {
				var exactReceipt bool
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_child_creation
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3 AND parent_incarnation=$4::uuid)`, child.ResourceType, child.ResourceID, childVersion, incarnation).Scan(&exactReceipt))
				require.True(t, exactReceipt, "close сохраняет инкарнацию квитанции принятого ребёнка")
			}
			intent := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister,
				Tuple:  outboxtypes.RelationTuple{User: "project:" + scene.Project, Relation: "project", Object: "childstage_container:container-one"},
				Mirror: outboxtypes.ResourceMirrorRow{ObjectType: "childstage_container", ObjectID: input.ResourceID}}
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&intent.Mirror.SourceVersion))
			removed, err := runner.RunResourceDecision(moduleCtx, intent)
			resourcePublicEntryCause(t, err)
			require.NoError(t, err)
			require.True(t, removed.Changed)
			var mirrors, states, edges, hierarchyFacts, reconcileEvents int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE (object_type=$1 AND object_id=$2) OR (object_type=$3 AND object_id=$4)),
 (SELECT count(*) FROM kaname.authority_child_parent_state WHERE object_type=$1 AND object_id=$2),
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE (object_type='childstage_container' AND object_id=$2) OR (object_type='childstage_child' AND object_id=$4)),
 (SELECT count(*) FROM kaname.relation_fact WHERE relation IN ('project','parent','owner')
  AND ((object_type='childstage_container' AND object_id=$2) OR (object_type='childstage_child' AND object_id=$4))),
 (SELECT count(DISTINCT (object_type,object_id)) FROM kaname.resource_reconcile_outbox WHERE event_type='mirror.delete'
  AND ((object_type=$1 AND object_id=$2) OR (object_type=$3 AND object_id=$4)))`,
				input.ResourceType, input.ResourceID, child.ResourceType, child.ResourceID).
				Scan(&mirrors, &states, &edges, &hierarchyFacts, &reconcileEvents))
			require.Zero(t, mirrors, "ordinary Unregister атомарно снимает родителя и принятого потомка")
			require.Zero(t, states)
			require.Zero(t, edges)
			require.Zero(t, hierarchyFacts)
			require.Equal(t, 1+wantChildren, reconcileEvents)
			require.JSONEq(t, string(immutableReceipts), string(receipts()), "историческая квитанция сохраняется; отказ не создаёт квитанцию")
			require.JSONEq(t, string(savedScopes), string(scopes()), "области сохраняются для авторизованного повтора снятия")
			authorityWaitReleased(t, r.runtime)
		})
	}
}
