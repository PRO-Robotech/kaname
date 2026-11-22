// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
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
			rejected, err := runner.RunUserChildRegistration(userCtx, refused, principal)
			require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
			require.Equal(t, domain.ErrUserChildRegistrationRefused.Error(), err.Error())
			require.True(t, rejected.IsZero())
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

// Общий барьер выпускает два настоящих runner calls. Обе допустимые
// сериализации сохраняют close и допускают ребёнка только до closed_at.
func TestChildParentCloseRuntimeConcurrentChildSerializes(t *testing.T) {
	r, runner, moduleCtx, _, principal := childRuntimeModuleFixture(t)
	input := childParentCloseCurrentInput(t, r)
	child := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/concurrent-close"}
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	userCtx := operations.WithPrincipal(ctx, principal)
	moduleCtx, cancelModule := context.WithTimeout(moduleCtx, 20*time.Second)
	defer cancelModule()
	type outcome struct {
		at  time.Time
		err error
	}
	start := make(chan struct{})
	closeDone, childDone := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		<-start
		at, err := runner.RunChildParentClose(moduleCtx, input)
		closeDone <- outcome{at, err}
	}()
	go func() {
		<-start
		at, err := runner.RunUserChildRegistration(userCtx, child, principal)
		childDone <- outcome{at, err}
	}()
	close(start)
	var closed, created outcome
	select {
	case closed = <-closeDone:
	case <-ctx.Done():
		t.Fatal("close не завершился")
	}
	select {
	case created = <-childDone:
	case <-ctx.Done():
		t.Fatal("child registration не завершилась")
	}
	resourcePublicEntryCause(t, closed.err)
	require.NoError(t, closed.err)
	require.False(t, closed.at.IsZero())
	var persisted time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT closed_at FROM kaname.authority_child_parent_state
 WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&persisted))
	require.True(t, closed.at.Equal(persisted))
	var mirrorCount, receiptCount int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type=$1 AND child_id=$2)`, child.ResourceType, child.ResourceID).Scan(&mirrorCount, &receiptCount))
	if created.err == nil {
		require.False(t, created.at.IsZero())
		require.False(t, created.at.After(closed.at), "принятый ребёнок предшествует закрытию")
		require.Equal(t, 1, mirrorCount)
		require.Equal(t, 1, receiptCount)
	} else {
		require.ErrorIs(t, created.err, domain.ErrUserChildRegistrationRefused)
		require.True(t, created.at.IsZero())
		require.Zero(t, mirrorCount)
		require.Zero(t, receiptCount)
	}
	authorityWaitReleased(t, r.runtime)
}
