// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	childregistration "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// 1045-05: назначенная роль сохраняется во всех состояниях. Эффективное
// child_registrar на module-object требует живого mirror и заново проверяется
// native source verifier; для отсутствующего объекта его нельзя утверждать
// по одной роли или старому emitted ledger. Положительный близнец и closed
// имеют настоящее объектное право; missing/removed отказывают уже при AuthZ.
func TestUserChildRuntimeParentAvailabilityUniformRefusal(t *testing.T) {
	r, runner, moduleCtx, scene, principal := childRuntimeModuleFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	handler := childregistration.NewHandler(internaliam.NewUserChildRegistration(runner))
	parent := childParentCloseCurrentInput(t, r)
	input := func(id string) kaname.UserChildRegistrationInput {
		return kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: id}
	}
	// Фиксируем именно созданную fixture роль и её account-scoped assignment,
	// а не материализованные факты, которые штатное снятие объекта вправе убрать.
	var bindingID string
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT b.id FROM kaname.access_bindings b
 JOIN kaname.roles role ON role.id=b.role_id
 JOIN kaname.access_binding_subjects subject ON subject.binding_id=b.id
 WHERE role.name='child_stage_registrar' AND role.account_id=$1
 AND subject.subject_type='user' AND subject.subject_id=$2
 AND b.status='ACTIVE' AND b.revoked_at IS NULL`, scene.Account, principal.ID).Scan(&bindingID))
	assignment := func() json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'binding',to_jsonb(b),'role',to_jsonb(role),
 'subjects',(SELECT jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text)
 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id))
 FROM kaname.access_bindings b JOIN kaname.roles role ON role.id=b.role_id WHERE b.id=$1`, bindingID).Scan(&raw))
		return raw
	}
	originalAssignment := assignment()
	checkAuthorization := func(candidate kaname.UserChildRegistrationInput, allowed bool) {
		t.Helper()
		tx, err := r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer func() { require.NoError(t, tx.Rollback(context.WithoutCancel(ctx))) }()
		_, _, _, err = kanamepg.ProbeUserChildAuthorization(ctx, tx, r.bundle, candidate, principal)
		if allowed {
			require.NoError(t, err, "настоящий native source verifier подтверждает объектное право")
		} else {
			require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused, "назначение роли не создаёт effective permission на отсутствующий mirror")
		}
	}
	assertRefused := func(candidate kaname.UserChildRegistrationInput, reason string) {
		t.Helper()
		before := childParentCloseSnapshot(t, r)
		var oldAuditIDs []string
		var oldAudits json.RawMessage
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT coalesce(array_agg(id ORDER BY id),'{}'),
 coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM kaname.audit_outbox a
 WHERE event_type='iam.child_registration.refused'`).Scan(&oldAuditIDs, &oldAudits))
		got, err := handler.Register(ctx, &iamv1.RegisterChildRequest{ResourceType: candidate.ResourceType, ResourceId: candidate.ResourceID})
		require.Nil(t, got)
		answer := status.Convert(err)
		require.Equal(t, codes.PermissionDenied, answer.Code())
		require.Equal(t, "permission denied", answer.Message())
		require.Empty(t, answer.Details())
		require.JSONEq(t, string(before), string(childParentCloseSnapshot(t, r)), "отказ не меняет mirror, scope, facts, edges, receipts или рабочие outboxes")
		require.JSONEq(t, string(originalAssignment), string(assignment()), "роль и её назначение сохраняются")
		var retainedAudits json.RawMessage
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]')
 FROM kaname.audit_outbox a WHERE id=ANY($1::text[])`, oldAuditIDs).Scan(&retainedAudits))
		require.JSONEq(t, string(oldAudits), string(retainedAudits), "предыдущие refusal audits неизменны")
		expected, err := json.Marshal(map[string]string{"actor": "user:" + principal.ID, "outcome": "permission_denied", "reason": reason})
		require.NoError(t, err)
		var added, exact int
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*),count(*) FILTER (
 WHERE tenant_account_id IS NULL AND event_payload=$2::jsonb AND status='pending' AND attempts=0)
 FROM kaname.audit_outbox WHERE event_type='iam.child_registration.refused' AND NOT (id=ANY($1::text[]))`, oldAuditIDs, expected).Scan(&added, &exact))
		require.Equal(t, 1, added, "единственный новый effect — durable refusal audit после rollback")
		require.Equal(t, 1, exact, "audit содержит только actor, outcome и закрытую причину, без координат")
		authorityWaitReleased(t, r.runtime)
	}

	open := input("container-one/availability-open")
	checkAuthorization(open, true)
	accepted, err := handler.Register(ctx, &iamv1.RegisterChildRequest{ResourceType: open.ResourceType, ResourceId: open.ResourceID})
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.NotNil(t, accepted)
	require.NotNil(t, accepted.Version)
	require.NoError(t, accepted.Version.CheckValid())
	var acceptedMirror bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type=$1 AND object_id=$2 AND source_version=$3)`, open.ResourceType, open.ResourceID, accepted.Version.AsTime()).Scan(&acceptedMirror))
	require.True(t, acceptedMirror, "положительный близнец действительно закоммичен")

	missing := input("never-registered/candidate")
	var missingMirror bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type='childstage.container' AND object_id='never-registered')`).Scan(&missingMirror))
	require.False(t, missingMirror)
	checkAuthorization(missing, false)
	assertRefused(missing, "permission_denied")

	closedAt, err := runner.RunChildParentClose(moduleCtx, parent)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, closedAt.IsZero())
	var closedMirror bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror m
 JOIN kaname.authority_child_parent_state p USING(object_type,object_id)
 WHERE m.object_type=$1 AND m.object_id=$2 AND m.source_version=$3 AND p.closed_at=$4)`,
		parent.ResourceType, parent.ResourceID, parent.SourceVersion, closedAt).Scan(&closedMirror))
	require.True(t, closedMirror, "close сохраняет mirror и меняет только состояние допуска")
	closed := input("container-one/availability-closed")
	checkAuthorization(closed, true)
	assertRefused(closed, "parent_closed")

	intent := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister,
		Tuple:  outboxtypes.RelationTuple{User: "project:" + scene.Project, Relation: "project", Object: "childstage_container:container-one"},
		Mirror: outboxtypes.ResourceMirrorRow{ObjectType: "childstage_container", ObjectID: parent.ResourceID}}
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&intent.Mirror.SourceVersion))
	removed, err := runner.RunResourceDecision(moduleCtx, intent)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.True(t, removed.Changed)
	var remaining int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_mirror
 WHERE (object_type=$1 AND object_id=$2) OR (object_type=$3 AND object_id=$4)`,
		parent.ResourceType, parent.ResourceID, open.ResourceType, open.ResourceID).Scan(&remaining))
	require.Zero(t, remaining, "штатный Unregister снял родителя и допущенного ребёнка")
	require.JSONEq(t, string(originalAssignment), string(assignment()), "снятие module-object не отзывает account-scoped назначение роли")
	afterRemoval := input("container-one/availability-removed")
	checkAuthorization(afterRemoval, false)
	assertRefused(afterRemoval, "permission_denied")
}
