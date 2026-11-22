// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	childregistration "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Полный публичный runner работает через ordinary LOGIN из production grant
// fixture. Private owner probes и ручная подготовка RC здесь не участвуют.
func TestUserChildRuntimeRunnerFullCommitReplayAndUniformRefusal(t *testing.T) {
	r, owner, scene, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r})
	staged, err := kanamepg.NewResourceDecisionRunner(ctx, r.repo, r.bundle, gate)
	require.NoError(t, err)
	input := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/runtime-candidate"}
	version, err := staged.RunUserChildRegistration(ctx, input, principal)
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.True(t, version.IsZero(), "prepared contract не допускает child registration")
	full, contract := fullContractActivate(t, r)
	// Даже installation context не превращает старый repo в FULL.
	version, err = staged.RunUserChildRegistration(contract.Context(ctx), input, principal)
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.True(t, version.IsZero())
	runner, err := kanamepg.NewResourceDecisionRunner(ctx, full, r.bundle, gate)
	require.NoError(t, err)
	var effective, session string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, r.role, effective)
	require.Equal(t, r.role, session)

	snapshot := func() json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT jsonb_build_object(
   'mirror',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_mirror x),
   'scopes',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_registration_scope x),
   'edges',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.resource_parent_edge x),
   'facts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY object_type,object_id,relation,subject),'[]') FROM kaname.relation_fact x),
   'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.authority_child_creation x),
   'parent_state',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.authority_child_parent_state x),
   'audits',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.audit_outbox x WHERE event_type<>'iam.child_registration.refused'),
   'reconcile',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.resource_reconcile_outbox x),
   'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.fga_outbox x)
  )`).Scan(&raw))
		return raw
	}
	before := snapshot()
	version, err = runner.RunUserChildRegistration(ctx, input, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, version.IsZero())
	after := snapshot()
	require.NotEqual(t, string(before), string(after))
	var persistedVersion, receiptVersion time.Time
	var account, project, user, actor string
	var scopes, facts, events, audits, receipts, parents, reconciles int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT source_version,parent_account_id,parent_project_id
 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&persistedVersion, &account, &project))
	require.True(t, version.Equal(persistedVersion))
	require.Equal(t, scene.Account, account)
	require.Equal(t, scene.Project, project)
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT source_version,user_id FROM kaname.authority_child_creation
 WHERE child_type=$1 AND child_id=$2`, input.ResourceType, input.ResourceID).Scan(&receiptVersion, &user))
	require.True(t, version.Equal(receiptVersion))
	require.Equal(t, principal.ID, user)
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT event_payload->>'actor' FROM kaname.audit_outbox
 WHERE event_payload#>>'{object,id}'=$1`, input.ResourceID).Scan(&actor))
	require.Equal(t, "user:"+principal.ID, actor)
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='childstage_child' AND object_id=$1 AND account_id=$2 AND project_id=$3),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='childstage_child' AND object_id=$1 AND relation='parent' AND subject='childstage_container:container-one' AND source_version=$4),
 (SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'object'='childstage_child:'||$1 AND payload->>'relation'='parent' AND payload->>'user'='childstage_container:container-one'),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='childstage.child' AND child_id=$1),
 (SELECT count(*) FROM kaname.authority_child_parent_state p JOIN kaname.authority_child_creation c ON c.parent_incarnation=p.incarnation WHERE p.object_type='childstage.container' AND p.object_id='container-one' AND p.closed_at IS NULL AND c.child_type='childstage.child' AND c.child_id=$1),
 (SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='childstage.child' AND object_id=$1)`, input.ResourceID, scene.Account, scene.Project, version).Scan(&scopes, &facts, &events, &audits, &receipts, &parents, &reconciles))
	require.Equal(t, 1, scopes)
	require.Equal(t, 1, facts)
	require.Equal(t, 1, events)
	require.Equal(t, 1, audits)
	require.Equal(t, 1, receipts)
	require.Equal(t, 1, parents)
	require.Equal(t, 1, reconciles)
	replay, err := runner.RunUserChildRegistration(ctx, input, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.True(t, version.Equal(replay))
	require.JSONEq(t, string(after), string(snapshot()), "replay сохраняет точный committed набор эффектов")
	handler := childregistration.NewHandler(internaliam.NewUserChildRegistration(runner))
	for i, refused := range []struct {
		input  kaname.UserChildRegistrationInput
		reason string
	}{
		{kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "unregistered-container/candidate"}, "permission_denied"},
		{kaname.UserChildRegistrationInput{ResourceType: "childstage.container", ResourceID: "container-one/candidate"}, "policy_unavailable"},
		{kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/INVALID"}, "invalid_coordinates"},
	} {
		got, callErr := handler.Register(ctx, &iamv1.RegisterChildRequest{ResourceType: refused.input.ResourceType, ResourceId: refused.input.ResourceID})
		require.Nil(t, got)
		answer := status.Convert(callErr)
		require.Equal(t, codes.PermissionDenied, answer.Code())
		require.Equal(t, "permission denied", answer.Message())
		require.Empty(t, answer.Details())
		require.JSONEq(t, string(after), string(snapshot()), "отказ меняет только отдельный reason audit")
		var refusalCount, exactCount int
		expected, err := json.Marshal(map[string]string{"actor": "user:" + principal.ID, "outcome": "permission_denied", "reason": refused.reason})
		require.NoError(t, err)
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*),count(*) FILTER (
 WHERE tenant_account_id IS NULL AND event_payload=$1::jsonb AND status='pending' AND attempts=0)
 FROM kaname.audit_outbox WHERE event_type='iam.child_registration.refused'`, expected).Scan(&refusalCount, &exactCount))
		require.Equal(t, i+1, refusalCount, "один отказ создаёт ровно одну durable строку после rollback")
		require.Equal(t, 1, exactCount, "payload не содержит координат запроса или дополнительных причин")
	}
	authorityWaitReleased(t, r.runtime)
}

func TestUserChildRuntimePrivateCompilerAndQuotaACL(t *testing.T) {
	r, owner, _, _ := childStageFixture(t)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	var privateCount, executable int
	// Runtime вызывает только три общих входа. Все функции закрытого
	// компилятора и тела сохраняют доступ только владельца схемы.
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),count(*) FILTER(WHERE has_function_privilege($1,p.oid,'EXECUTE'))
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='kaname' AND p.proname LIKE '\_authority\_child\_registration\_%' ESCAPE '\'`, r.role).Scan(&privateCount, &executable))
	require.GreaterOrEqual(t, privateCount, 14)
	require.Zero(t, executable, "runtime не исполняет owner-private compiler helpers")
	for _, table := range []string{"kaname.authority_child_parent_state", "kaname.authority_child_creation"} {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`, table).Scan(&allowed))
		require.False(t, allowed, "private quota table %s", table)
	}
}
