// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	accessbinding "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 1045-10: FULL runner и обычный module handler заменяют созданного человеком
// ребёнка. Отказ человеку проверяется на настоящем handler/gate, без заявления
// о сетевом listener: пользовательского RPC снятия регистрации у API нет.
func TestUserChildRuntimeModuleReplacementRejectsHumanAndStaleUnregister(t *testing.T) {
	r, runner, moduleCtx, scene, principal := childRuntimeModuleFixture(t)
	userCtx := operations.WithPrincipal(r.ctx, principal)
	child := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/replacement-child"}
	firstVersion, err := runner.RunUserChildRegistration(userCtx, child, principal)
	resourcePublicRequireNoError(t, err)
	require.False(t, firstVersion.IsZero())
	originalReceipt := childQuotaReceiptSnapshot(t, r)
	var receipts int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_child_creation
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3 AND user_id=$4`,
		child.ResourceType, child.ResourceID, firstVersion, principal.ID).Scan(&receipts))
	require.Equal(t, 1, receipts)
	var creator string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT event_payload->>'actor' FROM kaname.audit_outbox
 WHERE event_payload#>>'{object,id}'=$1`, child.ResourceID).Scan(&creator))
	require.Equal(t, "user:"+principal.ID, creator)

	roster, err := moduleidentity.Parse([]string{"modules/kacho-childstage=module-writer"})
	require.NoError(t, err)
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(roster)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	uc := internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewRegistrationTxBeginner(r.runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
		accessbinding.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalog.Fixed{F: facts}),
		kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(gate)
	require.NoError(t, uc.WithResourceDecisionRunner(runner))
	handler := internaliam.NewHandler(nil, nil).WithResourceRegistrar(uc, gate)
	unregister := &iamv1.UnregisterResourceRequest{SubjectId: "childstage_container:container-one", Relation: "parent",
		Object: "childstage_child:" + child.ResourceID, SourceVersion: timestamppb.New(firstVersion)}
	removed, err := handler.UnregisterResource(moduleCtx, unregister)
	resourcePublicRequireNoError(t, err)
	require.NotNil(t, removed)
	var active int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2)+
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='childstage_child' AND object_id=$2)+
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='childstage_child' AND object_id=$2)`,
		child.ResourceType, child.ResourceID).Scan(&active))
	require.Zero(t, active, "модуль действительно снял прежнюю регистрацию")
	require.JSONEq(t, string(originalReceipt), string(childQuotaReceiptSnapshot(t, r)))

	var replacementVersion time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&replacementVersion))
	require.True(t, replacementVersion.After(firstVersion))
	chain := []string{"childstage_container:container-one", "project:" + scene.Project, "account:" + scene.Account}
	replacement, err := handler.RegisterResource(moduleCtx, &iamv1.RegisterResourceRequest{
		SubjectId: unregister.SubjectId, Relation: unregister.Relation, Object: unregister.Object,
		ParentAccountId: scene.Account, ParentProjectId: scene.Project, ParentChain: chain,
		SourceVersion: timestamppb.New(replacementVersion),
	})
	resourcePublicRequireNoError(t, err)
	require.NotNil(t, replacement)
	var storedVersion time.Time
	var account, project string
	var storedChain []string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT source_version,parent_account_id,parent_project_id,
 (SELECT array_agg(parent_type||':'||parent_id ORDER BY depth) FROM kaname.resource_parent_edge
 WHERE object_type='childstage_child' AND object_id=$2)
 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, child.ResourceType, child.ResourceID).
		Scan(&storedVersion, &account, &project, &storedChain))
	require.True(t, replacementVersion.Equal(storedVersion))
	require.Equal(t, scene.Account, account)
	require.Equal(t, scene.Project, project)
	require.Equal(t, chain, storedChain)
	var scopes, expectedScopes, tuples, expectedTuples int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='childstage_child' AND object_id=$1),
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='childstage_child' AND object_id=$1 AND account_id=$2 AND project_id=$3),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='childstage_child' AND object_id=$1),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='childstage_child' AND object_id=$1
 AND relation='parent' AND subject='childstage_container:container-one' AND source_version=$4)`,
		child.ResourceID, scene.Account, scene.Project, replacementVersion).Scan(&scopes, &expectedScopes, &tuples, &expectedTuples))
	require.Equal(t, 1, scopes)
	require.Equal(t, 1, expectedScopes)
	require.Equal(t, 1, tuples)
	require.Equal(t, 1, expectedTuples)
	require.JSONEq(t, string(originalReceipt), string(childQuotaReceiptSnapshot(t, r)), "module Register не переписывает историю human create")

	// Действительная новая версия не даёт человеку module admission. Проверяем
	// этот отказ до stale module вызова, чтобы не спутать две причины сохранности.
	beforeHuman := childParentCloseSnapshot(t, r)
	humanRequest := &iamv1.UnregisterResourceRequest{SubjectId: unregister.SubjectId, Relation: unregister.Relation,
		Object: unregister.Object, SourceVersion: timestamppb.New(replacementVersion)}
	denied, err := handler.UnregisterResource(userCtx, humanRequest)
	require.Nil(t, denied)
	answer := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, answer.Code())
	require.Equal(t, "permission denied", answer.Message())
	require.Empty(t, answer.Details())
	require.JSONEq(t, string(beforeHuman), string(childParentCloseSnapshot(t, r)), "human Unregister не меняет ни экземпляр, ни историю")

	// Сохраняем точные существовавшие строки истории. Штатный stale audit,
	// если он добавлен, не обязан исчезнуть ради сравнения прежних событий.
	var auditIDs []string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT array_agg(id::text ORDER BY id) FROM kaname.audit_outbox
 WHERE event_payload#>>'{object,id}'=$1`, child.ResourceID).Scan(&auditIDs))
	require.NotEmpty(t, auditIDs)
	actor, _, verified := authzguard.ModuleActor(moduleCtx)
	require.True(t, verified)
	var registrations, unregistrations int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 count(*) FILTER (WHERE event_type='iam.resource_registration.registered'),
 count(*) FILTER (WHERE event_type='iam.resource_registration.unregistered')
 FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1 AND event_payload->>'actor'=$2`,
		child.ResourceID, actor).Scan(&registrations, &unregistrations))
	require.Equal(t, 1, registrations)
	require.Equal(t, 1, unregistrations)
	snapshot := func() json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'mirror',(SELECT to_jsonb(x) FROM kaname.resource_mirror x WHERE object_type=$1 AND object_id=$2),
 'scope',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_scope x WHERE object_type='childstage_child' AND object_id=$2),
 'edges',(SELECT jsonb_agg(to_jsonb(x) ORDER BY depth) FROM kaname.resource_parent_edge x WHERE object_type='childstage_child' AND object_id=$2),
 'facts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.relation_fact x WHERE object_type='childstage_child' AND object_id=$2),
 'receipts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY source_version) FROM kaname.authority_child_creation x WHERE child_type=$1 AND child_id=$2),
 'history',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.audit_outbox x WHERE id::text=ANY($3::text[])))`,
			child.ResourceType, child.ResourceID, auditIDs).Scan(&raw))
		return raw
	}
	beforeStale := snapshot()
	stale, err := handler.UnregisterResource(moduleCtx, unregister)
	resourcePublicRequireNoError(t, err)
	require.NotNil(t, stale, "запоздалое снятие остаётся идемпотентным успехом модуля")
	require.JSONEq(t, string(beforeStale), string(snapshot()), "старая версия не меняет новый экземпляр, scope, цепь, факты или прежнюю историю")
	require.JSONEq(t, string(originalReceipt), string(childQuotaReceiptSnapshot(t, r)))
	authorityWaitReleased(t, r.runtime)
}
