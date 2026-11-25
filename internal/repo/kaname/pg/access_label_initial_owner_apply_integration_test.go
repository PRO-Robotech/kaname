// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Владелец аккаунта получает первый apply от установочного владельца БД
// при действующем FULL. Project.Update и Revoke работают через обычный LOGIN.
func TestInitialAccessLabelApplyIssuesExactAndRevocableOwnerGrant(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	seedMembership(t, r.ctx, r.admin, domain.UserID(actor), domain.AccountID(r.a), "ACTIVE")
	var activeVerifiedOwner bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS (
 SELECT FROM kaname.accounts a JOIN kaname.users u ON u.id=a.owner_user_id
 JOIN kaname.memberships m ON m.account_id=a.id AND m.user_id=u.id
 WHERE a.id=$1 AND u.id=$2 AND u.invite_status='ACTIVE' AND u.email_verified_at IS NOT NULL
 AND m.state='ACTIVE')`, r.a, actor).Scan(&activeVerifiedOwner))
	require.True(t, activeVerifiedOwner)

	first := seedMetadataActualProject(t, r, "initial-apply-first")
	neighbor := seedMetadataActualProject(t, r, "initial-apply-neighbor")
	declare := func(id domain.ProjectID, key string, values ...string) kanamepg.AccessLabelDeclarationResult {
		t.Helper()
		definition, err := owner.AddAccessLabelValues(r.ctx, kanamepg.AccessLabelDeclaration{
			Account: r.a, Project: string(id), Module: "iam", Resource: "project", Key: key, Values: values,
		})
		require.NoError(t, err)
		require.NotEmpty(t, definition.ID)
		require.Positive(t, definition.Revision)
		return definition
	}
	declared := declare(first.ID, "classification", "internal")
	exact := declare(first.ID, "classification", "public")
	require.Equal(t, declared.ID, exact.ID)
	require.Less(t, declared.Revision, exact.Revision)
	declare(first.ID, "handling", "standard")
	declare(neighbor.ID, "classification", "internal")

	// У обычных ролей фикстуры есть только права вызова методов.
	editor := groupLifecycleBinding(t, r, r.a, actor, "initial_apply_project_update", domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"update"},
	})
	remover := groupLifecycleBinding(t, r, r.a, actor, "initial_apply_binding_revoke", domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "delete"},
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, editor))
	require.NoError(t, engine.ReconcileBinding(r.ctx, remover))
	full, contract := fullContractActivate(t, r)
	r.repo = full
	var static bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT EXISTS(SELECT FROM ONLY kaname.publication_model_revision)`).Scan(&static))
	require.True(t, static, "выдача использует активный FULL до первой публикации")

	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	ops := operations.NewRepo(r.runtime, "kaname")
	factory, err := kanamepg.NewMetadataMutationWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	ports, err := factory.WithInstalledAccessLabels(r.ctx)
	require.NoError(t, err)
	_, protected := ports.(kaname.ProjectAccessLabelsWriterFactory)
	require.True(t, protected)
	update := projectapp.NewUpdateProjectUseCase(full, ops).
		WithRelationStore(door, nil).WithProjectMetadataWriter(ports)
	ctx := contract.Context(declarerCtx(r.ctx, actor))
	projects := []string{string(first.ID), string(neighbor.ID)}
	for _, id := range projects {
		allowed, err := door.Check(ctx, "user:"+actor, "v_update", "project:"+id)
		require.NoError(t, err)
		require.True(t, allowed, "обычное право Project.Update действует в обоих проектах")
	}
	setLabels := func(id domain.ProjectID, labels domain.Labels, want codes.Code) {
		t.Helper()
		before := metadataActualProjectSnapshot(t, r, projects)
		op, err := update.Execute(ctx, projectapp.UpdateProjectInput{
			ID: id, AccessLabels: labels, UpdateMask: []string{"access_labels"},
		})
		require.NoError(t, err)
		done := awaitOperation(t, ctx, ops, op.ID)
		if want == codes.OK {
			require.Nil(t, done.Error)
			return
		}
		require.NotNil(t, done.Error)
		require.Equal(t, int32(want), done.Error.Code, done.Error.Message)
		require.JSONEq(t, before, metadataActualProjectSnapshot(t, r, projects))
	}
	type issuanceState struct {
		roles, bindings, projections, issuances, grants, revocations int
	}
	state := func() issuanceState {
		t.Helper()
		var n issuanceState
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.roles),
 (SELECT count(*) FROM kaname.access_bindings),
 (SELECT count(*) FROM kaname.authority_role_access_label_rule),
 (SELECT count(*) FROM kaname.authority_initial_access_label_apply_issuance),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.access_binding.granted'),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.access_binding.revoked')`).
			Scan(&n.roles, &n.bindings, &n.projections, &n.issuances, &n.grants, &n.revocations))
		return n
	}

	original := state()
	require.Zero(t, original.projections, "первый источник apply должен создать проверяемый вызов")
	require.Zero(t, original.issuances)
	setLabels(first.ID, domain.Labels{"classification": "internal"}, codes.PermissionDenied)
	input := kanamepg.InitialAccessLabelApply{
		Account: r.a, Project: string(first.ID),
		DefinitionID: domain.AccessLabelDefinitionID(exact.ID), ExpectedRevision: exact.Revision,
	}
	stale := input
	stale.ExpectedRevision = declared.Revision
	_, err = owner.IssueInitialAccessLabelApply(r.ctx, stale, r.bundle)
	requireAccessDefinitionSQLState(t, err, "42501")
	wrongProject := input
	wrongProject.Project = string(neighbor.ID)
	_, err = owner.IssueInitialAccessLabelApply(r.ctx, wrongProject, r.bundle)
	requireAccessDefinitionSQLState(t, err, "42501")
	_, err = full.IssueInitialAccessLabelApply(ctx, input, r.bundle)
	requireAccessDefinitionSQLState(t, err, "42501")
	require.Equal(t, original, state(), "отказы не создали роль, выдачу, проекцию или аудит")
	setLabels(first.ID, domain.Labels{"classification": "internal"}, codes.PermissionDenied)

	t.Run("commit-guards-incomplete-issuance", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		identity := r.bundle.Identity()
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_installation_enter_v3('role',$1,$2,$3)`,
			identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		require.NoError(t, err)
		rules, err := domain.EncodeRules(domain.Rules{accessRoleApply(exact.ID)})
		require.NoError(t, err)
		temporaryRole := ids.NewID(domain.PrefixRole)
		_, err = tx.Exec(r.ctx, `INSERT INTO kaname.roles(id,project_id,name,permissions,rules,created_at)
VALUES ($1,$2,'initial_apply_incomplete','[]'::jsonb,$3::jsonb,clock_timestamp())`, temporaryRole, first.ID, rules)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, `SELECT kaname._authority_initial_access_label_apply_project_v1($1,$2,$3::uuid,$4,$5)`,
			input.Account, input.Project, input.DefinitionID, input.ExpectedRevision, temporaryRole)
		require.NoError(t, err)
		requireAccessDefinitionSQLState(t, tx.Commit(r.ctx), "42501")
		require.Equal(t, original, state(), "запись откатывается без полной привязки и квитанции")
	})

	type issueResult struct {
		value kanamepg.InitialAccessLabelApplyResult
		err   error
	}
	issuedResults := make(chan issueResult, 2)
	for range 2 {
		go func() {
			value, err := owner.IssueInitialAccessLabelApply(r.ctx, input, r.bundle)
			issuedResults <- issueResult{value: value, err: err}
		}()
	}
	firstIssue, concurrentRepeat := <-issuedResults, <-issuedResults
	require.NoError(t, firstIssue.err)
	require.NoError(t, concurrentRepeat.err)
	require.Equal(t, firstIssue.value, concurrentRepeat.value, "одновременный повтор получает ту же выдачу")
	issued := firstIssue.value
	require.NotEmpty(t, issued.RoleID)
	require.NotEmpty(t, issued.BindingID)
	expected := original
	expected.roles++
	expected.bindings++
	expected.projections++
	expected.issuances++
	expected.grants++
	require.Equal(t, expected, state())
	binding := bindingRow(t, r, issued.BindingID)
	require.Equal(t, issued.RoleID, binding.RoleID)
	require.Equal(t, domain.AccessBindingStatusActive, binding.Status)
	require.Equal(t, domain.ScopeProject, binding.Scope)
	require.Equal(t, domain.ResourceType("project"), binding.ResourceType)
	require.Equal(t, string(first.ID), binding.ResourceID)
	require.Equal(t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}}, binding.Subjects)
	require.False(t, binding.System)
	require.False(t, binding.DeletionProtection)
	require.Empty(t, binding.GrantedRelation)
	var definitionID string
	var permissions, rules []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT p.definition_id::text,r.permissions,r.rules
 FROM kaname.authority_role_access_label_rule p JOIN kaname.roles r ON r.id=p.role_id
 WHERE p.role_id=$1`, issued.RoleID).Scan(&definitionID, &permissions, &rules))
	require.Equal(t, exact.ID, definitionID)
	require.JSONEq(t, `[]`, string(permissions))
	expectedRules, err := domain.EncodeRules(domain.Rules{accessRoleApply(exact.ID)})
	require.NoError(t, err)
	require.JSONEq(t, string(expectedRules), string(rules))

	setLabels(first.ID, domain.Labels{"classification": "internal"}, codes.OK)
	var labels string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT access_labels::text FROM kaname.projects WHERE id=$1`, first.ID).Scan(&labels))
	require.JSONEq(t, `{"classification":"internal"}`, labels)
	setLabels(first.ID, domain.Labels{"classification": "internal", "handling": "standard"}, codes.PermissionDenied)
	setLabels(neighbor.ID, domain.Labels{"classification": "internal"}, codes.PermissionDenied)
	setLabels(first.ID, domain.Labels{"classification": "unlisted"}, codes.PermissionDenied)

	// Штатный обработчик outbox материализует v_delete на новом объекте
	// привязки из сохранённой обычной роли, с которой будет вызван Revoke.
	objectParticipant, err := kanamepg.NewResourceObjectParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	objectReconciler, err := objectParticipant.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	background := reconcile.New(kanamepg.NewReconcileAdapter(r.runtime, source), slog.Default(), source)
	require.NoError(t, background.WithObjectReconciler(objectReconciler))
	require.NoError(t, background.ReconcileObjectForwardNoStale(ctx, "iam.accessBinding", string(issued.BindingID)))
	revoke := bindingapp.NewRevokeAccessBindingUseCase(full, ops).
		WithRelationStore(door, slog.Default()).WithBindingWithdrawal(withdrawalParticipant(t, r, nil))
	op, err := revoke.Execute(ctx, issued.BindingID)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, ctx, ops, op.ID).Error)
	revoked := bindingRow(t, r, issued.BindingID)
	require.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status)
	require.NotNil(t, revoked.RevokedAt)
	require.NotNil(t, revoked.RevokedByUserID)
	require.Equal(t, domain.UserID(actor), *revoked.RevokedByUserID)
	var grants, revokes int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 count(*) FILTER (WHERE event_type='iam.access_binding.granted'),
 count(*) FILTER (WHERE event_type='iam.access_binding.revoked' AND event_payload->>'actor'=$3)
 FROM kaname.audit_outbox
 WHERE event_payload->>'binding_id'=$1 AND event_payload->>'role_id'=$2
 AND event_payload->>'subject_type'='user' AND event_payload->>'subject_id'=$3
 AND event_payload->>'resource_type'='project' AND event_payload->>'resource_id'=$4`,
		issued.BindingID, issued.RoleID, actor, first.ID).Scan(&grants, &revokes))
	require.Equal(t, 1, grants)
	require.Equal(t, 1, revokes)
	allowed, err := door.Check(ctx, "user:"+actor, "v_update", "project:"+string(first.ID))
	require.NoError(t, err)
	require.True(t, allowed, "отзыв apply сохраняет обычное право Project.Update")
	setLabels(first.ID, domain.Labels{"classification": "public"}, codes.PermissionDenied)

	terminal := state()
	repeated, err := owner.IssueInitialAccessLabelApply(r.ctx, input, r.bundle)
	require.NoError(t, err)
	require.Equal(t, issued, repeated, "повтор возвращает уже отозванную выдачу")
	require.Equal(t, terminal, state(), "повтор не создаёт выдачу или событие аудита")
	require.Equal(t, revoked, bindingRow(t, r, issued.BindingID))
	setLabels(first.ID, domain.Labels{"classification": "public"}, codes.PermissionDenied)
}
