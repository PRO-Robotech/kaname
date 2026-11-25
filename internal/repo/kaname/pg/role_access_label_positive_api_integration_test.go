// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Настоящий source устанавливается owner ДО handoff ровно как в
// TestRoleAccessLabelNativeSourceUsesExactSignedReceiptAndSourceGeneration.
// После handoff нет подмены writer/checker и нет прямой записи apply projection.
func TestRoleAccessLabelProtectedApplyThroughActualCreateAndUpdate(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	first := seedAccessDefinition(t, r, "account", r.a, "role_api_first")
	second := seedAccessDefinition(t, r, "account", r.a, "role_api_second")
	noSource := seedAccessDefinition(t, r, "account", r.a, "role_api_no_source")
	var actor, secondHolder string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&actor))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.b).Scan(&secondHolder))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.memberships(id,user_id,account_id,state)
 VALUES(kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE')`, secondHolder, r.a)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}
	ordinary := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}}
	source := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: "role_api_source",
		Rules: domain.Rules{accessRoleApply(first.id), accessRoleApply(second.id)}}
	target := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: "role_api_existing", Rules: domain.Rules{ordinary}}
	seed, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	for _, role := range []*domain.Role{&source, &target} {
		ordinaryRules, _, splitErr := domain.SplitGrantCapabilityRules(role.Rules)
		require.NoError(t, splitErr)
		role.Permissions, err = domain.CompileRules(ordinaryRules)
		require.NoError(t, err)
		projection, projectionErr := r.bundle.Projection(*role)
		require.NoError(t, projectionErr)
		_, err = seed.RolesW().Insert(r.ctx, *role)
		require.NoError(t, err)
		require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, projection.Selectors))
		require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, projection.Verbs))
	}
	sourceExpiry := time.Now().UTC().Add(time.Hour)
	sourceBinding, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: subject.Type, SubjectID: subject.ID, Subjects: []domain.Subject{subject},
		RoleID: source.ID, ResourceType: "account", ResourceID: r.a, Scope: domain.DeriveFromResourceType("account"),
		Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}, ExpiresAt: &sourceExpiry,
	})
	require.NoError(t, err)
	var carriers []domain.AccessBindingID
	for _, fixture := range []struct {
		subject domain.Subject
		status  domain.AccessBindingStatus
	}{
		{subject, domain.AccessBindingStatusActive},
		{domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(secondHolder)}, domain.AccessBindingStatusPending},
	} {
		carrier, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
			ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: fixture.subject.Type, SubjectID: fixture.subject.ID, Subjects: []domain.Subject{fixture.subject},
			RoleID: target.ID, ResourceType: "account", ResourceID: r.a, Scope: domain.DeriveFromResourceType("account"),
			Status: fixture.status, Target: domain.AccessTarget{AllInScope: true},
		})
		require.NoError(t, err)
		carriers = append(carriers, carrier.ID)
	}
	require.NoError(t, seed.Commit(r.ctx))
	_, caps, err := domain.SplitGrantCapabilityRules(source.Rules)
	require.NoError(t, err)
	require.Len(t, caps, 2)
	privateSeed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, privateSeed)
	_, err = privateSeed.Exec(r.ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1`, sourceBinding.ID)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	for _, cap := range caps {
		_, err = privateSeed.Exec(r.ctx, accessRoleProjectionInsert, source.ID, cap.RuleFP, string(cap.DefinitionID))
		require.NoError(t, err)
	}
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, privateSeed.Commit(r.ctx))

	t.Run("resource-write-apply-requires-live-exact-source", func(t *testing.T) {
		for _, tc := range []struct {
			name, key, actorID string
			at                 time.Time
			allowed            bool
		}{
			{"active_exact_apply", "role_api_first", actor, sourceExpiry.Add(-30 * time.Minute), true},
			{"expired_at_decision_clock", "role_api_first", actor, sourceExpiry.Add(time.Minute), false},
			{"owner_without_apply_does_not_inherit", "role_api_no_source", actor, sourceExpiry.Add(-30 * time.Minute), false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tx, txErr := r.admin.Begin(r.ctx)
				require.NoError(t, txErr)
				lifecycleRollback(t, tx)
				old := resourceAccessLabelImage(t, r.a, "", map[string]string{tc.key: "old"})
				next := resourceAccessLabelImage(t, r.a, "", nil)
				var definitions []byte
				require.NoError(t, tx.QueryRow(r.ctx, resourceAccessLabelRequirementsSQL,
					"account", old, next, 1000, 100).Scan(&definitions))
				var requirement struct {
					Records json.RawMessage `json:"requirements"`
				}
				require.NoError(t, json.Unmarshal(definitions, &requirement))
				var sources []byte
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_resource_access_label_sources_hold_v1(
					'user',$1,$2::jsonb,1000,100)`, tc.actorID, requirement.Records).Scan(&sources))
				_, applyErr := tx.Exec(r.ctx, `SELECT kaname._authority_resource_access_label_sources_require_v1(
					$1::jsonb,$2::jsonb,$3,1000,100)`, sources, requirement.Records, tc.at)
				if tc.allowed {
					require.NoError(t, applyErr)
				} else {
					requireAccessDefinitionSQLState(t, applyErr, "42501")
				}
			})
		}
	})

	// Конечный ACL профиль агента: отдельный LOGIN, без grant_runtime/SET ROLE.
	pool, _, diagnostic := roleActorFiniteLogin(t, r)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	shared, sharedContract := fullContractActivate(t, r)
	roleRepo := kanamepg.New(pool, nil)
	roleContract, err := kanamepg.NewFullWriterContract(r.ctx, roleRepo, r.bundle)
	require.NoError(t, err)
	roleRepo, err = roleRepo.WithFullWriterContract(roleContract)
	require.NoError(t, err)
	roleWriters, err := kanamepg.NewRolePolicyWriters(r.ctx, shared, roleRepo, r.bundle)
	require.NoError(t, err)
	writers := &finiteRoleWriterDiagnostic{RolePolicyWriters: roleWriters, diagnostic: diagnostic}
	ops := operations.NewRepo(r.runtime, "kaname")
	catalog := rolePolicyCatalog(t, r)
	create := roleapp.NewCreateRoleUseCase(shared, ops, catalog).WithRoleAuthorityWriter(writers)
	update := roleapp.NewUpdateRoleUseCase(shared, ops, catalog).WithRoleAuthorityWriter(writers).
		WithTupleReconciler(bindingapp.NewRoleTupleReconciler())
	ctx := sharedContract.Context(declarerCtx(r.ctx, actor))

	// Durable oracle — owner читает результат уже завершённого API commit.
	exactProjection := func(t *testing.T, id domain.RoleID, rules domain.Rules) {
		t.Helper()
		_, expected, err := domain.SplitGrantCapabilityRules(rules)
		require.NoError(t, err)
		type row struct {
			RuleFP       string
			DefinitionID domain.AccessLabelDefinitionID
		}
		want := make([]row, 0, len(expected))
		for _, cap := range expected {
			want = append(want, row{cap.RuleFP, cap.DefinitionID})
		}
		rows, err := r.admin.Query(r.ctx, `SELECT rule_fp,definition_id::text FROM kaname.authority_role_access_label_rule WHERE role_id=$1 ORDER BY rule_fp,definition_id`, id)
		require.NoError(t, err)
		got := make([]row, 0, len(expected))
		for rows.Next() {
			var v row
			require.NoError(t, rows.Scan(&v.RuleFP, &v.DefinitionID))
			got = append(got, v)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.ElementsMatch(t, want, got, "полный exact набор, не только count")
		var stored []byte
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT rules FROM kaname.roles WHERE id=$1`, id).Scan(&stored))
		expectedRules, err := domain.EncodeRules(rules)
		require.NoError(t, err)
		require.JSONEq(t, string(expectedRules), string(stored))
	}

	t.Run("public-role-handler-stores-protected-selector", func(t *testing.T) {
		handler := roleapp.NewHandler(create, update, nil, nil, nil)
		rule := &iamv1.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
			MatchAccessLabels: map[string]string{"team": "first"}}
		op, err := handler.Create(ctx, &iamv1.CreateRoleRequest{
			AccountId: r.a, Name: "role_api_selector", Rules: []*iamv1.Rule{rule},
		})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.GetId()).Error)
		var roleID domain.RoleID
		require.NoError(t, r.admin.QueryRow(r.ctx,
			`SELECT id FROM kaname.roles WHERE account_id=$1 AND name='role_api_selector'`, r.a).Scan(&roleID))
		assertSelector := func(value string) {
			t.Helper()
			exactProjection(t, roleID, domain.Rules{{Module: "iam", Resources: []string{"project"},
				Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": value}}})
			var arm string
			var stored, ordinary []byte
			require.NoError(t, r.admin.QueryRow(r.ctx,
				`SELECT arm,match_access_labels,match_labels FROM kaname.role_rule_selectors WHERE role_id=$1`,
				roleID).Scan(&arm, &stored, &ordinary))
			require.Equal(t, "access_labels", arm)
			expected, encodeErr := json.Marshal(map[string]string{"team": value})
			require.NoError(t, encodeErr)
			require.JSONEq(t, string(expected), string(stored))
			require.JSONEq(t, `{}`, string(ordinary))
		}
		assertSelector("first")
		rule.MatchAccessLabels = map[string]string{"team": "second"}
		op, err = handler.Update(ctx, &iamv1.UpdateRoleRequest{
			RoleId: string(roleID), Rules: []*iamv1.Rule{rule},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}},
		})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.GetId()).Error)
		assertSelector("second")
	})

	var created domain.RoleID
	t.Run("create-fallback-definition-scope", func(t *testing.T) {
		rules := domain.Rules{accessRoleApply(first.id)}
		op, err := create.Execute(ctx, domain.Role{AccountID: domain.AccountID(r.a), Name: "role_api_created", Rules: rules})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name='role_api_created'`, r.a).Scan(&created))
		exactProjection(t, created, rules)
		var permissions []byte
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT permissions FROM kaname.roles WHERE id=$1`, created).Scan(&permissions))
		var ordinaryPermissions []string
		require.NoError(t, json.Unmarshal(permissions, &ordinaryPermissions))
		require.Empty(t, ordinaryPermissions, "apply не превращается в ordinary permission")
	})
	t.Run("update-active-and-pending-carriers-two-definitions", func(t *testing.T) {
		rules := domain.Rules{ordinary, accessRoleApply(first.id), accessRoleApply(second.id)}
		op, err := update.Execute(ctx, roleapp.UpdateRoleInput{ID: target.ID, Rules: rules, UpdateMask: []string{"rules"}})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
		exactProjection(t, target.ID, rules)
		for _, id := range carriers {
			var version int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT grant_capability_version FROM kaname.access_bindings WHERE id=$1`, id).Scan(&version))
			require.Equal(t, 1, version)
		}
	})
	t.Run("metadata-preserves-protected-projection", func(t *testing.T) {
		require.NotEmpty(t, created)
		description := domain.Description("ordinary metadata after protected create")
		op, err := update.Execute(ctx, roleapp.UpdateRoleInput{ID: created, Description: &description, UpdateMask: []string{"description"}})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
		exactProjection(t, created, domain.Rules{accessRoleApply(first.id)})
		var stored string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.roles WHERE id=$1`, created).Scan(&stored))
		require.Equal(t, string(description), stored)
	})
	t.Run("ordinary-owner-admin-cannot-replace-exact-apply-source", func(t *testing.T) {
		op, err := create.Execute(ctx, domain.Role{AccountID: domain.AccountID(r.a), Name: "role_api_missing_source", Rules: domain.Rules{accessRoleApply(noSource.id)}})
		require.NoError(t, err)
		outcome := awaitOperation(t, r.ctx, ops, op.ID)
		require.NotNil(t, outcome.Error)
		require.Equal(t, int32(codes.PermissionDenied), outcome.Error.GetCode())
		var count int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.roles WHERE account_id=$1 AND name='role_api_missing_source'`, r.a).Scan(&count))
		require.Zero(t, count)
	})
	t.Run("clean-revoke-clears-the-protected-projection", func(t *testing.T) {
		exactProjection(t, target.ID, domain.Rules{ordinary, accessRoleApply(first.id), accessRoleApply(second.id)})
		rules := domain.Rules{ordinary}
		op, err := update.Execute(ctx, roleapp.UpdateRoleInput{ID: target.ID, Rules: rules, UpdateMask: []string{"rules"}})
		require.NoError(t, err)
		require.Nil(t, awaitOperation(t, r.ctx, ops, op.ID).Error)
		exactProjection(t, target.ID, rules)
	})
}
