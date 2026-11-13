// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestGrantAuthoringActualCreateUpdateProjectionAndRollback(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, account := kac127SeedUserAndAccount(t, ctx, pool, "metaauthor")
	project := kac127SeedProject(t, ctx, pool, account, "metaauthor")
	plans, err := authzmodel.New(authzmodel.DSL)
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	cat := catalog.Fixed{F: facts}
	ops := operations.NewRepo(pool, "kaname")
	emit := func(tuples ...outboxtypes.RelationTuple) {
		w, e := repo.Writer(ctx)
		require.NoError(t, e)
		defer w.Rollback(ctx)
		require.NoError(t, w.EmitFGARelationWrite(ctx, tuples))
		require.NoError(t, w.Commit(ctx))
	}
	// Настоящий native predicate; субъект — существующий owner аккаунта.
	emit(outboxtypes.RelationTuple{User: "user:" + uid, Relation: "owner", Object: "account:" + account})
	create := func(name string, rules domain.Rules, prj string, wantOK bool) domain.RoleID {
		r := domain.Role{Name: domain.RoleName(name), Rules: rules}
		if prj != "" {
			r.ProjectID = domain.ProjectID(prj)
		} else {
			r.AccountID = domain.AccountID(account)
		}
		op, e := roleapp.NewCreateRoleUseCase(repo, ops, cat).WithGrantReferencePlans(plans).Execute(declarerCtx(ctx, uid), r)
		require.NoError(t, e)
		done := awaitOperation(t, ctx, ops, op.ID)
		var meta iamv1.CreateRoleMetadata
		require.NoError(t, done.Metadata.UnmarshalTo(&meta))
		id := domain.RoleID(meta.GetRoleId())
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.roles WHERE id=$1`, id).Scan(&n))
		if wantOK {
			require.Nil(t, done.Error)
			require.Equal(t, 1, n)
		} else {
			require.NotNil(t, done.Error)
			require.Zero(t, n)
		}
		return id
	}
	ordinary := domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	target := create("meta_project_target", ordinary, project, true)
	// Project-role не имеет account pointer: реальная видимость задаётся отдельно.
	emit(outboxtypes.RelationTuple{User: "user:" + uid, Relation: "viewer", Object: "iam_role:" + string(target)})
	rules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(target)}}, {Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}, {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}
	owner := create("meta_account_owner", rules, "", true)
	check := func(id domain.RoleID, wantCreate, wantBind int) {
		var c, b int
		require.NoError(t, pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.role_create_binding_rule WHERE role_id=$1),(SELECT count(*) FROM kaname.role_bind_role_rule WHERE role_id=$1)`, id).Scan(&c, &b))
		require.Equal(t, wantCreate, c)
		require.Equal(t, wantBind, b)
	}
	check(owner, 1, 1)
	var metaOrdinary int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_verb WHERE role_id=$1 AND verb IN ('bind','create')`, owner).Scan(&metaOrdinary))
	require.Zero(t, metaOrdinary)

	// Исторический version=0 carrier с FP полного mixed-правила сохраняет
	// ordinary selector через настоящий loader. Рядом новый producer даёт residual FP.
	mixed := domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get", "create"}}}
	legacy := create("meta_legacy_layout", mixed, "", true)
	oldFP := mixed.MaterializingSelectors()[0].RuleFP
	rw, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, rw.RolesW().ReplaceRuleSelectors(ctx, legacy, facts.GrantSelectors(mixed.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, rw.RolesW().ReplaceGrantCapabilities(ctx, legacy, nil))
	require.NoError(t, rw.Commit(ctx))
	abID := ids.NewID(domain.PrefixAccessBinding)
	seedTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = seedTx.Exec(ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status) VALUES($1,'user',$2,$3,'account',$4,'ACTIVE')`, abID, uid, legacy, account)
	require.NoError(t, err)
	_, err = seedTx.Exec(ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES($1,'user',$2)`, abID, uid)
	require.NoError(t, err)
	require.NoError(t, seedTx.Commit(ctx))
	loadFP := func(want string) {
		require.NoError(t, kanamepg.NewReconcileAdapter(pool, cat).WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
			b, ok, e := s.LoadBinding(ctx, domain.AccessBindingID(abID))
			require.NoError(t, e)
			require.True(t, ok)
			require.Len(t, b.Selectors, 1)
			require.Equal(t, want, b.Selectors[0].RuleFP)
			return nil
		}))
	}
	loadFP(oldFP)
	projection, err := facts.ProjectGrantRules(mixed, domain.TenantPolicy())
	require.NoError(t, err)
	rw, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, rw.RolesW().ReplaceRuleSelectors(ctx, legacy, projection.Selectors))
	require.NoError(t, rw.Commit(ctx))
	loadFP(projection.Selectors[0].RuleFP)
	// Смена FP при автоматическом сужении переносит только точные прежние
	// producer строки: снятая/отсутствующая ссылка не воскресает.
	before := []domain.GrantCapabilityRule{{RuleFP: strings.Repeat("a", 64), Kind: domain.GrantCapabilityBindRole, BoundRoleID: target}, {RuleFP: strings.Repeat("b", 64), Kind: domain.GrantCapabilityBindRole, BoundRoleID: owner}}
	after := []domain.GrantCapabilityRule{{RuleFP: strings.Repeat("c", 64), Kind: domain.GrantCapabilityBindRole, BoundRoleID: target}, {RuleFP: strings.Repeat("d", 64), Kind: domain.GrantCapabilityBindRole, BoundRoleID: owner}}
	rw, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, rw.RolesW().ReplaceGrantCapabilities(ctx, legacy, before[:1]))
	require.NoError(t, rw.RolesW().(rolerepo.GrantProjectionRetainer).RetainGrantCapabilities(ctx, legacy, before, after))
	require.NoError(t, rw.Commit(ctx))
	check(legacy, 0, 1)
	var kept string
	require.NoError(t, pool.QueryRow(ctx, `SELECT rule_fp FROM kaname.role_bind_role_rule WHERE role_id=$1`, legacy).Scan(&kept))
	require.Equal(t, after[0].RuleFP, kept)
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	readProof := func(wantOK bool) {
		w, e := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
		require.NoError(t, e)
		defer w.Rollback(ctx)
		cp, cost, e := w.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(ctx, owner)
		require.Positive(t, cost.Rows)
		if wantOK {
			require.NoError(t, e)
			require.NotEmpty(t, cp.ProjectionID)
		} else {
			require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		}
		require.NoError(t, w.Rollback(ctx))
	}
	readProof(true)
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	unresolved, err := rd.Roles().UnresolvedSegments(ctx, domain.SegmentsOf(owner, rules))
	require.NoError(t, err)
	require.Empty(t, unresolved[owner])
	require.NoError(t, rd.Rollback(ctx))
	update := func(next domain.Rules, wantOK bool) {
		op, e := roleapp.NewUpdateRoleUseCase(repo, ops, cat).WithGrantReferencePlans(plans).WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(repo, nil)).Execute(declarerCtx(ctx, uid), roleapp.UpdateRoleInput{ID: owner, Rules: next, UpdateMask: []string{"rules"}})
		require.NoError(t, e)
		done := awaitOperation(t, ctx, ops, op.ID)
		if wantOK {
			require.Nil(t, done.Error)
		} else {
			require.NotNil(t, done.Error)
		}
	}
	// Ошибка последней ссылки не сохраняет частичную роль/проекцию.
	missing := ids.NewID(domain.PrefixRole)
	invalid := append(domain.Rules{}, rules...)
	invalid[0].ResourceNames = []string{string(target), missing}
	update(invalid, false)
	check(owner, 1, 1)
	readProof(true)
	update(ordinary, true)
	check(owner, 0, 0)
	readProof(true)
	update(rules, true)
	check(owner, 1, 1)
	readProof(true)

	// Бюджет учитывает ВСЕ прочитанные meta rows до recoverable mismatch.
	sw, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
	require.NoError(t, err)
	extra := make([]domain.GrantCapabilityRule, 4096)
	for i := range extra {
		extra[i] = domain.GrantCapabilityRule{RuleFP: fmt.Sprintf("%064x", i+1), Kind: domain.GrantCapabilityCreateBinding}
	}
	require.NoError(t, sw.RolesW().ReplaceGrantCapabilities(ctx, owner, extra))
	_, cost, err := sw.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(ctx, owner)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Greater(t, cost.Rows, 4096)
	require.NoError(t, sw.Rollback(ctx))
	check(owner, 1, 1)
	readProof(true)
	invisible := create("meta_invisible_target", ordinary, project, true)
	denied := append(domain.Rules{}, rules...)
	denied[0].ResourceNames = []string{string(invisible)}
	create("meta_invisible_owner", denied, "", false)
	_, foreignAccount := kac127SeedUserAndAccount(t, ctx, pool, "metaforeign")
	foreignProject := kac127SeedProject(t, ctx, pool, foreignAccount, "metaforeign")
	foreign := create("meta_foreign_target", ordinary, foreignProject, true)
	emit(outboxtypes.RelationTuple{User: "user:" + uid, Relation: "viewer", Object: "iam_role:" + string(foreign)})
	denied[0].ResourceNames = []string{string(foreign)}
	create("meta_foreign_owner", denied, "", false)
	// System/module роль — реальная строка каталога, а не prefix/ID shortcut.
	var systemID, systemModule string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id,owner_module FROM kaname.roles WHERE is_system AND live AND owner_module IS NOT NULL ORDER BY id LIMIT 1`).Scan(&systemID, &systemModule))
	systemRules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{systemID}}}
	systemOwner := create("meta_system_reference", systemRules, "", true)
	check(systemOwner, 0, 1)
	rw, err = repo.Writer(ctx)
	require.NoError(t, err)
	retirement, err := rw.RolesW().RetireRole(ctx, domain.RoleID(systemID), systemModule, "kaname#1034 lifecycle probe", uid)
	require.NoError(t, err)
	require.True(t, retirement.Marked)
	require.NoError(t, rw.Commit(ctx))
	check(systemOwner, 0, 0)
	create("meta_withdrawn_reference", systemRules, "", false)
	rw, err = repo.Writer(ctx)
	require.NoError(t, err)
	revived, err := rw.RolesW().ReviveRole(ctx, domain.RoleID(systemID))
	require.NoError(t, err)
	require.True(t, revived)
	require.NoError(t, rw.Commit(ctx))
	check(systemOwner, 0, 0)

	// Фактическое удаление producer-role удаляет incoming reference; authored Rules
	// остаются как объяснение, а checkpoint и preview не обещают живую цель.
	op, err := roleapp.NewDeleteRoleUseCase(repo, ops).Execute(declarerCtx(ctx, uid), target)
	require.NoError(t, err)
	done := awaitOperation(t, ctx, ops, op.ID)
	require.Nil(t, done.Error)
	check(owner, 1, 0)
	readProof(false)
	rd, err = repo.Reader(ctx)
	require.NoError(t, err)
	unresolved, err = rd.Roles().UnresolvedSegments(ctx, domain.SegmentsOf(owner, rules))
	require.NoError(t, err)
	require.Contains(t, unresolved[owner], domain.RoleSegment{RoleID: owner, ObjectType: "iam.role", Verb: "bind"})
	require.NoError(t, rd.Rollback(ctx))

	// Снятие authoring axis в той же TX удаляет meta; rollback возвращает её.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `DELETE FROM kaname.role_rule_ref WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `UPDATE kaname.catalog_verb SET live=false WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	var retired int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.role_create_binding_rule WHERE role_id=$1`, owner).Scan(&retired))
	require.Zero(t, retired)
	_, err = tx.Exec(ctx, `UPDATE kaname.catalog_verb SET live=true WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.role_create_binding_rule WHERE role_id=$1`, owner).Scan(&retired))
	require.Zero(t, retired)
	require.NoError(t, tx.Rollback(ctx))
	check(owner, 1, 0)
	// Старый in-memory catalog ещё живой: отказ обязан дать реальный same-TX axis.
	_, err = pool.Exec(ctx, `DELETE FROM kaname.role_rule_ref WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE kaname.catalog_verb SET live=false WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	create("meta_stale_catalog", domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}}, "", false)
	_, err = pool.Exec(ctx, `UPDATE kaname.catalog_verb SET live=true WHERE module='iam' AND resource='accessBinding' AND verb='create'`)
	require.NoError(t, err)
	check(owner, 0, 0)
	var activated int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.access_bindings WHERE grant_capability_version<>0`).Scan(&activated))
	require.Zero(t, activated)
}

// kaname#1034: настоящий Unregister проходит RewriteRoleRules и DB CHECK,
// фиксируя сужение трёх ролей вместе с удалением зеркала и аудитом.
func TestGrantAuthoringUnregisterGlobalMaxRulesCommits(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx := context.Background()
	scene := registrationscene.Seed(t, ctx, pool)
	repo := kanamepg.New(pool, nil)
	var uid string
	require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, scene.Account).Scan(&uid))
	const removed, kept, parent = "meta_max_removed", "meta_max_kept", "meta_max_parent"
	for _, id := range []string{removed, kept, parent} {
		require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:" + id, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}))
	}
	// Другой тип с тем же ID живёт под ДРУГИМ родителем и не является потомком removed.
	for _, id := range []string{removed, kept} {
		require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "registry_registry:" + parent, Relation: "parent", Object: publicReadObject(id), ParentChain: []string{"registry_registry:" + parent}}))
	}
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	cat := catalog.Fixed{F: facts}
	plans, err := authzmodel.New(authzmodel.DSL)
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []outboxtypes.RelationTuple{{User: "user:" + uid, Relation: "owner", Object: "account:" + scene.Account}}))
	require.NoError(t, w.Commit(ctx))
	ops := operations.NewRepo(pool, "kaname")
	create := func(name string, rules domain.Rules) domain.RoleID {
		t.Helper()
		op, e := roleapp.NewCreateRoleUseCase(repo, ops, cat).WithGrantReferencePlans(plans).Execute(declarerCtx(ctx, uid), domain.Role{Name: domain.RoleName(name), AccountID: domain.AccountID(scene.Account), Rules: rules})
		require.NoError(t, e)
		done := awaitOperation(t, ctx, ops, op.ID)
		require.Nil(t, done.Error)
		var metadata iamv1.CreateRoleMetadata
		require.NoError(t, done.Metadata.UnmarshalTo(&metadata))
		return domain.RoleID(metadata.GetRoleId())
	}
	target := create("meta_max_target", domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}})
	type fixture struct {
		name      string
		count     int
		meta      bool
		want      int
		otherName bool
		id        domain.RoleID
		before    []domain.GrantCapabilityRule
	}
	cases := []fixture{{name: "ordinary64", count: domain.MaxRules, want: domain.MaxRules}, {name: "mixed64", count: domain.MaxRules, meta: true, want: domain.MaxRules}, {name: "underbudget", count: 2, meta: true, want: 3, otherName: true}}
	for i := range cases {
		c := &cases[i]
		rules := domain.Rules{{Module: "registry", Resources: []string{"registries", "repositories"}, Verbs: []string{"get"}, ResourceNames: []string{removed, kept}}}
		for len(rules) < c.count {
			rules = append(rules, domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
		}
		if c.meta {
			rules[len(rules)-1] = domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(target)}}
		}
		require.NoError(t, rules.Validate(domain.TenantPolicy(), facts))
		_, c.before, err = domain.SplitGrantCapabilityRules(rules)
		require.NoError(t, err)
		c.id = create("meta_max_"+c.name, rules)
	}
	// Исходный баг возвращал 65 rules и откатывал именно этот настоящий вызов.
	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:" + removed}))
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='registry.registries' AND object_id=$1`, removed).Scan(&n))
	require.Zero(t, n)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='registry.repositories' AND object_id=$1`, removed).Scan(&n))
	require.Equal(t, 1, n)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd, e := repo.Reader(ctx)
			require.NoError(t, e)
			defer rd.Rollback(ctx)
			stored, e := rd.Roles().Get(ctx, c.id)
			require.NoError(t, e)
			require.Len(t, stored.Rules, c.want)
			require.LessOrEqual(t, len(stored.Rules), domain.MaxRules)
			require.NoError(t, stored.Rules.Validate(domain.TenantPolicy(), facts))
			ordinary, caps, e := domain.SplitGrantCapabilityRules(stored.Rules)
			require.NoError(t, e)
			require.Equal(t, c.before, caps)
			perms, e := domain.CompileRules(ordinary)
			require.NoError(t, e)
			require.NotContains(t, perms, domain.Permission("registry.registries."+removed+".get"))
			require.Contains(t, perms, domain.Permission("registry.registries."+kept+".get"))
			require.Contains(t, perms, domain.Permission("registry.repositories."+kept+".get"))
			if c.otherName {
				require.Contains(t, perms, domain.Permission("registry.repositories."+removed+".get"))
			} else {
				require.NotContains(t, perms, domain.Permission("registry.repositories."+removed+".get"))
			}
			require.Equal(t, perms, stored.Permissions)
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND payload->>'role_id'=$2`, accessbindingapp.AuditEventRoleResourceUnregistered, c.id).Scan(&n))
			require.Equal(t, 1, n)
			if c.meta {
				require.Len(t, c.before, 1)
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_bind_role_rule WHERE role_id=$1 AND bound_role_id=$2 AND rule_fp=$3`, c.id, target, c.before[0].RuleFP).Scan(&n))
				require.Equal(t, 1, n)
			}
		})
	}
}
