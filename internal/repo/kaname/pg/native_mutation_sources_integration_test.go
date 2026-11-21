// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// Матрица проверяет native tier и вычисляемые глаголы через actual Role.Create
// либо canonical ApplyImage для system-only creator, затем staged materializer. Снятие canonical source сохраняет stale fact/ledger намеренно;
// часы и expires_at не меняются. Реальный TTL остаётся отдельным public тестом.
func TestNativeMutationMaterializedTierAndVerbSources(t *testing.T) {
	for _, tc := range []struct {
		name, resource, tier string
		verbs, questions     []string
		group                bool
	}{
		{"account_editor", "account", "editor", []string{"get", "list", "update"}, []string{"editor", "viewer", "v_get", "v_list", "v_update"}, false},
		{"account_scope_self", "account", "editor", []string{"get", "list", "update"}, []string{"editor", "viewer", "v_update"}, false},
		{"account_viewer", "account", "viewer", []string{"get", "list"}, []string{"viewer", "v_get", "v_list"}, false},
		{"project_editor", "project", "editor", []string{"get", "list", "update"}, []string{"editor", "viewer", "v_update"}, false},
		{"role_editor", "role", "editor", []string{"list", "update"}, []string{"editor", "viewer", "v_list", "v_update", "v_delete"}, false},
		{"role_viewer", "role", "viewer", []string{"list"}, []string{"viewer", "v_list"}, false},
		{"public_reader_anonymous", "registries", "public_reader", []string{"get", "list"}, []string{"public_reader", "v_get"}, false},
		{"public_reader_authenticated", "registries", "public_reader", []string{"get", "list"}, []string{"public_reader", "v_get"}, false},
		{"created_by_subject", "serviceAccount", "", []string{"get", "update"}, []string{"v_get", "v_update", "v_delete"}, false},
		{"container_creator", "serviceAccount", "service_account_creator", []string{"create"}, []string{"service_account_creator"}, false},
		{"group_editor", "account", "editor", []string{"get", "list", "update"}, []string{"editor", "viewer", "v_update"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var w delegationUCWorld
			if tc.name == "container_creator" {
				w = nativeMutationCreatorWorld(t)
			} else {
				w = delegationUCFixture(t)
			}
			objectType, objectID := "account", w.r.a
			if tc.resource == "project" {
				objectType = "project"
				objectID = nativeMutationSourceProject(t, w.r, "mutation-source-project")
			}
			subject := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.member)}
			actorRef := "user:" + w.member
			if tc.resource == "serviceAccount" {
				subject = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.input.DelegateID)}
				actorRef = "service_account:" + w.input.DelegateID
			}
			module := "iam"
			if tc.resource == "registries" {
				module, objectType, objectID = "registry", "registry_registry", "mutation-source-registry"
				project := nativeMutationSourceProject(t, w.r, "mutation-source-registry")
				uc := newRegisterUCWired(w.r.admin).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
				require.NoError(t, uc.Register(w.r.ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + project, Relation: "project", Object: objectType + ":" + objectID, ParentProjectId: project, ParentAccountId: w.r.a, ParentChain: []string{"project:" + project, "account:" + w.r.a}}))
				class := domain.ClassAnonymous
				if tc.name == "public_reader_authenticated" {
					class = domain.ClassAuthenticated
				}
				subject = domain.Subject{Type: domain.SubjectTypeSystemClass, ID: class}
			}
			if tc.name == "created_by_subject" {
				objectType, objectID = "iam_service_account", ids.NewID("sva")
				_, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name,created_by_type,created_by_id) VALUES($1,$2,'mutation-source-child','service_account',$3)`, objectID, w.r.a, w.input.DelegateID)
				require.NoError(t, err)
			}
			if tc.group {
				group := ids.NewID("grp")
				_, err := w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES($1,$2,'mutation-source-group')`, group, w.r.a)
				require.NoError(t, err)
				_, err = w.r.admin.Exec(w.r.ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id) VALUES($1,'user',$2)`, group, w.member)
				require.NoError(t, err)
				subject = domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(group)}
			}
			writers, diagnostic := newRoleMutationDiagnosticFactory(t, w)
			require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
			create := roleapp.NewCreateRoleUseCase(w.r.repo, w.ops, w.source).WithRoleAuthorityWriter(writers)
			role := domain.Role{AccountID: domain.AccountID(w.r.a), Name: domain.RoleName("ms_" + tc.name), Rules: domain.Rules{{Module: module, Resources: []string{tc.resource}, Verbs: tc.verbs}}}
			if tc.name == "created_by_subject" {
				role.Rules[0].CreatedBySubject = true
			}
			if tc.resource == "registries" {
				role.Rules[0].ResourceNames = []string{objectID}
				role.Rules[0].Children = []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}
			}
			if tc.name == "container_creator" {
				// Эта системная роль создана штатным ApplyImage до Prepare.
				// Custom Role.Create не вправе принимать serviceAccount:create.
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.roles WHERE name='iam.service_account.creator' AND is_system AND owner_module IS NULL AND live`).Scan(&role.ID))
			} else {
				op, err := create.Execute(declarerCtx(w.r.ctx, w.owner), role)
				require.NoError(t, err)
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				require.Nil(t, done.Error, "actual role: %s", diagnostic.snapshot())
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.roles WHERE account_id=$1 AND name=$2`, w.r.a, role.Name).Scan(&role.ID))
			}
			if tc.resource == "role" {
				objectType, objectID = "iam_role", string(role.ID)
			}
			target := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: module + "." + tc.resource, ID: objectID}}}
			if tc.name == "container_creator" || tc.name == "account_scope_self" {
				target = domain.AccessTarget{AllInScope: true}
			}
			binding := domain.AccessBindingID(ids.NewID("acb"))
			seed, err := w.r.repo.ParticipantAuthorityWriter(w.r.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: w.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
				defer cancel()
				_ = seed.Rollback(ctx)
			})
			_, err = bindingset.Insert(w.r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: binding, SubjectType: subject.Type, SubjectID: subject.ID, RoleID: role.ID, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: target})
			require.NoError(t, err)
			require.NoError(t, seed.Commit(w.r.ctx))
			staged := withdrawalParticipant(t, w.r, nil)
			require.NoError(t, staged.ReconcileStagedBinding(declarerCtx(w.r.ctx, w.owner), binding, false, nil))
			var tiers, admins int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FILTER(WHERE relation=$3),count(*) FILTER(WHERE relation='admin') FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2`, binding, objectType+":"+objectID, tc.tier).Scan(&tiers, &admins))
			if tc.tier != "" {
				require.Positive(t, tiers, "lawful producer действительно выпустил проверяемый tier")
				var nativeTier int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples e JOIN kaname.relation_fact f ON f.object_type=$4 AND f.object_id=$5 AND f.subject=e.fga_user AND f.relation=e.relation WHERE e.binding_id=$1 AND e.object=$2 AND e.relation=$3 AND e.fga_user=$6 AND f.condition_name='' AND f.condition_params='{}'::jsonb`, binding, objectType+":"+objectID, tc.tier, objectType, objectID, domain.FGASubjectRef(string(subject.Type), string(subject.ID))).Scan(&nativeTier))
				require.Positive(t, nativeTier, "tier существует одновременно в ledger и native fact")
			}
			if tc.name == "account_scope_self" {
				var scopeSelf int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND rule_fp='scope_self' AND object_id=$2`, binding, objectID).Scan(&scopeSelf))
				require.Positive(t, scopeSelf, "scope-self создан настоящим producer")
			}
			for _, relation := range tc.questions {
				if !strings.HasPrefix(relation, "v_") {
					continue
				}
				// Fold намеренно не хранит binding v_* как native facts:
				// ledger доказывает producer, Check ниже проверяет выводимый глагол.
				var emitted, direct int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2 AND relation=$3 AND fga_user=$4`, binding, objectType+":"+objectID, relation, domain.FGASubjectRef(string(subject.Type), string(subject.ID))).Scan(&emitted))
				require.Positive(t, emitted, "lawful binding producer выпустил %s в ledger", relation)
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4`, objectType, objectID, relation, domain.FGASubjectRef(string(subject.Type), string(subject.ID))).Scan(&direct))
				require.Zero(t, direct, "binding %s вычисляется, а не подставляется прямым native fact", relation)
			}
			require.Zero(t, admins, "admin не маскирует обычный tier")
			for _, relation := range tc.questions {
				public, e := w.door.Check(w.r.ctx, actorRef, relation, objectType+":"+objectID)
				require.NoError(t, e, relation)
				require.True(t, public, "живой публичный путь: %s", relation)
				got, e := checkLiveAdministrative(t, w, actorRef, relation, objectType+":"+objectID)
				require.NoError(t, e, relation)
				require.True(t, got, "живой источник %s", relation)
			}
			changed := administrativeFixtureExec(t, w, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, binding)
			require.EqualValues(t, 1, changed)
			for _, relation := range tc.questions {
				public, e := w.door.Check(w.r.ctx, actorRef, relation, objectType+":"+objectID)
				require.NoError(t, e, relation)
				if strings.HasPrefix(relation, "v_") {
					// В этих моделях v_* не выводится из editor/viewer. После
					// отзыва ordinary grant arm отвергает источник уже на read.
					require.False(t, public, "вычисляемый глагол снят вместе с выдачей: %s", relation)
				} else {
					require.True(t, public, "stale public fact сохранён: %s", relation)
				}
				got, e := checkLiveAdministrative(t, w, actorRef, relation, objectType+":"+objectID)
				require.NoError(t, e, "известный снятый источник даёт DENY: %s", relation)
				require.False(t, got, relation)
			}
		})
	}
}

// Отдельная bootstrap fixture нужна только system-only ветке; остальные
// используют прежнюю delegationUCFixture без расширения набора ролей.
func nativeMutationCreatorWorld(t *testing.T) delegationUCWorld {
	t.Helper()
	// Как в bootstrap: catalog/roles устанавливаются при uninitialized,
	// затем существующий Prepare ниже фиксирует фактическую полную модель.
	r, _ := writerProtocolRigBeforePreparation(t)
	raw, err := publicreadfixture.Read("registry.delegation-fixture.yaml")
	require.NoError(t, err)
	raw, err = publicreadfixture.WithWrites(raw)
	require.NoError(t, err)
	m, err := manifest.Load(raw)
	require.NoError(t, err)
	_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(r.admin)).ApplyAll(r.ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	live, err := kanamepg.NewCatalogRepo(r.admin).ReadLiveCatalog(r.ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(catalog.Halves{Live: live})
	require.NoError(t, err)
	reg, err := seed.LoadPermissionRegistry(r.ctx, slog.Default())
	require.NoError(t, err)
	entries := make([]roleexport.CatalogEntry, 0)
	for _, row := range reg.All() {
		entries = append(entries, roleexport.CatalogEntry{FQN: row.FQN, RequiredRelation: row.RequiredRelation, ScopeObjectType: row.ScopeExtractor.ObjectType})
	}
	attributed, _ := roleexport.Attribute(entries)
	rights, err := moduleroles.NewRightsExport(facts, attributed)
	require.NoError(t, err)
	_, err = moduleroles.NewApplier(moduleroles.NewRepoTxRunner(lifecycleOwner(r)), rights).Apply(r.ctx, m, moduleroles.BootActorID)
	require.NoError(t, err)
	// Как в сервисном bootstrap: встроенная роль создаётся штатным
	// ApplyImage, затем selectors/verbs приводятся до фиксации bundle.
	own, err := servicemanifest.Load()
	require.NoError(t, err)
	_, err = moduleroles.NewApplier(moduleroles.NewRepoTxRunner(lifecycleOwner(r)), rights).ApplyImage(r.ctx, own, moduleroles.BootActorID)
	require.NoError(t, err)
	require.NoError(t, seed.SyncAllSystemRoleSelectors(r.ctx, r.admin))
	_, err = seed.ReseedSystemRoleVerbs(r.ctx, lifecycleOwner(r), r.admin, facts, nil)
	require.NoError(t, err)
	model, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	r.bundle, err = granteffect.NewBundle(r.ctx, model, halves, granteffect.ProjectorVersion, rep.KeyTerms...)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	handoff, err := r.repo.LoadAuthorityBundle(r.ctx, model, rep.KeyTerms...)
	require.NoError(t, err)
	participant, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, handoff)
	require.NoError(t, err)
	var owner, role string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&owner))
	member := seedMemberUser(t, r.ctx, r.admin, r.a, "delegation-native-member")
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{owner, member})
	require.NoError(t, err)
	sa := seedSAID(t, r.ctx, r.admin, r.a, "delegation-native-recipient")
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE name='registry.puller' AND owner_module='registry'`).Scan(&role))
	return delegationUCWorld{r: r, source: catalog.Fixed{F: facts}, door: delegationNativeDoor{r: r}, participant: participant, ops: operations.NewRepo(r.runtime, "kaname"), owner: owner, member: member, input: gdapp.CreateInput{AccountID: r.a, DelegateType: "SUBJECT_TYPE_SERVICE_ACCOUNT", DelegateID: sa, RoleIDs: []string{role}, TargetTypes: []string{"registry.registries"}, SubjectTypes: []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}}}
}

// Как в Project.Create и metadataFixture: строка проекта и его канонические
// структурные указатели фиксируются вместе. resource_scope_edge читает связь
// project→account из журнала, а не из projects.account_id. Прав актору здесь нет.
func nativeMutationSourceProject(t *testing.T, r protocolRig, name domain.ProjectName) string {
	t.Helper()
	committed := false
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	if seed != nil {
		defer func() {
			if committed {
				return
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
			defer cancel()
			require.NoError(t, seed.Rollback(cleanup))
		}()
	}
	require.NoError(t, err)
	require.NotNil(t, seed)
	project, err := seed.ProjectsW().Insert(r.ctx, domain.Project{
		ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: domain.AccountID(r.a),
		Name: name, Labels: domain.Labels{},
	})
	require.NoError(t, err)
	var structural []service.RelationTuple
	for _, fact := range project.StructuralFacts() {
		structural = append(structural, service.RelationTuple{User: fact.User, Relation: fact.Relation, Object: fact.Object})
	}
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, structural))
	require.NoError(t, seed.Commit(r.ctx))
	committed = true
	var parents []string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT COALESCE(array_agg(parent_type||':'||parent_id ORDER BY parent_type,parent_id),'{}'::text[]) FROM kaname.resource_scope_edge WHERE object_type='project' AND object_id=$1`, string(project.ID)).Scan(&parents))
	require.ElementsMatch(t, []string{"account:" + r.a, "cluster:" + domain.ClusterSingletonID}, parents, "родительские связи проекта созданы каноническим producer")
	return string(project.ID)
}
