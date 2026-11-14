// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const fbRoleBoxQ = "box0000000000000017"

// Наблюдатели вызывают настоящий reconciler и сообщают его результат только
// после возврата. Operation.done и окончание detached fanout — разные события.
type fbRoleObjects struct {
	*reconcile.Reconciler
	callbacks *fb11SetupCallbacks
}

func (r *fbRoleObjects) ReconcileObjectForwardNoStale(ctx context.Context, typ, id string) error {
	err := r.Reconciler.ReconcileObjectForwardNoStale(ctx, typ, id)
	r.callbacks.completion(typ, id) <- err
	return err
}

func (r *fbRoleObjects) ReconcileObjectForward(ctx context.Context, typ, id string) error {
	err := r.Reconciler.ReconcileObjectForward(ctx, typ, id)
	r.callbacks.completion(typ, id) <- err
	return err
}

type fbRoleFanout struct {
	roleapp.RulesMembershipFanout
	callbacks *fb11SetupCallbacks
}

func (f *fbRoleFanout) ReconcileActiveBindings(ctx context.Context, id domain.RoleID) error {
	err := f.RulesMembershipFanout.ReconcileActiveBindings(ctx, id)
	f.callbacks.completion("fb.role.rules", string(id)) <- err
	return err
}

type fbRoleMutationWorld struct {
	*fullBindWorld
	callbacks *fb11SetupCallbacks
}

func newFBRoleMutationWorld(t *testing.T) *fbRoleMutationWorld {
	t.Helper()
	callbacks := &fb11SetupCallbacks{}
	base := newFullBindWorld(t, func(actual *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: actual, callbacks: callbacks}
	})
	w := &fbRoleMutationWorld{fullBindWorld: base, callbacks: callbacks}
	// Повторно загружается тот же настоящий DB handoff; новый bundle или
	// разрешающий authorizer тест не конструирует. Общий helper не меняется.
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{w.manifest(false)})
	require.NoError(t, err)
	bundle, err := w.repo.LoadAuthorityBundle(w.ctx, composed, report.KeyTerms...)
	require.NoError(t, err)
	writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	source := catalog.Fixed{F: w.facts}
	keys := kanamepg.NewRegisteredKeys(w.pool)
	objects := &fbRoleObjects{Reconciler: w.rec, callbacks: callbacks}
	create := roleapp.NewCreateRoleUseCase(w.repo, w.ops, source).
		WithRelationStore(w.door, slog.Default()).WithRegisteredKeys(keys).
		WithGrantReferencePlans(w.plans).WithObjectReconciler(objects).WithRoleAuthorityWriter(writers)
	update := roleapp.NewUpdateRoleUseCase(w.repo, w.ops, source).
		WithRegisteredKeys(keys).WithGrantReferencePlans(w.plans).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(&fbRoleFanout{RulesMembershipFanout: accessbindingapp.NewRoleMembershipFanout(w.repo, w.rec), callbacks: callbacks}).
		WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door)).
		WithObjectReconciler(objects, slog.Default()).WithRoleAuthorityWriter(writers)
	w.roles = roleapp.NewHandler(create, update, nil, nil, nil)
	w.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
	require.NoError(t, w.reg.Register(w.ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(w.prjB), Relation: "project", Object: atcBoxType + ":" + fbRoleBoxQ,
		ParentProjectId: string(w.prjB), ParentAccountId: string(w.accA),
		ParentChain: []string{"project:" + string(w.prjB), "account:" + string(w.accA)},
	}))
	w.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	return w
}

func (w *fbRoleMutationWorld) role(name string, rules ...*iamv1.Rule) domain.RoleID {
	w.t.Helper()
	op, err := w.roles.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
		Name: name, Rules: rules, DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)},
	})
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error, "настройка роли обязана завершиться успешно")
	var md iamv1.CreateRoleMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetRoleId())
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.role", md.GetRoleId()))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
	id := domain.RoleID(md.GetRoleId())
	w.assertRules(id, rules)
	return id
}

func (w *fbRoleMutationWorld) bind(subject domain.UserID, role domain.RoleID, kind, id string) domain.AccessBindingID {
	w.t.Helper()
	bid := w.createDone(asUser(w.ctx, w.usrA), &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(subject)}, RoleId: string(role),
		ScopeType: "iam." + kind, ScopeId: id, Target: allInScopeTarget(),
	}, "FB15–20: реальная настройка выдачи")
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", bid))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(bid)))
	var gotRole, gotScope, gotID, gotSubject, gotStatus string
	var whole bool
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT role_id,resource_type,resource_id,subject_id,status,(target->>'allInScope')::boolean FROM kaname.access_bindings WHERE id=$1`, bid).
		Scan(&gotRole, &gotScope, &gotID, &gotSubject, &gotStatus, &whole))
	require.Equal(w.t, string(role), gotRole)
	require.Equal(w.t, kind, gotScope)
	require.Equal(w.t, id, gotID)
	require.Equal(w.t, string(subject), gotSubject)
	require.Equal(w.t, "ACTIVE", gotStatus)
	require.True(w.t, whole)
	return domain.AccessBindingID(bid)
}

func (w *fbRoleMutationWorld) updateMethod(id domain.RoleID) {
	w.t.Helper()
	method := w.role("fb_role_update_method", &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"update"}, ResourceNames: []string{string(id)}})
	w.bind(w.usrD, method, "account", string(w.accA))
	w.methodGiven(id, false)
}

func (w *fbRoleMutationWorld) createMethod() {
	w.t.Helper()
	method := w.role("fb_role_create_method", &iamv1.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"update"}})
	w.bind(w.usrD, method, "account", string(w.accA))
	w.methodGiven("", true)
}

func (w *fbRoleMutationWorld) methodGiven(id domain.RoleID, create bool) {
	w.t.Helper()
	actor := "user:" + string(w.usrD)
	if create {
		w.native(actor, "editor", "account", string(w.accA), relverdict.Allow)
	} else {
		w.native(actor, "v_update", "iam_role", string(id), relverdict.Allow)
		w.native(actor, "admin", "iam_role", string(id), relverdict.Deny)
	}
	w.native(actor, "admin", "account", string(w.accA), relverdict.Deny)
	for _, project := range []domain.ProjectID{w.prjA, w.prjB} {
		w.native(actor, "admin", "project", string(project), relverdict.Deny)
	}
}

func (w *fbRoleMutationWorld) coverage(id string, get, list relverdict.Verdict) {
	w.t.Helper()
	w.native("user:"+string(w.usrD), "v_get", atcBoxType, id, get)
	w.native("user:"+string(w.usrD), "v_list", atcBoxType, id, list)
}

func (w *fbRoleMutationWorld) recipient(id string, get, list relverdict.Verdict) {
	w.t.Helper()
	w.native("user:"+string(w.usrE), "v_get", atcBoxType, id, get)
	w.native("user:"+string(w.usrE), "v_list", atcBoxType, id, list)
}

func (w *fbRoleMutationWorld) stored(id domain.RoleID) (domain.Role, string) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = rd.Rollback(ctx)
	}()
	r, version, err := rd.Roles().GetWithVersion(w.ctx, id)
	require.NoError(w.t, err)
	require.NotEmpty(w.t, version)
	return r, version
}

// Для плоских правил этой фикстуры проверяются полные authored rules,
// permissions, selector fingerprints, глаголы и declared references. Это
// durable-оракул; материализация recipient спрашивается отдельно через PG Ask.
func (w *fbRoleMutationWorld) assertRules(id domain.RoleID, rules []*iamv1.Rule) {
	w.t.Helper()
	r, _ := w.stored(id)
	require.Equal(w.t, w.accA, r.AccountID)
	require.Empty(w.t, r.ProjectID)
	require.False(w.t, r.IsSystem)
	want := make(domain.Rules, 0, len(rules))
	for _, rule := range rules {
		want = append(want, domain.Rule{Module: rule.GetModule(), Resources: rule.GetResources(), Verbs: rule.GetVerbs(), ResourceNames: rule.GetResourceNames()})
	}
	require.Equal(w.t, want, r.Rules)
	projection, err := w.facts.ProjectGrantRules(want, domain.PolicyOfRole(false, ""))
	require.NoError(w.t, err)
	require.Equal(w.t, projection.Permissions, r.Permissions)
	var creates, binds int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT (SELECT count(*) FROM kaname.role_create_binding_rule WHERE role_id=$1),(SELECT count(*) FROM kaname.role_bind_role_rule WHERE role_id=$1)`, id).Scan(&creates, &binds))
	wantCreates, wantBinds := 0, 0
	for _, capability := range projection.Capabilities {
		var exists bool
		if capability.Kind == domain.GrantCapabilityCreateBinding {
			wantCreates++
			require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.role_create_binding_rule WHERE role_id=$1 AND rule_fp=$2)`, id, capability.RuleFP).Scan(&exists))
		} else {
			wantBinds++
			require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.role_bind_role_rule WHERE role_id=$1 AND rule_fp=$2 AND bound_role_id=$3)`, id, capability.RuleFP, capability.BoundRoleID).Scan(&exists))
		}
		require.True(w.t, exists)
	}
	require.Equal(w.t, wantCreates, creates)
	require.Equal(w.t, wantBinds, binds)
	rows, err := w.pool.Query(w.ctx, `SELECT object_type,verb FROM kaname.role_verb WHERE role_id=$1 ORDER BY object_type,verb`, id)
	require.NoError(w.t, err)
	verbs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.RoleVerb, error) {
		var v domain.RoleVerb
		err := row.Scan(&v.ObjectType, &v.Verb)
		return v, err
	})
	require.NoError(w.t, err)
	require.ElementsMatch(w.t, projection.Verbs, verbs)
	rows, err = w.pool.Query(w.ctx, `SELECT module,resource,coalesce(verb,'') FROM kaname.role_rule_ref WHERE role_id=$1`, id)
	require.NoError(w.t, err)
	refs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.RoleRuleRef, error) {
		var ref domain.RoleRuleRef
		err := row.Scan(&ref.Module, &ref.Resource, &ref.Verb)
		return ref, err
	})
	require.NoError(w.t, err)
	require.ElementsMatch(w.t, domain.RuleRefsOf(want), refs)
	var selectorCount int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id=$1`, id).Scan(&selectorCount))
	require.Len(w.t, projection.Selectors, selectorCount)
	for _, s := range projection.Selectors {
		var types, names []string
		var labels, grants []byte
		var arm string
		var creator bool
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT object_types,resource_names,match_labels,verbs_by_type,arm,created_by_subject FROM kaname.role_rule_selectors WHERE role_id=$1 AND rule_fp=$2`, id, s.RuleFP).
			Scan(&types, &names, &labels, &grants, &arm, &creator))
		require.ElementsMatch(w.t, s.ObjectTypes, types)
		require.ElementsMatch(w.t, s.ResourceNames, names)
		wantLabels, err := json.Marshal(s.MatchLabels)
		require.NoError(w.t, err)
		if string(wantLabels) == "null" {
			wantLabels = []byte("{}")
		}
		wantGrants, err := json.Marshal(s.Grants)
		require.NoError(w.t, err)
		require.JSONEq(w.t, string(wantLabels), string(labels))
		require.JSONEq(w.t, string(wantGrants), string(grants))
		wantArm := "anchor"
		if len(s.ResourceNames) != 0 {
			wantArm = "names"
		}
		require.Equal(w.t, wantArm, arm)
		require.False(w.t, creator)
	}
}

// Сравниваются полные строки, включая xmin ролей, а не только count. Жизненный
// цикл принятой Operation намеренно отделён от бизнес/projection/audit/FGA.
func (w *fbRoleMutationWorld) business() map[string]string {
	w.t.Helper()
	tx, err := w.pool.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	out := map[string]string{}
	for _, table := range []string{
		"roles", "role_verb", "role_rule_selectors", "role_rule_ref", "role_grant_orphan", "role_selector_prune",
		"role_create_binding_rule", "role_bind_role_rule", "access_bindings", "access_binding_subjects",
		"access_binding_target_members", "access_binding_emitted_tuples", "fga_outbox", "relation_fact", "audit_outbox",
		"subject_change_outbox", "resource_reconcile_outbox", "resource_journal", "project_resource_quotas",
		"producer_source_receipt", "authority_policy_epoch", "authority_binding_epoch", "authority_policy_carrier_pending",
	} {
		var state string
		require.NoError(w.t, tx.QueryRow(w.ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname."+table+" r").Scan(&state))
		out[table] = state
	}
	var versions string
	require.NoError(w.t, tx.QueryRow(w.ctx, `SELECT coalesce(jsonb_object_agg(id,xmin::text),'{}'::jsonb)::text FROM kaname.roles`).Scan(&versions))
	out["role_versions"] = versions
	return out
}

func fbRoleRulesUpdate(id domain.RoleID, verbs ...string) *iamv1.UpdateRoleRequest {
	return &iamv1.UpdateRoleRequest{RoleId: string(id), Rules: []*iamv1.Rule{fullBindBoxRule(verbs...)}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}}}
}

func (w *fbRoleMutationWorld) update(req *iamv1.UpdateRoleRequest, allow bool) {
	w.t.Helper()
	fixed := proto.Clone(req)
	before := w.business()
	op, err := w.roles.Update(asUser(w.ctx, w.usrD), req)
	require.NoError(w.t, err, "валидный запрос проходит sync admission; semantic gate находится в worker")
	require.NotNil(w.t, op)
	var md iamv1.UpdateRoleMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.Equal(w.t, req.GetRoleId(), md.GetRoleId())
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.True(w.t, proto.Equal(fixed, req), "исследуемый payload неизменён")
	if !allow {
		require.NotNil(w.t, done.Error)
		require.Equal(w.t, int32(codes.PermissionDenied), done.Error.Code)
		require.Equal(w.t, "Grant authority denied", done.Error.Message)
		require.Equal(w.t, before, w.business(), "semantic отказ откатывает весь бизнес/projection/audit/FGA footprint")
		return
	}
	require.Nil(w.t, done.Error, "durable роль должна быть зафиксирована до materialization oracle")
	if req.GetRules() != nil {
		w.assertRules(domain.RoleID(req.GetRoleId()), req.GetRules())
		require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "fb.role.rules", req.GetRoleId()))
	}
}

func TestFullBind_FB15_CreateUnusedRoleRequiresDefinitionCoverage(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	w.createMethod()
	get := w.role("fb15_get", fullBindBoxRule("get"))
	list := w.role("fb15_list", fullBindBoxRule("list"))
	w.bind(w.usrD, get, "account", string(w.accA))
	req := &iamv1.CreateRoleRequest{Name: "fb15_proposed", Rules: []*iamv1.Rule{fullBindBoxRule("get", "list")}, DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)}}
	fixed := proto.Clone(req)
	w.methodGiven("", true)
	w.coverage(atcB1, relverdict.Allow, relverdict.Deny)
	before := w.business()
	op, err := w.roles.Create(asUser(w.ctx, w.usrD), req)
	require.NoError(t, err)
	require.NotNil(t, op)
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error)
	require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
	require.Equal(t, "Grant authority denied", done.Error.Message)
	require.Equal(t, before, w.business())
	var denied iamv1.CreateRoleMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&denied))
	require.NotEmpty(t, denied.GetRoleId())
	var exists bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.roles WHERE id=$1)`, denied.GetRoleId()).Scan(&exists))
	require.False(t, exists)
	w.recipient(atcB1, relverdict.Deny, relverdict.Deny)
	w.bind(w.usrD, list, "account", string(w.accA))
	w.methodGiven("", true)
	w.coverage(atcB1, relverdict.Allow, relverdict.Allow)
	w.coverage(fbRoleBoxQ, relverdict.Allow, relverdict.Allow)
	op, err = w.roles.Create(asUser(w.ctx, w.usrD), req)
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
	var created iamv1.CreateRoleMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&created))
	require.NotEmpty(t, created.GetRoleId())
	w.assertRules(domain.RoleID(created.GetRoleId()), req.Rules)
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.role", created.GetRoleId()))
	require.True(t, proto.Equal(fixed, req))
	var bindings int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1`, created.GetRoleId()).Scan(&bindings))
	require.Zero(t, bindings)
	w.recipient(atcB1, relverdict.Deny, relverdict.Deny)
}

func TestFullBind_FB16_UpdateUnusedRoleRequiresDefinitionCoverage(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	r := w.role("fb16_proposed", fullBindBoxRule("get"))
	w.updateMethod(r)
	coverage := w.role("fb16_coverage", fullBindBoxRule("get", "list"))
	w.bind(w.usrD, coverage, "project", string(w.prjA))
	var bindings int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1`, r).Scan(&bindings))
	require.Zero(t, bindings)
	req := fbRoleRulesUpdate(r, "get", "list")
	w.methodGiven(r, false)
	w.coverage(atcB1, relverdict.Allow, relverdict.Allow)
	w.coverage(fbRoleBoxQ, relverdict.Deny, relverdict.Deny)
	w.update(req, false)
	w.assertRules(r, []*iamv1.Rule{fullBindBoxRule("get")})
	w.recipient(atcB1, relverdict.Deny, relverdict.Deny)
	w.bind(w.usrD, coverage, "account", string(w.accA))
	w.methodGiven(r, false)
	w.coverage(fbRoleBoxQ, relverdict.Allow, relverdict.Allow)
	w.update(req, true)
	w.recipient(atcB1, relverdict.Deny, relverdict.Deny)
}

func TestFullBind_FB17_UsedAccountRoleNeedsEveryBindingScopeOnly(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	r := w.role("fb17_proposed", fullBindBoxRule("get"))
	w.bind(w.usrE, r, "project", string(w.prjA))
	w.bind(w.usrE, r, "project", string(w.prjB))
	w.updateMethod(r)
	coverage := w.role("fb17_coverage", fullBindBoxRule("get", "list"))
	w.bind(w.usrD, coverage, "project", string(w.prjA))
	req := fbRoleRulesUpdate(r, "get", "list")
	w.methodGiven(r, false)
	w.coverage(atcB1, relverdict.Allow, relverdict.Allow)
	w.coverage(fbRoleBoxQ, relverdict.Deny, relverdict.Deny)
	w.recipient(atcB1, relverdict.Allow, relverdict.Deny)
	w.recipient(fbRoleBoxQ, relverdict.Allow, relverdict.Deny)
	w.update(req, false)
	w.recipient(atcB1, relverdict.Allow, relverdict.Deny)
	w.recipient(fbRoleBoxQ, relverdict.Allow, relverdict.Deny)
	w.bind(w.usrD, coverage, "project", string(w.prjB))
	w.methodGiven(r, false)
	w.coverage(fbRoleBoxQ, relverdict.Allow, relverdict.Allow)
	// Account-выдача actor относится только к iam.role.update. Весь probemod
	// source живёт ровно в P/Q; positive не получает definition-wide источник.
	var accountCoverage int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings b JOIN kaname.roles r ON r.id=b.role_id WHERE b.subject_id=$1 AND b.resource_type='account' AND EXISTS(SELECT 1 FROM jsonb_array_elements(r.rules) rule WHERE rule->>'module'='probemod')`, string(w.usrD)).Scan(&accountCoverage))
	require.Zero(t, accountCoverage)
	w.update(req, true)
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
	w.recipient(fbRoleBoxQ, relverdict.Allow, relverdict.Allow)
}

func TestFullBind_FB18_BindDoesNotAuthorizeUncoveredRoleRules(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	r := w.role("fb18_proposed", fullBindBoxRule("get"))
	w.bind(w.usrE, r, "project", string(w.prjA))
	w.updateMethod(r)
	bind := w.role("fb18_bind", &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(r)}})
	w.bind(w.usrD, bind, "project", string(w.prjA))
	get := w.role("fb18_get", fullBindBoxRule("get"))
	list := w.role("fb18_list", fullBindBoxRule("list"))
	w.bind(w.usrD, get, "project", string(w.prjA))
	ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityBindRole, RoleID: r, Anchor: domain.ScopeAnchor{Type: "project", ID: string(w.prjA)}})
	require.NoError(t, err)
	tx, err := w.pool.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var at time.Time
	require.NoError(t, tx.QueryRow(w.ctx, `SELECT clock_timestamp()`).Scan(&at))
	verdict, _, err := relverdict.Ask(w.ctx, tx, relverdict.Query{PreparedPlans: w.plans, DecisionAt: at, Subject: "user:" + string(w.usrD), Relation: ref.Relation, ObjectType: ref.ObjectType, ObjectID: ref.ObjectID})
	require.NoError(t, err)
	require.Equal(t, relverdict.Allow, verdict)
	require.NoError(t, tx.Rollback(w.ctx))
	w.methodGiven(r, false)
	w.coverage(atcB1, relverdict.Allow, relverdict.Deny)
	req := fbRoleRulesUpdate(r, "get", "list")
	w.update(req, false)
	w.recipient(atcB1, relverdict.Allow, relverdict.Deny)
	w.bind(w.usrD, list, "project", string(w.prjA))
	w.methodGiven(r, false)
	w.coverage(atcB1, relverdict.Allow, relverdict.Allow)
	w.update(req, true)
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
}

func TestFullBind_FB19_MetadataDoesNotRequireRulesCoverage(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	r := w.role("fb19_proposed", fullBindBoxRule("get", "list"))
	w.bind(w.usrE, r, "project", string(w.prjA))
	w.updateMethod(r)
	w.coverage(atcB1, relverdict.Deny, relverdict.Deny)
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
	accessBefore := w.business()
	metadata := &iamv1.UpdateRoleRequest{RoleId: string(r), Description: "metadata without escalation", UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}}}
	w.update(metadata, true)
	stored, _ := w.stored(r)
	require.Equal(t, domain.Description(metadata.Description), stored.Description)
	w.assertRules(r, []*iamv1.Rule{fullBindBoxRule("get", "list")})
	accessAfter := w.business()
	for _, table := range []string{"role_verb", "role_rule_selectors", "role_rule_ref", "role_create_binding_rule", "role_bind_role_rule", "access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples", "relation_fact", "fga_outbox"} {
		require.Equal(t, accessBefore[table], accessAfter[table], "metadata-only не меняет доступ: %s", table)
	}
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
	// Это отдельный When FB19b: даже суженный proposed результат требует
	// coverage всех оставляемых правил; metadata-only не выдаёт такого права.
	w.methodGiven(r, false)
	w.update(fbRoleRulesUpdate(r, "get"), false)
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
}

func TestFullBind_FB20_RulesUpdateChecksActualResourceVersion(t *testing.T) {
	w := newFBRoleMutationWorld(t)
	r := w.role("fb20_proposed", fullBindBoxRule("get"))
	w.bind(w.usrE, r, "project", string(w.prjA))
	w.updateMethod(r)
	coverage := w.role("fb20_coverage", fullBindBoxRule("get", "list"))
	w.bind(w.usrD, coverage, "project", string(w.prjA))
	_, stale := w.stored(r)
	w.update(&iamv1.UpdateRoleRequest{RoleId: string(r), Description: "real intervening update", UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}}}, true)
	_, current := w.stored(r)
	require.NotEqual(t, stale, current, "устаревший token получен до настоящего API commit")
	w.methodGiven(r, false)
	w.coverage(atcB1, relverdict.Allow, relverdict.Allow)
	req := fbRoleRulesUpdate(r, "get", "list")
	req.ResourceVersion = stale
	fixed := proto.Clone(req).(*iamv1.UpdateRoleRequest)
	before := w.business()
	var operationsBefore, operationsAfter int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsBefore))
	op, err := w.roles.Update(asUser(w.ctx, w.usrD), req)
	require.Nil(t, op, "stale OCC отказывает до принятия Operation")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "Role was modified concurrently, retry", status.Convert(err).Message())
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsAfter))
	require.Equal(t, operationsBefore, operationsAfter)
	require.Equal(t, before, w.business())
	w.recipient(atcB1, relverdict.Allow, relverdict.Deny)
	require.True(t, proto.Equal(fixed, req))
	req = proto.Clone(fixed).(*iamv1.UpdateRoleRequest)
	req.ResourceVersion = current
	w.methodGiven(r, false)
	w.update(req, true)
	_, after := w.stored(r)
	require.NotEqual(t, current, after)
	w.recipient(atcB1, relverdict.Allow, relverdict.Allow)
}
