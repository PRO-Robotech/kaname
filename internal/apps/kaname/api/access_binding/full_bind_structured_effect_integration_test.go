// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const fbStructuredItem = "itm0000000000000013"

// Модуль меняет только роли. Типы, отношения и named parent остаются точно
// такими, какие TestMain уже допустил для probemod; global Install не меняется.
const fbStructuredRoles = `
roles:
  - id: probemod.fb_structured_osetr
    description: 'Контейнер и полный вложенный эффект.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
        children:
          - resources: [items]
            classes: [get, list]
  - id: probemod.fb_structured_partial
    description: 'Контейнер и только get ребёнка.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
        children:
          - resources: [items]
            classes: [get]
  - id: probemod.fb_structured_tail
    description: 'Недостающий list ребёнка.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
        children:
          - resources: [items]
            classes: [list]
`

type fbStructuredObjects struct {
	*reconcile.Reconciler
	callbacks *fb11SetupCallbacks
}

func (r *fbStructuredObjects) ReconcileObjectForwardNoStale(ctx context.Context, typ, id string) error {
	err := r.Reconciler.ReconcileObjectForwardNoStale(ctx, typ, id)
	r.callbacks.completion(typ, id) <- err
	return err
}

type fbStructuredWorld struct {
	*fullBindWorld
	callbacks                              *fb11SetupCallbacks
	observer                               *pgxpool.Pool
	osetr, partial, tail, creator, saAdmin domain.RoleID
	s1, s2, own1, own2                     string
	s1Creator, oldS2Creator                domain.AccessBindingID
}

func newFBStructuredWorld(t *testing.T, creators bool, identityFixtures ...func(*atcWorld)) *fbStructuredWorld {
	t.Helper()
	a := newATCWorld(t)
	// Дополнительная личность/членство готовится до Prepare/activation;
	// исследуемые права по-прежнему создаются ниже настоящими API.
	for _, setup := range identityFixtures {
		setup(a)
	}
	gdSeedMembership(t, a.ctx, a.pool, a.usrD, a.accA, "ACTIVE")
	gdSeedMembership(t, a.ctx, a.pool, a.usrE, a.accA, "ACTIVE")
	a.doc = append(append([]byte(nil), a.doc...), []byte(fbStructuredRoles)...)
	a.applyDelivered("FB13: настоящий generic manifest с children", a.manifest(false))
	if creators {
		fbStructuredImageRoles(t, a)
	}
	a.registerBox(atcB1)
	a.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"})
	require.NoError(t, a.reg.Register(a.ctx, &iamv1.RegisterResourceRequest{
		SubjectId: atcBoxType + ":" + atcB1, Relation: "box", Object: "probemod_item:" + fbStructuredItem,
		ParentProjectId: string(a.prjA), ParentAccountId: string(a.accA),
		ParentChain: []string{atcBoxType + ":" + atcB1, "project:" + string(a.prjA), "account:" + string(a.accA)},
	}))
	a.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	callbacks := &fb11SetupCallbacks{}
	observe := func(rec *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: rec, callbacks: callbacks}
	}
	bootstrap := accessbindingapp.NewCreateAccessBindingUseCase(a.repo, a.ops, catalog.Fixed{F: a.facts}).
		WithRelationStore(a.door, slog.Default()).WithReconciler(observe(a.rec))
	a.ab = accessbindingapp.NewHandler(bootstrap, nil, nil, nil, nil, nil, nil)
	a.ownerMayRemove("FB13/14: штатная авто-выдача владельца до activation")
	var owner domain.AccessBindingID
	require.NoError(t, a.pool.QueryRow(a.ctx, `SELECT id FROM kaname.access_bindings WHERE role_id=$1 AND subject_id=$2 AND resource_type='account' AND resource_id=$3 AND status='ACTIVE'`, domain.OwnerRoleID, a.usrA, a.accA).Scan(&owner))
	require.NoError(t, callbacks.awaitSetup(a.ctx, "iam.accessBinding", string(owner)))
	plans, err := authzmodel.Shared()
	require.NoError(t, err)
	w := &fbStructuredWorld{fullBindWorld: &fullBindWorld{atcWorld: a, plans: plans, ownerBinding: owner}, callbacks: callbacks, observer: a.pool}
	w.osetr = w.moduleRole("probemod.fb_structured_osetr")
	w.partial = w.moduleRole("probemod.fb_structured_partial")
	w.tail = w.moduleRole("probemod.fb_structured_tail")
	if creators {
		w.creator = w.moduleRole(sacCreatorRoleName)
		w.saAdmin = w.moduleRole(sacAdminRoleName)
		w.prepareCreators()
	}
	// Весь bootstrap завершён. Owner callback уже потреблён выше, поэтому
	// повторное ожидание его в install не заказывается. Ни один фон не заменён.
	w.installFullBindParticipants()
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{w.manifest(false)})
	require.NoError(t, err)
	bundle, err := w.repo.LoadAuthorityBundle(w.ctx, composed, report.KeyTerms...)
	require.NoError(t, err)
	writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	source := catalog.Fixed{F: w.facts}
	keys := kanamepg.NewRegisteredKeys(w.pool)
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, source).
		WithRelationStore(w.door, slog.Default()).WithRegisteredKeys(keys).
		WithBindingDecisions(writers).WithReconciler(observe(w.rec))
	w.ab = accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	w.roles = roleapp.NewHandler(roleapp.NewCreateRoleUseCase(w.repo, w.ops, source).
		WithRelationStore(w.door, slog.Default()).WithRegisteredKeys(keys).
		WithGrantReferencePlans(w.plans).WithRoleAuthorityWriter(writers).
		WithObjectReconciler(&fbStructuredObjects{Reconciler: w.rec, callbacks: callbacks}), nil, nil, nil, nil)
	return w
}

// Штатный ApplyImage и самолечение startup. Creator-правило не конструируется
// через запрещённый custom Role.Create и не записывается SQL-посевом.
func fbStructuredImageRoles(t *testing.T, a *atcWorld) {
	t.Helper()
	own, err := servicemanifest.Load()
	require.NoError(t, err)
	registry, err := seed.LoadPermissionRegistry(a.ctx, slog.Default())
	require.NoError(t, err)
	entries := []roleexport.CatalogEntry{}
	for _, row := range registry.All() {
		entries = append(entries, roleexport.CatalogEntry{FQN: row.FQN, RequiredRelation: row.RequiredRelation, ScopeObjectType: row.ScopeExtractor.ObjectType})
	}
	attributed, _ := roleexport.Attribute(entries)
	rights, err := moduleroles.NewRightsExport(a.facts, attributed)
	require.NoError(t, err)
	_, err = moduleroles.NewApplier(moduleroles.NewRepoTxRunner(a.repo), rights).ApplyImage(a.ctx, own, moduleroles.BootActorID)
	require.NoError(t, err)
	require.NoError(t, seed.SyncAllSystemRoleSelectors(a.ctx, a.pool))
	_, err = seed.ReseedSystemRoleVerbs(a.ctx, a.repo, a.pool, a.facts, nil)
	require.NoError(t, err)
}

func (w *fbStructuredWorld) moduleRole(name string) domain.RoleID {
	w.t.Helper()
	var id domain.RoleID
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT id FROM kaname.roles WHERE name=$1 AND is_system AND account_id IS NULL AND project_id IS NULL`, name).Scan(&id))
	require.NotEmpty(w.t, id)
	return id
}

func (w *fbStructuredWorld) authored(id domain.RoleID) domain.Role {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = rd.Rollback(ctx)
	}()
	r, err := rd.Roles().Get(w.ctx, id)
	require.NoError(w.t, err)
	require.True(w.t, r.IsSystem)
	require.Equal(w.t, domain.ClusterID(domain.ClusterSingletonID), r.ClusterID)
	require.Empty(w.t, r.AccountID)
	require.Empty(w.t, r.ProjectID)
	return r
}

func fbStructuredRequest(subject *iamv1.Subject, role domain.RoleID, kind, id string) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{subject}, RoleId: string(role), ScopeType: "iam." + kind, ScopeId: id, Target: allInScopeTarget()}
}

func (w *fbStructuredWorld) grant(req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	w.t.Helper()
	id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrA), req, "FB13/14: источник через настоящий Create"))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, id))
	w.binding(id, req)
	return id
}

func (w *fbStructuredWorld) binding(id domain.AccessBindingID, req *iamv1.CreateAccessBindingRequest) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = rd.Rollback(ctx)
	}()
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	require.Equal(w.t, req.GetRoleId(), string(b.RoleID))
	require.Equal(w.t, req.GetScopeId(), b.ResourceID)
	kind := "account"
	if req.GetScopeType() == "iam.project" {
		kind = "project"
	}
	require.Equal(w.t, kind, string(b.ResourceType))
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.True(w.t, b.Target.AllInScope)
	require.Empty(w.t, b.Target.Resources)
	subjects, err := rd.AccessBindings().ListSubjects(w.ctx, id)
	require.NoError(w.t, err)
	typ := domain.SubjectTypeUser
	if req.Subjects[0].GetType() == iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT {
		typ = domain.SubjectTypeServiceAccount
	}
	require.Equal(w.t, []domain.Subject{{Type: typ, ID: domain.SubjectID(req.Subjects[0].GetId())}}, subjects)
}

func (w *fbStructuredWorld) capability(actor string, role domain.RoleID, kind, id string, want relverdict.Verdict) {
	w.t.Helper()
	c := grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: domain.ScopeAnchor{Type: kind, ID: id}}
	if role != "" {
		c.Kind, c.RoleID = domain.GrantCapabilityBindRole, role
	}
	ref, err := grantcapability.Encode(c)
	require.NoError(w.t, err)
	tx, err := w.pool.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	var at time.Time
	require.NoError(w.t, tx.QueryRow(w.ctx, `SELECT clock_timestamp()`).Scan(&at))
	got, _, err := relverdict.Ask(w.ctx, tx, relverdict.Query{PreparedPlans: w.plans, DecisionAt: at, Subject: actor, Relation: ref.Relation, ObjectType: ref.ObjectType, ObjectID: ref.ObjectID})
	require.NoError(w.t, err)
	require.Equal(w.t, want, got)
}

func (w *fbStructuredWorld) createCapability(subject *iamv1.Subject, kind, id string) {
	w.t.Helper()
	op, err := w.roles.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
		Name: "fb_structured_create", DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)},
		Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}},
	})
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateRoleMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetRoleId())
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.role", md.GetRoleId()))
	w.grant(fbStructuredRequest(subject, domain.RoleID(md.GetRoleId()), kind, id))
}

func (w *fbStructuredWorld) noScopeAdmin(actor string) {
	w.t.Helper()
	w.native(actor, "system_admin", "cluster", domain.ClusterSingletonID, relverdict.Deny)
	w.native(actor, "admin", "account", string(w.accA), relverdict.Deny)
	w.native(actor, "admin", "project", string(w.prjA), relverdict.Deny)
}

// Полные строки наблюдает owner отдельной read-only TX; это не authority actor.
// До снимка завершены все наблюдаемые callbacks установки мира.
func (w *fbStructuredWorld) artifacts() map[string]string {
	w.t.Helper()
	tx, err := w.observer.BeginTx(w.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	out := map[string]string{}
	for _, table := range []string{
		"operations", "roles", "role_verb", "role_rule_selectors", "role_rule_ref", "role_create_binding_rule", "role_bind_role_rule",
		"access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples",
		"service_accounts", "resource_mirror", "fga_outbox", "relation_fact", "audit_outbox", "subject_change_outbox",
		"resource_reconcile_outbox", "resource_journal", "project_resource_quotas", "producer_source_receipt",
		"authority_policy_epoch", "authority_binding_epoch", "authority_policy_carrier_pending",
	} {
		var rows string
		require.NoError(w.t, tx.QueryRow(w.ctx, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname."+table+" r").Scan(&rows))
		out[table] = rows
	}
	return out
}

func (w *fbStructuredWorld) deny(ctx context.Context, req *iamv1.CreateAccessBindingRequest) {
	w.t.Helper()
	fixed, before := proto.Clone(req), w.artifacts()
	op, err := w.ab.Create(ctx, req)
	require.Nil(w.t, op)
	require.Equal(w.t, codes.PermissionDenied, status.Code(err))
	require.Equal(w.t, "permission denied", status.Convert(err).Message())
	require.True(w.t, proto.Equal(fixed, req))
	require.Equal(w.t, before, w.artifacts(), "отказ сохраняет полный бизнес/projection/audit/FGA footprint и Operation census")
}

func (w *fbStructuredWorld) allow(ctx context.Context, req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	w.t.Helper()
	fixed := proto.Clone(req)
	op, err := w.ab.Create(ctx, req)
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetAccessBindingId())
	id := domain.AccessBindingID(md.GetAccessBindingId())
	w.binding(id, req)
	require.True(w.t, proto.Equal(fixed, req))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	return id
}

// Нижний Ask может читать selectors независимо от выпущенных tuples. Поэтому
// окончание callback дополняется отдельным оракулом настоящего emitted ledger.
func (w *fbStructuredWorld) materialized(binding domain.AccessBindingID, subject, relation, typ, id string, want bool) {
	w.t.Helper()
	var present bool
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND fga_user=$2 AND relation=$3 AND object=$4)`, binding, subject, relation, typ+":"+id).Scan(&present))
	require.Equal(w.t, want, present)
}

func (w *fbStructuredWorld) prepareCreators() {
	w.t.Helper()
	// Эти API создают только исходный мир ДО active/strict. Legacy SA.Create
	// не объявляется готовым Identity participant и не вызывается после cutover.
	objects := &fbStructuredObjects{Reconciler: w.rec, callbacks: w.callbacks}
	sas := serviceaccountapp.NewHandler(serviceaccountapp.NewCreateServiceAccountUseCase(w.repo, w.ops).
		WithRelationStore(w.door, slog.Default()).WithObjectReconciler(objects), nil, nil, nil, nil, nil, nil)
	create := func(ctx context.Context, name string, creator domain.Subject) string {
		op, err := sas.Create(ctx, &iamv1.CreateServiceAccountRequest{AccountId: string(w.accA), Name: name})
		require.NoError(w.t, err)
		require.NotNil(w.t, op)
		require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error)
		var md iamv1.CreateServiceAccountMetadata
		require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
		id := md.GetServiceAccountId()
		require.NotEmpty(w.t, id)
		require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.serviceAccount", id))
		var account, typ, owner string
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT account_id,created_by_type,created_by_id FROM kaname.service_accounts WHERE id=$1`, id).Scan(&account, &typ, &owner))
		require.Equal(w.t, string(w.accA), account)
		require.Equal(w.t, string(creator.Type), typ)
		require.Equal(w.t, string(creator.ID), owner)
		return id
	}
	w.native("user:"+string(w.usrA), "editor", "account", string(w.accA), relverdict.Allow)
	human := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.usrA)}
	w.s1 = create(asUser(w.ctx, w.usrA), "fb14-s1", human)
	w.s2 = create(asUser(w.ctx, w.usrA), "fb14-s2", human)
	require.NotEqual(w.t, w.s1, w.s2)
	w.s1Creator = w.grant(fbStructuredRequest(svaSubject(w.s1), w.creator, "account", string(w.accA)))
	w.oldS2Creator = w.grant(fbStructuredRequest(svaSubject(w.s2), w.creator, "account", string(w.accA)))
	for _, id := range []string{w.s1, w.s2} {
		w.native("service_account:"+id, sacCreatorRelation, "account", string(w.accA), relverdict.Allow)
		w.noScopeAdmin("service_account:" + id)
	}
	w.own1 = create(asSA(w.ctx, w.s1), "fb14-own1", domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.s1)})
	w.own2 = create(asSA(w.ctx, w.s2), "fb14-own2", domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.s2)})
	w.native("service_account:"+w.s1, "v_update", sacSAModelType, w.own1, relverdict.Allow)
	w.native("service_account:"+w.s1, "v_update", sacSAModelType, w.own2, relverdict.Deny)
	w.native("service_account:"+w.s2, "v_update", sacSAModelType, w.own2, relverdict.Allow)
	// Старый C→S2 снимается настоящим Revoke до исследуемого Create. Активного
	// duplicate-key нет; durable creator=S2 остаётся и проверяется обоими Then.
	w.ownerMayRemove("FB14: отзыв временного fixture C→S2", string(w.oldS2Creator))
	op, err := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, slog.Default()).
		Execute(asUser(w.ctx, w.usrA), w.oldS2Creator)
	require.NoError(w.t, err)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.ID).Error)
	w.native("service_account:"+w.s2, sacCreatorRelation, "account", string(w.accA), relverdict.Deny)
	w.native("service_account:"+w.s2, "v_update", sacSAModelType, w.own2, relverdict.Deny)
}

// FB13 использует буквальную fixture без замены project parent и без удаления
// publicReadToChildren. Дополнительные роли — продолжение её единственного
// списка roles; исходная probemod.reader и все resource declarations неизменны.
const fb13SourceRoles = `
  - id: probemod.fb13_partial
    description: 'Контейнер и get ярлыков под ним.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
        children:
          - resources: [tags]
            classes: [get]
  - id: probemod.fb13_tail
    description: 'Недостающий list ярлыков под контейнером.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [boxes]
        classes: [get, list]
        children:
          - resources: [tags]
            classes: [list]
`

const (
	fb13OtherItem = "itm0000000000000014"
	fb13Tag       = "tag0000000000000013"
	fb13OtherTag  = "tag0000000000000014"
	fb13FutureTag = "tag0000000000000015"
)

type fb13ChildrenWorld struct {
	*fbStructuredWorld
	registration *internaliam.Handler
	version      time.Time
}

func newFB13ChildrenWorld(t *testing.T) *fb13ChildrenWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	canonical, err := os.ReadFile("../../../../manifest/testdata/probemod.children-fixture.yaml")
	require.NoError(t, err)
	original, err := manifest.Load(canonical)
	require.NoError(t, err)
	doc := append(append([]byte(nil), canonical...), []byte(fb13SourceRoles)...)
	delivered, err := manifest.Load(doc)
	require.NoError(t, err)
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{delivered})
	require.NoError(t, err)
	originalModel, originalReport, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{original})
	require.NoError(t, err)
	require.Equal(t, originalModel, composed, "добавлены только роли, canonical model не изменена")
	require.Equal(t, originalReport.KeyTerms, report.KeyTerms)
	admitted, err := authzmodel.Admit(composed, report.KeyTerms...)
	require.NoError(t, err)
	require.True(t, admitted.Admitted(), admitted.Census())
	plans, err := authzmodel.New(composed)
	require.NoError(t, err)
	for _, typ := range []string{atcBoxType, "probemod_item", "probemod_tag"} {
		for _, rel := range []string{"v_get", "v_list"} {
			_, err = plans.Plan(typ, rel)
			require.NoError(t, err, "полный план исходного canonical world: %s.%s", typ, rel)
		}
	}
	// Собираем отдельный мир сразу на этих plans. newSCWorld/newATCWorld здесь
	// не вызываются: ни чужих mirror seeds, ни process model swap не требуется.
	repo := kanamepg.New(pool, nil)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(pool, plans), personmarks.New(pool))
	sc := &scWorld{t: t, ctx: ctx, pool: pool, repo: repo, ops: operations.NewRepo(pool, "kaname"), door: door}
	a := &atcWorld{pcrWorld: &pcrWorld{scWorld: sc}, doc: doc}
	sc.usrA = mustSeedUser(t, ctx, pool, "fb13-owner")
	sc.accA = seedAccountByOwner(t, ctx, pool, "fb13-account", sc.usrA)
	a.usrD = mustSeedUser(t, ctx, pool, "fb13-actor")
	a.usrE = mustSeedUser(t, ctx, pool, "fb13-recipient")
	verifyAddresses(t, ctx, pool)
	gdSeedMembership(t, ctx, pool, a.usrD, sc.accA, "ACTIVE")
	gdSeedMembership(t, ctx, pool, a.usrE, sc.accA, "ACTIVE")
	a.applyDelivered("FB13: literal children fixture и два источника", delivered)
	callbacks := &fb11SetupCallbacks{}
	observe := func(rec *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: rec, callbacks: callbacks}
	}
	bootstrap := accessbindingapp.NewCreateAccessBindingUseCase(repo, sc.ops, catalog.Fixed{F: a.facts}).WithRelationStore(door, slog.Default()).WithReconciler(observe(sc.rec))
	sc.ab = accessbindingapp.NewHandler(bootstrap, nil, nil, nil, nil, nil, nil)
	owner := domain.AccessBindingID(sc.createDone(asUser(ctx, sc.usrA), fbStructuredRequest(userSubject(sc.usrA), domain.RoleID(domain.OwnerRoleID), "account", string(sc.accA)), "FB13: actual owner auto-binding"))
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.accessBinding", string(owner)))
	// Project.Create со-коммитит структурные pointers: SQL-посева project→account нет.
	projects := projectapp.NewHandler(projectapp.NewCreateProjectUseCase(repo, sc.ops).WithRelationStore(door, slog.Default()).WithObjectReconciler(&fbStructuredObjects{Reconciler: sc.rec, callbacks: callbacks}), nil, nil, nil, nil)
	op, err := projects.Create(asUser(ctx, sc.usrA), &iamv1.CreateProjectRequest{AccountId: string(sc.accA), Name: "fb13-project"})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, ctx, sc.ops, op.GetId()).Error)
	var projectMD iamv1.CreateProjectMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&projectMD))
	sc.prjA = domain.ProjectID(projectMD.GetProjectId())
	require.NotEmpty(t, sc.prjA)
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.project", string(sc.prjA)))
	sc.ownerSeeded = true
	w := &fb13ChildrenWorld{fbStructuredWorld: &fbStructuredWorld{fullBindWorld: &fullBindWorld{atcWorld: a, plans: plans, ownerBinding: owner}, callbacks: callbacks, observer: pool}}
	w.osetr = w.moduleRole("probemod.reader")
	w.partial = w.moduleRole("probemod.fb13_partial")
	w.tail = w.moduleRole("probemod.fb13_tail")
	require.NotEqual(t, w.osetr, w.partial)
	require.NotEqual(t, w.osetr, w.tail)
	require.NotEqual(t, w.partial, w.tail)
	source := catalog.Fixed{F: w.facts}
	authority := registrationwriterfixture.Authority{Module: "probemod"}
	// Gate изолирует только setup регистрации. Ни один Given grant им не выдаётся.
	w.reg = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(authority).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(w.rec, slog.Default())
	w.registration = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, authority)
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&w.version))
	for _, tree := range []struct{ box, item, tag string }{{atcB1, fbStructuredItem, fb13Tag}, {atcB2, fb13OtherItem, fb13OtherTag}} {
		w.register("project:"+string(w.prjA), "project", atcBoxType, "probemod.boxes", tree.box, []string{"project:" + string(w.prjA), "account:" + string(w.accA)})
		w.register(atcBoxType+":"+tree.box, "box", "probemod_item", "probemod.items", tree.item, []string{atcBoxType + ":" + tree.box, "project:" + string(w.prjA), "account:" + string(w.accA)})
		w.register("probemod_item:"+tree.item, "item", "probemod_tag", "probemod.tags", tree.tag, []string{"probemod_item:" + tree.item, atcBoxType + ":" + tree.box, "project:" + string(w.prjA), "account:" + string(w.accA)})
	}
	require.NoError(t, w.rec.ReconcileBinding(ctx, owner))
	// Те же реальные factories, что full-bind startup, но каждый consumer
	// получает local prepared plans либо bundle этой единственной композиции.
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(ctx, composed, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	require.NoError(t, repo.PrepareAuthorityBundle(ctx, bundle))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	source = catalog.Fixed{F: facts}
	login := "fb13_runtime_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{login}.Sanitize()
	password := ids.NewID("pwd")
	_, err = pool.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = pool.Exec(c, "DROP OWNED BY "+quoted)
		_, _ = pool.Exec(c, "DROP ROLE "+quoted)
	})
	_, err = pool.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, login)
	require.NoError(t, err)
	runtimeConfig := pool.Config()
	runtimeConfig.ConnConfig.User, runtimeConfig.ConnConfig.Password = login, password
	runtimeConfig.AfterConnect = nil
	runtime, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	var current, session string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&current, &session))
	require.Equal(t, login, current)
	require.Equal(t, login, session)
	runtimeRepo := kanamepg.New(runtime, nil)
	require.NoError(t, runtimeRepo.ValidateAuthorityRuntime(ctx))
	handed, err := runtimeRepo.LoadAuthorityBundle(ctx, composed, report.KeyTerms...)
	require.NoError(t, err)
	require.Equal(t, bundle.Identity(), handed.Identity())
	writers, err := kanamepg.NewGrantPolicyWriters(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	groups, err := kanamepg.NewGroupMembershipParticipant(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	stages, err := groups.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	rec := reconcile.New(kanamepg.NewReconcileAdapter(runtime, source), slog.Default(), source)
	require.NoError(t, rec.WithStagedBindingReconciler(stages))
	resources, err := kanamepg.NewResourceObjectParticipant(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	resourceBeginner, err := resources.RegistrationTxBeginner(runtime)
	require.NoError(t, err)
	objects, err := resources.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, rec.WithObjectReconciler(objects))
	runtimeDoor := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(runtime, plans), personmarks.New(runtime))
	runtimeOps := operations.NewRepo(runtime, "kaname")
	keys := kanamepg.NewRegisteredKeys(runtime)
	create := accessbindingapp.NewCreateAccessBindingUseCase(runtimeRepo, runtimeOps, source).WithRelationStore(runtimeDoor, slog.Default()).WithRegisteredKeys(keys).WithBindingDecisions(writers).WithReconciler(observe(rec))
	w.ab = accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	w.roles = roleapp.NewHandler(roleapp.NewCreateRoleUseCase(runtimeRepo, runtimeOps, source).WithRelationStore(runtimeDoor, slog.Default()).WithRegisteredKeys(keys).WithGrantReferencePlans(plans).WithRoleAuthorityWriter(writers).WithObjectReconciler(&fbStructuredObjects{Reconciler: rec, callbacks: callbacks}), nil, nil, nil, nil)
	w.pool, w.repo, w.ops, w.door, w.rec = runtime, runtimeRepo, runtimeOps, runtimeDoor, rec
	w.facts, w.stages = facts, stages
	w.reg = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewPoolTxBeginner(runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(authority).WithResourceTxBeginner(resourceBeginner).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(rec, slog.Default())
	w.registration = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, authority)
	require.NoError(t, repo.ActivateAuthorityBundle(ctx, bundle))
	var phase, enforcement string
	require.NoError(t, pool.QueryRow(ctx, `SELECT a.phase,p.enforcement FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &enforcement))
	require.Equal(t, "active", phase)
	require.Equal(t, "strict", enforcement)
	return w
}

func (w *fb13ChildrenWorld) register(subject, relation, typ, dotted, id string, chain []string) {
	w.t.Helper()
	w.version = w.version.Add(time.Microsecond)
	req := &iamv1.RegisterResourceRequest{SubjectId: subject, Relation: relation, Object: typ + ":" + id, ParentProjectId: string(w.prjA), ParentAccountId: string(w.accA), ParentChain: append([]string(nil), chain...), SourceVersion: timestamppb.New(w.version)}
	response, err := w.registration.RegisterResource(w.ctx, req)
	require.NoError(w.t, err, "реальный canonical RegisterResource %s", req.Object)
	require.NotNil(w.t, response)
	var project, account string
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT parent_project_id,parent_account_id FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, dotted, id).Scan(&project, &account))
	require.Equal(w.t, string(w.prjA), project)
	require.Equal(w.t, string(w.accA), account)
	rows, err := w.pool.Query(w.ctx, `SELECT parent_type||':'||parent_id FROM kaname.resource_parent_edge WHERE object_type=$1 AND object_id=$2 ORDER BY depth`, typ, id)
	require.NoError(w.t, err)
	stored, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(w.t, err)
	require.Equal(w.t, chain, stored, "полная actual цепь сохраняется, не заменяется сокращённой")
	var stands bool
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4)`, typ, id, relation, subject).Scan(&stands))
	require.True(w.t, stands)
}

func (w *fb13ChildrenWorld) request(subject domain.UserID, role domain.RoleID) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{userSubject(subject)}, RoleId: string(role), ScopeType: "iam.project", ScopeId: string(w.prjA), Target: resourcesTarget(rr("probemod.boxes", atcB1))}
}

func (w *fb13ChildrenWorld) binding(id domain.AccessBindingID, req *iamv1.CreateAccessBindingRequest) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = rd.Rollback(c)
	}()
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	require.Equal(w.t, req.GetRoleId(), string(b.RoleID))
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.Equal(w.t, "project", string(b.ResourceType))
	require.Equal(w.t, string(w.prjA), b.ResourceID)
	require.False(w.t, b.Target.AllInScope)
	require.Equal(w.t, []domain.ResourceRef{{Type: "probemod.boxes", ID: atcB1}}, b.Target.Resources)
	subjects, err := rd.AccessBindings().ListSubjects(w.ctx, id)
	require.NoError(w.t, err)
	require.Equal(w.t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(req.Subjects[0].GetId())}}, subjects)
}

func (w *fb13ChildrenWorld) grant(req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	w.t.Helper()
	id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrA), req, "FB13: actual source binding"))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, id))
	w.binding(id, req)
	return id
}

func (w *fb13ChildrenWorld) allow(req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	w.t.Helper()
	fixed := proto.Clone(req)
	id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrD), req, "FB13: полное покрытие canonical children"))
	w.binding(id, req)
	require.True(w.t, proto.Equal(fixed, req))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	return id
}

func TestFullBind_FB13_ChildrenEffectCannotDisappearFromCoverage(t *testing.T) {
	w := newFB13ChildrenWorld(t)
	for id, childVerbs := range map[domain.RoleID][]string{w.osetr: {"get", "list"}, w.partial: {"get"}, w.tail: {"list"}} {
		r := w.authored(id)
		require.Equal(t, "probemod", r.OwnerModule)
		require.Len(t, r.Rules, 1)
		require.Equal(t, "probemod", r.Rules[0].Module)
		require.Equal(t, []string{"boxes"}, r.Rules[0].Resources)
		require.ElementsMatch(t, []string{"get", "list"}, r.Rules[0].Verbs)
		require.Len(t, r.Rules[0].Children, 1)
		require.Equal(t, []string{"tags"}, r.Rules[0].Children[0].Resources)
		require.ElementsMatch(t, childVerbs, r.Rules[0].Children[0].Verbs)
	}
	require.Equal(t, domain.RoleName("probemod.reader"), w.authored(w.osetr).Name)
	var nestedSelectors, publicGrants int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id=$1 AND container_type='probemod.boxes' AND 'probemod.tags'=ANY(object_types)`, w.osetr).Scan(&nestedSelectors))
	require.Equal(t, 1, nestedSelectors)
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_box' AND relation='public_reader'`).Scan(&publicGrants))
	require.Zero(t, publicGrants, "ключ модели сохранён, но публикацией доступ не выдавался")
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	partial := w.grant(w.request(w.usrD, w.partial))
	actor, recipient := "user:"+string(w.usrD), "user:"+string(w.usrE)
	given := func(list relverdict.Verdict) {
		w.noScopeAdmin(actor)
		w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
		w.capability(actor, w.osetr, "project", string(w.prjA), relverdict.Deny)
		for _, rel := range []string{"v_get", "v_list"} {
			w.native(actor, rel, atcBoxType, atcB1, relverdict.Allow)
			w.native(actor, rel, "probemod_item", fbStructuredItem, relverdict.Deny)
			w.native(actor, rel, atcBoxType, atcB2, relverdict.Deny)
			w.native(actor, rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
		}
		w.native(actor, "v_get", "probemod_tag", fb13Tag, relverdict.Allow)
		w.native(actor, "v_list", "probemod_tag", fb13Tag, list)
	}
	unchanged := func() {
		for _, rel := range []string{"v_get", "v_list"} {
			w.native(recipient, rel, atcBoxType, atcB1, relverdict.Deny)
			w.native(recipient, rel, "probemod_tag", fb13Tag, relverdict.Deny)
			w.native(recipient, rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
		}
	}
	w.materialized(partial, actor, "v_get", "probemod_tag", fb13Tag, true)
	w.materialized(partial, actor, "v_list", "probemod_tag", fb13Tag, false)
	req := w.request(w.usrE, w.osetr)
	fixed := proto.Clone(req)
	given(relverdict.Deny)
	unchanged()
	w.deny(asUser(w.ctx, w.usrD), req)
	unchanged()
	// Меняется только Given: второй реальный source закрывает отсутствующий list.
	tail := w.grant(w.request(w.usrD, w.tail))
	w.materialized(tail, actor, "v_list", "probemod_tag", fb13Tag, true)
	given(relverdict.Allow)
	require.True(t, proto.Equal(fixed, req), "When обеих половин побайтово один")
	created := w.allow(req)
	for _, rel := range []string{"v_get", "v_list"} {
		w.materialized(created, recipient, rel, atcBoxType, atcB1, true)
		w.materialized(created, recipient, rel, "probemod_tag", fb13Tag, true)
		w.materialized(created, recipient, rel, "probemod_item", fbStructuredItem, false)
		w.materialized(created, recipient, rel, atcBoxType, atcB2, false)
		w.materialized(created, recipient, rel, "probemod_tag", fb13OtherTag, false)
		w.native(recipient, rel, atcBoxType, atcB1, relverdict.Allow)
		w.native(recipient, rel, "probemod_tag", fb13Tag, relverdict.Allow)
		w.native(recipient, rel, "probemod_item", fbStructuredItem, relverdict.Deny)
		w.native(recipient, rel, atcBoxType, atcB2, relverdict.Deny)
		w.native(recipient, rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
	}
	w.noScopeAdmin(recipient)
	// Children сохраняет будущих потомков выбранного box; после Create нет новой
	// роли либо выдачи. Новый tag регистрируется тем же настоящим runtime UC.
	w.register("probemod_item:"+fbStructuredItem, "item", "probemod_tag", "probemod.tags", fb13FutureTag, []string{"probemod_item:" + fbStructuredItem, atcBoxType + ":" + atcB1, "project:" + string(w.prjA), "account:" + string(w.accA)})
	for _, rel := range []string{"v_get", "v_list"} {
		w.materialized(created, recipient, rel, "probemod_tag", fb13FutureTag, true)
		w.native(recipient, rel, "probemod_tag", fb13FutureTag, relverdict.Allow)
		w.native(recipient, rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
	}
}

func TestFullBind_FB14_CreatorIdentityIsNotRenamedToRecipient(t *testing.T) {
	w := newFBStructuredWorld(t, true)
	creator := w.authored(w.creator)
	require.Empty(t, creator.OwnerModule, "ApplyImage сохраняет платформенное владение роли iam")
	require.Len(t, creator.Rules, 2)
	require.False(t, creator.Rules[0].CreatedBySubject)
	require.Equal(t, []string{"create"}, creator.Rules[0].Verbs)
	require.True(t, creator.Rules[1].CreatedBySubject)
	require.ElementsMatch(t, []string{"get", "list", "update", "delete"}, creator.Rules[1].Verbs)
	admin := w.authored(w.saAdmin)
	require.Empty(t, admin.OwnerModule)
	require.Len(t, admin.Rules, 1)
	require.Equal(t, []string{"serviceAccount"}, admin.Rules[0].Resources)
	require.Equal(t, []string{"*"}, admin.Rules[0].Verbs)
	require.False(t, admin.Rules[0].CreatedBySubject)
	var creatorRules, unconditionalRules int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.roles r,jsonb_array_elements(r.rules) rule WHERE r.id=$1 AND rule->>'created_by_subject'='true'`, w.creator).Scan(&creatorRules))
	require.Equal(t, 1, creatorRules)
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.roles r,jsonb_array_elements(r.rules) rule WHERE r.id=$1 AND coalesce(rule->>'created_by_subject','false')='false'`, w.saAdmin).Scan(&unconditionalRules))
	require.Equal(t, 1, unconditionalRules)
	w.createCapability(svaSubject(w.s1), "account", string(w.accA))
	actor, recipient := "service_account:"+w.s1, "service_account:"+w.s2
	given := func(foreign relverdict.Verdict) {
		w.noScopeAdmin(actor)
		w.capability(actor, "", "account", string(w.accA), relverdict.Allow)
		w.capability(actor, w.creator, "account", string(w.accA), relverdict.Deny)
		w.native(actor, sacCreatorRelation, "account", string(w.accA), relverdict.Allow)
		w.native(actor, "v_update", sacSAModelType, w.own1, relverdict.Allow)
		w.native(actor, "v_update", sacSAModelType, w.own2, foreign)
	}
	unchanged := func() {
		w.native(recipient, sacCreatorRelation, "account", string(w.accA), relverdict.Deny)
		w.native(recipient, "v_update", sacSAModelType, w.own1, relverdict.Deny)
		w.native(recipient, "v_update", sacSAModelType, w.own2, relverdict.Deny)
	}
	var liveRecipient int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND subject_id=$2 AND status='ACTIVE' AND revoked_at IS NULL`, w.creator, w.s2).Scan(&liveRecipient))
	require.Zero(t, liveRecipient)
	req := fbStructuredRequest(svaSubject(w.s2), w.creator, "account", string(w.accA))
	given(relverdict.Deny)
	unchanged()
	w.deny(asSA(w.ctx, w.s1), req)
	unchanged()
	w.grant(fbStructuredRequest(svaSubject(w.s1), w.saAdmin, "account", string(w.accA)))
	given(relverdict.Allow)
	created := w.allow(asSA(w.ctx, w.s1), req)
	require.NotEqual(t, w.oldS2Creator, created)
	w.materialized(created, recipient, "v_update", sacSAModelType, w.own2, true)
	w.materialized(created, recipient, "v_update", sacSAModelType, w.own1, false)
	w.native(recipient, sacCreatorRelation, "account", string(w.accA), relverdict.Allow)
	w.native(recipient, "v_update", sacSAModelType, w.own2, relverdict.Allow)
	w.native(recipient, "v_update", sacSAModelType, w.own1, relverdict.Deny)
	w.noScopeAdmin(recipient)
	var activeOriginal, revokedOld bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1 AND status='ACTIVE' AND revoked_at IS NULL),EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$2 AND status='REVOKED' AND revoked_at IS NOT NULL)`, w.s1Creator, w.oldS2Creator).Scan(&activeOriginal, &revokedOld))
	require.True(t, activeOriginal)
	require.True(t, revokedOld)
}
