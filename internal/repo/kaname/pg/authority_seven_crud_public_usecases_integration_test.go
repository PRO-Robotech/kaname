// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	saapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sevenCRUDPublicWorld struct {
	r                                          protocolRig
	ctx                                        context.Context
	full                                       *kanamepg.Repository
	observer                                   *sequenceSQLErrorObserver
	factory                                    *kanamepg.CRUDWriters
	ops                                        operations.Repo
	door                                       clients.RelationStore
	account                                    domain.Account
	project                                    domain.Project
	sa                                         domain.ServiceAccount
	role                                       domain.Role
	actor, owner, member, outsider, unverified string
	binding, foreignBinding, authorityBinding  domain.AccessBindingID
	mirror, oauth                              string
}

// Посев повторяет форму владельца Account.Create, включая набор субъектов и
// его ведомость. Только подготовка до owner Prepare/Stage/Activate использует
// owner connection; после активации она остаётся лишь наблюдателем.
func sevenCRUDSeedAccount(t *testing.T, r protocolRig, name string) (domain.Account, domain.AccessBindingID) {
	t.Helper()
	a := domain.Account{ID: domain.AccountID(ids.NewID(domain.PrefixAccount)), OwnerUserID: domain.UserID(ids.NewID(domain.PrefixUser)), Name: domain.AccountName(name), Labels: domain.Labels{}}
	tx := mustBeginTx(t, r.ctx, r.admin)
	_, err := tx.Exec(r.ctx, `INSERT INTO kaname.accounts(id,name,owner_user_id) VALUES($1,$2,$3)`, string(a.ID), string(a.Name), string(a.OwnerUserID))
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.users(id,account_id,external_id,email,invite_status,email_verified_at) VALUES($1,$2,$1,$3,'ACTIVE',clock_timestamp())`, string(a.OwnerUserID), string(a.ID), name+"@example.invalid")
	require.NoError(t, err)
	activewayin.Seed(t, r.ctx, tx)
	require.NoError(t, tx.Commit(r.ctx))
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	b, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(a.OwnerUserID), RoleID: domain.OwnerRoleID,
		ResourceType: "account", ResourceID: string(a.ID), Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, DeletionProtection: true, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err)
	ledger := []abrepo.RelationTuple{{User: "user:" + string(a.OwnerUserID), Relation: "owner", Object: "account:" + string(a.ID)}, {User: "account:" + string(a.ID), Relation: "account", Object: "iam_access_binding:" + string(b.ID)}}
	require.NoError(t, seed.AccessBindingsW().InsertEmittedTuples(r.ctx, b.ID, ledger))
	tuples := []service.RelationTuple{{User: ledger[1].User, Relation: ledger[1].Relation, Object: ledger[1].Object}}
	for _, f := range a.StructuralFacts() {
		tuples = append(tuples, service.RelationTuple{User: f.User, Relation: f.Relation, Object: f.Object})
	}
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, tuples))
	require.NoError(t, seed.Commit(r.ctx))
	return a, b.ID
}

// Все семь публичных сценариев проходят обычный LOGIN. Варианты меняют только
// исходные строки, никогда phase/identity/private proof или результат проверки.
func sevenCRUDPublicFixture(t *testing.T, command, variant string, beforeActivation ...func(*sevenCRUDPublicWorld)) sevenCRUDPublicWorld {
	t.Helper()
	r, ownerRepo := writerProtocolRigBeforePreparation(t)
	w := sevenCRUDPublicWorld{r: r}
	w.account, w.binding = sevenCRUDSeedAccount(t, r, "seven-target")
	foreign, foreignBinding := sevenCRUDSeedAccount(t, r, "seven-foreign")
	r.a, r.b = string(w.account.ID), string(foreign.ID)
	w.r, w.foreignBinding, w.owner = r, foreignBinding, string(w.account.OwnerUserID)
	w.member = seedMemberUser(t, r.ctx, r.admin, r.a, "seven-member")
	w.outsider = seedMemberUser(t, r.ctx, r.admin, r.b, "seven-outsider")
	w.unverified = seedMemberUser(t, r.ctx, r.admin, r.a, "seven-unverified")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{w.member, w.outsider})
	require.NoError(t, err)
	for _, uid := range []string{w.owner, w.member, w.unverified} {
		seedMembership(t, r.ctx, r.admin, domain.UserID(uid), domain.AccountID(r.a), "ACTIVE")
	}
	seedMembership(t, r.ctx, r.admin, domain.UserID(w.member), domain.AccountID(r.b), "ACTIVE")
	seed, err := ownerRepo.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	var tuples []service.RelationTuple
	for _, uid := range []string{w.owner, w.member, w.unverified} {
		tuples = append(tuples, shared.MembershipPointer(domain.UserID(uid), domain.AccountID(r.a)))
	}
	tuples = append(tuples, shared.MembershipPointer(domain.UserID(w.member), domain.AccountID(r.b)))
	w.project = domain.Project{ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: domain.AccountID(r.a), Name: "seven-project", Labels: domain.Labels{}}
	w.sa = domain.ServiceAccount{ID: domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)), AccountID: domain.AccountID(r.a), Name: "seven-sa"}
	if command == "project.delete" {
		w.project, err = seed.ProjectsW().Insert(r.ctx, w.project)
		require.NoError(t, err)
		for _, f := range w.project.StructuralFacts() {
			tuples = append(tuples, service.RelationTuple{User: f.User, Relation: f.Relation, Object: f.Object})
		}
	}
	if command == "service_account.delete" {
		w.sa, err = seed.ServiceAccountsW().Insert(r.ctx, w.sa)
		require.NoError(t, err)
		tuples = append(tuples, service.RelationTuple{User: "account:" + r.a, Relation: "account", Object: "iam_service_account:" + string(w.sa.ID)})
	}
	if command == "role.delete" {
		rules := domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}}
		permissions, compileErr := domain.CompileRules(rules)
		require.NoError(t, compileErr)
		w.role, err = seed.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(r.a), Name: "seven_target_role", Rules: rules, Permissions: permissions})
		require.NoError(t, err)
		var halves catalog.Halves
		require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
		facts, factsErr := catalog.NewFacts(halves)
		require.NoError(t, factsErr)
		require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, w.role.ID, facts.GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
		require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, w.role.ID, facts.RoleVerbsFromSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
		tuples = append(tuples, service.RelationTuple{User: "account:" + r.a, Relation: "account", Object: "iam_role:" + string(w.role.ID)})
		if variant == "bound" {
			b, insertErr := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), RoleID: w.role.ID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.outsider), ResourceType: "account", ResourceID: r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive})
			require.NoError(t, insertErr)
			w.binding = b.ID
		}
	}
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, tuples))
	require.NoError(t, seed.Commit(r.ctx))
	if variant == "nonempty" {
		w.mirror = insertMirrorRowDirect(t, r.ctx, r.admin, "vpc.network", w.project.ID)
	}
	if variant == "oauth" {
		w.oauth = ids.NewID("soc")
		_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.service_account_oauth_clients(id,sva_id,created_by_user_id,credential_kind,secret_hash,expires_at) VALUES($1,$2,$3,'SECRET',decode(repeat('cd',32),'hex'),now()+interval '1 day')`, w.oauth, string(w.sa.ID), w.owner)
		require.NoError(t, err)
	}
	w.actor = w.member
	if command == "account.delete" {
		w.actor = w.owner
	}
	if command == "project.create" || command == "service_account.create" {
		// USER получает реальное editor@account. SA-only container grant пользователю не выдаётся.
		w.authorityBinding = sevenCRUDSystemRelation(t, r, w.actor, "account", r.a, "editor")
	} else if command != "account.create" && command != "account.delete" {
		binding := groupLifecycleBinding(t, r, r.a, w.actor, "seven_operator_role", domain.Rule{Module: "iam", Resources: []string{"project", "serviceAccount", "role"}, Verbs: []string{"create", "delete"}})
		w.authorityBinding = binding
		source := rolePolicyCatalog(t, r)
		engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
		require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	}
	// Узкий hook соседних native expiry-проб работает только до активации.
	require.LessOrEqual(t, len(beforeActivation), 1)
	for _, prepare := range beforeActivation {
		prepare(&w)
	}
	require.NoError(t, ownerRepo.PrepareAuthorityBundle(r.ctx, r.bundle))
	full, contract := fullContractActivate(t, r)
	// Тот же ordinary LOGIN и full contract; наблюдатель не меняет запросы.
	if command == "account.create" || command == "account.delete" {
		full, w.observer = sequenceObservedFullRepo(t, r)
		contract, err = kanamepg.NewFullWriterContract(r.ctx, full, r.bundle)
		require.NoError(t, err)
	}
	w.full, w.ctx = full, contract.Context(r.ctx)
	w.factory, err = kanamepg.NewCRUDWriters(w.ctx, full, r.bundle)
	require.NoError(t, err)
	w.ops = operations.NewRepo(r.runtime, "kaname")
	require.Equal(t, 2, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.users WHERE id=ANY($1::text[]) AND invite_status='ACTIVE' AND email_verified_at IS NOT NULL`, []string{w.actor, w.outsider}))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.users WHERE id=$1 AND invite_status='ACTIVE' AND email_verified_at IS NULL`, w.unverified))
	var semanticProtocol, writerProtocol, requiredContract, stagedContract int
	var phase, enforcement string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT a.protocol_version,p.protocol_version,a.phase,p.enforcement,c.required_contract,c.staged_contract FROM kaname.authority_semantic_identity a JOIN kaname.authority_writer_protocol p USING(singleton) JOIN kaname.authority_writer_contract c USING(singleton) WHERE a.singleton`).Scan(&semanticProtocol, &writerProtocol, &phase, &enforcement, &requiredContract, &stagedContract))
	require.Equal(t, []int{1, 1, 2, 2}, []int{semanticProtocol, writerProtocol, requiredContract, stagedContract})
	require.Equal(t, "active", phase)
	require.Equal(t, "strict", enforcement)
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	w.door = authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	if command != "account.create" {
		relation, object := "v_delete", "account:"+r.a
		switch command {
		case "project.create":
			relation = "editor"
		case "service_account.create":
			var halves catalog.Halves
			require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
			facts, factsErr := catalog.NewFacts(halves)
			require.NoError(t, factsErr)
			grant, ok := facts.ContainerVerb("iam.serviceAccount", "create")
			require.True(t, ok)
			require.Equal(t, "account", grant.ParentType)
			relation = grant.Relation
		case "project.delete":
			object = "project:" + string(w.project.ID)
		case "service_account.delete":
			object = "iam_service_account:" + string(w.sa.ID)
		case "role.delete":
			object = "iam_role:" + string(w.role.ID)
		}
		allowed, checkErr := w.door.Check(w.ctx, "user:"+w.actor, relation, object)
		require.NoError(t, checkErr)
		require.True(t, allowed, "Дано: настоящий native verdict разрешает ровно проверяемое действие")
		allowed, checkErr = w.door.Check(w.ctx, "user:"+w.outsider, relation, object)
		require.NoError(t, checkErr)
		require.False(t, allowed, "Дано: подтверждённый чужой пользователь не имеет права")
	}
	sevenCRUDObserveResult(t, w, false)
	return w
}

// LRO — разрешённый отдельный результат отказа. Снимок содержит сами строки,
// а не только counts, и не включает лишь таблицу операций и счётчики sequence.
func sevenCRUDSnapshot(t *testing.T, w sevenCRUDPublicWorld) string {
	t.Helper()
	var state string
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.accounts t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.projects t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.service_accounts t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.users t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.memberships t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.roles t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.role_rule_selectors t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.role_verb t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_bindings t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_subjects t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_target_members t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.access_binding_emitted_tuples t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.fga_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.relation_fact t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_journal t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.audit_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_reconcile_outbox t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.resource_mirror t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.service_account_oauth_clients t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.minted_token_revocations t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM kaname.issued_account_ids t))::text`).Scan(&state))
	return state
}

func sevenCRUDResult(t *testing.T, w sevenCRUDPublicWorld, op *operations.Operation, err error, code codes.Code) *operations.Operation {
	t.Helper()
	if err != nil {
		sevenCRUDObserveResult(t, w, true)
	}
	require.NoError(t, err, "синхронный вход в существующий UC")
	require.NotNil(t, op)
	done := sevenCRUDOwnOperation(t, w, op.ID)
	actual := codes.OK
	if done.Error != nil {
		actual = status.FromProto(done.Error).Code()
	}
	sevenCRUDObserveResult(t, w, actual != code)
	if code == codes.OK {
		require.Nil(t, done.Error)
		require.NotNil(t, done.Response)
	} else {
		require.NotNil(t, done.Error)
		require.Equal(t, code, status.FromProto(done.Error).Code())
	}
	return done
}

// После каждого завершённого вызова канал очищается, включая ожидаемые отказы.
// Поэтому следующий положительный UC не наследует ошибку предыдущего вызова.
func sevenCRUDObserveResult(t *testing.T, w sevenCRUDPublicWorld, unexpected bool) {
	t.Helper()
	for _, record := range w.observer.take() {
		if unexpected {
			t.Logf("SEVEN_CRUD_PG code=%q message=%q where=%q", record.code, record.message, record.where)
		}
	}
}

// Шесть permission-bearing UC проверяются тем же вызовом для чужого actor,
// явного nil-порта и положительного пути. Account.Create ниже имеет другой
// контракт: владелец выводится из вызывающего, а не из native create-права.
func sevenCRUDDeniedAndMissing(t *testing.T, w sevenCRUDPublicWorld, call func(context.Context, kaname.CRUDWriterFactory) (*operations.Operation, error)) {
	t.Helper()
	before := sevenCRUDSnapshot(t, w)
	op, err := call(declarerCtx(w.ctx, w.outsider), w.factory)
	sevenCRUDResult(t, w, op, err, codes.PermissionDenied)
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "отказ native права ничего не меняет")
	op, err = call(declarerCtx(w.ctx, w.actor), nil)
	sevenCRUDResult(t, w, op, err, codes.Unavailable)
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "явный nil не возвращает raw writer")
}

func sevenCRUDCount(t *testing.T, w sevenCRUDPublicWorld, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, w.r.admin.QueryRow(w.ctx, query, args...).Scan(&n))
	return n
}
func sevenCRUDFact(t *testing.T, w sevenCRUDPublicWorld, user, relation, object string, want bool) {
	t.Helper()
	var exists bool
	require.NoError(t, w.r.runtime.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE subject=$1 AND relation=$2 AND object_type||':'||object_id=$3)`, user, relation, object).Scan(&exists))
	require.Equal(t, want, exists)
}
func sevenCRUDCommitted(t *testing.T, w sevenCRUDPublicWorld, event, kind, dotted, id string) {
	t.Helper()
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->>'resource_id'=$2 AND event_payload->>'actor'=$3`, event, id, w.actor))
	typ := "mirror.delete"
	if event == "iam.account.created" || event == "iam.project.created" || event == "iam.service_account.created" {
		typ = "mirror.upsert"
	}
	// Account.Create ставит событие только default Project, а не аккаунта.
	wantReconcile := 1
	if event == "iam.account.created" {
		wantReconcile = 0
	}
	require.Equal(t, wantReconcile, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type=$1 AND object_id=$2 AND event_type=$3`, dotted, id, typ))
	journalType := "DELETED"
	if typ == "mirror.upsert" {
		journalType = "CREATED"
	}
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind=$1 AND resource_id=$2 AND event_type=$3 AND payload->>'id'=$2`, kind, id, journalType))
}

func TestFullSevenCRUDAccountCreatePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "account.create", "")
	before := sevenCRUDSnapshot(t, w)
	uc := accountapp.NewCreateAccountUseCase(w.full, w.ops).WithAccountCreateWriter(w.factory)
	op, err := uc.Execute(declarerCtx(w.ctx, w.actor), domain.Account{Name: "seven-created", OwnerUserID: domain.UserID(w.outsider)})
	require.Nil(t, op)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "output-only owner нельзя подменить")
	op, err = uc.Execute(w.ctx, domain.Account{Name: "seven-created"})
	require.Nil(t, op)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, before, sevenCRUDSnapshot(t, w))
	op, err = uc.Execute(declarerCtx(w.ctx, w.unverified), domain.Account{Name: "seven-created"})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.NotNil(t, sevenCRUDOwnOperation(t, w, op.ID).Error, "неподтверждённый actor не становится владельцем; это не native Deny")
	sevenCRUDObserveResult(t, w, false)
	require.Equal(t, before, sevenCRUDSnapshot(t, w))
	op, err = accountapp.NewCreateAccountUseCase(w.full, w.ops).WithAccountCreateWriter(nil).Execute(declarerCtx(w.ctx, w.actor), domain.Account{Name: "seven-created"})
	sevenCRUDResult(t, w, op, err, codes.Unavailable)
	require.Equal(t, before, sevenCRUDSnapshot(t, w))
	op, err = uc.Execute(declarerCtx(w.ctx, w.actor), domain.Account{Name: "seven-created", Description: "seven CRUD account", Labels: domain.Labels{"case": "seven"}})
	done := sevenCRUDResult(t, w, op, err, codes.OK)
	require.NotNil(t, done.Metadata)
	var meta iamv1.CreateAccountMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&meta))
	require.NotEmpty(t, meta.GetAccountId())
	require.NotEmpty(t, meta.GetDefaultProjectId())
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.accounts WHERE id=$1 AND owner_user_id=$2 AND name='seven-created' AND description='seven CRUD account' AND labels='{"case":"seven"}'::jsonb`, meta.GetAccountId(), w.actor))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.projects WHERE id=$1 AND account_id=$2 AND name='default'`, meta.GetDefaultProjectId(), meta.GetAccountId()))
	var binding string
	require.NoError(t, w.r.runtime.QueryRow(w.ctx, `SELECT id FROM kaname.access_bindings WHERE resource_type='account' AND resource_id=$1 AND role_id=$2 AND subject_type='user' AND subject_id=$3 AND deletion_protection`, meta.GetAccountId(), string(domain.OwnerRoleID), w.actor).Scan(&binding))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$1 AND subject_type='user' AND subject_id=$2`, binding, w.actor))
	require.Equal(t, 2, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, binding))
	require.Equal(t, 2, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND ((fga_user=$2 AND relation='owner' AND object=$3) OR (fga_user=$3 AND relation='account' AND object=$4))`, binding, "user:"+w.actor, "account:"+meta.GetAccountId(), "iam_access_binding:"+binding))
	sevenCRUDFact(t, w, "user:"+w.actor, "owner", "account:"+meta.GetAccountId(), true)
	sevenCRUDFact(t, w, "account:"+meta.GetAccountId(), "account", "project:"+meta.GetDefaultProjectId(), true)
	sevenCRUDFact(t, w, "cluster:"+domain.ClusterSingletonID, "cluster", "project:"+meta.GetDefaultProjectId(), true)
	allowed, err := w.door.Check(w.ctx, "user:"+w.actor, "v_delete", "account:"+meta.GetAccountId())
	require.NoError(t, err)
	require.True(t, allowed, "владелец получает настоящий native verdict на созданный аккаунт")
	sevenCRUDCommitted(t, w, "iam.account.created", "account", "iam.account", meta.GetAccountId())
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='iam.project' AND object_id=$1 AND event_type='mirror.upsert'`, meta.GetDefaultProjectId()))
}

func TestFullSevenCRUDProjectCreatePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "project.create", "")
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return projectapp.NewCreateProjectUseCase(w.full, w.ops).WithProjectCreateWriter(f).Execute(ctx, w.project)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	done := sevenCRUDResult(t, w, op, err, codes.OK)
	require.NotNil(t, done.Metadata)
	var meta iamv1.CreateProjectMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&meta))
	id := meta.GetProjectId()
	require.NotEmpty(t, id)
	require.Equal(t, w.r.a, meta.GetAccountId())
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.projects WHERE id=$1 AND account_id=$2 AND name=$3`, id, w.r.a, string(w.project.Name)))
	sevenCRUDFact(t, w, "account:"+w.r.a, "account", "project:"+id, true)
	sevenCRUDFact(t, w, "cluster:"+domain.ClusterSingletonID, "cluster", "project:"+id, true)
	sevenCRUDCommitted(t, w, "iam.project.created", "project", "iam.project", id)
}

func TestFullSevenCRUDServiceAccountCreatePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "service_account.create", "")
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return saapp.NewCreateServiceAccountUseCase(w.full, w.ops).WithServiceAccountCreateWriter(f).Execute(ctx, w.sa)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	done := sevenCRUDResult(t, w, op, err, codes.OK)
	require.NotNil(t, done.Metadata)
	var meta iamv1.CreateServiceAccountMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&meta))
	id := meta.GetServiceAccountId()
	require.NotEmpty(t, id)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1 AND account_id=$2 AND name=$3 AND enabled AND created_by_type='user' AND created_by_id=$4`, id, w.r.a, string(w.sa.Name), w.actor))
	sevenCRUDFact(t, w, "account:"+w.r.a, "account", "iam_service_account:"+id, true)
	sevenCRUDCommitted(t, w, "iam.service_account.created", "iam_service_account", "iam.serviceAccount", id)
}

func TestFullSevenCRUDProjectDeletePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "project.delete", "")
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return projectapp.NewDeleteProjectUseCase(w.full, w.ops).WithProjectDeleteWriter(f).Execute(ctx, w.project.ID)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	sevenCRUDFact(t, w, "account:"+w.r.a, "account", "project:"+string(w.project.ID), true)
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	sevenCRUDResult(t, w, op, err, codes.OK)
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.projects WHERE id=$1`, string(w.project.ID)))
	sevenCRUDFact(t, w, "account:"+w.r.a, "account", "project:"+string(w.project.ID), false)
	sevenCRUDFact(t, w, "cluster:"+domain.ClusterSingletonID, "cluster", "project:"+string(w.project.ID), false)
	sevenCRUDCommitted(t, w, "iam.project.deleted", "project", "iam.project", string(w.project.ID))
}

func TestFullSevenCRUDServiceAccountDeletePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "service_account.delete", "")
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return saapp.NewDeleteServiceAccountUseCase(w.full, w.ops).WithServiceAccountDeleteWriter(f).Execute(ctx, w.sa.ID)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)))
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	sevenCRUDResult(t, w, op, err, codes.OK)
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)))
	sevenCRUDCommitted(t, w, "iam.service_account.deleted", "iam_service_account", "iam.serviceAccount", string(w.sa.ID))
}

func TestFullSevenCRUDRoleDeletePublic(t *testing.T) {
	t.Run("unbound", func(t *testing.T) {
		w := sevenCRUDPublicFixture(t, "role.delete", "")
		call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
			return roleapp.NewDeleteRoleUseCase(w.full, w.ops).WithRoleDeleteWriter(f).Execute(ctx, w.role.ID)
		}
		sevenCRUDDeniedAndMissing(t, w, call)
		require.Positive(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id=$1`, string(w.role.ID)))
		require.Positive(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.role_verb WHERE role_id=$1`, string(w.role.ID)))
		op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
		sevenCRUDResult(t, w, op, err, codes.OK)
		require.Zero(t, sevenCRUDCount(t, w, `SELECT (SELECT count(*) FROM kaname.roles WHERE id=$1)+(SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id=$1)+(SELECT count(*) FROM kaname.role_verb WHERE role_id=$1)`, string(w.role.ID)))
		sevenCRUDCommitted(t, w, "iam.role.deleted", "iam_role", "iam.role", string(w.role.ID))
	})
	t.Run("bound-is-restricted", func(t *testing.T) {
		w := sevenCRUDPublicFixture(t, "role.delete", "bound")
		before := sevenCRUDSnapshot(t, w)
		require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.access_bindings WHERE id=$1 AND role_id=$2`, string(w.binding), string(w.role.ID)))
		op, err := roleapp.NewDeleteRoleUseCase(w.full, w.ops).WithRoleDeleteWriter(w.factory).Execute(declarerCtx(w.ctx, w.actor), w.role.ID)
		sevenCRUDResult(t, w, op, err, codes.FailedPrecondition)
		require.Equal(t, before, sevenCRUDSnapshot(t, w), "Role.Delete не каскадирует binding или ведомость")
	})
}

func TestFullSevenCRUDProjectDeleteNonemptyPublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "project.delete", "nonempty")
	before := sevenCRUDSnapshot(t, w)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1 AND parent_project_id=$2`, w.mirror, string(w.project.ID)))
	op, err := projectapp.NewDeleteProjectUseCase(w.full, w.ops).WithProjectDeleteWriter(w.factory).Execute(declarerCtx(w.ctx, w.actor), w.project.ID)
	done := sevenCRUDResult(t, w, op, err, codes.FailedPrecondition)
	st := status.FromProto(done.Error)
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", w.project.ID), st.Message())
	var info *errdetails.ErrorInfo
	for _, detail := range st.Details() {
		if value, ok := detail.(*errdetails.ErrorInfo); ok {
			info = value
		}
	}
	require.NotNil(t, info)
	require.Equal(t, "REFERENCE_IN_USE", info.GetReason())
	require.Equal(t, refusaldomain.For(refusaldomain.ServiceIAM), info.GetDomain())
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "PNE отказ откатывает весь UC")
}

func TestFullSevenCRUDServiceAccountDeleteOAuthRestrictPublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "service_account.delete", "oauth")
	before := sevenCRUDSnapshot(t, w)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id=$1 AND sva_id=$2`, w.oauth, string(w.sa.ID)))
	op, err := saapp.NewDeleteServiceAccountUseCase(w.full, w.ops).WithServiceAccountDeleteWriter(w.factory).Execute(declarerCtx(w.ctx, w.actor), w.sa.ID)
	sevenCRUDResult(t, w, op, err, codes.FailedPrecondition)
	require.Equal(t, before, sevenCRUDSnapshot(t, w), "OAuth FK остаётся RESTRICT: ни каскада, ни частичного audit/outbox")
}

func TestFullSevenCRUDAccountDeletePublic(t *testing.T) {
	w := sevenCRUDPublicFixture(t, "account.delete", "")
	call := func(ctx context.Context, f kaname.CRUDWriterFactory) (*operations.Operation, error) {
		return accountapp.NewDeleteAccountUseCase(w.full, w.ops).WithAccountDeleteWriter(f).Execute(ctx, w.account.ID)
	}
	sevenCRUDDeniedAndMissing(t, w, call)
	var foreignBefore, foreignAfter string
	const foreignSQL = `SELECT jsonb_build_array((SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),(SELECT to_jsonb(b) FROM kaname.access_bindings b WHERE id=$2),(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM kaname.memberships m WHERE account_id=$1),(SELECT jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text) FROM kaname.access_binding_emitted_tuples e WHERE binding_id=$2))::text`
	require.NoError(t, w.r.admin.QueryRow(w.ctx, foreignSQL, w.r.b, string(w.foreignBinding)).Scan(&foreignBefore))
	var tupleAt, journalAt int64
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT COALESCE((SELECT max(id) FROM kaname.fga_outbox),0),COALESCE((SELECT max(sequence_no) FROM kaname.resource_journal),0)`).Scan(&tupleAt, &journalAt))
	var expected, actual []string
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT array_agg(k ORDER BY k) FROM (
 SELECT fga_user||'|'||relation||'|'||object AS k FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1
 UNION SELECT 'cluster:'||$2||'|cluster|account:'||$3
 UNION SELECT 'account:'||$3||'|account|iam_user:'||user_id FROM kaname.memberships WHERE account_id=$3) e`, string(w.binding), domain.ClusterSingletonID, w.r.a).Scan(&expected))
	require.Len(t, expected, 6, "две записи owner ledger, cluster и три membership pointers")
	var expectedUsers, actualUsers string
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT jsonb_agg(to_jsonb(u)||jsonb_build_object('account_id',NULL) ORDER BY id)::text FROM kaname.users u WHERE account_id=$1`, w.r.a).Scan(&expectedUsers))
	op, err := call(declarerCtx(w.ctx, w.actor), w.factory)
	sevenCRUDResult(t, w, op, err, codes.OK)
	require.Zero(t, sevenCRUDCount(t, w, `SELECT (SELECT count(*) FROM kaname.accounts WHERE id=$1)+(SELECT count(*) FROM kaname.memberships WHERE account_id=$1)+(SELECT count(*) FROM kaname.access_bindings WHERE resource_type='account' AND resource_id=$1)+(SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$2)+(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$2)`, w.r.a, string(w.binding)))
	require.Equal(t, 3, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.users WHERE id=ANY($1::text[]) AND account_id IS NULL`, []string{w.owner, w.member, w.unverified}))
	// Полный stored NEW, включая expected_login_kind, обязан совпасть после FK SET NULL.
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT jsonb_agg(to_jsonb(u) ORDER BY id)::text FROM kaname.users u WHERE id=ANY($1::text[])`, []string{w.owner, w.member, w.unverified}).Scan(&actualUsers))
	require.Equal(t, expectedUsers, actualUsers)
	require.NoError(t, w.r.admin.QueryRow(w.ctx, foreignSQL, w.r.b, string(w.foreignBinding)).Scan(&foreignAfter))
	require.Equal(t, foreignBefore, foreignAfter, "чужой аккаунт, его binding, ledger и членства сохраняются побайтово")
	sevenCRUDFact(t, w, "account:"+w.r.b, "account", "iam_user:"+w.member, true)
	require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT COALESCE(array_agg(k ORDER BY k),'{}'::text[]) FROM (
 SELECT (j.payload->>'user')||'|'||r.relation||'|'||(j.payload->>'object') AS k
 FROM kaname.fga_outbox j CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN j.payload ? 'relations' THEN j.payload->'relations' ELSE jsonb_build_array(j.payload->>'relation') END) r(relation)
 WHERE j.id>$1 AND j.event_type='fga.tuple.delete') q`, tupleAt).Scan(&actual))
	require.Equal(t, expected, actual, "удаления равны сохранённой ведомости и реальным структурным указателям")
	require.Zero(t, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.relation_fact WHERE subject||'|'||relation||'|'||object_type||':'||object_id=ANY($1::text[])`, expected))
	sevenCRUDCommitted(t, w, "iam.account.deleted", "account", "iam.account", w.r.a)
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='account' AND resource_id=$2 AND event_type='DELETED' AND scope=jsonb_build_array(jsonb_build_object('type','cluster','id',$3::text))`, journalAt, w.r.a, domain.ClusterSingletonID))
	require.Equal(t, 1, sevenCRUDCount(t, w, `SELECT count(*) FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='iam_access_binding' AND resource_id=$2 AND event_type='DELETED' AND scope=jsonb_build_array(jsonb_build_object('type','account','id',$3::text))`, journalAt, string(w.binding), w.r.a))
	// SET NULL и снятие membership дают по одному UPDATED. Порядок FK callbacks
	// не обещан: промежуточная scope может ещё содержать удаляемый аккаунт,
	// но чужое членство обязано присутствовать в обеих строках своего человека.
	for _, uid := range []string{w.owner, w.member, w.unverified} {
		var count int
		var scopesOK bool
		require.NoError(t, w.r.admin.QueryRow(w.ctx, `SELECT count(*),COALESCE(bool_and(
 scope <@ jsonb_build_array(jsonb_build_object('type','account','id',$3::text),jsonb_build_object('type','account','id',$4::text))
 AND CASE WHEN $2=$5 THEN scope @> jsonb_build_array(jsonb_build_object('type','account','id',$4::text)) ELSE NOT scope @> jsonb_build_array(jsonb_build_object('type','account','id',$4::text)) END),false)
 FROM kaname.resource_journal WHERE sequence_no>$1 AND resource_kind='iam_user' AND resource_id=$2 AND event_type='UPDATED' AND payload->>'id'=$2`, journalAt, uid, w.r.a, w.r.b, w.member).Scan(&count, &scopesOK))
		require.Equal(t, 2, count)
		require.True(t, scopesOK)
	}
}

// Реальная system-выдача разрешённого отношения с ledger и фактом, только до activation.
func sevenCRUDSystemRelation(t *testing.T, r protocolRig, actor, scopeType, scopeID, relation string) domain.AccessBindingID {
	t.Helper()
	w, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer w.Rollback(context.WithoutCancel(r.ctx))
	scope := domain.ScopeAccount
	if scopeType == "cluster" {
		scope = domain.ScopeCluster
	}
	b, err := bindingset.Insert(r.ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID:          domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(actor),
		GrantedRelation: relation, System: true, ResourceType: domain.ResourceType(scopeType), ResourceID: scopeID,
		Scope: scope, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err)
	tuples := []abrepo.RelationTuple{
		{User: "user:" + actor, Relation: relation, Object: scopeType + ":" + scopeID},
		{User: scopeType + ":" + scopeID, Relation: scopeType, Object: "iam_access_binding:" + string(b.ID)},
	}
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(r.ctx, b.ID, tuples))
	for _, tuple := range tuples {
		require.NoError(t, w.EmitFGARelationWrite(r.ctx, []service.RelationTuple{{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}}))
	}
	require.NoError(t, w.Commit(r.ctx))
	return b.ID
}

// Ждём только собственный LRO: общая очередь соседних тестов не его свидетельство.
func sevenCRUDOwnOperation(t *testing.T, w sevenCRUDPublicWorld, id string) *operations.Operation {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.ctx, 20*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		op, err := w.ops.Get(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, op)
		if op.Done {
			return op
		}
		select {
		case <-ctx.Done():
			require.NoError(t, ctx.Err(), "собственная операция не завершилась")
			return nil
		case <-tick.C:
		}
	}
}
