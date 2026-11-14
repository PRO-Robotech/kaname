// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	accessbinding "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type resourceParticipantFixture struct {
	r              protocolRig
	p              *kanamepg.ResourceObjectParticipant
	beginner       service.TxBeginner
	engine         *reconcile.Reconciler
	source         catalog.Source
	scene, foreign registrationscene.Scene
	member         string
	binding        domain.AccessBindingID
	gate           *authzguard.RelationWriteGate
	ctx            context.Context
}

func newResourceParticipantFixture(t *testing.T, strict bool) resourceParticipantFixture {
	t.Helper()
	r := writerProtocolRig(t)
	scene, foreign := registrationscene.Seed(t, r.ctx, r.admin), registrationscene.Seed(t, r.ctx, r.admin)
	member := seedMemberUser(t, r.ctx, r.admin, scene.Account, "resource-object-reader")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, member)
	require.NoError(t, err)
	// Настоящее account-scoped назначение установки и его штатная материализация.
	// Проверяемый модуль не получает ни owner, ни administrator bypass.
	roster, err := moduleidentity.Parse([]string{"modules/kacho-vpc=module-writer"})
	require.NoError(t, err)
	// Миграции оставляют platform module SA за пределами baseline; roster
	// только распознаёт сертификат. Создаём настоящую identity до installer.
	// Её аккаунт отличается от обеих сцен: право появится лишь из assignment.
	moduleWriter, err := lifecycleOwner(r).Writer(r.ctx)
	if moduleWriter != nil {
		t.Cleanup(func() { policyFixtureRollback(moduleWriter) })
	}
	require.NoError(t, err)
	_, err = moduleWriter.ServiceAccountsW().Insert(r.ctx, domain.ServiceAccount{
		ID:          domain.ServiceAccountID(authzguard.ServiceAccountIDForService("vpc")),
		AccountID:   domain.AccountID(r.a),
		Name:        domain.SvcAccountName("kacho-vpc"),
		Description: domain.Description("resource participant module identity"),
	})
	require.NoError(t, err)
	require.NoError(t, moduleWriter.Commit(r.ctx))
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster, seed.RegistrationWriterPlan{
		Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "resource-participant-vpc", AccountID: scene.Account, Module: "vpc"}},
	}))
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	source := catalog.Fixed{F: facts}
	// Роль/holder готовы до activation, самого будущего объекта ещё нет.
	rules := domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"visible": "yes"}}}
	projection, err := facts.ProjectGrantRules(rules, domain.TenantPolicy())
	require.NoError(t, err)
	owner := lifecycleOwner(r)
	w, err := owner.Writer(r.ctx)
	if w != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = w.Rollback(ctx)
		})
	}
	require.NoError(t, err)
	role, err := w.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), ProjectID: domain.ProjectID(scene.Project), Name: "resource_participant_reader", Rules: rules, Permissions: projection.Permissions})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, projection.Selectors))
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, projection.Verbs))
	require.NoError(t, w.RolesW().ReplaceRuleRefs(r.ctx, role.ID, domain.RuleRefsOf(rules)))
	bid := domain.AccessBindingID(ids.NewID("acb"))
	_, err = bindingset.Insert(r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: bid, RoleID: role.ID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member), ResourceType: "project", ResourceID: scene.Project, Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	require.NoError(t, w.Commit(r.ctx))
	if strict {
		require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
	}
	p, err := kanamepg.NewResourceObjectParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	beginner, err := p.RegistrationTxBeginner(r.runtime)
	require.NoError(t, err)
	engine, err := p.NewObjectReconciler(nil)
	require.NoError(t, err)
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(roster)
	ctx := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", true)
	require.NoError(t, gate.AuthorizeAccount(ctx, scene.Account), "positive из настоящего источника account writer")
	require.Equal(t, codes.PermissionDenied, status.Code(gate.AuthorizeAccount(ctx, foreign.Account)))
	return resourceParticipantFixture{r, p, beginner, engine, source, scene, foreign, member, bid, gate, ctx}
}
func (f resourceParticipantFixture) uc(audit interface {
	TupleStandsTx(context.Context, service.Tx, service.RelationTuple) (bool, error)
	EmitTx(context.Context, service.Tx, service.AuditEvent) error
}) *internaliam.RegisterResourceUseCase {
	return internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(f.r.runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbinding.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), f.source), audit, kanamepg.NewRegistrationScopeReader()).WithResourceTxBeginner(f.beginner).WithRegistrationAuthority(f.gate).WithObjectReconciler(f.engine, nil).WithResidualTupleReader(kanamepg.NewResidualTupleReader(f.r.runtime))
}
func (f resourceParticipantFixture) request(id string, version time.Time, visible bool) *iamv1.RegisterResourceRequest {
	labels := map[string]string{}
	if visible {
		labels["visible"] = "yes"
	}
	return &iamv1.RegisterResourceRequest{SubjectId: "project:" + f.scene.Project, Relation: "project", Object: "vpc_network:" + id, ParentProjectId: f.scene.Project, ParentAccountId: f.scene.Account, ParentChain: f.scene.ProjectChain(), Labels: labels, SourceVersion: timestamppb.New(version)}
}
func (f resourceParticipantFixture) native(t *testing.T, id string, want bool) {
	t.Helper()
	allow, err := (delegationNativeDoor{f.r}).Check(f.ctx, "user:"+f.member, "v_get", "vpc_network:"+id)
	require.NoError(t, err)
	require.Equal(t, want, allow)
}
func TestResourceParticipantActualRegisterUpdateUnregister(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			f := newResourceParticipantFixture(t, strict)
			uc := f.uc(kanamepg.NewRegistrationAudit())
			const id = "participant-future-network"
			version := time.Now().UTC()
			f.native(t, id, false)
			// Будущий объект регистрируется после activation и подготовленной выдачи.
			require.NoError(t, uc.Register(f.ctx, f.request(id, version, true)))
			f.native(t, id, true)
			var members, ledger int
			require.NoError(t, f.r.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_id=$2),(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_id=$2)`, f.binding, id).Scan(&members, &ledger))
			require.Positive(t, members)
			require.Positive(t, ledger)
			// Повторная доставка и все три реальные single-object двери.
			require.NoError(t, uc.Register(f.ctx, f.request(id, version, true)))
			require.NoError(t, f.engine.ReconcileObjectForwardNoStale(f.ctx, "vpc.network", id))
			require.NoError(t, f.engine.ReconcileObject(f.ctx, "vpc.network", id))
			f.native(t, id, true)
			require.NoError(t, uc.Register(f.ctx, f.request(id, version.Add(time.Second), false)))
			f.native(t, id, false)
			require.NoError(t, uc.Register(f.ctx, f.request(id, version.Add(2*time.Second), true)))
			f.native(t, id, true)
			require.NoError(t, uc.Unregister(f.ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + f.scene.Project, Relation: "project", Object: "vpc_network:" + id, SourceVersion: timestamppb.New(version.Add(3 * time.Second))}))
			f.native(t, id, false)
			var mirrors int
			require.NoError(t, f.r.admin.QueryRow(f.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1`, id).Scan(&mirrors))
			require.Zero(t, mirrors)
			denied := f.request("participant-denied", version, true)
			denied.SubjectId = "project:" + f.foreign.Project
			denied.ParentProjectId = f.foreign.Project
			denied.ParentAccountId = f.foreign.Account
			denied.ParentChain = f.foreign.ProjectChain()
			require.Equal(t, codes.PermissionDenied, status.Code(uc.Register(f.ctx, denied)))
			require.Equal(t, codes.PermissionDenied, status.Code(uc.Register(f.r.ctx, f.request("participant-unverified", version, true))))
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

type resourceFaultAudit struct {
	*kanamepg.RegistrationAudit
	cancel  context.CancelFunc
	reached bool
}

var errResourceAudit = errors.New("resource audit fault after real write")

func (a *resourceFaultAudit) EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error {
	if err := a.RegistrationAudit.EmitTx(ctx, tx, ev); err != nil {
		return err
	}
	a.reached = true
	if a.cancel != nil {
		a.cancel()
		return ctx.Err()
	}
	return errResourceAudit
}
func TestResourceParticipantActualMutationRollbackAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelled), func(t *testing.T) {
			f := newResourceParticipantFixture(t, true)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			audit := &resourceFaultAudit{RegistrationAudit: kanamepg.NewRegistrationAudit()}
			if cancelled {
				audit.cancel = cancel
			}
			before := resourceOutcomeCounts(t, f)
			err := f.uc(audit).Register(ctx, f.request("participant-rollback", time.Now(), true))
			require.Error(t, err)
			require.True(t, audit.reached)
			require.Equal(t, before, resourceOutcomeCounts(t, f), "включая mirror, pointers, fact, outbox и аудит")
			f.native(t, "participant-rollback", false)
			authorityWaitReleased(t, f.r.runtime)
			require.NoError(t, f.uc(kanamepg.NewRegistrationAudit()).Register(f.ctx, f.request("participant-rollback", time.Now().Add(time.Second), true)))
			f.native(t, "participant-rollback", true)
		})
	}
}
func resourceOutcomeCounts(t *testing.T, f resourceParticipantFixture) []int64 {
	t.Helper()
	out := []int64{}
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "resource_registration_scope", "resource_registration_pointer", "producer_source_receipt", "relation_fact", "fga_outbox", "audit_outbox", "resource_reconcile_outbox"} {
		var n int64
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, "SELECT count(*) FROM kaname."+table).Scan(&n))
		out = append(out, n)
	}
	return out
}

func TestResourceParticipantGlobalWaitOneConnectionAndClosedIdentity(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.New(pool, nil)
	p, err := kanamepg.NewResourceObjectParticipant(r.ctx, repo, r.bundle)
	require.NoError(t, err)
	beginner, err := p.RegistrationTxBeginner(pool)
	require.NoError(t, err)
	_, err = p.RegistrationTxBeginner(r.runtime)
	require.Error(t, err, "foreign pool не заменяет intended pool")
	held, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	if held != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = held.Rollback(ctx)
		})
	}
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		tx, e := beginner.Begin(ctx)
		if tx != nil {
			policyFixtureRollback(tx)
		}
		result <- e
	}()
	// Проверяется настоящее ожидание GLOBAL advisory lock, не ошибка entry.
	require.Eventually(t, func() bool {
		var n int
		err := r.admin.QueryRow(r.ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.usename=$1 AND l.locktype='advisory' AND l.classid=1262569283::oid AND l.objid=0::oid AND NOT l.granted`, r.role).Scan(&n)
		return err == nil && n > 0
	}, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err = <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("GLOBAL entry не завершился после отмены")
	}
	authorityWaitReleased(t, pool)
	require.NoError(t, held.Rollback(r.ctx))
	tx, err := beginner.Begin(r.ctx)
	if tx != nil {
		opened := tx
		t.Cleanup(func() { policyFixtureRollback(opened) })
	}
	require.NoError(t, err)
	native, ok := tx.(pgx.Tx)
	require.True(t, ok)
	var isolation string
	require.NoError(t, native.QueryRow(r.ctx, `SHOW transaction_isolation`).Scan(&isolation))
	require.Equal(t, "read committed", isolation)
	_, err = native.Exec(r.ctx, `UPDATE kaname.accounts SET description='participant same tx' WHERE id=$1`, r.a)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(r.ctx))
	authorityWaitReleased(t, pool)
	engine, err := p.NewObjectReconciler(nil)
	require.NoError(t, err)
	require.NoError(t, engine.ReconcileObject(r.ctx, "vpc.network", "absent-object"))
	require.ErrorContains(t, engine.ReconcileBinding(r.ctx, domain.AccessBindingID("acb-not-a-sweep")), "single object intent")
	authorityWaitReleased(t, pool)
	_, err = pool.Exec(r.ctx, `UPDATE kaname.accounts SET description='raw forbidden' WHERE id=$1`, r.a)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Error(t, repo.ActivateAuthorityBundle(r.ctx, r.bundle), "runtime не активирует identity")
	// Только owner fault injection: готовый participant обязан повторно сверить
	// identity на каждом входе; восстановленный positive остаётся настоящим.
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=repeat('f',64)`)
	require.NoError(t, err)
	resourceRequireRejectedBegin(t, r.ctx, beginner)
	require.Error(t, engine.ReconcileObject(r.ctx, "vpc.network", "absent-object"))
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=$1`, r.bundle.Identity().ModelID)
	require.NoError(t, err)
	require.NoError(t, engine.ReconcileObject(r.ctx, "vpc.network", "absent-object"))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	resourceRequireRejectedBegin(t, r.ctx, beginner)
	require.Error(t, engine.ReconcileObjectForward(r.ctx, "vpc.network", "absent-object"))
	authorityWaitReleased(t, pool)
}

func resourceRequireRejectedBegin(t *testing.T, ctx context.Context, b service.TxBeginner) {
	t.Helper()
	tx, err := b.Begin(ctx)
	if tx != nil {
		policyFixtureRollback(tx)
	}
	require.Error(t, err)
	require.Nil(t, tx)
}

// INSERT на command VIEW разрешает только вызов штатной команды. Без entry
// её SECURITY INVOKER trigger доходит до настоящего strict guard и получает отказ.
func TestResourceParticipantCommandViewRequiresEntry(t *testing.T) {
	f := newResourceParticipantFixture(t, true)
	var insert, privateWrite, definer bool
	require.NoError(t, f.r.runtime.QueryRow(f.ctx, `SELECT has_table_privilege(current_user,'kaname.resource_registration_command','INSERT'),has_table_privilege(current_user,'kaname.authority_writer_protocol','INSERT'),(SELECT prosecdef FROM pg_catalog.pg_proc WHERE oid='kaname.resource_registration_command_apply()'::regprocedure)`).Scan(&insert, &privateWrite, &definer))
	require.True(t, insert)
	require.False(t, privateWrite)
	require.False(t, definer)
	tx, err := f.r.runtime.Begin(f.ctx)
	if tx != nil {
		defer policyFixtureRollback(tx)
	}
	require.NoError(t, err)
	_, _, err = kanamepg.NewResourceMirrorEmitter().UpsertTx(f.ctx, tx, service.ResourceMirrorRow{
		ObjectType: "vpc.network", ObjectID: "command-entry-required", ParentProjectID: f.scene.Project,
		ParentAccountID: f.scene.Account, ParentChain: []string{"project:" + f.scene.Project, "account:" + f.scene.Account},
		Labels: map[string]string{"visible": "yes"}, SourceVersion: time.Now().UTC(),
	})
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Equal(t, "authority transaction attestation required", pe.Message, "отказ guard, а не отсутствие INSERT на VIEW")
	policyFixtureRollback(tx)
	var n int
	require.NoError(t, f.r.admin.QueryRow(f.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_id='command-entry-required'`).Scan(&n))
	require.Zero(t, n)
	f.native(t, "command-entry-required", false)
	require.NoError(t, f.uc(kanamepg.NewRegistrationAudit()).Register(f.ctx, f.request("command-entry-required", time.Now().UTC(), true)))
	f.native(t, "command-entry-required", true)
	authorityWaitReleased(t, f.r.runtime)
}

// Реальные SQL sections проверяют существующий runtime, будущий вызов installer,
// посторонний custom ACL и точное сохранение OID/owner/ACL функции. Goose journal не меняется.
func TestResourceParticipantCommandViewMigrationACL(t *testing.T) {
	r := writerProtocolRig(t)
	raw, err := migrations.FS.ReadFile("20261114100000_authority_runtime_can_submit_registration_commands.sql")
	require.NoError(t, err)
	parts := strings.Split(string(raw), "-- +goose Down")
	require.Len(t, parts, 2)
	custom := "registration_custom_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{custom}.Sanitize()
	_, err = r.admin.Exec(r.ctx, "CREATE ROLE "+quoted+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.admin.Exec(ctx, "DROP OWNED BY "+quoted)
		_, _ = r.admin.Exec(ctx, "DROP ROLE "+quoted)
	})
	_, err = r.admin.Exec(r.ctx, "GRANT USAGE ON SCHEMA kaname TO "+quoted+"; GRANT SELECT,INSERT ON kaname.resource_registration_command TO "+quoted)
	require.NoError(t, err)
	var original, identity string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prosrc,concat(oid,':',proowner,':',prosecdef,':',coalesce(proacl::text,''),':',proconfig::text) FROM pg_catalog.pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure`).Scan(&original, &identity))
	for _, up := range []bool{false, true} {
		section := parts[1]
		if up {
			section = parts[0]
		}
		tx, e := r.admin.Begin(r.ctx)
		if tx != nil {
			defer policyFixtureRollback(tx)
		}
		require.NoError(t, e)
		_, e = tx.Exec(r.ctx, section)
		require.NoError(t, e)
		require.NoError(t, tx.Commit(r.ctx))
		var body, actualIdentity string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prosrc,concat(oid,':',proowner,':',prosecdef,':',coalesce(proacl::text,''),':',proconfig::text) FROM pg_catalog.pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure`).Scan(&body, &actualIdentity))
		require.Equal(t, identity, actualIdentity)
		if up {
			require.Equal(t, original, body)
		} else {
			require.NotContains(t, body, "resource_registration_command")
		}
		var runtimeInsert, runtimeSelect, customInsert, customSelect, privateWrite bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT has_table_privilege($1,'kaname.resource_registration_command','INSERT'),has_table_privilege($1,'kaname.resource_registration_command','SELECT'),has_table_privilege($2,'kaname.resource_registration_command','INSERT'),has_table_privilege($2,'kaname.resource_registration_command','SELECT'),has_table_privilege($1,'kaname.authority_writer_protocol','INSERT')`, r.role, custom).Scan(&runtimeInsert, &runtimeSelect, &customInsert, &customSelect, &privateWrite))
		require.Equal(t, up, runtimeInsert)
		require.True(t, runtimeSelect)
		require.True(t, customInsert)
		require.True(t, customSelect)
		require.False(t, privateWrite)
	}
	// Проверяем и installer для нового вызова, независимо от backfill существующего ACL.
	_, err = r.admin.Exec(r.ctx, "REVOKE INSERT ON kaname.resource_registration_command FROM "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
	require.NoError(t, err)
	var granted bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.resource_registration_command','INSERT')`).Scan(&granted))
	require.True(t, granted)
	// Публичная видимость функции не даёт runtime право вызвать owner-only installer.
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	authorityWaitReleased(t, r.runtime)
}
