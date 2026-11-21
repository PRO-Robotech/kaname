// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
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

// Только public runner: старый participant/opener не создаётся даже для setup.
// Admin pool служит установке, fault injection и наблюдению; business работает
// под настоящим runtime LOGIN на единственном указанном pool.
type resourcePublicFixture struct {
	r        protocolRig
	ctx      context.Context
	scenes   [2]registrationscene.Scene
	members  [2]string
	bindings [2]domain.AccessBindingID
	roster   moduleidentity.Roster
	gate     *authzguard.RelationWriteGate
	uc       *internaliam.RegisterResourceUseCase
	engine   *reconcile.Reconciler
}

func newResourcePublicFixture(t *testing.T, maxConns int32) resourcePublicFixture {
	t.Helper()
	return newResourcePublicFixtureWithNames(t, maxConns, [2][]string{})
}

func newResourcePublicFixtureWithNames(t *testing.T, maxConns int32, names [2][]string) resourcePublicFixture {
	t.Helper()
	r := writerProtocolRig(t)
	cfg := r.runtime.Config()
	cfg.MaxConns = maxConns
	// Старый setup pool больше не участвует ни в одном business вызове.
	r.runtime.Close()
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	r.runtime, r.repo = pool, kanamepg.New(pool, nil)
	f := resourcePublicFixture{r: r}
	f.scenes = [2]registrationscene.Scene{registrationscene.Seed(t, r.ctx, r.admin), registrationscene.Seed(t, r.ctx, r.admin)}
	f.roster, err = moduleidentity.Parse([]string{"modules/kacho-vpc=module-writer"})
	require.NoError(t, err)
	owner := lifecycleOwner(r)
	w, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	_, err = w.ServiceAccountsW().Insert(r.ctx, domain.ServiceAccount{ID: domain.ServiceAccountID(authzguard.ServiceAccountIDForService("vpc")), AccountID: domain.AccountID(r.a), Name: "kacho-vpc", Description: "public resource runner identity"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(r.ctx))
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), f.roster, f.writerPlan(true)))
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	source := catalog.Fixed{F: facts}
	for i, scene := range f.scenes {
		rules := domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"visible": "yes"}}}
		if len(names[i]) != 0 {
			// Изоляция проверяет конечные непересекающиеся selectors. Общий
			// LABELS predicate законно включает foreign REJECTED candidates.
			rules[0].MatchLabels = nil
			rules[0].ResourceNames = names[i]
		}
		projection, err := facts.ProjectGrantRules(rules, domain.TenantPolicy())
		require.NoError(t, err)
		f.members[i] = seedMemberUser(t, r.ctx, r.admin, scene.Account, fmt.Sprintf("public-resource-reader-%d", i))
		_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, f.members[i])
		require.NoError(t, err)
		writer, e := owner.Writer(r.ctx)
		require.NoError(t, e)
		t.Cleanup(func() { policyFixtureRollback(writer) })
		role, e := writer.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), ProjectID: domain.ProjectID(scene.Project), Name: "public_resource_reader", Rules: rules, Permissions: projection.Permissions})
		require.NoError(t, e)
		require.NoError(t, writer.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, projection.Selectors))
		require.NoError(t, writer.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, projection.Verbs))
		require.NoError(t, writer.RolesW().ReplaceRuleRefs(r.ctx, role.ID, domain.RuleRefsOf(rules)))
		f.bindings[i] = domain.AccessBindingID(ids.NewID("acb"))
		_, e = bindingset.Insert(r.ctx, writer.AccessBindingsW(), domain.AccessBinding{ID: f.bindings[i], RoleID: role.ID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(f.members[i]), ResourceType: "project", ResourceID: scene.Project, Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
		require.NoError(t, e)
		require.NoError(t, writer.Commit(r.ctx))
	}
	require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
	f.gate = authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(f.roster)
	f.ctx = grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", true)
	for _, s := range f.scenes {
		require.NoError(t, f.gate.AuthorizeAccount(f.ctx, s.Account))
	}
	runner, err := kanamepg.NewResourceDecisionRunner(r.ctx, r.repo, r.bundle, f.gate)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(resourcePublicLogWriter{t: t}, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if err, ok := attr.Value.Any().(error); ok {
				return slog.String(attr.Key, resourcePublicErrorDetails(err))
			}
			return attr
		},
	}))
	f.engine, err = runner.NewObjectReconciler(logger)
	require.NoError(t, err)
	f.uc = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbinding.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(f.gate).WithObjectReconciler(f.engine, logger).WithResidualTupleReader(kanamepg.NewResidualTupleReader(pool))
	require.NoError(t, f.uc.WithResourceDecisionRunner(runner))
	return f
}

// Наблюдение не меняет ошибки production runner и не добавляет новый вызов.
// В частности, postcommit ошибка по-прежнему не меняет результат Register.
type resourcePublicLogWriter struct{ t *testing.T }

func (w resourcePublicLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

func resourcePublicErrorDetails(err error) string {
	if err == nil {
		return ""
	}
	result := fmt.Sprintf("%T: %v", err, err)
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		result += fmt.Sprintf("; SQLSTATE=%s message=%s detail=%s where=%s", pgerr.Code, pgerr.Message, pgerr.Detail, pgerr.Where)
	}
	var visit func(error, int)
	visit = func(current error, depth int) {
		if current == nil || depth > 8 {
			return
		}
		result += fmt.Sprintf("; cause[%d]=%T: %v", depth, current, current)
		if many, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				visit(child, depth+1)
			}
		} else if one, ok := current.(interface{ Unwrap() error }); ok {
			visit(one.Unwrap(), depth+1)
		}
	}
	visit(err, 0)
	return result
}

func resourcePublicRequireNoError(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "причина Object Run: %s", resourcePublicErrorDetails(err))
}

func (f resourcePublicFixture) writerPlan(includeA bool) seed.RegistrationWriterPlan {
	assignments := []domain.RegistrationAccountWriter{{AssignmentID: "resource-public-B", AccountID: f.scenes[1].Account, Module: "vpc"}}
	if includeA {
		assignments = append(assignments, domain.RegistrationAccountWriter{AssignmentID: "resource-public-A", AccountID: f.scenes[0].Account, Module: "vpc"})
	}
	return seed.RegistrationWriterPlan{Assignments: assignments}
}
func (f resourcePublicFixture) request(scene int, id string, version time.Time) *iamv1.RegisterResourceRequest {
	s := f.scenes[scene]
	return &iamv1.RegisterResourceRequest{SubjectId: "project:" + s.Project, Relation: "project", Object: "vpc_network:" + id, ParentProjectId: s.Project, ParentAccountId: s.Account, ParentChain: s.ProjectChain(), Labels: map[string]string{"visible": "yes"}, SourceVersion: timestamppb.New(version)}
}
func (f resourcePublicFixture) native(t *testing.T, scene int, id string, want bool) {
	t.Helper()
	allow, err := (delegationNativeDoor{f.r}).Check(f.ctx, "user:"+f.members[scene], "v_get", "vpc_network:"+id)
	require.NoError(t, err)
	require.Equal(t, want, allow)
}

// Канал закрывается после завершения actual call; cancellation и JOIN обязательны
// даже если assertion оборвал тест. В горутине нет require/Fatal.
type resourcePublicCall struct {
	done   chan struct{}
	err    error
	cancel context.CancelFunc
}

func resourcePublicStart(t *testing.T, parent context.Context, fn func(context.Context) error) *resourcePublicCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	call := &resourcePublicCall{done: make(chan struct{}), cancel: cancel}
	go func() { defer close(call.done); call.err = fn(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-call.done:
		case <-time.After(6 * time.Second):
			t.Errorf("public Resource goroutine did not join after cancellation")
		}
	})
	return call
}
func resourcePublicAwait(t *testing.T, call *resourcePublicCall) error {
	t.Helper()
	select {
	case <-call.done:
		return call.err
	case <-time.After(16 * time.Second):
		t.Fatal("public Resource call did not finish")
		return context.DeadlineExceeded
	}
}
func resourcePublicHold(t *testing.T, r protocolRig, query string, args ...any) pgx.Tx {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	tx, err := r.admin.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(c)
	})
	_, err = tx.Exec(ctx, query, args...)
	require.NoError(t, err)
	return tx
}
func resourcePublicWaitBlocked(t *testing.T, r protocolRig, blocker uint32, role, queryFragment string) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	var pid uint32
	require.Eventually(t, func() bool {
		err := r.admin.QueryRow(ctx, `SELECT a.pid FROM pg_stat_activity a WHERE a.datname=current_database() AND a.wait_event_type='Lock' AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND ($2='' OR a.usename=$2) AND position($3 in a.query)>0 AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted) ORDER BY a.pid LIMIT 1`, blocker, role, queryFragment).Scan(&pid)
		return err == nil
	}, 4*time.Second, 10*time.Millisecond, "actual pg_locks + pg_blocking_pids witness")
	return pid
}
func resourcePublicBlockedBy(t *testing.T, r protocolRig, pid, blocker uint32) {
	t.Helper()
	var blocked bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`, pid, blocker).Scan(&blocked))
	require.True(t, blocked, "writer A remains blocked while B commits")
}
func resourcePublicCounts(t *testing.T, r protocolRig) []int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	var result []int64
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "resource_registration_scope", "resource_registration_pointer", "producer_source_receipt", "relation_fact", "fga_outbox", "audit_outbox", "resource_reconcile_outbox", "access_binding_target_members", "access_binding_emitted_tuples"} {
		var n int64
		require.NoError(t, r.admin.QueryRow(ctx, "SELECT count(*) FROM kaname."+table).Scan(&n))
		result = append(result, n)
	}
	return result
}
func resourcePublicSnapshot(t *testing.T, r protocolRig) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	result := map[string]string{}
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "resource_registration_scope", "resource_registration_pointer", "producer_source_receipt", "relation_fact", "fga_outbox", "audit_outbox", "resource_reconcile_outbox", "access_binding_target_members", "access_binding_emitted_tuples"} {
		var snapshot string
		require.NoError(t, r.admin.QueryRow(ctx, "SELECT coalesce(jsonb_agg(row_value ORDER BY row_value::text),'[]'::jsonb)::text FROM (SELECT to_jsonb(t) row_value FROM kaname."+table+" t) snapshot").Scan(&snapshot))
		result[table] = snapshot
	}
	return result
}
func resourcePublicDelta(after, before []int64) []int64 {
	result := make([]int64, len(after))
	for i := range after {
		result[i] = after[i] - before[i]
	}
	return result
}

func TestResourcePublicRunSameSAAccountIsolation(t *testing.T) {
	f := newResourcePublicFixtureWithNames(t, 2, [2][]string{{"public-isolation-A"}, {"public-isolation-B"}})
	// Одновременно удержаны A и домашний аккаунт module SA. У B нет зависимости
	// ни от одного из них; общий actor/type не превращает footprint в GLOBAL.
	held := resourcePublicHold(t, f.r, `SELECT pg_advisory_xact_lock(1262569281,hashtext($1)),pg_advisory_xact_lock(1262569281,hashtext($2))`, f.scenes[0].Account, f.r.a)
	a := resourcePublicStart(t, f.ctx, func(ctx context.Context) error {
		return f.uc.Register(ctx, f.request(0, "public-isolation-A", time.Now().UTC()))
	})
	pid := resourcePublicWaitBlocked(t, f.r, held.Conn().PgConn().PID(), f.r.role, "authority_resource_enter_v2")
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, f.uc.Register(ctx, f.request(1, "public-isolation-B", time.Now().UTC())))
	resourcePublicBlockedBy(t, f.r, pid, held.Conn().PgConn().PID())
	f.native(t, 1, "public-isolation-B", true)
	f.native(t, 0, "public-isolation-A", false)
	require.NoError(t, held.Rollback(f.r.ctx))
	require.NoError(t, resourcePublicAwait(t, a))
	f.native(t, 0, "public-isolation-A", true)
	f.native(t, 1, "public-isolation-A", false)
	authorityWaitReleased(t, f.r.runtime)
}

func TestResourcePublicRunOneConnectionCancellationAndObjectRoutes(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	require.EqualValues(t, 1, f.r.runtime.Config().MaxConns)
	before := resourcePublicSnapshot(t, f.r)
	held := resourcePublicHold(t, f.r, `SELECT pg_advisory_xact_lock(1262569281,hashtext($1))`, f.scenes[0].Account)
	call := resourcePublicStart(t, f.ctx, func(ctx context.Context) error {
		return f.uc.Register(ctx, f.request(0, "public-cancel", time.Now().UTC()))
	})
	resourcePublicWaitBlocked(t, f.r, held.Conn().PgConn().PID(), f.r.role, "authority_resource_enter_v2")
	call.cancel()
	require.ErrorIs(t, resourcePublicAwait(t, call), context.Canceled)
	authorityWaitReleased(t, f.r.runtime)
	require.Equal(t, before, resourcePublicSnapshot(t, f.r), "cancelled attempt leaves no business artifacts or changed rows")
	require.NoError(t, held.Rollback(f.r.ctx))
	require.NoError(t, f.uc.Register(f.ctx, f.request(0, "public-after-cancel", time.Now().UTC())))
	resourcePublicRequireNoError(t, f.engine.ReconcileObject(f.ctx, "vpc.network", "public-after-cancel"))
	resourcePublicRequireNoError(t, f.engine.ReconcileObjectForward(f.ctx, "vpc.network", "public-after-cancel"))
	resourcePublicRequireNoError(t, f.engine.ReconcileObjectForwardNoStale(f.ctx, "vpc.network", "public-after-cancel"))
	f.native(t, 0, "public-after-cancel", true)
	authorityWaitReleased(t, f.r.runtime)
}

func TestResourcePublicRunDeferredCommitAbort(t *testing.T) {
	for _, sqlstate := range []string{"55P03", "P1034"} {
		t.Run(sqlstate, func(t *testing.T) {
			f := newResourcePublicFixture(t, 1)
			before := resourcePublicCounts(t, f.r)
			require.NoError(t, f.uc.Register(f.ctx, f.request(0, "public-clean-control", time.Now().UTC())))
			control := resourcePublicDelta(resourcePublicCounts(t, f.r), before)
			require.Positive(t, control[0])
			require.Positive(t, control[6])
			require.Positive(t, control[7])
			require.Positive(t, control[9])
			require.Positive(t, control[10])
			// Только владелец устанавливает инъектор; sequence переживает rollback.
			// На обеих попытках проверяем именно COMMIT: ранний SET CONSTRAINTS
			// завершается неповторяемой ошибкой до изменения счётчика попыток.
			_, err := f.r.admin.Exec(f.r.ctx, fmt.Sprintf(`CREATE SEQUENCE kaname.resource_public_retry_seq;
CREATE FUNCTION kaname.resource_public_commit_abort() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF NEW.object_id='public-commit-retry' THEN
  IF coalesce(lower(btrim(current_query())), '') NOT IN ('commit', 'commit;') THEN
   RAISE EXCEPTION 'resource commit witness fired before COMMIT' USING ERRCODE='P0001';
  END IF;
  IF nextval('kaname.resource_public_retry_seq')=1 THEN RAISE EXCEPTION 'resource native deferred commit abort' USING ERRCODE='%s'; END IF;
 END IF; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION kaname.resource_public_commit_abort() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER resource_public_commit_abort AFTER INSERT ON kaname.resource_mirror DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.resource_public_commit_abort()`, sqlstate))
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = f.r.admin.Exec(ctx, `DROP TRIGGER IF EXISTS resource_public_commit_abort ON kaname.resource_mirror; DROP FUNCTION IF EXISTS kaname.resource_public_commit_abort(); DROP SEQUENCE IF EXISTS kaname.resource_public_retry_seq`)
			})
			var deferred bool
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT tgdeferrable AND tginitdeferred FROM pg_trigger WHERE tgname='resource_public_commit_abort'`).Scan(&deferred))
			require.True(t, deferred)
			before = resourcePublicCounts(t, f.r)
			request := f.request(0, "public-commit-retry", time.Now().UTC())
			require.NoError(t, f.uc.Register(f.ctx, request))
			var attempts int64
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT last_value FROM kaname.resource_public_retry_seq`).Scan(&attempts))
			require.EqualValues(t, 2, attempts)
			require.Equal(t, control, resourcePublicDelta(resourcePublicCounts(t, f.r), before), "whole failed attempt rolled back: same artifact delta as clean registration")
			f.native(t, 0, "public-commit-retry", true)
			after := resourcePublicCounts(t, f.r)
			require.NoError(t, f.uc.Register(f.ctx, request))
			require.Equal(t, after, resourcePublicCounts(t, f.r), "identical delivery adds no mirror/member/ledger/audit/fact/outbox rows")
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func TestResourcePublicRunInstallationRevokedWhileWaiting(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	require.NoError(t, f.gate.AuthorizeAccount(f.ctx, f.scenes[0].Account))
	// Настоящий installer получает GLOBAL до plan advisory. Observer удерживает
	// только существующий плановый замок: source rows/grants не подделываются.
	held := resourcePublicHold(t, f.r, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.registration_account_writer_plan',0))`)
	revoke := resourcePublicStart(t, f.r.ctx, func(ctx context.Context) error {
		return seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(f.r.admin), f.roster, f.writerPlan(false))
	})
	installerPID := resourcePublicWaitBlocked(t, f.r, held.Conn().PgConn().PID(), "", "registration_account_writer_plan")
	call := resourcePublicStart(t, f.ctx, func(ctx context.Context) error {
		return f.uc.Register(ctx, f.request(0, "public-revoked-after-wait", time.Now().UTC()))
	})
	resourcePublicWaitBlocked(t, f.r, installerPID, f.r.role, "authority_resource_enter_v2")
	require.NoError(t, held.Rollback(f.r.ctx))
	require.NoError(t, resourcePublicAwait(t, revoke))
	require.Equal(t, codes.PermissionDenied, status.Code(resourcePublicAwait(t, call)))
	authorityWaitReleased(t, f.r.runtime)
	require.Equal(t, codes.PermissionDenied, status.Code(f.gate.AuthorizeAccount(f.ctx, f.scenes[0].Account)))
	require.NoError(t, f.gate.AuthorizeAccount(f.ctx, f.scenes[1].Account))
	// Denial audit допустим; ни один artifact отвергнутого объекта не допустим.
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "resource_registration_scope", "resource_registration_pointer", "producer_source_receipt", "relation_fact", "fga_outbox", "resource_reconcile_outbox", "access_binding_target_members", "access_binding_emitted_tuples"} {
		var partial int
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, "SELECT count(*) FROM kaname."+table+" t WHERE position($1 in to_jsonb(t)::text)>0", "public-revoked-after-wait").Scan(&partial))
		require.Zero(t, partial, "no partial rejected-object artifact in %s", table)
	}
	f.native(t, 0, "public-revoked-after-wait", false)
	require.NoError(t, f.uc.Register(f.ctx, f.request(1, "public-surviving-B", time.Now().UTC())))
	f.native(t, 1, "public-surviving-B", true)
	authorityWaitReleased(t, f.r.runtime)
}
