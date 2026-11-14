// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FB26–28: два последовательных порядка, шесть независимых миров PostgreSQL.
// Декораторы ниже сохраняют настоящие фабрики, набор семантики, проверку,
// обратные вызовы и транзакцию. Останавливается лишь этап перед решением/фиксацией.
type fbRaceWorld struct {
	*fbRemainingWorld
	writers *kanamepg.GrantPolicyWriters
}

// Диагностика сохраняет прежний трассировщик и не меняет запросы или контекст API.
// Аргументы SQL и параметры соединения не сохраняются и не печатаются.
type fbRaceSQLTrace struct {
	t     *testing.T
	prior pgx.QueryTracer
}
type fbRaceSQLTraceKey struct{}

func fbRaceDiagnosticText(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// Ошибки соединения могут содержать адреса и параметры: печатаем только тип.
// Для PostgreSQL разрешены лишь ограниченные поля самого серверного отказа.
func fbRaceFactoryFailure(t *testing.T, factory string, err error) {
	t.Helper()
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		t.Logf("FB26–28 %s failure: type=%T code=%q constraint=%q message=%q", factory, err, fbRaceDiagnosticText(pe.Code), fbRaceDiagnosticText(pe.ConstraintName), fbRaceDiagnosticText(pe.Message))
		return
	}
	t.Logf("FB26–28 %s failure: type=%T", factory, err)
}
func (d *fbRaceSQLTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if d.prior != nil {
		ctx = d.prior.TraceQueryStart(ctx, conn, data)
	}
	return context.WithValue(ctx, fbRaceSQLTraceKey{}, fbRaceDiagnosticText(data.SQL))
}
func (d *fbRaceSQLTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if d.prior != nil {
		d.prior.TraceQueryEnd(ctx, conn, data)
	}
	if data.Err == nil {
		return
	}
	sql, _ := ctx.Value(fbRaceSQLTraceKey{}).(string)
	var pe *pgconn.PgError
	if errors.As(data.Err, &pe) {
		d.t.Logf("FB26–28 PostgreSQL failure: pid=%d code=%q constraint=%q message=%q sql=%q", conn.PgConn().PID(), pe.Code, fbRaceDiagnosticText(pe.ConstraintName), fbRaceDiagnosticText(pe.Message), sql)
	}
}

func newFBRaceWorld(t *testing.T) *fbRaceWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	canonical, err := os.ReadFile("../../../../manifest/testdata/probemod.children-fixture.yaml")
	require.NoError(t, err)
	// Буквальный канонический манифест: без подмены модели и SQL-посева ролей/зеркал.
	doc := canonical
	delivered, err := manifest.Load(doc)
	require.NoError(t, err)
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{delivered})
	require.NoError(t, err)
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
	// Собираем отдельный мир сразу на этих планах. newSCWorld/newATCWorld здесь
	// не вызываются: чужие посевы зеркал и подмена модели процесса не требуются.
	repo := kanamepg.New(pool, nil)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(pool, plans), personmarks.New(pool))
	sc := &scWorld{t: t, ctx: ctx, pool: pool, repo: repo, ops: operations.NewRepo(pool, "kaname"), door: door}
	a := &atcWorld{pcrWorld: &pcrWorld{scWorld: sc}, doc: doc}
	sc.usrA = mustSeedUser(t, ctx, pool, "fbrace-owner")
	sc.accA = seedAccountByOwner(t, ctx, pool, "fbrace-account", sc.usrA)
	a.usrD = mustSeedUser(t, ctx, pool, "fbrace-actor")
	a.usrE = mustSeedUser(t, ctx, pool, "fbrace-recipient")
	sc.usrB = mustSeedUser(t, ctx, pool, "fbrace-actor-b")
	sc.usrC = mustSeedUser(t, ctx, pool, "fbrace-recipient-u")
	gdSeedMembership(t, ctx, pool, sc.usrB, sc.accA, "ACTIVE")
	gdSeedMembership(t, ctx, pool, sc.usrC, sc.accA, "ACTIVE")
	verifyAddresses(t, ctx, pool)
	gdSeedMembership(t, ctx, pool, a.usrD, sc.accA, "ACTIVE")
	gdSeedMembership(t, ctx, pool, a.usrE, sc.accA, "ACTIVE")
	a.applyDelivered("FB26–28: literal children fixture и два источника", delivered)
	callbacks := &fb11SetupCallbacks{}
	observe := func(rec *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: rec, callbacks: callbacks}
	}
	bootstrap := accessbindingapp.NewCreateAccessBindingUseCase(repo, sc.ops, catalog.Fixed{F: a.facts}).WithRelationStore(door, slog.Default()).WithReconciler(observe(sc.rec))
	sc.ab = accessbindingapp.NewHandler(bootstrap, nil, nil, nil, nil, nil, nil)
	owner := domain.AccessBindingID(sc.createDone(asUser(ctx, sc.usrA), fbStructuredRequest(userSubject(sc.usrA), domain.RoleID(domain.OwnerRoleID), "account", string(sc.accA)), "FB26–28: actual owner auto-binding"))
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.accessBinding", string(owner)))
	// Project.Create фиксирует структурные указатели в той же транзакции; SQL-посева project→account нет.
	projects := projectapp.NewHandler(projectapp.NewCreateProjectUseCase(repo, sc.ops).WithRelationStore(door, slog.Default()).WithObjectReconciler(&fbStructuredObjects{Reconciler: sc.rec, callbacks: callbacks}), nil, nil, nil, nil)
	op, err := projects.Create(asUser(ctx, sc.usrA), &iamv1.CreateProjectRequest{AccountId: string(sc.accA), Name: "fbrace-project"})
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
	source := catalog.Fixed{F: w.facts}
	authority := registrationwriterfixture.Authority{Module: "probemod"}
	// Проверка изолирует только настройку регистрации. Исходных прав выдачи она не даёт.
	w.reg = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(authority).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(w.rec, slog.Default())
	w.registration = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, authority)
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&w.version))
	w.register("project:"+string(w.prjA), "project", atcBoxType, "probemod.boxes", atcB1, []string{"project:" + string(w.prjA), "account:" + string(w.accA)})
	op, err = projects.Create(asUser(ctx, sc.usrA), &iamv1.CreateProjectRequest{AccountId: string(sc.accA), Name: "fbrace-project-q"})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, ctx, sc.ops, op.GetId()).Error)
	var qmd iamv1.CreateProjectMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&qmd))
	a.prjB = domain.ProjectID(qmd.GetProjectId())
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.project", string(a.prjB)))
	response, err := w.registration.RegisterResource(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(a.prjB), Relation: "project", Object: atcBoxType + ":" + fbRoleBoxQ,
		ParentProjectId: string(a.prjB), ParentAccountId: string(sc.accA),
		ParentChain: []string{"project:" + string(a.prjB), "account:" + string(sc.accA)}, SourceVersion: timestamppb.New(w.version.Add(time.Microsecond)),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.NoError(t, w.rec.ReconcileBinding(ctx, owner))
	// Те же настоящие фабрики, что при запуске полного контракта выдачи; каждый потребитель
	// получает локальные подготовленные планы либо набор семантики этой единственной композиции.
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(ctx, composed, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	require.NoError(t, repo.PrepareAuthorityBundle(ctx, bundle))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	source = catalog.Fixed{F: facts}
	login := "fbrace_runtime_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
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
	runtimeConfig.ConnConfig.Tracer = &fbRaceSQLTrace{t: t, prior: runtimeConfig.ConnConfig.Tracer}
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
	remaining := &fbRemainingWorld{fbStructuredWorld: w.fbStructuredWorld}
	objectsObserved := &fbRoleObjects{Reconciler: rec, callbacks: callbacks}
	remaining.groups = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(runtimeRepo, runtimeOps).WithRelationStore(runtimeDoor, slog.Default()).WithLifecycleWriter(groups).WithObjectReconciler(objectsObserved),
		nil, nil, nil, nil,
		groupapp.NewAddMemberUseCase(runtimeRepo, runtimeOps).WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(runtimeRepo, runtimeDoor)).WithMembershipWriter(groups).WithGroupAdditionAuthorityWriter(writers), nil, nil)
	out := &fbRaceWorld{fbRemainingWorld: remaining, writers: writers}
	out.premises()
	return out
}

// premises отделяет личность, принадлежность и регистрацию от полномочий.
func (w *fbRaceWorld) premises() {
	t := w.t
	for _, user := range []domain.UserID{w.usrB, w.usrC, w.usrD, w.usrE} {
		var exists, member bool
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.users WHERE id=$1),EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='ACTIVE')`, user, w.accA).Scan(&exists, &member))
		require.True(t, exists)
		require.True(t, member)
		w.noScopeAdmin("user:" + string(user))
		w.native("user:"+string(user), "admin", "project", string(w.prjB), relverdict.Deny)
	}
	for _, object := range []struct {
		id      string
		project domain.ProjectID
	}{{atcB1, w.prjA}, {fbRoleBoxQ, w.prjB}} {
		var account, project string
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT m.parent_account_id,m.parent_project_id FROM kaname.resource_mirror m JOIN kaname.projects p ON p.id=m.parent_project_id AND p.account_id=m.parent_account_id WHERE m.object_type='probemod.boxes' AND m.object_id=$1`, object.id).Scan(&account, &project))
		require.Equal(t, string(w.accA), account)
		require.Equal(t, string(object.project), project)
		var edge bool
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation='project' AND subject=$3)`, atcBoxType, object.id, "project:"+project).Scan(&edge))
		require.True(t, edge)
		for _, user := range []domain.UserID{w.usrB, w.usrC, w.usrD, w.usrE} {
			for _, relation := range []string{"v_get", "v_update"} {
				w.native("user:"+string(user), relation, atcBoxType, object.id, relverdict.Deny)
			}
		}
	}
}

// У барьеров собственный ограниченный срок. Ожидание по таймеру не доказывает блокировку.
type fbRaceGate struct {
	reached     chan struct{}
	released    chan struct{}
	seen        sync.Once
	releaseOnce sync.Once
	life        context.Context
}

func (g *fbRaceGate) hold(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.seen.Do(func() { close(g.reached) })
	select {
	case <-g.released:
		return ctx.Err()
	case <-g.life.Done():
		return g.life.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (g *fbRaceGate) release() {
	if g != nil {
		g.releaseOnce.Do(func() { close(g.released) })
	}
}
func (g *fbRaceGate) await(t *testing.T) {
	t.Helper()
	select {
	case <-g.reached:
	case <-g.life.Done():
		t.Fatalf("writer did not reach the actual decision/commit barrier: %v", g.life.Err())
	}
}

type fbRaceRun struct {
	done               chan struct{}
	operation, binding string
	apiErr, waitErr    error
	terminal           *operations.Operation
	callback           <-chan error
	callbackObserved   bool
}
type fbRaceHarness struct {
	w      *fbRaceWorld
	ctx    context.Context
	cancel context.CancelFunc
	gates  []*fbRaceGate
	runs   []*fbRaceRun
}

func newFBRaceHarness(w *fbRaceWorld) *fbRaceHarness {
	ctx, cancel := context.WithTimeout(w.ctx, 55*time.Second)
	h := &fbRaceHarness{w: w, ctx: ctx, cancel: cancel}
	w.t.Cleanup(func() {
		for _, g := range h.gates {
			g.release()
		}
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		for _, r := range h.runs {
			select {
			case <-r.done:
			case <-cleanup.Done():
				w.t.Errorf("concurrent API/worker did not join: %v", cleanup.Err())
				return
			}
			if r.operation != "" && r.terminal == nil {
				var err error
				r.terminal, err = fbRaceAwaitOperation(cleanup, w.ops, r.operation)
				if err != nil {
					w.t.Errorf("Operation worker cleanup failed: %v", err)
					continue
				}
			}
			if r.terminal != nil && r.terminal.Error == nil && r.callback != nil && !r.callbackObserved {
				select {
				case err := <-r.callback:
					r.callbackObserved = true
					if err != nil {
						w.t.Errorf("post-commit callback cleanup failed: %v", err)
					}
				case <-cleanup.Done():
					w.t.Errorf("post-commit callback did not join: %v", cleanup.Err())
				}
			}
		}
	})
	return h
}
func (h *fbRaceHarness) gate() *fbRaceGate {
	g := &fbRaceGate{reached: make(chan struct{}), released: make(chan struct{}), life: h.ctx}
	h.gates = append(h.gates, g)
	return g
}
func fbRaceAwaitOperation(ctx context.Context, ops operations.Repo, id string) (*operations.Operation, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := ops.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if op.Done {
			return op, nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
func (h *fbRaceHarness) run(fn func(context.Context) (string, string, error), callback ...string) *fbRaceRun {
	r := &fbRaceRun{done: make(chan struct{})}
	h.runs = append(h.runs, r)
	go func() {
		defer close(r.done)
		r.operation, r.binding, r.apiErr = fn(h.ctx)
		if r.binding != "" {
			r.callback = h.w.callbacks.completion("iam.accessBinding", r.binding)
		}
		if len(callback) == 2 {
			r.callback = h.w.callbacks.completion(callback[0], callback[1])
		}
		if r.operation != "" {
			r.terminal, r.waitErr = fbRaceAwaitOperation(h.ctx, h.w.ops, r.operation)
		}
		if r.waitErr == nil && r.terminal != nil && r.terminal.Error == nil && r.callback != nil {
			select {
			case r.waitErr = <-r.callback:
				r.callbackObserved = true
			case <-h.ctx.Done():
				r.waitErr = h.ctx.Err()
			}
		}
	}()
	return r
}
func (h *fbRaceHarness) result(r *fbRaceRun, want codes.Code, message string) {
	h.w.t.Helper()
	select {
	case <-r.done:
	case <-h.ctx.Done():
		h.w.t.Fatalf("concurrent result timeout: %v", h.ctx.Err())
	}
	require.NoError(h.w.t, r.apiErr, "ordinary/sync admission must pass")
	require.NotEmpty(h.w.t, r.operation)
	require.NoError(h.w.t, r.waitErr)
	require.NotNil(h.w.t, r.terminal)
	require.True(h.w.t, r.terminal.Done)
	if want == codes.OK {
		require.Nil(h.w.t, r.terminal.Error)
	} else {
		require.NotNil(h.w.t, r.terminal.Error)
		require.Equal(h.w.t, int32(want), r.terminal.Error.Code, "terminal message: %s", fbRaceDiagnosticText(r.terminal.Error.Message))
		require.Equal(h.w.t, message, r.terminal.Error.Message)
	}
}

// На достигнутом барьере после записи ровно одна транзакция прикладного LOGIN имеет XID.
// Устаревший читатель и фоновые обратные вызовы настройки не могут выдать себя за неё.
func (h *fbRaceHarness) writerPID(g *fbRaceGate) int {
	g.await(h.w.t)
	rows, err := h.w.observer.Query(h.ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND state='idle in transaction' AND backend_xid IS NOT NULL`, h.w.pool.Config().ConnConfig.User)
	require.NoError(h.w.t, err)
	pids, err := pgx.CollectRows(rows, pgx.RowTo[int])
	require.NoError(h.w.t, err)
	require.Len(h.w.t, pids, 1)
	return pids[0]
}
func (h *fbRaceHarness) lockWait(pid int) {
	h.w.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := h.w.observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, h.w.pool.Config().ConnConfig.User, pid).Scan(&blocked)
		require.NoError(h.w.t, err)
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			h.w.t.Fatalf("no actual competing writer lock wait for PID %d: %v", pid, ctx.Err())
		}
	}
}

// Каждая обёртка задаёт только срок/отмену, сохраняя все значения субъекта
// из настоящего контекста API/Operation. Проверка прав не подменяется.
func fbRaceContext(ctx, life context.Context) (context.Context, func()) {
	bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
	stop := context.AfterFunc(life, cancel)
	return bounded, func() { stop(); cancel() }
}

type fbRaceBindings struct {
	kaname.BindingDecisionRunner
	life          context.Context
	calls         atomic.Int32
	before, after *fbRaceGate
}

func (d *fbRaceBindings) RunBindingDecision(ctx context.Context, actor domain.Subject, b domain.AccessBinding, create bool, tuples func(domain.AccessBinding, domain.Role) []repoab.RelationTuple, apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	ctx, stop := fbRaceContext(ctx, d.life)
	defer stop()
	worker := d.calls.Add(1) == 2
	if worker {
		if err := d.before.hold(ctx); err != nil {
			return err
		}
	}
	return d.BindingDecisionRunner.RunBindingDecision(ctx, actor, b, create, tuples, func(ctx context.Context, w kaname.SemanticAuthorityWriter, b domain.AccessBinding, r domain.Role) error {
		if err := apply(ctx, w, b, r); err != nil {
			return err
		}
		if worker {
			return d.after.hold(ctx)
		}
		return nil
	})
}

type fbRaceWriter struct {
	kaname.SemanticAuthorityWriter
	gate *fbRaceGate
	stop func()
}

// Передаём все дополнительные порты полномочий, используемые grantpolicy/grantsource.
// Один SemanticAuthorityWriter потерял бы проверку происхождения и общий бюджет.
func (w *fbRaceWriter) AdmitSourceActor(ctx context.Context, a domain.Subject) (kaname.SourceReadCost, error) {
	p, ok := w.SemanticAuthorityWriter.(kaname.SemanticSourceReader)
	if !ok {
		return kaname.SourceReadCost{}, fmt.Errorf("actual writer lacks SemanticSourceReader")
	}
	return p.AdmitSourceActor(ctx, a)
}
func (w *fbRaceWriter) ProducerSources(ctx context.Context, f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
	p, ok := w.SemanticAuthorityWriter.(kaname.SemanticSourceReader)
	if !ok {
		return kaname.ProducerSourcePage{}, "", fmt.Errorf("actual writer lacks SemanticSourceReader")
	}
	return p.ProducerSources(ctx, f)
}
func (w *fbRaceWriter) RoleProjectionCheckpoint(ctx context.Context, id domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	p, ok := w.SemanticAuthorityWriter.(kaname.SemanticSourceReader)
	if !ok {
		return granteffect.ProjectionCheckpoint{}, kaname.SourceReadCost{}, fmt.Errorf("actual writer lacks SemanticSourceReader")
	}
	return p.RoleProjectionCheckpoint(ctx, id)
}
func (w *fbRaceWriter) ChargeSourceRead(cost kaname.SourceReadCost) error {
	p, ok := w.SemanticAuthorityWriter.(interface {
		ChargeSourceRead(kaname.SourceReadCost) error
	})
	if !ok {
		return fmt.Errorf("actual writer lacks shared SourceReadCost counter")
	}
	return p.ChargeSourceRead(cost)
}
func (w *fbRaceWriter) CapturedProducerPopulation(ctx context.Context, a domain.Subject) (kaname.CapturedProducerPopulation, error) {
	p, ok := w.SemanticAuthorityWriter.(kaname.CapturedProducerPopulationReader)
	if !ok {
		return nil, fmt.Errorf("actual writer lacks CapturedProducerPopulationReader")
	}
	population, err := p.CapturedProducerPopulation(ctx, a)
	if err != nil {
		return nil, err
	}
	// Этот мир намеренно использует штатную полную перепись производителей. Новый
	// протокол захваченной популяции требует новой фикстуры, а не посредника,
	// подменяющего личность писателя в подтверждении.
	if population != nil {
		return nil, fmt.Errorf("race fixture requires default complete producer census")
	}
	return population, nil
}
func (w *fbRaceWriter) Commit(ctx context.Context) error {
	if err := w.gate.hold(ctx); err != nil {
		return err
	}
	return w.SemanticAuthorityWriter.Commit(ctx)
}
func (w *fbRaceWriter) Rollback(ctx context.Context) error {
	defer w.stop()
	return w.SemanticAuthorityWriter.Rollback(ctx)
}
func (w *fbRaceWriter) PromoteRoleCapabilities(ctx context.Context, id domain.RoleID) error {
	p, ok := w.SemanticAuthorityWriter.(kaname.RoleCapabilityPromoter)
	if !ok {
		return fmt.Errorf("actual writer lacks RoleCapabilityPromoter")
	}
	return p.PromoteRoleCapabilities(ctx, id)
}
func (w *fbRaceWriter) ApplyPreparedRoleTuples(ctx context.Context, id domain.RoleID) error {
	p, ok := w.SemanticAuthorityWriter.(kaname.PreparedRoleTupleWriter)
	if !ok {
		return fmt.Errorf("actual writer lacks PreparedRoleTupleWriter")
	}
	return p.ApplyPreparedRoleTuples(ctx, id)
}

type fbRaceFactories struct {
	*kanamepg.GrantPolicyWriters
	t    *testing.T
	life context.Context
	gate *fbRaceGate
}

func (f *fbRaceFactories) RoleMutationWriter(ctx context.Context, in kaname.RoleMutationRequest, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	ctx, stop := fbRaceContext(ctx, f.life)
	w, err := f.GrantPolicyWriters.RoleMutationWriter(ctx, in, a)
	if err != nil {
		fbRaceFactoryFailure(f.t, "RoleMutationWriter", err)
		stop()
		return nil, err
	}
	return &fbRaceWriter{SemanticAuthorityWriter: w, gate: f.gate, stop: stop}, nil
}
func (f *fbRaceFactories) GroupAdditionAuthorityWriter(ctx context.Context, in domain.GroupMember, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	ctx, stop := fbRaceContext(ctx, f.life)
	w, err := f.GrantPolicyWriters.GroupAdditionAuthorityWriter(ctx, in, a)
	if err != nil {
		fbRaceFactoryFailure(f.t, "GroupAdditionAuthorityWriter", err)
		stop()
		return nil, err
	}
	return &fbRaceWriter{SemanticAuthorityWriter: w, gate: f.gate, stop: stop}, nil
}

type fbRaceWithdrawal struct {
	kaname.BindingWithdrawalRunner
	life context.Context
	gate *fbRaceGate
}

func (d *fbRaceWithdrawal) WithdrawBinding(ctx context.Context, id domain.AccessBindingID, kind kaname.BindingWithdrawalKind, actor string, before func(context.Context, kaname.Writer, clients.RelationStore, domain.AccessBinding) error, after func(context.Context, kaname.Writer, domain.AccessBinding) error) (domain.AccessBinding, error) {
	ctx, stop := fbRaceContext(ctx, d.life)
	defer stop()
	return d.BindingWithdrawalRunner.WithdrawBinding(ctx, id, kind, actor, before, func(ctx context.Context, w kaname.Writer, b domain.AccessBinding) error {
		if err := after(ctx, w, b); err != nil {
			return err
		}
		return d.gate.hold(ctx)
	})
}

// Два основных писателя сохраняют настоящую гонку на commit. Последующие
// проходы materialization ждут ДО своей транзакции, чтобы не стать третьим
// и четвёртым писателями этой пары. После решения соперника оба проходят
// через настоящий reconciler; harness ждёт их окончания до проверок доступа.
type fbRacePostCommitReconciler struct {
	accessbindingapp.SelectorReconciler
	gate *fbRaceGate
}

func (r *fbRacePostCommitReconciler) ReconcileBindingForward(ctx context.Context, id domain.AccessBindingID) error {
	if err := r.gate.hold(ctx); err != nil {
		return err
	}
	return r.SelectorReconciler.ReconcileBindingForward(ctx, id)
}
func (r *fbRacePostCommitReconciler) ReconcileObjectForwardNoStale(ctx context.Context, typ, id string) error {
	if err := r.gate.hold(ctx); err != nil {
		return err
	}
	return r.SelectorReconciler.ReconcileObjectForwardNoStale(ctx, typ, id)
}

func (w *fbRaceWorld) createHandler(runner kaname.BindingDecisionRunner, callbackGate *fbRaceGate) *accessbindingapp.Handler {
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, catalog.Fixed{F: w.facts}).WithRelationStore(w.door, slog.Default()).WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool)).WithBindingDecisions(runner).WithReconciler(&fb11SetupReconciler{SelectorReconciler: &fbRacePostCommitReconciler{SelectorReconciler: w.rec, gate: callbackGate}, callbacks: w.callbacks})
	return accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
}
func (h *fbRaceHarness) create(handler *accessbindingapp.Handler, actor domain.UserID, req *iamv1.CreateAccessBindingRequest) *fbRaceRun {
	return h.run(func(ctx context.Context) (string, string, error) {
		op, err := handler.Create(asUser(ctx, actor), req)
		if err != nil {
			return "", "", err
		}
		if op == nil {
			return "", "", fmt.Errorf("nil Create operation")
		}
		var md iamv1.CreateAccessBindingMetadata
		if err := op.GetMetadata().UnmarshalTo(&md); err != nil {
			return op.GetId(), "", err
		}
		return op.GetId(), md.GetAccessBindingId(), nil
	})
}
func (h *fbRaceHarness) revoke(id domain.AccessBindingID, gate *fbRaceGate) *fbRaceRun {
	uc := accessbindingapp.NewRevokeAccessBindingUseCase(h.w.repo, h.w.ops).WithRelationStore(h.w.door, slog.Default()).WithBindingWithdrawal(&fbRaceWithdrawal{BindingWithdrawalRunner: h.w.stages, life: h.ctx, gate: gate})
	return h.run(func(ctx context.Context) (string, string, error) {
		op, err := uc.Execute(asUser(ctx, h.w.usrA), id)
		if err != nil {
			return "", "", err
		}
		if op == nil {
			return "", "", fmt.Errorf("nil Revoke operation")
		}
		return op.ID, "", nil
	})
}
func (h *fbRaceHarness) update(req *iamv1.UpdateRoleRequest, gate *fbRaceGate) *fbRaceRun {
	w := h.w
	uc := roleapp.NewUpdateRoleUseCase(w.repo, w.ops, catalog.Fixed{F: w.facts}).WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool)).WithGrantReferencePlans(w.plans).WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).WithMembershipFanout(&fbRoleFanout{RulesMembershipFanout: accessbindingapp.NewRoleMembershipFanout(w.repo, w.rec), callbacks: w.callbacks}).WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door)).WithObjectReconciler(&fbRoleObjects{Reconciler: w.rec, callbacks: w.callbacks}, slog.Default()).WithRoleAuthorityWriter(&fbRaceFactories{GrantPolicyWriters: w.writers, t: w.t, life: h.ctx, gate: gate})
	handler := roleapp.NewHandler(nil, uc, nil, nil, nil)
	return h.run(func(ctx context.Context) (string, string, error) {
		op, err := handler.Update(asUser(ctx, w.usrD), req)
		if err != nil {
			return "", "", err
		}
		if op == nil {
			return "", "", fmt.Errorf("nil Update operation")
		}
		return op.GetId(), "", nil
	}, "fb.role.rules", req.GetRoleId())
}
func (h *fbRaceHarness) addMember(req *iamv1.AddGroupMemberRequest, gate *fbRaceGate) *fbRaceRun {
	w := h.w
	uc := groupapp.NewAddMemberUseCase(w.repo, w.ops).WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door)).WithGroupAdditionAuthorityWriter(&fbRaceFactories{GrantPolicyWriters: w.writers, t: w.t, life: h.ctx, gate: gate})
	handler := groupapp.NewHandler(nil, nil, nil, nil, nil, uc, nil, nil)
	return h.run(func(ctx context.Context) (string, string, error) {
		op, err := handler.AddMember(asUser(ctx, w.usrD), req)
		if err != nil {
			return "", "", err
		}
		if op == nil {
			return "", "", fmt.Errorf("nil AddMember operation")
		}
		return op.GetId(), "", nil
	})
}

func (w *fbRaceWorld) bindingRows(id domain.AccessBindingID, req *iamv1.CreateAccessBindingRequest) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		c, stop := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer stop()
		_ = rd.Rollback(c)
	}()
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	subjects, err := rd.AccessBindings().ListSubjects(w.ctx, id)
	require.NoError(w.t, err)
	require.Equal(w.t, req.GetRoleId(), string(b.RoleID))
	require.Equal(w.t, req.GetScopeId(), b.ResourceID)
	require.Equal(w.t, strings.TrimPrefix(req.GetScopeType(), "iam."), string(b.ResourceType))
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.Nil(w.t, b.RevokedAt)
	typ := domain.SubjectTypeUser
	if req.Subjects[0].GetType() == iamv1.SubjectType_SUBJECT_TYPE_GROUP {
		typ = domain.SubjectTypeGroup
	}
	require.Equal(w.t, []domain.Subject{{Type: typ, ID: domain.SubjectID(req.Subjects[0].GetId())}}, subjects)
	target := domain.AccessTarget{AllInScope: req.GetTarget().GetAllInScope() != nil}
	for _, ref := range req.GetTarget().GetResources().GetResources() {
		target.Resources = append(target.Resources, domain.ResourceRef{Type: ref.GetType(), ID: ref.GetId()})
	}
	require.Equal(w.t, target, b.Target)
}
func (w *fbRaceWorld) grantRace(req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrA), req, "FB26–28: actual setup binding"))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, id))
	w.bindingRows(id, req)
	return id
}
func (w *fbRaceWorld) absentBinding(id string) {
	w.t.Helper()
	require.NotEmpty(w.t, id)
	for _, table := range []string{"access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples"} {
		column := "binding_id"
		if table == "access_bindings" {
			column = "id"
		}
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx, "SELECT count(*) FROM kaname."+table+" WHERE "+column+"=$1", id).Scan(&n))
		require.Zero(w.t, n, table)
	}
}
func (w *fbRaceWorld) members(g domain.GroupID, users ...domain.UserID) {
	rows, err := w.pool.Query(w.ctx, `SELECT member_type||':'||member_id FROM kaname.group_members WHERE group_id=$1`, g)
	require.NoError(w.t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(w.t, err)
	want := make([]string, 0, len(users))
	for _, id := range users {
		want = append(want, "user:"+string(id))
	}
	require.ElementsMatch(w.t, want, got)
	for _, id := range []domain.UserID{w.usrC, w.usrE} {
		v := relverdict.Deny
		for _, present := range users {
			if id == present {
				v = relverdict.Allow
			}
		}
		w.native("user:"+string(id), "member", "group", string(g), v)
	}
}

func TestFullBind_FB26_GrantAndSourceRevokeSerialize(t *testing.T) {
	for _, order := range []string{"grant_commits_first", "revoke_commits_first"} {
		t.Run(order, func(t *testing.T) {
			w := newFBRaceWorld(t)
			role := w.role("fb26_proposed", fullBindBoxRule("get"))
			sourceRole := w.role("fb26_source", fullBindBoxRule("get"))
			w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
			source := w.grantRace(fbStructuredRequest(userSubject(w.usrD), sourceRole, "project", string(w.prjA)))
			actor, recipient := "user:"+string(w.usrD), "user:"+string(w.usrE)
			w.noScopeAdmin(actor)
			w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
			w.capability(actor, role, "project", string(w.prjA), relverdict.Deny)
			w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Deny)
			require.NoError(t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
			w.native("user:"+string(w.usrA), accessbindingapp.RemovalRelation, accessbindingapp.RemovalObjectType, string(source), relverdict.Allow)
			// Ранее зафиксированная обычная выдача переживает отзыв в ОБОИХ порядках.
			oldReq := fbStructuredRequest(userSubject(w.usrC), role, "project", string(w.prjA))
			old := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrD), oldReq, "FB26: existing ordinary grant"))
			require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(old)))
			w.bindingRows(old, oldReq)
			w.native("user:"+string(w.usrC), "v_get", atcBoxType, atcB1, relverdict.Allow)
			req := fbStructuredRequest(userSubject(w.usrE), role, "project", string(w.prjA))
			fixed := proto.Clone(req)
			beforeOperations := w.operationCount()
			h := newFBRaceHarness(w)
			winner := h.gate()
			runner := &fbRaceBindings{BindingDecisionRunner: w.writers, life: h.ctx}
			var grant, revoke *fbRaceRun
			var callbackGate *fbRaceGate
			// Настоящий закреплённый RR-читатель сохраняет устаревший Allow после отзыва. Ни одна
			// фабрика его не получает: окончательное решение принимает собственный писатель.
			stale, err := w.pool.BeginTx(h.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
			require.NoError(t, err)
			t.Cleanup(func() {
				c, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = stale.Rollback(c)
			})
			staleAsk := func() {
				got, _, err := relverdict.Ask(h.ctx, stale, relverdict.Query{PreparedPlans: w.plans, Subject: actor, Relation: "v_get", ObjectType: atcBoxType, ObjectID: atcB1})
				require.NoError(t, err)
				require.Equal(t, relverdict.Allow, got)
			}
			staleAsk()
			if order == "grant_commits_first" {
				runner.after = winner
				callbackGate = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrD, req)
				pid := h.writerPID(winner)
				revoke = h.revoke(source, nil)
				h.lockWait(pid)
				winner.release()
			} else {
				runner.before = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrD, req)
				runner.before.await(t) // Синхронное решение разрешило запрос; писатель ещё не принял решение.
				revoke = h.revoke(source, winner)
				pid := h.writerPID(winner)
				runner.before.release()
				h.lockWait(pid)
				winner.release()
			}
			if callbackGate != nil {
				callbackGate.await(t)
			}
			h.result(revoke, codes.OK, "")
			callbackGate.release()
			if order == "grant_commits_first" {
				h.result(grant, codes.OK, "")
				w.bindingRows(domain.AccessBindingID(grant.binding), req)
				w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Allow)
			} else {
				h.result(grant, codes.PermissionDenied, "permission denied")
				w.absentBinding(grant.binding)
				w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Deny)
			}
			var state string
			var revoked bool
			require.NoError(t, w.pool.QueryRow(h.ctx, `SELECT status,revoked_at IS NOT NULL FROM kaname.access_bindings WHERE id=$1`, source).Scan(&state, &revoked))
			require.Equal(t, "REVOKED", state)
			require.True(t, revoked)
			staleAsk()
			w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Deny)
			w.bindingRows(old, oldReq)
			w.native("user:"+string(w.usrC), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
			require.True(t, proto.Equal(fixed, req))
			require.Equal(t, beforeOperations+2, w.operationCount())
		})
	}
}

func TestFullBind_FB27_RoleExpansionAndNewScopeBindingSerialize(t *testing.T) {
	for _, order := range []string{"binding_commits_first", "update_commits_first"} {
		t.Run(order, func(t *testing.T) {
			w := newFBRaceWorld(t)
			role := w.role("fb27_role", fullBindBoxRule("get"))
			sourceU := w.role("fb27_update_coverage", fullBindBoxRule("get", "update"))
			sourceB := w.role("fb27_bind_coverage", fullBindBoxRule("get"))
			method := w.role("fb27_update_method", &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"update"}, ResourceNames: []string{string(role)}})
			w.grantRace(fbStructuredRequest(userSubject(w.usrD), sourceU, "project", string(w.prjA)))
			w.grantRace(fbStructuredRequest(userSubject(w.usrD), method, "account", string(w.accA)))
			w.grantRace(fbStructuredRequest(userSubject(w.usrB), sourceB, "project", string(w.prjB)))
			w.createCapability(userSubject(w.usrB), "project", string(w.prjB))
			existingReq := fbStructuredRequest(userSubject(w.usrC), role, "project", string(w.prjA))
			existing := w.grantRace(existingReq)
			u, b := "user:"+string(w.usrD), "user:"+string(w.usrB)
			w.native(u, "v_update", "iam_role", string(role), relverdict.Allow)
			w.native(u, "admin", "iam_role", string(role), relverdict.Deny)
			for _, actor := range []string{u, b} {
				w.noScopeAdmin(actor)
				w.native(actor, "admin", "project", string(w.prjB), relverdict.Deny)
				w.capability(actor, role, "project", string(w.prjA), relverdict.Deny)
				w.capability(actor, role, "project", string(w.prjB), relverdict.Deny)
			}
			w.capability(b, "", "project", string(w.prjB), relverdict.Allow)
			for _, relation := range []string{"v_get", "v_update"} {
				w.native(u, relation, atcBoxType, atcB1, relverdict.Allow)
				w.native(u, relation, atcBoxType, fbRoleBoxQ, relverdict.Deny)
			}
			w.native(b, "v_get", atcBoxType, fbRoleBoxQ, relverdict.Allow)
			w.native(b, "v_update", atcBoxType, fbRoleBoxQ, relverdict.Deny)
			w.native("user:"+string(w.usrC), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native("user:"+string(w.usrC), "v_update", atcBoxType, atcB1, relverdict.Deny)
			w.native("user:"+string(w.usrE), "v_get", atcBoxType, fbRoleBoxQ, relverdict.Deny)
			// До обоих конкурентных API предложенная роль имеет ровно одну выдачу в P.
			var scopes []string
			rows, err := w.pool.Query(w.ctx, `SELECT resource_id FROM kaname.access_bindings WHERE role_id=$1 AND status='ACTIVE'`, role)
			require.NoError(t, err)
			scopes, err = pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			require.Equal(t, []string{string(w.prjA)}, scopes)
			createReq := fbStructuredRequest(userSubject(w.usrE), role, "project", string(w.prjB))
			updateReq := fbRoleRulesUpdate(role, "get", "update")
			fixedCreate, fixedUpdate := proto.Clone(createReq), proto.Clone(updateReq)
			beforeOperations := w.operationCount()
			h := newFBRaceHarness(w)
			winner := h.gate()
			runner := &fbRaceBindings{BindingDecisionRunner: w.writers, life: h.ctx}
			var grant, update *fbRaceRun
			var callbackGate *fbRaceGate
			if order == "binding_commits_first" {
				runner.after = winner
				callbackGate = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrB, createReq)
				pid := h.writerPID(winner)
				update = h.update(updateReq, nil)
				h.lockWait(pid)
				winner.release()
			} else {
				runner.before = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrB, createReq)
				runner.before.await(t)
				update = h.update(updateReq, winner)
				pid := h.writerPID(winner)
				runner.before.release()
				h.lockWait(pid)
				winner.release()
			}
			roleRows := &fbRoleMutationWorld{fullBindWorld: w.fullBindWorld, callbacks: w.callbacks}
			if order == "binding_commits_first" {
				callbackGate.await(t)
				h.result(update, codes.PermissionDenied, "Grant authority denied")
				callbackGate.release()
				h.result(grant, codes.OK, "")
				roleRows.assertRules(role, []*iamv1.Rule{fullBindBoxRule("get")})
				w.bindingRows(domain.AccessBindingID(grant.binding), createReq)
				w.native("user:"+string(w.usrE), "v_get", atcBoxType, fbRoleBoxQ, relverdict.Allow)
				w.native("user:"+string(w.usrC), "v_update", atcBoxType, atcB1, relverdict.Deny)
			} else {
				h.result(update, codes.OK, "")
				h.result(grant, codes.PermissionDenied, "permission denied")
				roleRows.assertRules(role, updateReq.Rules)
				w.absentBinding(grant.binding)
				w.native("user:"+string(w.usrE), "v_get", atcBoxType, fbRoleBoxQ, relverdict.Deny)
				w.native("user:"+string(w.usrC), "v_update", atcBoxType, atcB1, relverdict.Allow)
			}
			w.bindingRows(existing, existingReq)
			w.native("user:"+string(w.usrC), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native("user:"+string(w.usrE), "v_update", atcBoxType, fbRoleBoxQ, relverdict.Deny)
			w.native(u, "v_update", "iam_role", string(role), relverdict.Allow)
			require.True(t, proto.Equal(fixedCreate, createReq))
			require.True(t, proto.Equal(fixedUpdate, updateReq))
			require.Equal(t, beforeOperations+2, w.operationCount())
		})
	}
}

func TestFullBind_FB28_GroupAdditionAndBindingSerialize(t *testing.T) {
	for _, order := range []string{"binding_commits_first", "member_commits_first"} {
		t.Run(order, func(t *testing.T) {
			w := newFBRaceWorld(t)
			g := w.group("fb28-group")
			// U=usrC, V=usrE, A1=usrD, A2=usrB; у всех ACTIVE-членство в том же A.
			op, err := w.groups.AddMember(asUser(w.ctx, w.usrA), &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: "user", MemberId: string(w.usrC)})
			require.NoError(t, err)
			require.NotNil(t, op)
			require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
			w.members(g, w.usrC)
			x := w.role("fb28_x", fullBindBoxRule("get"))
			y := w.role("fb28_y", fullBindBoxRule("update"))
			capability := w.role("fb28_create", &iamv1.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}})
			for _, actor := range []domain.UserID{w.usrD, w.usrB} {
				w.grantRace(fbStructuredRequest(userSubject(actor), capability, "project", string(w.prjA)))
			}
			w.groupMethod(g)
			xSource := fbStructuredRequest(userSubject(w.usrD), x, "project", string(w.prjA))
			xSource.Target = resourcesTarget(rr("probemod.boxes", atcB1))
			w.grantRace(xSource)
			ySource := fbStructuredRequest(userSubject(w.usrB), y, "project", string(w.prjA))
			ySource.Target = resourcesTarget(rr("probemod.boxes", atcB1))
			w.grantRace(ySource)
			groupSubject := &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: string(g)}
			xReq := fbStructuredRequest(groupSubject, x, "project", string(w.prjA))
			xReq.Target = resourcesTarget(rr("probemod.boxes", atcB1))
			existing := w.grantRace(xReq)
			a1, a2 := "user:"+string(w.usrD), "user:"+string(w.usrB)
			for _, actor := range []string{a1, a2} {
				w.noScopeAdmin(actor)
				w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
				for _, role := range []domain.RoleID{x, y} {
					w.capability(actor, role, "project", string(w.prjA), relverdict.Deny)
				}
			}
			w.native(a1, "v_update", "iam_group", string(g), relverdict.Allow)
			w.native(a1, "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native(a1, "v_update", atcBoxType, atcB1, relverdict.Deny)
			w.native(a2, "v_update", atcBoxType, atcB1, relverdict.Allow)
			w.native("user:"+string(w.usrC), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB1, relverdict.Deny)
			for _, user := range []domain.UserID{w.usrC, w.usrE} {
				w.native("user:"+string(user), "v_update", atcBoxType, atcB1, relverdict.Deny)
			}
			createReq := fbStructuredRequest(groupSubject, y, "project", string(w.prjA))
			createReq.Target = resourcesTarget(rr("probemod.boxes", atcB1))
			addReq := &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: "user", MemberId: string(w.usrE)}
			fixedCreate, fixedAdd := proto.Clone(createReq), proto.Clone(addReq)
			beforeOperations := w.operationCount()
			h := newFBRaceHarness(w)
			winner := h.gate()
			runner := &fbRaceBindings{BindingDecisionRunner: w.writers, life: h.ctx}
			var grant, add *fbRaceRun
			var callbackGate *fbRaceGate
			if order == "binding_commits_first" {
				runner.after = winner
				callbackGate = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrB, createReq)
				pid := h.writerPID(winner)
				add = h.addMember(addReq, nil)
				h.lockWait(pid)
				winner.release()
			} else {
				runner.before = h.gate()
				grant = h.create(w.createHandler(runner, callbackGate), w.usrB, createReq)
				runner.before.await(t)
				add = h.addMember(addReq, winner)
				pid := h.writerPID(winner)
				runner.before.release()
				h.lockWait(pid)
				winner.release()
			}
			if order == "binding_commits_first" {
				callbackGate.await(t)
				h.result(add, codes.PermissionDenied, "Grant authority denied")
				callbackGate.release()
			}
			h.result(grant, codes.OK, "")
			w.bindingRows(domain.AccessBindingID(grant.binding), createReq)
			w.bindingRows(existing, xReq)
			w.native("user:"+string(w.usrC), "v_update", atcBoxType, atcB1, relverdict.Allow)
			if order == "binding_commits_first" {
				w.members(g, w.usrC)
				w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB1, relverdict.Deny)
				w.native("user:"+string(w.usrE), "v_update", atcBoxType, atcB1, relverdict.Deny)
			} else {
				// Это предусмотренный допустимый исход: A2 покрывает безусловное Y для
				// ОБОИХ текущих получателей. Новая политика получателя/создателя не вводится.
				h.result(add, codes.OK, "")
				w.members(g, w.usrC, w.usrE)
				w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB1, relverdict.Allow)
				w.native("user:"+string(w.usrE), "v_update", atcBoxType, atcB1, relverdict.Allow)
			}
			w.native(a1, "v_update", "iam_group", string(g), relverdict.Allow)
			require.True(t, proto.Equal(fixedCreate, createReq))
			require.True(t, proto.Equal(fixedAdd, addReq))
			require.Equal(t, beforeOperations+2, w.operationCount())
		})
	}
}

func (w *fbRaceWorld) operationCount() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&n))
	return n
}

var _ kaname.BindingDecisionRunner = (*fbRaceBindings)(nil)
var _ kaname.BindingWithdrawalRunner = (*fbRaceWithdrawal)(nil)
var _ kaname.RoleAuthorityWriterFactory = (*fbRaceFactories)(nil)
var _ kaname.RoleMutationWriterFactory = (*fbRaceFactories)(nil)
var _ kaname.GroupAdditionAuthorityWriterFactory = (*fbRaceFactories)(nil)
var _ kaname.SemanticSourceReader = (*fbRaceWriter)(nil)
var _ kaname.PreparedRoleTupleWriter = (*fbRaceWriter)(nil)
var _ kaname.RoleCapabilityPromoter = (*fbRaceWriter)(nil)
var _ kaname.CapturedProducerPopulationReader = (*fbRaceWriter)(nil)
