// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_class_s2_integration_test.go — стадия S2 приёмки «аноним и вошедший —
// системный класс субъекта» (kaname#829): кто и что выдаёт классу. Посев — П1.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// scClusterViewRole — системная роль чтения сетей (`vpc.network.view`), правила
// `[get, list]`; живость сверяется посевом.
const scClusterViewRole = "rolfe683216e63311d3f"

func allInScopeRequest(w *scWorld, class string) *iamv1.CreateAccessBindingRequest {
	req := withSubjects(w.sc01Request(), classSubject(class))
	req.Target = allInScopeTarget()
	return req
}

// requireTargetRefusal — INVALID_ARGUMENT с нарушением поля target и ДОСЛОВНЫМ
// текстом.
func requireTargetRefusal(t *testing.T, err error, text, why string) {
	t.Helper()
	requireSyncRefusal(t, err, codes.InvalidArgument, text, why)
	requireFieldViolation(t, err, "target", why)
}

// SC-19 — «вошедшим» вне кластера нельзя выдать всю область (проект и
// аккаунт); близнец — SC-01.
func TestSystemClass_SC19_AuthenticatedAllInScopeOutsideClusterIsRejected(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-19 близнец SC-01")

	const text = "Illegal argument target: a grant to system class authenticated outside the cluster names its objects (allInScope is not accepted)"
	_, err := w.ab.Create(asUser(w.ctx, w.usrA), allInScopeRequest(w, "authenticated"))
	requireTargetRefusal(t, err, text, "SC-19: проект")

	onAccount := allInScopeRequest(w, "authenticated")
	onAccount.ScopeType, onAccount.ScopeId = "iam.account", string(w.accA)
	_, err = w.ab.Create(asUser(w.ctx, w.usrA), onAccount)
	requireTargetRefusal(t, err, text, "SC-19: аккаунт")
}

// SC-20 — классу выдаёт тот, кто вправе выдать человеку: без права —
// PERMISSION_DENIED тем же текстом, что у выдачи человеку.
func TestSystemClass_SC20_OnlyAGrantorMayGrantToAClass(t *testing.T) {
	w := newSCWorld(t)
	userReq := w.sc01Request()
	userReq.Subjects = []*iamv1.Subject{userSubject(w.usrC)}
	_, userErr := w.ab.Create(asUser(w.ctx, w.usrB), userReq)
	require.Error(t, userErr, "SC-20 контроль: usr-B без права не выдаёт и человеку")
	require.Equal(t, codes.PermissionDenied, status.Code(userErr), "SC-20 контроль: код отказа человеку")
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-20 близнец SC-01")

	_, err := w.ab.Create(asUser(w.ctx, w.usrB), w.sc01Request())
	requireSyncRefusal(t, err, codes.PermissionDenied, status.Convert(userErr).Message(), "SC-20")
}

// SC-21 — классу не выдаётся роль с пишущим глаголом (оба класса).
func TestSystemClass_SC21_WriteRoleIsRejectedForAClass(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolEdit)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-21 близнец SC-01")

	text := "Role " + string(w.rolEdit) + " grants verbs beyond get and list; a system class subject accepts read-only roles"
	for _, class := range []string{"authenticated", "anonymous"} {
		req := withSubjects(w.sc01Request(), classSubject(class))
		req.RoleId = string(w.rolEdit)
		_, err := w.ab.Create(asUser(w.ctx, w.usrA), req)
		requireSyncRefusal(t, err, codes.FailedPrecondition, text, "SC-21: класс "+class)
	}
}

func (w *scWorld) roleUpdate() *roleapp.UpdateRoleUseCase {
	return roleapp.NewUpdateRoleUseCase(w.repo, w.ops, catalogfixture.Source()).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(w.repo, w.rec))
}

func writeRules() domain.Rules {
	return domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list", "update"}}}
}

// SC-22 — роль, выданная классу, не получает пишущего глагола правкой;
// близнец — та же правка роли, не выданной классу, принята. Гонка правки и
// выдачи — ровно одна сторона проходит.
func TestSystemClass_SC22_RoleBoundToAClassRefusesAWriteVerb(t *testing.T) {
	w := newSCWorld(t)
	upd := w.roleUpdate()
	op, err := upd.Execute(asUser(w.ctx, w.usrA), roleapp.UpdateRoleInput{
		ID: w.rolRead2, Rules: writeRules(), UpdateMask: []string{"rules"},
	})
	require.NoError(t, err, "SC-22 близнец: правка роли, не выданной классу")
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.ID).Error, "SC-22 близнец: done без error")

	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-22 Дано: SC-01")
	_, err = upd.Execute(asUser(w.ctx, w.usrA), roleapp.UpdateRoleInput{
		ID: w.rolRead, Rules: writeRules(), UpdateMask: []string{"rules"},
	})
	requireSyncRefusal(t, err, codes.FailedPrecondition,
		"Role "+string(w.rolRead)+" is bound to a system class subject; it accepts read verbs only", "SC-22")
}

// SC-22 гонка (DoD S2) — правка роли параллельно созданию выдачи классу:
// проходит ровно одна сторона, вторая получает отказ SC-21 или SC-22.
func TestSystemClass_SC22_RaceRoleUpdateVersusClassGrant(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	upd := w.roleUpdate()

	var (
		wg              sync.WaitGroup
		grantErr, upErr error
		grantOp, upOp   string
	)
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		op, err := w.ab.Create(asUser(w.ctx, w.usrA), w.sc01Request())
		grantErr = err
		if op != nil {
			grantOp = op.GetId()
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		op, err := upd.Execute(asUser(w.ctx, w.usrA), roleapp.UpdateRoleInput{
			ID: w.rolRead, Rules: writeRules(), UpdateMask: []string{"rules"},
		})
		upErr = err
		if op != nil {
			upOp = op.ID
		}
	}()
	close(start)
	wg.Wait()

	outcome := func(syncErr error, opID string) error {
		if syncErr != nil || opID == "" {
			return syncErr
		}
		if done := awaitOp(t, w.ctx, w.ops, opID); done.Error != nil {
			return status.Error(codes.Code(done.Error.Code), done.Error.Message)
		}
		return nil
	}
	g, u := outcome(grantErr, grantOp), outcome(upErr, upOp)
	require.Truef(t, (g == nil) != (u == nil),
		"SC-22 гонка: проходит ровно одна сторона (выдача: %v; правка роли: %v)", g, u)
	loser := g
	if loser == nil {
		loser = u
	}
	assert.Equal(t, codes.FailedPrecondition, status.Code(loser), "SC-22 гонка: проигравший — отказ SC-21 или SC-22")
}

// SC-23 — пишущий глагол у класса недостижим при любом пути роли: правила роли
// сменены мимо правки роли (тем путём, каким их кладёт поставка), материализация
// обязана отобрать только get/list.
func TestSystemClass_SC23_WriteVerbUnreachableForAClassOnAnyRolePath(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrC, w.rolRead2)
	id := w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-23 Дано: SC-01")

	rd, err := w.repo.Reader(w.ctx)
	require.NoError(t, err)
	role, err := rd.Roles().Get(w.ctx, w.rolRead)
	_ = rd.Rollback(w.ctx)
	require.NoError(t, err, "SC-23 Дано: роль")
	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(w.ctx) }()
	compiled, err := domain.CompileRules(writeRules())
	require.NoError(t, err)
	role.Rules, role.Permissions = writeRules(), compiled
	_, err = wr.RolesW().Update(w.ctx, role, []string{"rules"})
	require.NoError(t, err, "SC-23 Дано: правила роли сменены мимо правки роли")
	require.NoError(t, wr.RolesW().ReplaceRuleSelectors(w.ctx, w.rolRead, catalogfixture.Facts().GrantSelectors(writeRules().MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, wr.Commit(w.ctx))
	require.NoError(t, w.rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)), "SC-23: повторная материализация")

	w.requireCheck(fmtSubject("user", string(w.usrB)), "update", scObj1, false, "SC-23: пишущий глагол классу недостижим")
	w.requireCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-23 близнец: чтение осталось")
}

// SC-24 — анониму нельзя выдать всю область; близнец — SC-07.
func TestSystemClass_SC24_AnonymousAllInScopeIsRejected(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), withSubjects(w.sc01Request(), classSubject("anonymous")), "SC-24 близнец SC-07")

	_, err := w.ab.Create(asUser(w.ctx, w.usrA), allInScopeRequest(w, "anonymous"))
	requireTargetRefusal(t, err,
		"Illegal argument target: a grant to system class anonymous names its objects (allInScope is not accepted)", "SC-24")
}

// seedLiveHumanSession — живая запись сессии человека уровня «2» (вход час
// назад, предъявление минуту назад — П1); момент последнего предъявления
// переставляет seedPresentedSession.
func seedLiveHumanSession(t *testing.T, w *scWorld, user domain.UserID) {
	t.Helper()
	_, err := w.pool.Exec(w.ctx, `
		INSERT INTO kaname.human_sessions
		  (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at, assurance_level, presented_methods)
		VALUES ($1, $2, encode(sha256(convert_to($1, 'UTF8')), 'hex'),
		        now() - interval '1 hour', now() - interval '1 minute', now() + interval '1 day', '2', '{password}')`,
		"hs-sc25-"+string(user), string(user))
	require.NoError(t, err, "SC-25 посев: живая сессия человека")
}

// seedPresentedSession — последнее предъявление живой сессии `ago` назад.
func seedPresentedSession(t *testing.T, w *scWorld, user domain.UserID, ago time.Duration) {
	t.Helper()
	tag, err := w.pool.Exec(w.ctx, `
		UPDATE kaname.human_sessions SET last_presented_at = now() - make_interval(secs => $2)
		 WHERE user_id = $1 AND ended_at IS NULL`, string(user), ago.Seconds())
	require.NoError(t, err, "SC-25 посев: момент предъявления")
	require.EqualValues(t, 1, tag.RowsAffected(), "SC-25 посев: ровно одна живая сессия")
}

// SC-25 — несвежая сессия (16 мин) не выдаёт классу; 14 мин — выдаёт; выдача
// человеку той же несвежей сессией принята.
func TestSystemClass_SC25_StaleSessionDoesNotGrantToAClass(t *testing.T) {
	w := newSCWorld(t) // П1 уже держит живую сессию usr-A

	seedPresentedSession(t, w, w.usrA, 16*time.Minute)
	userReq := w.sc01Request()
	userReq.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
	w.createDone(asUser(w.ctx, w.usrA), userReq, "SC-25 близнец: выдача человеку несвежей сессией")

	_, err := w.ab.Create(asUser(w.ctx, w.usrA), w.sc01Request())
	require.Error(t, err, "SC-25: несвежая сессия")
	st := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code(), "SC-25: код (текст %q)", st.Message())
	var reasons []string
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			reasons = append(reasons, ei.GetReason())
		}
	}
	require.Contains(t, reasons, "SESSION_NOT_FRESH", "SC-25: причина")

	seedPresentedSession(t, w, w.usrA, 14*time.Minute)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-25 близнец: 14 минут")
}

// SC-26 — сессия уровня «1» не выдаёт ничего (пол службы «2», сегодняшняя
// форма отказа); близнец — уровень «2» проходит SC-01.
func TestSystemClass_SC26_LevelOneSessionGrantsNothing(t *testing.T) {
	w := newSCWorld(t)
	const fqn = "/kaname.cloud.iam.v1.AccessBindingService/Create"
	floor := authzguard.NewACRFloor(scCreateFloorLookup{}, []string{fqn}).WithProductionMode(true)
	call := func(acr string) error {
		ctx := grpcsrv.WithCertIdentityIn(asUser(w.ctx, w.usrA), grpcsrv.NewTrustDomain("kacho.cloud"),
			"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway", true)
		ctx = grpcsrv.WithTrustedPrincipal(ctx, operations.Principal{Type: "user", ID: string(w.usrA)}, true)
		ctx = grpcsrv.WithTrustedACR(ctx, acr, true)
		_, err := floor.Unary()(ctx, w.sc01Request(), &grpc.UnaryServerInfo{FullMethod: fqn},
			func(ctx context.Context, req any) (any, error) {
				op, err := w.ab.Create(ctx, req.(*iamv1.CreateAccessBindingRequest))
				if err != nil {
					return nil, err
				}
				if done := awaitOp(t, w.ctx, w.ops, op.GetId()); done.Error != nil {
					return nil, status.Error(codes.Code(done.Error.Code), done.Error.Message)
				}
				return op, nil
			})
		return err
	}
	require.NoError(t, call("2"), "SC-26 близнец: уровень «2» — SC-01")

	err := call("1")
	requireSyncRefusal(t, err, codes.PermissionDenied, "permission denied", "SC-26")
	var violations []string
	for _, d := range status.Convert(err).Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				violations = append(violations, v.GetType()+"|"+v.GetSubject()+"|"+v.GetDescription())
			}
		}
	}
	assert.Equal(t, []string{"authz.step_up|acr_values:2|insufficient_user_authentication: higher ACR required"}, violations)
}

// scCreateFloorLookup — пол `required_acr_min` у `AccessBindingService.Create`
// — «2» (опция proto ствола).
type scCreateFloorLookup struct{}

func (scCreateFloorLookup) RequiredACRMin(string) string { return "2" }

// grantAdminOnProject — выдача учётке `admin` на проект (материализуется в
// право выдавать).
func (w *scWorld) grantAdminOnProject(sva string) {
	w.t.Helper()
	_, err := w.pool.Exec(w.ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', 'admin', 'object', $2::text), now())`,
		"service_account:"+sva, "project:"+string(w.prjA))
	require.NoError(w.t, err, "посев: admin учётки на проекте")
}

// SC-27 — сервисная учётка с правом выдаёт классу; без права — отказ SC-20.
func TestSystemClass_SC27_ServiceAccountWithAuthorityGrantsToAClass(t *testing.T) {
	w := newSCWorld(t)
	svaCtx := operations.WithPrincipal(w.ctx, operations.Principal{Type: "service_account", ID: w.svaA})
	_, err := w.ab.Create(svaCtx, w.sc01Request())
	require.Error(t, err, "SC-27 близнец: sva-A без admin")
	require.Equal(t, codes.PermissionDenied, status.Code(err), "SC-27 близнец: PERMISSION_DENIED (текст %q)", status.Convert(err).Message())

	w.grantAdminOnProject(w.svaA)
	userReq := w.sc01Request()
	userReq.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
	w.createDone(svaCtx, userReq, "SC-27 контроль: учётка с admin выдаёт человеку")

	id := w.createDone(svaCtx, w.sc01Request(), "SC-27: учётка выдаёт классу")
	pb, err := w.ab.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err)
	assert.Empty(t, pb.GetGrantedByUserId(), "SC-27: grantedByUserId пуст")
	var actor string
	require.NoError(t, w.pool.QueryRow(w.ctx, `
		SELECT event_payload->>'actor' FROM kaname.audit_outbox
		 WHERE event_type = 'iam.access_binding.granted' AND event_payload->>'binding_id' = $1`, id).Scan(&actor))
	assert.Equal(t, w.svaA, actor, "SC-27: исполнитель в записи аудита — sva-A")
}

// SC-28 — выдача классу на кластере ролью с правилом-якорем отвергается
// правилами ствола (решение диспетчера Д4, приёмка ред. 5/6, заголовок SC-28
// ред. 17): класс на кластере получает тот же отказ ствола, что человек; своего
// правила у класса нет.
//
// Здесь стояло «выдача классу на кластере глаголом создания недостижима». Это
// неверно: системная роль модуля с именами или метками правило кластера
// проходит, и выдача классу `authenticated` на всю область кластера такой ролью
// принимается (близнец SC-81, `TestClassGrantsOnContainers_SC81_Twin_…`).
// Проба утверждает только ветвь роли с правилом-якорем; исходы её строк не
// менялись.
//
// Строки сценария: отказ в праве у владельца аккаунта (`usr-A`); близнец —
// тот же запрос от кластерного администратора упирается в правило ствола
// дословно; близнец правила — субъект-человек получает тот же отказ;
// контроль живости пути — выдача человеку роли кластерного администратора на
// кластере доходит до `done`.
func TestSystemClass_SC28_ClusterGrantToAClassByAnAnchorRoleIsRefusedByTheTrunkRule(t *testing.T) {
	w := newSCWorld(t)
	var live bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT live FROM kaname.roles WHERE id = $1`, scClusterViewRole).Scan(&live),
		"SC-28 предпосылка: системная роль чтения сетей")
	require.True(t, live, "SC-28 предпосылка: роль жива")
	admin := mustSeedUser(t, w.ctx, w.pool, "scadm")
	verifyAddresses(t, w.ctx, w.pool)
	_, err := w.pool.Exec(w.ctx, `SELECT kaname.restore_cluster_admin('user', $1)`, string(admin))
	require.NoError(t, err, "SC-28 посев: кластерный администратор объявленным путём")
	// usr-K выдаёт свежей сессией уровня «2», как usr-A в П1 (Р5): без неё
	// близнец упирался бы в окно свежести выдачи классу, а не в правило ствола.
	seedLiveHumanSession(t, w, admin)

	clusterReq := func(subject *iamv1.Subject, role string) *iamv1.CreateAccessBindingRequest {
		return &iamv1.CreateAccessBindingRequest{
			Subjects: []*iamv1.Subject{subject}, RoleId: role,
			ScopeType: "iam.cluster", ScopeId: domain.ClusterSingletonID, Target: allInScopeTarget(),
		}
	}
	countOps := func() int {
		var n int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&n))
		return n
	}
	// refused — синхронный отказ кодом; текст сверяется дословно, когда задан.
	refused := func(err error, code codes.Code, text, why string) {
		t.Helper()
		require.Errorf(t, err, "%s: ожидался синхронный отказ", why)
		st := status.Convert(err)
		require.Equalf(t, code, st.Code(), "%s: код (текст %q)", why, st.Message())
		if text != "" {
			require.Equalf(t, text, st.Message(), "%s: текст отказа", why)
		}
	}
	const trunkRule = "GLOBAL scope requires names or labels selector for non-cluster-admin roles"

	// Контроль живости пути (не близнец): человеку — роль кластерного
	// администратора на кластере от usr-K.
	w.createDone(asUser(w.ctx, admin), clusterReq(userSubject(w.usrB), domain.ClusterAdminRoleID),
		"SC-28 контроль: выдача человеку роли кластерного администратора на кластере")

	opsBefore := countOps()

	// Строка 1: usr-A, тело К — отказ в праве, роль не названа.
	_, err = w.ab.Create(asUser(w.ctx, w.usrA), clusterReq(classSubject("authenticated"), scClusterViewRole))
	refused(err, codes.PermissionDenied, "", "SC-28: владелец аккаунта не выдаёт на кластере")
	msg := status.Convert(err).Message()
	assert.NotContains(t, msg, scClusterViewRole, "SC-28: текст отказа не называет роль")
	assert.NotContains(t, msg, "vpc.network.view", "SC-28: текст отказа не называет роль")

	// Близнец: тело К от usr-K — правило ствола дословно.
	_, err = w.ab.Create(asUser(w.ctx, admin), clusterReq(classSubject("authenticated"), scClusterViewRole))
	refused(err, codes.InvalidArgument, trunkRule, "SC-28 близнец: кластерный администратор, класс")

	// Близнец правила ствола: тело К с субъектом-человеком от usr-K.
	_, err = w.ab.Create(asUser(w.ctx, admin), clusterReq(userSubject(w.usrB), scClusterViewRole))
	refused(err, codes.InvalidArgument, trunkRule, "SC-28 близнец правила: кластерный администратор, человек")

	assert.Equal(t, opsBefore, countOps(), "SC-28: ни одна строка отказа не создала Operation")
	var classOnCluster int
	require.NoError(t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE subject_type = 'system_class' AND role_id = $1`, scClusterViewRole).Scan(&classOnCluster))
	assert.Zero(t, classOnCluster, "SC-28: выдачи классу на кластере нет")
}

// SC-29 — аудит называет класс и исполнителя на выдаче и отзыве; близнец —
// выдача человеку той же формы.
func TestSystemClass_SC29_AuditNamesTheClassAndTheActor(t *testing.T) {
	w := newSCWorld(t)
	userReq := w.sc01Request()
	userReq.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
	userID := w.createDone(asUser(w.ctx, w.usrA), userReq, "SC-29 близнец: выдача человеку")
	assert.Equal(t, map[string]string{"subject_type": "user", "subject_id": string(w.usrB), "actor": string(w.usrA)},
		w.auditOf(userID, "iam.access_binding.granted"), "SC-29 близнец: форма записи")

	id := w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-29 Дано: SC-01")
	w.ownerMayRemove("SC-29 Дано", id)
	op, err := w.ab.Delete(asUser(w.ctx, w.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
	want := map[string]string{"subject_type": "system_class", "subject_id": "authenticated", "actor": string(w.usrA)}
	assert.Equal(t, want, w.auditOf(id, "iam.access_binding.granted"), "SC-29: запись выдачи")
	assert.Equal(t, want, w.auditOf(id, "iam.access_binding.revoked"), "SC-29: запись отзыва")
}

func (w *scWorld) auditOf(bindingID, eventType string) map[string]string {
	w.t.Helper()
	var raw []byte
	require.NoErrorf(w.t, w.pool.QueryRow(w.ctx, `
		SELECT event_payload FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'binding_id' = $2`, eventType, bindingID).Scan(&raw),
		"запись аудита %s выдачи %s", eventType, bindingID)
	var p map[string]any
	require.NoError(w.t, json.Unmarshal(raw, &p))
	out := map[string]string{}
	for _, k := range []string{"subject_type", "subject_id", "actor"} {
		s, _ := p[k].(string)
		out[k] = s
	}
	return out
}
