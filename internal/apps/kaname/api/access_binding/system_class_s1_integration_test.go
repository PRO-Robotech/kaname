// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_class_s1_integration_test.go — стадия S1 приёмки «аноним и вошедший —
// системный класс субъекта» (kaname#829): контракт выдачи классу и
// классификация говорящего. Имя каждой пробы несёт ID сценария; посев — П1
// (`system_class_world_integration_test.go`).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/genproto/googleapis/rpc/errdetails"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// requireSyncRefusal — синхронный отказ с кодом и ДОСЛОВНЫМ текстом.
func requireSyncRefusal(t *testing.T, err error, code codes.Code, text, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался синхронный отказ", why)
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: отказ не gRPC-статус: %v", why, err)
	require.Equalf(t, code, st.Code(), "%s: код отказа (текст %q)", why, st.Message())
	require.Equalf(t, text, st.Message(), "%s: текст отказа", why)
}

// SC-01 — выдача классу `authenticated` заводится, как выдача человеку.
func TestSystemClass_SC01_AuthenticatedGrantIsCreatedLikeAUserGrant(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)

	id := w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-01: выдача классу authenticated")
	pb, err := w.ab.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "SC-01: Get выдачи классу")
	require.Len(t, pb.GetSubjects(), 1)
	assert.Equal(t, scSystemClassType, pb.GetSubjects()[0].GetType())
	assert.Equal(t, "authenticated", pb.GetSubjects()[0].GetId())
	assert.Equal(t, "system_class", pb.GetSubjectType())
	assert.Equal(t, "authenticated", pb.GetSubjectId())
	assert.False(t, pb.GetSystem())
	assert.Equal(t, string(w.usrA), pb.GetGrantedByUserId())
	assert.Zero(t, pb.GetCreatedAt().GetNanos(), "createdAt усечён до секунды")
}

// SC-02 — имя класса вне словаря отвергается; близнец — SC-01.
func TestSystemClass_SC02_UnknownClassNameIsRejected(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-02 близнец SC-01")

	_, err := w.ab.Create(asUser(w.ctx, w.usrA), withSubjects(w.sc01Request(), classSubject("everyone")))
	requireSyncRefusal(t, err, codes.InvalidArgument,
		`Illegal argument subject id "everyone" for subject type system_class (allowed: anonymous|authenticated)`,
		"SC-02")
}

// SC-03 — пустое имя класса отвергается; близнец — SC-01.
func TestSystemClass_SC03_EmptyClassNameIsRejected(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-03 близнец SC-01")

	_, err := w.ab.Create(asUser(w.ctx, w.usrA), withSubjects(w.sc01Request(), classSubject("")))
	requireSyncRefusal(t, err, codes.InvalidArgument,
		"Illegal argument subject id (must be non-empty)", "SC-03")
}

// SC-04 — класс и человек в одной выдаче, порядок запроса сохранён.
func TestSystemClass_SC04_ClassAndUserInOneGrant(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrC, w.rolRead2)

	id := w.createDone(asUser(w.ctx, w.usrA),
		withSubjects(w.sc01Request(), classSubject("authenticated"), userSubject(w.usrB)), "SC-04")
	pb, err := w.ab.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err)
	require.Len(t, pb.GetSubjects(), 2)
	assert.Equal(t, scSystemClassType, pb.GetSubjects()[0].GetType())
	assert.Equal(t, "authenticated", pb.GetSubjects()[0].GetId())
	assert.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_USER, pb.GetSubjects()[1].GetType())
	assert.Equal(t, string(w.usrB), pb.GetSubjects()[1].GetId())
}

// SC-05 — повтор того же класса в одной выдаче отвергается; близнец — SC-04.
func TestSystemClass_SC05_DuplicateClassInOneGrantIsRejected(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrC, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA),
		withSubjects(w.sc01Request(), classSubject("authenticated"), userSubject(w.usrB)), "SC-05 близнец SC-04")

	req := withSubjects(w.sc01Request(), classSubject("authenticated"), classSubject("authenticated"))
	req.RoleId = string(w.rolRead2)
	_, err := w.ab.Create(asUser(w.ctx, w.usrA), req)
	requireSyncRefusal(t, err, codes.InvalidArgument,
		"Illegal argument subjects: duplicate subject system_class/authenticated", "SC-05")
}

// SC-06 — вторая активная такая же выдача — ALREADY_EXISTS в операции;
// близнец — та же выдача с другой ролью только чтения принята.
func TestSystemClass_SC06_SecondIdenticalActiveGrantAlreadyExists(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-06: первая выдача")

	op, err := w.ab.Create(asUser(w.ctx, w.usrA), w.sc01Request())
	require.NoError(t, err, "SC-06: дубль отвергается в операции, а не синхронно")
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "SC-06: дубль активной выдачи обязан завершиться ошибкой")
	assert.Equal(t, int32(codes.AlreadyExists), done.Error.Code, "SC-06: код ошибки операции")

	twin := w.sc01Request()
	twin.RoleId = string(w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), twin, "SC-06 близнец: другая роль только чтения")
}

// SC-07 — устаревшая одиночная пара принимает класс; отрицание — подстановка
// `user:*` отвергается сегодняшним текстом.
func TestSystemClass_SC07_LegacySinglePairAcceptsAClass(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)

	legacy := &iamv1.CreateAccessBindingRequest{
		SubjectType: "system_class", SubjectId: "anonymous",
		RoleId: string(w.rolRead), ScopeType: "iam.project", ScopeId: string(w.prjA),
		Target: obj1Target(),
	}
	id := w.createDone(asUser(w.ctx, w.usrA), legacy, "SC-07: устаревшая пара system_class/anonymous")
	pb, err := w.ab.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err)
	require.Len(t, pb.GetSubjects(), 1)
	assert.Equal(t, scSystemClassType, pb.GetSubjects()[0].GetType())
	assert.Equal(t, "anonymous", pb.GetSubjects()[0].GetId())

	wild := &iamv1.CreateAccessBindingRequest{
		SubjectType: "user", SubjectId: "*",
		RoleId: string(w.rolRead), ScopeType: "iam.project", ScopeId: string(w.prjA),
		Target: obj1Target(),
	}
	_, err = w.ab.Create(asUser(w.ctx, w.usrA), wild)
	requireSyncRefusal(t, err, codes.InvalidArgument,
		`Illegal argument subject_id "*" on a non-system access binding`, "SC-07 отрицание")
}

// SC-10 — аноним не получает выданного «вошедшим»; близнецы — человек и учётка.
func TestSystemClass_SC10_AnonymousDoesNotInheritAuthenticated(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrC, w.rolRead2)
	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-10 Дано: выдача SC-01")
	w.pollCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-10 Дано: материализация для usr-B")

	resp, err := w.check("system_class:anonymous", "get", scObj1)
	require.NoError(t, err, "SC-10: вопрос анонима")
	assert.False(t, resp.GetAllowed(), "SC-10: аноним не выводит authenticated")
	assert.Empty(t, resp.GetDenyReasons(), "SC-10: «пути нет»")
	w.requireCheck(fmtSubject("service_account", w.svaA), "get", scObj1, true, "SC-10 близнец: учётка")
}

// SC-11 — вошедший получает выданное анониму (включение, Р2); группа —
// нет.
func TestSystemClass_SC11_SignedInInheritsAnonymous(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrC, w.rolRead2)
	legacy := &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{classSubject("anonymous")},
		RoleId:   string(w.rolRead), ScopeType: "iam.project", ScopeId: string(w.prjA),
		Target: obj1Target(),
	}
	w.createDone(asUser(w.ctx, w.usrA), legacy, "SC-11 Дано: выдача SC-07")

	w.pollCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-11: вошедший читает выданное анониму")
	w.requireCheck("system_class:anonymous", "get", scObj1, true, "SC-11: аноним читает выданное анониму")
	w.requireCheck("group:"+w.grpA+"#member", "get", scObj1, false, "SC-11 отрицание: группа классов не получает")
}

// SC-14 — «вошедший» без личности говорящим не бывает.
func TestSystemClass_SC14_AuthenticatedIsNotASpeaker(t *testing.T) {
	w := newSCWorld(t)
	_, err := w.check("system_class:anonymous", "get", scObj1)
	require.NoError(t, err, "SC-14 близнец: вопрос анонима отвечается по выдачам, не отказом")

	_, err = w.check("system_class:authenticated", "get", scObj1)
	requireSyncRefusal(t, err, codes.InvalidArgument,
		"Illegal argument subject: system class authenticated is not a speaker", "SC-14")
}

// SC-15 — подстановка говорящим не бывает (полоса L6, PRO-Robotech/kaname#832;
// решение диспетчера Д1, разбор CE-10 (б)).
//
// Переходное отображение `user:*` в аноним снято: плоскость данных реестра
// kacho спрашивает о вызывающем без личности классом `system_class:anonymous`
// (SC-39, край L4 — PRO-Robotech/kacho#3238). Вопрос от подстановки — отказ
// разбора `INVALID_ARGUMENT` дословным текстом приёмки, и даже при выдаче
// анониму на объекте: подстановка его прав не наследует.
//
// Близнец — тот же вопрос от `user:usr-B`: ответ по выдачам (`allowed = true`).
// Отличие — один факт: говорящий. Второй близнец — `system_class:anonymous`
// на той же выдаче читает: отказ подстановке не отнял чтения у анонима.
func TestSystemClass_SC15_WildcardIsNotASpeaker(t *testing.T) {
	w := newSCWorld(t)
	w.createDone(asUser(w.ctx, w.usrA),
		withSubjects(w.sc01Request(), classSubject("anonymous")), "SC-15 Дано: выдача SC-07")
	// Материализация: вошедший читает выданное анониму (SC-11).
	w.pollCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-15 Дано: материализация SC-07")

	w.requireCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-15 близнец: человек — ответ по выдачам")
	w.requireCheck("system_class:anonymous", "get", scObj1, true, "SC-15 близнец: аноним читает выданное анониму")

	_, err := w.check("user:*", "get", scObj1)
	requireSyncRefusal(t, err, codes.InvalidArgument,
		"Illegal argument subject: wildcard is not a speaker", "SC-15")
}

// SC-16 — развёртка прав классов не перечисляет; близнец — без классовой
// выдачи ответ тот же.
func TestSystemClass_SC16_ExpandAccessDoesNotListClasses(t *testing.T) {
	w := newSCWorld(t)
	// Разворачивает КЛАСТЕРНЫЙ АДМИНИСТРАТОР, а не владелец аккаунта. Право
	// разворачивать объект владелец получает выдачей роли владельца на аккаунт
	// (её заводит сага создания аккаунта), а она же делает его читателем объекта
	// — и он сам оказывается в развёртке вторым принципалом. «Ровно один
	// принципал» приёмки поэтому достижим только у вызывающего, право которого
	// не материализуется на объекте: у администратора облака (плоский
	// надзор). Расхождение с «Когда usr-A» приёмки вынесено в возврат.
	admin := mustSeedUser(t, w.ctx, w.pool, "sc16adm")
	verifyAddresses(t, w.ctx, w.pool)
	_, err := w.pool.Exec(w.ctx, `SELECT kaname.restore_cluster_admin('user', $1)`, string(admin))
	require.NoError(t, err, "SC-16 посев: кластерный администратор объявленным путём")
	userReq := w.sc01Request()
	userReq.Subjects = []*iamv1.Subject{userSubject(w.usrB)}
	w.createDone(asUser(w.ctx, w.usrA), userReq, "SC-16 Дано: прямая выдача usr-B")
	w.pollCheck(fmtSubject("user", string(w.usrB)), "get", scObj1, true, "SC-16 Дано: материализация usr-B")

	expand := func() *iamv1.ExpandAccessResponse {
		resp, err := w.ab.ExpandAccess(asUser(w.ctx, admin), &iamv1.ExpandAccessRequest{
			ObjectType: scModelType, ObjectId: scObj1, Relation: "viewer",
		})
		require.NoError(t, err, "SC-16: развёртка")
		return resp
	}
	before := expand()

	w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-16 Дано: выдача SC-01")
	after := expand()
	require.Len(t, after.GetPrincipals(), 1, "SC-16: ровно один принципал")
	assert.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_USER, after.GetPrincipals()[0].GetType())
	assert.Equal(t, string(w.usrB), after.GetPrincipals()[0].GetId())
	assert.False(t, after.GetTruncated())
	assert.Equal(t, before.GetPrincipals(), after.GetPrincipals(), "SC-16 близнец: ответ тот же без классовой выдачи")
}

// SC-17 — перечень выдач по субъекту-классу.
//
// У класса нет дома (разбор CE-22): страница сужается построчно — строка видна
// тому, кто прочёл бы её по идентификатору (паритет с Get). Отрицательный
// близнец (CE-22, заказан приёмке): арендатор другого аккаунта чужих выдач
// классу не видит — страница пуста, полосы «сам» у класса нет.
func TestSystemClass_SC17_ListBySubjectClass(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	authID := w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-17 Дано: SC-01")
	anonID := w.createDone(asUser(w.ctx, w.usrA),
		withSubjects(w.sc01Request(), classSubject("anonymous")), "SC-17 Дано: SC-07")

	list := func(caller domain.UserID) []string {
		resp, err := w.ab.ListBySubject(asUser(w.ctx, caller), &iamv1.ListAccessBindingsBySubjectRequest{
			SubjectType: "system_class", SubjectId: "anonymous",
		})
		require.NoError(t, err, "SC-17: перечень по классу")
		var got []string
		for _, b := range resp.GetAccessBindings() {
			got = append(got, b.GetId())
		}
		return got
	}
	got := list(w.usrA)
	assert.Equal(t, []string{anonID}, got, "SC-17: ровно выдача SC-07")
	assert.NotContains(t, got, authID)

	assert.Empty(t, list(w.usrC), "SC-17 близнец: арендатор acc-B выдач классу в acc-A не видит")

	// Администратор облака — без сужения (полоса надзора).
	admin := mustSeedUser(t, w.ctx, w.pool, "sc17adm")
	verifyAddresses(t, w.ctx, w.pool)
	_, err := w.pool.Exec(w.ctx, `SELECT kaname.restore_cluster_admin('user', $1)`, string(admin))
	require.NoError(t, err, "SC-17 посев: кластерный администратор объявленным путём")
	assert.Equal(t, []string{anonID}, list(admin), "SC-17: администратор облака видит выдачу классу")
}

// SC-18 — «вошедший» другого арендатора читает выданное классу в acc-A;
// соседний объект закрыт; после отзыва — закрыто обоим.
func TestSystemClass_SC18_SignedInOfAnotherTenantReadsTheNamedObject(t *testing.T) {
	w := newSCWorld(t)
	w.controlUserGrant(w.usrB, w.rolRead2)
	w.requireCheck(fmtSubject("user", string(w.usrC)), "get", scObj1, false, "SC-18 предпосылка: у usr-C нет выдач в acc-A")

	id := w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-18 Дано: SC-01")
	w.pollCheck(fmtSubject("user", string(w.usrC)), "get", scObj1, true, "SC-18: usr-C из acc-B")
	w.requireCheck(fmtSubject("service_account", w.svaB), "get", scObj1, true, "SC-18: sva-B из acc-B")
	w.requireCheck(fmtSubject("user", string(w.usrC)), "get", scObj2, false, "SC-18: соседний объект закрыт")

	w.ownerMayRemove("SC-18 близнец Дано", id)
	op, err := w.ab.Delete(asUser(w.ctx, w.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "SC-18 близнец: отзыв")
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
	w.pollCheck(fmtSubject("user", string(w.usrC)), "get", scObj1, false, "SC-18 близнец: после отзыва usr-C")
	w.pollCheck(fmtSubject("service_account", w.svaB), "get", scObj1, false, "SC-18 близнец: после отзыва sva-B")
}

// SC-08 — класс не становится членом группы: отказ называет поле
// `member_type`, как на любом виде вне `user|service_account`; близнец — человек.
func TestSystemClass_SC08_ClassIsNotAGroupMember(t *testing.T) {
	w := newSCWorld(t)
	add := groupapp.NewAddMemberUseCase(w.repo, w.ops).
		WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door))

	// Близнец — человек, состоящий в аккаунте группы: участник группы обязан
	// принадлежать её аккаунту (Д-3 приёмки role-rights-stay-within-what-is-named.md),
	// и без членства близнец мерил бы не вид участника, а принадлежность.
	gdSeedMembership(t, w.ctx, w.pool, w.usrB, w.accA, "ACTIVE")
	op, err := add.Execute(asUser(w.ctx, w.usrA), groupapp.AddMemberInput{
		GroupID: domain.GroupID(w.grpA), MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(w.usrB),
	})
	require.NoError(t, err, "SC-08 близнец: человек принимается в группу")
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.ID).Error, "SC-08 близнец: done без error")

	// Контроль формы отказа: вид вне user|service_account, который домен уже
	// знает (группа), отвергается с полем member_type.
	_, err = add.Execute(asUser(w.ctx, w.usrA), groupapp.AddMemberInput{
		GroupID: domain.GroupID(w.grpA), MemberType: domain.SubjectTypeGroup, MemberID: domain.SubjectID(w.grpA),
	})
	requireFieldViolation(t, err, "member_type", "SC-08 контроль: группа в группе")

	_, err = add.Execute(asUser(w.ctx, w.usrA), groupapp.AddMemberInput{
		GroupID: domain.GroupID(w.grpA), MemberType: domain.SubjectType("system_class"), MemberID: "authenticated",
	})
	requireFieldViolation(t, err, "member_type", "SC-08: класс в группе")
}

// requireFieldViolation — INVALID_ARGUMENT с нарушением названного поля.
func requireFieldViolation(t *testing.T, err error, field, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался отказ", why)
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: отказ не gRPC-статус: %v", why, err)
	require.Equalf(t, codes.InvalidArgument, st.Code(), "%s: код (текст %q)", why, st.Message())
	var fields []string
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			for _, v := range br.GetFieldViolations() {
				fields = append(fields, v.GetField())
			}
		}
	}
	require.Containsf(t, fields, field, "%s: поле нарушения (текст %q)", why, st.Message())
}
