// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_integration_test.go — стадия S5 «публичное чтение
// контейнера» (задача PRO-Robotech/kaname#856): SC-60…67, SC-69, SC-73 и
// служебная половина SC-70 (а).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 10, отпечаток 198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9.
// Мир — П6 (`public_container_read_world_integration_test.go`).
//
// SC-68 (сужение по цели) здесь НЕ утверждается: его реализация и проба — задача
// PRO-Robotech/kaname#857 (`go test ./internal/repo/kaname/pg/relverdict/ -run
// '^Test(Ask|Batch)_SC68_'`), первая в порядке S5. Части SC-69 и SC-73, где
// ответ зависит от сужения, утверждаются здесь в той мере, в какой их «Тогда»
// названо самим сценарием.
//
// Порядок в каждой пробе: контроль фикстуры (`newPCRWorld`) → доставка новой
// редакции (`deliverNewEdition`, начало предмета) → утверждения сценария, в
// которых положительный близнец стоит раньше отрицания, если отрицание без него
// неотличимо от неразвернувшейся выдачи.

import (
	"context"
	"fmt"
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

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestPublicContainerRead_SC60_OneAnonymousGrantOpensTheRegistryAndAllItsRepositories —
// SC-60: одна выдача анониму открывает реестр и все его репозитории, включая
// зарегистрированный после выдачи; внутреннее ребро отвечает так же.
// Близнец — то же «Дано» без выдачи ПЧ: шесть вопросов → false.
func TestPublicContainerRead_SC60_OneAnonymousGrantOpensTheRegistryAndAllItsRepositories(t *testing.T) {
	// Близнец — отдельный мир П6: то же «Дано», `…/late` зарегистрирован, выдачи нет.
	twin := newPCRWorld(t)
	twin.deliverNewEdition("SC-60 близнец")
	twin.registerRepository(pcrX, "late")
	for _, q := range sixPairs() {
		twin.requireAsk(pcrAnon, q.relation, q.modelType, q.id, false, "SC-60 близнец: без выдачи ПЧ "+q.String())
	}

	p := newPCRWorld(t)
	p.deliverNewEdition("SC-60")
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-60: выдача ПЧ")
	for _, q := range sixPairs()[:4] {
		p.pollAsk(pcrAnon, q.relation, q.modelType, q.id, true, "SC-60: после материализации "+q.String())
	}
	p.registerRepository(pcrX, "late")
	for _, q := range sixPairs()[4:] {
		p.pollAsk(pcrAnon, q.relation, q.modelType, q.id, true, "SC-60: репозиторий после выдачи "+q.String())
	}
	for _, q := range sixPairs() {
		assert.Truef(t, p.askInternal(pcrAnon, q.relation, q.modelType, q.id),
			"SC-60: InternalIAMService.Check отвечает иначе, чем AuthorizeService.Check, на %s", q)
	}
}

// TestPublicContainerRead_SC61_RegistriesGetHolderDoesNotReadRepositories —
// SC-61: держатель `registries:get` репозиториев не читает; близнец — с
// публичной выдачей на X вошедший usr-B читает `…/app` (несёт класс anonymous, Р2).
func TestPublicContainerRead_SC61_RegistriesGetHolderDoesNotReadRepositories(t *testing.T) {
	p := newPCRWorld(t)
	usrB := fmtSubject("user", string(p.usrB))
	p.deliverNewEdition("SC-61")

	p.requireAsk(usrB, "v_get", pcrRegType, pcrX, true, "SC-61: выдача rol-reg-get действует (контроль живости)")
	p.requireAsk(usrB, "v_get", pcrRepoType, pcrXApp, false, "SC-61: общего наследования чтения от реестра нет")
	p.requireAsk(usrB, "v_list", pcrRepoType, pcrXApp, false, "SC-61: общего наследования чтения от реестра нет")

	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-61 близнец: выдача ПЧ")
	p.pollAsk(usrB, "v_get", pcrRepoType, pcrXApp, true, "SC-61 близнец: вошедший несёт класс anonymous")
	p.pollAsk(usrB, "v_list", pcrRepoType, pcrXApp, true, "SC-61 близнец: вошедший несёт класс anonymous")
}

// TestPublicContainerRead_SC73_RoleWithoutAChildRuleOpensNoDescendants — SC-73:
// выдача анониму роли без правила над `registry.repositories` открывает только
// сам реестр. Близнец — та же цель ролью `registry.public.read`.
func TestPublicContainerRead_SC73_RoleWithoutAChildRuleOpensNoDescendants(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-73")

	p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(classSubject("anonymous"), p.rolRegGet, pcrXTarget()),
		"SC-73: выдача анониму rol-reg-get на X")
	p.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "SC-73: выдача действует (контроль живости)")
	p.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, false, "SC-73: роль без правила над ребёнком потомков не открывает")
	p.requireAsk(pcrAnon, "v_list", pcrRepoType, pcrXApp, false, "SC-73: роль без правила над ребёнком потомков не открывает")
	p.registerRepository(pcrX, "late")
	p.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrXLate, false, "SC-73: и поздний репозиторий не открыт")

	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-73 близнец: выдача ПЧ ролью registry.public.read")
	p.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SC-73 близнец: правило над ребёнком открывает потомков")
	p.pollAsk(pcrAnon, "v_list", pcrRepoType, pcrXApp, true, "SC-73 близнец: правило над ребёнком открывает потомков")
}

// TestPublicContainerRead_SC62_ClassReadsOnly — SC-62: запись, удаление и
// создание классу недостижимы; от вошедшего usr-D — тоже. Близнец — v_get на
// тех же объектах. Отличие — глагол.
func TestPublicContainerRead_SC62_ClassReadsOnly(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-62")
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-62 Дано: выдача ПЧ")
	p.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "SC-62 близнец: чтение реестра")
	p.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SC-62 близнец: чтение репозитория")

	writes := []pcrPair{
		{"v_update", pcrRepoType, pcrXApp}, {"v_delete", pcrRepoType, pcrXApp},
		{"v_update", pcrRegType, pcrX}, {"v_delete", pcrRegType, pcrX}, {"v_create", pcrRegType, pcrX},
	}
	for _, subject := range []string{pcrAnon, fmtSubject("user", string(p.usrD))} {
		for _, q := range writes {
			p.requireAsk(subject, q.relation, q.modelType, q.id, false, "SC-62: классу только чтение — "+q.String())
		}
	}
}

// TestPublicContainerRead_SC63_RevokeRemovesReadFromAllRepositoriesAtOnce —
// SC-63: отзыв выдачи ПЧ снимает чтение со всех репозиториев разом; выдача
// usr-B не тронута. Близнец — те же вопросы до отзыва.
func TestPublicContainerRead_SC63_RevokeRemovesReadFromAllRepositoriesAtOnce(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-63")
	id := p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-63 Дано: выдача ПЧ")
	p.registerRepository(pcrX, "late")
	for _, q := range sixPairs() {
		p.pollAsk(pcrAnon, q.relation, q.modelType, q.id, true, "SC-63 близнец: до отзыва "+q.String())
	}

	p.ownerMayRemove("SC-63 Дано", id)
	op, err := p.ab.Delete(asUser(p.ctx, p.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "SC-63: отзыв выдачи ПЧ")
	done := awaitOp(t, p.ctx, p.ops, op.GetId())
	require.Nilf(t, done.Error, "SC-63: операция отзыва завершилась ошибкой %+v", done.Error)

	for _, q := range sixPairs() {
		p.pollAsk(pcrAnon, q.relation, q.modelType, q.id, false, "SC-63: после отзыва "+q.String())
	}
	p.requireAsk(fmtSubject("user", string(p.usrB)), "v_get", pcrRegType, pcrX, true, "SC-63: отзыв снял только выдачу ПЧ")
}

// TestPublicContainerRead_SC64_AllInScopeToAnonymousStillRefused — SC-64: тело
// «выдача ПЧ» с целью allInScope — синхронный отказ текстом SC-24. Близнец —
// SC-60 (цель resources).
func TestPublicContainerRead_SC64_AllInScopeToAnonymousStillRefused(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-64")
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-64 близнец: SC-60, цель resources")

	req := p.pchRequest()
	req.Target = allInScopeTarget()
	op, err := p.ab.Create(asUser(p.ctx, p.usrA), req)
	require.Nil(t, op, "SC-64: Operation не создаётся")
	requireTargetRefusal(t, err,
		"Illegal argument target: a grant to system class anonymous names its objects (allInScope is not accepted)", "SC-64")
}

// TestPublicContainerRead_SC65_UndeclaredContainerIsRefusedForAClass — SC-65:
// выдача классу роли, покрывающей тип-ребёнок цели, на необъявленный контейнер
// (iam.project) — FAILED_PRECONDITION с причиной; на объявленный (X) — принята,
// и без правила над repositories потомки не открыты; человеку отказа нет.
// «И (механизм общий)» — пробы `internal/modelrender` (`TestRender_SC65_`) и
// `…/reconcile` (`TestRuleObjectTuples_SC65_`).
func TestPublicContainerRead_SC65_UndeclaredContainerIsRefusedForAClass(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-65")
	prjTarget := resourcesTarget(&iamv1.ResourceRef{Type: "iam.project", Id: string(p.prjA)})

	// Близнец: та же роль и субъект, цель — X (тип объявлен).
	p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(classSubject("anonymous"), p.rolProjRegRead, pcrXTarget()),
		"SC-65 близнец: цель — объявленный контейнер X")
	p.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "SC-65 близнец: чтение X")
	p.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, false, "SC-65 близнец: правила над repositories нет — public_reader не пишется")
	p.requireAsk(pcrAnon, "v_list", pcrRepoType, pcrXApp, false, "SC-65 близнец: правила над repositories нет — public_reader не пишется")

	// И (человеку отказа нет): то же тело, что «Когда», субъект — usr-D.
	p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(userSubject(p.usrD), p.rolProjRegRead, prjTarget),
		"SC-65 «И»: выдача человеку на iam.project")

	// Предмет: класс, цель — необъявленный контейнер.
	op, err := p.ab.Create(asUser(p.ctx, p.usrA), p.grantRequest(classSubject("anonymous"), p.rolProjRegRead, prjTarget))
	require.Nil(t, op, "SC-65: Operation не создаётся")
	requireSyncRefusal(t, err, codes.FailedPrecondition,
		fmt.Sprintf("Type iam.project does not pass public read to its children; role %s covers its child type registry.registries",
			p.rolProjRegRead), "SC-65")

	// Контроль: SC-60 (роль registry.public.read, цель X) — принято.
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-65 контроль: SC-60")
}

// TestPublicContainerRead_SC66_TargetCapFreshnessAndFloorAsToday — SC-66:
// предел 256 объектов цели, окно свежести выдающего и пол уровня — как сейчас.
func TestPublicContainerRead_SC66_TargetCapFreshnessAndFloorAsToday(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-66")
	targetOf := func(n int) *iamv1.AccessTarget {
		refs := make([]*iamv1.ResourceRef, 0, n)
		for i := 1; i <= n; i++ {
			refs = append(refs, &iamv1.ResourceRef{Type: pcrRegTgt, Id: fmt.Sprintf("reg%017d", i)})
		}
		return resourcesTarget(refs...)
	}

	// (а) 257 — отказ; (б) 256 — принято. Близнецы — число объектов.
	req := p.pchRequest()
	req.Target = targetOf(257)
	_, err := p.ab.Create(asUser(p.ctx, p.usrA), req)
	requireSyncRefusal(t, err, codes.InvalidArgument, "Illegal argument target.resources (must be 1..256)", "SC-66 (а)")
	req.Target = targetOf(256)
	id := p.createDone(asUser(p.ctx, p.usrA), req, "SC-66 (б): 256 объектов")
	p.ownerMayRemove("SC-66 Дано", id)
	op, err := p.ab.Delete(asUser(p.ctx, p.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "SC-66: снятие (б) перед (в), (г)")
	require.Nil(t, awaitOp(t, p.ctx, p.ops, op.GetId()).Error, "SC-66: снятие (б)")

	// (в) 16 минут — отказ SESSION_NOT_FRESH; (г) 14 минут — принято.
	seedPresentedSession(t, p.scWorld, p.usrA, 16*time.Minute)
	_, err = p.ab.Create(asUser(p.ctx, p.usrA), p.pchRequest())
	require.Error(t, err, "SC-66 (в): несвежая сессия")
	st := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, st.Code(), "SC-66 (в): код (текст %q)", st.Message())
	var reasons []string
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			reasons = append(reasons, ei.GetReason())
		}
	}
	require.Contains(t, reasons, "SESSION_NOT_FRESH", "SC-66 (в): причина")
	seedPresentedSession(t, p.scWorld, p.usrA, 14*time.Minute)
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-66 (г): 14 минут")

	// (д) сессия уровня «1» — PERMISSION_DENIED, PreconditionFailure authz.step_up
	// (пол службы, форма SC-26). Близнец — SC-60 (уровень «2»), принят выше в (г).
	const fqn = "/kaname.cloud.iam.v1.AccessBindingService/Create"
	floor := authzguard.NewACRFloor(scCreateFloorLookup{}, []string{fqn}).WithProductionMode(true)
	ctx := grpcsrv.WithCertIdentityIn(asUser(p.ctx, p.usrA), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway", true)
	ctx = grpcsrv.WithTrustedPrincipal(ctx, operations.Principal{Type: "user", ID: string(p.usrA)}, true)
	ctx = grpcsrv.WithTrustedACR(ctx, "1", true)
	_, err = floor.Unary()(ctx, p.pchRequest(), &grpc.UnaryServerInfo{FullMethod: fqn},
		func(ctx context.Context, req any) (any, error) {
			return p.ab.Create(ctx, req.(*iamv1.CreateAccessBindingRequest))
		})
	requireSyncRefusal(t, err, codes.PermissionDenied, "permission denied", "SC-66 (д)")
	var violations []string
	for _, d := range status.Convert(err).Details() {
		if pf, ok := d.(*errdetails.PreconditionFailure); ok {
			for _, v := range pf.GetViolations() {
				violations = append(violations, v.GetType()+"|"+v.GetSubject()+"|"+v.GetDescription())
			}
		}
	}
	assert.Equal(t, []string{"authz.step_up|acr_values:2|insufficient_user_authentication: higher ACR required"}, violations,
		"SC-66 (д): форма отказа пола")
}

// TestPublicContainerRead_SC67_PerRepositoryPublicationWorksAsBefore — SC-67:
// поштучная публикация репозитория (`user:*` + v_get через RegisterResource)
// открывает только сам репозиторий и только на v_get. Близнец — тот же
// репозиторий без публикации.
func TestPublicContainerRead_SC67_PerRepositoryPublicationWorksAsBefore(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-67")
	p.registerRepository(pcrY, "pub")
	p.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrYPub, false, "SC-67 близнец: без публикации")

	require.NoError(t, p.reg.Register(p.ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "user:*", Relation: "v_get", Object: pcrRepoType + ":" + pcrYPub,
	}), "SC-67: публикация репозитория владельцем")
	p.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrYPub, true, "SC-67: публикация открывает репозиторий")
	p.requireAsk(pcrAnon, "v_list", pcrRepoType, pcrYPub, false, "SC-67: только v_get")
	p.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrYApp, false, "SC-67: только сам репозиторий")
	p.requireAsk(pcrAnon, "v_get", pcrRegType, pcrY, false, "SC-67: реестр не открыт")
}

// TestPublicContainerRead_SC69_AuthenticatedGrantOpensToSignedInOnly — SC-69:
// выдача `authenticated` открывает контейнер вошедшим (принципалы acc-B) и не
// открывает анониму. Близнец — SC-60: та же выдача анониму. Отличие — класс.
func TestPublicContainerRead_SC69_AuthenticatedGrantOpensToSignedInOnly(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("SC-69")
	req := p.pchRequest()
	req.Subjects = []*iamv1.Subject{classSubject("authenticated")}
	p.createDone(asUser(p.ctx, p.usrA), req, "SC-69: выдача ПЧ классу authenticated")

	for _, subject := range []string{fmtSubject("user", string(p.usrC)), fmtSubject("service_account", p.svaB)} {
		for _, rel := range []string{"v_get", "v_list"} {
			p.pollAsk(subject, rel, pcrRepoType, pcrXApp, true, "SC-69: вошедший "+subject)
		}
	}
	for _, rel := range []string{"v_get", "v_list"} {
		p.requireAsk(pcrAnon, rel, pcrRepoType, pcrXApp, false, "SC-69: анониму не открыто")
	}
	// Сужение (SC-68, kaname#857): Y и его репозиторий вошедшему не открыты.
	p.requireAsk(fmtSubject("user", string(p.usrC)), "v_get", pcrRegType, pcrY, false, "SC-69: Y вне цели")
	p.requireAsk(fmtSubject("user", string(p.usrC)), "v_get", pcrRepoType, pcrYApp, false, "SC-69: Y/app вне цели")

	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-69 близнец: SC-60, выдача анониму")
	p.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SC-69 близнец: анониму открыто выдачей анониму")
}

// TestPublicContainerRead_SC70_a_PriorEditionRefusesThePublicGrant — SC-70 (а),
// служебная половина: со стартом на манифесте прежней редакции роли
// `registry.public.read` нет, и выдача ПЧ синхронно отвергается сегодняшним
// текстом (`create.go`). Близнец — (б): после доставки новой редакции та же
// выдача принята. Сборочная половина SC-70 — `internal/modelcompose`.
func TestPublicContainerRead_SC70_a_PriorEditionRefusesThePublicGrant(t *testing.T) {
	p := newPCRWorld(t)
	_, err := p.ab.Create(asUser(p.ctx, p.usrA), p.pchRequest())
	requireSyncRefusal(t, err, codes.FailedPrecondition,
		"Role "+publicreadfixture.PublicReadRoleID+" not found", "SC-70 (а): роль ещё не доставлена")

	p.deliverNewEdition("SC-70 (б)")
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "SC-70 (б): после доставки новой редакции выдача ПЧ принята")
}
