// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_ce_integration_test.go — пробы на условия разбора классов к
// приёмке делегированных выдач (PRO-Robotech/kaname#986), которые сценарии
// приёмки не держат: запись разбора
// docs/specs/reviews/delegated-grants-stay-within-the-delegation-class-exposure/initial/43622b18….md,
// заказы «Заказы (адресат · предмет · основание)». CE-09 — в файле группы G.
//
// CE-01 и CE-02 испытуемым имеют не службу делегирования, а ПЕРЕЕЗД вопроса
// двери в обработчик (Р1а): они краснеют до реализации тем, что use-case
// отзыва принимает субъекта, которого дверь сегодня отвергла бы, — вопроса
// `v_delete` в обработчике нет. Службы делегирования они не спрашивают.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ce01World — мир CE-01: sva-A2 держит `admin` на prj-A (право выдавать по
// Пути 2), но не держит `v_delete` на объекте выдачи: `project.super_admin`
// выводится только из аккаунта и кластера (разбор классов, «Чего измерить
// нельзя» п.1), а прямой факт на проекте пообъектной материализации не даёт.
type ce01World struct {
	*gdWorld
	bo, bo2 string
}

func newCE01World(t *testing.T) *ce01World {
	t.Helper()
	w := newGDWorld(t)
	c := &ce01World{gdWorld: w}
	gdSeedTuple(t, w.ctx, w.pool, "service_account:"+w.svaA2, "admin", "project:"+string(w.prjA))
	w.pollRelation("service_account:"+w.svaA2, "admin", "project:"+string(w.prjA), true,
		"CE-01 контроль: sva-A2 держит admin на prj-A")
	// Контроль права выдавать: sva-A2 заводит выдачу на prj-A.
	w.createDoneX(asSA(w.ctx, w.svaA2), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{svaSubject(w.svaA)}
	}), "CE-01 контроль: sva-A2 проходит право выдавать на prj-A")
	c.bo = w.boOf()
	c.bo2 = w.createDoneX(asUser(w.ctx, w.usrA), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolRegAdmin), []*iamv1.Subject{svaSubject(w.svaA3)}
	}), "CE-01 Дано: Bo2 от usr-A")
	for _, id := range []string{c.bo, c.bo2} {
		w.requireRelation("service_account:"+w.svaA2, "v_delete", "iam_access_binding:"+id, false,
			"CE-01 контроль: у sva-A2 нет v_delete на объекте выдачи")
		w.pollRelation("user:"+string(w.usrA), "v_delete", "iam_access_binding:"+id, true,
			"CE-01 контроль: у usr-A есть v_delete на объекте выдачи")
	}
	return c
}

// CE-01 — субъект с правом выдавать, но без `v_delete` на объекте выдачи:
// отзыв и удаление отвергаются и после снятия двери (Р1а, вопрос двери
// переезжает в обработчик дословно); близнец — владелец с `v_delete`.
func TestGrantDelegation_CE01_GrantAuthorityWithoutVDeleteCannotRevokeOrDelete(t *testing.T) {
	c := newCE01World(t)
	_, err := c.revokeBinding(asSA(c.ctx, c.svaA2), c.bo)
	requireRefusal(t, err, codes.PermissionDenied, "permission denied",
		"CE-01 Revoke: субъект без v_delete на объекте выдачи (вопроса v_delete в обработчике нет)")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, c.getBinding(c.bo).GetStatus(), "CE-01 Revoke: Bo действует")
	_, err = c.deleteBinding(asSA(c.ctx, c.svaA2), c.bo2)
	requireRefusal(t, err, codes.PermissionDenied, "permission denied",
		"CE-01 Delete: субъект без v_delete на объекте выдачи (вопроса v_delete в обработчике нет)")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, c.getBinding(c.bo2).GetStatus(), "CE-01 Delete: Bo2 действует")

	// Близнец — тот же глагол от владельца, держащего v_delete.
	op, err := c.revokeBinding(asUser(c.ctx, c.usrA), c.bo)
	c.requireVerbDone(op.GetId(), err, "CE-01 близнец: владелец отзывает Bo")
}

// ceFailOn — порт отношений, отказывающий ошибкой на вопросе об одном
// отношении; прочие вопросы — настоящей двери решения.
type ceFailOn struct {
	inner    clients.RelationStore
	relation string
	hits     int
}

func (f *ceFailOn) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if relation == f.relation {
		f.hits++
		return false, errors.New("инъекция: хранилище отношений не ответило")
	}
	return f.inner.Check(ctx, subject, relation, object)
}

// CE-02 — у вопроса `v_delete` в обработчике три исхода: ошибка хранилища —
// `UNAVAILABLE` `authz backend unavailable`, не отказ и не делегированный путь.
func TestGrantDelegation_CE02_VDeleteQuestionOutageIsUnavailable(t *testing.T) {
	w := newGDWorld(t)
	bo := w.boOf()
	twinBinding := w.createDoneX(asUser(w.ctx, w.usrA), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolRegAdmin), []*iamv1.Subject{svaSubject(w.svaA3)}
	}), "CE-02 Дано: выдача близнеца")

	fail := &ceFailOn{inner: w.door, relation: "v_delete"}
	_, revoke, _ := w.newGrantVerbs(w.ops)
	revoke = revoke.WithRelationStore(fail, nil)
	op, err := revoke.Execute(asUser(w.ctx, w.usrA), domain.AccessBindingID(bo))
	if err == nil {
		awaitOp(t, w.ctx, w.ops, op.ID)
	}
	t.Logf("CE-02: вопросов v_delete к хранилищу — %d", fail.hits)
	requireRefusal(t, err, codes.Unavailable, "authz backend unavailable",
		"CE-02: ошибка хранилища на вопросе v_delete (вопроса v_delete в обработчике нет — отзыв прошёл)")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.getBinding(bo).GetStatus(), "CE-02: Bo действует")

	// Близнец — тот же отзыв при отвечающем хранилище.
	w.awaitRemovalRight(w.usrA, twinBinding, "CE-02 близнец Дано: у владельца v_delete на выдаче близнеца")
	op2, err := w.revokeBinding(asUser(w.ctx, w.usrA), twinBinding)
	w.requireVerbDone(op2.GetId(), err, "CE-02 близнец: хранилище отвечает")
}

// CE-03 — четвёртый путь не открывает делегату `ExpandAccess` и `ListByRole`;
// близнец — те же вызовы от владельца.
func TestGrantDelegation_CE03_DelegatePathStaysOutOfExpandAccessAndListByRole(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-03")
	d1 := w.d1()
	b10 := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "CE-03 Дано: B10")
	w.requireDelegatedBinding(b10, d1, "CE-03 Дано: B10")
	w.pollAsk(fmtSubject("service_account", w.svaA), "v_get", pcrRegType, pcrX, true, "CE-03 Дано: B10 материализована")

	expand := func(ctx context.Context) (*iamv1.ExpandAccessResponse, error) {
		return w.abx.ExpandAccess(ctx, &iamv1.ExpandAccessRequest{ObjectType: "account", ObjectId: string(w.accA), Relation: "admin"})
	}
	byRole := func(ctx context.Context) (*iamv1.ListAccessBindingsResponse, error) {
		return w.abx.ListByRole(ctx, &iamv1.ListAccessBindingsByRoleRequest{RoleId: string(w.rolPusher), PageSize: 1000})
	}
	// Близнец.
	er, err := expand(asUser(w.ctx, w.usrA))
	require.NoError(t, err, "CE-03 близнец: ExpandAccess от usr-A")
	require.NotEmpty(t, er.GetPrincipals(), "CE-03 близнец: ExpandAccess от usr-A пуст")
	lr, err := byRole(asUser(w.ctx, w.usrA))
	require.NoError(t, err, "CE-03 близнец: ListByRole от usr-A")
	require.True(t, bindingIn(lr.GetAccessBindings(), b10), "CE-03 близнец: ListByRole от usr-A без B10")

	er, err = expand(asSA(w.ctx, w.svaIss))
	assert.Truef(t, err != nil || len(er.GetPrincipals()) == 0,
		"CE-03: ExpandAccess от делегата отдал принципалов %v", er.GetPrincipals())
	lr, err = byRole(asSA(w.ctx, w.svaIss))
	assert.Truef(t, err != nil || !bindingIn(lr.GetAccessBindings(), b10), "CE-03: ListByRole от делегата отдал B10")
}

func bindingIn(xs []*iamv1.AccessBinding, id string) bool {
	for _, b := range xs {
		if b.GetId() == id {
			return true
		}
	}
	return false
}

// CE-05 — оси субъекта проверяются у КАЖДОГО элемента `subjects`, а не у
// проекции `subjects[0]`; близнец — оба субъекта из аккаунта делегирования.
func TestGrantDelegation_CE05_EverySubjectOfAMultiSubjectGrantIsChecked(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-05")
	d1 := w.d1()
	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA), svaSubject(w.svaB)}
	})), "CE-05: второй субъект — учётка acc-B")
	id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA), svaSubject(w.svaA2)}
	})), "CE-05 близнец: оба субъекта из acc-A")
	w.requireDelegatedBinding(id, d1, "CE-05 близнец")
}

// CE-10 — отзыв делегирования снимает выпущенное: прямых фактов субъекта
// выдачи на объекте после отзыва нет (а не только «строка REVOKED»).
func TestGrantDelegation_CE10_DelegationRevokeRemovesEmittedFacts(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-10")
	d1 := w.d1()
	requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "CE-10 Дано: B10")
	subject := fmtSubject("service_account", w.svaA)
	w.pollAsk(subject, "v_get", pcrRegType, pcrX, true, "CE-10 Дано: B10 материализована")
	before := w.directFacts(subject, pcrRegType, pcrX)
	t.Logf("CE-10: прямых фактов sva-A на X до отзыва — %d", before)
	require.Positive(t, before, "CE-10 контроль: выдача registry выпускает прямые факты — без них утверждение ниже вакуумно")

	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "CE-10")
	deadline := time.Now().Add(30 * time.Second)
	for w.directFacts(subject, pcrRegType, pcrX) > 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	assert.Zero(t, w.directFacts(subject, pcrRegType, pcrX), "CE-10: прямые факты sva-A на X пережили отзыв делегирования")
}

// CE-15 — `delegationId` читает единая проекция: он есть и в перечне, а не только в Get.
func TestGrantDelegation_CE15_ListCarriesTheDelegationReference(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-15")
	d1 := w.d1()
	b10 := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "CE-15 Дано: B10")
	resp, err := w.abx.ListBySubject(asUser(w.ctx, w.usrA), &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "service_account", SubjectId: w.svaA, PageSize: 1000})
	require.NoError(t, err, "CE-15: ListBySubject sva-A")
	var found bool
	for _, b := range resp.GetAccessBindings() {
		if b.GetId() != b10 {
			continue
		}
		found = true
		got, ok := delegationIDOf(t, b)
		assert.True(t, ok, "CE-15: у B10 в перечне ключа delegationId нет")
		assert.Equal(t, d1, got, "CE-15: delegationId B10 в перечне")
	}
	require.True(t, found, "CE-15: B10 нет в перечне выдач sva-A")
}

// CE-16 — `delegation_id` в строке аудита удаления (Delete) берётся из строки
// выдачи, как у отзыва.
func TestGrantDelegation_CE16_DeleteAuditCarriesTheDelegationReference(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-16")
	d1 := w.d1()
	b10 := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "CE-16 Дано: B10")
	opID, err := w.deleteBinding(asSA(w.ctx, w.svaIss), b10)
	w.requireVerbDone(opID, err, "CE-16: делегат удаляет B10")
	got := findAudit(w.auditRows(), "iam.access_binding.revoked", b10)
	require.Len(t, got, 1, "CE-16: строк iam.access_binding.revoked у удалённой B10")
	assert.Equal(t, d1, got[0].payload["delegation_id"], "CE-16: delegation_id")
	assert.Equal(t, w.svaIss, fmt.Sprint(got[0].payload["actor"]), "CE-16: actor")
}

// ceFailFor — порт отношений, отказывающий ошибкой на любом вопросе об одном
// субъекте; прочие вопросы — настоящей двери решения. Обе формы вопроса —
// одиночная и партийная: проверка права выдавать на областях спрашивает ярус
// партией, и дублёр, отвечающий только на одиночный, инъекцию бы не донёс.
// Партии одного вопроса идут параллельно, поэтому счёт — под замком.
type ceFailFor struct {
	inner   accessbindingapp.GrantAuthorityRelations
	subject string
	mu      sync.Mutex
	hits    int
}

func (f *ceFailFor) hit() {
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()
}

func (f *ceFailFor) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if subject == f.subject {
		f.hit()
		return false, errors.New("инъекция: хранилище отношений не ответило")
	}
	return f.inner.Check(ctx, subject, relation, object)
}

func (f *ceFailFor) BatchCheckWithContext(ctx context.Context, subject, relation string, objects []string,
	condCtx map[string]any) ([]bool, error) {
	if subject == f.subject {
		f.hit()
		return nil, errors.New("инъекция: хранилище отношений не ответило")
	}
	return f.inner.BatchCheckWithContext(ctx, subject, relation, objects, condCtx)
}

// CE-06 — у вопроса о праве делегирующего (Д3) три исхода: неполадка хранилища —
// `UNAVAILABLE` `authz backend unavailable`, а не отказ в праве и не выдача.
// Делегирующий — usr-E (Путь 2, вопрос к модели); близнец — тот же вызов при
// отвечающем хранилище.
func TestGrantDelegation_CE06_DelegatorAuthorityOutageIsUnavailable(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-06")
	w.createDelegation(asUser(w.ctx, w.usrE), w.d1Body(w.svaIss2), "CE-06 Дано: D-E от usr-E")

	fail := &ceFailFor{inner: w.door, subject: "user:" + string(w.usrE)}
	create, _, _ := w.newGrantVerbs(w.ops)
	create.WithDelegatedGrantPath(accessbindingapp.NewDelegatedGrantPath(w.repo, fail))
	h := accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	op, err := h.Create(asSA(w.ctx, w.svaIss2), w.v())
	t.Logf("CE-06: вопросов о субъекте usr-E к хранилищу — %d", fail.hits)
	require.Nilf(t, op, "CE-06: выдача заведена при неотвечающем хранилище")
	requireRefusal(t, err, codes.Unavailable, "authz backend unavailable",
		"CE-06: неполадка на вопросе о праве делегирующего")
	require.Positive(t, fail.hits, "CE-06 контроль: вопрос о праве делегирующего не задан — инъекция вакуумна")

	// Близнец — хранилище отвечает.
	requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss2), w.v()), "CE-06 близнец: хранилище отвечает")
}

// CE-13 — делегирование не меняет исход удаления аккаунта (§2 п.6 приёмки):
// ссылка `grant_delegations.account_id` внешнего ключа не несёт, охрана
// удаления аккаунта делегирований не называет. Близнец — такой же аккаунт без
// делегирования; исходы сравниваются кодом и текстом (с id аккаунта, заменённым
// меткой), а не «оба прошли».
func TestGrantDelegation_CE13_AccountDeleteOutcomeIsUnchangedByADelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-13")
	del := accountapp.NewDeleteAccountUseCase(w.repo, w.ops)
	outcome := func(withDelegation bool, tag string) string {
		owner := mustSeedUser(t, w.ctx, w.pool, "ce13"+tag)
		verifyAddresses(t, w.ctx, w.pool)
		acc := seedAccountByOwner(t, w.ctx, w.pool, "acc-ce13-"+tag, owner)
		if withDelegation {
			w.createDelegation(asUser(w.ctx, owner), w.delegationBody(acc, w.svaIss,
				[]domain.RoleID{w.rolPuller}, []string{"registry.registries"}, []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}),
				"CE-13 Дано: делегирование на аккаунт "+tag)
		}
		op, err := del.Execute(asUser(w.ctx, owner), acc)
		if err != nil {
			st, _ := status.FromError(err)
			return fmt.Sprintf("sync %v %s", st.Code(), strings.ReplaceAll(st.Message(), string(acc), "<acc>"))
		}
		done := awaitOp(t, w.ctx, w.ops, op.ID)
		if done.Error != nil {
			return fmt.Sprintf("op %v %s", codes.Code(done.Error.Code), strings.ReplaceAll(done.Error.Message, string(acc), "<acc>"))
		}
		return "done"
	}
	with := outcome(true, "d")
	without := outcome(false, "n")
	t.Logf("CE-13: удаление аккаунта с делегированием — %s; без делегирования — %s", with, without)
	assert.Equal(t, without, with, "CE-13: делегирование изменило исход удаления аккаунта")
}
