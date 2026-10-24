// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_reregister_world_integration_test.go — снятие регистрации объекта
// снимает его выдачи (PRO-Robotech/kaname#963).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ключ объекта модуля освобождается: у реестра registry-operator идентификатор —
// его ИМЯ, и после снятия регистрации тот же ключ может зарегистрировать
// заново другой владелец. Выдача, сделанная на прежний объект (цель «названные
// объекты» с этим ключом), к новому переходить НЕ должна: новый объект
// начинается с пустого набора выдач. Выдача, сделанная ПОСЛЕ повторной
// регистрации, действует как обычно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВОПРОС ЗАДАЁТСЯ ДВЕРИ РЕШЕНИЯ, А НЕ РЕЕСТРУ КОРТЕЖЕЙ
//
// Решение о доступе выводится не только из материализованных кортежей: ветвь
// выдач (`relverdict`, `grantarm.go`) читает саму привязку — её цель и правила
// роли — и цепь объекта. Снять материализованное мало, если ветвь выдач заново
// находит привязку, называющую освободившийся ключ. Поэтому исход судится
// `AuthorizeService.Check` — тем значением, которое получает модуль.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОРЯДОК НЕСУЩИЙ
//
//  1. мир П6 (`newPCRWorld`): реестр X в prj-A, выдача `rol-reg-get` человеку
//     usr-B на X — и положительный контроль фикстуры (usr-B читает X);
//  2. регистрация снята ровно так, как снимает владелец (`Unregister` указателя
//     области), с провязкой use-case как у корня службы;
//  3. контроль снятия: usr-B больше не читает X — иначе красное ниже было бы о
//     другом дефекте (снятие не сработало вовсе);
//  4. тот же ключ зарегистрирован заново ДРУГИМ владельцем (usr-C) в той же
//     области — контроль живости: новый владелец читает новый X;
//  5. предмет: прежняя выдача не достаёт до нового X — сразу после регистрации
//     и после перерасчёта (проход по объекту и проход по привязке).
//
// Близнец (`…GrantMadeAfterReRegistrationReaches`) отличается ОДНИМ фактом:
// выдача сделана после повторной регистрации, и она действует.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// urWorld — П6 с провязкой регистрации как у корня службы и версиями владельца.
type urWorld struct {
	*pcrWorld
	ver time.Time // последняя версия источника, которую ставил владелец
}

// newURWorld поднимает П6 и довязывает use-case регистрации тем, что корень
// службы (`cmd/kaname/wiring.go`) ставит сверх П6: событие перерасчёта в той же
// транзакции, разрешение аккаунта по проекту и читатель остатка отношений
// снимаемого объекта.
func newURWorld(t *testing.T) *urWorld {
	t.Helper()
	p := newPCRWorld(t)
	p.reg = p.reg.
		WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver()).
		WithResidualTupleReader(kanamepg.NewResidualTupleReader(p.pool))
	return &urWorld{pcrWorld: p, ver: time.Now()}
}

// nextVersion — монотонная версия владельца: каждое следующее намерение новее.
func (w *urWorld) nextVersion() *timestamppb.Timestamp {
	w.ver = w.ver.Add(time.Second)
	return timestamppb.New(w.ver)
}

// withdrawX — снятие регистрации реестра X владельцем: указатель области с
// версией-надгробием. Остальное на объекте (владелец объекта) снимает читатель
// остатка — так, как в боевой посадке.
func (w *urWorld) withdrawX() {
	w.t.Helper()
	require.NoError(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId:     "project:" + string(w.prjA),
		Relation:      "project",
		Object:        pcrRegType + ":" + pcrX,
		SourceVersion: w.nextVersion(),
	}), "снятие регистрации реестра X")
}

// reRegisterX — тот же ключ X зарегистрирован заново в той же области, владелец
// объекта — `owner`.
//
// Версия — СВОЯ у каждого намерения. Два намерения с одной версией use-case
// читает как повторную доставку одного: второе не меняет строку зеркала, и его
// кортеж не ставится (ворота повторной доставки в `Register`). Тогда владелец
// объекта не получил бы `owner`, и контроль живости ниже краснел бы по фикстуре.
func (w *urWorld) reRegisterX(owner domain.UserID) {
	w.t.Helper()
	obj := pcrRegType + ":" + pcrX
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(w.prjA), Relation: "project", Object: obj},
		{SubjectId: "user:" + string(owner), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{"project:" + string(w.prjA), "account:" + string(w.accA)}
		r.SourceVersion = w.nextVersion()
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "повторная регистрация реестра X (%s)", r.GetRelation())
	}
}

// recompute — перерасчёт тем, чем его делает служба: проход по объекту (событие
// зеркала) и проход по привязке (периодический обход).
func (w *urWorld) recompute(bindingIDs ...string) {
	w.t.Helper()
	require.NoError(w.t, w.rec.ReconcileObject(w.ctx, pcrRegTgt, pcrX), "перерасчёт по объекту X")
	for _, id := range bindingIDs {
		require.NoErrorf(w.t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)), "перерасчёт привязки %s", id)
	}
}

// reachX — сцена до предмета: выдача usr-B на X действует, регистрация снята,
// выдача перестала действовать, ключ занят заново владельцем usr-C.
func (w *urWorld) reachX() {
	w.t.Helper()
	usrB := fmtSubject("user", string(w.usrB))
	// Шаг 1 — контроль фикстуры: newPCRWorld уже дождался v_get, здесь
	// повторяется мгновенным вопросом, чтобы сцена не зависела от его порядка.
	w.requireAsk(usrB, "v_get", pcrRegType, pcrX, true,
		"контроль фикстуры: выдача rol-reg-get человеку usr-B на X действует до снятия")

	// Шаг 2–3 — снятие и его контроль.
	w.withdrawX()
	w.pollAsk(usrB, "v_get", pcrRegType, pcrX, false,
		"контроль снятия: после снятия регистрации X человек usr-B всё ещё читает X")

	// Шаг 4 — ключ занят заново ДРУГИМ владельцем; контроль живости нового объекта.
	w.reRegisterX(w.usrC)
	w.pollAsk(fmtSubject("user", string(w.usrC)), "v_get", pcrRegType, pcrX, true,
		"контроль живости: новый владелец usr-C не читает повторно зарегистрированный X")
}

// TestUnregister_GrantOnFormerObjectDoesNotReachReRegisteredKey — прежняя выдача
// не переходит к объекту, занявшему освободившийся ключ.
func TestUnregister_GrantOnFormerObjectDoesNotReachReRegisteredKey(t *testing.T) {
	w := newURWorld(t)
	w.reachX()
	usrB := fmtSubject("user", string(w.usrB))

	// Предмет, сразу после повторной регистрации (её синхронный проход уже был).
	assert.False(t, w.ask(usrB, "v_get", pcrRegType, pcrX),
		"kaname#963: выдача, сделанная на ПРЕЖНИЙ объект X, достаёт до объекта, заново "+
			"занявшего ключ X, — человек usr-B читает чужой реестр")

	// Предмет, после перерасчёта: ни проход по объекту, ни проход по привязке не
	// воскрешают прежних отношений.
	w.recompute(w.grantB)
	assert.False(t, w.ask(usrB, "v_get", pcrRegType, pcrX),
		"kaname#963: перерасчёт после повторной регистрации вернул прежней выдаче "+
			"доступ к объекту, заново занявшему ключ X")
}

// TestUnregister_GrantMadeAfterReRegistrationReaches — близнец: выдача, сделанная
// ПОСЛЕ повторной регистрации, действует, в том числе после перерасчёта.
func TestUnregister_GrantMadeAfterReRegistrationReaches(t *testing.T) {
	w := newURWorld(t)
	w.reachX()
	usrD := fmtSubject("user", string(w.usrD))

	// До выдачи у usr-D доступа нет — иначе «allow» ниже не о выдаче.
	w.requireAsk(usrD, "v_get", pcrRegType, pcrX, false,
		"контроль близнеца: usr-D читает X без выдачи")

	id := w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, pcrXTarget()),
		"kaname#963 близнец: выдача rol-reg-get человеку usr-D на повторно зарегистрированный X")
	w.pollAsk(usrD, "v_get", pcrRegType, pcrX, true,
		"kaname#963 близнец: выдача, сделанная после повторной регистрации, не действует")

	w.recompute(id)
	w.requireAsk(usrD, "v_get", pcrRegType, pcrX, true,
		"kaname#963 близнец: перерасчёт снял выдачу, сделанную после повторной регистрации")
}
