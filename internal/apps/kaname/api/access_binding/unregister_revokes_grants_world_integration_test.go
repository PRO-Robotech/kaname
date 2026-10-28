// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_revokes_grants_world_integration_test.go — держатели сценариев приёмки
// docs/engineering/acceptance/unregistration-revokes-its-grants.md (редакция 2,
// отпечаток 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4;
// задача PRO-Robotech/kaname#963): группы A, B, C, E, F, F3, H и I (URG-33, URG-34
// для путей глагола и срока). Конкуренция (группа G) — соседний файл
// `unregister_race_world_integration_test.go`, имена вложенного правила (F2) —
// `unregister_nested_names_world_integration_test.go`, строка, отозванная до
// миграции (URG-34, R0), — проба наката в `internal/migrations`.
//
// Мир — У приёмки (`newURWorld` пробы kaname#963 поверх П6) с дополнениями раздела «Мир
// проб»: реестр Z, никогда не регистрируемый ключ Q, роли с названиями. Чтения —
// теми частями, что корень службы: `AccessBindingService.Get/List/ListSubjectPrivileges/
// ExpandAccess/Revoke`, `AuthorizeService.Check`. Роль читается строкой хранилища
// (`Roles().Get`) — тем же чтением, которым её отдаёт `RoleService.Get`: решение о
// видимости пользовательской роли в мире не материализовано, и вопрос «чем роль
// стала» от него не зависит.

import (
	"context"
	"encoding/json"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ключи мира проб: Z регистрируется дополнительно, Q — никогда.
const (
	urZ = "reg00000000000000003"
	urQ = "reg00000000000000009"
)

// urxWorld — мир У приёмки с полным набором чтений выдачи.
type urxWorld struct {
	*urWorld
	abx   *accessbindingapp.Handler
	verMu sync.Mutex // версия владельца из параллельных горутин снятия
}

// newURXWorld поднимает мир У, регистрирует Z и провязывает чтения.
func newURXWorld(t *testing.T) *urxWorld {
	t.Helper()
	w := &urxWorld{urWorld: newURWorld(t)}
	w.registerRegistry(urZ)
	// Структурные факты, которые создание аккаунта и проекта кладёт в боевой
	// посадке: владелец аккаунта и указатель проекта на аккаунт. Мир П6 сеет
	// аккаунт и проект строками, без них у usr-A нет права администрировать
	// объекты аккаунта (`project.super_admin: admin from account`, `account.admin:
	// … or owner`), и ExpandAccess/List отвечали бы отказом о фикстуре, а не о
	// предмете.
	_, err := w.pool.Exec(w.ctx,
		`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		 VALUES ('account', $1, 'owner', 'user:' || $2),
		        ('project', $3, 'account', 'account:' || $1)
		 ON CONFLICT DO NOTHING`, string(w.accA), string(w.usrA), string(w.prjA))
	require.NoError(t, err, "мир У: структурные факты аккаунта и проекта")
	w.rewire()
	return w
}

// rewire — обработчик выдач с чтениями и отзывом поверх ТЕКУЩЕГО каталожного факта
// мира. Доставка манифеста (`applyDelivered`) пересобирает `ab`, поэтому после неё
// зовётся снова.
func (w *urxWorld) rewire() {
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, pcrFacts{w.pcrWorld}).
		WithRelationStore(w.door, nil).
		WithReconciler(w.rec).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	del := accessbindingapp.NewDeleteAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
	lsp := accessbindingapp.NewListSubjectPrivilegesUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	list := accessbindingapp.NewListUseCase(w.repo).WithRelationStore(w.door).WithRelationQueries(w.door)
	expand := accessbindingapp.NewExpandAccessUseCase(w.door).WithGrantAuthority(w.repo, w.door, nil)
	revoke := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).WithRelationStore(w.door, nil)
	w.abx = accessbindingapp.NewHandler(create, del, get, nil, nil, nil, lsp).
		WithList(list).WithExpandAccess(expand).WithRevoke(revoke)
	w.ab = w.abx
}

// target — цель «названные объекты» из реестров с данными id (в порядке подачи).
func urTarget(regs ...string) *iamv1.AccessTarget {
	refs := make([]*iamv1.ResourceRef, 0, len(regs))
	for _, id := range regs {
		refs = append(refs, &iamv1.ResourceRef{Type: pcrRegTgt, Id: id})
	}
	return resourcesTarget(refs...)
}

// grantTo — выдача `role` человеку `who` на prj-A, доведённая до done.
func (w *urxWorld) grantTo(who domain.UserID, role domain.RoleID, target *iamv1.AccessTarget, protect bool, why string) string {
	w.t.Helper()
	req := w.grantRequest(userSubject(who), role, target)
	req.DeletionProtection = protect
	return w.createDone(asUser(w.ctx, w.usrA), req, why)
}

// withdraw — снятие регистрации реестра `id` владельцем, своей версией.
func (w *urxWorld) withdraw(ctx context.Context, id string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.withdrawErr(ctx, id), "снятие регистрации реестра %s", id)
}

// withdrawErr — то же без утверждения: годно в горутине пробы гонки.
func (w *urxWorld) withdrawErr(ctx context.Context, id string) error {
	w.verMu.Lock()
	ver := w.nextVersion()
	w.verMu.Unlock()
	return w.reg.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId:     "project:" + string(w.prjA),
		Relation:      "project",
		Object:        pcrRegType + ":" + id,
		SourceVersion: ver,
	})
}

// get — `AccessBindingService.Get` от имени usr-A.
func (w *urxWorld) get(id string) *iamv1.AccessBinding {
	w.t.Helper()
	b, err := w.abx.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoErrorf(w.t, err, "Get(%s)", id)
	return b
}

// targetIDs — id объектов цели в порядке хранения.
func targetIDs(b *iamv1.AccessBinding) []string {
	var out []string
	for _, r := range b.GetTarget().GetResources().GetResources() {
		out = append(out, r.GetType()+"/"+r.GetId())
	}
	return out
}

func regRefs(ids ...string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, pcrRegTgt+"/"+id)
	}
	return out
}

// listIDs — id выдач субъекта в `List` (с отозванными или без) от имени usr-A.
func (w *urxWorld) listIDs(who domain.UserID, includeRevoked bool) map[string]*iamv1.AccessBinding {
	w.t.Helper()
	resp, err := w.abx.List(asUser(w.ctx, w.usrA), &iamv1.ListAccessBindingsRequest{
		Filter:         fmt.Sprintf(`subject="%s"`, who),
		IncludeRevoked: includeRevoked,
		PageSize:       100,
	})
	require.NoErrorf(w.t, err, "List(subject=%s, includeRevoked=%v)", who, includeRevoked)
	out := map[string]*iamv1.AccessBinding{}
	for _, b := range resp.GetAccessBindings() {
		out[b.GetId()] = b
	}
	return out
}

// privilegeBindings — id выдач в `ListSubjectPrivileges` человека (самого себя).
func (w *urxWorld) privilegeBindings(who domain.UserID) []string {
	w.t.Helper()
	resp, err := w.abx.ListSubjectPrivileges(asUser(w.ctx, who), &iamv1.ListSubjectPrivilegesRequest{
		SubjectType: "user", SubjectId: string(who), PageSize: 100,
	})
	require.NoErrorf(w.t, err, "ListSubjectPrivileges(%s)", who)
	var out []string
	for _, p := range resp.GetPrivileges() {
		out = append(out, p.GetBindingId())
	}
	return out
}

// expandUsers — люди в `ExpandAccess(X, v_get)` от имени usr-A (владелец acc-A).
func (w *urxWorld) expandUsers(id string) []string {
	w.t.Helper()
	resp, err := w.abx.ExpandAccess(asUser(w.ctx, w.usrA), &iamv1.ExpandAccessRequest{
		ObjectType: pcrRegType, ObjectId: id, Relation: "v_get",
	})
	require.NoErrorf(w.t, err, "ExpandAccess(%s)", id)
	var out []string
	for _, p := range resp.GetPrincipals() {
		out = append(out, p.GetId())
	}
	return out
}

// roleRules — правила роли строкой хранилища.
func (w *urxWorld) roleRules(id domain.RoleID) domain.Rules {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	r, err := rd.Roles().Get(w.ctx, id)
	require.NoErrorf(w.t, err, "роль %s", id)
	return r.Rules
}

// namesRule — правило чтения реестров, суженное названиями.
func namesRule(ids ...string) domain.Rule {
	return domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, ResourceNames: ids}
}

// auditCount — строки аудита данного типа, где поле полезной нагрузки равно value.
func (w *urxWorld) auditCount(eventType, field, value string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = $1 AND event_payload->>$2 = $3`,
		eventType, field, value).Scan(&n))
	return n
}

// auditPayload — полезная нагрузка единственной строки аудита данного типа по полю.
func (w *urxWorld) auditPayload(eventType, field, value string) map[string]any {
	w.t.Helper()
	var raw []byte
	require.NoErrorf(w.t, w.pool.QueryRow(w.ctx,
		`SELECT event_payload FROM kaname.audit_outbox WHERE event_type = $1 AND event_payload->>$2 = $3`,
		eventType, field, value).Scan(&raw), "строка аудита %s с %s=%s", eventType, field, value)
	out := map[string]any{}
	require.NoError(w.t, json.Unmarshal(raw, &out))
	return out
}

// journalUpdated — строки ленты UPDATED по ресурсу.
func (w *urxWorld) journalUpdated(kind, id string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_journal WHERE resource_kind = $1 AND resource_id = $2 AND event_type = 'UPDATED'`,
		kind, id).Scan(&n))
	return n
}

func (w *urxWorld) usr(id domain.UserID) string { return fmtSubject("user", string(id)) }

// ── Группа A — выдача на один объект ─────────────────────────────────────────

// URG-01 · снятие регистрации отзывает выдачу на один объект.
func TestURG01_UnregisterRevokesSingleTargetGrant(t *testing.T) {
	w := newURXWorld(t)
	w.requireAsk(w.usr(w.usrB), "v_get", pcrRegType, pcrX, true, "URG-01 контроль: выдача A действует")

	w.withdrawX()

	a := w.get(w.grantB)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, a.GetStatus(), "URG-01: выдача A не отозвана снятием регистрации X")
	assert.NotNil(t, a.GetRevokedAt(), "URG-01: revokedAt не выставлен")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, a.GetRevocationReason(),
		"URG-01: причина отзыва не RESOURCE_UNREGISTERED")
	assert.Empty(t, a.GetRevokedByUserId(), "URG-01: revokedByUserId не пуст — отозвал не человек")
	assert.Equal(t, regRefs(pcrX), targetIDs(a), "URG-01: цель отозванной выдачи изменилась")

	assert.NotContains(t, w.listIDs(w.usrB, false), w.grantB, "URG-01: List без includeRevoked содержит отозванную A")
	got, ok := w.listIDs(w.usrB, true)[w.grantB]
	if assert.True(t, ok, "URG-01: List с includeRevoked не содержит A") {
		assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, got.GetRevocationReason(),
			"URG-01: List с includeRevoked несёт не ту причину")
	}
	assert.False(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, pcrX), "URG-01: после снятия usr-B читает X")
	assert.NotContains(t, w.privilegeBindings(w.usrB), w.grantB, "URG-01: ListSubjectPrivileges содержит отозванную A")
}

// URG-02 · повторная регистрация не возвращает доступ прежней выдаче.
func TestURG02_ReRegistrationDoesNotRestoreFormerGrant(t *testing.T) {
	w := newURXWorld(t)
	w.reachX()
	usrB := w.usr(w.usrB)

	assert.False(t, w.ask(usrB, "v_get", pcrRegType, pcrX), "URG-02: сразу после регистрации прежняя выдача действует")
	w.recompute(w.grantB)
	assert.False(t, w.ask(usrB, "v_get", pcrRegType, pcrX), "URG-02: перерасчёт вернул прежней выдаче доступ")
	assert.NotContains(t, w.expandUsers(pcrX), string(w.usrB), "URG-02: ExpandAccess(X) называет usr-B")
	assert.Equal(t, iamv1.AccessBinding_REVOKED, w.get(w.grantB).GetStatus(), "URG-02: A не REVOKED")
}

// URG-03 · близнец 02: выдача после повторной регистрации действует.
func TestURG03_GrantAfterReRegistrationWorks(t *testing.T) {
	w := newURXWorld(t)
	w.reachX()
	usrD := w.usr(w.usrD)
	w.requireAsk(usrD, "v_get", pcrRegType, pcrX, false, "URG-03 контроль: usr-D читает X без выдачи")

	id := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), false, "URG-03: выдача usr-D на новый X")
	w.pollAsk(usrD, "v_get", pcrRegType, pcrX, true, "URG-03: новая выдача не действует")
	w.recompute(id)
	w.requireAsk(usrD, "v_get", pcrRegType, pcrX, true, "URG-03: перерасчёт снял новую выдачу")
	assert.Contains(t, w.privilegeBindings(w.usrD), id, "URG-03: ListSubjectPrivileges(usr-D) без новой выдачи")
	users := w.expandUsers(pcrX)
	assert.Contains(t, users, string(w.usrD), "URG-03: ExpandAccess(X) не называет usr-D")
	assert.NotContains(t, users, string(w.usrB), "URG-03: ExpandAccess(X) называет usr-B")
}

// URG-04 · такая же выдача после повторной регистрации — новая.
func TestURG04_SameGrantAfterReRegistrationIsNew(t *testing.T) {
	w := newURXWorld(t)
	w.reachX()

	op, err := w.abx.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrB), w.rolRegGet, urTarget(pcrX)))
	require.NoError(t, err, "URG-04: синхронный отказ создания")
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.Nilf(t, done.Error, "URG-04: такая же выдача после повторной регистрации отвергнута: %+v", done.Error)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEqual(t, w.grantB, md.GetAccessBindingId(), "URG-04: id новой выдачи совпал с A")

	a := w.get(w.grantB)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, a.GetStatus(), "URG-04: A не REVOKED")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, a.GetRevocationReason(), "URG-04: причина A")
	w.pollAsk(w.usr(w.usrB), "v_get", pcrRegType, pcrX, true, "URG-04: новая выдача usr-B не действует")
}

// URG-05 · близнец 01: тот же id другого типа ключом X не является.
func TestURG05_SameIDOtherTypeIsNotTheKey(t *testing.T) {
	w := newURXWorld(t)
	other := resourcesTarget(&iamv1.ResourceRef{Type: "registry.repositories", Id: pcrX})
	role := w.seedRole("urg05_repo_get", domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	id := w.grantTo(w.usrD, role, other, false, "URG-05: выдача на registry.repositories с id X")

	w.withdrawX()

	b := w.get(id)
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, b.GetStatus(), "URG-05: выдача на другой тип отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_UNSPECIFIED, b.GetRevocationReason(), "URG-05: причина задана")
	assert.Equal(t, []string{"registry.repositories/" + pcrX}, targetIDs(b), "URG-05: цель изменилась")
}

// ── Группа B — выдача на несколько объектов ──────────────────────────────────

// URG-06 · цель из нескольких объектов сужается.
func TestURG06_MultiTargetGrantNarrows(t *testing.T) {
	w := newURXWorld(t)
	b2 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "URG-06: выдача B2 на X, Y")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "URG-06 контроль: B2 действует на X")

	w.withdrawX()

	b := w.get(b2)
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, b.GetStatus(), "URG-06: B2 не ACTIVE")
	assert.Equal(t, regRefs(pcrY), targetIDs(b), "URG-06: цель B2 не сужена до [Y]")
	assert.Nil(t, b.GetRevokedAt(), "URG-06: revokedAt задан")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_UNSPECIFIED, b.GetRevocationReason(), "URG-06: причина задана")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-06: usr-D читает снятый X")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrY), "URG-06: usr-D не читает Y")
	assert.Contains(t, w.privilegeBindings(w.usrD), b2, "URG-06: ListSubjectPrivileges без B2")

	w.reRegisterX(w.usrC)
	w.recompute(b2)
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-06: после повторной регистрации B2 достаёт до X")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrY), "URG-06: после перерасчёта usr-D не читает Y")
}

// URG-07 · опустевшая цель — отзыв, не пустой перечень.
func TestURG07_EmptiedTargetRevokesNotWidens(t *testing.T) {
	w := newURXWorld(t)
	b2 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "URG-07: выдача B2 на X, Y")
	w.withdraw(w.ctx, pcrY)

	w.withdrawX()

	b := w.get(b2)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "URG-07: опустевшая B2 не отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(), "URG-07: причина")
	assert.Equal(t, regRefs(pcrX), targetIDs(b), "URG-07: в цели отозванной не последний снятый ключ")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, urZ), "URG-07: Z, не названный целью, стал доступен")
}

// URG-08 · сужение до цели, совпавшей с действующей выдачей.
func TestURG08_NarrowingCoincidesWithLiveGrant(t *testing.T) {
	w := newURXWorld(t)
	b2 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "URG-08: B2 на X, Y")
	b3 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrY), false, "URG-08: B3 на Y")

	w.withdrawX()

	for _, id := range []string{b2, b3} {
		b := w.get(id)
		assert.Equalf(t, iamv1.AccessBinding_ACTIVE, b.GetStatus(), "URG-08: %s не ACTIVE", id)
		assert.Equalf(t, regRefs(pcrY), targetIDs(b), "URG-08: цель %s не [Y]", id)
	}
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrY), "URG-08: usr-D не читает Y")
}

// URG-09 · суженная выдача слот уникальности не занимает.
func TestURG09_NarrowedGrantDoesNotHoldTheSlot(t *testing.T) {
	w := newURXWorld(t)
	b2 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "URG-09: B2 на X, Y")
	w.withdrawX()
	// «Дано URG-06 исполнен»: без сужения B2 вопрос о слоте суженной выдачи не
	// задан вовсе — совпадения ключа нет, и зелёное ниже было бы ни о чём.
	require.Equal(t, regRefs(pcrY), targetIDs(w.get(b2)), "URG-09 предусловие: B2 не сужена до [Y]")

	op, err := w.abx.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, urTarget(pcrY)))
	require.NoError(t, err)
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	assert.Nilf(t, done.Error, "URG-09: выдача, совпавшая с суженной, отвергнута: %+v", done.Error)
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(b2).GetStatus(), "URG-09: B2 не ACTIVE")
}

// URG-10 · близнец 09: совпадение с несуженной выдачей отвергается.
func TestURG10_DuplicateOfUnnarrowedGrantRefused(t *testing.T) {
	w := newURXWorld(t)
	w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrY), false, "URG-10: B3 на Y")

	op, err := w.abx.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, urTarget(pcrY)))
	require.NoError(t, err)
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "URG-10: дубль несуженной выдачи принят")
	assert.Equal(t, int32(codes.AlreadyExists), done.Error.Code, "URG-10: код")
	assert.Equal(t, fmt.Sprintf("these permissions are already granted to %s on project:%s", w.usrD, w.prjA),
		done.Error.Message, "URG-10: текст")
}

// ── Группа C — защита от удаления ────────────────────────────────────────────

// URG-11 · защищённая выдача отзывается снятием регистрации.
func TestURG11_ProtectedGrantRevokedByUnregistration(t *testing.T) {
	w := newURXWorld(t)
	p := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), true, "URG-11: защищённая P на X")

	w.withdrawX()

	b := w.get(p)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "URG-11: защищённая P не отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(), "URG-11: причина")
	assert.True(t, b.GetDeletionProtection(), "URG-11: флаг защиты изменён")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-11: usr-D читает X")
}

// URG-12 · близнец 11: отзыв глаголом защиту уважает.
func TestURG12_RevokeVerbHonorsProtection(t *testing.T) {
	w := newURXWorld(t)
	p := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), true, "URG-12: защищённая P на X")

	_, err := w.abx.Revoke(asUser(w.ctx, w.usrA), &iamv1.RevokeAccessBindingRequest{AccessBindingId: p})
	require.Error(t, err, "URG-12: отзыв защищённой принят")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "URG-12: код")
	assert.Equal(t, fmt.Sprintf("access binding %s has deletion_protection enabled; clear it via Update before revoke", p),
		status.Convert(err).Message(), "URG-12: текст")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(p).GetStatus(), "URG-12: P не ACTIVE")
}

// ── Группа E — вложенное правило по контейнеру ───────────────────────────────

// readerOnX — мир после доставки новой редакции и выдача registry.reader на `reg`.
func (w *urxWorld) readerOn(reg string) string {
	w.t.Helper()
	w.deliverNewEdition("URG-15")
	w.rewire()
	return w.grantTo(w.usrD, ndRolReader, urTarget(reg), false, "выдача registry.reader на "+reg)
}

// URG-15 · выдача на контейнер отзывается вместе с потомками.
func TestURG15_ContainerGrantRevokedWithDescendants(t *testing.T) {
	w := newURXWorld(t)
	n := w.readerOn(pcrX)
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, pcrXApp, true, "URG-15 контроль: N читает X/app")

	w.withdrawX()

	b := w.get(n)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "URG-15: N не отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(), "URG-15: причина")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-15: usr-D читает X")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXApp), "URG-15: usr-D читает X/app")
}

// URG-16 · потомки повторно зарегистрированного контейнера прежней выдаче недоступны.
func TestURG16_DescendantsOfReRegisteredContainerUnreachable(t *testing.T) {
	w := newURXWorld(t)
	n := w.readerOn(pcrX)
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, pcrXApp, true, "URG-16 контроль: N читает X/app")
	w.withdrawX()
	w.reRegisterX(w.usrC)
	w.registerRepository(pcrX, "late")

	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXLate), "URG-16: сразу — usr-D читает X/late")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXApp), "URG-16: сразу — usr-D читает X/app")
	w.recompute(n)
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXLate), "URG-16: после перерасчёта usr-D читает X/late")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXApp), "URG-16: после перерасчёта usr-D читает X/app")
}

// URG-17 · близнец 15: выдача на другой контейнер не тронута.
func TestURG17_OtherContainerGrantUntouched(t *testing.T) {
	w := newURXWorld(t)
	n2 := w.readerOn(pcrY)

	w.withdrawX()

	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(n2).GetStatus(), "URG-17: N2 тронута")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, pcrYApp, true, "URG-17: usr-D не читает Y/app")
}

// ── Группа F — ветвь names правила роли ──────────────────────────────────────

// URG-19 · название убирается, остальные действуют.
func TestURG19_NameRemovedOthersRemain(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_xy", domain.Rules{namesRule(pcrX, pcrY)})
	w.grantTo(w.usrD, role, ndAllInScope(), false, "URG-19: выдача rol-reg-names-XY")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "URG-19 контроль: X")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrY, true, "URG-19 контроль: Y")

	w.withdrawX()

	rules := w.roleRules(role)
	if assert.Len(t, rules, 1, "URG-19: число правил") {
		assert.Equal(t, []string{pcrY}, rules[0].ResourceNames, "URG-19: названия роли не сужены до [Y]")
	}
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-19: usr-D читает X")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrY), "URG-19: usr-D не читает Y")
	w.reRegisterX(w.usrC)
	w.recompute()
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-19: после повторной регистрации usr-D читает X")
}

// URG-20 · правило без названий убирается, роль без правил не даёт ничего.
func TestURG20_LastNameDropsRuleRoleGrantsNothing(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_x", domain.Rules{namesRule(pcrX)})
	id := w.grantTo(w.usrD, role, ndAllInScope(), false, "URG-20: выдача rol-reg-names-X")

	w.withdrawX()

	assert.Empty(t, w.roleRules(role), "URG-20: правила роли не пусты")
	var rules, perms string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT rules::text, permissions::text FROM kaname.roles WHERE id = $1`,
		string(role)).Scan(&rules, &perms))
	assert.Equal(t, "[]", rules, "URG-20: rules строки роли")
	assert.Equal(t, "[]", perms, "URG-20: permissions строки роли")
	for _, reg := range []string{pcrX, urZ, pcrY} {
		assert.Falsef(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, reg), "URG-20: usr-D читает %s", reg)
	}
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(id).GetStatus(), "URG-20: выдача не ACTIVE")
}

// URG-21 · правило без названий убирается, остальные правила остаются.
func TestURG21_EmptiedRuleDroppedOtherRulesStay(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_x_y", domain.Rules{namesRule(pcrX), namesRule(pcrY)})
	w.grantTo(w.usrD, role, ndAllInScope(), false, "URG-21: выдача rol-reg-names-X-Y")

	w.withdrawX()

	rules := w.roleRules(role)
	if assert.Len(t, rules, 1, "URG-21: число правил") {
		assert.Equal(t, []string{pcrY}, rules[0].ResourceNames, "URG-21: оставшееся правило")
	}
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrY, true, "URG-21: usr-D не читает Y")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-21: usr-D читает X")
}

// URG-22 · близнец 19: роль, не называющая X, не тронута.
func TestURG22_RoleNotNamingKeyUntouched(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_y", domain.Rules{namesRule(pcrY)})
	w.grantTo(w.usrD, role, ndAllInScope(), false, "URG-22: выдача rol-reg-names-Y")
	before := w.roleRules(role)

	w.withdrawX()

	assert.Equal(t, before, w.roleRules(role), "URG-22: правила роли изменились")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrY, true, "URG-22: usr-D не читает Y")
	assert.Zero(t, w.auditCount("iam.role.resource_unregistered_narrowed", "role_id", string(role)),
		"URG-22: строка сужения роли для роли без X")
}

// ── Группа F3 — выдача на роль без правил ────────────────────────────────────

// emptiedRole — URG-20 до «Тогда»: роль rol-reg-names-X без правил.
func (w *urxWorld) emptiedRole() domain.RoleID {
	w.t.Helper()
	role := w.seedRole("rol_reg_names_x", domain.Rules{namesRule(pcrX)})
	w.withdrawX()
	require.Empty(w.t, w.roleRules(role), "предусловие F3: роль rol-reg-names-X не опустела")
	return role
}

// URG-38 · выдача на роль без правил с целью «вся область» ничего не даёт.
func TestURG38_GrantOnRulelessRoleGrantsNothing(t *testing.T) {
	w := newURXWorld(t)
	role := w.emptiedRole()

	id := w.grantTo(w.usrB, role, ndAllInScope(), false, "URG-38: выдача роли без правил")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(id).GetStatus(), "URG-38: выдача не ACTIVE")
	assert.False(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, pcrY), "URG-38: usr-B читает Y")
	assert.False(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, urZ), "URG-38: usr-B читает Z")
	rows, err := w.pool.Query(w.ctx,
		`SELECT relation, object FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, id)
	require.NoError(t, err)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var rel, obj string
		require.NoError(t, rows.Scan(&rel, &obj))
		got = append(got, rel+" "+obj)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"project iam_access_binding:" + id}, got,
		"URG-38: реестр выпущенного несёт не только указатель на родителя выдачи")
}

// URG-39 · близнец 38: роль с правилом даёт своё.
func TestURG39_GrantOnRoleWithRuleGrants(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_y", domain.Rules{namesRule(pcrY)})
	w.grantTo(w.usrB, role, ndAllInScope(), false, "URG-39: выдача rol-reg-names-Y")
	w.pollAsk(w.usr(w.usrB), "v_get", pcrRegType, pcrY, true, "URG-39: usr-B не читает Y")
	assert.False(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, urZ), "URG-39: usr-B читает Z")
}

// URG-40 · выдача с перечнем объектов на роль без правил отвергается проверкой покрытия.
func TestURG40_PerObjectGrantOnRulelessRoleRefusedByCoverage(t *testing.T) {
	w := newURXWorld(t)
	role := w.emptiedRole()

	_, err := w.abx.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrB), role, urTarget(pcrY)))
	require.Error(t, err, "URG-40: выдача с перечнем на роль без правил принята")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "URG-40: код")
	assert.Equal(t, fmt.Sprintf("role %s does not grant verbs on registry.registries; target type must be covered by role.rules", role),
		status.Convert(err).Message(), "URG-40: текст не проверки покрытия")
}

// URG-41 · близнец 40: роль с правилом покрывает тип.
func TestURG41_PerObjectGrantOnRoleWithRuleAccepted(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("rol_reg_names_y", domain.Rules{namesRule(pcrY)})
	w.grantTo(w.usrB, role, urTarget(pcrY), false, "URG-41: выдача rol-reg-names-Y на Y")
}

// ── Группа H — что снятием не является ───────────────────────────────────────

// URG-29 · снятие незарегистрированного ключа выдачу на этот ключ не трогает.
func TestURG29_UnregisterOfUnregisteredKeyLeavesGrant(t *testing.T) {
	w := newURXWorld(t)
	id := w.grantTo(w.usrD, w.rolRegGet, urTarget(urQ), false, "URG-29: выдача на Q")

	w.withdraw(w.ctx, urQ)

	b := w.get(id)
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, b.GetStatus(), "URG-29: выдача на Q отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_UNSPECIFIED, b.GetRevocationReason(), "URG-29: причина задана")
}

// URG-30 · устаревшее надгробие после повторной регистрации ничего не отзывает.
func TestURG30_StaleTombstoneRevokesNothing(t *testing.T) {
	w := newURXWorld(t)
	w.reachX()
	stale := w.ver.Add(-time.Hour) // старше хранимой регистрации v3
	id := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), false, "URG-30: выдача usr-D после повторной регистрации")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "URG-30 контроль: usr-D читает X")

	require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + pcrX,
		SourceVersion: timestamppb.New(stale),
	}), "URG-30: запоздалое снятие")

	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(id).GetStatus(), "URG-30: устаревшее надгробие отозвало выдачу")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-30: usr-D не читает X")
	// Доступ владельца нового объекта (usr-C) при запоздалом снятии — предмет kaname#969
	// (приёмка, редакция 17eaa8f2, «вне объёма»): эта проба его не судит.
}

// URG-31 · снятие публикации — не снятие регистрации.
func TestURG31_PublicationWithdrawalIsNotUnregistration(t *testing.T) {
	w := newURXWorld(t)
	w.deliverNewEdition("URG-31")
	w.rewire()
	pub := &iamv1.RegisterResourceRequest{
		SubjectId: pcrAnon, Relation: "v_get", Object: pcrRegType + ":" + pcrX, SourceVersion: w.nextVersion(),
	}
	require.NoError(t, w.reg.Register(w.ctx, pub), "URG-31: публикация X")

	require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: pcrAnon, Relation: "v_get", Object: pcrRegType + ":" + pcrX, SourceVersion: w.nextVersion(),
	}), "URG-31: снятие публикации")

	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(w.grantB).GetStatus(), "URG-31: снятие публикации отозвало A")
	assert.True(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, pcrX), "URG-31: usr-B не читает X")
}

// URG-32 · повтор применённого снятия ничего не меняет.
func TestURG32_RepeatedUnregistrationChangesNothing(t *testing.T) {
	w := newURXWorld(t)
	req := &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + pcrX,
		SourceVersion: w.nextVersion(),
	}
	require.NoError(t, w.reg.Unregister(w.ctx, req), "URG-32: снятие")
	a := w.get(w.grantB)
	require.Equal(t, iamv1.AccessBinding_REVOKED, a.GetStatus(), "URG-32 предусловие: URG-01 не исполнен")
	auditBefore := w.auditCount("iam.access_binding.resource_unregistered_revoked", "binding_id", w.grantB)
	journalBefore := w.journalUpdated("iam_access_binding", w.grantB)

	require.NoError(t, w.reg.Unregister(w.ctx, req), "URG-32: повтор")

	again := w.get(w.grantB)
	assert.Equal(t, a.GetRevokedAt().AsTime(), again.GetRevokedAt().AsTime(), "URG-32: revokedAt изменился")
	assert.Equal(t, a.GetRevocationReason(), again.GetRevocationReason(), "URG-32: причина изменилась")
	assert.Equal(t, auditBefore, w.auditCount("iam.access_binding.resource_unregistered_revoked", "binding_id", w.grantB),
		"URG-32: повтор добавил строку аудита")
	assert.Equal(t, journalBefore, w.journalUpdated("iam_access_binding", w.grantB), "URG-32: повтор добавил строку ленты")
}

// ── Группа I — наблюдаемость и причина ───────────────────────────────────────

// URG-33 · аудит и лента каждого изменения.
func TestURG33_AuditAndJournalOfEachChange(t *testing.T) {
	w := newURXWorld(t)
	b2 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "URG-33: B2 на X, Y")
	role := w.seedRole("rol_reg_names_xy", domain.Rules{namesRule(pcrX, pcrY)})
	w.grantTo(w.usrD, role, ndAllInScope(), false, "URG-33: выдача rol-reg-names-XY")
	journalA := w.journalUpdated("iam_access_binding", w.grantB)
	journalB2 := w.journalUpdated("iam_access_binding", b2)
	journalRole := w.journalUpdated("iam_role", string(role))

	module := operations.WithPrincipal(w.ctx, operations.Principal{Type: "service_account", ID: w.svaA})
	require.NoError(t, w.reg.Unregister(module, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + pcrX,
		SourceVersion: w.nextVersion(),
	}), "URG-33: снятие X служебной учёткой")

	key := map[string]any{"type": pcrRegTgt, "id": pcrX}
	if assert.Equal(t, 1, w.auditCount("iam.access_binding.resource_unregistered_revoked", "binding_id", w.grantB),
		"URG-33: строк отзыва A") {
		p := w.auditPayload("iam.access_binding.resource_unregistered_revoked", "binding_id", w.grantB)
		assert.Equal(t, "resource_unregistered", p["revocation_reason"], "URG-33: revocation_reason")
		assert.Equal(t, key, p["unregistered_resource"], "URG-33: unregistered_resource отзыва")
		assert.Equal(t, w.svaA, p["actor"], "URG-33: actor отзыва")
	}
	if assert.Equal(t, 1, w.auditCount("iam.access_binding.resource_unregistered_narrowed", "binding_id", b2),
		"URG-33: строк сужения B2") {
		p := w.auditPayload("iam.access_binding.resource_unregistered_narrowed", "binding_id", b2)
		assert.EqualValues(t, 1, p["remaining_resource_count"], "URG-33: remaining_resource_count")
		assert.Equal(t, key, p["unregistered_resource"], "URG-33: unregistered_resource сужения")
		assert.Equal(t, w.svaA, p["actor"], "URG-33: actor сужения")
	}
	if assert.Equal(t, 1, w.auditCount("iam.role.resource_unregistered_narrowed", "role_id", string(role)),
		"URG-33: строк сужения роли") {
		p := w.auditPayload("iam.role.resource_unregistered_narrowed", "role_id", string(role))
		assert.EqualValues(t, 0, p["removed_rule_count"], "URG-33: removed_rule_count")
		assert.EqualValues(t, 1, p["remaining_rule_count"], "URG-33: remaining_rule_count")
		assert.Equal(t, key, p["unregistered_resource"], "URG-33: unregistered_resource роли")
		assert.Equal(t, w.svaA, p["actor"], "URG-33: actor роли")
	}
	assert.Greater(t, w.journalUpdated("iam_access_binding", w.grantB), journalA, "URG-33: лента без UPDATED для A")
	assert.Greater(t, w.journalUpdated("iam_access_binding", b2), journalB2, "URG-33: лента без UPDATED для B2")
	assert.Greater(t, w.journalUpdated("iam_role", string(role)), journalRole, "URG-33: лента без UPDATED для роли")
	a := w.get(w.grantB)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, a.GetStatus(), "URG-33: полное состояние A — не REVOKED")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, a.GetRevocationReason(),
		"URG-33: полное состояние A без причины")
}

// URG-34 · причина пишется на каждом пути отзыва (глагол и срок; R0 — проба наката).
func TestURG34_ReasonOnRevokeAndExpiryPaths(t *testing.T) {
	w := newURXWorld(t)
	r1 := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrY), false, "URG-34: R1 на Y")
	r2 := w.grantTo(w.usrB, w.rolRegGet, urTarget(pcrY), false, "URG-34: R2 на Y")
	// Срок R2 — «сейчас + 2 с» приёмки. Вход создания требует не меньше
	// MinExpiresIn, поэтому срок ставится строкой после приёма, а проход срока —
	// глагол реконсайлера, который его и отзывает.
	_, err := w.pool.Exec(w.ctx, `UPDATE kaname.access_bindings SET expires_at = now() + interval '2 seconds' WHERE id = $1`, r2)
	require.NoError(t, err, "URG-34: срок R2")

	op, err := w.abx.Revoke(asUser(w.ctx, w.usrA), &iamv1.RevokeAccessBindingRequest{AccessBindingId: r1})
	require.NoError(t, err, "URG-34: отзыв R1")
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "URG-34: операция отзыва R1")
	require.Eventually(t, func() bool {
		var past bool
		_ = w.pool.QueryRow(w.ctx, `SELECT expires_at < now() FROM kaname.access_bindings WHERE id = $1`, r2).Scan(&past)
		return past
	}, 10*time.Second, 100*time.Millisecond, "URG-34: срок R2 не истёк")
	require.NoError(t, w.rec.ExpireBinding(w.ctx, domain.AccessBindingID(r2)), "URG-34: проход срока R2")

	b1 := w.get(r1)
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_REVOKE, b1.GetRevocationReason(), "URG-34: причина R1")
	assert.Equal(t, string(w.usrA), b1.GetRevokedByUserId(), "URG-34: revokedByUserId R1")
	b2 := w.get(r2)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b2.GetStatus(), "URG-34: R2 не отозвана сроком")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_EXPIRED, b2.GetRevocationReason(), "URG-34: причина R2")
	assert.Empty(t, b2.GetRevokedByUserId(), "URG-34: revokedByUserId R2")
}

// ── DoD §6 п.7, п.10 — атомарность и цена поиска ─────────────────────────────

// failingWithdrawal — настоящий отзыв, после которого транзакция снятия
// получает отказ: всё, что отзыв записал, обязано откатиться вместе со снятием.
type failingWithdrawal struct {
	inner *accessbindingapp.UnregisteredKeyWithdrawal
}

func (f failingWithdrawal) LockTx(ctx context.Context, tx service.Tx, key domain.ResourceRef) error {
	return f.inner.LockTx(ctx, tx, key)
}

func (f failingWithdrawal) WithdrawTx(ctx context.Context, tx service.Tx, key domain.ResourceRef, actor string) error {
	if err := f.inner.WithdrawTx(ctx, tx, key, actor); err != nil {
		return err
	}
	return errors.New("инъекция kaname#963: отказ после отзыва и до фиксации")
}

// DoD п.7 · отзыв в транзакции снятия: отказ после отзыва и до фиксации не
// оставляет ни снятия, ни отзыва, ни строки аудита.
func TestURG01_RevokeCommitsOnlyWithUnregistration(t *testing.T) {
	w := newURXWorld(t)
	uc := internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(w.pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		failingWithdrawal{inner: accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld})},
		kanamepg.NewRegistrationAudit(),
	)
	err := uc.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + pcrX,
		SourceVersion: w.nextVersion(),
	})
	require.Error(t, err, "п.7: инъецированный отказ не дошёл до вызывающего")

	var mirror int
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`, pcrRegTgt, pcrX).Scan(&mirror))
	assert.Equal(t, 1, mirror, "п.7: строка регистрации снята без отзыва")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(w.grantB).GetStatus(), "п.7: отзыв зафиксирован без снятия")
	assert.Zero(t, w.auditCount("iam.access_binding.resource_unregistered_revoked", "binding_id", w.grantB),
		"п.7: строка аудита отзыва пережила откат")
}

// DoD п.10 · поиск выдач и правил по ключу идёт индексом. Цена на базе стенда
// пишется в DoD-proof задачи; здесь — что план вообще способен взять индекс
// (последовательный просмотр выключен, иначе на крошечной таблице планировщик
// законно выбрал бы его), и печать плана с числами исполнения.
func TestUnregistrationLookupUsesIndexes(t *testing.T) {
	w := newURXWorld(t)
	tmpl := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX, pcrY), false, "п.10: выдача на X, Y")
	w.seedRole("rol_reg_names_xy", domain.Rules{namesRule(pcrX, pcrY)})

	explain := func(what, index, sql string, args ...any) {
		t.Helper()
		tx, err := w.pool.Begin(w.ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(w.ctx) }()
		_, err = tx.Exec(w.ctx, `SET LOCAL enable_seqscan = off`)
		require.NoError(t, err)
		rows, err := tx.Query(w.ctx, `EXPLAIN (ANALYZE, BUFFERS) `+sql, args...)
		require.NoError(t, err)
		var plan []string
		for rows.Next() {
			var line string
			require.NoError(t, rows.Scan(&line))
			plan = append(plan, line)
		}
		rows.Close()
		require.NoError(t, rows.Err())
		text := strings.Join(plan, "\n")
		t.Logf("п.10 %s:\n%s", what, text)
		assert.Containsf(t, text, index, "п.10 %s: план не берёт индекс %s", what, index)
	}
	// Операторы хранилища — те самые, что исполняет снятие, а не их копия: копия
	// разошлась бы с продуктом молча (ревью db-architect @5c0f8f13d).
	//
	// Объём выдач — 5000 действующих выдач на другие ключи, с собранной статистикой.
	// Продуктовый оператор упорядочивает по id, и на семи строках мира планировщик
	// законно идёт первичным ключом с фильтром: «берёт ли индекс» на таком объёме
	// спрашивать не о чем. На объёме, где просмотр всех выдач дорог, — есть.
	//
	// Набор субъектов каждой выдачи — копия набора шаблона в ТОЙ ЖЕ инструкции:
	// выдача без строки набора к фиксации не допускается (миграция 20261018214804),
	// пара выдачи обязана быть в её наборе (миграция 20261019194800).
	_, err := w.pool.Exec(w.ctx,
		`WITH vol AS (
		   INSERT INTO kaname.access_bindings
		   SELECT (jsonb_populate_record(NULL::kaname.access_bindings, to_jsonb(b) || jsonb_build_object(
		             'id', 'acbvol' || lpad(g::text, 14, '0'),
		             'target_digest', 'vol' || g,
		             'target', jsonb_build_object('resources', jsonb_build_array(
		                 jsonb_build_object('type', $1::text, 'id', 'vol' || g)))))).*
		     FROM kaname.access_bindings b, generate_series(1, 5000) g
		    WHERE b.id = $2
		   RETURNING id)
		 INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		 SELECT vol.id, s.subject_type, s.subject_id, s.ordinal
		   FROM vol, kaname.access_binding_subjects s
		  WHERE s.binding_id = $2`,
		pcrRegTgt, tmpl)
	require.NoError(t, err, "п.10: объём выдач")
	_, err = w.pool.Exec(w.ctx, `ANALYZE kaname.access_bindings`)
	require.NoError(t, err, "п.10: статистика выдач")
	explain("выдачи по ключу", "access_bindings_target_resources_live_idx", kanamepg.BindingsNamingKeySQL, pcrRegTgt, pcrX)
	explain("правила по ключу", "role_rule_selectors_resource_names_idx", kanamepg.RolesNamingKeySQL, pcrRegTgt, pcrX)
}
