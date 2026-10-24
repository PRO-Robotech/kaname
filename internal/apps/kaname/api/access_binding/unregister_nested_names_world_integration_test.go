// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_nested_names_world_integration_test.go — группа F2 приёмки
// docs/engineering/acceptance/unregistration-revokes-its-grants.md (отпечаток
// 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4, kaname#963):
// URG-35…URG-37, имена вложенного правила (Р7).
//
// Мир П3-У — мир У с доставленной фикстурой
// `internal/manifest/testdata/probemod.children-names-fixture.yaml` (каталог, роли,
// самолечение отбора — `applyDelivered` мира П6) и объектами модуля probemod,
// зарегистрированными с цепью предков: ящик b1 в prj-A, предмет i1 в b1, ярлыки t1,
// t3 в i1. Контроль фикстуры — до «Когда»: без него красное ниже было бы о
// неработающих вложенных именах, а не о снятии.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const urNamesFixture = "probemod.children-names-fixture.yaml"

// Окно материализации — то же, что у опроса мира П6 (SC-13).
const (
	waitWindow = 30 * time.Second
	pollStep   = 200 * time.Millisecond
)

// newP3UWorld поднимает П3-У: доставка фикстуры и регистрация b1, i1, t1, t3.
func newP3UWorld(t *testing.T) *urxWorld {
	t.Helper()
	w := newURXWorld(t)
	doc, err := publicreadfixture.Read(urNamesFixture)
	require.NoError(t, err, "фикстура П3-У")
	m, err := manifest.Load(doc)
	require.NoError(t, err, "фикстура П3-У обязана загружаться")
	w.applyDelivered("П3-У: доставка probemod", m)
	w.rewire()
	w.registerProbe("probemod_box:b1", "project:"+string(w.prjA), "project")
	w.registerProbe("probemod_item:i1", "probemod_box:b1", "box")
	w.registerProbe("probemod_tag:t1", "probemod_item:i1", "item")
	w.registerProbe("probemod_tag:t3", "probemod_item:i1", "item")
	return w
}

// probeChain — цепь предков объекта модуля probemod от ближнего к ярусам.
func (w *urxWorld) probeChain(parent string) []string {
	tail := []string{"project:" + string(w.prjA), "account:" + string(w.accA)}
	switch parent {
	case "probemod_box:b1":
		return append([]string{"probemod_box:b1"}, tail...)
	case "probemod_item:i1":
		return append([]string{"probemod_item:i1", "probemod_box:b1"}, tail...)
	default:
		return tail
	}
}

// registerProbe — регистрация объекта модуля probemod владельцем: указатель на
// родителя и владелец объекта usr-A, своя версия у каждого намерения.
func (w *urxWorld) registerProbe(obj, parent, relation string) {
	w.t.Helper()
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: parent, Relation: relation, Object: obj},
		{SubjectId: "user:" + string(w.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = w.probeChain(parent)
		r.SourceVersion = w.nextVersion()
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "П3-У: регистрация %s (%s)", obj, r.GetRelation())
	}
}

// unregisterProbe — снятие регистрации объекта модуля probemod.
func (w *urxWorld) unregisterProbe(obj, parent, relation string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: parent, Relation: relation, Object: obj, SourceVersion: w.nextVersion(),
	}), "П3-У: снятие %s", obj)
}

// askProbe — `AuthorizeService.Check` по объекту модуля probemod.
func (w *urxWorld) askProbe(subject, modelType, resource, id string) bool {
	w.t.Helper()
	resp, err := w.authz.Check(moduleCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:          subject,
		Resource:         &iamv1.ResourceRef{Type: modelType, Id: id},
		Action:           "probemod." + resource + ".get",
		RequiredRelation: "v_get",
	})
	require.NoErrorf(w.t, err, "Check(%s, v_get, %s:%s) не ответил", subject, modelType, id)
	return resp.GetAllowed()
}

func (w *urxWorld) tag(id string) bool {
	return w.askProbe(w.usr(w.usrD), "probemod_tag", "tags", id)
}

// grantProbeRole — выдача роли манифеста человеку usr-D на prj-A, вся область.
func (w *urxWorld) grantProbeRole(name string) domain.RoleID {
	w.t.Helper()
	role := domain.SystemRoleID(domain.RoleName(name))
	w.grantTo(w.usrD, role, ndAllInScope(), false, "П3-У: выдача "+name)
	return role
}

// pollTag — опрос `Check` по ярлыку до want (окно материализации).
func (w *urxWorld) pollTag(id string, want bool, why string) {
	w.t.Helper()
	require.Eventuallyf(w.t, func() bool { return w.tag(id) == want }, waitWindow, pollStep,
		"%s: Check(usr-D, v_get, probemod_tag:%s) не дошёл до %v", why, id, want)
}

// URG-35 · имя убирается из вложенного правила, остальные действуют.
func TestURG35_NestedNameRemovedOthersRemain(t *testing.T) {
	w := newP3UWorld(t)
	role := w.grantProbeRole("probemod.reader_t13")
	w.pollTag("t1", true, "URG-35 контроль фикстуры: t1")
	w.pollTag("t3", true, "URG-35 контроль фикстуры: t3")
	ownerBefore := w.roleRules(role)[0]

	w.unregisterProbe("probemod_tag:t1", "probemod_item:i1", "item")

	rules := w.roleRules(role)
	require.Len(t, rules, 1, "URG-35: правило-владелец")
	if assert.Len(t, rules[0].Children, 1, "URG-35: вложенное правило") {
		assert.Equal(t, []string{"t3"}, rules[0].Children[0].ResourceNames, "URG-35: имена вложенного правила не [t3]")
	}
	assert.Equal(t, ownerBefore.Resources, rules[0].Resources, "URG-35: ресурсы правила-владельца изменились")
	assert.Equal(t, ownerBefore.Verbs, rules[0].Verbs, "URG-35: глаголы правила-владельца изменились")
	assert.False(t, w.tag("t1"), "URG-35: usr-D читает снятый t1")
	assert.True(t, w.tag("t3"), "URG-35: usr-D не читает t3")

	w.registerProbe("probemod_tag:t1", "probemod_item:i1", "item")
	w.recompute()
	assert.False(t, w.tag("t1"), "URG-35: после повторной регистрации t1 usr-D его читает")
}

// URG-36 · последнее имя — вложенное правило снимается, а не хранится пустым.
func TestURG36_LastNestedNameDropsChild(t *testing.T) {
	w := newP3UWorld(t)
	role := w.grantProbeRole("probemod.reader_t1")
	w.pollTag("t1", true, "URG-36 контроль фикстуры: t1")
	require.False(t, w.tag("t3"), "URG-36 контроль фикстуры: имена сужают — t3 доступен")

	w.unregisterProbe("probemod_tag:t1", "probemod_item:i1", "item")

	rules := w.roleRules(role)
	require.Len(t, rules, 1, "URG-36: правило-владелец снято")
	assert.Empty(t, rules[0].Children, "URG-36: вложенное правило без имён хранится")
	assert.Equal(t, []string{"boxes"}, rules[0].Resources, "URG-36: правило-владелец изменилось")
	assert.False(t, w.tag("t3"), "URG-36: пустой перечень стал ветвью anchor — t3 открыт")
	w.registerProbe("probemod_tag:t4", "probemod_item:i1", "item")
	assert.False(t, w.tag("t4"), "URG-36: пустой перечень стал ветвью anchor — t4 открыт")
	assert.True(t, w.askProbe(w.usr(w.usrD), "probemod_box", "boxes", "b1"), "URG-36: правило-владелец не действует")
}

// URG-37 · близнец 35: вложенное правило без снятого имени не тронуто.
func TestURG37_NestedRuleWithoutKeyUntouched(t *testing.T) {
	w := newP3UWorld(t)
	role := w.grantProbeRole("probemod.reader_t3")
	w.pollTag("t3", true, "URG-37 контроль фикстуры: t3")
	before := w.roleRules(role)

	w.unregisterProbe("probemod_tag:t1", "probemod_item:i1", "item")

	assert.Equal(t, before, w.roleRules(role), "URG-37: правила роли изменились")
	assert.True(t, w.tag("t3"), "URG-37: usr-D не читает t3")
	assert.Zero(t, w.auditCount("iam.role.resource_unregistered_narrowed", "role_id", string(role)),
		"URG-37: строка сужения роли без снятого имени")
}
