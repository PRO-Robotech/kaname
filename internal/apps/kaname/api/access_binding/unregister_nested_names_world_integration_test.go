// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_nested_names_world_integration_test.go — группа F2 приёмки
// docs/engineering/acceptance/unregistration-revokes-its-grants.md (отпечаток
// 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4, kaname#963):
// URG-35…URG-37, имена вложенного правила (Р7).
//
// # ПОЧЕМУ МИР НА ТИПАХ REGISTRY, А НЕ PROBEMOD
//
// Приёмка строит П3-У на модуле probemod. Решение о доступе по такому миру
// ответа не даёт: типов `probemod_*` нет в модели прав, и форма решения отвечает
// на вопрос о них отказом «тип не объявлен» (`relverdict.Ask` →
// `authzplan.ErrTypeNotDeclared`), каким бы ни было состояние выдач. Замер —
// прогон @d6b63a6db: контроль фикстуры краснел при полном наборе строк (каталог,
// зеркало, рёбра, отбор с именами вложенного правила, проекция глаголов,
// действующая выдача — напечатаны разбором). Поэтому мир П3-У собран на
// контейнере, который модель объявляет: `registry.registries` с вложенным
// правилом над `repositories`. Имя вложенного правила — непрозрачный id
// репозитория, и ярлыки приёмки `t1`, `t3`, `t4` здесь — id репозиториев под X
// (форма имени `^[a-zA-Z0-9_-]+$` им годна). Роли — та же новая редакция
// манифеста registry, к которой добавлены три роли таблицы П3-У.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// urNamedRoles — роли П3-У: правило над реестрами и вложенное правило над
// репозиториями с собственными именами.
const urNamedRoles = `
  - id: registry.reader_t13
    description: >
      Пробная роль П3-У: чтение реестра и репозиториев t1, t3 под ним.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:
          - resources: [repositories]
            classes: [get, list]
            resourceNames: [t1, t3]

  - id: registry.reader_t1
    description: >
      Пробная роль П3-У: чтение реестра и репозитория t1 под ним.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:
          - resources: [repositories]
            classes: [get, list]
            resourceNames: [t1]

  - id: registry.reader_t3
    description: >
      Пробная роль П3-У: чтение реестра и репозитория t3 под ним.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get, list]
        children:
          - resources: [repositories]
            classes: [get, list]
            resourceNames: [t3]
`

// newP3UWorld поднимает П3-У: доставка новой редакции с ролями П3-У.
func newP3UWorld(t *testing.T) *urxWorld {
	t.Helper()
	w := newURXWorld(t)
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err, "фикстура П3-У")
	text := strings.TrimRight(string(doc), "\n") + "\n" + urNamedRoles
	m, err := manifest.Load([]byte(text))
	require.NoError(t, err, "фикстура П3-У обязана загружаться")
	w.applyDelivered("П3-У: доставка registry с ролями П3-У", m)
	w.rewire()
	return w
}

// registerTag — регистрация репозитория `id` под реестром X владельцем.
func (w *urxWorld) registerTag(id string) {
	w.t.Helper()
	obj := pcrRepoType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: pcrRegType + ":" + pcrX, Relation: "parent", Object: obj},
		{SubjectId: "user:" + string(w.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{pcrRegType + ":" + pcrX, "project:" + string(w.prjA), "account:" + string(w.accA)}
		r.SourceVersion = w.nextVersion()
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "П3-У: регистрация репозитория %s (%s)", id, r.GetRelation())
	}
}

// unregisterTag — снятие регистрации репозитория `id`.
func (w *urxWorld) unregisterTag(id string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: pcrRegType + ":" + pcrX, Relation: "parent", Object: pcrRepoType + ":" + id,
		SourceVersion: w.nextVersion(),
	}), "П3-У: снятие репозитория %s", id)
}

func (w *urxWorld) tag(id string) bool { return w.ask(w.usr(w.usrD), "v_get", pcrRepoType, id) }

// grantNamedRole — выдача роли манифеста человеку usr-D на prj-A, вся область.
func (w *urxWorld) grantNamedRole(name string) domain.RoleID {
	w.t.Helper()
	role := domain.SystemRoleID(domain.RoleName(name))
	w.grantTo(w.usrD, role, ndAllInScope(), false, "П3-У: выдача "+name)
	return role
}

// URG-35 · имя убирается из вложенного правила, остальные действуют.
func TestURG35_NestedNameRemovedOthersRemain(t *testing.T) {
	w := newP3UWorld(t)
	w.registerTag("t1")
	w.registerTag("t3")
	role := w.grantNamedRole("registry.reader_t13")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, "t1", true, "URG-35 контроль фикстуры: t1")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, "t3", true, "URG-35 контроль фикстуры: t3")
	ownerBefore := w.roleRules(role)[0]

	w.unregisterTag("t1")

	rules := w.roleRules(role)
	require.Len(t, rules, 1, "URG-35: правило-владелец")
	if assert.Len(t, rules[0].Children, 1, "URG-35: вложенное правило") {
		assert.Equal(t, []string{"t3"}, rules[0].Children[0].ResourceNames, "URG-35: имена вложенного правила не [t3]")
	}
	assert.Equal(t, ownerBefore.Resources, rules[0].Resources, "URG-35: ресурсы правила-владельца изменились")
	assert.Equal(t, ownerBefore.Verbs, rules[0].Verbs, "URG-35: глаголы правила-владельца изменились")
	assert.False(t, w.tag("t1"), "URG-35: usr-D читает снятый t1")
	assert.True(t, w.tag("t3"), "URG-35: usr-D не читает t3")

	w.registerTag("t1")
	w.recompute()
	assert.False(t, w.tag("t1"), "URG-35: после повторной регистрации t1 usr-D его читает")
}

// URG-36 · последнее имя — вложенное правило снимается, а не хранится пустым.
func TestURG36_LastNestedNameDropsChild(t *testing.T) {
	w := newP3UWorld(t)
	w.registerTag("t1")
	w.registerTag("t3")
	role := w.grantNamedRole("registry.reader_t1")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, "t1", true, "URG-36 контроль фикстуры: t1")
	require.False(t, w.tag("t3"), "URG-36 контроль фикстуры: имена сужают — t3 доступен")

	w.unregisterTag("t1")

	rules := w.roleRules(role)
	require.Len(t, rules, 1, "URG-36: правило-владелец снято")
	assert.Empty(t, rules[0].Children, "URG-36: вложенное правило без имён хранится")
	assert.Equal(t, []string{"registries"}, rules[0].Resources, "URG-36: правило-владелец изменилось")
	assert.False(t, w.tag("t3"), "URG-36: пустой перечень стал ветвью anchor — t3 открыт")
	w.registerTag("t4")
	assert.False(t, w.tag("t4"), "URG-36: пустой перечень стал ветвью anchor — t4 открыт")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "URG-36: правило-владелец не действует")
}

// URG-37 · близнец 35: вложенное правило без снятого имени не тронуто.
func TestURG37_NestedRuleWithoutKeyUntouched(t *testing.T) {
	w := newP3UWorld(t)
	w.registerTag("t1")
	w.registerTag("t3")
	role := w.grantNamedRole("registry.reader_t3")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, "t3", true, "URG-37 контроль фикстуры: t3")
	before := w.roleRules(role)

	w.unregisterTag("t1")

	assert.Equal(t, before, w.roleRules(role), "URG-37: правила роли изменились")
	assert.True(t, w.tag("t3"), "URG-37: usr-D не читает t3")
	assert.Zero(t, w.auditCount("iam.role.resource_unregistered_narrowed", "role_id", string(role)),
		"URG-37: строка сужения роли без снятого имени")
}
