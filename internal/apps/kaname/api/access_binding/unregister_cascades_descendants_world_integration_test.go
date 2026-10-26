// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_cascades_descendants_world_integration_test.go — снятие регистрации
// родителя снимает и его потомков (PRO-Robotech/kaname#1002).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Реестр X зарегистрирован в prj-A, под ним — репозитории X/app и X/web (цепь
// предков каждого начинается с X). Регистратор модуля снимает только X: потомков
// он перечислить не может — чтения зеркала kaname у него нет, а X/web заведён вне
// его учёта. Снятие X обязано снять вместе с ним регистрацию потомков (строку
// зеркала и цепь предков), их отношения (владелец, указатель на родителя) и выдачи
// на них — иначе после снятия остаются зарегистрированные объекты без живого
// родителя, и право на них переживает свой предмет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИСХОД СУДИТСЯ ТРЕМЯ ЧТЕНИЯМИ
//
// Регистрация — строка зеркала и цепь предков; кортежи — прямой факт
// `relation_fact`; выдача — `AccessBindingService.Get` и ответ двери решения
// `AuthorizeService.Check`. Каждое чтение судит свою половину: снятая строка
// зеркала при живом факте владельца оставила бы доступ, отозванная выдача при
// живой цепи — объект «под областью».
//
// Близнецы отличаются ОДНИМ фактом от предмета: снимается потомок, а не родитель
// (родитель и прочие потомки на месте), и снятие повторяется (ничего не меняется).

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Потомок реестра X, заведённый вне учёта регистратора: в мире П6 его нет.
const pcrXWeb = pcrX + "/web"

// repoTarget — цель «названные объекты» из репозиториев с данными id.
func repoTarget(ids ...string) *iamv1.AccessTarget {
	refs := make([]*iamv1.ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, &iamv1.ResourceRef{Type: "registry.repositories", Id: id})
	}
	return resourcesTarget(refs...)
}

// cascadeWorld — мир У с вторым потомком X и выдачами на потомков.
type cascadeWorld struct {
	*urxWorld
	grantXApp, grantXWeb, grantYApp string
}

// newCascadeWorld — сцена до предмета: X/web зарегистрирован, у usr-D выдачи на
// X/app, X/web и Y/app действуют (положительный контроль фикстуры).
func newCascadeWorld(t *testing.T) *cascadeWorld {
	t.Helper()
	w := &cascadeWorld{urxWorld: newURXWorld(t)}
	w.registerRepository(pcrX, "web")
	role := w.seedRole("cascade_repo_get",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	w.grantXApp = w.grantTo(w.usrD, role, repoTarget(pcrXApp), false, "kaname#1002: выдача usr-D на X/app")
	w.grantXWeb = w.grantTo(w.usrD, role, repoTarget(pcrXWeb), false, "kaname#1002: выдача usr-D на X/web")
	w.grantYApp = w.grantTo(w.usrD, role, repoTarget(pcrYApp), false, "kaname#1002: выдача usr-D на Y/app")
	for _, id := range []string{pcrXApp, pcrXWeb, pcrYApp} {
		w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, id, true,
			"kaname#1002 контроль фикстуры: выдача usr-D на "+id+" не действует до снятия")
		require.Truef(t, w.registered(pcrRepoType, id),
			"kaname#1002 контроль фикстуры: репозиторий %s не зарегистрирован", id)
		require.NotZerof(t, w.factsOn(pcrRepoType, id),
			"kaname#1002 контроль фикстуры: у репозитория %s нет отношений", id)
	}
	return w
}

// registered — есть ли у объекта регистрация: строка зеркала (словарь каталога)
// и цепь предков (словарь модели).
func (w *cascadeWorld) registered(modelType, id string) bool {
	w.t.Helper()
	var mirror, edges int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		map[string]string{pcrRegType: pcrRegTgt, pcrRepoType: "registry.repositories"}[modelType],
		id).Scan(&mirror))
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type = $1 AND object_id = $2`,
		modelType, id).Scan(&edges))
	return mirror > 0 || edges > 0
}

// factsOn — число прямых фактов (отношений), стоящих на объекте.
func (w *cascadeWorld) factsOn(modelType, id string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2`,
		modelType, id).Scan(&n))
	return n
}

// unregisterRepo — снятие регистрации репозитория владельцем: указатель на
// родителя с версией-надгробием.
func (w *cascadeWorld) unregisterRepo(registry, name string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId:     pcrRegType + ":" + registry,
		Relation:      "parent",
		Object:        pcrRepoType + ":" + registry + "/" + name,
		SourceVersion: w.nextVersion(),
	}), "снятие регистрации репозитория %s/%s", registry, name)
}

// assertDescendantGone — у потомка нет регистрации, отношений и действующей выдачи.
func (w *cascadeWorld) assertDescendantGone(id, grant, why string) {
	w.t.Helper()
	assert.Falsef(w.t, w.registered(pcrRepoType, id), "%s: регистрация потомка %s осталась", why, id)
	assert.Zerof(w.t, w.factsOn(pcrRepoType, id), "%s: отношения потомка %s остались", why, id)
	b := w.get(grant)
	assert.Equalf(w.t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "%s: выдача на потомка %s не отозвана", why, id)
	assert.Equalf(w.t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(),
		"%s: причина отзыва выдачи на потомка %s", why, id)
	assert.Falsef(w.t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, id), "%s: usr-D читает снятого потомка %s", why, id)
}

// assertAlive — объект зарегистрирован, его отношения и выдача на месте.
func (w *cascadeWorld) assertAlive(modelType, id, grant, why string) {
	w.t.Helper()
	assert.Truef(w.t, w.registered(modelType, id), "%s: регистрация %s снята", why, id)
	assert.NotZerof(w.t, w.factsOn(modelType, id), "%s: отношения %s сняты", why, id)
	assert.Equalf(w.t, iamv1.AccessBinding_ACTIVE, w.get(grant).GetStatus(), "%s: выдача на %s не ACTIVE", why, id)
}

// TestUnregister_ParentTakesItsDescendants — снятие X снимает X/app и X/web
// (X/web регистратор не перечислял) с их отношениями и выдачами; соседний Y/app
// не тронут.
func TestUnregister_ParentTakesItsDescendants(t *testing.T) {
	w := newCascadeWorld(t)

	w.withdrawX()

	w.assertDescendantGone(pcrXApp, w.grantXApp, "kaname#1002")
	w.assertDescendantGone(pcrXWeb, w.grantXWeb, "kaname#1002")
	w.assertAlive(pcrRepoType, pcrYApp, w.grantYApp, "kaname#1002: потомок соседнего реестра")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrYApp), "kaname#1002: usr-D не читает Y/app")
}

// TestUnregister_DescendantLeavesParentAndSiblings — близнец: снятие одного
// потомка не трогает родителя и прочих потомков.
func TestUnregister_DescendantLeavesParentAndSiblings(t *testing.T) {
	w := newCascadeWorld(t)

	w.unregisterRepo(pcrX, "app")

	w.assertDescendantGone(pcrXApp, w.grantXApp, "kaname#1002 близнец")
	w.assertAlive(pcrRegType, pcrX, w.grantB, "kaname#1002 близнец: родитель")
	w.assertAlive(pcrRepoType, pcrXWeb, w.grantXWeb, "kaname#1002 близнец: сосед по родителю")
	assert.True(t, w.ask(w.usr(w.usrB), "v_get", pcrRegType, pcrX), "kaname#1002 близнец: usr-B не читает X")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, pcrXWeb), "kaname#1002 близнец: usr-D не читает X/web")
}

// TestUnregister_RepeatedParentWithdrawalChangesNothing — повтор снятия родителя
// успешен и ничего не меняет: соседний реестр и его потомок на месте.
func TestUnregister_RepeatedParentWithdrawalChangesNothing(t *testing.T) {
	w := newCascadeWorld(t)
	w.withdrawX()
	before := w.get(w.grantXApp)

	w.withdrawX()

	again := w.get(w.grantXApp)
	assert.Equal(t, before.GetRevokedAt().AsTime(), again.GetRevokedAt().AsTime(), "kaname#1002 повтор: revokedAt изменился")
	w.assertDescendantGone(pcrXApp, w.grantXApp, "kaname#1002 повтор")
	w.assertDescendantGone(pcrXWeb, w.grantXWeb, "kaname#1002 повтор")
	w.assertAlive(pcrRepoType, pcrYApp, w.grantYApp, "kaname#1002 повтор: потомок соседнего реестра")
}

// publishRepo — публикация репозитория для анонимного чтения владельцем
// (`user:*` + v_get) с версией владельца ver: у объекта своя упорядочивающая
// версия, с версией родителя она не сравнима.
func (w *cascadeWorld) publishRepo(id string, ver time.Time, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.reg.Register(w.ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "user:*", Relation: "v_get", Object: pcrRepoType + ":" + id,
		SourceVersion: timestamppb.New(ver),
	}), "%s: публикация репозитория %s", why, id)
}

// publication — хранимое направление публикации объекта: есть ли строка
// надгробия и открыта ли она.
func (w *cascadeWorld) publication(id string) (exists, published bool) {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*), coalesce(bool_or(published), false) FROM kaname.public_read_publication
		  WHERE object_type = $1 AND object_id = $2`,
		pcrRepoType, id).Scan(&n, &published), "чтение публикации %s", id)
	return n > 0, published
}

// assertPublicationGone — публикация потомка снята вместе с ним: аноним не
// читает, надгробие стоит закрытым.
func (w *cascadeWorld) assertPublicationGone(id, why string) {
	w.t.Helper()
	assert.Falsef(w.t, w.ask(pcrAnon, "v_get", pcrRepoType, id), "%s: аноним читает снятого потомка %s", why, id)
	exists, published := w.publication(id)
	assert.Truef(w.t, exists, "%s: надгробия публикации потомка %s нет", why, id)
	assert.Falsef(w.t, published, "%s: публикация потомка %s стоит открытой", why, id)
}

// TestUnregister_ParentTakesDescendantPublicationNewerThanItsTombstone —
// SD-1017-C1: потомок опубликован СВОЕЙ версией, новее надгробия родителя.
// Снятие родителя обязано снять и эту публикацию: регистрации у потомка больше
// нет, а id репозитория — его имя, и уцелевшая публикация отдала бы анонимное
// чтение следующему объекту под тем же ключом.
//
// Запоздавшая повторная доставка того же открытия после снятия публикацию не
// возвращает: надгробие помнит версию открытия, и повтор не новее.
func TestUnregister_ParentTakesDescendantPublicationNewerThanItsTombstone(t *testing.T) {
	w := newCascadeWorld(t)
	w.deliverNewEdition("kaname#1002 SD-1017-C1")
	w.rewire()
	ahead := w.ver.Add(time.Hour) // своя версия потомка новее надгробия родителя
	w.publishRepo(pcrXApp, ahead, "SD-1017-C1")
	w.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SD-1017-C1 контроль фикстуры: публикация X/app не открыла")

	w.withdrawX()

	w.assertDescendantGone(pcrXApp, w.grantXApp, "SD-1017-C1")
	w.assertPublicationGone(pcrXApp, "SD-1017-C1")

	w.publishRepo(pcrXApp, ahead, "SD-1017-C1 повторная доставка")
	assert.False(t, w.ask(pcrAnon, "v_get", pcrRepoType, pcrXApp),
		"SD-1017-C1: повторная доставка открытия вернула анонимное чтение снятому потомку")
}

// TestUnregister_ParentTakesDescendantPublicationOlderThanItsTombstone —
// близнец SD-1017-C1: та же публикация версией СТАРШЕ надгробия родителя.
// Отличие от предмета — один факт: порядок версий публикации и надгробия.
func TestUnregister_ParentTakesDescendantPublicationOlderThanItsTombstone(t *testing.T) {
	w := newCascadeWorld(t)
	w.deliverNewEdition("kaname#1002 SD-1017-C1 близнец")
	w.rewire()
	w.publishRepo(pcrXApp, w.nextVersion().AsTime(), "SD-1017-C1 близнец")
	w.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SD-1017-C1 близнец, контроль фикстуры: публикация X/app не открыла")

	w.withdrawX()

	w.assertDescendantGone(pcrXApp, w.grantXApp, "SD-1017-C1 близнец")
	w.assertPublicationGone(pcrXApp, "SD-1017-C1 близнец")
}
