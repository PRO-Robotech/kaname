// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// anonymous_self_check_module_verb_integration_test.go — анонимная самопроверка
// (kaname#959) на НАСТОЯЩЕМ решателе: задача PRO-Robotech/kaname#994.
//
// Вопрос анонимной формы отношения не несёт — `requiredRelation` в ней запрещён
// (`authzguard.IsAnonymousSelfCheck`), и отношение выводит служба. Пробы kaname#959
// подменяли решатель заглушкой, и потому не видели, ЧТО за отношение уходит к
// форме: общее умолчание `viewer`, которого у типов модулей системный класс не
// держит. Выдача анониму действовала (явный `v_get` — true), а анонимная
// самопроверка того же действия на том же объекте отвечала false.
//
// Мир — П6 (`public_container_read_world_integration_test.go`): дверь решения —
// `relverdict` под допуском, материализация — `reconcile`, каталог модуля —
// живые строки после доставки манифеста registry новой редакции. Вопрос идёт
// через обработчик публичной службы `AuthorizeService.Check` контекстом без
// удостоверения, то есть ровно той полосой, которой спрашивает прокси реестра.
//
// Порядок в каждой пробе: контроль фикстуры явным отношением (выдача
// материализована) → анонимная форма. Отрицание без положительного близнеца
// неотличимо от неразвернувшейся выдачи, поэтому близнец стоит раньше.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// anonSelfCheckHandler — обработчик публичной службы решения с теми же частями,
// что корень службы (`cmd/kaname/wiring.go::buildAuthZServices`): та же дверь
// решения и ЖИВОЙ каталог модуля мира. Строится после доставки: каталог берётся
// из строк, которые доставка положила.
func (p *pcrWorld) anonSelfCheckHandler() *authorizeapp.Handler {
	p.t.Helper()
	require.NotNil(p.t, p.facts, "мир П6: каталожного факта нет — доставка не выполнялась")
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           p.door,
		ClusterAdminChecker: p.door,
		Catalog:             catalog.Fixed{F: p.facts},
	})
	return authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil)).WithModuleRoster(moduleroster.Roster(p.t))
}

// anonSelf — анонимная самопроверка: только ресурс и действие, контекст без
// удостоверения. Предусловие проверяется до вопроса: запрос, выпавший из
// анонимной формы, получил бы отказ «subject: required», и проба утверждала бы
// о нём, а не о решении.
func anonSelf(t *testing.T, h *authorizeapp.Handler, action, modelType, id string) bool {
	t.Helper()
	ctx := context.Background()
	req := &iamv1.AuthorizeCheckRequest{
		Resource: &iamv1.ResourceRef{Type: modelType, Id: id},
		Action:   action,
	}
	require.Truef(t, authzguard.IsAnonymousSelfCheck(ctx, req, moduleidentity.Roster{}),
		"предусловие: вопрос %s %s:%s обязан быть анонимной формой", action, modelType, id)
	resp, err := h.Check(ctx, req)
	require.NoErrorf(t, err, "анонимная самопроверка %s %s:%s не ответила", action, modelType, id)
	require.Emptyf(t, resp.GetDenyReasons(), "анониму причины отказа не называются (SC-10): %s %s:%s", action, modelType, id)
	return resp.GetAllowed()
}

// TestAnonymousSelfCheck_PublicReadGrantAllowsRepositoryGet — kaname#994, пп. 1–2
// предиката: выдача анониму роли чтения реестра с его репозиториями → анонимная
// самопроверка `registry.repositories.get` на репозитории = allowed; близнец без
// выдачи = false. Отличие близнеца — ровно одна выдача.
func TestAnonymousSelfCheck_PublicReadGrantAllowsRepositoryGet(t *testing.T) {
	twin := newPCRWorld(t)
	twin.deliverNewEdition("kaname#994 близнец")
	th := twin.anonSelfCheckHandler()
	for _, q := range []struct{ action, modelType, id string }{
		{"registry.repositories.get", pcrRepoType, pcrXApp},
		{"registry.repositories.list", pcrRepoType, pcrXApp},
		{"registry.registries.get", pcrRegType, pcrX},
	} {
		assert.Falsef(t, anonSelf(t, th, q.action, q.modelType, q.id),
			"kaname#994 близнец: без выдачи анонимная самопроверка %s %s:%s обязана отказать", q.action, q.modelType, q.id)
	}

	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#994")
	p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "kaname#994: выдача анониму роли чтения реестра на X")
	p.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true,
		"контроль фикстуры kaname#994: выдача анониму материализована в v_get на X/app")
	h := p.anonSelfCheckHandler()

	assert.True(t, anonSelf(t, h, "registry.repositories.get", pcrRepoType, pcrXApp),
		"kaname#994: анонимная самопроверка repositories.get на X/app после выдачи обязана разрешить")
	assert.True(t, anonSelf(t, h, "registry.repositories.list", pcrRepoType, pcrXApp),
		"kaname#994: анонимная самопроверка repositories.list на X/app после выдачи обязана разрешить")
	assert.True(t, anonSelf(t, h, "registry.registries.get", pcrRegType, pcrX),
		"kaname#994: анонимная самопроверка registries.get на X после выдачи обязана разрешить")

	// Чтение не расширяется до записи: тот же объект, другой глагол.
	for _, action := range []string{"registry.repositories.update", "registry.repositories.delete"} {
		assert.Falsef(t, anonSelf(t, h, action, pcrRepoType, pcrXApp),
			"kaname#994: выдача чтения не даёт анониму %s", action)
	}
	// Глагол, которого тип в каталоге не объявляет, — честный отказ, а не
	// подстановка умолчания: у репозитория `v_create` нет.
	assert.False(t, anonSelf(t, h, "registry.repositories.create", pcrRepoType, pcrXApp),
		"kaname#994: глагол без отношения в каталоге типа — отказ")
	// Действие о ДРУГОМ ресурсе, чем тип объекта, — честный отказ: глагол
	// берётся у типа объекта, и действие обязано его называть.
	assert.False(t, anonSelf(t, h, "registry.registries.get", pcrRepoType, pcrXApp),
		"kaname#994: действие реестра на объекте-репозитории — отказ")
	// Объект вне выдачи (реестр Y) остаётся закрытым.
	assert.False(t, anonSelf(t, h, "registry.repositories.get", pcrRepoType, pcrYApp),
		"kaname#994: репозиторий вне цели выдачи анониму закрыт")
}

// TestAnonymousSelfCheck_RoleWithoutRepositoryGetStaysRefused — kaname#994:
// выдача анониму роли, дающей только `registries:get` (без правила над
// репозиториями), открывает сам реестр и не открывает репозиторий. Близнец —
// тот же вопрос о реестре: он и доказывает, что выдача действует.
func TestAnonymousSelfCheck_RoleWithoutRepositoryGetStaysRefused(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#994 роль без get")
	p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(classSubject("anonymous"), p.rolRegGet, pcrXTarget()),
		"kaname#994: выдача анониму rol-reg-get на X")
	p.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "контроль фикстуры kaname#994: выдача анониму материализована в v_get на X")
	h := p.anonSelfCheckHandler()

	assert.True(t, anonSelf(t, h, "registry.registries.get", pcrRegType, pcrX),
		"kaname#994 близнец: выдача rol-reg-get открывает анониму сам реестр")
	assert.False(t, anonSelf(t, h, "registry.repositories.get", pcrRepoType, pcrXApp),
		"kaname#994: роль без get над репозиториями репозиторий анониму не открывает")
	assert.False(t, anonSelf(t, h, "registry.registries.list", pcrRegType, pcrX),
		"kaname#994: роль без list над реестром list анониму не открывает")
}
