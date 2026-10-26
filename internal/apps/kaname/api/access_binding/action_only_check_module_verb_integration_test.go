// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// action_only_check_module_verb_integration_test.go — вопрос `authorize:check`
// без отношения от ВОШЕДШЕГО и от МОДУЛЯ на настоящем решателе: задача
// PRO-Robotech/kaname#995.
//
// Найдено полосой kaname#994: анонимной самопроверке отношение выводится
// глаголом типа из каталога модуля, а прочим вызывающим без отношения — общим
// умолчанием, ярусом. Ярус `viewer` объединяет `get` и `list`, поэтому человек,
// которому выдан только `get`, получал «да» и на вопрос о `list`: ответ шире
// выданного.
//
// Мир — П6 (`public_container_read_world_integration_test.go`): человеку usr-B
// выдана роль `pcr_reg_get` (только `registries:get`) на реестр X. Порядок в
// каждой пробе: контроль фикстуры явным отношением → вопрос без отношения.
//
// Здесь же снята проба kaname#994 «вошедший без отношения отвечает как явный
// viewer»: её предмет — ярус у вошедшего — снят этой задачей.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// askCheck — вопрос `authorize:check` о человеке usr-B на реестре X контекстом
// вызывающего; relation пусто — вопрос без отношения.
func askCheck(t *testing.T, h *authorizeapp.Handler, ctx context.Context, subject, action, relation string) bool {
	t.Helper()
	resp, err := h.Check(ctx, &iamv1.AuthorizeCheckRequest{
		Subject:          subject,
		Resource:         &iamv1.ResourceRef{Type: pcrRegType, Id: pcrX},
		Action:           action,
		RequiredRelation: relation,
	})
	require.NoErrorf(t, err, "Check %s (отношение %q) от %s не ответил", action, relation, subject)
	return resp.GetAllowed()
}

// TestActionOnlyCheck_GetGrantDoesNotAnswerList — kaname#995, п. 1 предиката:
// выдан `get` без `list` — вопрос `list` без отношения от вошедшего и от модуля
// отвечается отказом. Близнец — тот же вопрос о `get`: он разрешён, и это
// доказывает, что выдача действует и вопрос дошёл до решения.
func TestActionOnlyCheck_GetGrantDoesNotAnswerList(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#995")
	usrB := fmtSubject("user", string(p.usrB))
	h := p.anonSelfCheckHandler()

	callers := []struct {
		name string
		ctx  context.Context
	}{
		{"вошедший о себе", asUser(p.ctx, p.usrB)},
		{"модуль", moduleCtx()},
	}
	for _, c := range callers {
		// Контроль фикстуры: выдано ровно `get`.
		require.Truef(t, askCheck(t, h, c.ctx, usrB, "registry.registries.get", "v_get"),
			"контроль kaname#995 (%s): выдача get человеку usr-B на X действует", c.name)
		require.Falsef(t, askCheck(t, h, c.ctx, usrB, "registry.registries.list", "v_list"),
			"контроль kaname#995 (%s): list человеку usr-B на X не выдан", c.name)

		assert.Truef(t, askCheck(t, h, c.ctx, usrB, "registry.registries.get", ""),
			"kaname#995 близнец (%s): get без отношения при выданном get обязан разрешить", c.name)
		assert.Falsef(t, askCheck(t, h, c.ctx, usrB, "registry.registries.list", ""),
			"kaname#995 (%s): list без отношения при выданном только get обязан отказать", c.name)
	}
}

// TestActionOnlyCheck_ExplicitRelationKeepsItsAnswer — kaname#995, п. 2
// предиката: вызывающий, передавший отношение явно, получает прежний ответ.
// Явный ярус `viewer` по-прежнему спрашивает ярус — правка меняет только вывод
// отношения из действия.
func TestActionOnlyCheck_ExplicitRelationKeepsItsAnswer(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#995 явное отношение")
	usrB := fmtSubject("user", string(p.usrB))
	h := p.anonSelfCheckHandler()
	ctx := moduleCtx()

	assert.True(t, askCheck(t, h, ctx, usrB, "registry.registries.get", "v_get"),
		"kaname#995: явное v_get при выданном get — прежний ответ")
	assert.False(t, askCheck(t, h, ctx, usrB, "registry.registries.list", "v_list"),
		"kaname#995: явное v_list без выдачи list — прежний ответ")
	// Явный ярус спрашивает ярус, как прежде: до правки этот вопрос отвечал «да».
	assert.True(t, askCheck(t, h, ctx, usrB, "registry.registries.list", "viewer"),
		"kaname#995: явный viewer при выданном get — прежний ответ")
}

// TestActionOnlyCheck_ListGrantAnswersList — kaname#995, п. 2 предиката: выдача
// `list` даёт «да» на вопрос о `list` без отношения — правка не сужает права
// сверх выданного.
func TestActionOnlyCheck_ListGrantAnswersList(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#995 выдача list")
	p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(userSubject(p.usrD), p.rolProjRegRead, pcrXTarget()),
		"kaname#995: выдача get+list человеку usr-D на X")
	usrD := fmtSubject("user", string(p.usrD))
	p.pollAsk(usrD, "v_list", pcrRegType, pcrX, true,
		"контроль фикстуры kaname#995: выдача list человеку usr-D материализована в v_list на X")
	h := p.anonSelfCheckHandler()

	assert.True(t, askCheck(t, h, moduleCtx(), usrD, "registry.registries.list", ""),
		"kaname#995: list без отношения при выданном list обязан разрешить")
	assert.True(t, askCheck(t, h, moduleCtx(), usrD, "registry.registries.get", ""),
		"kaname#995: get без отношения при выданном get обязан разрешить")
}
