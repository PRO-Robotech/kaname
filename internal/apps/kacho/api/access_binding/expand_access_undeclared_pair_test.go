// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access_undeclared_pair_test.go — пара, которую тип НЕ объявляет,
// отвергается НА ВХОДЕ (#1290).
//
// Приём отношения шёл по ОБЪЕДИНЕНИЮ наборов всех типов, а компиляция плана — по
// набору КОНКРЕТНОГО типа. Пара из зазора (глагол объявлен где-то ещё, но не у
// этого типа) доезжала до формы и возвращалась INTERNAL: «мы сломались» на
// корректном запросе, тогда как сломались не мы — запрос назвал пару, которой не
// бывает.
//
// Отказ обязан быть ТЕРМИНАЛЬНЫМ (повтор не поможет никогда) и называть виновное
// поле. Каждое отрицание ниже стоит рядом со своим положительным контролем: без
// него «отвергнуто» неотличимо от «отвергается всё».

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExpandAccess_RelationTheTypeDoesNotDeclare_RefusedOnInput(t *testing.T) {
	// `v_addtargets` объявляет ровно один тип дерева — nlb_target_group. У сети
	// его нет, поэтому план по паре (vpc_network, v_addtargets) не собирается.
	exp := &fakeLister{}
	uc := authorizedUC(exp)

	_, _, err := uc.Execute(authedCtx(), "vpc_network", "vpcn_x", "v_addtargets", 0)
	require.Error(t, err, "пара, которой тип не объявляет, обязана быть отвергнута")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"отказ обязан быть терминальным: повтор того же запроса не пройдёт никогда")
	assert.Contains(t, st.Message(), "relation", "отказ обязан называть поле")
	assert.Contains(t, st.Message(), "v_addtargets")
	assert.Contains(t, st.Message(), "vpc_network",
		"без имени типа вызывающему непонятно, ЧЕМ именно негодна пара")
	assert.Zero(t, exp.calls, "до источника принципалов такой запрос доходить не должен")
}

func TestExpandAccess_RelationTheTypeDeclares_PassesValidation(t *testing.T) {
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к предыдущему: тот же глагол у типа, который его
	// объявляет, обязан пройти вход и дойти до источника.
	exp := &fakeLister{byNode: map[string][]string{
		"nlb_target_group:tg_x#v_addtargets": {"user:usr_u1"},
	}}
	uc := authorizedUC(exp)

	res, _, err := uc.Execute(authedCtx(), "nlb_target_group", "tg_x", "v_addtargets", 0)
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, 1, exp.calls, "объявленная пара обязана доходить до источника")
}

func TestExpandAccess_UndeclaredObjectType_RefusedNamingTheType(t *testing.T) {
	exp := &fakeLister{}
	uc := authorizedUC(exp)

	_, _, err := uc.Execute(authedCtx(), "no_such_object_type_1290", "x_1", "v_get", 0)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "object_type",
		"виновное поле здесь — тип, а не отношение: у необъявленного типа не объявлено НИ ОДНО отношение")
	assert.Zero(t, exp.calls)
}

func TestExpandAccess_OffSurfaceRelation_KeepsItsContractTone(t *testing.T) {
	// Машинерия модели остаётся вне поверхности, и тон её отказа — часть
	// контракта (сквозной кейс RBACSUBJ-EXPAND-VAL-RELATION ждёт именно его).
	// Новая ветка про потиповое объявление не имеет права его переписать.
	exp := &fakeLister{}
	uc := authorizedUC(exp)

	_, _, err := uc.Execute(authedCtx(), "account", "acc_x", "sg_compute_instance", 0)
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Equal(t, `Illegal argument relation "sg_compute_instance"`, st.Message())
	assert.Zero(t, exp.calls)
}
