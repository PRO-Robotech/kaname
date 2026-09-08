// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

// expand_relations_undeclared_pair_test.go — СОСЕДНИЙ глагол того же класса
// (#1290).
//
// ExpandRelations принимает пару (тип ресурса, отношение) ЦЕЛИКОМ от
// вызывающего и не спрашивает о ней ничего, а разбирает её та же компиляция
// плана. Пара, которой тип не объявляет, доезжала до формы и возвращалась
// UNAVAILABLE — то есть «повтори позже» на ввод, который не станет годным
// никогда.

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

func TestHandler_ExpandRelations_PairTheTypeDoesNotDeclare_IsTerminal(t *testing.T) {
	h := newHandler(true)

	_, err := h.ExpandRelations(moduleCertCtx(), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_x"},
		Relation: "v_addtargets",
	})
	if err == nil {
		t.Fatalf("пара, которой тип не объявляет, обязана быть отвергнута")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v; ожидался InvalidArgument — повтор такого запроса не пройдёт никогда", st.Code())
	}
	if !strings.Contains(st.Message(), "relation") || !strings.Contains(st.Message(), "vpc_network") {
		t.Errorf("message = %q; отказ обязан называть поле и тип", st.Message())
	}
}

func TestHandler_ExpandRelations_UndeclaredResourceType_IsTerminal(t *testing.T) {
	h := newHandler(true)

	_, err := h.ExpandRelations(moduleCertCtx(), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "no_such_object_type_1290", Id: "x_1"},
		Relation: "viewer",
	})
	if err == nil {
		t.Fatalf("необъявленный тип ресурса обязан быть отвергнут")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v; ожидался InvalidArgument", st.Code())
	}
	if !strings.Contains(st.Message(), "resource.type") {
		t.Errorf("message = %q; виновное поле здесь — тип ресурса", st.Message())
	}
}

// TestHandler_ExpandRelations_DeclaredPair_StillAnswers — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
// к обоим отрицаниям: объявленная пара по-прежнему доходит до источника и
// отвечает. Без него отказы выше зеленели бы на RPC, отвергающем всё.
func TestHandler_ExpandRelations_DeclaredPair_StillAnswers(t *testing.T) {
	h := newHandler(true)

	resp, err := h.ExpandRelations(moduleCertCtx(), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_x"},
		Relation: "viewer",
	})
	if err != nil {
		t.Fatalf("объявленная пара обязана отвечать: %v", err)
	}
	if resp.GetTree() == nil || len(resp.GetTree().GetLeaves()) == 0 {
		t.Errorf("ожидались основания права; получено %+v", resp.GetTree())
	}
}
