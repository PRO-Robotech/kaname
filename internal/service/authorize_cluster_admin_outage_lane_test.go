// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// authorize_cluster_admin_outage_lane_test.go — общая дверь: неотвеченный вопрос
// НАДЗОРА обязан стать недоступностью, а не вердиктом «не положено» (#1045).
//
// # Почему это дороже, чем в одном use-case
//
// В эту дверь входит каждый запрос платформы: интерсептор всякой службы
// спрашивает `InternalIAMService.Check`, а фильтр списка соседа — `BatchCheck`.
// Схлопнутый исход надзора здесь означает, что мигание хранилища прав приезжает
// к соседу отказом в правах — а отказ в правах его дренаж классифицирует как
// ТЕРМИНАЛЬНЫЙ.
//
// # Четыре решающих пути, и каждый со своей пробой
//
// Надзор спрашивается из четырёх мест, и три из них — запасные (общий
// разрешающий случай до надзора не доходит вовсе). Проба на один путь ничего не
// говорит об остальных: именно так этот класс и пережил закрытие двух площадок.
//
//	1. одиночный вопрос, отношение не разрешается → решает ОДИН надзор;
//	2. одиночный вопрос, форма отказала            → надзор запасным путём;
//	3. внутренняя дверь (CheckRelation)            → надзор запасным путём;
//	4. партия (BatchCheck)                          → надзор запасным путём, мемоизирован.
//
// Рядом с каждой — положительный контроль: доступный надзор, ответивший «нет»,
// по-прежнему даёт ОТКАЗ (а не ошибку), и вердикт попадает в свою позицию.

import (
	"context"
	"errors"
	"testing"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// errClusterStoreDown — отказ ТРАНСПОРТА надзора, не вердикт о правах.
var errClusterStoreDown = errors.New("cluster-admin store unreachable")

// outageClusterChecker — надзор, который не отвечает. Считает вопросы, чтобы
// проба не утверждала о пути, который не исполнялся.
type outageClusterChecker struct{ calls int }

func (c *outageClusterChecker) Check(context.Context, string, string, string) (bool, error) {
	c.calls++
	return false, errClusterStoreDown
}

// mustBeUnavailable — единственное утверждение: ОТВЕТ вызывающему. Не факт
// вызова и не текст: сосед ветвится по недоступности, и только по ней.
func mustBeUnavailable(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: отказа нет вовсе — неотвеченный вопрос надзора стал ВЕРДИКТОМ", what)
	}
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("%s: ошибка %v не является недоступностью — вызывающий не отличит "+
			"«хранилище не ответило» от «не положено», и повтор выглядит бессмысленным", what, err)
	}
}

// ── путь 1: отношение не разрешается, решает один надзор ────────────────────

func TestAuthorize_Check_SuperGateOutage_UnresolvableRelation_IsUnavailable(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &outageClusterChecker{}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_x",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "no.such.verb.at.all", // не разрешается → решает ОДИН надзор
	})

	mustBeUnavailable(t, err, "Check при неотвечающем надзоре и неразрешимом отношении")
	if res != nil && res.Allowed {
		t.Fatal("неотвеченный вопрос надзора дал РАЗРЕШЕНИЕ — это уже не fail-closed")
	}
	if cl.calls == 0 {
		t.Fatal("вопрос надзора не задан — проба утверждала бы о пути, который не исполнялся")
	}
}

func TestAuthorize_Check_UnresolvableRelation_StoreDenies_StaysAVerdict(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{}} // доступен, говорит «нет»
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_x",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "no.such.verb.at.all",
	})
	if err != nil {
		t.Fatalf("доступный надзор, ответивший «нет», обязан дать ВЕРДИКТ, а не ошибку: %v", err)
	}
	if res.Allowed || len(res.DenyReasons) == 0 {
		t.Fatalf("отказ потерял свою форму: allowed=%v, причины=%v", res.Allowed, res.DenyReasons)
	}
}

// ── путь 2: форма отказала, надзор запасным путём ───────────────────────────

func TestAuthorize_Check_SuperGateOutage_AfterPerObjectDeny_IsUnavailable(t *testing.T) {
	store := &mockRelations{checkResp: false} // пообъектный вопрос отказал
	cl := &outageClusterChecker{}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_x",
		Resource: ResourceRef{Type: "compute_instance", ID: "inst_9"},
		Action:   "compute.instances.delete",
	})

	mustBeUnavailable(t, err, "Check при неотвечающем надзоре на запасном пути")
	if res != nil && res.Allowed {
		t.Fatal("неотвеченный вопрос надзора дал РАЗРЕШЕНИЕ")
	}
	if cl.calls == 0 {
		t.Fatal("вопрос надзора не задан")
	}
}

// ── путь 3: внутренняя дверь ────────────────────────────────────────────────

func TestAuthorize_CheckRelation_SuperGateOutage_IsUnavailable(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &outageClusterChecker{}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_x",
		Relation: "v_delete",
		Object:   "vpc_network:vpcn_x",
	})

	mustBeUnavailable(t, err, "CheckRelation при неотвечающем надзоре")
	if res != nil && res.Allowed {
		t.Fatal("неотвеченный вопрос надзора дал РАЗРЕШЕНИЕ на внутренней двери")
	}
	if cl.calls == 0 {
		t.Fatal("вопрос надзора не задан")
	}
}

func TestAuthorize_CheckRelation_StoreDenies_StaysAVerdict(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_x",
		Relation: "v_delete",
		Object:   "vpc_network:vpcn_x",
	})
	if err != nil {
		t.Fatalf("доступный надзор, ответивший «нет», обязан дать ВЕРДИКТ, а не ошибку: %v", err)
	}
	if res.Allowed {
		t.Fatal("отказ превратился в разрешение")
	}
}

// ── путь 4: партия ──────────────────────────────────────────────────────────

// TestAuthorize_BatchCheck_SuperGateOutage_FailsTheBatch — партия роняется
// ЦЕЛИКОМ. Молча суженный набор разрешений — это страница видимого, отданная
// соседу как истина.
func TestAuthorize_BatchCheck_SuperGateOutage_FailsTheBatch(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &outageClusterChecker{}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	reqs := make([]CheckRequest, 4)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:  "user:usr_x",
			Resource: ResourceRef{Type: "compute_instance", ID: "inst_x"},
			Action:   "compute.instances.delete",
		}
	}
	results, err := svc.BatchCheck(context.Background(), reqs)

	mustBeUnavailable(t, err, "BatchCheck при неотвечающем надзоре")
	for i, r := range results {
		if r != nil && r.Allowed {
			t.Fatalf("позиция %d разрешена при неотвеченном вопросе надзора", i)
		}
	}
	if cl.calls == 0 {
		t.Fatal("вопрос надзора не задан")
	}
}

// TestAuthorize_BatchCheck_StoreDenies_EveryVerdictLands — положительный
// контроль: доступный надзор, ответивший «нет», отказывает КАЖДОЙ позиции, и
// партия не роняется.
func TestAuthorize_BatchCheck_StoreDenies_EveryVerdictLands(t *testing.T) {
	store := &mockRelations{checkResp: false}
	cl := &scClusterChecker{admins: map[string]bool{}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store, ClusterAdminChecker: cl})

	reqs := make([]CheckRequest, 4)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:  "user:usr_x",
			Resource: ResourceRef{Type: "compute_instance", ID: "inst_x"},
			Action:   "compute.instances.delete",
		}
	}
	results, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("доступный надзор, ответивший «нет», обязан дать ВЕРДИКТЫ, а не ошибку: %v", err)
	}
	if len(results) != len(reqs) {
		t.Fatalf("позиций в ответе %d при %d в запросе", len(results), len(reqs))
	}
	for i, r := range results {
		if r == nil || r.Allowed {
			t.Fatalf("позиция %d: вердикт не доехал (%+v)", i, r)
		}
	}
}
