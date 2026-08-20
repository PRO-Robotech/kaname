// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// authorize_switch_test.go — ПЕРЕКЛЮЧЁННЫЙ ТИП НА КРАЮ: решает форма.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ КРАЮ НУЖНЫ СВОИ ПРОБЫ, ХОТЯ РУБИЛЬНИК ОДИН
//
// Край через обёртку собственных стражей НЕ ПРОХОДИТ: композиционный корень
// выдаёт ему голый транспорт, и это записанное решение. Значит маршрутизация у
// него своя, и проба обёртки о ней не утверждает ничего.
//
// Композиция вердикта у края тоже своя и состоит ИЗ ТРЁХ слагаемых: ответ
// движка, плоский надзор администратора облака и структурный запасной путь.
// Переключение обязано заменить композицию ЦЕЛИКОМ, а не первое слагаемое, —
// иначе «источник вердикта для этого типа — форма» неправда, и неправда
// молчаливая: ответ вызывающему выглядит исправным.

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// switchingShadow — сравнение с переключённым рубильником для края.
type switchingShadow struct {
	tracingShadow

	switched   map[string]bool
	formAllows map[string]bool
	formErr    error

	verdicts    []string
	engineAsked int
}

func (s *switchingShadow) Decides(objectType string) bool { return s.switched[objectType] }

func (s *switchingShadow) Verdict(
	ctx context.Context, subject, objectType, objectID, relation string,
	_ map[string]any, askEngine func(context.Context) (bool, bool),
) (bool, error) {
	s.verdicts = append(s.verdicts, subject+"|"+objectType+"|"+objectID+"|"+relation)
	if s.formErr != nil {
		return false, s.formErr
	}
	if askEngine != nil {
		askEngine(ctx)
		s.engineAsked++
	}
	return s.formAllows[objectType+":"+objectID], nil
}

func edgeWithSwitch(engineAllows bool, formAllows map[string]bool, types ...string) (*AuthorizeService, *tracingRelations, *switchingShadow) {
	tr := &trace{}
	engine := &tracingRelations{tr: tr, allow: engineAllows}
	shadow := &switchingShadow{
		tracingShadow: tracingShadow{tr: tr},
		switched:      map[string]bool{},
		formAllows:    formAllows,
	}
	for _, ty := range types {
		shadow.switched[ty] = true
	}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: engine, Shadow: shadow})
	return svc, engine, shadow
}

func checkOne(t *testing.T, svc *AuthorizeService, objectType, objectID string) (*CheckResult, error) {
	t.Helper()
	return svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr-1",
		Resource: ResourceRef{Type: objectType, ID: objectID},
		Action:   "vpc.networks.get",
	})
}

// Вердикт переключённого типа принадлежит ФОРМЕ. Ответы намеренно
// противоположны — иначе утверждение тождественно истинно.
func TestEdgeSwitchedTypeReturnsTheFormsVerdict(t *testing.T) {
	svc, _, shadow := edgeWithSwitch(false, map[string]bool{"vpc_network:net-1": true}, "vpc_network")

	res, err := checkOne(t, svc, "vpc_network", "net-1")

	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !res.Allowed {
		t.Fatal("вернулся ответ движка — источник вердикта на краю не переключён")
	}
	if len(shadow.verdicts) != 1 {
		t.Fatalf("форму обязаны спросить ровно один раз, спросили %d", len(shadow.verdicts))
	}
	if len(shadow.askedKinds()) != 0 {
		t.Fatalf("на переключённом типе решение не предъявляется как ДВИЖКОВОЕ: %v", shadow.askedKinds())
	}
}

// Зеркальная половина.
func TestEdgeSwitchedTypeReturnsTheFormsDenial(t *testing.T) {
	svc, _, _ := edgeWithSwitch(true, map[string]bool{}, "vpc_network")

	res, err := checkOne(t, svc, "vpc_network", "net-1")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if res.Allowed {
		t.Fatal("вернулся ответ движка вместо отказа формы")
	}
	if len(res.DenyReasons) == 0 {
		t.Fatal("отказ обязан нести причину — молчаливый отказ неотличим от сорванного вопроса")
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: не переключённый тип идёт прежним путём.
func TestEdgeUnswitchedTypeStillGoesToTheEngine(t *testing.T) {
	svc, engine, shadow := edgeWithSwitch(true, map[string]bool{}, "vpc_network")

	res, err := checkOne(t, svc, "vpc_subnet", "sub-1")
	if err != nil || !res.Allowed {
		t.Fatalf("не переключённый тип обязан отвечаться движком: allowed=%v err=%v", res.Allowed, err)
	}
	if len(shadow.verdicts) != 0 {
		t.Fatalf("форма решала по не названному типу: %v", shadow.verdicts)
	}
	if len(shadow.askedKinds()) != 1 {
		t.Fatalf("решение движка обязано быть предъявлено сравнению: %v", shadow.askedKinds())
	}
	_ = engine
}

// ОТКАЗ ФОРМЫ — недоступность, а не отказ в доступе и не поход к движку.
func TestEdgeFormFailureSurfacesAsUnavailable(t *testing.T) {
	svc, engine, shadow := edgeWithSwitch(true, map[string]bool{}, "vpc_network")
	shadow.formErr = errors.New("форма не ответила")

	res, err := checkOne(t, svc, "vpc_network", "net-1")

	if err == nil {
		t.Fatal("отказ формы обязан доехать до вызывающего ошибкой")
	}
	if res != nil && res.Allowed {
		t.Fatal("подставлен ответ движка")
	}
	if len(engine.tr.snapshot()) != 0 {
		t.Fatalf("движок спрошен на пути запроса — молчаливый возврат к нему: %v", engine.tr.snapshot())
	}
}

// АВАРИЙНЫЙ ПУТЬ АДМИНИСТРАТОРА ОБЛАКА переживает переключение типа.
//
// Плоский надзор — вопрос об ОБЪЕКТЕ `cluster`, а не о ресурсе, и потому не
// зависит ни от цепи областей, ни от доставки рёбер. Его позиция управляется
// собственным типом `cluster`; на переключении ЧУЖОГО типа он обязан остаться
// на месте — иначе человек, обязанный всё починить, теряет доступ ровно тогда,
// когда он нужен.
func TestCloudAdminStillReachesASwitchedType(t *testing.T) {
	tr := &trace{}
	engine := &tracingRelations{tr: tr, allow: false}
	admin := &alwaysAdmin{}
	shadow := &switchingShadow{
		tracingShadow: tracingShadow{tr: tr},
		switched:      map[string]bool{"vpc_network": true},
		formAllows:    map[string]bool{}, // форма отказывает
	}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: engine, Shadow: shadow, ClusterAdminChecker: admin,
	})

	res, err := checkOne(t, svc, "vpc_network", "net-1")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !res.Allowed {
		t.Fatal("администратор облака потерял доступ к переключённому типу — аварийный путь оборван")
	}
}

// alwaysAdmin — плоский надзор, отвечающий «да».
type alwaysAdmin struct{}

func (alwaysAdmin) Check(context.Context, string, string, string) (bool, error) { return true, nil }

func (alwaysAdmin) CheckWithContextualTuples(
	context.Context, string, string, string, map[string]any, []authztypes.TupleKey,
) (bool, error) {
	return true, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ВНУТРЕННЯЯ ДВЕРЬ — та, через которую идёт КАЖДЫЙ запрос платформы
//
// `InternalIAMService.Check` делегирует не в `Check`, а в `CheckRelation`:
// вызывающий уже принёс разрешённое отношение, и шаг «действие → отношение»
// пропускается. Дверей, стало быть, две, и маршрутизация нужна ОБЕИМ.
//
// Эти пробы дописаны ПОСЛЕ того, как стенд показал `verdicts_form` = 0 при
// 6611 решениях и четырнадцати переключённых типах: пробы утверждали публичную
// дверь, а нагрузка шла во внутреннюю. Утверждение о наблюдаемом («чей ответ
// получил вызывающий») было верным — и относилось не к той двери.
// ─────────────────────────────────────────────────────────────────────────────

func checkRelationOne(t *testing.T, svc *AuthorizeService, object, relation string) (*CheckResult, error) {
	t.Helper()
	return svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr-1",
		Relation: relation,
		Object:   object,
	})
}

func TestInternalGateSwitchedTypeReturnsTheFormsVerdict(t *testing.T) {
	svc, _, shadow := edgeWithSwitch(false, map[string]bool{"vpc_network:net-1": true}, "vpc_network")

	res, err := checkRelationOne(t, svc, "vpc_network:net-1", "v_get")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !res.Allowed {
		t.Fatal("внутренняя дверь вернула ответ движка — через неё идёт КАЖДЫЙ запрос платформы")
	}
	if len(shadow.verdicts) != 1 {
		t.Fatalf("форму обязаны спросить ровно один раз, спросили %d", len(shadow.verdicts))
	}
}

func TestInternalGateSwitchedTypeReturnsTheFormsDenial(t *testing.T) {
	svc, _, _ := edgeWithSwitch(true, map[string]bool{}, "vpc_network")

	res, err := checkRelationOne(t, svc, "vpc_network:net-1", "v_get")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if res.Allowed {
		t.Fatal("внутренняя дверь вернула ответ движка вместо отказа формы")
	}
}

// Положительный контроль: не переключённый тип идёт прежним путём.
func TestInternalGateUnswitchedTypeStillGoesToTheEngine(t *testing.T) {
	svc, _, shadow := edgeWithSwitch(true, map[string]bool{}, "vpc_network")

	res, err := checkRelationOne(t, svc, "vpc_subnet:sub-1", "v_get")
	if err != nil || !res.Allowed {
		t.Fatalf("не переключённый тип обязан отвечаться движком: allowed=%v err=%v", res.Allowed, err)
	}
	if len(shadow.verdicts) != 0 {
		t.Fatalf("форма решала по не названному типу: %v", shadow.verdicts)
	}
	if len(shadow.askedKinds()) != 1 {
		t.Fatalf("решение движка обязано быть предъявлено сравнению: %v", shadow.askedKinds())
	}
}

// Отказ формы на внутренней двери — недоступность, а не отказ в доступе.
func TestInternalGateFormFailureSurfacesAsUnavailable(t *testing.T) {
	svc, engine, shadow := edgeWithSwitch(true, map[string]bool{}, "vpc_network")
	shadow.formErr = errors.New("форма не ответила")

	res, err := checkRelationOne(t, svc, "vpc_network:net-1", "v_get")
	if err == nil {
		t.Fatal("отказ формы обязан доехать до вызывающего ошибкой")
	}
	if res != nil && res.Allowed {
		t.Fatal("подставлен ответ движка")
	}
	if len(engine.tr.snapshot()) != 0 {
		t.Fatalf("движок спрошен на пути запроса: %v", engine.tr.snapshot())
	}
}

// Администратор облака достигает переключённого типа и через внутреннюю дверь.
func TestInternalGateCloudAdminStillReachesASwitchedType(t *testing.T) {
	tr := &trace{}
	shadow := &switchingShadow{
		tracingShadow: tracingShadow{tr: tr},
		switched:      map[string]bool{"vpc_network": true},
		formAllows:    map[string]bool{},
	}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           &tracingRelations{tr: tr, allow: false},
		Shadow:              shadow,
		ClusterAdminChecker: alwaysAdmin{},
	})

	res, err := checkRelationOne(t, svc, "vpc_network:net-1", "v_get")
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !res.Allowed {
		t.Fatal("администратор облака потерял доступ через внутреннюю дверь — аварийный путь оборван")
	}
}
