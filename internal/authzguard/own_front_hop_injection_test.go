// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// own_front_hop_injection_test.go — доказательство того, что утверждение о хопе
// СПОСОБНО упасть, и падает на своём предмете, а не на соседнем (#2371).
//
// # Осей две, по числу сторон утверждения
//
//  1. СУЖЕНИЕ — хоп не проходит пол. Это дословно состояние дерева ДО правки, и
//     подаётся оно не переписанной копией, а действующей политикой БЕЗ
//     объявленного хопа: один изменённый факт против законного близнеца.
//  2. РАСШИРЕНИЕ — хоп проходит ВСЁ, включая круг края. Это соблазнительная
//     неверная починка: «имя не разобралось, но это мы — пропустить». Подаётся
//     решением, которое так и делает.
//
// Обе обязаны краснеть, и краснеть РАЗНЫМИ величинами: сужение — недостачей,
// расширение — избытком. Проба, утверждающая только «покраснело», не отличила бы
// починку, поменявшую одну беду на другую.
//
// # Законный близнец
//
// Действующая политика с объявленным хопом молчит по обеим величинам. Без него
// красное ниже приходило бы от чего угодно.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// revertedHopDecision — дерево ДО правки: хоп полом не признаётся.
//
// Не копия разбора, а действующая политика без объявленной величины: так мир
// инъекции отличается от законного близнеца РОВНО ОДНИМ фактом.
func revertedHopDecision(prod bool) hopDecision { return testPolicy(prod).allow }

// naiveHopDecision — соблазнительная неверная починка: «имя не разобралось, но
// лист наш — пропустить».
//
// Она выглядит минимальной и закрывает предмет задачи целиком: фронт начинает
// обслуживать все свои маршруты. Цена не видна ни в диффе, ни на стенде — на
// стенде политика вырождается, а в диффе обе половины защитимы порознь. Платит
// за неё держатель ЛЮБОГО листа внутреннего центра: дотянувшись до фронта по
// HTTP, он получает глаголы, запрещённые ему на gRPC.
func naiveHopDecision(prod bool) hopDecision {
	p := hopPolicy(prod)
	return func(ctx context.Context, fullMethod string) error {
		if san, verified := grpcsrv.CertIdentityFromContext(ctx); verified && p.isOwnFrontHop(san) {
			return nil
		}
		return p.allow(ctx, fullMethod)
	}
}

// TestOwnFrontHopInjection_NarrowingIsCaught — сужение поймано, и поймано
// НЕДОСТАЧЕЙ.
func TestOwnFrontHopInjection_NarrowingIsCaught(t *testing.T) {
	methods := internalMethods(t)
	extra, missing := hopVersusModule(revertedHopDecision(true), methods)
	if len(missing) == 0 {
		t.Fatal("хоп без объявления сравнялся с модулем — утверждение не заметило бы возврата дефекта")
	}
	if len(extra) != 0 {
		t.Fatalf("сужение дало ИЗБЫТОК %v — величины перепутаны, и починка одной беды на другую "+
			"прошла бы за исправление", extra)
	}
	t.Logf("сужение: хопу недостаёт %d методов из %d", len(missing), len(methods))
}

// TestOwnFrontHopInjection_WideningIsCaught — расширение поймано, и поймано
// ИЗБЫТКОМ.
func TestOwnFrontHopInjection_WideningIsCaught(t *testing.T) {
	methods := internalMethods(t)
	extra, missing := hopVersusModule(naiveHopDecision(true), methods)
	if len(extra) == 0 {
		t.Fatal("хоп, пропущенный мимо круга края, сравнялся с модулем — утверждение не заметило бы, " +
			"что полоса HTTP стала шире полосы gRPC")
	}
	if len(missing) != 0 {
		t.Fatalf("расширение дало НЕДОСТАЧУ %v — величины перепутаны", missing)
	}
	t.Logf("расширение: хопу позволено на %d методов больше из %d", len(extra), len(methods))
}

// TestOwnFrontHopInjection_LegitimateTwinStaysSilent — законный близнец, и он
// несущий: без него красное выше приходило бы от чего угодно.
//
// Обе посадки: в не-боевой политика вырождается целиком, и молчание там —
// отдельный факт, а не следствие первого.
func TestOwnFrontHopInjection_LegitimateTwinStaysSilent(t *testing.T) {
	methods := internalMethods(t)
	for _, prod := range []bool{true, false} {
		extra, missing := hopVersusModule(hopPolicy(prod).allow, methods)
		if len(extra) > 0 || len(missing) > 0 {
			t.Errorf("prod=%v: действующая политика расходится с модулем (избыток %v, недостача %v)",
				prod, extra, missing)
		}
	}
}

// TestOwnFrontHopInjection_CensusReproducesTheDefect — перепись маршрутов тоже
// способна упасть, и её «до» воспроизводит предмет задачи дословно.
//
// Утверждается ПАРА чисел: необъявленный хоп отвергается целиком, объявленный —
// нет. Одно число не отличило бы починку от политики, пропускающей всё.
func TestOwnFrontHopInjection_CensusReproducesTheDefect(t *testing.T) {
	routed := routedInternalMethods(t)
	ctx := newOwnFrontHopCtx()
	count := func(decide hopDecision) int {
		denied := 0
		for _, m := range routed {
			if decide(ctx, m) != nil {
				denied++
			}
		}
		return denied
	}
	before := count(revertedHopDecision(true))
	after := count(hopPolicy(true).allow)
	naive := count(naiveHopDecision(true))
	t.Logf("боевая посадка, маршрутов %d: до %d отвергнутых · после %d · при неверной починке %d",
		len(routed), before, after, naive)
	if before != len(routed) {
		t.Errorf("«до» отвергает %d из %d, ожидалось всё — перепись перестала воспроизводить предмет",
			before, len(routed))
	}
	if after >= before {
		t.Errorf("«после» отвергает %d, «до» — %d: правка ничего не изменила", after, before)
	}
	if naive != 0 {
		t.Errorf("неверная починка отвергает %d вместо 0 — она перестала быть тем, от чего "+
			"утверждение защищает, и инъекция потеряла предмет", naive)
	}
}
