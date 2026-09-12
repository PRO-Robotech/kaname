// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// own_front_hop_chain_injection_test.go — доказательство того, что перепись
// ЦЕПОЧКИ и её утверждения способны упасть, и падают каждое на своём предмете.
//
// # Осей три, и третья заведена потому, что первые две её не покрывают
//
//  1. СУЖЕНИЕ — хоп не объявлен. Дословно дерево ДО правки.
//  2. РАСШИРЕНИЕ мимо круга края — соблазнительная неверная починка «имя не
//     разобралось, но лист наш — пропустить».
//  3. ОСВОБОЖДЕНИЕ ОТ ПОЛА ЧИТАЮЩИХ — вторая соблазнительная починка: «хоп уже
//     признан полом, признаем и здесь». Она НЕ ловится вложением в допуск
//     модуля: освобождённый хоп СРАВНИВАЕТСЯ с модулем, не превышая его. Именно
//     поэтому у неё своё утверждение, и именно поэтому здесь проверяется ОБЕ
//     стороны: новое утверждение краснеет, а вложение МОЛЧИТ. Молчание вложения
//     тут не недостаток — оно доказывает, что новое утверждение несущее, а не
//     дубль.
//
// # Законный близнец
//
// Действующая цепочка молчит по всем трём. Без него красное ниже приходило бы
// от чего угодно.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// deniedByChain — сколько маршрутов отвергает данная цепочка в боевой посадке.
func deniedByChain(t *testing.T, gates []chainGate) int {
	t.Helper()
	routed := routedInternalMethods(t)
	ctx := newOwnFrontHopCtx()
	n := 0
	for _, m := range routed {
		if chainDenier(gates, ctx, m) != "" {
			n++
		}
	}
	return n
}

// relationTierLeak — сколько методов под полом читающих проходит хоп.
func relationTierLeak(t *testing.T, gates []chainGate) int {
	t.Helper()
	floor := map[string]bool{}
	for _, m := range ReadFloorRPCs() {
		floor[m] = true
	}
	hop := chainAdmitted(gates, newOwnFrontHopCtx(), internalMethods(t))
	n := 0
	for m := range hop {
		if floor[m] {
			n++
		}
	}
	return n
}

// chainExcess — на скольких методах цепочка пропускает хоп там, где отвергает
// проверенный модуль.
func chainExcess(t *testing.T, gates []chainGate) int {
	t.Helper()
	methods := internalMethods(t)
	hop := chainAdmitted(gates, newOwnFrontHopCtx(), methods)
	module := chainAdmitted(gates, newVPCCtx(), methods)
	return len(diff(hop, module))
}

// revertedChain — цепочка без объявленного хопа: дерево ДО правки.
func revertedChain() []chainGate { return internalChain(true, false) }

// chainPastTheGatewayCircle — хоп пропускается МИМО круга края.
func chainPastTheGatewayCircle() []chainGate {
	gates := internalChain(true, true)
	inner := gates[0].decide
	gates[0].decide = func(ctx context.Context, fullMethod string) error {
		if san, verified := grpcsrv.CertIdentityFromContext(ctx); verified && san == ownFrontHopSAN {
			return nil
		}
		return inner(ctx, fullMethod)
	}
	return gates
}

// chainExemptFromTheReadFloor — хоп освобождён от пола читающих.
//
// Ровно один изменённый факт против законного близнеца: политика вызывающего и
// ступень подтверждения остаются действующими.
func chainExemptFromTheReadFloor() []chainGate {
	gates := internalChain(true, true)
	inner := gates[1].decide
	gates[1].decide = func(ctx context.Context, fullMethod string) error {
		if san, verified := grpcsrv.CertIdentityFromContext(ctx); verified && san == ownFrontHopSAN {
			return nil
		}
		return inner(ctx, fullMethod)
	}
	return gates
}

// TestOwnFrontHopChainInjection_NarrowingIsCaught — возврат дефекта ловится
// переписью цепочки: отвергнуто ВСЁ.
func TestOwnFrontHopChainInjection_NarrowingIsCaught(t *testing.T) {
	routed := len(routedInternalMethods(t))
	if got := deniedByChain(t, revertedChain()); got != routed {
		t.Fatalf("цепочка без объявленного хопа отвергла %d из %d, ожидалось всё — "+
			"перепись не заметила бы возврата дефекта", got, routed)
	}
	if got := deniedByChain(t, internalChain(true, true)); got >= routed {
		t.Fatalf("действующая цепочка отвергла %d из %d — «после» ничего не доказывает", got, routed)
	}
}

// TestOwnFrontHopChainInjection_WideningPastTheGatewayCircleIsCaught —
// расширение ловится ИЗБЫТКОМ, а не просто краснотой.
func TestOwnFrontHopChainInjection_WideningPastTheGatewayCircleIsCaught(t *testing.T) {
	gates := chainPastTheGatewayCircle()
	if got := chainExcess(t, gates); got == 0 {
		t.Fatal("хоп, пропущенный мимо круга края, не дал избытка — утверждение не заметило бы, " +
			"что полоса HTTP стала шире полосы gRPC")
	}
	// Отказов при этом остаётся НЕ НОЛЬ, и это не изъян инъекции: часть круга
	// края лежит ещё и под полом читающих, который инъекция не трогает. Поэтому
	// утверждается СНИЖЕНИЕ против законного близнеца, а не пустота — «ноль
	// отказов» здесь был бы требованием сломать сразу двух стражей, то есть
	// инъекцией не на один факт.
	legit := deniedByChain(t, internalChain(true, true))
	broken := deniedByChain(t, gates)
	if broken >= legit {
		t.Fatalf("цепочка, пропускающая хоп мимо круга края, отвергла %d против %d у действующей — "+
			"инъекция подана не туда", broken, legit)
	}
	t.Logf("расширение мимо круга края: отвергнуто %d против %d · избыток %d",
		broken, legit, chainExcess(t, gates))
}

// TestOwnFrontHopChainInjection_ReadFloorExemptionIsCaughtOnlyByItsOwnAssertion —
// третья ось, и обе её стороны несущие.
//
// Освобождение от пола читающих обязано краснеть у СВОЕГО утверждения и
// оставаться невидимым для вложения. Вторая половина доказывает, что новое
// утверждение не дубль: не будь его, эта починка прошла бы за исправление.
func TestOwnFrontHopChainInjection_ReadFloorExemptionIsCaughtOnlyByItsOwnAssertion(t *testing.T) {
	gates := chainExemptFromTheReadFloor()
	leak := relationTierLeak(t, gates)
	if leak == 0 {
		t.Fatal("хоп, освобождённый от пола читающих, не прошёл ни одного метода под ним — " +
			"утверждение об отношениях не заметило бы этой починки")
	}
	if excess := chainExcess(t, gates); excess != 0 {
		t.Fatalf("вложение в допуск модуля дало избыток %d — эта ось должна быть ему НЕВИДИМА, "+
			"иначе доказательство несущности нового утверждения ложно", excess)
	}
	t.Logf("освобождение от пола читающих: методов под ним пройдено %d · избыток по вложению %d",
		leak, 0)
}

// TestOwnFrontHopChainInjection_LegitimateTwinStaysSilent — действующая цепочка
// молчит по всем трём величинам, в ОБЕИХ посадках.
func TestOwnFrontHopChainInjection_LegitimateTwinStaysSilent(t *testing.T) {
	for _, prod := range []bool{true, false} {
		gates := internalChain(prod, true)
		if got := chainExcess(t, gates); got != 0 {
			t.Errorf("prod=%v: действующая цепочка даёт избыток %d", prod, got)
		}
		if !prod {
			continue
		}
		if got := relationTierLeak(t, gates); got != 0 {
			t.Errorf("prod=%v: действующая цепочка пропускает хоп на %d методов под полом читающих",
				prod, got)
		}
	}
}
