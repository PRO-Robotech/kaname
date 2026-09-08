// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_front_hop_chain_census_test.go — что собственный внутренний REST-фронт
// обслуживает НА ПУТИ ЗАПРОСА, а не на одном страже.
//
// # Зачем отдельно от переписи по политике вызывающего
//
// Соседняя перепись (own_front_hop_caller_policy_test.go) судит ОДИН рукав —
// политику вызывающего. Её «пропущено N» верно про неё и ШИРЕ того, что
// увидит арендатор: за политикой в той же цепочке стоят ещё два стража, и один
// из них судит хоп ТЕМ ЖЕ разбором имени модуля, которым судила политика.
//
// Число, названное по одному стражу, есть заявление шире сделанного. Поэтому
// отчётной величиной служит перепись ЦЕПОЧКИ, а перепись по рукаву остаётся
// там, где она верна, — при своём страже.
//
// # Порядок стражей повторяет композиционный корень
//
// cmd/kaname/serve.go, внутренний слушатель: политика вызывающего → пол
// читающих → ступень подтверждения личности. Порядок несущий: каждый следующий
// вправе рассчитывать, что предыдущий уже отказал.
//
// # Соседи подаются в САМОЙ СНИСХОДИТЕЛЬНОЙ посадке, и это в РАЗНЫЕ стороны
//
// Пол читающих получает решателя, отвечающего «разрешено» на любое отношение:
// тогда всё, что он ОТВЕРГАЕТ, отвергнуто не из-за ненайденного отношения, а
// из-за разбора имени — то есть по предмету задачи.
//
// Ступень подтверждения получает каталог БЕЗ требований. Здесь снисходительность
// обязательна по другой причине, и она стоила отдельного прогона: строгий
// каталог отвергает круг края ВТОРЫМ замком, и тогда инъекция, пропускающая хоп
// мимо ПЕРВОГО, не меняет вердикта цепочки ни на один маршрут — расширение
// становится невидимым, а доказательство способности упасть ложным. Проверено
// подачей: со строгим каталогом обе цепочки отвергают 21, с пустым — 21 против
// 1. Что ступень при этом ничего не отнимает у хопа сверх уже отвергнутого,
// утверждается ОТДЕЛЬНО и как раз строгим каталогом
// (TestOwnFrontHop_StepUpArmAddsNothingForTheHop).
package authzguard

import (
	"context"
	"sort"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// СОСЕДИ ПО ЦЕПОЧКЕ В САМОЙ СНИСХОДИТЕЛЬНОЙ ПОСАДКЕ

// grantsEveryRelation — решатель отношений, отвечающий «разрешено» всегда.
//
// Пол читающих спрашивает отношение ПОСЛЕ того, как вывел учётную запись из
// имени. Всеразрешающий решатель делает первый шаг единственной причиной
// отказа: если пол отверг, то не потому, что отношения не нашлось.
type grantsEveryRelation struct{}

func (grantsEveryRelation) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// declaresNoStepUp — каталог без требований к ступени подтверждения.
//
// Ступень при таком каталоге пропускает всё и потому не приписывает себе чужих
// отказов. Это нужно ИМЕННО переписи: со строгим каталогом ступень становится
// вторым замком на круге края и делает невидимой инъекцию, ломающую первый.
type declaresNoStepUp struct{}

func (declaresNoStepUp) RequiredACRMin(string) string { return "" }

// demandsHighestStepUp — каталог, требующий высшей ступени от КАЖДОГО метода.
//
// Строже действующего намеренно и применяется ровно в одном утверждении: что
// ступень не отнимает у хопа ничего сверх уже отвергнутого. Такое утверждение
// имеет силу только при максимальном требовании.
type demandsHighestStepUp struct{}

func (demandsHighestStepUp) RequiredACRMin(string) string { return "2" }

// ─────────────────────────────────────────────────────────────────────────────
// ЦЕПОЧКА

// chainGate — страж цепочки под своим именем.
//
// Имя нужно самой переписи: «отвергнуто 21» без указания, КТО отверг, не
// отличает предмет задачи от соседнего стража, и починка пошла бы не туда.
type chainGate struct {
	name   string
	decide hopDecision
}

// internalChain собирает трёх стражей вызывающего внутреннего слушателя в том
// же порядке, в каком их выстраивает композиционный корень.
//
// hopDeclared — единственный изменяемый факт между «до» и «после»: посадка,
// сборка и соседи те же. Иначе перепись сравнивала бы два разных мира.
func internalChain(prod, hopDeclared bool) []chainGate {
	policy := testPolicy(prod)
	if hopDeclared {
		policy = policy.WithOwnFrontHop(ownFrontHopSAN)
	}
	viewer := NewSystemViewerFloor(grantsEveryRelation{}, ReadFloorRPCs()).WithProductionMode(prod)
	acr := NewACRFloor(declaresNoStepUp{}, GatewayFrontedInternalRPCs()).WithProductionMode(prod)
	return []chainGate{
		{"политика вызывающего", policy.allow},
		{"пол читающих", viewer.allow},
		{"ступень подтверждения", acr.allow},
	}
}

// chainDenier — имя ПЕРВОГО стража, отвергшего вызов, либо пустая строка, если
// вызов прошёл цепочку целиком.
//
// Первого, а не всех: на пути запроса второй страж после отказа первого не
// исполняется вовсе, и приписывать ему отказ значило бы утверждать о том, чего
// не происходит.
func chainDenier(gates []chainGate, ctx context.Context, fullMethod string) string {
	for _, g := range gates {
		if g.decide(ctx, fullMethod) != nil {
			return g.name
		}
	}
	return ""
}

// chainAdmitted — множество методов, прошедших цепочку целиком.
func chainAdmitted(gates []chainGate, ctx context.Context, methods []string) map[string]bool {
	out := make(map[string]bool, len(methods))
	for _, m := range methods {
		if chainDenier(gates, ctx, m) == "" {
			out[m] = true
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ОТЧЁТНАЯ ПЕРЕПИСЬ

// TestOwnFrontHop_ChainCensus — сколько маршрутов внутреннего фронта доживает
// до обработчика в каждой посадке, до и после объявления хопа, с разбивкой по
// стражу-отказчику.
//
// «До» — не прошлая ревизия дерева, а та же сборка без объявленного хопа: один
// изменённый факт. Перепись остаётся воспроизводимой и после того, как дефекта
// не станет.
//
// Печатается ВСЕГДА: «ноль отвергнутых» обязано быть отличимо от «ноль
// осмотренных».
func TestOwnFrontHop_ChainCensus(t *testing.T) {
	routed := routedInternalMethods(t)
	ctx := newOwnFrontHopCtx()

	type census struct {
		denied int
		byGate map[string]int
	}
	take := func(prod, declared bool) census {
		gates := internalChain(prod, declared)
		c := census{byGate: map[string]int{}}
		for _, m := range routed {
			if who := chainDenier(gates, ctx, m); who != "" {
				c.denied++
				c.byGate[who]++
			}
		}
		return c
	}

	var prodUndeclared, prodDeclared census
	for _, prod := range []bool{true, false} {
		posture := "стенд"
		if prod {
			posture = "боевая"
		}
		for _, declared := range []bool{false, true} {
			c := take(prod, declared)
			names := make([]string, 0, len(c.byGate))
			for n := range c.byGate {
				names = append(names, n)
			}
			sort.Strings(names)
			breakdown := ""
			for _, n := range names {
				breakdown += " · " + n + " " + itoa(c.byGate[n])
			}
			t.Logf("посадка %-7s · хоп объявлен %-5v : маршрутов %d · отвергнуто %2d · пропущено %2d%s",
				posture, declared, len(routed), c.denied, len(routed)-c.denied, breakdown)
			if prod && !declared {
				prodUndeclared = c
			}
			if prod && declared {
				prodDeclared = c
			}
		}
	}

	// Предмет задачи воспроизводится: без объявленного хопа боевая посадка
	// отвергает КАЖДЫЙ маршрут фронта.
	if prodUndeclared.denied != len(routed) {
		t.Errorf("боевая посадка, хоп НЕ объявлен: отвергнуто %d из %d, ожидалось всё — "+
			"перепись перестала воспроизводить предмет задачи, и «после» больше ничего не доказывает",
			prodUndeclared.denied, len(routed))
	}
	// Исход задачи: поверхность обслуживает СВОЮ полосу, а не ноль.
	if prodDeclared.denied >= len(routed) {
		t.Errorf("боевая посадка, хоп объявлен: отвергнуто %d из %d — "+
			"фронт по-прежнему не обслуживает НИ ОДНОГО маршрута",
			prodDeclared.denied, len(routed))
	}
	// Обратная сторона: полоса HTTP не стала шире полосы gRPC. Утверждается
	// вложением, а не числом: круг края растёт, и число устарело бы молча.
	if prodDeclared.denied == 0 {
		t.Errorf("боевая посадка, хоп объявлен: отвергнуто 0 из %d — цепочка пропускает хоп всюду, "+
			"то есть полоса HTTP стала шире полосы gRPC", len(routed))
	}
}

// TestOwnFrontHop_ChainNeverAdmitsMoreThanAVerifiedModule — цепочка не
// пропускает хоп НИ НА ОДНОМ методе, на котором она отвергает проверенный
// модуль.
//
// Вложение, а не равенство, и это принципиально. Равенства здесь нет и быть не
// должно: пол читающих спрашивает у вызывающего ОТНОШЕНИЕ, а у хопа нет
// учётной записи, на которой отношение можно держать. Требовать равенства
// значило бы требовать выдать хопу право, которого он не может нести, — то
// есть открыть по HTTP то, что по gRPC открыто трём названным учётным записям.
//
// Сверяется на ОБЕИХ посадках: в не-боевой стражи вырождаются, и вердикт одной
// посадки о другой не говорит ничего.
func TestOwnFrontHop_ChainNeverAdmitsMoreThanAVerifiedModule(t *testing.T) {
	methods := internalMethods(t)
	for _, prod := range []bool{true, false} {
		gates := internalChain(prod, true)
		hop := chainAdmitted(gates, newOwnFrontHopCtx(), methods)
		module := chainAdmitted(gates, newVPCCtx(), methods)
		if extra := diff(hop, module); len(extra) > 0 {
			t.Errorf("prod=%v: цепочка пропускает хопу фронта то, что отвергает проверенному модулю "+
				"(%d из %d): %v — полоса HTTP шире полосы gRPC",
				prod, len(extra), len(methods), extra)
		}
		t.Logf("prod=%-5v : методов внутреннего слушателя %d · цепочка пропускает хопу %d · модулю %d",
			prod, len(methods), len(hop), len(module))
	}
}

// TestOwnFrontHop_ChainNeverPassesARelationTierGate — хоп не проходит НИ ОДНОГО
// метода, чьё право держится ОТНОШЕНИЕМ.
//
// # Почему вложения в допуск модуля для этого НЕ ХВАТАЕТ
//
// Отношение держит учётная запись. У модуля она есть, у хопа — нет: за ним стоит
// не один сосед, а всякий, кто дотянулся до фронта. Поэтому «хопу позволено не
// больше, чем модулю» здесь молчит: освободи хоп от пола читающих — и он
// сравняется с модулем, не превысив его. Величины равны, а смысл разный, и
// вложение этой разницы не видит by construction.
//
// Утверждение сформулировано прямо: множество пройденных хопом методов не
// пересекается с полом читающих. Проверяется в БОЕВОЙ посадке — в не-боевой
// стражи вырождаются, и пересечение там законно.
func TestOwnFrontHop_ChainNeverPassesARelationTierGate(t *testing.T) {
	methods := internalMethods(t)
	floor := map[string]bool{}
	for _, m := range ReadFloorRPCs() {
		floor[m] = true
	}
	if len(floor) == 0 {
		t.Fatal("пол читающих пуст — сверять не с чем, вердикт беспредметен")
	}
	gates := internalChain(true, true)
	hop := chainAdmitted(gates, newOwnFrontHopCtx(), methods)
	var leaked []string
	for m := range hop {
		if floor[m] {
			leaked = append(leaked, m)
		}
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		t.Errorf("хоп прошёл %d методов, чьё право держится отношением: %v — "+
			"отношение держит учётная запись, а за хопом стоит всякий, кто дотянулся до фронта",
			len(leaked), leaked)
	}
	t.Logf("методов под полом читающих %d · из них хоп проходит %d", len(floor), len(leaked))
}

// TestOwnFrontHop_ChainDenialsAreAttributed — у каждого отказа боевой посадки
// назван страж, и перечень стражей-отказчиков НЕ ПУСТ.
//
// Без этого утверждения разбивка переписи могла бы молча выродиться в пустую
// карту, а строка отчёта осталась бы на вид прежней.
func TestOwnFrontHop_ChainDenialsAreAttributed(t *testing.T) {
	routed := routedInternalMethods(t)
	gates := internalChain(true, true)
	ctx := newOwnFrontHopCtx()
	seen := map[string]int{}
	for _, m := range routed {
		if who := chainDenier(gates, ctx, m); who != "" {
			seen[who]++
		}
	}
	if len(seen) == 0 {
		t.Fatal("в боевой посадке цепочка не отвергла ни одного маршрута — " +
			"либо круг края опустел, либо разбивка переписи перестала что-либо измерять")
	}
	for who, n := range seen {
		t.Logf("отказал %-24s : %d маршрутов", who, n)
	}
}

// TestOwnFrontHop_StepUpArmAddsNothingForTheHop — ступень подтверждения не
// отнимает у хопа ни одного метода сверх уже отвергнутого стражами выше.
//
// Утверждается при САМОМ СТРОГОМ каталоге — требование высшей ступени от
// каждого метода. Совпадение множеств при нём означает, что отчётная перепись
// не занижена выбором пустого каталога: ужесточить ступень некуда, и вердикт от
// этого не меняется.
func TestOwnFrontHop_StepUpArmAddsNothingForTheHop(t *testing.T) {
	methods := internalMethods(t)
	ctx := newOwnFrontHopCtx()

	lenient := internalChain(true, true)
	strict := internalChain(true, true)
	strict[2] = chainGate{
		"ступень подтверждения (строгий каталог)",
		NewACRFloor(demandsHighestStepUp{}, GatewayFrontedInternalRPCs()).WithProductionMode(true).allow,
	}

	a := chainAdmitted(lenient, ctx, methods)
	b := chainAdmitted(strict, ctx, methods)
	if extra := diff(a, b); len(extra) > 0 {
		t.Errorf("строгая ступень отняла у хопа %d методов: %v — отчётная перепись занижает отказы, "+
			"потому что измеряет ступень слабее действующей", len(extra), extra)
	}
	if extra := diff(b, a); len(extra) > 0 {
		t.Errorf("строгая ступень ДОБАВИЛА хопу %d методов: %v — подача инъекции неверна", len(extra), extra)
	}
	t.Logf("хопу проходит при пустом каталоге %d · при строгом %d", len(a), len(b))
}

// itoa — маленькое целое в строку без импорта ради одной подписи.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
