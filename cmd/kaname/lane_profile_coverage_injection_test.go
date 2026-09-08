// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_profile_coverage_injection_test.go — способность гейта покрытия полос
// упасть и смолчать, доказанная инъекцией В ОБЕ СТОРОНЫ.
//
// Инъекция зовёт ТУ ЖЕ функцию, что исполняется на дереве (judgeLaneCoverage),
// а не свою копию предиката: копия разошлась бы с настоящим гейтом молча — и
// разошлась бы там, где расхождение не видно.
//
// Каждый отрицательный случай отличается от своего положительного близнеца
// РОВНО ОДНИМ фактом. Дельта в два факта не сказала бы, который из них дал
// красное.
package main

import (
	"strings"
	"testing"
)

// Дефект: полосу умеют поднять, и ни один профиль её не объявляет. Обязано
// находиться — иначе возможность есть, а узнать о ней арендатору неоткуда.
func TestInjection_AReachableLaneWithNoProfileIsFound(t *testing.T) {
	_, _, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: true, Profiled: false},
	})
	if len(findings) != 1 || !strings.Contains(findings[0], "synthetic") {
		t.Fatalf("достижимая полоса без профиля не найдена: %v", findings)
	}
	if !strings.Contains(findings[0], "НИ ОДИН профиль") {
		t.Fatalf("находка обязана называть предмет, получено: %q", findings[0])
	}
}

// Законный близнец: та же полоса, объявленная профилем, — молчание. РОВНО ОДИН
// изменённый факт против случая выше.
func TestInjection_AReachableLaneWithAProfileIsSilent(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: true, Profiled: true, ProfileNames: []string{"values.synthetic.yaml"}},
	})
	if len(findings) != 0 {
		t.Fatalf("достижимая объявленная полоса объявлена находкой: %v", findings)
	}
	if profiled != 1 || reachable != 1 {
		t.Fatalf("перепись не засчитала полосу: объявлено %d, поднимается %d", profiled, reachable)
	}
}

// Дефект С ДРУГОЙ СТОРОНЫ: профиль обещает посадку, которую корень отвергает.
// Без этого случая гейт чинился бы профилем-обещанием.
func TestInjection_AnUnreachableLaneWithAProfileIsFound(t *testing.T) {
	_, _, findings := judgeLaneCoverage([]laneFact{
		{
			Lane: "synthetic", Reachable: false, Profiled: true,
			ProfileNames: []string{"values.synthetic.yaml"},
			Refusal:      "нечем впустить человека",
		},
	})
	if len(findings) != 1 || !strings.Contains(findings[0], "values.synthetic.yaml") {
		t.Fatalf("недостижимая объявленная полоса не найдена: %v", findings)
	}
	if !strings.Contains(findings[0], "нечем впустить человека") {
		t.Fatalf("находка обязана нести ОТКАЗ корня, иначе читателю нечем её проверить: %q", findings[0])
	}
}

// Законный близнец второго рода: недостижимая полоса, которую никто не
// объявляет, находкой не является — и в обе величины переписи не входит.
// Одно число скрыло бы ровно этот случай.
func TestInjection_AnUnreachableLaneWithNoProfileIsSilentAndNotCounted(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage([]laneFact{
		{Lane: "synthetic", Reachable: false, Profiled: false, Refusal: "нечем впустить человека"},
	})
	if len(findings) != 0 {
		t.Fatalf("недостижимая необъявленная полоса объявлена находкой: %v", findings)
	}
	if profiled != 0 || reachable != 0 {
		t.Fatalf("перепись засчитала то, чего нет: объявлено %d, поднимается %d", profiled, reachable)
	}
}

// Пустой вход не производит находок И не производит переписи: «ноль находок»
// на пустом обходе обязано быть отличимо от «ноль прочитанного», и различает их
// падение самого гейта по дереву (t.Fatal на пустом перечне полос).
func TestInjection_AnEmptyWalkProducesNothingToJudge(t *testing.T) {
	profiled, reachable, findings := judgeLaneCoverage(nil)
	if len(findings) != 0 || profiled != 0 || reachable != 0 {
		t.Fatalf("пустой вход обязан не производить ничего: находок %v, объявлено %d, поднимается %d",
			findings, profiled, reachable)
	}
}
