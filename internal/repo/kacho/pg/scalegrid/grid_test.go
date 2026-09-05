// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// grid_test.go — самопроверки сетки и переписи. Без Postgres: предмет здесь —
// объявление, а не поведение базы.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
)

// TestGridDigestMovesWhenTheTopPointDrops — отпечаток сетки ловит СОКРАЩЕНИЕ.
//
// Ради этого он и заведён: отчёт, снятый на сокращённой сетке, неотличим от
// полного и читается как полный. Число точек при этом не меняется — меняется
// верхнее значение, — поэтому отпечаток по числу точек здесь был бы слеп.
func TestGridDigestMovesWhenTheTopPointDrops(t *testing.T) {
	full := scalegrid.Full()
	digest := scalegrid.Digest(full)

	// Законный близнец: та же сетка, пересчитанная заново, — отпечаток тот же.
	// Без него «отпечаток изменился» зеленело бы и на приборе, дающем случайное
	// число при каждом вызове.
	if again := scalegrid.Digest(scalegrid.Full()); again != digest {
		t.Fatalf("отпечаток одной и той же сетки не воспроизводится: %s против %s — "+
			"тогда его расхождение ничего не означает", digest, again)
	}

	// Инъекция: верхняя точка оси N опущена с 10⁶ до 10⁵. ЧИСЛО ТОЧЕК ТО ЖЕ.
	reduced := make([][]scalegrid.Point, len(full))
	for i, axis := range full {
		cp := append([]scalegrid.Point{}, axis...)
		reduced[i] = cp
	}
	last := len(reduced[0]) - 1
	if reduced[0][last].N != 1_000_000 {
		t.Fatalf("верхняя точка оси N — %d, а не миллион: инъекция целится не туда, "+
			"и её зелёное не про сокращение сетки", reduced[0][last].N)
	}
	reduced[0][last].N = 100_000

	if got := scalegrid.Digest(reduced); got == digest {
		t.Errorf("отпечаток НЕ СДВИНУЛСЯ при опускании верхней точки оси N с 10⁶ до 10⁵ "+
			"(оба %s) — сокращённая сетка носила бы то же имя, что полная, и отчёт по ней "+
			"читался бы как полный", got)
	}
	if len(reduced[0]) != len(full[0]) {
		t.Fatalf("инъекция изменила ЧИСЛО точек (%d против %d): тогда она доказывает, что "+
			"отпечаток ловит длину, а не содержимое", len(reduced[0]), len(full[0]))
	}
}

// TestFullGridCarriesTheMillionAndTheZeroOfAxisF — сетка несёт обязательные точки.
func TestFullGridCarriesTheMillionAndTheZeroOfAxisF(t *testing.T) {
	var haveMillionN, haveMillionB, haveZeroF bool
	recruits := map[scalegrid.Recruit]int{}
	points := 0
	for _, axis := range scalegrid.Full() {
		for _, p := range axis {
			points++
			recruits[p.Recruit]++
			if p.Axis == scalegrid.AxisN && p.N == 1_000_000 {
				haveMillionN = true
			}
			if p.Axis == scalegrid.AxisB && p.B == 1_000_000 {
				haveMillionB = true
			}
			if p.Axis == scalegrid.AxisF && p.F == 0 {
				haveZeroF = true
			}
		}
	}
	t.Logf("объём осмотренного: точек полной сетки %d, способов набора %d", points, len(recruits))

	if !haveMillionN {
		t.Error("на оси N нет точки 10⁶: критерий владельца назван МИЛЛИОНОМ, и сетка, " +
			"кончающаяся ниже, отвечает не на тот вопрос")
	}
	if !haveMillionB {
		t.Error("на оси B нет точки 10⁶: «миллион связей в облаке» измеряется именно ею")
	}
	if !haveZeroF {
		t.Error("на оси F нет точки F = 0: без неё «полоса фактов входит в стоимость» " +
			"неотличимо от «полосы фактов не существует»")
	}
	// Способы набора: ось R набирается двумя, ось F — тремя.
	for _, want := range []scalegrid.Recruit{
		scalegrid.RecruitViaGroup, scalegrid.RecruitFactSelf,
		scalegrid.RecruitFactGroup, scalegrid.RecruitFactWildcard,
	} {
		if recruits[want] == 0 {
			t.Errorf("способ набора %q не встречается в сетке ни разу: ветви speaker разные, "+
				"и молчание одной о другой ничего не говорит", want)
		}
	}
}

// TestCensusRefusesWhenTheConditionWasNotCreated — ноль в переписи не «зелено».
func TestCensusRefusesWhenTheConditionWasNotCreated(t *testing.T) {
	p := scalegrid.Point{Axis: scalegrid.AxisF, N: 1000, B: 1000, R: 9, F: 100,
		Recruit: scalegrid.RecruitFactSelf}

	// Законный близнец: перепись сошлась — отказа нет. Без него всякое «отказал»
	// ниже зеленело бы и на переписи, отвергающей вообще всё.
	ok := scalegrid.Census{
		MirrorObjects: 1000, Edges: 3000, Bindings: 1009,
		BindingsNamingSubject: 9, FactsNamingSubject: 100,
		Roles: 10, RoleRules: 10, VerdictsAsked: 22,
	}
	if err := ok.Verify(p); err != nil {
		t.Fatalf("перепись, сошедшаяся с точкой, отвергнута: %v", err)
	}

	// Тихий недосев: объявлено F = 100, в таблице 12.
	short := ok
	short.FactsNamingSubject = 12
	err := short.Verify(p)
	if err == nil {
		t.Fatalf("тихий недосев (объявлено F=100, в таблице 12) ПРИНЯТ: точка мерила бы не то, " +
			"что называет, и выглядело бы это как «величина не выросла»")
	}
	for _, want := range []string{"условие замера не создано", "в таблице 12", "ТРЕТИЙ исход"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q — находка без координаты требует той же работы заново:\n%v",
				want, err)
		}
	}

	// Точка F = 0 законна: её ноль исключением НЕ является.
	zero := scalegrid.Point{Axis: scalegrid.AxisF, N: 1000, B: 1000, R: 9, F: 0,
		Recruit: scalegrid.RecruitFactSelf}
	noFacts := ok
	noFacts.FactsNamingSubject = 0
	if err := noFacts.Verify(zero); err != nil {
		t.Errorf("точка F = 0 отвергнута за ноль фактов (%v) — она ОБЯЗАТЕЛЬНАЯ нижняя точка "+
			"оси, и её ноль есть условие, а не его отсутствие", err)
	}
}
