// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// producer_has_a_caller_injection_test.go — доказательство, что гейт
// `TestIAM2638_EveryDeclaredMetricProducerHasACaller` способен упасть И способен
// смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до снятия семейства
// попыток к хранилищу вердикта гейт назвал ровно одну находку при популяции в 17
// производителей фасада. Здесь то же свойство закреплено воспроизводимо, на
// синтетике: доказательство, требующее вернуть дефект в рабочую копию, в
// конвейере не исполняется никогда.
//
// У дефекта ДВА близнеца, и второй — граница предпосылки:
//
//	близнец РАВЕНСТВА  — тот же метод фасада, отличающийся ровно одним фактом:
//	                     его зовут. Гейт обязан молчать;
//	близнец ГРАНИЦЫ    — метод ДОКЛАДЧИКА без вызывающих в этом дереве. Его
//	                     зовут из другого модуля интерфейсом, обход такого вызова
//	                     не видит, и гейт обязан молчать ПО ПРЕДПОСЫЛКЕ, а не по
//	                     совпадению.
//
// Без второго близнеца исключение докладчиков было бы объявлением: проверить,
// что оно действует, нечем.

import (
	"os"
	"path/filepath"
	"testing"
)

// injProducerWithoutCaller — ДЕФЕКТ: метод фасада трогает величину, и его имя не
// встречается больше нигде.
const injProducerWithoutCaller = `package metrics

type Registry struct{ vec metricVec }

func (r *Registry) ObserveNobodyCallsMe(op string) {
	r.vec.WithLabelValues(op).Inc()
}
`

// injProducerWithCaller — ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, отличается ровно одним
// фактом — производителя зовут.
const injProducerWithCaller = `package metrics

func (r *Registry) ObserveSomebodyCallsMe(op string) {
	r.vec.WithLabelValues(op).Inc()
}

func useIt(r *Registry) { r.ObserveSomebodyCallsMe("x") }
`

// injRecorderWithoutCaller — БЛИЗНЕЦ ГРАНИЦЫ: докладчик без вызывающих в этом
// дереве. Он отдаётся фундаменту интерфейсом, и его зовут из другого модуля.
const injRecorderWithoutCaller = `package metrics

type OutboxRecorder struct{ vec metricVec }

func (rec *OutboxRecorder) SetBacklogDepthNobodyCallsHere(table string, depth float64) {
	rec.vec.WithLabelValues(table).Set(depth)
}
`

func writeProducerInjTree(t *testing.T, sources map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	var files []string
	for name, body := range sources {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("положить синтетику %s: %v", name, err)
		}
		files = append(files, path)
	}
	return files
}

// TestIAM2638_InjectionRedsTheUncalledProducerAndKeepsQuietOnTheCalledOne — ось
// «производитель без вызывающего», обе стороны сразу.
func TestIAM2638_InjectionRedsTheUncalledProducerAndKeepsQuietOnTheCalledOne(t *testing.T) {
	files := writeProducerInjTree(t, map[string]string{
		"defect.go":   injProducerWithoutCaller,
		"twin.go":     injProducerWithCaller,
		"boundary.go": injRecorderWithoutCaller,
	})
	prods, census, err := scanProducersOf(t, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.Producers != 2 {
		t.Fatalf("производителей фасада ожидалось 2 (дефект + близнец равенства; "+
			"докладчик в популяцию не входит), найдено %d — распознаватель судит не ту "+
			"популяцию: %s", census.Producers, census.Summary())
	}
	if census.OffFacade != 1 {
		t.Fatalf("методов докладчика вне популяции ожидался 1, насчитано %d — "+
			"предпосылка исключения не исполняется, и её действие недоказуемо: %s",
			census.OffFacade, census.Summary())
	}

	dead := deadProducers(t, prods, files)
	if len(dead) != 1 {
		t.Fatalf("находок ожидалась РОВНО одна (дефект), получено %d: %+v — либо гейт "+
			"не видит производителя без вызывающего, либо роняет заодно близнеца",
			len(dead), dead)
	}
	if dead[0].Name != "ObserveNobodyCallsMe" {
		t.Fatalf("находка названа именем %q, а дефект внесён в `ObserveNobodyCallsMe` — "+
			"гейт краснеет не на том, на чём проверяется", dead[0].Name)
	}
}

// TestIAM2638_InjectionStaysQuietWhenNothingIsDead — контроль: дерево без дефекта
// находок не даёт. Без него «одна находка» была бы неотличима от «гейт краснеет
// на чём угодно».
func TestIAM2638_InjectionStaysQuietWhenNothingIsDead(t *testing.T) {
	files := writeProducerInjTree(t, map[string]string{
		"twin.go":     injProducerWithCaller,
		"boundary.go": injRecorderWithoutCaller,
	})
	prods, census, err := scanProducersOf(t, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.Producers != 1 {
		t.Fatalf("производителей фасада ожидался 1, найдено %d: %s",
			census.Producers, census.Summary())
	}
	if dead := deadProducers(t, prods, files); len(dead) != 0 {
		t.Fatalf("гейт нашёл %d находок на дереве без дефекта: %+v — идеал превращён "+
			"в поломку", len(dead), dead)
	}
}

// scanProducersOf — разбор синтетического дерева тем же распознавателем, каким
// судится живое.
func scanProducersOf(t *testing.T, files []string) ([]metricProducer, producerCensus, error) {
	t.Helper()
	prods, census, err := scanRegistryProducers(files)
	census.ModuleFiles = len(files)
	return prods, census, err
}

// deadProducers — те же вычитание и предикат, что в гейте.
func deadProducers(t *testing.T, prods []metricProducer, files []string) []metricProducer {
	t.Helper()
	refs, decls, err := referencesByName(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var dead []metricProducer
	for _, p := range prods {
		if refs[p.Name]-decls[p.Name] == 0 {
			dead = append(dead, p)
		}
	}
	return dead
}
