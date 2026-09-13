// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// closed_label_sets_injection_test.go — доказательство, что гейт
// `TestIAM2500_EveryClosedLabelSetSeedsItsCellsAtRegistration` способен упасть И
// способен смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до починки гейт
// назвал двенадцать семейств, отдающих НОЛЬ рядов сразу после регистрации
// (перепись при этом не изменилась — 32 объявления вектора, из них 18 закрытых).
// Здесь то же свойство закреплено воспроизводимо, на синтетике: доказательство,
// требующее вернуть дефект в рабочую копию, в конвейере не исполняется никогда.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма записи,
// отличающаяся РОВНО ОДНИМ фактом. Инъекция, роняющая заодно что-то ещё,
// доказательством не является: красное пришло бы от соседа.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// injUnknownFamily — ДЕФЕКТ: вектор объявлен, а семейства нет ни в таблице
// закрытых наборов, ни в ведомости открытых. Слепая зона.
const injUnknownFamily = `package metrics

import "github.com/prometheus/client_golang/prometheus"

func build() {
	_ = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Namespace + "_family_nobody_declared_total",
		Help: "h",
	}, []string{"outcome"})
}
`

// injKnownFamily — ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, отличается ровно одним
// фактом — семейство названо таблицей закрытых наборов.
const injKnownFamily = `package metrics

import "github.com/prometheus/client_golang/prometheus"

func build() {
	_ = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: Namespace + "_catalog_snapshot_refreshes_total",
		Help: "h",
	}, []string{"outcome"})
}
`

// injUnresolvedName — ДЕФЕКТ иного рода: имя семейства собрано формой, которой
// распознаватель не знает. Оно обязано попасть в перепись «с неразрешённым
// именем», а не исчезнуть из наблюдения молча.
const injUnresolvedName = `package metrics

import "github.com/prometheus/client_golang/prometheus"

func familyName() string { return "kaname_computed" }

func build() {
	_ = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: familyName(),
		Help: "h",
	}, []string{"outcome"})
}
`

// injCollectorNotVector — ЗАКОННЫЙ БЛИЗНЕЦ границы: коллектор со своим
// `Collect` отдаёт все клетки на каждом скрейпе by construction, и вектором не
// является. Гейт обязан о нём МОЛЧАТЬ.
const injCollectorNotVector = `package metrics

import "github.com/prometheus/client_golang/prometheus"

func build() {
	_ = prometheus.NewDesc("kaname_mirror_outcomes_total", "h", []string{"outcome"}, nil)
}
`

func writeInjTree(t *testing.T, sources map[string]string) []string {
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

// TestIAM2500_InjectionRedsTheUndeclaredFamilyAndKeepsQuietOnTheDeclaredOne —
// ось «слепая зона»: объявление, не названное ни таблицей, ни ведомостью.
func TestIAM2500_InjectionRedsTheUndeclaredFamilyAndKeepsQuietOnTheDeclaredOne(t *testing.T) {
	files := writeInjTree(t, map[string]string{
		"defect.go": injUnknownFamily,
		"twin.go":   injKnownFamily,
		"border.go": injCollectorNotVector,
	})
	sites, census, err := scanVectorSites(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	findings, _, _ := adjudicateLabelSets(sites, &census)

	if census.Vectors != 2 {
		t.Fatalf("объявлений вектора ожидалось 2 (дефект + близнец; коллектор вектором "+
			"не является), найдено %d — распознаватель судит не то, что объявлено", census.Vectors)
	}
	if len(findings) != 1 {
		t.Fatalf("находок ожидалась РОВНО одна (дефект), получено %d: %+v — "+
			"либо гейт не видит дефекта, либо роняет заодно законного близнеца",
			len(findings), findings)
	}
	if got := findings[0].Family; got != Namespace+"_family_nobody_declared_total" {
		t.Errorf("находка названа семейством %q, а дефект внесён в %q — гейт краснеет "+
			"не на том, ради чего заведён", got, Namespace+"_family_nobody_declared_total")
	}
	if census.Closed != 1 {
		t.Errorf("закрытых объявлений ожидалось 1 (близнец), насчитано %d", census.Closed)
	}
}

// TestIAM2500_InjectionRedsTheNameFormItDoesNotKnow — ось «форма записи, о
// которой распознаватель не знает». Такое объявление обязано быть НАЗВАНО, а не
// молча выпасть из наблюдения: молчание неотличимо от чистого дерева.
func TestIAM2500_InjectionRedsTheNameFormItDoesNotKnow(t *testing.T) {
	files := writeInjTree(t, map[string]string{
		"defect.go": injUnresolvedName,
		"twin.go":   injKnownFamily,
	})
	sites, census, err := scanVectorSites(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	findings, _, _ := adjudicateLabelSets(sites, &census)
	if census.Unnamed != 1 {
		t.Fatalf("объявлений с неразрешённым именем ожидалось 1, насчитано %d — "+
			"неизвестная форма записи проехала бы молча", census.Unnamed)
	}
	if len(findings) != 1 {
		t.Fatalf("находок ожидалась ровно одна, получено %d: %+v", len(findings), findings)
	}
}

// TestIAM2500_InjectionRedsTheEmptyWalk — пустой обход есть ОТКАЗ РАЗБОРА, а не
// чистое дерево: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func TestIAM2500_InjectionRedsTheEmptyWalk(t *testing.T) {
	sites, census, err := scanVectorSites(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.Parsed != 0 || census.Vectors != 0 || len(sites) != 0 {
		t.Fatalf("пустой перечень дал непустую перепись: %s", census.Summary())
	}
	// Живой гейт на такой переписи обязан звать Fatalf — здесь проверяется
	// ПРЕДПОСЫЛКА этого отказа, а не его текст.
	filesOnlyTests := writeInjTree(t, map[string]string{"only_test.go": injKnownFamily})
	renamed := filepath.Join(filepath.Dir(filesOnlyTests[0]), "x_test.go")
	if err := os.Rename(filesOnlyTests[0], renamed); err != nil {
		t.Fatalf("переименовать синтетику: %v", err)
	}
	_, census2, err := scanVectorSites([]string{renamed})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census2.Parsed != 0 {
		t.Fatalf("тестовый файл попал в разбор прод-дерева: %s", census2.Summary())
	}
}

// TestIAM2500_InjectionRedsAnEntryThatHasNothingLeftToSay — запись таблицы либо
// ведомости, которой в пакете больше нет предмета, — находка: утверждение и
// послабление обязаны истекать вместе со своим предметом.
func TestIAM2500_InjectionRedsAnEntryThatHasNothingLeftToSay(t *testing.T) {
	files := writeInjTree(t, map[string]string{"twin.go": injKnownFamily})
	sites, census, err := scanVectorSites(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, staleTable, staleOpen := adjudicateLabelSets(sites, &census)
	// В синтетике объявлено ОДНО семейство из таблицы, поэтому все остальные
	// записи обеих ведомостей обязаны быть названы просроченными.
	if len(staleTable) != len(closedLabelSetFamilies)-1 {
		t.Errorf("просроченных записей таблицы ожидалось %d, названо %d — "+
			"истечение не работает", len(closedLabelSetFamilies)-1, len(staleTable))
	}
	if len(staleOpen) != len(openLabelSetFamilies) {
		t.Errorf("просроченных записей ведомости ожидалось %d, названо %d",
			len(openLabelSetFamilies), len(staleOpen))
	}
}

// TestIAM2500_InjectionRedsTheUnseededVectorAndKeepsQuietOnTheSeededTwin — ось,
// ради которой гейт заведён: поведение на проводе, а не форма записи.
func TestIAM2500_InjectionRedsTheUnseededVectorAndKeepsQuietOnTheSeededTwin(t *testing.T) {
	const family = "kaname_injection_probe_total"
	cells := []string{"ok", "error", "misconfigured"}

	unseeded := func(r *Registry) {
		v := prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: family, Help: "h"}, []string{"outcome"})
		r.reg.MustRegister(v)
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, отличается ровно одним фактом — клетки
	// заведены нулём при регистрации.
	seeded := func(r *Registry) {
		v := prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: family, Help: "h"}, []string{"outcome"})
		for _, c := range cells {
			v.WithLabelValues(c)
		}
		r.reg.MustRegister(v)
	}

	if got := rowsAfterRegistration(t, family, unseeded); got != 0 {
		t.Errorf("незасеянный вектор отдал %d рядов — предпосылка гейта неверна, "+
			"и тогда он зелен при любом дереве by construction", got)
	}
	if got := rowsAfterRegistration(t, family, seeded); got != len(cells) {
		t.Errorf("засеянный вектор отдал %d рядов вместо %d — гейт не увидел бы "+
			"починки и краснел бы на исправном коде", got, len(cells))
	}
}
