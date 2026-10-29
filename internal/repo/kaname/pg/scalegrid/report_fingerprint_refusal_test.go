// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// report_fingerprint_refusal_test.go — ОТЧЁТ БЕЗ ОТПЕЧАТКА НЕ ПИШЕТСЯ (kaname#74).
//
// # Предмет
//
// Провенанс замера брал отпечаток предмета формой «получилось — положить,
// не получилось — промолчать». Молчание здесь не нейтрально: шапка без
// отпечатка собиралась, отчёт ложился в дерево, а гейт свежести находил в нём
// пустые строки отпечатка и объявлял его несвежим. Причину — почему отпечаток
// не снят — не печатал никто: она была отброшена в момент провала, за часы
// замера до того, как её кто-либо спросил.
//
// Свойство поэтому двустороннее, и проба держит обе стороны:
//
//	отпечаток не снят       шапка ОТКАЗЫВАЕТ и называет причину провала дословно;
//	отпечаток снят          шапка собирается и несёт перечень файлов под ним.
//
// Вторая сторона — законный близнец: без неё отказ «всегда» прошёл бы первую.

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// TestHeaderRefusesAProvenanceWithoutAFingerprint — шапка без отпечатка
// невалидна так же, как шапка без команды повторения: гейт свежести сверять её
// не с чем, а «сверять не с чем» он читает как «несвежий» без причины.
func TestHeaderRefusesAProvenanceWithoutAFingerprint(t *testing.T) {
	t.Parallel()
	bare := scalegrid.Provenance{
		TreeRev: "abc123", When: time.Now(), CPUCores: 1,
		RunCommand: "make scale-grid-full", GridText: "  ось N: 100\n",
	}
	_, err := bare.Header("проба")
	if err == nil {
		t.Fatal("шапка без отпечатка предмета ПРИНЯТА: отчёт лёг бы в дерево, а гейт " +
			"свежести объявил бы его несвежим, не назвав, почему отпечатка нет")
	}
	if !strings.Contains(err.Error(), "отпечат") {
		t.Errorf("отказ не называет предмет — отпечаток: %v", err)
	}
}

// TestProvenanceOutsideAnyTreeNamesWhyTheFingerprintIsMissing — прогон вне
// дерева git: корня нет, отпечатка нет, и шапка обязана сказать именно это.
//
// Каталог прогона — пустой временный, а подъём git к родителям закрыт
// `GIT_CEILING_DIRECTORIES`: иначе исход зависел бы от того, лежит ли каталог
// временных файлов машины внутри чьей-то рабочей копии.
func TestProvenanceOutsideAnyTreeNamesWhyTheFingerprintIsMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", dir)
	t.Chdir(dir)

	prov := scalegrid.TakeProvenance("make scale-grid-full", nil)
	_, err := prov.Header("проба")
	if err == nil {
		t.Fatal("провенанс, снятый ВНЕ дерева, дал шапку: отпечаток не снят, а причина " +
			"отброшена — отчёт читался бы как несвежий без единого слова почему")
	}
	if !strings.Contains(err.Error(), "корень дерева") {
		t.Errorf("отказ не называет причину провала (корень дерева не установлен): %v", err)
	}
}

// TestProvenanceInATreeWithoutTheSubjectQuotesTheFingerprintFailure — дерево git
// есть, предмета замера в нём нет: провал ComputeFingerprint обязан дойти до
// шапки ДОСЛОВНО, а не раствориться в пустом отпечатке.
func TestProvenanceInATreeWithoutTheSubjectQuotesTheFingerprintFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", dir)
	if out, err := gitenv.Command(dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дерево фикстуры не заведено: %v\n%s", err, out)
	}
	t.Chdir(dir)

	// Причина провала берётся у ТОГО ЖЕ вычислителя, что зовёт провенанс: своя
	// копия текста разошлась бы с ним молча.
	_, want := scalegrid.ComputeFingerprint(dir)
	if want == nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в пустом дереве %s отпечаток снялся — "+
			"предусловие «предмета нет» не создано", dir)
	}

	prov := scalegrid.TakeProvenance("make scale-grid-full", nil)
	_, err := prov.Header("проба")
	if err == nil {
		t.Fatalf("провал отпечатка проглочен: шапка собрана, хотя ComputeFingerprint "+
			"отказал словами %q", want)
	}
	if !strings.Contains(err.Error(), want.Error()) {
		t.Errorf("отказ шапки не цитирует причину провала отпечатка:\n  отказ:   %v\n  причина: %v",
			err, want)
	}
}

// TestProvenanceInThisTreeCarriesTheFingerprint — законный близнец: в дереве
// модуля отпечаток снимается, шапка собирается и перечисляет файлы под ним.
func TestProvenanceInThisTreeCarriesTheFingerprint(t *testing.T) {
	t.Parallel()
	prov := scalegrid.TakeProvenance("make scale-grid-full", nil)
	header, err := prov.Header("проба")
	if err != nil {
		t.Fatalf("в дереве модуля шапка ОТКАЗАЛА — отказ сработал бы на любом прогоне: %v", err)
	}
	if len(prov.Fingerprint.Files) == 0 {
		t.Fatal("в дереве модуля под отпечатком ноль файлов — близнец не близнец")
	}
	if !strings.Contains(header, scalegrid.MarkerFileList) {
		t.Errorf("шапка не несёт перечня файлов под отпечатком:\n%s", header)
	}
	t.Logf("файлов под отпечатком %d", len(prov.Fingerprint.Files))
}
