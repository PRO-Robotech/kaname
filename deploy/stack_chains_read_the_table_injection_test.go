// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// stack_chains_read_the_table_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что
// TestUmbrellaStackChainsAreReadFromTheTable СПОСОБЕН упасть, и упасть ровно на
// своём предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОГОНОВ ТРИ, И ТРЕТИЙ ОБЯЗАТЕЛЕН
//
//	(A) КОНТРОЛЬ           — перечень совпадает с таблицей: тело МОЛЧИТ. Без него
//	                         красное ниже могло бы приходить от чего угодно.
//	(B) НОВОЕ свойство     — по одной оси на прогон, каждая ОДНОФАКТНО: пропавший
//	                         стенд · выпавший слой · лишний стенд · порядок слоёв.
//	(C) СУЩЕСТВУЮЩЕЕ       — предпосылки самого гейта: неразобранная строка
//	                         таблицы и таблица без стендов. Без этого прогона
//	                         молчание существующего контроля неотличимо от
//	                         молчания мёртвого.
//
// ЗАКОННЫЙ БЛИЗНЕЦ на каждой оси — та же форма входа, в которой дефекта нет:
// цепочка из одного слоя (законна: `dev` и `prod` именно таковы), стенд с
// дефисом в имени (законен: `dev-prod`), профиль с точками в имени (законен:
// `values.digests.example.yaml`). Гейт обязан по ним МОЛЧАТЬ.
//
// ВХОД СИНТЕТИЧЕСКИЙ НАМЕРЕННО. Настоящее дерево несёт ровно одно состояние —
// сошедшееся, — а предмет здесь ЧЕТЫРЕ расхождения плюс две мёртвые
// предпосылки. Инъекция в настоящее дерево к тому же означала бы правку общей
// рабочей копии, а таблица состава — чужой предмет.
//
// ЧЕГО ИНЪЕКЦИЯ НЕ ДОКАЗЫВАЕТ, и это сказано прямо: она подаёт вход телу гейта,
// а не проверяет, что тело вызывается из настоящего прохода. Это утверждает сам
// гейт своей переписью — он читает перечень ЧЕРЕЗ profileSources, то есть через
// настоящего потребителя.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tableOfSix — сошедшееся состояние: таблица и перечень называют одно и то же.
// Форма взята с настоящего дерева, включая обе законные крайности — цепочку из
// одного слоя и имя стенда с дефисом.
func tableOfSix() map[string][]string {
	return map[string][]string{
		"dev":         {"values.dev.yaml"},
		"dev-prod":    {"values.dev.yaml", "values.dev-prod.yaml"},
		"prod":        {"values.prod.yaml"},
		"fe3455":      {"values.prod.yaml", "values.fe3455.yaml", "values.fe3455-prod.yaml", "values.fe3455-ory-posture.yaml"},
		"prorobotech": {"values.dev.yaml", "values.dev-prod.yaml", "values.prorobotech.yaml"},
		"a8f60d":      {"values.dev.yaml", "values.dev-prod.yaml", "values.a8f60d.yaml"},
	}
}

func copyChains(src map[string][]string) map[string][]string {
	out := make(map[string][]string, len(src))
	for name, chain := range src {
		out[name] = append([]string(nil), chain...)
	}
	return out
}

// ── (A) КОНТРОЛЬ ────────────────────────────────────────────────────────────

func TestChainAgreementInjection_ControlIsSilent(t *testing.T) {
	table := tableOfSix()
	if got := judgeChainAgreement(table, copyChains(table)); len(got) != 0 {
		t.Fatalf("контроль: на сошедшемся перечне гейт обязан молчать, а он назвал %d: %v",
			len(got), got)
	}
	t.Logf("контроль: стендов %d, расхождений 0 — красное ниже приходит от инъекции, "+
		"а не от постороннего", len(table))
}

// Законный близнец: перечень, отданный в другом ПОРЯДКЕ ключей карты. Карта в Go
// не упорядочена, и гейт не вправе этого замечать — иначе он краснел бы через
// прогон, случайно, и его бы отключили.
func TestChainAgreementInjection_MapOrderIsNotAFinding(t *testing.T) {
	table := tableOfSix()
	used := map[string][]string{}
	for _, name := range []string{"a8f60d", "prorobotech", "fe3455", "prod", "dev-prod", "dev"} {
		used[name] = append([]string(nil), table[name]...)
	}
	if got := judgeChainAgreement(table, used); len(got) != 0 {
		t.Fatalf("законный близнец: порядок ключей карты находкой не является, а гейт назвал %d: %v",
			len(got), got)
	}
}

// ── (B) НОВОЕ свойство, по одной оси на прогон ───────────────────────────────

func TestChainAgreementInjection_MissingStackIsAFinding(t *testing.T) {
	table := tableOfSix()
	used := copyChains(table)
	delete(used, "a8f60d") // ровно тот дефект, что жил в дереве

	got := judgeChainAgreement(table, used)
	if len(got) != 1 {
		t.Fatalf("стенд, отсутствующий в перечне, обязан дать РОВНО одну находку, получено %d: %v",
			len(got), got)
	}
	// Находка обязана называть КООРДИНАТУ — иначе на неё потратят прогон и снимут
	// гейт как непонятный.
	if !strings.Contains(got[0], "a8f60d") {
		t.Fatalf("находка не называет стенд: %q", got[0])
	}
	if !strings.Contains(got[0], "НЕ НАЗВАН") {
		t.Fatalf("находка не отличает «не назван» от «разошёлся» — виды находок РАЗНЫЕ, "+
			"общий текст скрыл бы, что именно чинить: %q", got[0])
	}
}

func TestChainAgreementInjection_DroppedLayerIsAFinding(t *testing.T) {
	table := tableOfSix()
	used := copyChains(table)
	// prorobotech без СРЕДНЕГО слоя — ровно тот дефект, из-за которого перепись
	// контуров поставщика пропускала стенд как dev-класс.
	used["prorobotech"] = []string{"values.dev.yaml", "values.prorobotech.yaml"}

	got := judgeChainAgreement(table, used)
	if len(got) != 1 {
		t.Fatalf("выпавший слой обязан дать РОВНО одну находку, получено %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "prorobotech") || !strings.Contains(got[0], "values.dev-prod.yaml") {
		t.Fatalf("находка не называет ни стенд, ни выпавший слой: %q", got[0])
	}
}

func TestChainAgreementInjection_ExtraStackIsNotSilentlyForgiven(t *testing.T) {
	table := tableOfSix()
	used := copyChains(table)
	used["stand-nobody-declared"] = []string{"values.dev.yaml", "values.dev-prod.yaml"}

	// Лишний стенд расхождением ПО ТАБЛИЦЕ не является: гейт судит, что каждый
	// ОБЪЯВЛЕННЫЙ стенд назван, — и это его предмет. Утверждение здесь ОТРИЦАТЕЛЬНОЕ
	// и стоит намеренно: оно фиксирует ГРАНИЦУ гейта, чтобы следующий читатель не
	// принял её за дыру, и падает, если границу однажды передвинут молча.
	if got := judgeChainAgreement(table, used); len(got) != 0 {
		t.Fatalf("граница гейта сдвинулась: лишний стенд в перечне перестал быть "+
			"безразличным (%d находок: %v). Если это осознанное расширение — правь "+
			"и это утверждение тем же изменением", len(got), got)
	}
}

func TestChainAgreementInjection_LayerOrderIsAFinding(t *testing.T) {
	table := tableOfSix()
	used := copyChains(table)
	// Порядок слоёв НЕ косметика: helm накладывает их слева направо, и обмен
	// местами меняет действующую посадку.
	used["dev-prod"] = []string{"values.dev-prod.yaml", "values.dev.yaml"}

	got := judgeChainAgreement(table, used)
	if len(got) != 1 {
		t.Fatalf("перестановка слоёв обязана дать РОВНО одну находку, получено %d: %v",
			len(got), got)
	}
	if !strings.Contains(got[0], "dev-prod") {
		t.Fatalf("находка не называет стенд: %q", got[0])
	}
}

// Законный близнец оси «состав слоёв»: цепочка из ОДНОГО слоя. Настоящее дерево
// несёт такие (`dev`, `prod`), и гейт обязан по ним молчать.
func TestChainAgreementInjection_SingleLayerChainIsLegal(t *testing.T) {
	table := map[string][]string{"prod": {"values.prod.yaml"}}
	if got := judgeChainAgreement(table, copyChains(table)); len(got) != 0 {
		t.Fatalf("законный близнец: цепочка из одного слоя находкой не является, "+
			"а гейт назвал %d: %v", len(got), got)
	}
}

// ── (C) СУЩЕСТВУЮЩЕЕ: предпосылки самого гейта ──────────────────────────────
//
// Читатель таблицы обязан ОТКАЗАТЬ на неразобранной строке и на таблице без
// стендов. Оба прогона идут через настоящий umbrellaChainsFromTable, поэтому
// проверяется исполняемое, а не проза о нём.

// syntheticOuter — синтетический корень внешнего дерева с таблицей состава
// внутри. Подмены рабочего каталога больше НЕТ и не нужно: база приходит
// читателю параметром, поэтому синтетический вход подаётся прямо — и это тот же
// вид базы (`синтетический корень`), который гейт привязки координат считает
// законным.
func syntheticOuter(t *testing.T, body string) string {
	t.Helper()
	outer := t.TempDir()
	path := filepath.Join(outer, "deploy", "stacks.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("каталог синтетического дерева: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("таблица синтетического дерева: %v", err)
	}
	return outer
}

// refuses — отработал ли читатель ОТКАЗОМ на этом входе. Отказ выражен
// t.Fatalf, то есть завершением горутины: он ловится собственным *testing.T,
// а не перехватом паники вызывающего.
func refuses(t *testing.T, outer string) bool {
	t.Helper()
	sub := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		umbrellaChainsFromTable(sub, outer)
	}()
	<-done
	return sub.Failed()
}

func TestChainAgreementInjection_UnparsedTableLineRefuses(t *testing.T) {
	if !refuses(t, syntheticOuter(t, "dev:values.dev.yaml\nэто не строка стека\n")) {
		t.Fatal("неразобранная строка таблицы обязана РОНЯТЬ прогон: «стендов меньше» и " +
			"«предикат перестал их узнавать» — разные вещи, и молчание здесь сузило бы " +
			"проверку незаметно")
	}
}

func TestChainAgreementInjection_TableWithoutStacksRefuses(t *testing.T) {
	if !refuses(t, syntheticOuter(t, "# только комментарии\n\n")) {
		t.Fatal("таблица без стендов обязана РОНЯТЬ прогон: пустой обход даёт «ноль " +
			"находок», неотличимый от «ноль прочитанного»")
	}
}

// Законный близнец предпосылки: таблицы НЕТ вовсе. Это дерево поставляемого
// чарта, и там отсутствие законно — читатель обязан вернуть «предмета нет», а не
// отказать и не отдать пустой перечень.
func TestChainAgreementInjection_AbsentTableIsAConditionNotAFinding(t *testing.T) {
	chains, present := umbrellaChainsFromTable(t, t.TempDir())
	if present || chains != nil {
		t.Fatalf("отсутствующая таблица — УСЛОВИЕ НЕ СОЗДАНО, а не находка и не пустой "+
			"перечень: получено present=%v, стендов=%d", present, len(chains))
	}
}

// Законный близнец оси разбора: таблица, которую читатель ОБЯЗАН прочесть
// целиком — с комментариями, пустыми строками и цепочкой из одного слоя.
func TestChainAgreementInjection_WellFormedTableIsReadWhole(t *testing.T) {
	outer := syntheticOuter(t, "# шапка\n\ndev:values.dev.yaml\n"+
		"dev-prod:values.dev.yaml,values.dev-prod.yaml\n")
	chains, present := umbrellaChainsFromTable(t, outer)
	if !present {
		t.Fatal("таблица на месте, а читатель объявил предмет отсутствующим")
	}
	if len(chains) != 2 || len(chains["dev"]) != 1 || len(chains["dev-prod"]) != 2 {
		t.Fatalf("годная таблица прочитана неверно: %v", chains)
	}
}
