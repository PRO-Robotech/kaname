// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// census_fixture_producer_test.go — фикстура пробы-переписи идёт через
// производителя, а не пишет предмет переписи сама. Порт с монорепо, см.
// годок `census_fixture_producer.go`.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// censusProducerPackageName — имя пакета-производителя, и заодно проверка
// ПРЕДПОСЫЛКИ гейта: что такой пакет есть и функция в нём объявлена.
func censusProducerPackageName(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(check.EdgeProducerDir))
	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		t.Fatalf("пакет-производитель %s не прочитан (%v): предпосылка гейта не выполнена",
			check.EdgeProducerDir, err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if perr != nil {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Recv == nil && fn.Name.Name == check.EdgeProducerCall {
				return f.Name.Name
			}
		}
	}
	t.Fatalf("в пакете %s нет функции %s: производитель переименован или переехал",
		check.EdgeProducerDir, check.EdgeProducerCall)
	return ""
}

// censusOwnProofPath — ЕДИНСТВЕННЫЙ файл, который гейт не судит: его
// собственное доказательство инъекцией.
//
// # Почему исключение вообще нужно — и почему в монорепо его не было
//
// В монорепо корнем обхода был каталог службы (`services/iam`), а носитель
// гейта лежал в `internal/repohygiene` — ВНЕ этого корня, поэтому гейт не
// встречал сам себя by construction. Здесь предмет и гейт живут в одном
// модуле, и корень обхода — собственная композиция модуля: доказательство
// попадает в обход.
//
// Синтетика доказательства несёт обе приметы переписи и оператор прямой
// записи ВНУТРИ строковых литералов — это ВХОД разбора, а не утверждение о
// продукте. Разбор смотрит внутрь литералов намеренно (настоящий SQL живёт
// там же), поэтому отличить вход от предмета по форме нельзя.
//
// # Почему ОДНО ИМЯ, а не образец
//
// Исключение названо точным путём: образец (`*_injection_test.go`) прощал бы
// ЛЮБОЕ будущее доказательство, в том числе то, чья синтетика перестала быть
// синтетикой. Одно имя покрывает ровно один файл и второго нарушителя
// замаскировать не может.
//
// # Самоистечение
//
// Файла нет — исключению нечего исключать, и это находка: гейт роняет прогон
// ниже, а не молчит.
const censusOwnProofPath = "internal/check/census_fixture_producer_injection_test.go"

// TestCensusFixturesSeedThroughTheProducer — сам гейт. Имя сохранено
// дословно из монорепо.
func TestCensusFixturesSeedThroughTheProducer(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	producerPkg := censusProducerPackageName(t, root)

	files, err := treecorpus.UnderWithSuffix(root, "_test.go")
	if err != nil {
		t.Fatalf("состав тестового дерева: %v", err)
	}

	scanned, censusFiles, rawWriters := 0, 0, 0
	ownProofSeen := false
	byDir := map[string][]check.CensusFileFacts{}
	for _, p := range files {
		body, rerr := os.ReadFile(p) // #nosec G304 -- путь получен из индекса СВОЕГО дерева
		if rerr != nil {
			t.Fatalf("чтение %s: %v", p, rerr)
		}
		scanned++
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		if rel == censusOwnProofPath {
			ownProofSeen = true
			continue
		}
		if !strings.Contains(string(body), check.CensusEdgeTable) {
			continue
		}
		facts, ferr := check.CensusFactsOf(rel, body, producerPkg)
		if ferr != nil {
			t.Fatalf("разбор %s: %v", rel, ferr)
		}
		if facts.RawWrite {
			rawWriters++
		}
		if facts.Census {
			censusFiles++
		}
		dir := path.Dir(rel)
		byDir[dir] = append(byDir[dir], facts)
	}

	t.Logf("осмотрено тестовых файлов: %d; каталогов с приметой: %d; "+
		"из них проб-переписей: %d; проб с прямой записью рёбер (включая законных "+
		"читателей): %d; пакет-производитель: %s",
		scanned, len(byDir), censusFiles, rawWriters, producerPkg)
	if scanned == 0 {
		t.Fatal("осмотрено ноль файлов — гейт не читал дерева, и его молчание ничего не значит")
	}
	// Второй конец самоистечения исключения: файл, который гейт не судит,
	// обязан существовать. Нет его — исключение прощает пустоту, и следующий
	// файл с тем же именем достанется ему уже прощённым.
	if !ownProofSeen {
		t.Fatalf("исключение без предмета: %s в обходе не встретился — "+
			"доказательство инъекцией переименовано либо снято, и исключение "+
			"снимается тем же изменением", censusOwnProofPath)
	}
	if censusFiles == 0 {
		t.Fatalf("в дереве нет ни одной пробы, пересчитывающей покрытие рёбрами "+
			"(один стейтмент, называющий %q и %q): предмет гейта отпал",
			check.CensusMirrorTable, check.CensusEdgeTable)
	}

	if findings := check.JudgeCensusFixtures(byDir); len(findings) > 0 {
		t.Fatalf("перепись утверждает свойство собственной фикстуры:\n  %s",
			strings.Join(findings, "\n  "))
	}
}
