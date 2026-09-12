// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// census_fixture_producer_injection_test.go — доказательство падучести
// JudgeCensusFixtures / CensusFactsOf в обе стороны.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const censusInjectedRawWriteSrc = `package badcensus

func TestFullness(t *T) {
	_ = ` + "`" + `SELECT count(*) FROM kaname.resource_mirror m JOIN kaname.resource_parent_edge e ON e.child_id = m.id` + "`" + `
	_ = ` + "`" + `INSERT INTO kaname.resource_parent_edge (child_id, parent_id) VALUES ($1, $2)` + "`" + `
}
`

const censusInjectedNoProducerSrc = `package orphancensus

func TestFullness(t *T) {
	_ = ` + "`" + `SELECT count(*) FROM kaname.resource_mirror m JOIN kaname.resource_parent_edge e ON e.child_id = m.id` + "`" + `
}
`

const censusLawfulProducerSeedSrc = `package goodcensus

import "github.com/example/x/internal/repo/kaname/pg/resource_mirror"

func seed(tx T) {
	resource_mirror.UpsertTx(nil, tx, resource_mirror.Row{})
}
`

const censusLawfulSameSrc = `package goodcensus

func TestFullness(t *T) {
	_ = ` + "`" + `SELECT count(*) FROM kaname.resource_mirror m JOIN kaname.resource_parent_edge e ON e.child_id = m.id` + "`" + `
}
`

// TestCensusFixtureProducerInjection_RawWrite — прямая запись рёбер в том же
// файле, что и перепись, — находка.
func TestCensusFixtureProducerInjection_RawWrite(t *testing.T) {
	t.Parallel()
	facts, err := check.CensusFactsOf("bad.go", []byte(censusInjectedRawWriteSrc), "resource_mirror")
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if !facts.Census || !facts.RawWrite {
		t.Fatalf("разбор не увидел перепись и/или прямую запись: %+v", facts)
	}
	findings := check.JudgeCensusFixtures(map[string][]check.CensusFileFacts{"bad": {facts}})
	if len(findings) != 1 || !strings.Contains(findings[0], "прямой записью") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка о прямой записи, получено %v", findings)
	}
}

// TestCensusFixtureProducerInjection_NoProducerInPackage — перепись есть,
// пакет производителя не зовёт вовсе — находка.
func TestCensusFixtureProducerInjection_NoProducerInPackage(t *testing.T) {
	t.Parallel()
	facts, err := check.CensusFactsOf("orphan.go", []byte(censusInjectedNoProducerSrc), "resource_mirror")
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	findings := check.JudgeCensusFixtures(map[string][]check.CensusFileFacts{"orphan": {facts}})
	if len(findings) != 1 || !strings.Contains(findings[0], "не зовёт производителя") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка «не зовёт производителя», получено %v", findings)
	}
}

// TestCensusFixtureProducerInjection_LawfulProducerSeed — перепись в одном
// файле, производитель зовётся из СОСЕДНЕГО файла того же пакета — молчание
// (единица суждения — пакет, а не файл).
func TestCensusFixtureProducerInjection_LawfulProducerSeed(t *testing.T) {
	t.Parallel()
	seedFacts, err := check.CensusFactsOf("seed.go", []byte(censusLawfulProducerSeedSrc), "resource_mirror")
	if err != nil {
		t.Fatalf("разбор seed: %v", err)
	}
	censusFacts, err := check.CensusFactsOf("census.go", []byte(censusLawfulSameSrc), "resource_mirror")
	if err != nil {
		t.Fatalf("разбор census: %v", err)
	}
	if !seedFacts.Producer {
		t.Fatalf("разбор не увидел вызов производителя в seed.go: %+v", seedFacts)
	}
	findings := check.JudgeCensusFixtures(map[string][]check.CensusFileFacts{
		"good": {seedFacts, censusFacts},
	})
	if len(findings) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: производитель зовётся соседним файлом пакета, "+
			"а гейт покраснел: %v", findings)
	}
}

// TestCensusFixtureProducerInjection_ReaderTwin — законный близнец: проба
// читателя (без переписи, quantифицирующего литерала) вправе класть рёбра
// прямо — молчание.
func TestCensusFixtureProducerInjection_ReaderTwin(t *testing.T) {
	t.Parallel()
	readerSrc := `package reader

func TestOneObject(t *T) {
	_ = ` + "`" + `INSERT INTO kaname.resource_parent_edge (child_id, parent_id) VALUES ($1, $2)` + "`" + `
	_ = ` + "`" + `SELECT * FROM kaname.resource_parent_edge WHERE child_id = $1` + "`" + `
}
`
	facts, err := check.CensusFactsOf("reader.go", []byte(readerSrc), "resource_mirror")
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if facts.Census {
		t.Fatalf("разбор ошибочно признал одностороннее чтение переписью: %+v", facts)
	}
	findings := check.JudgeCensusFixtures(map[string][]check.CensusFileFacts{"reader": {facts}})
	if len(findings) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: проба читателя (не перепись) дала находку: %v", findings)
	}
}
