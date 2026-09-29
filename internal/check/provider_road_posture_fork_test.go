// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_fork_test.go — ГЕЙТ ПО ДЕРЕВУ: у каждого потребителя
// административной дороги своё решение о посадке (задача kaname#338).
//
// Разбор предмета, решение о форме и то, чего разбор не видит, — в шапке
// `provider_road_posture_fork.go` и в
// `docs/engineering/architecture/provider-admin-road-posture-is-a-fork.md`.
// Здесь — обход, перепись обоих родов и потолок.
//
// ОБХОД ДВУХПРОХОДНЫЙ, и это не удобство. Строитель дороги живёт в одном файле,
// а потребители — в других. Строителей узнаёт первый проход по чтениям резолвера
// адреса (разбор соседнего гейта единственного читателя, а не его копия), второй
// судит потребителей во всём дереве.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// providerRoadFork — ИМЯ развилки посадки. Подаётся гейтом, а не выводится
	// из дерева: выведенный предмет сменился бы вместе с деревом молча.
	providerRoadFork = "onProviderAdminRoad"

	// providerRoadCensusFloor — нижняя граница обхода. Обход, принёсший
	// меньше, дерева не читал.
	providerRoadCensusFloor = 300

	// providerRoadCeiling — ПОТОЛОК находок. Ноль — замер по факту: на дереве
	// этой задачи у каждого потребителя своё решение. До устройства их было
	// шесть без своего решения, и гейт заводился ИМЕННО на том числе.
	providerRoadCeiling = 0
)

type providerRoadTreeFile struct {
	rel string
	src []byte
}

type providerRoadScan struct {
	Parsed   int
	Builders []string
	Reads    []check.ProviderAddressRead
	Census   check.ProviderRoadConsumerCensus
	Findings []check.ProviderRoadFinding
}

// providerRoadTree — прод-файлы Go модуля.
func providerRoadTree(t *testing.T) []providerRoadTreeFile {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}
	var out []providerRoadTreeFile
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			t.Fatalf("чтение %s: %v — файл состава дерева не читается, вердикт беспредметен", rel, rderr)
		}
		out = append(out, providerRoadTreeFile{rel: rel, src: src})
	}
	return out
}

// scanProviderRoad — оба прохода над набором файлов.
func scanProviderRoad(t *testing.T, files []providerRoadTreeFile) providerRoadScan {
	t.Helper()
	var out providerRoadScan
	for _, f := range files {
		reads, _, err := check.ScanProviderAddressReads(f.rel, f.src,
			providerAddressResolver, providerAddressTwin)
		if err != nil {
			t.Fatalf("разбор %s: %v", f.rel, err)
		}
		out.Reads = append(out.Reads, reads...)
	}
	out.Builders = check.ProviderRoadBuilders(out.Reads)
	out.Findings = append(out.Findings, check.ProviderRoadBuildersOutsideTheFork(out.Reads, providerRoadFork)...)

	for _, f := range files {
		out.Parsed++
		found, c, err := check.ScanProviderRoadConsumers(f.rel, f.src, providerRoadFork, out.Builders)
		if err != nil {
			t.Fatalf("разбор %s: %v", f.rel, err)
		}
		out.Findings = append(out.Findings, found...)
		out.Census = out.Census.Add(c)
	}
	return out
}

// TestProviderRoadConsumersEachDecideTheirPosture — сам гейт.
func TestProviderRoadConsumersEachDecideTheirPosture(t *testing.T) {
	t.Parallel()
	scan := scanProviderRoad(t, providerRoadTree(t))
	c := scan.Census

	t.Logf("перепись: прод-файлов Go разобрано %d · функций с телом осмотрено %d · "+
		"строителей дороги (читают %s) %d: %s\n"+
		"  первый род, зовущие строителя: %d — развилкой %s %d, мимо неё %d\n"+
		"  второй род, принимающие доводом: %d — из ветви построенной посадки %d, "+
		"из строителя мимо развилки %d\n"+
		"  находок %d (потолок %d)",
		scan.Parsed, c.Funcs, providerAddressResolver, len(scan.Builders),
		strings.Join(scan.Builders, ", "),
		c.FirstKind(), providerRoadFork, c.ForkCalls, c.UnforkedCalls,
		c.SecondKind(), c.ArmReceptions, c.UnforkedReceptions,
		len(scan.Findings), providerRoadCeiling)

	if err := check.ProviderRoadConsumerPremise(scan.Parsed, providerRoadCensusFloor,
		scan.Builders, c, providerRoadFork); err != nil {
		t.Fatalf("вердикт беспредметен: %v", err)
	}

	if len(scan.Findings) > providerRoadCeiling {
		where := make([]string, 0, len(scan.Findings))
		for _, f := range scan.Findings {
			where = append(where, fmt.Sprintf("%s:%d  %s() — %s [%s]", f.File, f.Line, f.Func, f.Kind, f.Detail))
		}
		sort.Strings(where)
		t.Fatalf("потребителей административной дороги без СВОЕГО решения о посадке и "+
			"строителей мимо развилки — %d при потолке %d:\n  %s\n\n"+
			"Исход один: дорогу строит только развилка %s, и потребитель получает её "+
			"параметром ветви построенной посадки, в паре с ветвью другой посадки. Одна "+
			"ветвь — один потребитель. Ответ о посадке, прочитанный где-нибудь рядом, "+
			"исходом НЕ является: компилятор не судит, что по нему решено.",
			len(scan.Findings), providerRoadCeiling, strings.Join(where, "\n  "), providerRoadFork)
	}
}
