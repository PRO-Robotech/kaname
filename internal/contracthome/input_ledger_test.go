// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// input_ledger_test.go — ВХОДНОЙ контракт в дереве службы приезжает как есть, и
// его правка здесь наблюдаема.
//
// # ПРЕДМЕТ
//
// Оператор `import` резолвится ФАЙЛОМ. Поэтому под `proto/` неизбежно лежат
// копии контрактов, службе не принадлежащих, — и вместе с ними неизбежно ДВА
// МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ. Класс известен: два места, из которых верно одно, и
// расхождение приходит молча, потому что второе место читают редко.
//
// Ведомость `proto/inputs.yaml` делает расхождение наблюдаемым: у каждого входа
// записан отпечаток содержимого, и гейт пересчитывает его по файлу.
//
// # ГЕЙТ ДВУСТОРОННИЙ
//
// Запись без файла — находка (ведомость описывает снятое). Файл без записи —
// тоже находка (вход завёлся мимо ведомости, и его правку никто не заметит).
// Односторонний предикат закрывался бы дописыванием записей, не сверяя ничего.
//
// # ЧЕГО ГЕЙТ НЕ ПОКРЫВАЕТ — НАЗВАНО ПРЯМО
//
// Он судит копию ЗДЕСЬ. Правку ИСТОЧНИКА он не видит: дерева источника в этом
// прогоне нет by construction, и назвать «совпадает с источником» было бы
// заявлением шире проверенного. Держателем такой сверки может быть только
// сторона, видящая оба дерева. Остаток объявлен в шапке самой ведомости.
package contracthome

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"gopkg.in/yaml.v3"
)

// inputLedgerFile — ведомость входных контрактов в каталоге контрактов.
const inputLedgerFile = "inputs.yaml"

// inputLedger — ведомость. Поле `stubs` читается, чтобы «модуль заглушек не
// назван» было находкой: вход без объявленного дома заглушек есть приглашение
// породить их вторично.
type inputLedger struct {
	Source struct {
		Repo     string `yaml:"repo"`
		Revision string `yaml:"revision"`
	} `yaml:"source"`
	Inputs []struct {
		Path   string `yaml:"path"`
		SHA256 string `yaml:"sha256"`
		Stubs  string `yaml:"stubs"`
	} `yaml:"inputs"`
}

const (
	ledgerGroundDrift = "отпечаток не совпал с ведомостью: копия входного контракта правлена " +
		"здесь, и второе место об одном предмете разошлось с первым"
	ledgerGroundMissingFile = "запись ведомости описывает файл, которого в дереве нет: " +
		"исключение без предмета"
	ledgerGroundUnledgered = "входной контракт лежит в дереве, но в ведомости не назван: " +
		"его правку не заметит никто"
	ledgerGroundNoStubHome = "у входа не назван модуль, публикующий его заглушки: " +
		"без этого второе их порождение в модуль службы ничем не отличимо от первого"
)

// ledgerFinding — одна находка сверки.
type ledgerFinding struct {
	Path   string
	Ground string
	Detail string
}

func (f ledgerFinding) String() string {
	if f.Detail == "" {
		return fmt.Sprintf("%s — %s", f.Path, f.Ground)
	}
	return fmt.Sprintf("%s — %s (%s)", f.Path, f.Ground, f.Detail)
}

// ledgerCensus — объём осмотренного.
type ledgerCensus struct {
	Entries   int
	Hashed    int
	TreeFiles int
	Revision  string
}

func (c ledgerCensus) String() string {
	return fmt.Sprintf("записей ведомости %d; отпечатков пересчитано %d; входных контрактов "+
		"в дереве %d; ревизия источника %s", c.Entries, c.Hashed, c.TreeFiles, c.Revision)
}

// scanInputLedger сверяет ведомость входных контрактов с деревом в обе стороны.
func scanInputLedger(tree *treecorpus.Tree) (ledgerCensus, []ledgerFinding, error) {
	var census ledgerCensus
	root := tree.Root()

	ledgerPath := path.Join(protoRoot, inputLedgerFile)
	raw, err := os.ReadFile(path.Join(root, ledgerPath))
	if err != nil {
		return census, nil, fmt.Errorf("ведомость входных контрактов %s не прочитана: %w", ledgerPath, err)
	}
	var ledger inputLedger
	if err := yaml.Unmarshal(raw, &ledger); err != nil {
		return census, nil, fmt.Errorf("%s: разбор ведомости: %w", ledgerPath, err)
	}
	census.Entries = len(ledger.Inputs)
	census.Revision = ledger.Source.Revision

	// Состав дерева: всё под `proto/` ВНЕ собственного корня службы и есть вход.
	inTree := map[string]bool{}
	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".proto") || !strings.HasPrefix(rel, protoRoot+"/") {
			continue
		}
		inner := strings.TrimPrefix(rel, protoRoot+"/")
		if inner == ownContractRoot || strings.HasPrefix(inner, ownContractRoot+"/") {
			continue
		}
		inTree[inner] = true
		census.TreeFiles++
	}

	var findings []ledgerFinding
	named := map[string]bool{}
	for _, e := range ledger.Inputs {
		named[e.Path] = true
		if e.Stubs == "" {
			findings = append(findings, ledgerFinding{Path: e.Path, Ground: ledgerGroundNoStubHome})
		}
		body, readErr := os.ReadFile(path.Join(root, protoRoot, e.Path))
		if readErr != nil {
			findings = append(findings, ledgerFinding{Path: e.Path, Ground: ledgerGroundMissingFile})
			continue
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		census.Hashed++
		if got != e.SHA256 {
			findings = append(findings, ledgerFinding{
				Path: e.Path, Ground: ledgerGroundDrift,
				Detail: fmt.Sprintf("в ведомости %s, у файла %s", e.SHA256, got),
			})
		}
	}
	for inner := range inTree {
		if !named[inner] {
			findings = append(findings, ledgerFinding{Path: inner, Ground: ledgerGroundUnledgered})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Ground < findings[j].Ground
	})
	return census, findings, nil
}

// TestVendoredInputContractsMatchTheirLedger — сам гейт.
func TestVendoredInputContractsMatchTheirLedger(t *testing.T) {
	t.Parallel()

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: %v",
			serviceRoot, err)
	}

	census, findings, err := scanInputLedger(tree)
	if err != nil {
		t.Fatalf("перепись: %s\nведомость входных контрактов: %v", census, err)
	}
	t.Logf("перепись: %s", census)

	if census.Entries == 0 {
		t.Fatalf("%s не называет ни одного входа — сверять нечего, и «расхождений нет» здесь "+
			"означало бы «ничего не прочитано»", path.Join(protoRoot, inputLedgerFile))
	}
	if census.TreeFiles == 0 {
		t.Fatal("входных контрактов в дереве не найдено ни одного — либо замыкание графа " +
			"держится чем-то другим, либо разбор их больше не видит; вердикт беспредметен")
	}
	if census.Revision == "" {
		t.Fatal("ведомость не называет ревизию источника: «приехало как есть» без адреса " +
			"источника непроверяемо ни для кого")
	}

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
