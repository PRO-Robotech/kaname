// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_closure_test.go — контракты службы ЗАМЫКАЮТСЯ в её собственном
// дереве: всякий `import` из её `.proto` резолвится файлом этого репозитория
// либо встроенным типом компилятора, и ничем третьим.
//
// # ПРЕДМЕТ
//
// Решением владельца 2026-09-13 контракты службы уезжают в её репозиторий
// (kacho#2616). «Уехали» проверяется не наличием каталога, а ЗАМКНУТОСТЬЮ:
// каталог, в котором лежит сорок один файл, а сорок второй импортируется из
// чужого дерева, не собирается нигде, кроме того чужого дерева, — то есть
// переезд объявлен и неисполним.
//
// Поэтому гейт судит ГРАФ ИМПОРТОВ, а не состав каталога. Он отвечает на
// вопрос, который задаёт посторонний, клонировавший один этот репозиторий:
// «хватит ли мне того, что я скачал».
//
// # ЧТО ЗДЕСЬ НЕ ПРОВЕРЯЕТСЯ — И ЧЕМ ЭТО ПОКРЫТО
//
// Гейт НЕ компилирует контракты: вердикт компилятора даёт `buf lint` и
// `buf build` в задании `proto` конвейера. Инструмента `buf` в прогоне проб нет
// ни на одной машине по построению (он ставится действием конвейера), и проба,
// зовущая его, отвечала бы «условие не создано» КАЖДЫЙ прогон — то есть
// существовала бы как текст. Разделение намеренное: замкнутость графа
// проверяется здесь и всегда, вердикт компилятора — там и с кодом выхода.
//
// # ГЕЙТ ДВУСТОРОННИЙ, И ВТОРАЯ СТОРОНА НЕСУЩАЯ
//
// Первая сторона: импорт, которому в дереве нет файла, — находка (дерево
// неполно). Вторая: файл `.proto` ВНЕ собственного корня контрактов службы,
// которого не импортирует никто, — тоже находка. Такой файл есть копия чужого
// контракта без предмета: она переживёт снятие своего единственного
// потребителя и останется вторым местом об одном предмете, которое никто не
// сверяет. Исключение живёт, пока есть что исключать.
//
// # ЕДИНИЦА СЧЁТА — ОПЕРАТОР, А НЕ ПОДСТРОКА
//
// Путь контракта встречается в этих файлах не только оператором `import`: он
// стоит в комментариях и в значениях опций. Поэтому текст разбирается на
// ОПЕРАТОРЫ (разделители `;`, `{`, `}` вне строк и комментариев), и предметом
// становится оператор, начинающийся словом `import`. Проверка подстрокой
// краснела бы на собственном объяснении.
package contracthome

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// serviceRoot — корень дерева службы относительно каталога этого пакета.
const serviceRoot = "../.."

// protoRoot — каталог контрактов в дереве службы. Корень входов `buf` тот же.
const protoRoot = "proto"

// ownContractRoot — СОБСТВЕННЫЙ корень контрактов службы внутри `proto/`.
// Ровно он порождает заглушки в модуль службы; всё прочее под `proto/` —
// вход, чьи заглушки публикует их собственный модуль.
const ownContractRoot = "kaname"

// wellKnownPrefix — типы, встроенные в компилятор контрактов. Файла в дереве у
// них нет и быть не должно: их несёт сам `buf`/`protoc`.
const wellKnownPrefix = "google/protobuf/"

// protoImportPattern — оператор импорта. Модификаторы `public`/`weak` языком
// допускаются, поэтому распознаются, а не игнорируются молча.
var protoImportPattern = regexp.MustCompile(`^import\s+(?:public\s+|weak\s+)?"([^"]+)"$`)

// protoStatement — один оператор контракта вместе со строкой своего начала.
type protoStatement struct {
	Text string
	Line int
}

// protoStatements разбирает текст контракта на операторы. Строки и комментарии
// НЕ дают разделителей: `;` внутри строкового значения опции оператор не
// заканчивает.
func protoStatements(src []byte) []protoStatement {
	var out []protoStatement
	var cur strings.Builder

	line := 1
	startLine := 1
	fresh := true

	inString, inLine, inBlock, escaped := false, false, false, false

	flush := func() {
		text := strings.TrimSpace(cur.String())
		if text != "" {
			out = append(out, protoStatement{Text: text, Line: startLine})
		}
		cur.Reset()
		fresh = true
	}

	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\n' {
			line++
			if inLine {
				inLine = false
			}
			if !inString && !inBlock {
				cur.WriteByte(' ')
			}
			continue
		}
		switch {
		case inLine:
			continue
		case inBlock:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		case inString:
			cur.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}

		if c == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				inLine = true
				i++
				continue
			}
			if src[i+1] == '*' {
				inBlock = true
				i++
				continue
			}
		}
		if c == '"' {
			inString = true
			cur.WriteByte(c)
			if fresh {
				startLine = line
				fresh = false
			}
			continue
		}
		if c == ';' || c == '{' || c == '}' {
			flush()
			continue
		}
		if fresh && c != ' ' && c != '\t' && c != '\r' {
			startLine = line
			fresh = false
		}
		cur.WriteByte(c)
	}
	flush()
	return out
}

// protoImportRef — одно ребро графа контрактов.
type protoImportRef struct {
	From string // rel-путь импортирующего файла от корня дерева
	Line int
	Path string // путь, названный оператором, как он написан
}

// closureFinding — разрыв замкнутости. Основание несёт ИСХОД, а не оттенок:
// «нет файла» ломает сборку у постороннего, «никто не импортирует» оставляет
// в дереве копию без предмета.
type closureFinding struct {
	Where  string
	Line   int
	Path   string
	Ground string
}

const (
	closureGroundMissing = "файла нет в этом репозитории: посторонний, клонировавший его один, контракты не соберёт"
	closureGroundOrphan  = "копия чужого контракта, которую не импортирует ни один контракт службы: исключение без предмета"
)

func (f closureFinding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d — import %q (%s)", f.Where, f.Line, f.Path, f.Ground)
	}
	return fmt.Sprintf("%s — %s", f.Where, f.Ground)
}

// closureCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type closureCensus struct {
	ProtoFiles     int // всего .proto под корнем контрактов
	OwnFiles       int // из них под собственным корнем службы
	InputFiles     int // из них входных (корень не собственный)
	Statements     int
	Imports        int
	WellKnown      int // импортов встроенных типов
	ResolvedInTree int
	Unresolved     int
	OrphanInputs   int
}

func (c closureCensus) String() string {
	return fmt.Sprintf("файлов .proto %d (своих %d, входных %d); операторов %d; "+
		"импортов %d — встроенных %d, резолвится деревом %d, не резолвится %d; "+
		"входных без потребителя %d",
		c.ProtoFiles, c.OwnFiles, c.InputFiles, c.Statements,
		c.Imports, c.WellKnown, c.ResolvedInTree, c.Unresolved, c.OrphanInputs)
}

// scanContractClosure строит граф импортов контрактов дерева и возвращает
// разрывы его замкнутости.
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ: у настоящего дерева службы авторитет — ИНДЕКС
// git, у синтетики инъекции — обход диска (`treecorpus.SyntheticTree`).
func scanContractClosure(tree *treecorpus.Tree) (closureCensus, []closureFinding, error) {
	var census closureCensus
	root := tree.Root()

	// Состав корня контрактов: адрес контракта внутри `proto/` — это и есть
	// путь, которым его называет `import`.
	inTree := map[string]bool{}
	var protos []string
	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".proto") {
			continue
		}
		if rel != protoRoot && !strings.HasPrefix(rel, protoRoot+"/") {
			continue
		}
		inner := strings.TrimPrefix(rel, protoRoot+"/")
		inTree[inner] = true
		protos = append(protos, inner)
		census.ProtoFiles++
		if inner == ownContractRoot || strings.HasPrefix(inner, ownContractRoot+"/") {
			census.OwnFiles++
		} else {
			census.InputFiles++
		}
	}

	imported := map[string]bool{}
	var findings []closureFinding

	for _, inner := range protos {
		src, err := os.ReadFile(path.Join(root, protoRoot, inner))
		if err != nil {
			return census, nil, fmt.Errorf("%s: чтение контракта: %w", inner, err)
		}
		for _, st := range protoStatements(src) {
			census.Statements++
			m := protoImportPattern.FindStringSubmatch(st.Text)
			if m == nil {
				continue
			}
			census.Imports++
			target := m[1]
			imported[target] = true
			switch {
			case strings.HasPrefix(target, wellKnownPrefix):
				census.WellKnown++
			case inTree[target]:
				census.ResolvedInTree++
			default:
				census.Unresolved++
				findings = append(findings, closureFinding{
					Where: path.Join(protoRoot, inner), Line: st.Line,
					Path: target, Ground: closureGroundMissing,
				})
			}
		}
	}

	// Вторая сторона: входной контракт без потребителя.
	for _, inner := range protos {
		if inner == ownContractRoot || strings.HasPrefix(inner, ownContractRoot+"/") {
			continue
		}
		if imported[inner] {
			continue
		}
		census.OrphanInputs++
		findings = append(findings, closureFinding{
			Where: path.Join(protoRoot, inner), Ground: closureGroundOrphan,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Where != findings[j].Where {
			return findings[i].Where < findings[j].Where
		}
		return findings[i].Line < findings[j].Line
	})
	return census, findings, nil
}

// TestServiceContractsResolveInsideItsOwnTree — сам гейт.
func TestServiceContractsResolveInsideItsOwnTree(t *testing.T) {
	t.Parallel()

	tree, err := treecorpus.NewTree(serviceRoot)
	if err != nil {
		t.Fatalf("состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: "+
			"обход диска вместо индекса читал бы каталоги, которых в репозитории нет: %v",
			serviceRoot, err)
	}

	census, findings, err := scanContractClosure(tree)
	if err != nil {
		t.Fatalf("обход контрактов службы: %v", err)
	}
	t.Logf("перепись: %s", census)

	if census.ProtoFiles == 0 {
		t.Fatalf("под %s/ не прочитано ни одного .proto — контрактов службы в её дереве НЕТ, "+
			"и «замкнутость не нарушена» здесь означало бы «нечего было замыкать» "+
			"(решение владельца 2026-09-13, kacho#2616)", protoRoot)
	}
	if census.OwnFiles == 0 {
		t.Fatalf("под %s/%s/ не прочитано ни одного .proto — собственного корня контрактов "+
			"у службы нет, и вердикт беспредметен", protoRoot, ownContractRoot)
	}
	if census.Imports == 0 {
		t.Fatal("операторов import не осмотрено ни одного — обход пуст, вердикт беспредметен")
	}

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
