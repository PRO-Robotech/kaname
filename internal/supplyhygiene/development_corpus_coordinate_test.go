// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// development_corpus_coordinate_test.go — прод-код не называет документов,
// которых у клонирующего нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kacho#2619)
//
// Прод-код службы ссылался на документы РЕГЛАМЕНТА РАЗРАБОТКИ по голому имени
// файла: `security.md`, `api-conventions.md`, `architecture.md` и соседи свода.
// Регламент живёт в воркспейсе разработки и в поставку продукта не входит — так
// решено осознанно. Служба вынесена отдельным ПУБЛИЧНЫМ репозиторием, и у
// всякого, кто её клонировал, такое имя не резолвится ни во что: ни файла, ни
// каталога, ни ссылки.
//
// Это не косметика: ссылка стоит рядом с решениями о периметре, и читатель, не
// нашедший обоснования, вправе счесть решение необоснованным.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ, И ПОЧЕМУ БЕЗ СПИСКА ИМЁН
//
// Всякое ГОЛОЕ ИМЯ ФАЙЛА `*.md`, названное комментарием либо строковым литералом
// прод-кода, обязано РЕЗОЛВИТЬСЯ в составе дерева службы.
//
// Перечня имён корпуса здесь НЕТ намеренно. Выписанный перечень пришлось бы
// держать в согласии со сводом, который в этом дереве не лежит и предикатом не
// выводится: новое имя корпуса приехало бы в комментарий и осталось невидимым.
// Предикат «имя названо — файла нет» этого не требует и закрывает класс шире:
// он ловит и всякую другую ссылку на документ, пережившую своё дерево.
//
// Координата с сегментом каталога (`docs/architecture/x.md`) этой осью НЕ
// судится: у неё свой держатель — ось координат документа в
// `internal/apps/kaname/api/sa_keys/revoke_window_doc_test.go`, где граница
// между координатой и именем документа проведена и доказана обеими половинами
// инъекции. Две оси об одном предмете разошлись бы молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ТЕКСТУ
//
// Имя документа встречается и в ИСПОЛНЯЕМОМ коде — путями, которые строит сам
// продукт, — и в прозе, объясняющей эту самую ось. Поиск по сырому файлу не
// отличает одно от другого и краснел бы на собственном объяснении. Судятся узлы:
// комментарий и строковый литерал.
//
// Литерал судится наравне с комментарием НАМЕРЕННО, и он хуже: строка уезжает
// оператору текстом отказа. Ссылка на документ, которого у оператора нет, в
// отказе — не неудобство, а тупик: отказ обязан восстанавливать следующий шаг.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо, с числами
//
//  1. СГЕНЕРИРОВАННЫЕ СТАБЫ (`pkg/api/**`) исключены: их комментарии производит
//     контракт, и правка стаба уехала бы при первой регенерации. Производитель
//     назван (`proto/**`), исключение самоистекает — ось печатает, сколько
//     вхождений в исключённой полосе, и «ноль» там означает, что исключать
//     больше нечего.
//  2. ПРОБЫ (`*_test.go`), документация (`docs/**`), сценарии и профили осью не
//     судятся. Класс там тот же, радиус другой, и одним изменением он не
//     закрывается честно; остаток назван числом и предикатом в задаче.
//     2а. ОДИН ФАЙЛ ПРОЩЁН ПОИМЁННО, и причина не в удобстве. Текст запроса
//     вердикта лежит в строковом литерале, а этот литерал стоит ПОД ОТПЕЧАТКОМ
//     трёх отчётов замера: правка его — даже в комментарии SQL — объявляет
//     отчёты утверждающими о дереве, которого нет, и пересъём требует базы и
//     двухчасового прогона. Прощение САМОИСТЕКАЕТ: ось требует, чтобы предмет у
//     него БЫЛ, и объявляет находку, когда прощать стало нечего.
//  3. Она НЕ судит, что проза после правки говорит правду: это суждение о
//     смысле. Она судит, что названное имя резолвится.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// generatedStubsPrefix — полоса сгенерированных стабов: их комментарии
// производит контракт, а не автор кода.
const generatedStubsPrefix = "pkg/api/"

// fingerprintedLiteralFile — файл, чей строковый литерал стоит под отпечатком
// отчётов замера. Прощён поимённо, и прощение самоистекает: см. §«Чего эта
// проверка не закрывает», п. 2а.
const fingerprintedLiteralFile = "internal/repo/kaname/pg/relverdict/query.go"

// bareDocName — ГОЛОЕ ИМЯ документа: без сегмента каталога и без ведущей косой
// черты. Отрицательный класс слева отсекает координату (`docs/x.md`) и хвост
// чужого имени (`MODEL-MANIFEST.md` при поиске `MANIFEST.md`).
var bareDocName = regexp.MustCompile(`(?:^|[^A-Za-z0-9_./-])([A-Za-z0-9_][A-Za-z0-9_.-]*\.md)\b`)

// docNameFinding — одно попадание: координата и неразрешимое имя.
type docNameFinding struct {
	file string
	line int
	name string
	kind string
}

// docNameCensus — объём осмотренного.
type docNameCensus struct {
	filesTracked  int
	filesParsed   int
	commentsSeen  int
	literalsSeen  int
	namesSeen     int
	namesResolved int
	excludedHits  int
	exemptedHits  int
}

// resolvableBasenames — множество имён файлов дерева без каталога, плюс то же
// множество с дописанным `.md`.
//
// Имя, встречающееся в дереве хоть где-то, названо разрешимым: комментарий
// имеет право сослаться на соседний документ по имени, и предмет оси не в этом.
//
// БЕЗРАСШИРЕННЫЙ БЛИЗНЕЦ ЗАСЧИТЫВАЕТСЯ ТОЖЕ, и это не послабление. Проза
// законно перечисляет ИМЕНА ФАЙЛОВ, которые распознаёт сам продукт: перечень
// оснований файла лицензии называет `LICENSE`, `LICENSE.md`, `LICENSE-MIT`. Там
// `LICENSE.md` — не координата документа, а образец входа, и документ, на
// который он указывает, в дереве ЕСТЬ, только без расширения. Ось, красневшая
// на нём, ловила бы форму записи, а не существо, — и первый же такой ложный
// срабат её бы отключил.
//
// Имена корпуса от этого не спасаются: файла `security` в дереве нет так же,
// как и `security.md` (проверено предикатом по именам файлов состава).
func resolvableBasenames(tree *treecorpus.Tree) map[string]struct{} {
	out := map[string]struct{}{}
	for rel := range tree.Files() {
		base := filepath.Base(rel)
		out[base] = struct{}{}
		if !strings.HasSuffix(base, ".md") {
			out[base+".md"] = struct{}{}
		}
	}
	return out
}

// collectDocNames — голые имена документов в тексте узла.
func collectDocNames(text string) []string {
	var out []string
	for _, m := range bareDocName.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

// scanDevelopmentCorpusCoordinates — разбор над ПРОИЗВОЛЬНЫМ деревом. Вынесено
// из теста затем, чтобы способность гейта упасть доказывалась подачей входа.
func scanDevelopmentCorpusCoordinates(tree *treecorpus.Tree) (docNameCensus, []docNameFinding, error) {
	var census docNameCensus

	root := tree.Root()
	known := resolvableBasenames(tree)
	census.filesTracked = tree.Count()

	var findings []docNameFinding

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.ParseComments)
		if err != nil {
			return census, nil, err
		}

		excluded := strings.HasPrefix(rel, generatedStubsPrefix)
		exempted := rel == fingerprintedLiteralFile
		if !excluded {
			census.filesParsed++
		}

		record := func(pos token.Pos, text, kind string) {
			for _, name := range collectDocNames(text) {
				if excluded {
					census.excludedHits++
					continue
				}
				census.namesSeen++
				if _, ok := known[name]; ok {
					census.namesResolved++
					continue
				}
				if exempted {
					census.exemptedHits++
					continue
				}
				findings = append(findings, docNameFinding{
					file: rel, line: fset.Position(pos).Line, name: name, kind: kind,
				})
			}
		}

		for _, group := range file.Comments {
			for _, c := range group.List {
				if !excluded {
					census.commentsSeen++
				}
				record(c.Pos(), c.Text, "комментарий")
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if !excluded {
				census.literalsSeen++
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				value = lit.Value
			}
			record(lit.Pos(), value, "строковый литерал")
			return true
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})

	return census, findings, nil
}

func TestProdCodeNamesNoDocumentTheCloneLacks(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева не прочитан")

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err, "прод-файл не разобран")

	t.Logf(
		"перепись: файлов в составе %d · прод-файлов Go разобрано %d · комментариев %d · литералов %d · "+
			"имён документов названо %d · из них резолвится %d · находок %d · "+
			"в исключённой полосе %s вхождений %d · прощено поимённо %d",
		census.filesTracked, census.filesParsed, census.commentsSeen, census.literalsSeen,
		census.namesSeen, census.namesResolved, len(findings), generatedStubsPrefix,
		census.excludedHits, census.exemptedHits,
	)

	require.NotZero(t, census.filesParsed, "обход пуст: прод-файлов не разобрано ни одного — вердикт беспредметен")
	require.NotZero(t, census.commentsSeen, "обход пуст: комментариев не осмотрено ни одного — вердикт беспредметен")
	require.NotZero(t, census.namesSeen, "обход пуст: имён документов не распознано ни одного — распознаватель ослеп")
	require.NotZero(t, census.namesResolved,
		"обход пуст: ни одно имя документа не резолвится — значит сломан не код, а разрешение имён")

	// ПРОЩЕНИЕ САМОИСТЕКАЕТ: запись, которой больше нечего прощать, — находка.
	// Иначе она унаследует следующую слепую зону и переживёт свой предмет.
	require.NotZerof(t, census.exemptedHits,
		"поимённое прощение %s потеряло предмет: вхождений там больше нет. "+
			"Снимите константу fingerprintedLiteralFile и этот страж вместе с ней — "+
			"исключение без предмета есть слепая зона, выданная вперёд", fingerprintedLiteralFile)

	for _, f := range findings {
		t.Errorf(
			"%s:%d — %s называет документ %q, которого в дереве службы НЕТ. "+
				"Служба вынесена отдельным публичным репозиторием: у клонирующего это имя не резолвится "+
				"ни во что, и читатель, пришедший за обоснованием, не находит ничего. "+
				"Исходов три: назвать факт на месте · перенести обоснование в docs/engineering и сослаться "+
				"КООРДИНАТОЙ · снять ссылку, если рядом сказано всё нужное",
			f.file, f.line, f.kind, f.name,
		)
	}
}
