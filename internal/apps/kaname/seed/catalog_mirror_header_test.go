// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// catalog_mirror_header_test.go — шапка зеркала каталога прав обязана описывать
// ДЕРЕВО, а не намерение, с которым файл заводили.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#2502)
//
// Шапка `permissions.go` несла шесть утверждений, и на момент находки не было
// верно НИ ОДНО: зеркало объявлялось не читаемым рантаймом — при том что его
// грузит композиционный корень; объявлялось читаемым обработчиком проверки
// доступа — в том же файле, двумя абзацами ниже; расхождение копий объявлялось
// не инцидентом — при рецепте сборки, требовавшем побайтового совпадения; состав
// объявлялся «в бо́льшей части с пустыми полями» — при нуле записей без права;
// признак объявлялся будущим — при пробе, уже инвертированной; и ссылка вела в
// документ, которого нет ни в одном из двух репозиториев.
//
// Тяжесть не в числе утверждений, а в предмете: это каталог прав. Читатель,
// поверивший шапке, заключит, что расхождение копий безопасно, и «починит» код
// под неверный комментарий (`security.md` §Hardening, п. 5).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ МАШИННО-ЧИТАЕМЫЙ МАРКЕР, А НЕ ПРОВЕРКА ПРОЗЫ
//
// Проза меняется, и проверять её на согласие с деревом нечем: предикат по
// подстроке считал бы и ЭТУ шапку, объясняющую снятые утверждения. Поэтому у
// каждой сверяемой величины есть маркер — форма, которую проза не производит
// случайно, — и гейт сверяет ЕГО с числом, которое считает сам.
//
// Маркер обязан встречаться РОВНО ОДИН раз. Ноль означает, что сверять нечего;
// больше одного — два места об одном числе, из которых верно одно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТЫРЕ ОСИ, И КАЖДАЯ ПАДАЕТ САМА
//
//  1. ЧИТАТЕЛИ. Сколько прод-файлов вне оснастки проб грузят реестр — разбор
//     считает САМ, по узлу вызова. Ось закрывает ровно снятое утверждение
//     «используется ТОЛЬКО интеграционными пробами»: появился прод-читатель —
//     шапка обязана это признать; исчез — тоже.
//  2. ОСНАСТКА ПРОБ. Читатели под `internal/testsupport/` считаются ОТДЕЛЬНО.
//     Слить их с первым числом значило бы сделать «зеркало читает рантайм»
//     неотличимым от «зеркало читает фикстура», то есть потерять сам предмет
//     первой оси.
//  3. СОСТАВ. Записей в каталоге · без права · без требуемого отношения — три
//     числа, каждое из embed-файла, каждое своим маркером. Одно общее число
//     скрыло бы, какая половина утверждения устарела.
//  4. КООРДИНАТА ДОКУМЕНТА. Всякий путь `*.md`, названный в комментариях файла,
//     обязан резолвиться в дереве. Ровно этой осью ловится шестое снятое
//     утверждение — ссылка в документ, которого нет.
//  5. ИМЯ СВОЕГО ПАКЕТА. Всякая ссылка вида `seed.<Имя>` в комментариях файла
//     обязана быть ОБЪЯВЛЕНА пакетом. Шапка называла точку входа `seed.Run()`,
//     которой в пакете нет ни одной, и тип с именем, которого в пакете нет тоже:
//     читатель шёл по ним и не находил ничего.
//
//     Форма взята КВАЛИФИЦИРОВАННАЯ намеренно. Голое имя в обратных кавычках
//     несут и переменные окружения, и имена полей JSON, и имена чужих пакетов —
//     предикат по ним давал бы ложные находки там, где проза законна. С
//     квалификатором двусмысленности нет by construction: `seed.` называет ровно
//     этот пакет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит ЧИСЛА и КООРДИНАТЫ, а не смысл прозы: шапка, чьи маркеры сошлись,
// может остаться плохо написанной, и это решается чтением, а не гейтом. Она
// молчит и о том, идентичны ли копии каталога у службы и у края: второго
// операнда в этом дереве НЕТ ПО ПОСТРОЕНИЮ — служба уехала отдельным
// репозиторием, — поэтому такое утверждение здесь было бы непроверяемым, и его
// место в шапке занял факт о том, где копия читается.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// treeRootFromSeed — корень дерева службы от каталога этого пакета.
const treeRootFromSeed = "../../../.."

// mirrorHeaderFile — файл, чью шапку судит гейт (от корня дерева).
const mirrorHeaderFile = "internal/apps/kaname/seed/permissions.go"

// mirrorCatalogFile — embed-файл каталога (от корня дерева).
const mirrorCatalogFile = "internal/apps/kaname/seed/embedded/permission_catalog.json"

// registryLoader — имя функции, чьих вызывающих считает перепись.
const registryLoader = "LoadPermissionRegistry"

// mirrorPackageDir — каталог пакета, чьи объявления сверяются с прозой шапки
// (от корня дерева).
const mirrorPackageDir = "internal/apps/kaname/seed"

// mirrorPackageQualifier — квалификатор этого пакета в прозе.
const mirrorPackageQualifier = "seed"

// fixtureReaderPrefix — оснастка проб. Её читатели считаются отдельно от
// прод-читателей: слить их значило бы потерять предмет первой оси.
const fixtureReaderPrefix = "internal/testsupport/"

// mirrorMarkers — сверяемые величины: маркер → как назвать его в находке.
//
// Перечень закрыт и объявлен ОДИН раз: величина без маркера не сверяется ничем,
// а маркер без величины сверял бы себя с собой.
var mirrorMarkers = []struct {
	name string
	re   *regexp.Regexp
	of   func(catalogHeaderFacts) int
}{
	{"читателей реестра в прод-коде", regexp.MustCompile(`ЧИТАТЕЛЕЙ РЕЕСТРА В ПРОД-КОДЕ:\s*(\d+)`),
		func(f catalogHeaderFacts) int { return len(f.ProdReaders) }},
	{"читателей реестра в оснастке проб", regexp.MustCompile(`ЧИТАТЕЛЕЙ РЕЕСТРА В ОСНАСТКЕ ПРОБ:\s*(\d+)`),
		func(f catalogHeaderFacts) int { return len(f.FixtureReaders) }},
	{"записей каталога", regexp.MustCompile(`ЗАПИСЕЙ КАТАЛОГА:\s*(\d+)`),
		func(f catalogHeaderFacts) int { return f.Entries }},
	{"записей без права", regexp.MustCompile(`ЗАПИСЕЙ БЕЗ ПРАВА:\s*(\d+)`),
		func(f catalogHeaderFacts) int { return f.NoPermission }},
	{"записей без требуемого отношения", regexp.MustCompile(`ЗАПИСЕЙ БЕЗ ОТНОШЕНИЯ:\s*(\d+)`),
		func(f catalogHeaderFacts) int { return f.NoRelation }},
}

// docCoordinate — путь документа, названный в прозе. Расширение закрыто: гейт
// судит координаты документов, а не всякую строку с точкой.
var docCoordinate = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_./-]*\.md\b`)

// ownPackageRef — ссылка на имя СВОЕГО пакета: `seed.<Заглавная>`. Левая граница
// закрыта, чтобы `myseed.X` не засчитался нашим пакетом.
var ownPackageRef = regexp.MustCompile(`(?:^|[^\w.])` + mirrorPackageQualifier + `\.([A-Z][A-Za-z0-9_]*)`)

// catalogHeaderFacts — вход предиката. Собран так, чтобы предикат можно было
// прогнать инъекцией, не трогая дерево.
type catalogHeaderFacts struct {
	// Comments — весь текст комментариев файла шапки.
	Comments string
	// ProdReaders — прод-файлы вне оснастки проб, где разбор нашёл вызов.
	ProdReaders []string
	// FixtureReaders — то же в оснастке проб.
	FixtureReaders []string
	// Entries / NoPermission / NoRelation — состав embed-каталога.
	Entries, NoPermission, NoRelation int
	// DocPaths — координата документа → резолвится ли она в дереве.
	DocPaths map[string]bool
	// OwnRefs — имя своего пакета, названное прозой → объявлено ли оно пакетом.
	OwnRefs map[string]bool
}

// auditCatalogMirrorHeader — предикат всех осей. Возвращает находки; пусто = норма.
func auditCatalogMirrorHeader(f catalogHeaderFacts) []string {
	var found []string

	for _, m := range mirrorMarkers {
		hits := m.re.FindAllStringSubmatch(f.Comments, -1)
		if len(hits) != 1 {
			found = append(found, fmt.Sprintf(
				"маркер величины %q встречается %d раз(а), а обязан ровно один: ноль означает, "+
					"что сверять с деревом нечего, больше одного — два места об одном числе",
				m.name, len(hits)))
			continue
		}
		claimed, err := strconv.Atoi(hits[0][1])
		if err != nil {
			found = append(found, fmt.Sprintf("маркер величины %q не несёт числа: %q", m.name, hits[0][1]))
			continue
		}
		if measured := m.of(f); claimed != measured {
			found = append(found, fmt.Sprintf(
				"шапка называет %s: %d; замер дерева даёт %d", m.name, claimed, measured))
		}
	}

	for _, p := range sortedDocPaths(f.DocPaths) {
		if !f.DocPaths[p] {
			found = append(found, "шапка называет документ "+p+
				", которого в дереве нет — утверждение отправляет читателя в никуда")
		}
	}

	for _, name := range sortedDocPaths(f.OwnRefs) {
		if !f.OwnRefs[name] {
			found = append(found, "шапка называет "+mirrorPackageQualifier+"."+name+
				", чего пакет не объявляет — читатель пойдёт по имени и не найдёт ничего")
		}
	}

	return found
}

func sortedDocPaths(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCatalogMirrorHeaderDescribesTheTree — гейт на дереве службы.
func TestCatalogMirrorHeaderDescribesTheTree(t *testing.T) {
	tree, err := treecorpus.NewTree(treeRootFromSeed)
	require.NoError(t, err, "состав дерева службы не собран — вердикт беспредметен")
	root := tree.Root()

	comments := fileComments(t, filepath.Join(root, filepath.FromSlash(mirrorHeaderFile)))
	prod, fixture, scanned, parsed := registryReaders(t, tree, true)
	entries, noPerm, noRel := catalogComposition(t, filepath.Join(root, filepath.FromSlash(mirrorCatalogFile)))
	docs := docPathsIn(comments, tree)
	declared := packageDeclarations(t, tree, mirrorPackageDir)
	ownRefs := ownRefsIn(comments, declared)

	// ПРЕДПОСЫЛКИ. «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.Positive(t, scanned, "не осмотрено ни одного файла Go — предпосылка переписи сломана")
	require.NotEmpty(t, comments, "комментариев файла шапки не прочитано ни одного")
	require.Positive(t, entries, "каталог пуст — состав сверять нечем")
	require.NotEmpty(t, prod,
		"разбор не нашёл НИ ОДНОГО прод-читателя реестра вне оснастки проб — предикат "+
			"меряет не то, и всякое утверждение о числе читателей было бы вакуумным")
	require.Contains(t, declared, registryLoader,
		"разбор не нашёл в пакете даже загрузчика реестра — перечень объявлений собран не по "+
			"тому каталогу, и пятая ось объявила бы ненайденным всё")
	require.NotEmpty(t, ownRefs,
		"шапка не называет НИ ОДНОГО имени своего пакета — пятая ось не проверяет ничего, "+
			"и «имён не названо» стало бы неотличимо от «названное на месте»")

	facts := catalogHeaderFacts{
		Comments: comments, ProdReaders: prod, FixtureReaders: fixture,
		Entries: entries, NoPermission: noPerm, NoRelation: noRel,
		DocPaths: docs, OwnRefs: ownRefs,
	}
	found := auditCatalogMirrorHeader(facts)

	t.Logf("перепись: файлов Go осмотрено %d, разобрано %d; читателей %s в прод-коде %d (%s), "+
		"в оснастке проб %d (%s); записей каталога %d (без права %d · без отношения %d); "+
		"координат документов в шапке %d; объявлений пакета %d, имён своего пакета в шапке %d",
		scanned, parsed, registryLoader, len(prod), strings.Join(prod, ", "),
		len(fixture), strings.Join(fixture, ", "), entries, noPerm, noRel, len(docs),
		len(declared), len(ownRefs))

	require.Emptyf(t, found,
		"шапка зеркала каталога прав расходится с деревом:\n  %s\n\n"+
			"Шапка, противоречащая рантайму, хуже отсутствия шапки: она даёт уверенность "+
			"вместо вопроса, и следующий «починит» код под неверный комментарий.",
		strings.Join(found, "\n  "))
}

// fileComments — текст ВСЕХ комментариев файла.
//
// Именно комментариев, а не файла целиком: иначе идентификатор в коде зачёлся бы
// за утверждение, и гейт судил бы имя переменной вместо прозы.
func fileComments(t *testing.T, abs string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
	require.NoErrorf(t, err, "разбор %s: без него гейт судил бы пустую строку", abs)
	var sb strings.Builder
	for _, g := range f.Comments {
		sb.WriteString(g.Text())
		sb.WriteString("\n")
	}
	return sb.String()
}

// registryReaders — пути файлов, в которых РАЗБОР нашёл вызов загрузчика реестра.
//
// `prodOnly` исключает пробы: вызов из пробы читателем на пути запроса не
// является. Флаг — параметр, а не константа, потому что НЕВЫРОЖДЕННОСТЬ самого
// исключения обязана быть проверена: перепись без фильтра стоит рядом в инъекции
// и обязана быть СТРОГО шире.
//
// Файл, объявляющий загрузчик, читателем не считается: иначе число никогда не
// было бы нулём и ось молчала бы на дереве, где читателей не осталось.
func registryReaders(t *testing.T, tree *treecorpus.Tree, prodOnly bool) (prod, fixture []string, scanned, parsed int) {
	t.Helper()
	root := tree.Root()
	fset := token.NewFileSet()
	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if !strings.HasSuffix(slash, ".go") || slash == mirrorHeaderFile {
			continue
		}
		if prodOnly && strings.HasSuffix(slash, "_test.go") {
			continue
		}
		scanned++
		body, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(slash)))
		require.NoError(t, rerr)
		// Дешёвый отсев: разбирается только то, где имя вообще встречается.
		if !strings.Contains(string(body), registryLoader) {
			continue
		}
		parsed++
		f, perr := parser.ParseFile(fset, slash, body, 0)
		require.NoErrorf(t, perr, "разбор %s", slash)
		hit := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if fn.Sel != nil && fn.Sel.Name == registryLoader {
					hit = true
				}
			case *ast.Ident:
				if fn.Name == registryLoader {
					hit = true
				}
			}
			return true
		})
		if !hit {
			continue
		}
		if strings.HasPrefix(slash, fixtureReaderPrefix) {
			fixture = append(fixture, slash)
			continue
		}
		prod = append(prod, slash)
	}
	sort.Strings(prod)
	sort.Strings(fixture)
	return prod, fixture, scanned, parsed
}

// catalogComposition — состав embed-каталога: записей · без права · без отношения.
func catalogComposition(t *testing.T, abs string) (entries, noPermission, noRelation int) {
	t.Helper()
	raw, err := os.ReadFile(abs)
	require.NoErrorf(t, err, "каталог %s не прочитан — состав сверять нечем", abs)
	var rows []struct {
		Permission       string `json:"permission"`
		RequiredRelation string `json:"required_relation"`
	}
	require.NoError(t, json.Unmarshal(raw, &rows), "разбор каталога")
	for _, r := range rows {
		if r.Permission == "" {
			noPermission++
		}
		if r.RequiredRelation == "" {
			noRelation++
		}
	}
	return len(rows), noPermission, noRelation
}

// docPathsIn — координаты документов, названные в прозе, и резолвится ли каждая.
//
// Резолв идёт по СОСТАВУ дерева, а не по файловой системе: координата, названная
// в шапке, обязана быть отслеживаемым файлом, иначе следующий клон её не увидит.
func docPathsIn(comments string, tree *treecorpus.Tree) map[string]bool {
	out := map[string]bool{}
	for _, p := range docCoordinate.FindAllString(comments, -1) {
		out[p] = tree.HasFile(p)
	}
	return out
}

// packageDeclarations — имена, ОБЪЯВЛЕННЫЕ пакетом на ВЕРХНЕМ УРОВНЕ: функции,
// типы, константы, переменные.
//
// Методы в перечень НЕ входят, и это не упрощение: ссылкой `seed.X` метод
// адресовать нельзя вовсе — квалификатор пакета разрешается только в объявление
// верхнего уровня. Первая редакция этой функции метод считала, и находка
// пропала молча: шапка называла точку входа `seed.Run()`, а в пакете есть метод
// `Run` у совсем другого типа, поэтому имя «нашлось».
//
// Пробы в перечень не входят тоже: проза шапки говорит о прод-поверхности
// пакета, и имя, живущее только в пробе, поверхностью не является.
func packageDeclarations(t *testing.T, tree *treecorpus.Tree, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	files := 0
	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if filepath.ToSlash(filepath.Dir(slash)) != dir || !strings.HasSuffix(slash, ".go") {
			continue
		}
		if strings.HasSuffix(slash, "_test.go") {
			continue
		}
		files++
		f, err := parser.ParseFile(fset, slash, nil, 0)
		if err != nil {
			f, err = parser.ParseFile(fset, filepath.Join(tree.Root(), filepath.FromSlash(slash)), nil, 0)
		}
		require.NoErrorf(t, err, "разбор %s", slash)
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Name != nil && decl.Recv == nil {
					out[decl.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name != nil {
							out[sp.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range sp.Names {
							out[n.Name] = true
						}
					}
				}
			}
		}
	}
	require.Positivef(t, files, "в каталоге %s не прочитано ни одного прод-файла Go — "+
		"перечень объявлений пуст, и пятая ось объявила бы ненайденным всё", dir)
	return out
}

// ownRefsIn — имена своего пакета, названные прозой, и объявлено ли каждое.
func ownRefsIn(comments string, declared map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, m := range ownPackageRef.FindAllStringSubmatch(comments, -1) {
		out[m[1]] = declared[m[1]]
	}
	return out
}
