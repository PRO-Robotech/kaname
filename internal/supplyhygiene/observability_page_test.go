// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// observability_page_test.go — ОПУБЛИКОВАННАЯ страница наблюдаемости обещает
// ровно то, что служба производит, и разбирается по ней БЕЗ других наших
// компонентов.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Опубликованная страница — единственный артефакт наблюдаемости, который
// получает дежурный, не читая кода. Обещание величины, которой нет, ХУЖЕ
// отсутствия страницы: дежурный строит по ней запрос, получает пустой ряд и
// читает его как «событий не было». Это тот же класс, что «поле запроса, на
// которое никто не смотрит», только на поверхности документации.
//
// Второе: страница, объясняющая отказ через край платформы, неисполнима в
// установке, где платформы нет by construction, — а служба поставляется именно
// так.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПОЛОСЫ
//
//  1. ПРАВДИВОСТЬ. Каждое имя ряда, названное на странице, имеет производителя
//     в дереве. Производители собираются РАЗБОРОМ синтаксического дерева обоих
//     модулей (службы и фундамента, который она пинит), а не поиском слова:
//     имена рядов встречаются и в строках, и в комментариях, и поиск словом
//     принял бы за производителя собственное объяснение.
//  2. ИСПОЛНИМОСТЬ. Всякая команда в блоке кода обращается к самой службе и не
//     называет чужого компонента.
//
// Одной первой мало: страница может быть правдива и при этом требовать того,
// чего в установке нет. Одной второй мало: команды могут быть исполнимы и
// спрашивать несуществующие величины.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ «НОЛЬ НАЗВАННЫХ РЯДОВ» — НАХОДКА, А НЕ ЧИСТО
//
// До этой проверки страница не называла НИ ОДНОГО ряда: она перечисляла области
// («Пул БД», «Ory-интеграции») и обещала величины, производителя у которых нет.
// Проверка, молчащая на такой странице, была бы вакуумной ровно там, ради чего
// написана, — поэтому пустой перечень названного роняет прогон.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит СУЩЕСТВОВАНИЕ ряда, а не верность его толкования: страница вправе
// объяснить существующий ряд неправильно, и машинного предиката у этого нет.
// Она также не судит прозу: величина, названная словами и без имени ряда, вне
// её наблюдения. Обе границы держатся вниманием и обзором.
//
// Указатель производителей ПЕРМИССИВЕН по построению: он принимает имя,
// объявленное в позиции имени ряда где угодно в обоих модулях, в том числе у
// соседнего сервиса платформы. Ошибаться он может только в сторону «принял
// существующее», и класс, ради которого заведён, — «названо то, чего нет
// вовсе», — этим не затрагивается.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// observabilityPage — опубликованная страница относительно корня службы.
// Опубликовано ровно то, что лежит под каталогом содержимого сайта: инженерные
// страницы и руководство дежурного сайт не служит, и у того, кто ставит
// продукт, их нет.
const observabilityPage = "docs/content/advanced/observability.mdx"

// foreignWorkloads — компоненты, которых в отдельной установке НЕТ by
// construction. Команда, называющая такой, неисполнима у того, кто поставил
// только эту службу.
var foreignWorkloads = []string{"api-gateway"}

// seriesShape — форма имени ряда обоих префиксов: своего и того, что приходит с
// библиотекой платформы.
var seriesShape = regexp.MustCompile(`\b(?:kaname|kacho)_[a-z0-9_]+\b`)

// derivedSuffixes — хвосты, которые Prometheus дописывает к имени гистограммы.
// Запрос дежурного берёт именно их, а производителем объявлено базовое имя.
var derivedSuffixes = []string{"_bucket", "_sum", "_count"}

// fencedBlock — блок кода страницы: язык и его строки.
type fencedBlock struct {
	lang  string
	line  int
	lines []string
}

// pageCensus — объём осмотренного одним обходом.
type pageCensus struct {
	pageLines       int // строк страницы
	fencedBlocks    int // блоков кода
	commandBlocks   int // из них с командами
	seriesMentions  int // упоминаний имени ряда
	seriesDistinct  int // из них различных
	producerFiles   int // прочитано файлов Go обоих модулей
	producerSeries  int // собрано имён рядов с производителем
	producerModules int // модулей, давших хотя бы один файл
}

// splitFenced режет страницу на блоки кода. Разбор ведётся по ограде, а не по
// отступу: отступ в таблице страницы значит другое.
func splitFenced(raw string) []fencedBlock {
	var out []fencedBlock
	var cur *fencedBlock
	for i, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "```") {
			if cur != nil {
				cur.lines = append(cur.lines, line)
			}
			continue
		}
		if cur == nil {
			cur = &fencedBlock{
				lang: strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "```")),
				line: i + 1,
			}
			continue
		}
		out = append(out, *cur)
		cur = nil
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// metricNameConsts — значения строковых констант и переменных уровня пакета,
// разрешимые как имя ряда. Нужны потому, что часть коллекторов называет ряд
// константой, а не литералом по месту.
func metricNameConsts(files []*ast.File) map[string]string {
	out := map[string]string{}
	// Два прохода: во втором разрешаются `Namespace + "_x"`, где `Namespace`
	// объявлен в этом же корпусе.
	for pass := 0; pass < 2; pass++ {
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != len(vs.Values) {
						continue
					}
					for i, n := range vs.Names {
						if v, ok := evalString(vs.Values[i], out); ok {
							out[n.Name] = v
						}
					}
				}
			}
		}
	}
	return out
}

// evalString сводит выражение к строке, если оно из строки и состоит.
func evalString(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(x.Value)
		return v, err == nil
	case *ast.Ident:
		v, ok := consts[x.Name]
		return v, ok
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, okL := evalString(x.X, consts)
		r, okR := evalString(x.Y, consts)
		if !okL || !okR {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return evalString(x.X, consts)
	}
	return "", false
}

// collectSeriesProducers — имена рядов, объявленные в ПОЗИЦИИ имени ряда:
// полем `Name` у настроек коллектора и первым доводом `NewDesc`.
//
// Именно позиция, а не слово: то же имя стоит в текстах справки, в сообщениях
// журнала и в комментариях, и поиск словом принял бы их за объявление.
func collectSeriesProducers(roots []string) (map[string]bool, pageCensus, error) {
	var census pageCensus
	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, root := range roots {
		var files []*ast.File
		filesHere := 0
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // недоступный подкаталог модуля пропускаем молча
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil // неразбираемый файл — не предмет этой проверки
			}
			files = append(files, f)
			filesHere++
			return nil
		})
		if err != nil {
			return nil, census, err
		}
		if filesHere > 0 {
			census.producerModules++
		}
		census.producerFiles += filesHere

		consts := metricNameConsts(files)
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Name" {
						if v, ok := evalString(x.Value, consts); ok && seriesShape.MatchString(v) {
							out[v] = true
						}
					}
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "NewDesc" || len(x.Args) == 0 {
						return true
					}
					if v, ok := evalString(x.Args[0], consts); ok && seriesShape.MatchString(v) {
						out[v] = true
					}
				}
				return true
			})
		}
	}

	// Имена, собираемые фундаментом ИЗ ЧАСТЕЙ (`BuildFQName`), разбором не
	// восстановимы: приставка приходит доводом. Их даёт сам коллектор — тем же
	// объявлением, которым отдаёт их реестру. Пул здесь нулевой намеренно:
	// объявления коллектор отдаёт независимо от того, настроен ли пул.
	descs := make(chan *prometheus.Desc, 64)
	go func() {
		coredb.NewPoolStatsCollector(metrics.Namespace, "primary", nil).Describe(descs)
		close(descs)
	}()
	for d := range descs {
		if m := seriesShape.FindString(d.String()); m != "" {
			out[m] = true
		}
	}

	census.producerSeries = len(out)
	return out, census, nil
}

// hasProducer — есть ли у названного ряда производитель.
//
// Полное имя спрашивается ПЕРВЫМ, и только затем — имя без хвоста гистограммы.
// Обратный порядок ошибается на настоящем ряде, чьё имя оканчивается так же:
// `kaname_outbox_poisoned_count` — это счётчик, а не производное от
// несуществующего `kaname_outbox_poisoned`, и срезанный хвост превращал бы
// живой ряд в находку. Поймано первым же прогоном этой проверки.
func hasProducer(producers map[string]bool, name string) bool {
	if producers[name] {
		return true
	}
	for _, s := range derivedSuffixes {
		if strings.HasSuffix(name, s) && producers[strings.TrimSuffix(name, s)] {
			return true
		}
	}
	return false
}

// scanObservabilityPage — разбор над ПРОИЗВОЛЬНЫМИ страницей и корнями
// производителей. Вынесено из пробы затем, чтобы способность упасть
// доказывалась подачей входа, а не чтением.
func scanObservabilityPage(pagePath string, producerRoots []string) (pageCensus, []string, error) {
	raw, err := os.ReadFile(pagePath)
	if err != nil {
		return pageCensus{}, nil, err
	}

	producers, census, err := collectSeriesProducers(producerRoots)
	if err != nil {
		return census, nil, err
	}

	lines := strings.Split(string(raw), "\n")
	census.pageLines = len(lines)

	// ── полоса 1: у каждого названного ряда есть производитель ──
	mentions := seriesShape.FindAllString(string(raw), -1)
	census.seriesMentions = len(mentions)
	distinct := map[string]bool{}
	for _, m := range mentions {
		distinct[m] = true
	}
	census.seriesDistinct = len(distinct)

	var findings []string
	names := make([]string, 0, len(distinct))
	for n := range distinct {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !hasProducer(producers, n) {
			findings = append(findings, "названа величина "+n+", производителя у неё в дереве НЕТ: "+
				"запрос по ней вернёт пустой ряд, а пустой ряд читается как «событий не было»")
		}
	}
	if census.seriesDistinct == 0 {
		findings = append(findings, "страница не называет НИ ОДНОГО ряда — она перечисляет области, "+
			"а не величины, и по ней нельзя построить ни одного запроса")
	}

	// ── полоса 2: команды исполнимы без других наших компонентов ──
	for _, b := range splitFenced(string(raw)) {
		census.fencedBlocks++
		if b.lang != "bash" && b.lang != "sh" && b.lang != "shell" {
			continue
		}
		census.commandBlocks++
		body := strings.Join(b.lines, "\n")
		for _, w := range foreignWorkloads {
			if strings.Contains(body, w) {
				findings = append(findings, "команда в блоке со строки "+strconv.Itoa(b.line)+
					" обращается к компоненту "+w+", которого в отдельной установке нет: "+
					"разбор по ней неисполним у того, кто поставил только эту службу")
			}
		}
	}
	if census.commandBlocks == 0 {
		findings = append(findings, "на странице нет ни одного блока команд — порядка разбора "+
			"отказа, исполнимого дежурным, она не несёт")
	}

	return census, findings, nil
}

// externalModuleDir — каталог внешнего модуля, который служба пинит версией.
// Отказ разрешения роняет пробу, а не читается как «корня нет»: производители
// живут во внешних модулях, и молчание здесь объявило бы вымыслом каждое имя,
// которое они производят.
func externalModuleDir(t *testing.T, modulePath string) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	// Каталог модуля лежит в кэше модулей; путь к нему объявлен файлом go.sum
	// службы и разрешается сборкой, поэтому спрашивается он у сборки, а не
	// собирается из частей.
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePath)
	cmd.Dir = filepath.Join(dir, serviceRoot)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "каталог модуля %s не разрешился: %s", modulePath, out)
	return strings.TrimSpace(string(out))
}

// producerRootCount — сколько корней даёт producerRoots. Число стоит РЯДОМ со
// своим производителем, чтобы проба сверяла объём осмотренного с тем же
// источником, из которого он получен, а не с рукописной копией.
const producerRootCount = 3

// producerRoots — где ищутся ПРОИЗВОДИТЕЛИ имён, названных документацией: ряды
// наблюдаемости, контракты gRPC. Корней ТРИ, и ни один не лишний:
//
//	дерево службы                — то, что она объявляет сама;
//	модуль фундамента            — `grpcsrv`, `observability`, `operations`: всё,
//	                               что производит ряды транспорта и хранения;
//	остаток платформенного модуля — контракты, которые служба ещё берёт оттуда.
//
// Прежняя редакция знала ДВА корня — дерево и `<платформа>/pkg`, — и на день
// заведения это было верно: фундамент физически лежал там. После выделения
// фундамента отдельным модулем прежний адрес стал давать остаток платформы, где
// `grpcsrv` уже нет: страница наблюдаемости назвала три ряда
// `kacho_grpc_server_*`, а указатель их не нашёл — «названо то, чего нет»
// прозвучало о существующем. Третий корень заведён тем же замером: контракты
// доступа остаются у платформы, и без него ослеп бы отбор тревог.
func producerRoots(t *testing.T) []string {
	t.Helper()
	return []string{
		serviceRoot,
		externalModuleDir(t, foundationModulePath),
		filepath.Join(externalModuleDir(t, platformModulePath), "pkg"),
	}
}

func TestObservabilityPagePromisesOnlyWhatTheServiceProduces(t *testing.T) {
	roots := producerRoots(t)

	census, findings, err := scanObservabilityPage(filepath.Join(serviceRoot, observabilityPage), roots)
	require.NoErrorf(t, err, "разбор страницы: %s", filepath.Join(serviceRoot, observabilityPage))

	t.Logf("перепись: строк страницы %d · блоков кода %d · из них с командами %d · "+
		"упоминаний рядов %d · из них различных %d · прочитано файлов Go %d в %d модулях · "+
		"собрано производителей %d · находок %d",
		census.pageLines, census.fencedBlocks, census.commandBlocks,
		census.seriesMentions, census.seriesDistinct,
		census.producerFiles, census.producerModules, census.producerSeries, len(findings))

	// Пустой обход — находка по каждой оси отдельно.
	require.NotZero(t, census.pageLines, "обход пуст: страница не прочитана — вердикт беспредметен")
	require.NotZero(t, census.producerFiles, "обход пуст: файлов Go не прочитано ни одного — "+
		"«производителя нет» означало бы «не искали»")
	require.Equal(t, producerRootCount, census.producerModules, "прочитан не тот набор модулей: "+
		"указатель производителей обязан покрывать дерево службы, модуль фундамента И остаток "+
		"платформенного модуля — см. producerRoots")
	require.NotZero(t, census.producerSeries, "обход пуст: производителей не собрано ни одного — "+
		"распознаватель ослеп, вердикт беспредметен")

	for _, f := range findings {
		t.Errorf("%s: %s", filepath.ToSlash(filepath.Join(serviceRoot, observabilityPage)), f)
	}
}
