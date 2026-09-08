// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lockclaims_test.go — комментарий не приписывает форварду блокировки, которой
// он не берёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Шестнадцать строк прод-кода в девяти файлах и пять строк проб приписывали
// быстрому пути материализации («форварду») SHARE-блокировку — оборотом, который
// объявлен ниже константой claimForm и в прозе здесь не воспроизводится.
// Реализация объявляет обратное и прямо в шапке: форвард не берёт advisory-
// блокировки ВОВСЕ — ни EXCLUSIVE, ни SHARE. Утверждение пережило снятие
// блокировки и продолжало читаться как факт — в том числе в ОБЪЯВЛЕНИИ
// интерфейса, то есть там, где его читают, не открывая реализацию.
//
// Цена измерена: по этому комментарию была заведена и три месяца прожила задача,
// чей признак выведен из ложного утверждения; закрыть её удалось только замером,
// опровергнувшим половину посылки. Следующий, планируя темп пути создания, будет
// исходить из очереди, которой нет, — либо не заметит настоящую.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ, И ЧЕМ УТВЕРЖДЕНИЕ ОТЛИЧАЕТСЯ ОТ ОТРИЦАНИЯ
//
// Предикат по слову находку от объяснения НЕ отличает: дерево законно несёт и то,
// и другое — «здесь СТОЯЛА блокировка и снята», «ни EXCLUSIVE, ни SHARE». Поэтому
// судится не слово, а ФОРМА:
//
//   - находка — искомый оборот (константа claimForm ниже), В ОКНЕ ПЕРЕД которым
//     нет отрицания;
//   - законный близнец — тот же оборот с отрицанием в окне («no …», «without a …»,
//     «БЕЗ …»).
//
// Судится РАЗОБРАННЫЙ комментарий (go/ast), а не сырой текст: сам оборот живёт в
// этом файле строковой константой, и проверка по тексту нашла бы находкой саму
// себя — ровно тот класс, который она ловит. Оборот НЕ воспроизводится в прозе
// этого файла ни разу: комментарий, цитирующий его, стал бы находкой при первом
// же прогоне после коммита.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДПОСЫЛКА ПРОВЕРЯЕТСЯ, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
// Запрет обоснован фактом о дереве: форвард блокировки не берёт. Факт может
// измениться — тогда утверждения комментариев станут ВЕРНЫМИ, а гейт — ложью.
// Поэтому предпосылка ВЫВОДИТСЯ разбором: считаются вызовы `AcquireBindingLock*`
// в файле форварда (обязано быть 0) и в файле полного прохода (обязано быть
// БОЛЬШЕ нуля — положительный контроль: без него «ноль у форварда» неотличимо от
// сломанного распознавателя, который не находит блокировку нигде).
package lockclaims

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// serviceRoot — корень службы относительно каталога этого пакета.
const serviceRoot = "../.."

// forwardFile / fullPathFile — файлы, из которых ВЫВОДИТСЯ предпосылка.
const (
	forwardFile  = "internal/apps/kaname/api/access_binding/reconcile/forward.go"
	fullPathFile = "internal/apps/kaname/api/access_binding/reconcile/reconcile.go"
)

// claimForm — оборот, приписывающий блокировку. Регистр не значим: дерево пишет
// его и заглавными, и вперемешку.
const claimForm = "share advisory lock"

// negationWindow — сколько знаков ПЕРЕД оборотом читается в поисках отрицания.
// Величина выбрана по самой длинной законной форме дерева («holds NO advisory
// lock on the binding at all», 44 знака) с запасом.
const negationWindow = 64

// negations — токены отрицания обеих языковых форм корпуса.
var negations = []string{
	" no ", " not ", " never ", " neither ", " nor ", "without", "no-",
	" без ", " ни ", "никак", " нет ",
}

// skippedDirs — каталоги, обходу не принадлежащие.
var skippedDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "build": {}, ".docusaurus": {},
}

// claimCensus — объём осмотренного. Печатается ВСЕГДА: «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
type claimCensus struct {
	filesParsed      int
	commentGroups    int
	advisoryMentions int
	claims           int
	denials          int
}

// claimFinding — одно попадание.
type claimFinding struct {
	file    string
	line    int
	excerpt string
}

// scanLockClaims — весь разбор одним местом, над ПРОИЗВОЛЬНЫМ составом. Обход
// вынесен из теста затем, чтобы способность гейта упасть проверялась подачей
// настоящего входа, а не чтением.
func scanLockClaims(tree *treecorpus.Tree) (claimCensus, []claimFinding, error) {
	var census claimCensus
	var findings []claimFinding

	root := tree.Root()
	fset := token.NewFileSet()

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") || inSkippedDir(rel) {
			continue
		}
		path := filepath.Join(root, rel)
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return census, findings, err
		}
		census.filesParsed++

		for _, group := range file.Comments {
			census.commentGroups++
			// Текст группы — БЕЗ маркеров комментария, склеенный: оборот
			// переносится строкой, и посточная проверка его не увидела бы.
			flat := collapse(group.Text())
			lower := strings.ToLower(flat)
			census.advisoryMentions += strings.Count(lower, "advisory")

			for offset := 0; ; {
				idx := strings.Index(lower[offset:], claimForm)
				if idx < 0 {
					break
				}
				at := offset + idx
				if negatedBefore(lower, at) {
					census.denials++
				} else {
					census.claims++
					findings = append(findings, claimFinding{
						file:    filepath.ToSlash(rel),
						line:    lineOfClaim(fset, group),
						excerpt: excerptAround(flat, at),
					})
				}
				offset = at + len(claimForm)
			}
		}
	}
	return census, findings, nil
}

// negatedBefore — стоит ли в окне ПЕРЕД оборотом отрицание.
func negatedBefore(lower string, at int) bool {
	from := at - negationWindow
	if from < 0 {
		from = 0
	}
	window := " " + lower[from:at]
	for _, n := range negations {
		if strings.Contains(window, n) {
			return true
		}
	}
	return false
}

// lineOfClaim — строка, с которой начинается группа комментария: она и есть
// координата, по которой правят.
func lineOfClaim(fset *token.FileSet, group *ast.CommentGroup) int {
	return fset.Position(group.Pos()).Line
}

func excerptAround(flat string, at int) string {
	from := at - 48
	if from < 0 {
		from = 0
	}
	to := at + len(claimForm) + 24
	if to > len(flat) {
		to = len(flat)
	}
	return "…" + flat[from:to] + "…"
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func inSkippedDir(rel string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if _, skip := skippedDirs[seg]; skip {
			return true
		}
	}
	return false
}

// lockAcquireCalls — сколько раз файл ЗОВЁТ захват advisory-блокировки привязки.
// Считается по узлу вызова, а не по слову: имя стоит и в комментариях, и в
// объявлении порта, и текстовый счёт дал бы блокировку там, где её нет.
func lockAcquireCalls(path string) (int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return 0, err
	}
	n := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if strings.HasPrefix(sel.Sel.Name, "AcquireBindingLock") {
			n++
		}
		return true
	})
	return n, nil
}

// TestForwardPathCommentsDoNotClaimALockItDoesNotTake — гейт.
func TestForwardPathCommentsDoNotClaimALockItDoesNotTake(t *testing.T) {
	// ── ПРЕДПОСЫЛКА ─────────────────────────────────────────────────────────
	forwardLocks, err := lockAcquireCalls(filepath.Join(serviceRoot, forwardFile))
	require.NoErrorf(t, err, "файл форварда (%s) не разобран — предпосылка не установлена", forwardFile)
	fullLocks, err := lockAcquireCalls(filepath.Join(serviceRoot, fullPathFile))
	require.NoErrorf(t, err, "файл полного прохода (%s) не разобран — предпосылка не установлена", fullPathFile)

	t.Logf("предпосылка: захватов блокировки привязки у форварда %d, у полного прохода %d",
		forwardLocks, fullLocks)

	require.NotZerof(t, fullLocks,
		"положительный контроль провален: у полного прохода (%s) не найдено НИ ОДНОГО захвата "+
			"блокировки, хотя он её берёт — значит распознаватель сломан, и «ноль у форварда» "+
			"ничего не доказывает", fullPathFile)
	require.Zerof(t, forwardLocks,
		"ПРЕДПОСЫЛКА ИЗМЕНИЛАСЬ: форвард (%s) снова берёт блокировку привязки (%d захвата). "+
			"Тогда утверждения комментариев могут быть ВЕРНЫМИ, и эту проверку надо переписать "+
			"под новый факт, а не чинить дерево под неё", forwardFile, forwardLocks)

	// ── ОБХОД ───────────────────────────────────────────────────────────────
	tree, treeErr := treecorpus.NewTree(serviceRoot)
	require.NoErrorf(t, treeErr,
		"состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен", serviceRoot)

	census, findings, err := scanLockClaims(tree)
	require.NoError(t, err, "разбор дерева не завершён — вердикт беспредметен")

	t.Logf("перепись: файлов Go разобрано %d · групп комментариев прочитано %d · "+
		"упоминаний advisory %d · утверждений о SHARE-блокировке %d · отрицаний той же формы %d",
		census.filesParsed, census.commentGroups, census.advisoryMentions,
		census.claims, census.denials)

	// Пустой обход — находка, а не идеал.
	require.NotZero(t, census.filesParsed, "обход пуст: файлов Go не разобрано ни одного")
	require.NotZero(t, census.commentGroups, "обход пуст: групп комментариев не прочитано ни одной")
	require.NotZerof(t, census.advisoryMentions,
		"обход пуст по ПРЕДМЕТУ: слово advisory не встретилось в комментариях ни разу — "+
			"либо распознаватель не читает комментарии, либо предмет ушёл из дерева")

	for _, f := range findings {
		t.Errorf("%s:%d — комментарий приписывает форварду SHARE-блокировку, которой он НЕ БЕРЁТ: %s\n"+
			"  Реализация: %s, раздел «LOCK CHOICE». Законная форма — назвать факт "+
			"(«holds NO advisory lock at all») либо объяснить ИСТОРИЮ снятой блокировки.",
			f.file, f.line, f.excerpt, forwardFile)
	}
}
