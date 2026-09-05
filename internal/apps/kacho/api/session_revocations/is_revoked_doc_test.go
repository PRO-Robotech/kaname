// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_doc_test.go — комментарии, рассуждающие о том, КТО зовёт полосу
// отзыва, обязаны описывать ДЕРЕВО, а не намерение.
//
// # Предмет (#1156)
//
// Шапка `IsRevoked` объявляла, что вызывающего у неё нет: «ни край, ни
// refresh-хук её не зовут». Утверждение пережило свой предмет — край получил
// читателя (#1122: `IsSessionRevoked` в клиенте края, провязанный в решение
// слоя аутентификации), а шапку не тронули.
//
// Это не косметика. Комментарий, отрицающий ЖИВОЙ контроль безопасности,
// провоцирует «починку» кода под неверный комментарий: следующий читатель вправе
// счесть полосу мёртвой и снять её (`security.md` §Hardening, п.5 «misleading
// comment про security = ловушка»).
//
// # Радиус взят по МЕХАНИЗМУ, а не по файлу, где дефект заметили
//
// То же утверждение жило ещё в двух местах — в обосновании двух послаблений
// периметра (`authzguard`), где оно значило «послаблению нечего исключать».
// Поэтому гейт судит ЗАКРЫТЫЙ НАБОР файлов, а не один: перечень ниже, и
// исчезнувший файл — находка, а не тишина.
//
// # Что утверждает гейт — две оси, каждая падает сама
//
//  1. ЧИСЛО. Ровно один файл набора называет, сколько вызывающих у метода в
//     прод-коде дерева; гейт считает их САМ и требует совпадения. Появился
//     вызывающий — утверждение обязано это признать; исчез — тоже.
//  2. КРАЙ, ПОФАЙЛОВО. Клиент края экспонирует метод чтения ⟺ КАЖДЫЙ файл
//     набора его называет. Одна сторона без другой оставляла бы ровно ту ложь,
//     ради которой гейт заведён: «у края нет метода чтения» при живом методе.
//
// # Почему разбор, а не поиск по тексту
//
// Текстовый предикат считает и упоминания в комментариях — в том числе в ЭТОЙ
// шапке, — поэтому число зависело бы от того, как написан объясняющий его абзац.
// Перепись судит по узлу вызова, а утверждения читает из комментариев; к
// идентификаторам в коде обе стороны безразличны by construction
// (`testing.md` §«Гейт на класс», п.4).

import (
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

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// isRevokedMethod — имя метода, чьих вызывающих считает перепись.
const isRevokedMethod = "IsRevoked"

// edgeReadMethod — метод чтения нашего отзыва в клиенте края. Его присутствие и
// есть предмет второй оси.
const edgeReadMethod = "IsSessionRevoked"

// edgeClientFile — файл клиента края (относительно корня монорепо).
const edgeClientFile = "gateway/internal/clients/session_revocations_client.go"

// laneFiles — ЗАКРЫТЫЙ набор прод-файлов, чьи комментарии рассуждают о том, кто
// зовёт полосу отзыва: сам хендлер и два обоснования послаблений периметра.
// Именно в них жило утверждение «вызывающего нет», и именно поэтому они судятся
// вместе: исправить одно, оставив два, значит оставить три места об одном
// предмете, из которых верно одно.
var laneFiles = []string{
	"services/iam/internal/apps/kacho/api/session_revocations/handler.go",
	"services/iam/internal/authzguard/system_viewer_floor.go",
	"services/iam/internal/authzguard/caller_policy.go",
}

// callerCountMarker — машинно-читаемая форма числа. Проза меняется, маркер —
// нет; поэтому сверять можно именно его, а не пересказ.
var callerCountMarker = regexp.MustCompile(`ВЫЗЫВАЮЩИХ В ПРОД-КОДЕ:\s*(\d+)`)

// isRevokedDocFacts — вход предиката. Собран так, чтобы предикат можно было
// прогнать инъекцией, не трогая дерево (см. is_revoked_doc_injection_test.go).
type isRevokedDocFacts struct {
	// Comments — путь файла → весь текст его комментариев.
	Comments map[string]string
	// CallerFiles — пути прод-файлов, где разбор нашёл вызов метода.
	CallerFiles []string
	// EdgeExportsRead — экспонирует ли клиент края метод чтения.
	EdgeExportsRead bool
}

// auditIsRevokedDoc — предикат обеих осей. Возвращает находки; пусто = норма.
func auditIsRevokedDoc(f isRevokedDocFacts) []string {
	var found []string

	markers := 0
	for _, path := range sortedKeys(f.Comments) {
		m := callerCountMarker.FindStringSubmatch(f.Comments[path])
		if m == nil {
			continue
		}
		markers++
		claimed, err := strconv.Atoi(m[1])
		if err != nil || claimed != len(f.CallerFiles) {
			found = append(found, path+": называет вызывающих: "+m[1]+
				"; разбор дерева нашёл "+strconv.Itoa(len(f.CallerFiles))+
				" — "+strings.Join(f.CallerFiles, ", "))
		}
	}
	if markers != 1 {
		found = append(found, "маркер «ВЫЗЫВАЮЩИХ В ПРОД-КОДЕ: <N>» встречается "+
			strconv.Itoa(markers)+" раз(а), а обязан ровно один: ноль означает, что "+
			"сверять с деревом нечего, больше одного — два места об одном числе")
	}

	for _, path := range sortedKeys(f.Comments) {
		mentions := strings.Contains(f.Comments[path], edgeReadMethod)
		switch {
		case f.EdgeExportsRead && !mentions:
			found = append(found, path+": клиент края экспонирует "+edgeReadMethod+
				", а комментарий его не называет — он описывает полосу как не имеющую "+
				"читателя на пути запроса, тогда как читатель есть и решает вопрос доступа")
		case !f.EdgeExportsRead && mentions:
			found = append(found, path+": комментарий называет "+edgeReadMethod+
				", которого клиент края больше не экспонирует — утверждение пережило свой предмет")
		}
	}

	return found
}

// TestIsRevokedDocDescribesTheTree — гейт на дереве.
func TestIsRevokedDocDescribesTheTree(t *testing.T) {
	root := monorepoRootForDoc(t)

	callers, filesScanned, filesParsed := isRevokedCallSites(t, root, true)
	edge := fileDeclaresMethod(t, filepath.Join(root, edgeClientFile), edgeReadMethod)
	comments := laneComments(t, root)

	// ПРЕДПОСЫЛКИ. «Ноль находок» обязано быть отличимо от «ноль прочитанного»:
	// пустой корпус или непрочитанные комментарии дали бы зелёное на любом дереве.
	require.Positive(t, filesScanned,
		"не осмотрено ни одного прод-файла Go — предпосылка переписи сломана")
	require.NotEmpty(t, callers,
		"разбор не нашёл НИ ОДНОГО вызова %s — предикат меряет не то, и всякое "+
			"утверждение о числе вызывающих было бы вакуумным", isRevokedMethod)
	require.Lenf(t, comments, len(laneFiles),
		"прочитано %d файлов набора из %d — предпосылка сломана", len(comments), len(laneFiles))
	for path, text := range comments {
		require.NotEmptyf(t, text, "%s: комментариев не прочитано ни одного", path)
	}

	found := auditIsRevokedDoc(isRevokedDocFacts{
		Comments: comments, CallerFiles: callers, EdgeExportsRead: edge,
	})
	require.Emptyf(t, found,
		"утверждения о полосе отзыва расходятся с деревом:\n  %s\n"+
			"Комментарий обязан отражать РЕАЛЬНОСТЬ, а не намерение: отрицая живой "+
			"контроль безопасности, он провоцирует снятие полосы как мёртвой.",
		strings.Join(found, "\n  "))

	t.Logf("перепись: прод-файлов Go осмотрено %d, разобрано %d; вызывающих %s: %d (%s); "+
		"файлов набора: %d; клиент края экспонирует %s: %t",
		filesScanned, filesParsed, isRevokedMethod, len(callers), strings.Join(callers, ", "),
		len(comments), edgeReadMethod, edge)
}

// isRevokedCallSites — пути файлов, в которых РАЗБОР нашёл вызов метода.
//
// `prodOnly` исключает пробы (они не образуют вызывающего на пути запроса) и
// сгенерённые стабы `pkg/api/` (там метод перевызывается транспортом, а не
// спрашивается по существу). Флаг — параметр, а не константа, потому что
// НЕВЫРОЖДЕННОСТЬ самого исключения обязана быть проверена: перепись без
// фильтра стоит рядом в инъекции и обязана быть СТРОГО шире.
func isRevokedCallSites(t *testing.T, root string, prodOnly bool) (callers []string, scanned, parsed int) {
	t.Helper()
	files, err := treecorpus.UnderWithSuffix(root, ".go")
	require.NoError(t, err, "индекс отслеживаемых файлов Go")

	genPrefix := filepath.Join(root, "pkg", "api") + string(filepath.Separator)
	fset := token.NewFileSet()
	for _, path := range files {
		if prodOnly && (strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, genPrefix)) {
			continue
		}
		scanned++
		body, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		// Дешёвый отсев: разбирается только то, где имя вообще встречается.
		if !strings.Contains(string(body), isRevokedMethod) {
			continue
		}
		parsed++
		f, perr := parser.ParseFile(fset, path, body, 0)
		require.NoErrorf(t, perr, "разбор %s", path)
		hit := false
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok && sel.Sel != nil && sel.Sel.Name == isRevokedMethod {
				hit = true
			}
			return true
		})
		if hit {
			rel, rerr := filepath.Rel(root, path)
			require.NoError(t, rerr)
			callers = append(callers, filepath.ToSlash(rel))
		}
	}
	sort.Strings(callers)
	return callers, scanned, parsed
}

// fileDeclaresMethod — объявляет ли файл метод с этим именем (получатель любой).
func fileDeclaresMethod(t *testing.T, path, name string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoErrorf(t, err, "разбор клиента края %s: без него вторая ось гейта "+
		"молчала бы, не проверив ничего", path)
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv != nil && fn.Name != nil && fn.Name.Name == name {
			return true
		}
	}
	return false
}

// laneComments — текст ВСЕХ комментариев каждого файла набора.
//
// Именно комментариев, а не файла целиком: иначе идентификатор в коде зачёлся бы
// за утверждение, и гейт судил бы имя переменной вместо прозы.
func laneComments(t *testing.T, root string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(laneFiles))
	fset := token.NewFileSet()
	for _, rel := range laneFiles {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		_, serr := os.Stat(abs)
		require.NoErrorf(t, serr, "файл набора %q не найден: набор пережил своё дерево, "+
			"и гейт молча перестал бы судить это место", rel)
		f, perr := parser.ParseFile(fset, abs, nil, parser.ParseComments)
		require.NoErrorf(t, perr, "разбор %s", rel)
		var sb strings.Builder
		for _, g := range f.Comments {
			sb.WriteString(g.Text())
			sb.WriteString("\n")
		}
		out[rel] = sb.String()
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func monorepoRootForDoc(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}
