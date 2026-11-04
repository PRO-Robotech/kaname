// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// ЗДЕСЬ СТОЯЛ СТРАЖ KEEPALIVE НА МЕЖСЛУЖЕБНОМ ДОЗВОНЕ — его предмет исчез вместе
// с последним дозвоном (задача kacho#1024).
//
// Он требовал keepalive от каждого `grpc.NewClient`/`grpc.Dial` В ЭТОМ ПАКЕТЕ и
// падал, не найдя ни одного: «страж потерял цель». Так и вышло — толчок к краю был
// последним исходящим вызовом владельца прав. Оставить страж значило оставить
// проверку, которая краснеет на исправном дереве; удалить молча — потерять место,
// где о дозвонах iam вообще идёт речь.
//
// Поэтому предмет ЗАМЕНЁН, а не снят: гейт ниже утверждает более сильное свойство
// того же дерева, и оно и есть то, ради чего толчок снимали.

// generatedStubDir — каталог ПОРОЖДЁННЫХ заглушек контрактов службы, появившийся
// в этом дереве вместе с контрактами (решение владельца 2026-09-13, kacho#2616).
//
// ПОЧЕМУ ОН ИСКЛЮЧЁН ИЗ ОСИ ДОЗВОНА, И ПОЧЕМУ ЭТО НЕ ОСЛАБЛЕНИЕ.
//
// Транскодер REST порождает у каждой службы функцию `Register…HandlerFromEndpoint`,
// и внутри неё стоит `grpc.NewClient`. Адрес ей передаёт ВЫЗЫВАЮЩИЙ: сама заглушка
// не выбирает, куда звонить, и ребра графа не заводит — она предлагает форму.
// В этом дереве вызывающий один — собственный фронт REST службы
// (`internal/restfront`), и он направляет транскодер на СВОЙ же gRPC-слушатель.
// Внутрипроцессная петля ребром графа рёбер не является: ребро описывает, кто из
// служб зовёт кого на пути запроса.
//
// Свойство «вызывающий только один и только такой» здесь НЕ подразумевается — оно
// проверяется осью ниже: обращение к `…HandlerFromEndpoint` вне фронта REST есть
// находка. Без этой оси исключение было бы маской: новый исходящий дозвон,
// сделанный через порождённый помощник, прошёл бы молча.
//
// Прежде этой полосы не требовалось, и вот почему: заглушки лежали в модуле
// платформы, то есть ВНЕ корня обхода, — «дозвонов ноль» было свойством поставки,
// а не дерева. Переезд контрактов сделал прежнее умолчание видимым.
const generatedStubDir = "pkg/api/"

// restFrontDir — единственное место, откуда законно зовётся порождённый
// транскодер: фронт REST самой службы. Перечень обязан истекать сам — обращение
// без предмета роняет ось вместе с настоящей находкой.
const restFrontDir = "internal/restfront/"

// endpointRegistrar — обращение к порождённому транскодеру, открывающему
// соединение по переданному адресу.
var endpointRegistrar = regexp.MustCompile(`HandlerFromEndpoint\b`)

// TestIamIsALeafAndCallsNobodyByGRPC — владелец прав НЕ дозванивается ни до кого.
//
// # Предмет
//
// iam объявлен ЛИСТОМ графа рёбер: его зовут, он не зовёт никого. До снятия толчка
// к краю это было объявлением — в дереве жил ровно один исходящий вызов, и он вёл
// к потребителю, то есть замыкал граф. Теперь это свойство ПОСТРОЕНИЯ, и гейт
// держит его вперёд: следующий исходящий дозвон обязан быть решением, а не
// побочным следствием чужой правки.
//
// # Что судится, а что нет
//
// Судится gRPC. HTTP к службе личности НЕ судится и судиться не может: iam —
// единственный фасад к ней, вызовы идут ВНУТРИ фасада и листом его не отменяют.
// Граница названа здесь, чтобы следующий не «починил» гейт в запрет всякого
// исходящего запроса.
//
// # Что делать, если гейт покраснел
//
// Не снимать его. Появившийся дозвон означает НОВОЕ РЕБРО, и оно обязано быть
// записано в перечне рёбер рантайма вместе с проверкой ацикличности: если A зовёт
// B, то B не зовёт A. Гейт — место, где этот разговор начинается.
func TestIamIsALeafAndCallsNobodyByGRPC(t *testing.T) {
	root := iamServiceRoot(t)

	// Перечень файлов берётся у ИНДЕКСА git, а не обходом диска. Под корнем лежат
	// каталоги, которых в репозитории нет — рабочие копии соседних сессий, отчёты
	// прогонов, сборочные выходы, — и обход по диску сделал бы вердикт свойством
	// ЧУЖОГО рабочего каталога, а не коммита. Ошибка при этом двусторонняя: красное
	// на файле, которого в репозитории нет, и молчание в свежем клоне там, где гейт
	// обязан говорить.
	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("перечень файлов владельца прав: %v", err)
	}

	reached, err := productionImportClosure(root, files, "cmd/kaname")
	if err != nil {
		t.Fatalf("замыкание импортов production: %v", err)
	}

	var (
		filesRead      int
		unreachedFiles int
		stubFiles      int
		stubDials      int
		dials          []string
		outsideFront   []string
		frontCallSite  int
	)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		// Недостижимый production пакет не входит в сервер; reachable operator code
		// проверяется наравне с остальными, независимо от каталога.
		if !reached[filepath.Clean(path)] {
			unreachedFiles++
			continue
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			t.Fatalf("путь %s не приведён к корню %s: %v", path, root, relErr)
		}
		rel = filepath.ToSlash(rel)
		generated := strings.HasPrefix(rel, generatedStubDir)
		if generated {
			stubFiles++
		}
		filesRead++
		b, rerr := os.ReadFile(path) // #nosec G304 -- путь производится индексом git
		if rerr != nil {
			t.Fatalf("чтение %s: %v", path, rerr)
		}
		lines, err := grpcAliasDials(path, b)
		if err != nil {
			t.Fatalf("дозвоны %s: %v", path, err)
		}
		for _, line := range lines {
			if generated {
				stubDials++
			} else {
				dials = append(dials, rel+":"+itoa(line))
			}
		}
		for i, line := range strings.Split(string(b), "\n") {
			// Комментарий не является дозвоном: разбор этого места уже написан
			// прозой и не должен ронять собственный гейт.
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if endpointRegistrar.MatchString(code) && !generated {
				switch {
				case strings.HasPrefix(rel, restFrontDir):
					frontCallSite++
				default:
					outsideFront = append(outsideFront, rel+":"+itoa(i+1))
				}
			}
		}
	}

	// Премиса: прочитано то, что заведомо есть. Без неё «ноль дозвонов» было бы
	// достижимо пустым обходом, то есть неотличимо от «ноль прочитанного».
	if filesRead == 0 {
		t.Fatalf("прочитано файлов %d — обход пуст, вердикт беспредметен", filesRead)
	}
	// Перепись называет ОБЕ величины: одно число скрыло бы ровно тот случай, ради
	// которого гейт заведён, — «дозвонов ноль» стало бы неотличимо от «весь дозвон
	// уехал под исключение».
	t.Logf("перепись: файлов серверного процесса прочитано %d · дозвонов %d · "+
		"недостижимых production файлов %d · файлов порождённых заглушек %d "+
		"(дозвонов транскодера в них %d) · обращений к транскодеру во фронте REST %d · "+
		"вне фронта %d",
		filesRead, len(dials), unreachedFiles, stubFiles, stubDials, frontCallSite, len(outsideFront))

	// Самоистечение полосы заглушек: исключению обязано быть что исключать.
	// Заглушки уехали из дерева — полоса уходит тем же изменением, иначе она
	// переживёт свой предмет и начнёт прятать настоящий дозвон.
	if stubFiles == 0 {
		t.Fatalf("полоса порождённых заглушек (%s) не исключила НИ ОДНОГО файла: её предмет "+
			"исчез. Снимите полосу тем же изменением, которым сняли заглушки из дерева",
			generatedStubDir)
	}
	if stubDials == 0 {
		t.Fatalf("в порождённых заглушках (%d файлов) не найдено ни одного дозвона транскодера: "+
			"либо транскодер больше не порождается, либо его форма сменилась — и тогда полоса "+
			"исключает не то, что называет", stubFiles)
	}
	// Ось вызывающего: порождённый транскодер зовётся ТОЛЬКО фронтом REST службы.
	// Она и делает полосу выше послаблением с предметом, а не маской на каталог.
	if frontCallSite == 0 {
		t.Fatalf("обращений к транскодеру во фронте REST (%s) не найдено ни одного: ось "+
			"вызывающего беспредметна, и полоса заглушек перестала быть проверяемой",
			restFrontDir)
	}
	if len(outsideFront) > 0 {
		t.Fatalf("порождённый транскодер зовётся ВНЕ фронта REST — %d место(а): %s\n\n"+
			"Внутри транскодера стоит `grpc.NewClient` по переданному адресу. Во фронте REST "+
			"этот адрес — собственный слушатель службы, то есть внутрипроцессная петля. "+
			"Обращение из другого места означает дозвон по ЧУЖОМУ адресу, то есть НОВОЕ РЕБРО "+
			"графа, и оно обязано быть записано в перечень рёбер рантайма вместе с проверкой "+
			"ацикличности.", len(outsideFront), strings.Join(outsideFront, ", "))
	}

	if len(dials) > 0 {
		t.Fatalf("владелец прав дозванивается наружу — %d место(а): %s\n\n"+
			"iam объявлен листом графа рёбер. Исходящий вызов — НОВОЕ РЕБРО: его надо "+
			"записать в перечень рёбер рантайма и проверить ацикличность (если A зовёт B, "+
			"то B не зовёт A). Соединение к владельцу открывает ПОТРЕБИТЕЛЬ, а не наоборот.",
			len(dials), strings.Join(dials, ", "))
	}
}

// iamServiceRoot — корень дерева владельца прав, найденный от рабочего каталога
// пакета вверх до `go.mod`. Путь не выписывается: выписанный, он разошёлся бы с
// деревом при первом переезде и молча начал бы обходить пустоту.
func iamServiceRoot(t *testing.T) string {
	t.Helper()
	// Корень СВОЕГО модуля, приведённый к посадке. Прежде он собирался подъёмом
	// до САМОГО ВНЕШНЕГО `go.mod` с приписыванием `services/iam` — форма, верная
	// ровно для монорепо: в самостоятельном клоне самый внешний `go.mod` есть
	// корень клона, и приписанный подкаталог не существует.
	return platformtree.RequirePath(t, "services/iam")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// productionImportClosure охватывает все tracked non-test варианты build tags:
// это консервативное объединение поддерживаемых сборок, без исключений по имени.
// Неразрешённый локальный импорт, повреждённый файл и пустой root — ошибки.
func productionImportClosure(root string, paths []string, entry string) (map[string]bool, error) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	var module string
	for _, line := range strings.Split(string(mod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			module = fields[1]
		}
	}
	if module == "" {
		return nil, fmt.Errorf("нет module в go.mod")
	}
	byDir := map[string][]string{}
	imports := map[string][]string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("разбор %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		dir := filepath.ToSlash(rel)
		byDir[dir] = append(byDir[dir], filepath.Clean(path))
		for _, imp := range file.Imports {
			name, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if name == module || strings.HasPrefix(name, module+"/") {
				dep := strings.TrimPrefix(strings.TrimPrefix(name, module), "/")
				if dep == "" {
					dep = "."
				}
				imports[dir] = append(imports[dir], dep)
			}
		}
	}
	seen := map[string]bool{}
	reached := map[string]bool{}
	var visit func(string) error
	visit = func(dir string) error {
		if seen[dir] {
			return nil
		}
		if len(byDir[dir]) == 0 {
			return fmt.Errorf("локальный пакет %s не разрешён в tracked корпусе", dir)
		}
		seen[dir] = true
		for _, path := range byDir[dir] {
			reached[path] = true
		}
		for _, dep := range imports[dir] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(entry); err != nil {
		return nil, err
	}
	return reached, nil
}

// grpcAliasDials судит import identity: переименование grpc не скрывает дозвон.
func grpcAliasDials(path string, src []byte) ([]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	aliases := map[string]bool{}
	for _, imp := range file.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		if name != "google.golang.org/grpc" {
			continue
		}
		alias := "grpc"
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == "." {
			return nil, fmt.Errorf("dot import grpc не позволяет доказать отсутствие дозвона")
		}
		aliases[alias] = true
	}
	var lines []int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if ok && aliases[id.Name] && (sel.Sel.Name == "NewClient" || sel.Sel.Name == "Dial" || sel.Sel.Name == "DialContext") {
			lines = append(lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines, nil
}
