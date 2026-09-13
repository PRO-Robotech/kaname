// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// delivered_package_edge.go — РЕБРО ИЗ ПОСТАВЛЯЕМОГО ПАКЕТА ВО ВНУТРЕННИЙ
// ОБЪЯВЛЯЕТСЯ, а не заводится молча (kaname#48).
//
// # Предмет
//
// `pkg/` — то, что импортирует ЧУЖОЙ модуль: край платформы берёт отсюда
// читателя журнала смены субъекта. `internal/` — то, что не поставляется как
// API: язык Go отвергает его прямой импорт снаружи. Ребро между ними законно —
// импортирующий код лежит внутри модуля, — и именно поэтому оно заводится
// НЕЗАМЕТНО: ни сборка, ни `go vet` о нём не скажут, а внешний потребитель
// получит зависимость, которой не может ни настроить, ни подменить.
//
// # Почему ведомость, а не запрет
//
// Запретить ребро целиком нельзя: имя продукта в теле отказа живёт в
// `internal/` НАМЕРЕННО (поставкой оно не является), а полоса отказа живёт в
// `pkg/`, потому что её читает край. Одно из двух пришлось бы переносить —
// и перенос был бы хуже ребра. Поэтому ребро объявляется поимённо, с причиной
// и предикатом снятия.
//
// # Ведомость самоистекает
//
// Запись, которой больше нечего объявлять, — находка: она унаследует следующее
// ребро, заведённое молча. Ровно то же требование, что у ведомости домена
// отказа (`internal/refusaldomain`), и оно здесь не ослаблено.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Ребро, заведённое ТРАНЗИТИВНО: `pkg/a` → `pkg/b` → `internal/c`. Прямых рёбер
// в дереве считанные единицы, и каждое объявлено; транзитивное потребовало бы
// графа импортов пакета, а не разбора файла. Появится второй уровень — предикат
// обязан расшириться до графа, и это отдельное изменение, а не молчаливое
// сужение.
package supplyhygiene

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ModulePath — путь модуля службы.
const ModulePath = "github.com/PRO-Robotech/kaname"

// DeliveredDir — каталог поставляемых пакетов относительно корня дерева.
const DeliveredDir = "pkg"

// InternalPrefix — приставка импорта, который наружу не поставляется.
const InternalPrefix = ModulePath + "/internal/"

// DeliveredEdge — одно ребро «поставляемый пакет → внутренний».
type DeliveredEdge struct {
	// From — путь файла относительно корня дерева.
	From string
	// To — импортируемый внутренний пакет, полным путём.
	To string
}

// DeclaredEdge — объявленное ребро вместе с причиной и предикатом снятия.
type DeclaredEdge struct {
	// FromPkg — каталог поставляемого пакета относительно корня дерева.
	FromPkg string
	// To — внутренний пакет, полным путём.
	To string
	// Why — почему ребро заведено.
	Why string
	// Until — наблюдаемое условие, при котором записи здесь больше не место.
	Until string
}

// DeliveredEdgeScan — что увидел обход.
type DeliveredEdgeScan struct {
	// Files — не-тестовых файлов Go разобрано.
	Files int
	// Imports — импортов всего.
	Imports int
	// Edges — рёбра в `internal/`, по возрастанию.
	Edges []DeliveredEdge
}

// ScanDeliveredEdges обходит каталог поставляемых пакетов.
//
// Вынесен отдельно от гейта затем, чтобы инъекция гоняла ТУ ЖЕ функцию на
// синтетическом дереве.
func ScanDeliveredEdges(root string) (DeliveredEdgeScan, error) {
	var out DeliveredEdgeScan
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil
		}
		out.Files++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for _, imp := range file.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			out.Imports++
			if strings.HasPrefix(p, InternalPrefix) {
				out.Edges = append(out.Edges, DeliveredEdge{From: filepath.ToSlash(rel), To: p})
			}
		}
		return nil
	})
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].From != out.Edges[j].From {
			return out.Edges[i].From < out.Edges[j].From
		}
		return out.Edges[i].To < out.Edges[j].To
	})
	return out, err
}

// EdgeIsDeclared — покрыто ли ребро объявленной записью.
//
// Запись покрывает ПАКЕТ, а не файл: пакет есть единица импорта, и требовать
// перечисления файлов значило бы заводить находку при всяком разбиении файла.
func EdgeIsDeclared(e DeliveredEdge, declared []DeclaredEdge) (DeclaredEdge, bool) {
	dir := filepath.ToSlash(filepath.Dir(e.From))
	for _, d := range declared {
		if d.FromPkg == dir && d.To == e.To {
			return d, true
		}
	}
	return DeclaredEdge{}, false
}
