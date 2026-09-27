// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// interactive_client_secret_material_writer_test.go — ГЕЙТ G приёмки
// confidential-interactive-client-secret-shown-once (IC-SECRET-03, Р5; задача
// PRO-Robotech/kaname#405): проверочное значение секрета интерактивного
// клиента и момент его установки кладёт ТОТ ЖЕ оператор вставки, что строку
// клиента, и второго писателя материала в пакете нет.
//
// # Почему гейт, а не проба на базе
//
// Одноместность записи изнутри транзакции не видна, а схема строку со способом
// секретом без материала ПРИНИМАЕТ — обратной связи «способ секретом ⟹ материал
// в строке» у неё нет намеренно (клиент внешнего поставщика). Второй писатель —
// отдельный `UPDATE … SET secret_verifier = …` после вставки — открыл бы окно
// «клиент со способом секретом есть, предъявить нечего», а при сбое между двумя
// операторами — клиента, которого нельзя доказать никогда. Проба на базе такой
// дефект видит только на сбое между операторами, то есть не видит.
//
// # Что опознаётся — по узлу разбора, не по слову
//
// Строковое значение Go (литерал, склейка литералов и объявлений пакета,
// локальная константа) судится как SQL: оператор, ПИШУЩИЙ таблицу реестра
// клиентов — `INSERT INTO` с колонкой материала в перечне либо `UPDATE … SET`,
// присваивающий колонке материала НЕ пустую строку. Присваивание пустой строки —
// СНЯТИЕ материала (`ClearClientSecretVerifier`) — законный близнец и писателем
// не считается: оно материала не несёт. Комментарий и имя функции не судятся.
//
// # Чего гейт не видит — названо
//
//  1. пакеты, кроме этого (доступ к базе у службы живёт только здесь);
//  2. оператор, собранный во время исполнения (`fmt.Sprintf`, `strings.Join`);
//  3. запись в схеме (триггер) — не Go.
//
// # Перепись печатается всегда
//
// «файлов N · функций M · строковых значений SQL K · писателей W · снятий C».
// Пустой обход (ноль прод-файлов) — не «чисто», а «не выполнилось». Обход, не
// нашедший законного писателя, — находка с названной причиной: производитель,
// которого гейт держит, обязан существовать, иначе «второго писателя нет»
// было бы верно и о пакете, где материал не пишет никто.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientMaterialWriter — единственный законный писатель материала.
const clientMaterialWriter = "InteractiveClientRepo.Insert"

// Колонки материала и момента его установки.
const (
	clientMaterialColumn = "secret_verifier"
	clientMaterialStamp  = "secret_verifier_set_at"
)

var (
	clientRegistryInsert = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+(?:"?kaname"?\s*\.\s*)?"?interactive_clients"?\s*\(([^)]*)\)`)
	clientRegistryUpdate = regexp.MustCompile(`(?is)\bUPDATE\s+(?:"?kaname"?\s*\.\s*)?"?interactive_clients"?\s+SET\s+(.*?)(?:\bWHERE\b|\bRETURNING\b|\bFROM\b|$)`)
)

// clientMaterialCensus — объём осмотренного и найденное.
type clientMaterialCensus struct {
	files, funcs, sqlValues int
	// writers — «Функция @ файл:строка» каждого писателя материала.
	writers []string
	// clears — функций, снимающих материал присваиванием пустой строки.
	clears int
	// writerStamps — пишет ли законный писатель и момент установки.
	writerStamps bool
}

func (c clientMaterialCensus) String() string {
	return fmt.Sprintf("файлов %d · функций %d · строковых значений SQL %d · писателей материала %d %v · снятий %d",
		c.files, c.funcs, c.sqlValues, len(c.writers), c.writers, c.clears)
}

func normColumn(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), `"`))
}

// sqlMaterialWrite — пишет ли значение SQL материал; снимает ли его; называет
// ли вставка момент установки.
func sqlMaterialWrite(sql string) (writes, clears, stamps bool) {
	for _, m := range clientRegistryInsert.FindAllStringSubmatch(sql, -1) {
		cols := map[string]bool{}
		for _, c := range strings.Split(m[1], ",") {
			cols[normColumn(c)] = true
		}
		if cols[clientMaterialColumn] {
			writes = true
			stamps = stamps || cols[clientMaterialStamp]
		}
	}
	for _, m := range clientRegistryUpdate.FindAllStringSubmatch(sql, -1) {
		for _, assign := range strings.Split(m[1], ",") {
			col, expr, ok := strings.Cut(assign, "=")
			if !ok || normColumn(col) != clientMaterialColumn {
				continue
			}
			switch strings.TrimSpace(expr) {
			case "''", "''::text":
				clears = true
			default:
				writes = true
			}
		}
	}
	return writes, clears, stamps
}

// auditClientMaterialWriters — перепись писателей материала по каталогу dir.
// Отказ — «не выполнилось», а не находка.
func auditClientMaterialWriters(dir string) ([]string, clientMaterialCensus, error) {
	var c clientMaterialCensus
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, c, fmt.Errorf("не выполнилось: каталог пакета не прочитан: %w", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, c, fmt.Errorf("не выполнилось: разбор %s: %w", name, perr)
		}
		files = append(files, file)
	}
	c.files = len(files)
	if c.files == 0 {
		return nil, c, fmt.Errorf("не выполнилось: прод-файлов в %s ноль — «писателей 0» значило бы «ничего не прочитано»", dir)
	}

	// Строковые объявления пакета — тем же вычислителем, что перепись путей
	// записи отсечки (`cutoffStringValue`): второй вычислитель разошёлся бы.
	declared := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						declared[id.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	values := map[string]string{}
	for changed := true; changed; {
		changed = false
		for name, expr := range declared {
			if _, done := values[name]; done {
				continue
			}
			if s, ok := cutoffStringValue(expr, values); ok {
				values[name] = s
				changed = true
			}
		}
	}

	var findings []string
	writerSeen := false
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			c.funcs++
			var sqls []string
			selected := map[*ast.Ident]struct{}{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					selected[x.Sel] = struct{}{}
				case *ast.BinaryExpr:
					if s, ok := cutoffStringValue(x, values); ok {
						sqls = append(sqls, s)
						return false
					}
				case *ast.BasicLit:
					if s, ok := cutoffStringValue(x, values); ok {
						sqls = append(sqls, s)
					}
				case *ast.Ident:
					if _, sel := selected[x]; sel {
						return true
					}
					if s, ok := values[x.Name]; ok {
						sqls = append(sqls, s)
					}
				}
				return true
			})
			c.sqlValues += len(sqls)
			var writes, clears, stamps bool
			for _, s := range sqls {
				w, cl, st := sqlMaterialWrite(s)
				writes, clears, stamps = writes || w, clears || cl, stamps || st
			}
			if clears {
				c.clears++
			}
			if !writes {
				continue
			}
			name := funcPathName(fn)
			pos := fset.Position(fn.Pos())
			coord := fmt.Sprintf("%s @ %s:%d", name, filepath.Base(pos.Filename), pos.Line)
			c.writers = append(c.writers, coord)
			if name == clientMaterialWriter {
				writerSeen = true
				c.writerStamps = stamps
				if !stamps {
					findings = append(findings, coord+": вставка кладёт материал, но не момент его установки тем же оператором")
				}
				continue
			}
			findings = append(findings, coord+": второй писатель материала секрета интерактивного клиента — "+
				"материал кладёт только вставка строки тем же оператором (Р5)")
		}
	}
	sort.Strings(c.writers)
	if !writerSeen {
		findings = append(findings, clientMaterialWriter+": вставка строки клиента материала не кладёт — "+
			"клиент со способом секретом получит строку без проверочного значения")
	}
	sort.Strings(findings)
	return findings, c, nil
}

// TestInteractiveClientSecretMaterialHasOneWriter — гейт G на дереве пакета.
func TestInteractiveClientSecretMaterialHasOneWriter(t *testing.T) {
	findings, census, err := auditClientMaterialWriters(".")
	require.NoError(t, err)
	t.Logf("перепись писателей материала: %s; находок %d", census, len(findings))
	for _, f := range findings {
		t.Error(f)
	}
}
