// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// constraint_liveness_test.go — гейт класса: ОТОБРАЖЕНИЕ ОТКАЗА НЕ ПЕРЕЖИВАЕТ
// СВОЙ ПРЕДМЕТ.
//
// ПРЕДМЕТ. `pgmaperr.go` переводит имя нарушенного ограничения в текст, который
// читает арендатор. Имя ограничения — факт СХЕМЫ, а не кода: его заводит
// миграция и снимает миграция. Когда ограничение снято, ветвь отображения
// остаётся — и остаётся молча: она не краснеет, потому что вход, на котором она
// срабатывает, перестал быть представимым (`testing.md` §«Гейт на класс», п.9 —
// негативное утверждение замолкает).
//
// Цена измерена, а не предположена. Ветвь `access_binding_conditions_condition_fk`
// пережила снятие своего предмета: миграция `0075_retire_tenant_condition_surface`
// сносит обе таблицы (`access_binding_conditions`, `conditions`) вместе с внешним
// ключом, заведённым `0048`, а отображение продолжало обещать арендатору два
// текста про ресурс `Condition` — компонент, снятый с продукта ЦЕЛИКОМ. Клиент
// шёл искать настройку того, чего в продукте нет.
//
// # Судится ДЕЙСТВУЮЩАЯ схема, а не текст миграций (kaname#278)
//
// Прежняя редакция применяла Up-половины регулярными выражениями и знала только
// явное снятие — по имени, сносом таблицы, сносом триггера. `DROP COLUMN` она не
// знала вовсе, а сервер этим оператором уносит все индексы и ключи, в которые
// колонка входит, не называя их ни одной строкой. Инъекция А задачи (снятие
// `users.account_id`, как его готовит kacho#1351) унесла индекс
// `users_account_email_unique`, названный ветвью, — и прежний гейт остался
// зелёным. Теперь цепочка накатывается на настоящую базу, и живость читается из
// каталога (`live_schema_test.go`): снятие любого вида решает сервер.
//
// ЧТО ГЕЙТ СУДИТ И ЧЕГО НЕ СУДИТ (граница названа, чтобы «ноль находок» не
// читалось шире сделанного):
//
//   - судит: имена, по которым `pgmaperr.go` выбирает текст, прочитанные
//     РАЗБОРОМ (не подстрокой: те же имена стоят в объяснениях рядом, и
//     проверка по тексту краснела бы на собственном комментарии). Законных форм
//     записи ДВЕ, и распознаватель знает обе: ветвь `case` у `switch
//     x.ConstraintName` и сравнение `x.ConstraintName == "…"` (`!=`, в любом
//     порядке операндов). Вторую прежняя редакция не читала — два имени полос
//     23000 были вне наблюдения;
//   - судит: производит ли действующая схема это имя — ограничением, уникальным
//     индексом или триггерной функцией, которую исполняет живой триггер;
//   - ПРЕДПОСЫЛКА распознавателя проверяется: всякое чтение `ConstraintName` в
//     файле обязано быть одной из двух форм. Чтение в третьей форме — не
//     молчание, а отказ: отображение ли это, разбор решить не может;
//   - НЕ судит: верен ли текст по существу и полон ли перечень отображённых
//     ограничений. Ограничений в схеме десятки, отображена их часть — это
//     осознанно (неразобранное получает общий текст), и предметом гейта не
//     является.
//
// ЯРУС — КОНТЕЙНЕРНЫЙ. Под `-short` гейт пропускает себя с названной причиной;
// исполняет его задание `integration` конвейера (`ci.yml`, «интеграция (Postgres
// в контейнерах)»), которое отбирает этот пакет признаком импорта `corelib/pgtest`.
//
// Способность падать и молчать доказана инъекцией настоящим сервером —
// `constraint_liveness_injection_test.go`.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// mappedNames — имена ветвей отображения и перепись разбора.
type mappedNames struct {
	names map[string]token.Position
	// reads — всех чтений `ConstraintName` в файле; bySwitch / byComparison —
	// из них опознанных как ветвь отображения.
	reads, bySwitch, byComparison int
	// unclassified — позиции ФОРМ, в которых имя ветви могло бы стоять, но
	// распознаватель прочитать его не может: чтение `ConstraintName` ни ветвью
	// switch, ни сравнением с литералом · значение `case` в switch по
	// `ConstraintName`, не являющееся строковым литералом (именованная
	// константа, склейка строк). Обе формы дают ОТКАЗ, а не молчание: имя,
	// которого разбор не видит, — слепая зона, а не отсутствие предмета.
	unclassified []string
}

func isConstraintNameRead(e ast.Expr) (*ast.SelectorExpr, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "ConstraintName" {
		return nil, false
	}
	return sel, true
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

// mappedConstraintNamesIn — ЧИСТЫЙ разбор одного файла: имена ветвей и перепись.
func mappedConstraintNamesIn(fset *token.FileSet, f *ast.File) mappedNames {
	out := mappedNames{names: map[string]token.Position{}}
	consumed := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SwitchStmt:
			sel, ok := isConstraintNameRead(x.Tag)
			if !ok {
				return true
			}
			consumed[sel] = true
			out.bySwitch++
			for _, stmt := range x.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				// cc.List пуст у `default:` — законно, пропускается. Непустое
				// значение `case`, не являющееся строковым литералом, — форма,
				// которую разбор не читает: за именованной константой либо
				// склейкой строк может стоять имя снятого ограничения, и молча
				// пропустить его значило бы вернуть ровно ту слепоту, которую
				// закрывает симметричная ветвь сравнения ниже.
				for _, e := range cc.List {
					if v, ok := stringLiteral(e); ok {
						out.names[v] = fset.Position(e.Pos())
						continue
					}
					out.unclassified = append(out.unclassified, fset.Position(e.Pos()).String())
				}
			}
		case *ast.BinaryExpr:
			if x.Op != token.EQL && x.Op != token.NEQ {
				return true
			}
			sel, ok := isConstraintNameRead(x.X)
			other := x.Y
			if !ok {
				sel, ok = isConstraintNameRead(x.Y)
				other = x.X
			}
			if !ok {
				return true
			}
			if v, lit := stringLiteral(other); lit {
				consumed[sel] = true
				out.byComparison++
				out.names[v] = fset.Position(other.Pos())
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "ConstraintName" {
			return true
		}
		out.reads++
		if !consumed[sel] {
			out.unclassified = append(out.unclassified, fset.Position(sel.Pos()).String())
		}
		return true
	})
	return out
}

// mappedConstraintNames — имена, по которым `pgmaperr.go` выбирает текст отказа.
func mappedConstraintNames(t *testing.T, file string) mappedNames {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("%s не разобран: %v", file, err)
	}
	return mappedConstraintNamesIn(fset, f)
}

func TestRefusalTextNeverNamesARetiredConstraint(t *testing.T) {
	mapped := mappedConstraintNames(t, "pgmaperr.go")
	// Предпосылка разбора: обход обязан быть непустым, иначе «ноль находок»
	// неотличимо от «ноль прочитанного».
	if len(mapped.names) == 0 {
		t.Fatal("ветвей отображения ограничений прочитано 0 — разбор разошёлся с файлом")
	}
	schema := liveSchemaOfTheChain(t)

	dead := deadMappedConstraints(schema, mapped.names)

	t.Logf("перепись: %s · чтений ConstraintName %d (switch %d, сравнений %d, вне форм %d) · "+
		"отображено имён %d · потеряли предмет %d",
		schema.census(), mapped.reads, mapped.bySwitch, mapped.byComparison, len(mapped.unclassified),
		len(mapped.names), len(dead))

	if len(mapped.unclassified) > 0 {
		t.Errorf("ПРЕДПОСЫЛКА распознавателя нарушена: %d форм, где имя ветви могло бы стоять, разбор "+
			"прочитать не может (чтение ConstraintName не в ветви switch и не в сравнении с литералом, "+
			"либо значение case не строковым литералом) — отображение ли это, разбор решить не может:\n  %s\n"+
			"Научите распознаватель этой форме (с инъекцией), прежде чем судить.",
			len(mapped.unclassified), strings.Join(mapped.unclassified, "\n  "))
	}
	if len(schema.unrecognizedRaise) > 0 {
		t.Errorf("ПРЕДПОСЫЛКА чтения схемы нарушена: у функций %s слот CONSTRAINT = несёт не "+
			"литерал — поднимаемое имя каталогом не читается, и его живость не судится",
			strings.Join(schema.unrecognizedRaise, ", "))
	}
	if len(dead) > 0 {
		t.Fatalf("отображение отказа пережило свой предмет — %d ветвей называют имя, которого "+
			"действующая схема не производит:\n  %s\n"+
			"Исходов два: снять ветвь вместе с предметом либо вернуть предмет в схему. Оставить как есть — нельзя: "+
			"ветвь не покраснеет никогда, а текст, который она обещает, называет арендатору снятое.",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// deadMappedConstraints — ЧИСТЫЙ предикат гейта: какие из отображённых имён
// действующая схема не производит. Выделен затем, чтобы способность гейта
// падать и молчать доказывалась синтетическим входом, а не наличием дефекта в
// дереве: проба, опирающаяся на живую находку, исчезает вместе с нею — ровно
// тогда, когда находка правильно закрыта.
func deadMappedConstraints(s liveSchema, mapped map[string]token.Position) []string {
	var dead []string
	for name, pos := range mapped {
		if s.producesName(name) {
			continue
		}
		dead = append(dead, name+" ("+pos.String()+") — "+s.absenceOf(name))
	}
	sort.Strings(dead)
	return dead
}
