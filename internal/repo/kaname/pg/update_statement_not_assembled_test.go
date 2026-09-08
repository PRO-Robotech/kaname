// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// update_statement_not_assembled_test.go — набор обновляемых колонок известен
// КОМПИЛЯТОРУ, а не вычисляется в рантайме (задача продукта #2058).
//
// # Предмет — не безопасность запроса, а проверяемость набора колонок
//
// Значения здесь всегда связывались параметрами, поэтому подстановки значений в
// запрос не было и нет. Неверно другое: список `SET` собирался из маски
// форматированием строки, то есть **какие колонки пишет оператор** решалось во
// время исполнения и не проверялось ни типами, ни компилятором. Это размывает
// границу CQRS — писатель обязан выставлять конкретные поля, а не собирать текст
// запроса (`evgeniy` §13).
//
// Цена не теоретическая: ошибка в собранном фрагменте не видна ни сборке, ни
// обзору диффа, а видна только прогону, дошедшему до этой ветви маски. Соседний
// оператор того же хранилища уже был неисполним при ЛЮБОМ входе из-за колонки,
// которой не было в схеме, — и заметили это не типы, а падение.
//
// # Единица счёта — и почему она УЖЕ, чем «форматируется оператор UPDATE»
//
// Единица: вызов `fmt.Sprintf`, чей первый аргумент — литерал оператора
// `UPDATE`, и подстановка стоит МЕЖДУ `SET` и `WHERE`. То есть форматированием
// рождается сам СПИСОК присваиваний.
//
// Широкая единица («литерал начинается с UPDATE») здесь проверена и отвергнута
// замером: она даёт находки на коде, который иначе написать НЕЛЬЗЯ, и гейт,
// краснеющий на верном коде, отключают первым. В этом же пакете таких форм две,
// и обе законны:
//
//	имя объекта                — идентификатор параметром не связывается вовсе
//	                             (`pgx.Identifier{…}.Sanitize()` — единственный путь);
//	перечень колонок RETURNING — константа пакета, к списку SET отношения не имеет.
//
// Обе стоят кейсами инъекции ниже и обязаны МОЛЧАТЬ. Судится при этом УЗЕЛ
// разбора, а не текст: та же форма в комментарии (в том числе в этом) находкой
// не является — иначе гейт краснел бы на собственном объяснении.
//
// # Ведомость ИСТЕКЛА — и это состояние, а не заготовка
//
// Приём был продублирован по пяти ресурсам домена. Задача #2058 перевела два
// (роль, служебная учётка) и прощала остальные три ПОИМЁННО со ссылкой на
// #2065; #2065 перевела их — аккаунт, группу и проект — и сняла записи ТЕМ ЖЕ
// изменением, каким перевела ресурсы. Ведомость сегодня пуста, и это ЦЕЛЬ: гейт
// на ней проходит, объявляя переписью «прощено ведомостью 0».
//
// Ведомость самоистекает: запись, которой больше нечего прощать, — находка.
// Иначе прощение пережило бы свой предмет и унесло бы с собой полосу наблюдения.
// Отсюда обязанность следующего, кто заведёт запись: снимать её вместе с
// переводом ресурса, а не «на всякий случай».
package pg_test

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

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// assembledUpdateDebt — ресурсы, чью запись ещё не перевели. Ключ — имя файла,
// значение — задача-преемник. Пустая ведомость есть ЦЕЛЬ, а не поломка: гейт на
// ней проходит, а перепись печатает «прощено ведомостью 0» — так «прощать нечего»
// остаётся отличимым от «прощение молча сняли вместе с наблюдением».
var assembledUpdateDebt = map[string]string{}

// TestUpdateStatementIsNotAssembledAtRuntime — оператор обновления не
// собирается форматированием строки.
func TestUpdateStatementIsNotAssembledAtRuntime(t *testing.T) {
	files, err := treecorpus.UnderWithSuffix(".", ".go")
	require.NoError(t, err, "состав пакета взять неоткуда — вердикт был бы о пустоте")

	var read int
	hits := map[string][]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		read++
		fset := token.NewFileSet()
		src, perr := parser.ParseFile(fset, f, nil, parser.ParseComments)
		require.NoError(t, perr, "разбор %s", f)
		for _, pos := range assembledUpdateCalls(src) {
			base := filepath.Base(f)
			hits[base] = append(hits[base], fset.Position(pos).Line)
		}
	}

	// Предпосылка: обход непуст. «Находок ноль» на нуле прочитанных файлов —
	// это «ноль прочитанного», а не чистый пакет.
	require.NotZero(t, read, "не-тестовых файлов пакета прочитано ноль: смотреть было не на что")

	var findings, forgiven []string
	var stmtsFound, stmtsForgiven int
	for _, base := range sortedNames(hits) {
		where := base + ":" + joinLines(hits[base])
		if issue, ok := assembledUpdateDebt[base]; ok {
			forgiven = append(forgiven, where+" ("+issue+")")
			stmtsForgiven += len(hits[base])
			continue
		}
		findings = append(findings, where)
		stmtsFound += len(hits[base])
	}

	// Самоистечение: запись ведомости, которой нечего прощать, — находка.
	var stale []string
	for base := range assembledUpdateDebt {
		if _, still := hits[base]; !still {
			stale = append(stale, base)
		}
	}
	sort.Strings(stale)

	// Единица переписи — ОПЕРАТОР, а не файл: в одном файле их бывает несколько,
	// и счёт файлами занижал бы объём молча.
	t.Logf("перепись: не-тестовых файлов пакета прочитано %d · собранных операторов SET %d "+
		"(в %d файлах) · прощено ведомостью %d · находок %d",
		read, stmtsFound+stmtsForgiven, len(forgiven)+len(findings), stmtsForgiven, stmtsFound)

	require.Empty(t, stale,
		"записи ведомости больше нечего прощать: %s.\n"+
			"Прощение, пережившее свой предмет, унесло бы с собой полосу наблюдения — "+
			"снимите запись тем же изменением, каким перевели ресурс.", strings.Join(stale, ", "))

	require.Empty(t, findings,
		"оператор обновления собирается форматированием строки: %s.\n"+
			"Набор колонок вычисляется в рантайме и не проверяется ни типами, ни компилятором. "+
			"Выставляй явный набор колонок статическим оператором, а применимость поля передавай "+
			"параметром — тогда ошибка набора становится ошибкой сборки.", strings.Join(findings, ", "))
}

// TestAssembledUpdateRecognizer_ProvenByInjection — распознаватель находит
// собранный оператор и молчит на законных близнецах.
func TestAssembledUpdateRecognizer_ProvenByInjection(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
		why  string
	}{
		{
			name: "собранный список SET — находка",
			src: "package pg\nimport \"fmt\"\nfunc q(parts []string) string {\n" +
				"\treturn fmt.Sprintf(`UPDATE roles SET %s WHERE id = $1`, parts[0])\n}",
			want: 1,
			why:  "ради этой формы гейт и заведён",
		},
		{
			name: "близнец: подставлен перечень колонок RETURNING, список SET статический",
			src: "package pg\nimport \"fmt\"\nfunc q(cols string) string {\n" +
				"\treturn fmt.Sprintf(`UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s`, cols)\n}",
			want: 0,
			why: "перечень колонок к списку SET отношения не имеет; красней гейт здесь — " +
				"его отключили бы первым",
		},
		{
			name: "близнец: подставлено ИМЯ объекта",
			src: "package pg\nimport \"fmt\"\nfunc q(table string) string {\n" +
				"\treturn fmt.Sprintf(`UPDATE %s SET response_data = $2 WHERE id = $1`, table)\n}",
			want: 0,
			why: "идентификатор параметром не связывается вовсе — иначе написать нельзя, " +
				"и подстановка стоит ДО списка SET",
		},
		{
			name: "многострочный оператор со статическим SET — молчит",
			src: "package pg\nimport \"fmt\"\nfunc q(cols string) string {\n" +
				"\treturn fmt.Sprintf(`\n\t\tUPDATE access_bindings\n\t\t   SET labels = $2\n" +
				"\t\t WHERE id = $1\n\t\tRETURNING %s`, cols)\n}",
			want: 0,
			why: "ключевые слова ищутся по границе слова: SET начинает строку, а не следует за пробелом — " +
				"иначе распознаватель не увидел бы половины операторов пакета",
		},
		{
			name: "многострочный оператор со СБОРНЫМ SET — находка",
			src: "package pg\nimport \"fmt\"\nfunc q(parts, cols string) string {\n" +
				"\treturn fmt.Sprintf(`\n\t\tUPDATE accounts\n\t\t   SET %s\n" +
				"\t\t WHERE id = $1\n\t\tRETURNING %s`, parts, cols)\n}",
			want: 1,
			why:  "перенос строки не выводит оператор из-под гейта",
		},
		{
			name: "близнец: статический оператор константой",
			src: "package pg\nconst cols = \"id, name\"\n" +
				"const q = `UPDATE roles SET name = $2 WHERE id = $1 RETURNING ` + cols",
			want: 0,
			why:  "статический оператор — это и есть цель правки",
		},
		{
			name: "близнец: форматируется НЕ оператор обновления",
			src: "package pg\nimport \"fmt\"\nfunc q(cols string) string {\n" +
				"\treturn fmt.Sprintf(`SELECT %s FROM roles WHERE id = $1`, cols)\n}",
			want: 0,
			why:  "предмет гейта — список SET оператора обновления, а не всякая сборка запроса",
		},
		{
			name: "близнец: экранированный процент подстановкой не является",
			src: "package pg\nimport \"fmt\"\nfunc q(cols string) string {\n" +
				"\treturn fmt.Sprintf(`UPDATE roles SET name = '100%%' WHERE id = $1 RETURNING %s`, cols)\n}",
			want: 0,
			why:  "%% — это процент в значении, а не сборка списка",
		},
		{
			name: "близнец: форма названа в комментарии",
			src: "package pg\n// Здесь стоял fmt.Sprintf(`UPDATE roles SET %s …`) — снят.\n" +
				"const q = `UPDATE roles SET name = $2 WHERE id = $1`",
			want: 0,
			why:  "судится узел кода, а не текст — иначе гейт краснел бы на собственном объяснении",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "inject.go", tc.src, parser.ParseComments)
			require.NoError(t, err)
			require.Len(t, assembledUpdateCalls(f), tc.want, tc.why)
		})
	}
}

// assembledUpdateCalls — позиции вызовов `fmt.Sprintf`, форматированием
// рождающих СПИСОК присваиваний оператора обновления.
func assembledUpdateCalls(f *ast.File) []token.Pos {
	var out []token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sprintf" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if setListIsFormatted(v) {
			out = append(out, call.Lparen)
		}
		return true
	})
	return out
}

// formatVerb — подстановка формата. `%%` — экранированный процент, подстановкой
// не является, и потому исключён явно.
var formatVerb = regexp.MustCompile(`%[-+# 0-9.*]*[a-zA-Z]`)

// setListIsFormatted — оператор ли это обновления, и стоит ли подстановка МЕЖДУ
// `SET` и `WHERE`.
//
// Отрезок берётся от ключевого слова `SET` до ближайшего `WHERE` за ним; без
// `WHERE` — до конца литерала (оператор без условия — тоже оператор, и список у
// него тот же). Ключевые слова ищутся по ГРАНИЦЕ СЛОВА: в этом пакете операторы
// пишутся в несколько строк, и `SET` начинает строку, а не следует за пробелом.
func setListIsFormatted(sql string) bool {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "UPDATE") {
		return false
	}
	set := kwSet.FindStringIndex(sql)
	if set == nil {
		return false
	}
	rest := sql[set[1]:]
	if w := kwWhere.FindStringIndex(rest); w != nil {
		rest = rest[:w[0]]
	}
	return formatVerb.MatchString(strings.ReplaceAll(rest, "%%", ""))
}

var (
	kwSet   = regexp.MustCompile(`(?i)\bSET\b`)
	kwWhere = regexp.MustCompile(`(?i)\bWHERE\b`)
)

func sortedNames(m map[string][]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinLines(lines []int) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, strconv.Itoa(l))
	}
	return strings.Join(parts, ",")
}
