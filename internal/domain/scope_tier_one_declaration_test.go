// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_tier_one_declaration_test.go — отношение «вид якоря ↔ ярус» объявлено
// в пакете ОДИН раз (задача продукта #2057).
//
// # Предмет
//
// Отношение несли три места: перевод вида в проволочную форму, сверка яруса с
// парой (вид, идентификатор) и вывод яруса из вида. Согласованы они были
// сегодня и дрейфовали независимо: каждое перечисляло виды само.
//
// # Единица счёта — и почему она НЕ «файл, называющий ярус»
//
// Наивный предикат «в пакете названы cluster/account/project» даёт СЕГОДНЯ шесть
// не-тестовых файлов домена, и пять из них к этому отношению не относятся вовсе
// (назначаемость роли · структурные кортежи · принадлежность цели · носитель
// предела). Гейт, краснеющий на верном коде, отключают первым — поэтому единица
// сужена до пересечения двух признаков:
//
//	объявление верхнего уровня пакета, тело которого
//	  (а) называет строковым литералом ДВА и более из трёх видов якоря  И
//	  (б) называет хотя бы один идентификатор из ЗАКРЫТОГО набора яруса
//
// Набор (б) закрытый и выписан поимённо, а не по приставке `Scope`: приставка
// поймала бы `RoleScope*`, `ScopeFiltered` и прочих однофамильцев, к отношению
// не относящихся.
//
// # Законные близнецы, которые обязаны молчать
//
//	access_binding.go        — один вид (`cluster`) плюс `ScopeUnspecified`: (а) не выполнено
//	role_definition_tier.go  — проволочные формы без голых видов: (а) не выполнено
//	rule_fingerprint.go      — два яруса без голых видов: (а) не выполнено
//	structural_tuple.go      — три вида без единого имени яруса: (б) не выполнено
//
// Способность распознавателя падать и молчать доказана инъекцией на синтетике —
// `TestScopeTierRecognizer_ProvenByInjection` ниже; она подаёт и второе
// объявление (обязано считаться), и каждого из четырёх близнецов (обязан не
// считаться).
package domain_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// scopeAnchorKinds — три голых вида якоря. Перечень закрыт СХЕМОЙ (проверка
// `access_bindings_scope_ck` допускает ровно ярусы 1..3) и здесь служит входом
// распознавателя, а не вторым объявлением словаря: гейт спрашивает «сколько
// объявлений», и ему нужен признак, а не сам словарь.
var scopeAnchorKinds = []string{"cluster", "account", "project"}

// scopeTierIdents — ЗАКРЫТЫЙ набор имён яруса. Выписан поимённо намеренно: по
// приставке `Scope` распознаватель ловил бы однофамильцев.
var scopeTierIdents = map[string]bool{
	"ScopeCluster":           true,
	"ScopeAccount":           true,
	"ScopeProject":           true,
	"ScopeUnspecified":       true,
	"ScopeTypeClusterDotted": true,
	"ScopeTypeAccountDotted": true,
	"ScopeTypeProjectDotted": true,
}

// TestScopeTierRelationIsDeclaredOnce — объявлений отношения «вид ↔ ярус» в
// пакете ровно одно.
func TestScopeTierRelationIsDeclaredOnce(t *testing.T) {
	files, err := treecorpus.UnderWithSuffix(".", ".go")
	require.NoError(t, err, "состав пакета взять неоткуда — вердикт был бы о пустоте")

	var read int
	var found []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		read++
		src, rerr := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		require.NoError(t, rerr, "разбор %s", f)
		for _, name := range scopeTierDeclsIn(src) {
			found = append(found, filepath.Base(f)+":"+name)
		}
	}

	// Предпосылка: обход непуст. «Объявление одно» верно и на нуле прочитанных
	// файлов — и тогда это «ноль прочитанного», а не «ноль находок».
	require.NotZero(t, read,
		"не-тестовых файлов пакета прочитано ноль: смотреть было не на что")
	require.NotEmpty(t, found,
		"распознаватель не нашёл НИ ОДНОГО объявления отношения: словарь переехал "+
			"либо признак перестал его ловить — тогда «объявление одно» ничего не значит")

	sort.Strings(found)
	t.Logf("перепись: не-тестовых файлов пакета прочитано %d · объявлений отношения «вид ↔ ярус» %d: %s",
		read, len(found), strings.Join(found, ", "))

	require.Len(t, found, 1,
		"отношение «вид якоря ↔ ярус» объявлено %d раза: %s.\n"+
			"Перечисления согласованы сегодня и дрейфуют независимо — второе место "+
			"разойдётся с первым МОЛЧА. Объяви словарь однажды, а обратные указатели ВЫВЕДИ.",
		len(found), strings.Join(found, ", "))
}

// TestScopeTierRecognizer_ProvenByInjection — распознаватель способен и
// сосчитать второе объявление, и промолчать на законном близнеце.
//
// Инъекция идёт по синтетике, а не по дереву: дефект, внесённый в дерево,
// пришлось бы вносить и убирать, а вердикт о способности падать нужен на КАЖДОМ
// прогоне.
func TestScopeTierRecognizer_ProvenByInjection(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
		why  string
	}{
		{
			name: "единственное объявление словарём",
			src: `package domain
var vocab = map[string]Scope{"cluster": ScopeCluster, "account": ScopeAccount, "project": ScopeProject}`,
			want: 1,
			why:  "прямая карта — это и есть объявление отношения",
		},
		{
			name: "внесённое ВТОРОЕ объявление ветвлением",
			src: `package domain
var vocab = map[string]Scope{"cluster": ScopeCluster, "account": ScopeAccount, "project": ScopeProject}
func Derive(rt string) Scope {
	switch rt {
	case "cluster":
		return ScopeCluster
	case "account":
		return ScopeAccount
	case "project":
		return ScopeProject
	}
	return ScopeUnspecified
}`,
			want: 2,
			why:  "второе перечисление обязано считаться — иначе гейт вакуумный",
		},
		{
			name: "близнец: один вид плюс имя яруса",
			src: `package domain
func Validate(rt, id string, s Scope) bool {
	if rt == "cluster" && id == "" { return false }
	return s != ScopeUnspecified
}`,
			want: 0,
			why:  "один вид — это проверка вида, а не перечисление словаря",
		},
		{
			name: "близнец: проволочные формы без голых видов",
			src: `package domain
func Dotted(s Scope) string {
	switch s {
	case ScopeCluster:
		return ScopeTypeClusterDotted
	case ScopeAccount:
		return ScopeTypeAccountDotted
	}
	return ScopeTypeProjectDotted
}`,
			want: 0,
			why:  "голых видов нет — перечислять словарь тут нечем",
		},
		{
			name: "близнец: три вида без единого имени яруса",
			src: `package domain
var bindableScopes = []string{"project", "account", "cluster"}`,
			want: 0,
			why:  "перечень видов БЕЗ яруса — другое отношение, гейт его не судит",
		},
		{
			name: "близнец: виды в комментарии, а не в коде",
			src: `package domain
// Type is one of "project" | "account" | "cluster"; ярус тут ни при чём: ScopeCluster.
func Noop() {}`,
			want: 0,
			why:  "распознаватель судит узел кода, а не текст — иначе краснел бы на собственном объяснении",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "inject.go", tc.src, parser.ParseComments)
			require.NoError(t, err)
			require.Len(t, scopeTierDeclsIn(f), tc.want, tc.why)
		})
	}
}

// scopeTierDeclsIn — имена объявлений верхнего уровня, несущих отношение
// «вид якоря ↔ ярус».
//
// Судятся УЗЛЫ разбора: строковый литерал и идентификатор. Текстовый поиск
// считал бы находкой и комментарий, объясняющий сам гейт.
func scopeTierDeclsIn(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		kinds := map[string]bool{}
		tier := false
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(x.Value)
				if err != nil {
					return true
				}
				for _, k := range scopeAnchorKinds {
					if v == k {
						kinds[k] = true
					}
				}
			case *ast.Ident:
				if scopeTierIdents[x.Name] {
					tier = true
				}
			}
			return true
		})
		if len(kinds) < 2 || !tier {
			continue
		}
		out = append(out, declName(d))
	}
	return out
}

// declName — имя объявления для координаты в находке.
func declName(d ast.Decl) string {
	switch x := d.(type) {
	case *ast.FuncDecl:
		if x.Recv != nil && len(x.Recv.List) > 0 {
			return recvTypeName(x.Recv.List[0].Type) + "." + x.Name.Name
		}
		return x.Name.Name
	case *ast.GenDecl:
		var names []string
		for _, spec := range x.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, n := range s.Names {
					names = append(names, n.Name)
				}
			case *ast.TypeSpec:
				names = append(names, s.Name.Name)
			}
		}
		if len(names) > 0 {
			return strings.Join(names, "+")
		}
	}
	return "<безымянное объявление>"
}

func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}
