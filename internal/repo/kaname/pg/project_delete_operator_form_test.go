// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// project_delete_operator_form_test.go — ФОРМА оператора удаления проекта
// (IAM-PNE-1-12, полоса Б; дом Д приёмки `non-empty-project-is-not-deleted.md`).
//
// # Что утверждается — свойство ТЕКСТА, а не поведения
//
// Интеграционная проба видит исход и не видит текста; здесь наоборот. Три
// свойства файла, несущего оператор:
//
//	1. словарь чужих видов НЕ выписан: точечных имён в строковых литералах ровно
//	   два, и оба про своё семейство — образец приставки `iam.%` в отборе и
//	   подпись `iam.role` у счёта ролей (§2.3);
//	2. отбор записан СЕМЕЙСТВОМ с разделителем (`NOT LIKE 'iam.%'`), а не
//	   перечислением его членов;
//	3. отбор в ОБЕИХ формах оператора — в охране и в группировке — один и тот
//	   же: каждое чтение зеркала несёт колонку родителя и приставку семейства
//	   дословно; соединения с таблицами каталога нет ни в одной форме (§2.2).
//
// Разойдись формы — отказ пришёл бы с пустой скобкой (охрана удержала, перечень
// не назвал) либо назвал бы вид, которого удержание не касается.
//
// # Гейт читает ЛИТЕРАЛЫ, а не текст файла
//
// Точечные имена стоят и в комментариях этого же файла (в том числе в
// объяснении самого отбора). Проверка по сырому тексту краснела бы на
// собственном объяснении, поэтому обход идёт по узлам `*ast.BasicLit`.
//
// Схемный квалификатор `kaname.<таблица>` точечным именем вида не является и
// из перечня исключается явно: модуля с именем `kaname` в каталоге нет и быть
// не может — это имя схемы службы.
//
// Способность упасть и смолчать доказана инъекцией — ниже, в этом же файле.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// projectDeleteOperatorFile — файл, несущий оператор удаления проекта.
const projectDeleteOperatorFile = "project_repo.go"

// mirrorSelection — отбор строк зеркала, обязанный стоять при КАЖДОМ чтении
// зеркала в операторе: колонка родителя и приставка семейства с разделителем.
// Пробелы нормализуются перед сравнением.
const mirrorSelection = "parent_project_id = $1 AND m.object_type NOT LIKE 'iam.%'"

// dottedName — точечное имя вида либо образец приставки в литерале.
//
// Голова — не короче трёх знаков: имена модулей каталога такие (`iam`, `vpc`,
// `compute`), а одно- и двухбуквенные головы в SQL этого файла — псевдонимы
// таблиц (`m.object_type`, `p.id`), то есть не имена видов. Псевдоним длиннее
// двух знаков попадёт в перепись и будет назван находкой по имени — это цена
// однозначности, а не слепота: гейт скажет, что именно не так.
var dottedName = regexp.MustCompile(`\b[a-z][a-zA-Z0-9_]{2,}\.[a-zA-Z%][a-zA-Z0-9_%]*`)

// operatorForm — то, что обход прочитал о файле.
type operatorForm struct {
	// literals — ОБЪЁМ ОСМОТРЕННОГО: строковых литералов разобрано.
	literals int
	// dotted — множество точечных имён по всем литералам (без квалификатора схемы).
	dotted map[string]struct{}
	// operator — литерал, несущий оператор удаления; пусто, если его нет.
	operator string
	// catalogJoined — в операторе встречается таблица каталога.
	catalogJoined bool
	// mirrorReads / selections — сколько раз оператор читает зеркало и сколько
	// раз при чтении стоит дословный отбор.
	mirrorReads int
	selections  int
}

func readOperatorForm(t *testing.T, name string, src any) operatorForm {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	require.NoErrorf(t, err, "%s не разобран — непрочитанное есть НАХОДКА, а не согласие", name)

	form := operatorForm{dotted: map[string]struct{}{}}
	// Пути импортов — тоже строковые литералы (`github.com/…`), и точечное имя
	// в них — имя хоста, а не вида. Исключаются по узлу, а не по подстроке.
	importPaths := map[*ast.BasicLit]struct{}{}
	for _, imp := range file.Imports {
		importPaths[imp.Path] = struct{}{}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if _, isImport := importPaths[lit]; isImport {
			return true
		}
		value, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		form.literals++
		for _, m := range dottedName.FindAllString(value, -1) {
			if strings.HasPrefix(m, "kaname.") {
				continue
			}
			form.dotted[m] = struct{}{}
		}
		if strings.Contains(value, "DELETE FROM projects") {
			form.operator = value
			collapsed := strings.Join(strings.Fields(value), " ")
			form.catalogJoined = strings.Contains(collapsed, "catalog_resource") ||
				strings.Contains(collapsed, "catalog_verb")
			form.mirrorReads = strings.Count(collapsed, "resource_mirror")
			form.selections = strings.Count(collapsed, mirrorSelection)
		}
		return true
	})
	return form
}

// judgeOperatorForm — вердикт над прочитанным. Один предикат для живого гейта
// и для инъекции: два судьи об одном предмете разошлись бы молча.
func judgeOperatorForm(f operatorForm) []string {
	if f.literals == 0 {
		return []string{"обход не нашёл ни одного строкового литерала — вердикт беспредметен"}
	}
	var findings []string
	if f.operator == "" {
		return []string{"оператора удаления проекта (DELETE FROM projects) в файле нет — судить нечего"}
	}
	names := make([]string, 0, len(f.dotted))
	for n := range f.dotted {
		names = append(names, n)
	}
	sort.Strings(names)
	wantNames := []string{"iam.%", "iam.role"}
	if strings.Join(names, ",") != strings.Join(wantNames, ",") {
		findings = append(findings, "точечные имена в литералах файла: ["+strings.Join(names, ", ")+
			"], ожидались ровно ["+strings.Join(wantNames, ", ")+"] — образец семейства с "+
			"разделителем и подпись счёта ролей; выписанный вид либо член семейства есть находка")
	}
	if f.catalogJoined {
		findings = append(findings, "оператор соединяется с таблицей каталога — каталог охрану и "+
			"перечень не спрашивает (§2.2)")
	}
	if f.mirrorReads < 2 {
		findings = append(findings, "оператор читает зеркало меньше двух раз: охрана и группировка "+
			"обязаны читать его обе")
	}
	if f.selections != f.mirrorReads {
		findings = append(findings, "чтений зеркала "+strconv.Itoa(f.mirrorReads)+", а дословный отбор ["+
			mirrorSelection+"] стоит у "+strconv.Itoa(f.selections)+" — формы оператора разошлись: "+
			"пустая скобка либо вид, которого удержание не касается")
	}
	return findings
}

// TestProjectDelete_PNE_1_12B — живой гейт над project_repo.go.
func TestProjectDelete_PNE_1_12B(t *testing.T) {
	t.Parallel()
	_, err := os.Stat(projectDeleteOperatorFile)
	require.NoError(t, err, "%s не прочитан", projectDeleteOperatorFile)
	f := readOperatorForm(t, projectDeleteOperatorFile, nil)
	t.Logf("перепись: литералов разобрано %d · точечных имён %d · чтений зеркала в операторе %d · отборов %d",
		f.literals, len(f.dotted), f.mirrorReads, f.selections)
	for _, finding := range judgeOperatorForm(f) {
		t.Errorf("%s", finding)
	}
}

// ── Инъекция: гейт СПОСОБЕН упасть и СПОСОБЕН смолчать ──────────────────────

const operatorFormLive = `package pg

const projectRoleChildKind = "iam.role"

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT LIKE 'iam.%')
		  AND NOT EXISTS (SELECT 1 FROM roles WHERE project_id = $1)
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT LIKE 'iam.%'
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int, (SELECT count(*) FROM roles WHERE project_id = $1)
` + "`" + `
`

// operatorFormEnumerated — словарь чужих видов ВЫПИСАН: новый вид в перечень не
// попадёт, и слепота ляжет в сторону разрешения удаления.
const operatorFormEnumerated = `package pg

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT LIKE 'iam.%'
		                     AND m.object_type IN ('vpc.network', 'compute.instance'))
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT LIKE 'iam.%'
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int
` + "`" + `
const projectRoleChildKind = "iam.role"
`

// operatorFormFamilyEnumerated — семейство перечислено членами, а не приставкой.
const operatorFormFamilyEnumerated = `package pg

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT IN ('iam.role', 'iam.group'))
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT IN ('iam.role', 'iam.group')
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int
` + "`" + `
`

// operatorFormGroupingWithoutFamily — исключение семейства стоит в охране и
// потеряно в группировке: роль посчитана дважды, вид службы назван арендатору.
const operatorFormGroupingWithoutFamily = `package pg

const projectRoleChildKind = "iam.role"

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT LIKE 'iam.%')
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int
` + "`" + `
`

// operatorFormPrefixWithoutDot — приставка без разделителя: вид модуля `iamx`
// выпал бы из отбора.
const operatorFormPrefixWithoutDot = `package pg

const projectRoleChildKind = "iam.role"

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT LIKE 'iam%')
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT LIKE 'iam%'
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int
` + "`" + `
`

// operatorFormCatalogJoined — третье условие охраны через каталог: занижение
// счёта, снятое приёмкой (§2.2).
const operatorFormCatalogJoined = `package pg

const projectRoleChildKind = "iam.role"

const q = ` + "`" + `
	WITH del AS (
		DELETE FROM projects p WHERE p.id = $1
		  AND NOT EXISTS (SELECT 1 FROM resource_mirror m
		                   WHERE m.parent_project_id = $1
		                     AND m.object_type NOT LIKE 'iam.%'
		                     AND EXISTS (SELECT 1 FROM catalog_verb v WHERE v.live))
		RETURNING 1
	), held AS (
		SELECT m.object_type AS kind, count(*) AS n FROM resource_mirror m
		 WHERE m.parent_project_id = $1
		   AND m.object_type NOT LIKE 'iam.%'
		 GROUP BY m.object_type
	)
	SELECT (SELECT count(*) FROM del)::int
` + "`" + `
`

// operatorFormOnlyInComments — всё названо прозой, оператора нет.
const operatorFormOnlyInComments = `package pg

// Оператор: DELETE FROM projects с отбором parent_project_id = $1 AND
// m.object_type NOT LIKE 'iam.%' и подписью iam.role. Здесь ничего не объявлено.
type marker struct{}
`

func TestProjectDelete_PNE_1_12B_InjectionRedsTheFormAndKeepsQuietOnTheLiveOne(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		src         string
		wantFinding bool
		wantInText  string
	}{
		{name: "живая форма — гейт молчит", src: operatorFormLive},
		{name: "словарь чужих видов выписан", src: operatorFormEnumerated, wantFinding: true, wantInText: "точечные имена"},
		{name: "семейство перечислено членами", src: operatorFormFamilyEnumerated, wantFinding: true, wantInText: "точечные имена"},
		{name: "исключение семейства потеряно в группировке", src: operatorFormGroupingWithoutFamily, wantFinding: true, wantInText: "формы оператора разошлись"},
		{name: "приставка без разделителя", src: operatorFormPrefixWithoutDot, wantFinding: true, wantInText: "точечные имена"},
		{name: "соединение с каталогом", src: operatorFormCatalogJoined, wantFinding: true, wantInText: "таблицей каталога"},
		{name: "оператор только в комментариях", src: operatorFormOnlyInComments, wantFinding: true, wantInText: "беспредметен"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := readOperatorForm(t, "synthetic.go", tc.src)
			findings := judgeOperatorForm(f)
			t.Logf("литералов %d · точечных %d · чтений %d · отборов %d · находок %d: %v",
				f.literals, len(f.dotted), f.mirrorReads, f.selections, len(findings), findings)
			if tc.wantFinding && len(findings) == 0 {
				t.Fatalf("инъекция не покраснела: гейт не способен упасть на этом входе")
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("законный близнец покраснел: %v", findings)
			}
			if tc.wantInText != "" && !strings.Contains(strings.Join(findings, " | "), tc.wantInText) {
				t.Fatalf("находка не называет %q: %v", tc.wantInText, findings)
			}
		})
	}
}
