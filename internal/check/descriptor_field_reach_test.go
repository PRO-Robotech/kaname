// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// descriptor_field_reach_test.go — у КАЖДОГО поля контракта
// `InternalModuleService` есть свой конец в прод-коде: поле запроса кто-то
// ЧИТАЕТ, поле ответа кто-то ПИШЕТ (kaname#865, DoD S1 п.5 приёмки
// `module-manifest-revision-only-moves-forward.md`, класс «принято и
// проигнорировано»).
//
// # Что судится
//
// Поля берутся из ДЕСКРИПТОРА файла контракта, а не перечнем: новое поле
// попадает под суд тем же изменением, которым его заводят. Сообщение,
// оканчивающееся на `Request`, — вход: поле обязано читаться (`r.GetX()` либо
// `r.X` не слева от присваивания) у получателя `r`, чей тип в исходнике
// объявлен ЭТИМ сообщением. Прочие сообщения — выход: поле обязано
// писаться (ключ составного литерала этого сообщения либо присваивание
// `….X = …`).
//
// # Чем ограничен разбор — слепые зоны названы
//
// Разбор синтаксический, без типов. Чтение засчитывается полю запроса только
// у идентификатора, чей тип объявлен сообщением запроса: параметр или
// результат функции (и объемлющей — для замыкания), `var r T`, `r := &pkg.T{…}`.
// Замер, из-за которого правило такое (CV-865-1): чтение того же имени у
// любого получателя закрывало поле, и замена `req.GetExpectedState()`
// литералом в обработчике оставляла гейт зелёным на восьми чтениях
// одноимённого поля в соседних пакетах. Цена — ложная находка там, где запрос
// читается через выражение без объявленного типа (`f().GetX()`, поле
// структуры, `r := f()`): такая находка закрывается переходом на
// типизированный идентификатор, а не послаблением. Блоков разбор не различает:
// затенение внутри вложенного блока действует до конца функции.
//
// Присваивание `x.X = …` не знает, какому
// сообщению принадлежит `x`. Поэтому присваивание засчитывается ТОЛЬКО полю,
// чьё имя Go единственно среди выходных сообщений контракта; у одноимённых
// полей разных сообщений (`AppliedRevision` есть у плана, применения и
// каталога) конец обязан стоять ключом составного литерала СВОЕГО сообщения.
// Замер, из-за которого правило такое: снятая запись `AppliedDigest` у `Get`
// засчитывалась присваиванием того же имени у `Plan`, и гейт молчал.
//
// Обход — не-тестовые `.go` под `internal/` и `cmd/` этого модуля, без
// порождённого `pkg/api` (там поля объявлены, а не прочитаны).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// descriptorField — поле контракта и сторона, с которой у него обязан быть
// конец.
type descriptorField struct {
	message string
	field   string
	goName  string
	input   bool
}

// descriptorFieldExemption — ПОСЛАБЛЕНИЕ: поле, у которого конца в прод-коде
// нет, и причина названа в коде рядом с местом, где он стоял бы. Истекает само:
// поле получило конец либо исчезло из контракта — запись становится находкой.
type descriptorFieldExemption struct {
	message, field, why string
}

// descriptorFieldExemptions — ведомость послаблений. Заводится ПО ФАКТУ.
var descriptorFieldExemptions = []descriptorFieldExemption{
	// `applyOperationPayload` (internal/apps/kaname/api/module/apply.go,
	// «Чего здесь НЕТ»): перепись применителя этих величин не несёт, и
	// подставить фактические числа значило бы объявить «план обещал ровно
	// столько», чего никто не измерял; величина сегодня не наблюдается ни одним
	// вызывающим. Предикат снятия: `applyOperationPayload` пишет поле — тогда
	// запись истекает находкой этого же гейта.
	{"ApplyModuleResponse", "planned_resettled_rule_refs", "плановая оценка переселения внутри транзакции не производится"},
	{"ApplyModuleResponse", "planned_resettled_role_verbs", "плановая оценка переселения внутри транзакции не производится"},
}

// moduleServiceFields — поля всех сообщений файла контракта.
func moduleServiceFields(t *testing.T) []descriptorField {
	t.Helper()
	fd := iamv1.File_kaname_cloud_iam_v1_internal_module_service_proto
	var out []descriptorField
	msgs := fd.Messages()
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
		if err != nil {
			t.Fatalf("тип сообщения %s не зарегистрирован: %v", md.FullName(), err)
		}
		goNames := goFieldNames(reflect.TypeOf(mt.Zero().Interface()))
		fields := md.Fields()
		for j := 0; j < fields.Len(); j++ {
			f := fields.Get(j)
			name, ok := goNames[string(f.Name())]
			if !ok {
				t.Fatalf("поле %s.%s не найдено в порождённом типе", md.Name(), f.Name())
			}
			out = append(out, descriptorField{
				message: string(md.Name()), field: string(f.Name()), goName: name,
				input: strings.HasSuffix(string(md.Name()), "Request"),
			})
		}
	}
	return out
}

// goFieldNames — имя поля Go по имени поля контракта (тег `protobuf`).
func goFieldNames(rt reflect.Type) map[string]string {
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	out := map[string]string{}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		for _, part := range strings.Split(f.Tag.Get("protobuf"), ",") {
			if name, ok := strings.CutPrefix(part, "name="); ok {
				out[name] = f.Name
			}
		}
	}
	return out
}

// fieldEnds — где в исходниках у имён полей есть концы.
type fieldEnds struct {
	files int
	// written[сообщение.ПолеGo] / assigned[ПолеGo] / read[сообщение.ПолеGo] —
	// места. Чтение ключуется СООБЩЕНИЕМ получателя: засчитывается только у
	// идентификатора, чей тип объявлен в исходнике (`readerScope`).
	written  map[string][]string
	assigned map[string][]string
	read     map[string][]string
}

// readerScope — идентификаторы с объявленным типом сообщения: параметры и
// именованные результаты функции, `var x T` в её теле, и то же у объемлющих
// функций (замыкание видит их переменные). Значение — имя сообщения.
type readerScope map[string]string

// messageOfType — имя сообщения типа `pkg.M` либо `*pkg.M`; иначе "".
func messageOfType(e ast.Expr) string {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// with — область, расширенная полями списка (параметры, результаты, `var`).
func (s readerScope) with(names []*ast.Ident, typ ast.Expr) readerScope {
	msg := messageOfType(typ)
	out := make(readerScope, len(s)+len(names))
	for k, v := range s {
		out[k] = v
	}
	for _, n := range names {
		if msg == "" {
			delete(out, n.Name) // затенение именем без типа сообщения
			continue
		}
		out[n.Name] = msg
	}
	return out
}

// declare — объявление в теле (`var`, `:=`) расширяет ТЕКУЩУЮ область: тип
// сообщения берётся из объявленного типа либо из составного литерала справа
// (`r := &iamv1.M{…}`); прочее значение затеняет имя.
func (s readerScope) declare(names []*ast.Ident, typ ast.Expr, values []ast.Expr) {
	for i, n := range names {
		msg := messageOfType(typ)
		if typ == nil && len(values) == len(names) {
			if lit, ok := unparen(values[i]).(*ast.CompositeLit); ok {
				msg = messageOfType(literalType(lit))
			}
		}
		if msg == "" {
			delete(s, n.Name)
			continue
		}
		s[n.Name] = msg
	}
}

// unparen — выражение без `&` и скобок.
func unparen(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.UnaryExpr:
			e = x.X
		default:
			return e
		}
	}
}

// withFields — область, расширенная параметрами и результатами функции.
func (s readerScope) withFields(lists ...*ast.FieldList) readerScope {
	for _, l := range lists {
		if l == nil {
			continue
		}
		for _, f := range l.List {
			s = s.with(f.Names, f.Type)
		}
	}
	return s
}

// scanFieldEnds разбирает исходники и собирает концы.
func scanFieldEnds(t *testing.T, sources map[string]string) fieldEnds {
	t.Helper()
	ends := fieldEnds{written: map[string][]string{}, assigned: map[string][]string{}, read: map[string][]string{}}
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, sources[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s не разобран: %v — непрочитанное есть находка", name, err)
		}
		ends.files++
		lhs := map[ast.Expr]bool{}
		var visit func(scope readerScope) func(ast.Node) bool
		visit = func(scope readerScope) func(ast.Node) bool {
			return func(n ast.Node) bool {
				return scanNode(fset, &ends, lhs, scope, visit, n)
			}
		}
		ast.Inspect(file, visit(readerScope{}))
	}
	return ends
}

// scanNode — один узел обхода `scanFieldEnds`. Функция и замыкание открывают
// свою область (параметры и результаты), `var` расширяет текущую до конца
// обхода функции — разбор без типов не знает блоков, слепая зона названа в
// шапке.
func scanNode(fset *token.FileSet, ends *fieldEnds, lhs map[ast.Expr]bool, scope readerScope,
	visit func(readerScope) func(ast.Node) bool, n ast.Node) bool {
	switch x := n.(type) {
	case *ast.FuncDecl:
		if x.Body != nil {
			ast.Inspect(x.Body, visit(scope.withFields(x.Recv, x.Type.Params, x.Type.Results)))
		}
		return false
	case *ast.FuncLit:
		ast.Inspect(x.Body, visit(scope.withFields(x.Type.Params, x.Type.Results)))
		return false
	case *ast.ValueSpec:
		scope.declare(x.Names, x.Type, x.Values)
	case *ast.AssignStmt:
		if x.Tok == token.DEFINE {
			names := make([]*ast.Ident, 0, len(x.Lhs))
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					names = append(names, id)
				}
			}
			scope.declare(names, nil, x.Rhs)
		}
		for _, l := range x.Lhs {
			if sel, ok := l.(*ast.SelectorExpr); ok {
				lhs[sel] = true
				ends.assigned[sel.Sel.Name] = append(ends.assigned[sel.Sel.Name], fset.Position(sel.Pos()).String())
			}
		}
	case *ast.CompositeLit:
		sel, ok := literalType(x).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, el := range x.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				k := sel.Sel.Name + "." + key.Name
				ends.written[k] = append(ends.written[k], fset.Position(kv.Pos()).String())
			}
		}
	case *ast.SelectorExpr:
		if lhs[x] {
			return true
		}
		recv, ok := x.X.(*ast.Ident)
		if !ok {
			return true
		}
		msg, ok := scope[recv.Name]
		if !ok {
			return true
		}
		pos := fset.Position(x.Pos()).String()
		ends.read[msg+"."+x.Sel.Name] = append(ends.read[msg+"."+x.Sel.Name], pos)
		if name := strings.TrimPrefix(x.Sel.Name, "Get"); name != x.Sel.Name {
			ends.read[msg+"."+name] = append(ends.read[msg+"."+name], pos)
		}
	}
	return true
}

// literalType — тип составного литерала без `&`.
func literalType(x *ast.CompositeLit) ast.Expr {
	if u, ok := x.Type.(*ast.UnaryExpr); ok {
		return u.X
	}
	return x.Type
}

// judgeFieldEnds — находки: поле без конца и запись послабления без предмета.
func judgeFieldEnds(fields []descriptorField, ends fieldEnds, exemptions []descriptorFieldExemption) (findings []string, exempted int) {
	exempt := map[string]bool{}
	for _, e := range exemptions {
		exempt[e.message+"."+e.field] = true
	}
	// Сколько выходных сообщений несут поле с этим именем Go: присваивание
	// засчитывается только единственному.
	outputs := map[string]int{}
	for _, f := range fields {
		if !f.input {
			outputs[f.goName]++
		}
	}
	seen := map[string]bool{}
	for _, f := range fields {
		key := f.message + "." + f.field
		seen[key] = true
		var has bool
		if f.input {
			has = len(ends.read[f.message+"."+f.goName]) > 0
		} else {
			has = len(ends.written[f.message+"."+f.goName]) > 0 ||
				(outputs[f.goName] == 1 && len(ends.assigned[f.goName]) > 0)
		}
		switch {
		case has && exempt[key]:
			findings = append(findings, "послабление "+key+" истекло: у поля есть конец в прод-коде — сними запись ведомости")
		case !has && exempt[key]:
			exempted++
		case !has && f.input:
			findings = append(findings, "поле запроса "+key+" ("+f.goName+") не читается прод-кодом — принято и проигнорировано")
		case !has:
			findings = append(findings, "поле ответа "+key+" ("+f.goName+") не пишется прод-кодом — объявлено и не производится")
		}
	}
	for _, e := range exemptions {
		if !seen[e.message+"."+e.field] {
			findings = append(findings, "послабление "+e.message+"."+e.field+" без предмета: поля в контракте нет")
		}
	}
	return findings, exempted
}

// prodSources — не-тестовые исходники `internal/` и `cmd/` модуля.
func prodSources(t *testing.T) map[string]string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	out := map[string]string{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(p) // #nosec G304 -- обход собственного дерева модуля
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			out[rel] = string(b)
			return nil
		})
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход %s: %v", top, err)
		}
	}
	return out
}

// TestEveryDescriptorFieldHasAReader_InternalModuleService — у каждого поля
// контракта `InternalModuleService` есть конец в прод-коде.
func TestEveryDescriptorFieldHasAReader_InternalModuleService(t *testing.T) {
	fields := moduleServiceFields(t)
	sources := prodSources(t)
	ends := scanFieldEnds(t, sources)
	findings, exempted := judgeFieldEnds(fields, ends, descriptorFieldExemptions)
	inputs := 0
	for _, f := range fields {
		if f.input {
			inputs++
			t.Logf("вход %s.%s: чтений у получателя своего сообщения %d", f.message, f.field, len(ends.read[f.message+"."+f.goName]))
		}
	}
	t.Logf("перепись: файлов прочитано %d · полей контракта %d (вход %d, выход %d) · по ведомости %d · находок %d",
		ends.files, len(fields), inputs, len(fields)-inputs, exempted, len(findings))
	if ends.files == 0 || len(fields) == 0 {
		t.Fatal("обход беспредметен: прочитано ноль файлов либо ноль полей — «находок ноль» здесь ничего не значит")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestEveryDescriptorFieldHasAReader_JudgeFallsAndStaysSilent — инъекция в обе
// стороны на синтетике: поле ответа без записи и поле запроса без чтения —
// находки; чтение одноимённого поля у получателя чужого сообщения либо без
// объявленного типа — находка; запись литералом, присваиванием и чтение
// геттером у получателя своего сообщения (параметр, замыкание, `var`) —
// молчание; послабление с концом и без предмета — находки.
func TestEveryDescriptorFieldHasAReader_JudgeFallsAndStaysSilent(t *testing.T) {
	fields := []descriptorField{
		{message: "PlanModuleResponse", field: "applied_revision", goName: "AppliedRevision"},
		{message: "ApplyModuleResponse", field: "applied_digest", goName: "AppliedDigest"},
		{message: "PlanModuleRequest", field: "module", goName: "Module", input: true},
	}
	lawful := map[string]string{"a.go": `package a
func f(req *iamv1.PlanModuleRequest) {
	resp := &iamv1.PlanModuleResponse{AppliedRevision: nil}
	var r iamv1.ApplyModuleResponse
	r.AppliedDigest = nil
	_ = req.GetModule()
	_, _ = resp, r
}
`}
	findings, _ := judgeFieldEnds(fields, scanFieldEnds(t, lawful), nil)
	if len(findings) != 0 {
		t.Fatalf("законный близнец дал находки: %v", findings)
	}

	injected := map[string]string{"a.go": `package a
func f(req *iamv1.PlanModuleRequest) {
	resp := &iamv1.PlanModuleResponse{}
	var r iamv1.ApplyModuleResponse
	req.Module = ""
	_, _ = resp, r
}
`}
	findings, _ = judgeFieldEnds(fields, scanFieldEnds(t, injected), nil)
	want := []string{"PlanModuleResponse.applied_revision", "ApplyModuleResponse.applied_digest", "PlanModuleRequest.module"}
	if len(findings) != len(want) {
		t.Fatalf("инъекция: ожидалось %d находок, получено %d: %v", len(want), len(findings), findings)
	}
	for i, w := range want {
		if !strings.Contains(findings[i], w) {
			t.Errorf("находка %d не называет %s: %q", i, w, findings[i])
		}
	}

	// Одноимённое поле двух сообщений: присваивание у одного не закрывает
	// другое (замер, ради которого правило заведено).
	twoNamed := []descriptorField{
		{message: "PlanModuleResponse", field: "applied_digest", goName: "AppliedDigest"},
		{message: "ModuleCatalog", field: "applied_digest", goName: "AppliedDigest"},
	}
	findings, _ = judgeFieldEnds(twoNamed, scanFieldEnds(t, map[string]string{"a.go": `package a
func f(resp *iamv1.PlanModuleResponse) { resp.AppliedDigest = nil; _ = &iamv1.ModuleCatalog{AppliedDigest: nil} }
`}), nil)
	if len(findings) != 1 || !strings.Contains(findings[0], "PlanModuleResponse.applied_digest") {
		t.Fatalf("присваивание одноимённого поля засчитано не тому сообщению: %v", findings)
	}

	// Одноимённое поле запроса: чтение того же имени у получателя ДРУГОГО
	// сообщения либо у получателя без объявленного типа поле не закрывает
	// (CV-865-1: `req.GetExpectedState()` заменён литералом, а гейт молчал на
	// восьми чтениях того же имени в соседних пакетах). Близнец — чтение через
	// параметр своего сообщения внутри замыкания и через `var` — молчит.
	reqFields := []descriptorField{
		{message: "PlanModuleRequest", field: "module", goName: "Module", input: true},
		{message: "ApplyModuleRequest", field: "expected_state", goName: "ExpectedState", input: true},
	}
	findings, _ = judgeFieldEnds(reqFields, scanFieldEnds(t, map[string]string{"a.go": `package a
func f(other *iamv1.GetModuleRequest, req *iamv1.ApplyModuleRequest, st *catalog.State) {
	_ = other.GetModule()
	_ = st.ExpectedState
	_ = x.GetModule()
	_ = req.GetModule()
}
`}), nil)
	if len(findings) != 2 || !strings.Contains(findings[0], "PlanModuleRequest.module") ||
		!strings.Contains(findings[1], "ApplyModuleRequest.expected_state") {
		t.Fatalf("чтение одноимённого поля чужого получателя засчитано полю запроса: %v", findings)
	}
	findings, _ = judgeFieldEnds(reqFields, scanFieldEnds(t, map[string]string{"a.go": `package a
func f(req *iamv1.PlanModuleRequest) {
	go func() { _ = req.GetModule() }()
}
func g() {
	var r iamv1.ApplyModuleRequest
	_ = r.ExpectedState
}
`}), nil)
	if len(findings) != 0 {
		t.Fatalf("законный близнец (параметр в замыкании, var своего сообщения) дал находки: %v", findings)
	}

	findings, exempted := judgeFieldEnds(fields, scanFieldEnds(t, lawful), []descriptorFieldExemption{
		{"PlanModuleResponse", "applied_revision", "x"},
		{"PlanModuleResponse", "gone_field", "x"},
	})
	if exempted != 0 || len(findings) != 2 ||
		!strings.Contains(findings[0], "истекло") || !strings.Contains(findings[1], "без предмета") {
		t.Fatalf("послабление с концом и без предмета обязаны быть находками: %v (по ведомости %d)", findings, exempted)
	}
}

var _ protoreflect.FileDescriptor = iamv1.File_kaname_cloud_iam_v1_internal_module_service_proto
