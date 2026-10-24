// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_level_two_enrollment_test.go — способ, чьё предъявление одно даёт
// уровень «2», заводится и снимается только сессией уровня «2» (задача
// kaname#747; приёмка
// `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`,
// отпечаток 711609ce…, Р1, Р3, §7 инвариант 1, §8 первая строка; сценарии
// KN747-01…04, -09…11, -13…16).
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Две вещи над НАСТОЯЩИМ встроенным каталогом прав службы — тем, который второй
// замок службы читает на каждом запросе (край читает его копию):
//
//	(1) ОТНОШЕНИЕ (инвариант 1): пол `AccessKeyService/BeginRegistration`,
//	    `FinishRegistration`, `Revoke` не ниже пола `UserTokenService/Issue`
//	    и не ниже «2» (инвариант 2). Отношение, а не литерал: поднятый пол
//	    выпуска токена поднимает и их.
//	(2) ИСХОД ПРАВИЛА ПОВЫШЕНИЯ (`grpcsrv.EvaluateStepUp`, одно на оба замка):
//	    субъект-человек с уровнем «1» получает на трёх глаголах отказ по
//	    уровню, с уровнем «2» — проход.
//
// # ЧЕГО ЗДЕСЬ НЕТ
//
// Ответ края на недостаток уровня (`401`, `code` 16, вызов с `acr_values`) —
// дом платформы: его производит край до пересылки службе. Порядок «уровень
// раньше свежести» (KN747-16) — свойство механизма: пол судят край и второй
// замок службы ДО сценария, где живёт окно свежести; проба судит вход этого
// механизма — пол каталога и вердикт общего правила над ним. Сам второй замок
// на обоих путях входа — public_level_two_second_lock_test.go и
// cmd/kaname/access_key_level_two_listeners_test.go. Сквозной исход каждого
// сценария — кейсы края (§9 п. 4).
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// Предикат отношения вынесен функцией; инъекция ниже зовёт ТОТ ЖЕ предикат с
// законным близнецом и с каждым видом дефекта.
package authzguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/grpcsrv"

	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	kn747BeginRegistration  = "kaname.cloud.iam.v1.AccessKeyService/BeginRegistration"
	kn747FinishRegistration = "kaname.cloud.iam.v1.AccessKeyService/FinishRegistration"
	kn747Revoke             = "kaname.cloud.iam.v1.AccessKeyService/Revoke"
	// kn747Anchor — пол, относительно которого судится отношение (инвариант 1).
	kn747Anchor = "kaname.cloud.iam.v1.UserTokenService/Issue"
	// kn747LevelTwo — ступень, которую даёт одно предъявление ключа (Ф11 Р2).
	kn747LevelTwo = "2"
)

// kn747Guarded — глаголы, заводящие либо снимающие способ, чьё предъявление
// одно даёт «2» (§1.2: П1, П3).
var kn747Guarded = []string{kn747BeginRegistration, kn747FinishRegistration, kn747Revoke}

// levelTwoEnrollmentFindings — предикат отношения по ОДНОМУ каталогу.
func levelTwoEnrollmentFindings(lookup ACRRequirementLookup) []string {
	var out []string
	anchor := lookup.RequiredACRMin(kn747Anchor)
	if acrlevel.Rank(anchor) == 0 {
		out = append(out, fmt.Sprintf("%s: пола нет (%q) — отношение сказано ни о чём", kn747Anchor, anchor))
	}
	for _, fqn := range kn747Guarded {
		floor := lookup.RequiredACRMin(fqn)
		if acrlevel.Rank(floor) < acrlevel.Rank(kn747LevelTwo) {
			out = append(out, fmt.Sprintf("%s требует %q: способ, дающий «2» одним предъявлением, "+
				"заводится или снимается сессией ниже «2»", fqn, floor))
		}
		if acrlevel.Rank(anchor) > 0 && acrlevel.Rank(floor) < acrlevel.Rank(anchor) {
			out = append(out, fmt.Sprintf("%s требует %q, %s — %q: заведение способа дешевле "+
				"выпуска, который этот способ открывает", fqn, floor, kn747Anchor, anchor))
		}
	}
	sort.Strings(out)
	return out
}

// TestKN747_FloorOfKeyVerbsIsNotBelowLevelTwo — Р3, инварианты 1 и 2.
func TestKN747_FloorOfKeyVerbsIsNotBelowLevelTwo(t *testing.T) {
	reg := loadRealACRCatalog(t)
	// Фикстура проверяется ДО предмета: якорь отношения обязан быть в каталоге,
	// иначе красное значило бы «каталог не тот», а не «пол не тот».
	anchor := reg.RequiredACRMin(kn747Anchor)
	if acrlevel.Rank(anchor) == 0 {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: у якоря %s в каталоге нет пола (%q)", kn747Anchor, anchor)
	}
	t.Logf("перепись: якорь %s → required_acr_min=%q", kn747Anchor, anchor)
	for _, fqn := range kn747Guarded {
		if _, ok := reg.LookupFQN(fqn); !ok {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: глагола %s нет в каталоге", fqn)
		}
		t.Logf("перепись: %s → required_acr_min=%q", fqn, reg.RequiredACRMin(fqn))
	}
	if f := levelTwoEnrollmentFindings(reg); len(f) > 0 {
		t.Fatalf("способ, дающий «2», заводится дешевле «2» — %d находк(и):\n  %v\n\n"+
			"Пол объявляет контракт (`required_acr_min` у трёх глаголов "+
			"proto/kaname/cloud/iam/v1/access_key_service.proto); каталог службы и копия края "+
			"порождаются из него (kaname#747, Р3).", len(f), f)
	}
}

// TestKN747_StepUpVerdictOnKeyVerbs — исход общего правила повышения над полом
// каталога по каждому сценарию полосы ключа.
func TestKN747_StepUpVerdictOnKeyVerbs(t *testing.T) {
	reg := loadRealACRCatalog(t)
	cases := []struct {
		id, fqn, acr string
		want         grpcsrv.StepUpVerdict
		what         string
	}{
		{"KN747-01", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "регистрация сессией «2» (пароль и код) — проход"},
		{"KN747-01/finish", kn747FinishRegistration, "2", grpcsrv.StepUpAllow, "приём результата сессией «2» — проход"},
		{"KN747-01/issue", kn747Anchor, "2", grpcsrv.StepUpAllow, "выпуск личного токена сессией «2» — проход"},
		{"KN747-02", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией «1» (код заведён, не предъявлен)"},
		{"KN747-03", kn747FinishRegistration, "1", grpcsrv.StepUpDenyACR, "результат церемонии из сессии «1»"},
		{"KN747-04", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией «1» (кода нет)"},
		{"KN747-09", kn747Revoke, "1", grpcsrv.StepUpDenyACR, "снятие ключа сессией «1»"},
		{"KN747-10", kn747Revoke, "2", grpcsrv.StepUpAllow, "снятие ключа сессией «2» — проход"},
		{"KN747-11", kn747Anchor, "2", grpcsrv.StepUpAllow, "сессия входа ключом («2») выпускает личный токен"},
		{"KN747-13", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией восстановления «1»"},
		{"KN747-14", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "сессия восстановления с кодом («2») — проход"},
		{"KN747-15", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "пол пройден сессией «2»; отказ свежести — у службы после пола"},
		{"KN747-16", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "сессия «1» с истёкшим окном — отказ по уровню на замке до службы"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			required := reg.RequiredACRMin(c.fqn)
			got := grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
				PrincipalType: "user", PresentedACR: c.acr, RequiredACR: required,
			})
			if got != c.want {
				t.Errorf("%s: %s сессией уровня %q при поле каталога %q — вердикт %d, ожидался %d (%s)",
					c.id, c.fqn, c.acr, required, got, c.want, c.what)
			}
		})
	}
}

// TestKN747_FloorPredicateCanFail — инъекция с законным близнецом.
func TestKN747_FloorPredicateCanFail(t *testing.T) {
	legal := fakeACRCatalog{kn747Anchor: "2"}
	for _, fqn := range kn747Guarded {
		legal[fqn] = "2"
	}
	if f := levelTwoEnrollmentFindings(legal); len(f) != 0 {
		t.Fatalf("законное решение объявлено находкой: %v", f)
	}
	clone := func() fakeACRCatalog {
		c := fakeACRCatalog{}
		for k, v := range legal {
			c[k] = v
		}
		return c
	}
	for _, fqn := range kn747Guarded {
		t.Run("пол «1» у "+fqn, func(t *testing.T) {
			bad := clone()
			bad[fqn] = "1"
			// одна находка «ниже «2»» и одна «ниже якоря»
			if f := levelTwoEnrollmentFindings(bad); len(f) != 2 {
				t.Fatalf("ожидалось 2 находки, получено %d: %v", len(f), f)
			}
		})
	}
	t.Run("якорь поднят до «3» — отношение, а не литерал", func(t *testing.T) {
		bad := clone()
		bad[kn747Anchor] = "3"
		if f := levelTwoEnrollmentFindings(bad); len(f) != len(kn747Guarded) {
			t.Fatalf("ожидалось %d находки (по одной на глагол), получено %d: %v", len(kn747Guarded), len(f), f)
		}
	})
	t.Run("якорь без пола", func(t *testing.T) {
		bad := clone()
		bad[kn747Anchor] = ""
		if f := levelTwoEnrollmentFindings(bad); len(f) != 1 {
			t.Fatalf("ожидалась одна находка, получено %d: %v", len(f), f)
		}
	})
}

// ─── kaname#788: охрана инварианта 2 выводится из писателей, а не выписана ──
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Инвариант 2 приёмки: всякий глагол, ЗАВОДЯЩИЙ способ, чьё предъявление одно
// даёт «2», стоит под полом «2» — и у любого нового такого способа. Перечень
// [kn747Guarded] выписан рукой; эта проба выводит множество заводящих глаголов
// обходом дерева и сверяет его с перечнем: новый глагол-писатель вне перечня —
// красное с координатой, а не молчание.
//
// Вывод — цепочкой узлов разбора, не поиском слова:
//
//  1. ОПЕРАТОР: строковый литерал Go, заводящий строку способа — вставка в
//     таблицу [levelTwoMethodTables] либо её перенос к другой личности
//     (`UPDATE … SET … user_id =`). Литерал в объявлении константы или
//     переменной называет её имя; писатель тогда — функция, читающая имя.
//  2. ЗАМЫКАНИЕ: функция, зовущая писателя по имени, — сама писатель; так
//     цепочка проходит репозиторий, порт и помощников, до метода сценария.
//  3. ГЛАГОЛ: писатель — метод типа `<Глагол>UseCase` в каталоге службы
//     (`internal/apps/kaname/api/<пакет>`); службу называет тот единственный
//     контракт `kaname.cloud.iam.v1`, все методы которого — методы `Handler`
//     того же пакета.
//
// Писатель, цепочка которого не дошла ни до глагола (корень без вызывающих —
// фоновая задача, посев), ни до разобранной службы, — находка: способ «2»,
// заведённый мимо пола, ровно то, что запрещает инвариант.
//
// # ГРАНИЦА ОБХОДА
//
// Модуль целиком, кроме `_test.go`, `testdata`, `vendor` и порождённого
// `pkg/api`. Способ «2» сегодня один — ключ доступа (§1.1 приёмки: «пароль и
// код» требует двух предъявлений в одной сессии по построению и в перечень
// таблиц не входит). Новый такой способ входит в [levelTwoMethodTables] тем
// же изменением, что заводит его таблицу.
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// TestKN788_GateFindsAWriterOutsideTheGuard — синтетическое дерево в
// t.TempDir(): писатель вне перечня краснеет с координатой, законный близнец
// молчит, пустое дерево — «не выполнилось», а не «нарушений нет».

// levelTwoMethodTables — таблицы способов, чьё предъявление одно даёт «2».
var levelTwoMethodTables = []string{"user_access_keys"}

// levelTwoWriterLiteral — литерал, заводящий строку способа «2».
func levelTwoWriterLiteral(lit string) bool {
	for _, tbl := range levelTwoMethodTables {
		name := `(?:"?kaname"?\.)?"?` + regexp.QuoteMeta(tbl) + `"?`
		if regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+` + name + `(?:\s|\(|$)`).MatchString(lit) {
			return true
		}
		if regexp.MustCompile(`(?is)\bUPDATE\s+` + name + `\s+SET\b.*\buser_id\s*=`).MatchString(lit) {
			return true
		}
	}
	return false
}

// kn788Census — объём осмотренного и найденное по звеньям цепочки.
type kn788Census struct {
	files, literals, writers int
	verbs                    []string
}

type kn788Func struct {
	decl *ast.FuncDecl
	file string
	pkg  string // каталог пакета относительно корня
	recv string // имя типа получателя, без звёздочки
}

// levelTwoEnrollmentVerbs — перепись заводящих глаголов дерева root и находки
// сверки с guard. err — предпосылка обхода не выполнена (проверять нечего).
func levelTwoEnrollmentVerbs(root string, guard []string, exempt map[string]string) (kn788Census, []string, error) {
	var c kn788Census
	fset := token.NewFileSet()
	var funcs []kn788Func
	handlers := map[string]map[string]bool{} // пакет → методы Handler
	queryIdents := map[string]bool{}
	writers := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch {
			case d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == ".git" || rel == "pkg/api":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("%s: %w", rel, perr)
		}
		c.files++
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, decl := range f.Decls {
			switch dd := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range dd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						if kn788HasWriterLiteral(v) && i < len(vs.Names) {
							c.literals++
							queryIdents[vs.Names[i].Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				fn := kn788Func{decl: dd, file: rel, pkg: pkg}
				if dd.Recv != nil && len(dd.Recv.List) == 1 {
					fn.recv = kn788RecvName(dd.Recv.List[0].Type)
				}
				if fn.recv == "Handler" {
					if handlers[pkg] == nil {
						handlers[pkg] = map[string]bool{}
					}
					handlers[pkg][dd.Name.Name] = true
				}
				if dd.Body != nil && kn788HasWriterLiteral(dd.Body) {
					c.literals++
					writers[dd.Name.Name] = true
				}
				funcs = append(funcs, fn)
			}
		}
		return nil
	})
	if err != nil {
		return c, nil, err
	}
	if c.files == 0 {
		return c, nil, fmt.Errorf("прочитано файлов 0 — обход не нашёл дерева")
	}
	// Писатель через константу запроса: функция, читающая её имя.
	for _, fn := range funcs {
		if fn.decl.Body != nil && kn788Refers(fn.decl.Body, queryIdents, false) {
			writers[fn.decl.Name.Name] = true
		}
	}
	if len(writers) == 0 {
		return c, nil, fmt.Errorf("писателей строк способа «2» 0 при %d прочитанных файлах — "+
			"перечень таблиц %v не нашёл ни одного оператора", c.files, levelTwoMethodTables)
	}
	// Замыкание по вызовам; метод сценария — конец цепочки.
	isUseCase := func(fn kn788Func) bool {
		return strings.HasPrefix(fn.pkg, "internal/apps/kaname/api/") && strings.HasSuffix(fn.recv, "UseCase") && fn.recv != "UseCase"
	}
	called := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			if fn.decl.Body == nil || !kn788Refers(fn.decl.Body, writers, true) {
				continue
			}
			for name := range kn788Callees(fn.decl.Body, writers) {
				called[name] = true
			}
			if !isUseCase(fn) && !writers[fn.decl.Name.Name] {
				writers[fn.decl.Name.Name] = true
				changed = true
			}
		}
	}
	c.writers = len(writers)
	var findings []string
	verbs := map[string]bool{}
	guarded := map[string]bool{}
	for _, g := range guard {
		guarded[g] = true
	}
	for _, fn := range funcs {
		if fn.decl.Body == nil {
			continue
		}
		pos := fset.Position(fn.decl.Pos())
		where := fmt.Sprintf("%s:%d", fn.file, pos.Line)
		if isUseCase(fn) {
			if !kn788Refers(fn.decl.Body, writers, true) {
				continue
			}
			verb := strings.TrimSuffix(fn.recv, "UseCase")
			fqn, ok := kn788ResolveService(handlers[fn.pkg], verb)
			if !ok {
				findings = append(findings, fmt.Sprintf("%s: сценарий %s заводит способ «2», но службу контракта по "+
					"методам Handler пакета %s не разобрать", where, fn.recv, fn.pkg))
				continue
			}
			verbs[fqn] = true
			continue
		}
		if writers[fn.decl.Name.Name] && !called[fn.decl.Name.Name] {
			findings = append(findings, fmt.Sprintf("%s: %s заводит способ «2», и цепочка не дошла ни до одного "+
				"глагола — способ заведён мимо пола", where, fn.decl.Name.Name))
		}
	}
	for v := range verbs {
		c.verbs = append(c.verbs, v)
		if !guarded[v] {
			findings = append(findings, fmt.Sprintf("%s заводит способ «2», но не назван в охране инварианта 2 "+
				"(kn747Guarded) — его пол не сверяется с «2»", v))
		}
		if _, ok := exempt["/"+v]; ok {
			findings = append(findings, fmt.Sprintf("%s заводит способ «2», но изъят из второго замка "+
				"(PublicGatewayFloorExemptRPCs)", v))
		}
	}
	sort.Strings(c.verbs)
	if len(c.verbs) == 0 && len(findings) == 0 {
		return c, nil, fmt.Errorf("писателей %d, а глаголов 0 и находок 0 — цепочка оборвалась молча", c.writers)
	}
	sort.Strings(findings)
	return c, findings, nil
}

func kn788RecvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return kn788RecvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return kn788RecvName(t.X)
	}
	return ""
}

func kn788HasWriterLiteral(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if lit, ok := x.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && levelTwoWriterLiteral(s) {
				found = true
			}
		}
		return !found
	})
	return found
}

// kn788Refers — тело ссылается на имя из names: вызовом (calls) либо любым
// идентификатором.
func kn788Refers(body ast.Node, names map[string]bool, calls bool) bool {
	if calls {
		return len(kn788Callees(body, names)) > 0
	}
	found := false
	ast.Inspect(body, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

func kn788Callees(body ast.Node, names map[string]bool) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if names[fn.Name] {
				out[fn.Name] = true
			}
		case *ast.SelectorExpr:
			if names[fn.Sel.Name] {
				out[fn.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

// kn788ResolveService — FQN глагола: контракт kaname.cloud.iam.v1 с методом
// verb, все методы которого — методы Handler пакета; из таких — наибольший по
// числу методов, и он обязан быть единственным. Наибольший, а не любой: метод
// с именем `List` есть у многих контрактов, и контракт из одного `List`
// покрывается всяким Handler, у которого есть `List`.
func kn788ResolveService(handler map[string]bool, verb string) (string, bool) {
	if len(handler) == 0 {
		return "", false
	}
	var hits []string
	best := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("kaname.cloud.iam.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			sd := fd.Services().Get(i)
			if sd.Methods().ByName(protoreflect.Name(verb)) == nil {
				continue
			}
			all := true
			for j := 0; j < sd.Methods().Len(); j++ {
				if !handler[string(sd.Methods().Get(j).Name())] {
					all = false
					break
				}
			}
			if !all {
				continue
			}
			switch n := sd.Methods().Len(); {
			case n > best:
				best, hits = n, []string{string(sd.FullName()) + "/" + verb}
			case n == best:
				hits = append(hits, string(sd.FullName())+"/"+verb)
			}
		}
		return true
	})
	if len(hits) != 1 {
		return "", false
	}
	return hits[0], true
}

func TestKN788_EnrollmentVerbsAreDerivedFromWritersAndGuarded(t *testing.T) {
	c, findings, err := levelTwoEnrollmentVerbs(filepath.Join("..", ".."), kn747Guarded, PublicGatewayFloorExemptRPCs())
	t.Logf("перепись: файлов прочитано %d · литералов-писателей %d · писателей в цепочке %d · заводящих глаголов %d %v",
		c.files, c.literals, c.writers, len(c.verbs), c.verbs)
	if err != nil {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("заводящий способ «2» глагол вне охраны инварианта 2 — %d находк(и):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// kn788Tree — синтетическое дерево: служба ключа доступа с Handler на все
// методы контракта и сценарием useCase, зовущим писателя строки ключа.
func kn788Tree(t *testing.T, useCase string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/repo/pg/keys.go", "package pg\n\nconst putKeySQL = `INSERT INTO user_access_keys (id) VALUES ($1)`\n\n"+
		"type W struct{}\n\nfunc (w *W) PutKey() { _ = putKeySQL }\n")
	var h strings.Builder
	h.WriteString("package access_keys\n\ntype Handler struct{}\n\n")
	for _, m := range []string{"BeginRegistration", "FinishRegistration", "List", "Revoke", "BeginAssertion", "FinishAssertion"} {
		fmt.Fprintf(&h, "func (h *Handler) %s() {}\n", m)
	}
	write("internal/apps/kaname/api/access_keys/handler.go", h.String())
	if useCase != "" {
		write("internal/apps/kaname/api/access_keys/uc.go", "package access_keys\n\ntype port interface{ PutKey() }\n\n"+
			"type "+useCase+" struct{ w port }\n\nfunc (uc *"+useCase+") Execute() { uc.w.PutKey() }\n")
	}
	return root
}

func TestKN788_GateFindsAWriterOutsideTheGuard(t *testing.T) {
	t.Run("законный близнец: писатель в охране — молчит", func(t *testing.T) {
		c, f, err := levelTwoEnrollmentVerbs(kn788Tree(t, "FinishRegistrationUseCase"), kn747Guarded, nil)
		if err != nil || len(f) != 0 {
			t.Fatalf("законное дерево: err=%v находки=%v", err, f)
		}
		if len(c.verbs) != 1 || c.verbs[0] != "kaname.cloud.iam.v1.AccessKeyService/FinishRegistration" {
			t.Fatalf("глагол выведен неверно: %v", c.verbs)
		}
	})
	t.Run("новый писатель вне охраны — красное с глаголом", func(t *testing.T) {
		_, f, err := levelTwoEnrollmentVerbs(kn788Tree(t, "ListUseCase"), kn747Guarded, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(f) != 1 || !strings.Contains(f[0], "kaname.cloud.iam.v1.AccessKeyService/List заводит") {
			t.Fatalf("ожидалась одна находка о AccessKeyService/List, получено %v", f)
		}
	})
	t.Run("заводящий глагол изъят из второго замка — красное", func(t *testing.T) {
		exempt := map[string]string{"/kaname.cloud.iam.v1.AccessKeyService/FinishRegistration": "инъекция"}
		_, f, err := levelTwoEnrollmentVerbs(kn788Tree(t, "FinishRegistrationUseCase"), kn747Guarded, exempt)
		if err != nil || len(f) != 1 || !strings.Contains(f[0], "изъят из второго замка") {
			t.Fatalf("ожидалась одна находка об изъятии: err=%v находки=%v", err, f)
		}
	})
	t.Run("писатель без глагола — красное с координатой", func(t *testing.T) {
		_, f, err := levelTwoEnrollmentVerbs(kn788Tree(t, ""), kn747Guarded, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(f) != 1 || !strings.Contains(f[0], "internal/repo/pg/keys.go:") || !strings.Contains(f[0], "мимо пола") {
			t.Fatalf("ожидалась одна находка с координатой писателя, получено %v", f)
		}
	})
	t.Run("пустое дерево — не выполнилось", func(t *testing.T) {
		if _, _, err := levelTwoEnrollmentVerbs(t.TempDir(), kn747Guarded, nil); err == nil {
			t.Fatal("пустой обход объявлен зелёным")
		}
	})
	t.Run("литерал без писателя — не выполнилось", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.go"), []byte("package a\n\nfunc F() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := levelTwoEnrollmentVerbs(root, kn747Guarded, nil); err == nil {
			t.Fatal("обход без единого писателя объявлен зелёным")
		}
	})
}

// TestKN788_WriterLiteralKnowsEveryLawfulForm — распознаватель оператора по
// каждой законной форме записи и законные близнецы, которые писателем не
// являются.
func TestKN788_WriterLiteralKnowsEveryLawfulForm(t *testing.T) {
	for _, s := range []string{
		"INSERT INTO user_access_keys (id) VALUES ($1)",
		"\n\t\tinsert into kaname.user_access_keys(id) values ($1)",
		`INSERT INTO "kaname"."user_access_keys" (id) VALUES ($1)`,
		"UPDATE user_access_keys SET user_id = $2 WHERE id = $1",
	} {
		if !levelTwoWriterLiteral(s) {
			t.Errorf("писатель не распознан: %q", s)
		}
	}
	for _, s := range []string{
		"SELECT id FROM user_access_keys WHERE user_id = $1",
		"DELETE FROM user_access_keys WHERE user_id = $1",
		"UPDATE user_access_keys SET last_used_at = $2 WHERE id = $1",
		"INSERT INTO user_access_keys_archive (id) VALUES ($1)",
		"INSERT INTO access_key_challenges (challenge) VALUES ($1)",
	} {
		if levelTwoWriterLiteral(s) {
			t.Errorf("не писатель объявлен писателем: %q", s)
		}
	}
}
