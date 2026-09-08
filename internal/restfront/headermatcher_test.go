// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// headermatcher_test.go — гейт и проба сужающего сопоставителя заголовков.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Право говорить за пользователя есть свойство ОТПРАВИТЕЛЯ, а не запроса. Фронт
// отправителем личности не является и им становиться не должен: он передаёт то,
// что предъявил арендатор, а решает о личности звено слушателя.
//
// Умолчание библиотеки этого не обеспечивает. Измерено вызовом (см. пробу
// ниже): при умолчании до слушателя доезжают ОБЕ формы имени личности — голая
// не проходит, но МОСТОВАЯ (с префиксом, который маршрутизатор снимает сам)
// пересекает границу наравне с удостоверением. То есть достаточно прислать
// заголовок под префиксом, чтобы назвать себя кем угодно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА УТВЕРЖДЕНИЯ, И ОНИ РАЗНЫЕ
//
//  1. ГЕЙТ читает ОБЪЯВЛЕНИЕ: каждый мультиплексор пакета собран с сужающим
//     сопоставителем. Свойство дерева, и держится оно обходом, а не пробой:
//     проба зелена ровно для того мультиплексора, который она построила.
//  2. ПРОБА читает ИСХОД: что реально доезжает до слушателя. Она подаёт обе
//     формы имени личности и требует, чтобы ни одна не прошла, а законный
//     близнец — удостоверение — прошёл. Односторонняя проба зеленела бы на
//     сопоставителе, отвергающем всё, включая удостоверение, — то есть на
//     фронте, не работающем вовсе.

package restfront

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ (KAN-REST-15). Каждый мультиплексор собран с сужающим сопоставителем.

// muxConstructions обходит каталог и возвращает по каждому вызову
// `runtime.NewServeMux` координату и признак «сужающий сопоставитель передан».
//
// Каталог принимается доводом, а не берётся из рабочего: тем же вызовом
// инъекция подаёт синтетический вход, меняя ровно один факт.
func muxConstructions(dir string) (calls []string, narrowed []bool, err error) {
	fset := token.NewFileSet()
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return nil, nil, rerr
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, nil, perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, isSel := call.Fun.(*ast.SelectorExpr)
			if !isSel || sel.Sel.Name != "NewServeMux" {
				return true
			}
			pkg, isIdent := sel.X.(*ast.Ident)
			if !isIdent || pkg.Name != "runtime" {
				return true
			}
			has := false
			for _, arg := range call.Args {
				inner, isCall := arg.(*ast.CallExpr)
				if !isCall {
					continue
				}
				if id, isID := inner.Fun.(*ast.Ident); isID && id.Name == narrowingOptionFunc {
					has = true
				}
			}
			calls = append(calls, name+":"+fsetLine(fset, call.Pos()))
			narrowed = append(narrowed, has)
			return true
		})
	}
	return calls, narrowed, nil
}

// narrowingOptionFunc — имя объявления, дающего мультиплексору сужающий
// сопоставитель. ОДНО на пакет: второе объявление того же предмета разошлось бы
// с первым молча, и разошлось бы именно там, где это не видно.
const narrowingOptionFunc = "narrowingHeaderMatcherOption"

func fsetLine(fset *token.FileSet, p token.Pos) string {
	return strings.TrimPrefix(fset.Position(p).String(), fset.Position(p).Filename+":")
}

func TestEveryMuxIsBuiltWithTheNarrowingHeaderMatcher(t *testing.T) {
	calls, narrowed, err := muxConstructions(restFrontDir(t))
	if err != nil {
		t.Fatalf("обход пакета не состоялся: %v", err)
	}

	var bare []string
	for i, ok := range narrowed {
		if !ok {
			bare = append(bare, calls[i])
		}
	}

	t.Logf("осмотрено: мультиплексоров собрано в пакете %d, из них с сужающим "+
		"сопоставителем %d, с умолчанием библиотеки %d",
		len(calls), len(calls)-len(bare), len(bare))

	if len(calls) == 0 {
		t.Fatal("в пакете не собрано ни одного мультиплексора — обход пуст, вердикт " +
			"беспредметен: «все собраны сужающими» верно тривиально, когда их нет")
	}
	if len(bare) > 0 {
		t.Errorf("мультиплексоры собраны с умолчанием библиотеки: %s.\n"+
			"Умолчание пропускает имя личности в МОСТОВОЙ форме — вызывающий назовёт "+
			"себя кем угодно, прислав заголовок под префиксом. Соберите его с %s()",
			strings.Join(bare, ", "), narrowingOptionFunc)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ПРОБА ИСХОДА. Что доезжает до слушателя.

// principalMetadataKeys — ключи, которыми платформа переносит личность.
//
// БЕРУТСЯ У ФУНДАМЕНТА, а не переписываются. Пока они стояли здесь литералами,
// это было ВТОРОЕ объявление одного предмета — и оно уже разошлось с первым:
// третьим ключом значилось `x-kacho-principal-display`, которого не существует
// (настоящий — `…-display-name`). Проба при этом оставалась зелёной: сужающий
// сопоставитель отбрасывает пространство имён целиком, поэтому она честно
// утверждала, что несуществующий ключ не доезжает. Ровно тот класс, ради
// которого объявление сведено в одно место.
var principalMetadataKeys = []string{
	grpcsrv.MDKeyPrincipalID,
	grpcsrv.MDKeyPrincipalType,
	grpcsrv.MDKeyPrincipalDisplay,
}

// metadataThroughMux прогоняет запрос через мультиплексор и возвращает
// метаданные, которые ушли бы слушателю.
func metadataThroughMux(t *testing.T, mux *runtime.ServeMux, hdrs map[string]string) metadata.MD {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/accounts/acc-probe", nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	ctx, err := runtime.AnnotateContext(req.Context(), mux, req,
		"/kaname.cloud.iam.v1.AccountService/Get")
	if err != nil {
		t.Fatalf("аннотирование запроса не состоялось: %v", err)
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("исходящих метаданных нет вовсе — проба ничего не измерила")
	}
	return md
}

func TestNarrowingMatcherDropsBothFormsAndKeepsTheCredential(t *testing.T) {
	const credential = "Bearer probe-credential"
	hdrs := map[string]string{
		"Authorization": credential,
	}
	// Обе формы, которыми вызывающий мог бы назвать себя сам. Мостовая
	// существует НЕЗАВИСИМО от голой и умолчанием пропускается — отсутствия
	// голой недостаточно.
	for _, k := range principalMetadataKeys {
		hdrs[http.CanonicalHeaderKey(k)] = "usr-someone-else"
		hdrs["Grpc-Metadata-"+http.CanonicalHeaderKey(k)] = "usr-someone-else"
	}

	// Мультиплексор берётся у КОНСТРУКТОРА ПАКЕТА, а не собирается пробой: иначе
	// она измеряла бы тот фронт, который построила сама, и оставалась зелёной
	// при любом настоящем.
	md := metadataThroughMux(t, newMux(), hdrs)

	// ЗАКОННЫЙ БЛИЗНЕЦ. Без него проба зеленела бы на сопоставителе, который
	// отвергает всё: фронт был бы «безопасен» и неработоспособен разом.
	got := md.Get("authorization")
	if len(got) != 1 || got[0] != credential {
		t.Errorf("удостоверение не доехало до слушателя ровно одним значением: %v.\n"+
			"Ключ обязан совпадать с тем, под которым его читает проверяющий, и нести "+
			"РОВНО ОДНО значение: два предъявления читаются как неоднозначность о том, "+
			"кто звонит, и отвергаются — то есть фронт не работал бы ни на одном запросе", got)
	}

	var leaked []string
	for k := range md {
		for _, p := range principalMetadataKeys {
			if strings.Contains(strings.ToLower(k), p) {
				leaked = append(leaked, k+"="+strings.Join(md.Get(k), ","))
			}
		}
	}
	sort.Strings(leaked)

	t.Logf("осмотрено: заголовков подано %d (из них форм имени личности %d), "+
		"ключей метаданных дошло %d, из них несущих личность %d",
		len(hdrs), len(principalMetadataKeys)*2, len(md), len(leaked))

	if len(leaked) > 0 {
		t.Errorf("до слушателя доехало имя личности, названное САМИМ вызывающим: %s.\n"+
			"Фронт отправителем личности не является: он передаёт предъявленное "+
			"удостоверение, а кто звонит — решает звено слушателя",
			strings.Join(leaked, ", "))
	}
}

// TestLibraryDefaultWouldLetThePrincipalThrough — измерение, на котором стоит
// решение, а не проверка нашего кода.
//
// Оно здесь потому, что предпосылка гейта — свойство ЧУЖОЙ библиотеки, и её
// смена обязана ронять проверку, а не тихо обесценивать её. Перестань умолчание
// пропускать мостовую форму — эта проба покраснеет и скажет, что сужение больше
// не нужно; сегодня она зелена, и сужение обосновано.
func TestLibraryDefaultWouldLetThePrincipalThrough(t *testing.T) {
	hdrs := map[string]string{"Authorization": "Bearer probe-credential"}
	for _, k := range principalMetadataKeys {
		hdrs["Grpc-Metadata-"+http.CanonicalHeaderKey(k)] = "usr-someone-else"
	}

	md := metadataThroughMux(t, runtime.NewServeMux(), hdrs)

	var passed []string
	for _, p := range principalMetadataKeys {
		if len(md.Get(p)) > 0 {
			passed = append(passed, p)
		}
	}
	t.Logf("осмотрено: умолчание библиотеки пропустило форм имени личности %d из %d",
		len(passed), len(principalMetadataKeys))

	if len(passed) == 0 {
		t.Fatal("умолчание библиотеки больше не пропускает имя личности в мостовой форме.\n" +
			"Это не поломка, а смена предпосылки: сужающий сопоставитель заводился " +
			"именно против неё. Перемерьте основание решения, прежде чем менять код")
	}
}
