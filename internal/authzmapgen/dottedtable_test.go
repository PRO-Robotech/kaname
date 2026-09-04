// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmapgen_test

// dottedtable_test.go — ВТОРАЯ таблица каталога порождается из манифестов
// (задача #1092).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СУДИТСЯ
//
// `objectTypes` — словарь КАТАЛОГА (`<модуль>.<ресурс>`) в словарь МОДЕЛИ ПРАВ
// (`vpc_network`). Он жил рукописным литералом рядом с манифестом, который тот
// же факт объявляет: имя ресурса и его `objectType` стоят в одной записи
// манифеста. Два места об одном предмете обязаны совпадать, и совпадение
// стерегли гейты — то есть расхождение ловилось ПОСЛЕ внесения.
//
// Здесь оно становится невыразимым: таблицу пишет производитель, объявить
// ресурс — значит вписать его в манифест модуля.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДИТСЯ РЕНДЕР, А НЕ ПАКЕТ ПРОДУКТА
//
// Пакет продукта судит гейт свежести (побайтово) и перепись таблиц типов (по
// составу). Здесь спрашивается ДРУГОЕ: что производитель вообще эмитит эту
// таблицу и эмитит её ПОЛНОСТЬЮ. Проба по продукту на это не отвечает — она
// зелена и тогда, когда таблица приехала туда рукой.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmapgen"
)

// mapLiteralOf — содержимое package-level карты `string → string` порождённого
// текста, опознанной ПО ИМЕНИ.
//
// Имя здесь законно, в отличие от переписи таблиц типов: там предмет — «сколько
// таблиц в пакете», и имя стояло бы ещё и в прозе, объясняющей остаток. Тут
// предмет — «эмитит ли ПРОИЗВОДИТЕЛЬ именно эту таблицу», и вопрос по имени
// и есть вопрос по существу. Разбор, а не подстрока: объявление в комментарии
// узлом не является.
func mapLiteralOf(t *testing.T, src []byte, name string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tables_gen.go", src, 0)
	if err != nil {
		t.Fatalf("порождённый текст не разбирается (%v) — значит он и не компилируется", err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, id := range vs.Names {
				if id.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					t.Fatalf("%s объявлена не составным литералом", name)
				}
				out := map[string]string{}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						t.Fatalf("%s: элемент не пара ключ-значение", name)
					}
					k, kerr := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
					v, verr := strconv.Unquote(kv.Value.(*ast.BasicLit).Value)
					if kerr != nil || verr != nil {
						t.Fatalf("%s: пара не разбирается", name)
					}
					out[k] = v
				}
				return out
			}
		}
	}
	return nil
}

// TestRenderedFileCarriesTheDottedNameTable — производитель эмитит `objectTypes`
// и эмитит его ЦЕЛИКОМ.
//
// Проверяется равенство, а не включение: таблица, потерявшая тип, выглядит целой,
// а потерянный тип не резолвится каталогом — вопрос о нём не задаётся вовсе, и
// проверка выглядит пройденной.
func TestRenderedFileCarriesTheDottedNameTable(t *testing.T) {
	tables, err := authzmapgen.Collect(repoRoot)
	if err != nil {
		t.Fatalf("обход манифестов не состоялся (%v) — предпосылка пробы исчезла, "+
			"а не дерево стало чистым", err)
	}
	body, err := authzmapgen.Render(tables)
	if err != nil {
		t.Fatalf("рендер: %v", err)
	}

	want := map[string]string{}
	for _, e := range tables.Entries {
		want[e.Dotted] = e.ObjectType
	}
	if len(want) == 0 {
		t.Fatal("обход не дал ни одной записи — сверять было бы не с чем")
	}

	got := mapLiteralOf(t, body, "objectTypes")
	t.Logf("перепись: записей манифестов %d, в порождённой таблице %d", len(want), len(got))
	if got == nil {
		t.Fatalf("производитель НЕ эмитит objectTypes — словарь имён остаётся вторым "+
			"местом об одном предмете (записей манифестов %d)", len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("манифесты объявляют %s → %s, порождено %q", k, v, got[k])
		}
	}
	for k, v := range got {
		if want[k] != v {
			t.Errorf("порождено %s → %s, манифесты такого не объявляют", k, v)
		}
	}
}

// TestExportedCatalogIsTheManifestTree — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на наблюдаемом:
// то, что пакет ОТДАЁТ вызывающим, есть в точности то, что объявили манифесты.
//
// Проба выше судит текст производителя, эта — экспортированную поверхность
// продукта. Различие не педантское: текст, отданный производителем и не
// доехавший до продукта (либо доехавший рядом со вторым, рукописным объявлением),
// прошёл бы первую и не проходит эту.
func TestExportedCatalogIsTheManifestTree(t *testing.T) {
	tables, err := authzmapgen.Collect(repoRoot)
	if err != nil {
		t.Fatalf("обход манифестов не состоялся (%v)", err)
	}

	exported := map[string]string{}
	for _, c := range authzmap.Catalog() {
		fga, ok := authzmap.ObjectType(c.Module, c.Resource)
		if !ok {
			t.Fatalf("каталог отдаёт пару %s.%s, а тип по ней не резолвится", c.Module, c.Resource)
		}
		exported[c.Module+"."+c.Resource] = fga
	}
	if len(exported) == 0 {
		t.Fatal("экспортированный каталог пуст — сверять было бы не с чем")
	}
	t.Logf("перепись: манифесты объявляют %d записей, каталог отдаёт %d",
		len(tables.Entries), len(exported))

	for _, e := range tables.Entries {
		if exported[e.Dotted] != e.ObjectType {
			t.Errorf("манифесты объявляют %s → %s, каталог отдаёт %q",
				e.Dotted, e.ObjectType, exported[e.Dotted])
		}
		delete(exported, e.Dotted)
	}
	for k, v := range exported {
		t.Errorf("каталог отдаёт %s → %s, манифесты такого не объявляют — запись "+
			"пришла не из дерева", k, v)
	}
}
