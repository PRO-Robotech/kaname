// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fieldpaths_internal_test.go — СТОРОНА СТРУКТУР для согласия схемы и структур
// (MOD-MF-21, приёмка §5.6).
//
// # Что здесь есть и чего здесь НЕТ
//
// MOD-MF-21 требует РАВЕНСТВА двух множеств: ключей опубликованной схемы и полей
// Go-структур. Здесь заведена и доказана ровно ПОЛОВИНА — сторона структур:
// перечень путей, ВЫВЕДЕННЫЙ разбором типов, а не выписанный. Само равенство
// утверждает schemaagreement_internal_test.go, и он берёт эту половину отсюда.
//
// Прежняя редакция этой шапки говорила «схемы в дереве ещё нет». Она была верна
// на своей полосе и перестала быть верной двумя коммитами позже — схема лежит в
// services/iam/schema/. Комментарий не исполняется, поэтому ни один прогон такого
// расхождения не ловит; правится оно чтением.
//
// Выписанный перечень не сдвинулся бы от нового поля и продолжал бы сторожить
// прежние — то есть проба перестала бы проверять ровно то свойство, ради которого
// написана. Полоса схемы берёт fieldPaths() отсюда и сличает множества.
package manifest

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// mustReadFixture — настоящий манифест, которым пользуются пробы этого пакета.
func mustReadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/vpc.seed-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}
	return data
}

// fieldPaths — точечные пути всех полей манифеста, выведенные разбором типов.
// Элемент списка обозначается суффиксом `[]`, чтобы `seed.groups` (сам список) и
// `seed.groups[].name` (поле элемента) были РАЗНЫМИ путями: схема описывает их
// порознь, и склейка скрыла бы расхождение по одному из двух.
func fieldPaths() []string {
	var out []string
	walkFieldPaths(reflect.TypeOf(Manifest{}), "", &out)
	sort.Strings(out)
	return out
}

// untaggedFields — экспортированные поля без явного yaml-тега. Такое поле имя
// ключа не объявляет, а НАСЛЕДУЕТ у правила библиотеки — и разойдётся со схемой
// молча при первом же переименовании поля Go.
func untaggedFields() []string {
	var out []string
	walkUntagged(reflect.TypeOf(Manifest{}), "", &out)
	sort.Strings(out)
	return out
}

func yamlKey(f reflect.StructField) (string, bool) {
	tag, ok := f.Tag.Lookup("yaml")
	if !ok {
		return "", false
	}
	name := strings.Split(tag, ",")[0]
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}

// elemType — тип, чьи поля становятся продолжением пути, и суффикс пути.
//
// Форм у составного значения ТРИ, и распознаватель обязан знать все: указатель
// (путь не меняется), список (суффикс `[]`) и КАРТА (суффикс `{}`). Форма, о
// которой обход не знает, не даёт ни красного, ни зелёного — она МОЛЧИТ, и всё
// записанное в ней оказывается вне наблюдения (`testing.md` §«Гейт на класс»,
// п. 7). Карта заведена вместе с разделом `deprecatedVerbs`, чей ключ — само имя
// глагола; без неё четыре ключа его записи не сличались бы со схемой ВОВСЕ.
func elemType(t reflect.Type) (reflect.Type, string) {
	suffix := ""
	for {
		switch t.Kind() {
		case reflect.Pointer:
			t = t.Elem()
		case reflect.Slice, reflect.Array:
			suffix += "[]"
			t = t.Elem()
		case reflect.Map:
			suffix += "{}"
			t = t.Elem()
		default:
			return t, suffix
		}
	}
}

func walkFieldPaths(t reflect.Type, prefix string, out *[]string) {
	t, _ = elemType(t)
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, ok := yamlKey(f)
		if !ok {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		*out = append(*out, path)
		inner, suffix := elemType(f.Type)
		walkFieldPaths(inner, path+suffix, out)
	}
}

func walkUntagged(t reflect.Type, prefix string, out *[]string) {
	t, _ = elemType(t)
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, ok := yamlKey(f)
		if !ok {
			*out = append(*out, prefix+t.Name()+"."+f.Name)
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		inner, suffix := elemType(f.Type)
		walkUntagged(inner, path+suffix, out)
	}
}

// TestMODMF21StructSideFieldPathsAreDerivedNotWritten — сторона структур выведена
// разбором типов и доходит до всех глубин.
//
// Проверяется не совпадение с ожидаемым списком (его нет и не должно быть здесь:
// второй перечень об одном предмете — ровно то, против чего MOD-MF-21 заведена),
// а свойства обхода: он непуст, спускается на глубину 3, не дублирует путей.
func TestMODMF21StructSideFieldPathsAreDerivedNotWritten(t *testing.T) {
	paths := fieldPaths()
	if len(paths) == 0 {
		t.Fatalf("обход типов не дал ни одного пути — сличать полосе схемы будет нечего")
	}
	t.Logf("перепись: путей полей структур %d", len(paths))

	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			t.Errorf("путь %q встречается дважды — множество перестало быть множеством", p)
		}
		seen[p] = true
	}

	// Точечный положительный контроль: обход обязан доходить до глубины 3 и
	// различать список от поля его элемента.
	for _, want := range []string{
		"apiVersion",
		"module",
		"seed",
		"seed.serviceAccounts",
		"seed.serviceAccounts[].description",
		"seed.accessBindings[].subjects[].type",
		"seed.joins[].serviceAccount.name",
		"seed.joins[].why",
		// Три раздела #1778: список ресурсов, обе формы глагола и КАРТА
		// устаревших глаголов — форма, которой обход не знал до неё.
		"resources[].verbs[].class",
		"resources[].relations[].definition",
		"roles[].rules[].matchLabels",
		"roles[].tier.tierType",
		"deprecatedVerbs{}.removeWhen",
	} {
		if !seen[want] {
			t.Errorf("обход не дошёл до пути %q: %v", want, paths)
		}
	}
}

// TestMODMF21EveryFieldDeclaresItsKeyExplicitly — имя ключа ОБЪЯВЛЕНО тегом, а не
// унаследовано у правила библиотеки.
//
// Без тега `gopkg.in/yaml.v3` берёт имя поля Go в нижнем регистре: `RoleID` стал
// бы ключом `roleid`, а не `roleId`, и расхождение со схемой не показала бы ни
// сборка, ни разбор законного документа — оба ответили бы «валидно».
func TestMODMF21EveryFieldDeclaresItsKeyExplicitly(t *testing.T) {
	untagged := untaggedFields()
	if len(untagged) != 0 {
		t.Fatalf("полей без явного yaml-тега %d: %v", len(untagged), untagged)
	}
	t.Logf("перепись: полей без явного тега 0 · путей всего %d", len(fieldPaths()))
}
