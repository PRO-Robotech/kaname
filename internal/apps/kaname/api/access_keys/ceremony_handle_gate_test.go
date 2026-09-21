// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// ceremony_handle_gate_test.go — ЗАМОК на рукоятку по дереву пакета.
//
// # Зачем гейт, если поведенческая проба уже есть
//
// Поведенческая проба (`irreversible_facts_test.go`) судит ЗНАЧЕНИЕ, легшее в
// строку. Здесь судится ИСХОДНИК: в композитном литерале `iamv1.CeremonyUser`
// поле `Id` — рукоятка, а соседнее `Name` — адрес почты, законно. Расстояние
// между ними — один символ правки, и автор, подставивший `out.User.Email` в
// `Id`, получил бы 64-байтовую рукоятку только при дополнении — поведенческая
// проба на коротком адресе краснеет, на дополненном могла бы и нет. Поэтому
// предмет опознаётся УЗЛОМ РАЗБОРА (`gate-judges-ast-node`), а не поиском слова.
//
// # Чем доказана способность падать
//
// Инъекцией в обе стороны на синтетике в `t.TempDir()`: дефект (`Id` из имени
// человека) находится и называет координату, законный близнец (`Id` из
// рукоятки) молчит. Перепись печатается отдельно от находок, пустой обход —
// отказ, а не зелёное.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ceremonyUserLiteral — имя типа, чьё поле `Id` несёт рукоятку церемонии.
const ceremonyUserLiteral = "CeremonyUser"

// handleCarrierField — единственное законное имя поля-носителя: рукоятка
// приезжает в транспорт готовой величиной сценария, а не собирается на месте.
const handleCarrierField = "UserHandle"

// ceremonyUserIdFindings — находки одного разобранного файла: композитные
// литералы `*.CeremonyUser`, чьё поле `Id` присвоено НЕ селектором `<x>.UserHandle`.
// Возвращает также число осмотренных литералов — перепись отдельно от находок.
func ceremonyUserIdFindings(fset *token.FileSet, file *ast.File) (findings []string, literals int) {
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != ceremonyUserLiteral {
			return true
		}
		literals++
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Id" {
				continue
			}
			carrier, ok := kv.Value.(*ast.SelectorExpr)
			if ok && carrier.Sel != nil && carrier.Sel.Name == handleCarrierField {
				continue
			}
			findings = append(findings, fset.Position(kv.Value.Pos()).String()+
				": поле Id литерала "+ceremonyUserLiteral+" присвоено не рукояткой (ждали <x>."+handleCarrierField+")")
		}
		return true
	})
	return findings, literals
}

// TestAccessKey_CeremonyUserIdIsAssignedOnlyTheMintedHandle — обход пакета:
// рукоятка доезжает до церемонии носителем, и ни один литерал не собирает её
// из имени человека.
func TestAccessKey_CeremonyUserIdIsAssignedOnlyTheMintedHandle(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(moduleRootOf(t), "internal", "apps", "kaname", "api", "access_keys")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	var (
		findings  []string
		literals  int
		filesRead int
	)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		filesRead++
		f, n := ceremonyUserIdFindings(fset, file)
		findings = append(findings, f...)
		literals += n
	}
	t.Logf("перепись: файлов прочитано %d · литералов %s осмотрено %d · находок %d",
		filesRead, ceremonyUserLiteral, literals, len(findings))
	require.NotZero(t, filesRead, "предпосылка гейта: не-тестовых файлов пакета ноль — обходить нечего")
	require.NotZero(t, literals, "предпосылка гейта: литералов %s ноль — запрет судить не о чем", ceremonyUserLiteral)
	require.Empty(t, findings, "рукоятка церемонии собрана не из носителя:\n%s", strings.Join(findings, "\n"))
}

// TestAccessKey_CeremonyUserIdGateIsProvenByInjection — способность гейта
// падать: дефект найден и назван координатой, законный близнец той же формы —
// молчит.
func TestAccessKey_CeremonyUserIdGateIsProvenByInjection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		value string
		want  int
	}{
		{"дефект: адрес почты вместо рукоятки", "[]byte(out.User.Email)", 1},
		{"дефект: платформенный id вместо рукоятки", "[]byte(in.UserID)", 1},
		{"законный близнец: носитель рукоятки", "out.UserHandle", 0},
		{"законный близнец: носитель другого приёмника", "ch.UserHandle", 0},
	} {
		src := "package p\n\nfunc f() any {\n\treturn &iamv1." + ceremonyUserLiteral +
			"{Id: " + tc.value + ", Name: string(out.User.Email)}\n}\n"
		dir := t.TempDir()
		path := filepath.Join(dir, "injected.go")
		require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		findings, literals := ceremonyUserIdFindings(fset, file)
		require.Equal(t, 1, literals, "%s: инъекция обязана нести ровно один литерал", tc.name)
		require.Len(t, findings, tc.want, "%s: находок %d\n%s", tc.name, len(findings), strings.Join(findings, "\n"))
		if tc.want > 0 {
			require.Contains(t, findings[0], path, "%s: находка обязана называть координату", tc.name)
		}
	}
}
