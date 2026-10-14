// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// ceremony_handle_gate_test.go — держатель Ф13-33 (P): значение рукоятки
// церемонии берётся только у НОСИТЕЛЯ рукоятки (приёмка
// `passwordless-login-with-access-key.md`, Р3 редакции 9, §5 Ф13-33).
//
// # Почему гейт по дереву, если поведенческие пробы есть
//
// Поведенческие пробы (`ceremony_handle_test.go`) судят ЛЕГШЕЕ значение. Здесь
// судится ИСТОЧНИК: в литерале `iamv1.CeremonyUser` поле `Id` — рукоятка, а
// соседнее `Name` — адрес почты, законно. Расстояние между ними — один символ
// правки, и подставленный адрес дал бы значение нужной длины только при
// дополнении: поведенческая проба на коротком адресе краснеет, на дополненном
// могла бы и не покраснеть. Поэтому предмет опознаётся УЗЛОМ РАЗБОРА, а не
// поиском слова.
//
// # Три правила, и каждое закрывает свою дверь
//
//   - литерал церемонии: поле `Id` литерала `CeremonyUser` присвоено селектором
//     `<x>.UserHandle` — значением, приехавшим из сценария готовым;
//   - приёмники рукоятки в пакете церемонии: поле `UserHandle` литералов
//     `BeginRegistrationOutput` и `AccessKey` и любое присваивание
//     `<x>.UserHandle = …` получают байты НОСИТЕЛЯ — вызов `<x>.Bytes()`
//     (`domain.CeremonyHandle` непрозрачен: байты наружу только так);
//   - восстановление носителя из сохранённых байтов
//     (`domain.RestoreCeremonyHandle`) зовёт только адаптер хранилища
//     (`internal/repo/`): иначе носитель собирался бы из чего угодно, и первые
//     два правила судили бы обёртку, а не значение.
//
// Производителей носителя без входа — один (`domain.NewCeremonyHandle`), и
// значение, выводимое из чего бы то ни было о человеке, его подписью не
// выражается.
//
// # Чем доказана способность падать
//
// Инъекцией в обе стороны на синтетике в `t.TempDir()`: отвергнутый исход Р3
// стоит среди входов дословно — значение из платформенного `id` и из адреса
// почты находятся и называют координату; законный близнец (значение у
// носителя) молчит, в том числе у второго приёмника. Перепись печатается
// отдельно от находок; пустой обход — отказ, а не «ноль находок».

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// ceremonyUserLiteral — тип, чьё поле `Id` несёт рукоятку церемонии.
	ceremonyUserLiteral = "CeremonyUser"
	// handleCarrierField — имя поля-носителя рукоятки у сценария.
	handleCarrierField = "UserHandle"
	// handleBytesMethod — единственный выход байтов носителя.
	handleBytesMethod = "Bytes"
	// handleRestoreFunc — восстановление носителя из сохранённых байтов.
	handleRestoreFunc = "RestoreCeremonyHandle"
)

// handleReceiverLiterals — литералы, чьё поле `UserHandle` получает
// ЧЕКАНЕННУЮ рукоятку. `FinishAssertionInput` сюда не входит: его рукоятка —
// ПРЕДЪЯВЛЕННАЯ клиентом, и её источник — транспорт.
var handleReceiverLiterals = map[string]bool{"BeginRegistrationOutput": true, "AccessKey": true}

// handleCensus — объём осмотренного, печатается отдельно от находок.
type handleCensus struct {
	files, ceremonyLiterals, receivers, restoreCalls int
}

// typeName — имя типа литерала: `T` либо `pkg.T`.
func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// isCarrierSelector — `<x>.UserHandle`.
func isCarrierSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == handleCarrierField
}

// isCarrierBytes — `<x>.Bytes()` без аргументов.
func isCarrierBytes(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == handleBytesMethod
}

// ceremonyPackageFindings — первые два правила над файлом пакета церемонии.
func ceremonyPackageFindings(fset *token.FileSet, file *ast.File, c *handleCensus) (findings []string) {
	at := func(n ast.Node) string { return fset.Position(n.Pos()).String() }
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			name := typeName(x.Type)
			switch {
			case name == ceremonyUserLiteral:
				c.ceremonyLiterals++
				for _, elt := range x.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Id" && !isCarrierSelector(kv.Value) {
						findings = append(findings, at(kv.Value)+": поле Id литерала "+ceremonyUserLiteral+
							" присвоено не носителем рукоятки (ждали <x>."+handleCarrierField+")")
					}
				}
			case handleReceiverLiterals[name]:
				c.receivers++
				for _, elt := range x.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == handleCarrierField && !isCarrierBytes(kv.Value) {
						findings = append(findings, at(kv.Value)+": поле "+handleCarrierField+" литерала "+name+
							" получает не байты носителя рукоятки (ждали <x>."+handleBytesMethod+"())")
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if !isCarrierSelector(lhs) || i >= len(x.Rhs) {
					continue
				}
				c.receivers++
				if !isCarrierBytes(x.Rhs[i]) {
					findings = append(findings, at(x.Rhs[i])+": присваивание <x>."+handleCarrierField+
						" получает не байты носителя рукоятки (ждали <x>."+handleBytesMethod+"())")
				}
			}
		}
		return true
	})
	return findings
}

// restoreFindings — третье правило: `RestoreCeremonyHandle` вне адаптера
// хранилища. `rel` — путь файла от корня модуля через `/`.
func restoreFindings(fset *token.FileSet, file *ast.File, rel string, c *handleCensus) (findings []string) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || typeName(call.Fun) != handleRestoreFunc {
			return true
		}
		c.restoreCalls++
		if !strings.HasPrefix(rel, "internal/repo/") {
			findings = append(findings, fset.Position(call.Pos()).String()+": "+handleRestoreFunc+
				" вне адаптера хранилища — носитель рукоятки собирается только из сохранённого значения")
		}
		return true
	})
	return findings
}

// isProductionGo — не-тестовый Go-файл.
func isProductionGo(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// TestAccessKey_F13_33_CeremonyHandleComesOnlyFromItsCarrier — обход дерева.
func TestAccessKey_F13_33_CeremonyHandleComesOnlyFromItsCarrier(t *testing.T) {
	t.Parallel()
	root := moduleRootOf(t)
	fset := token.NewFileSet()
	var (
		c        handleCensus
		findings []string
	)

	pkgDir := filepath.Join(root, "internal", "apps", "kaname", "api", "access_keys")
	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !isProductionGo(e.Name()) {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(pkgDir, e.Name()), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		c.files++
		findings = append(findings, ceremonyPackageFindings(fset, file, &c)...)
	}

	moduleFiles := 0
	for _, top := range []string{"internal", "cmd"} {
		require.NoError(t, filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isProductionGo(d.Name()) {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			moduleFiles++
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			findings = append(findings, restoreFindings(fset, file, filepath.ToSlash(rel), &c)...)
			return nil
		}))
	}

	t.Logf("перепись: файлов пакета церемонии %d · литералов %s %d · приёмников рукоятки %d · "+
		"файлов модуля %d · вызовов %s %d · находок %d",
		c.files, ceremonyUserLiteral, c.ceremonyLiterals, c.receivers, moduleFiles, handleRestoreFunc, c.restoreCalls, len(findings))
	require.NotZero(t, c.files, "предпосылка: не-тестовых файлов пакета церемонии ноль — обходить нечего")
	require.NotZero(t, c.ceremonyLiterals, "предпосылка: литералов %s ноль — судить не о чем", ceremonyUserLiteral)
	require.NotZero(t, c.receivers, "предпосылка: приёмников рукоятки ноль — второе правило судить не о чем")
	require.NotZero(t, moduleFiles, "предпосылка: не-тестовых файлов модуля ноль")
	require.Empty(t, findings, "рукоятка церемонии взята не у носителя:\n%s", strings.Join(findings, "\n"))
}

// TestAccessKey_F13_33_CeremonyHandleGateIsProvenByInjection — способность
// гейта падать: каждое правило находит дефект с координатой, законный близнец
// той же формы молчит.
func TestAccessKey_F13_33_CeremonyHandleGateIsProvenByInjection(t *testing.T) {
	t.Parallel()
	parse := func(t *testing.T, body string) (*token.FileSet, *ast.File, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "injected.go")
		require.NoError(t, os.WriteFile(path, []byte("package p\n\n"+body), 0o600))
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		return fset, file, path
	}
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"литерал церемонии: платформенный id", "func f() any {\n\treturn &iamv1.CeremonyUser{Id: []byte(in.UserID), Name: string(out.User.Email)}\n}\n", 1},
		{"литерал церемонии: адрес почты", "func f() any {\n\treturn &iamv1.CeremonyUser{Id: []byte(out.User.Email), Name: string(out.User.Email)}\n}\n", 1},
		{"литерал церемонии: близнец — носитель", "func f() any {\n\treturn &iamv1.CeremonyUser{Id: out.UserHandle, Name: string(out.User.Email)}\n}\n", 0},
		{"сценарий: платформенный id", "func f() any {\n\treturn BeginRegistrationOutput{UserHandle: []byte(in.UserID)}\n}\n", 1},
		{"сценарий: близнец — байты носителя", "func f() any {\n\treturn BeginRegistrationOutput{UserHandle: handle.Bytes()}\n}\n", 0},
		{"строка ключа: платформенный id", "func f() any {\n\treturn domain.AccessKey{UserHandle: []byte(in.UserID)}\n}\n", 1},
		{"строка ключа: близнец — байты носителя", "func f() any {\n\treturn domain.AccessKey{UserHandle: handle.Bytes()}\n}\n", 0},
		{"второй приёмник: присваивание из адреса", "func f() {\n\tkey.UserHandle = []byte(user.Email)\n}\n", 1},
		{"второй приёмник: близнец — байты носителя", "func f() {\n\tkey.UserHandle = handle.Bytes()\n}\n", 0},
		{"предъявленная рукоятка не судится", "func f() any {\n\treturn FinishAssertionInput{UserHandle: cred.GetUserHandle()}\n}\n", 0},
	} {
		fset, file, path := parse(t, tc.body)
		var c handleCensus
		findings := ceremonyPackageFindings(fset, file, &c)
		require.Len(t, findings, tc.want, "%s: находок %d\n%s", tc.name, len(findings), strings.Join(findings, "\n"))
		if tc.want > 0 {
			require.Contains(t, findings[0], path, "%s: находка обязана называть координату", tc.name)
		}
	}

	restore := "func f() {\n\t_, _ = domain.RestoreCeremonyHandle([]byte(in.UserID))\n}\n"
	for _, tc := range []struct {
		name, rel string
		want      int
	}{
		{"восстановление в сценарии", "internal/apps/kaname/api/access_keys/begin_registration.go", 1},
		{"восстановление в адаптере — близнец", "internal/repo/kaname/pg/access_key_repo.go", 0},
	} {
		fset, file, path := parse(t, restore)
		var c handleCensus
		findings := restoreFindings(fset, file, tc.rel, &c)
		require.Equal(t, 1, c.restoreCalls, "%s: вызов обязан быть сосчитан", tc.name)
		require.Len(t, findings, tc.want, "%s: находок %d\n%s", tc.name, len(findings), strings.Join(findings, "\n"))
		if tc.want > 0 {
			require.Contains(t, findings[0], path, "%s: находка обязана называть координату", tc.name)
		}
	}
}
