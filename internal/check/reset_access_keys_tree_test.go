// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// reset_access_keys_tree_test.go — LMR-08: свойства дерева у глагола сброса
// ключей доступа (задача PRO-Robotech/kaname#638; приёмка
// `docs/engineering/acceptance/cloud-administrator-resets-login-methods.md`,
// редакция 5, Р1, Р2, Р4, Р8).
//
// # Что судится — узлом, а не словом
//
//   - запись каталога `UserService/ResetAccessKeys`: отношение
//     `identity_suspender`, объект `iam_user` из `user_id`, пол «2», флага
//     сокрытия существования нет (разобранный JSON);
//   - причина `access-keys-reset` объявлена ОДНОЙ строковой константой вне проб
//     (узел-литерал разбора Go, не подстрока);
//   - операторы снятия строк способа входа (`"DELETE FROM " + loginMethodsTable`)
//     вне проб — по-прежнему три, и ни один не новый: сброс строку пароля не
//     снимает (Р8, П-х);
//   - прежних имён глагола в дереве нет вне приёмок и записей ревью.
//
// Перепись печатается всегда; пустой обход — отказ, а не «чисто».

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const resetAccessKeysFQN = "kaname.cloud.iam.v1.UserService/ResetAccessKeys"

// TestResetAccessKeys_LMR08_CatalogEntryIsTheIdentitySuspender — запись каталога.
func TestResetAccessKeys_LMR08_CatalogEntryIsTheIdentitySuspender(t *testing.T) {
	data, err := os.ReadFile(platformtree.RequirePath(t, "services/iam/internal/apps/kaname/seed/embedded/permission_catalog.json"))
	require.NoError(t, err)
	var entries []map[string]any
	require.NoError(t, json.Unmarshal(data, &entries))
	require.NotEmpty(t, entries, "каталог разобран в ноль записей — предпосылка сломана")

	var found map[string]any
	var control map[string]any
	for _, e := range entries {
		switch e["fqn"] {
		case resetAccessKeysFQN:
			found = e
		case "kaname.cloud.iam.v1.UserService/ResetSecondFactor":
			control = e
		}
	}
	require.NotNil(t, control, "КОНТРОЛЬ: разбор находит запись соседнего глагола")
	require.NotNilf(t, found, "каталог не знает %s (LMR-08)", resetAccessKeysFQN)
	require.Equal(t, "iam.users.resetAccessKeys", found["permission"])
	require.Equal(t, "identity_suspender", found["required_relation"], "Р2: отношение надзора над личностью")
	se, ok := found["scope_extractor"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "iam_user", se["object_type"])
	require.Equal(t, "user_id", se["from_request_field"])
	require.Equal(t, "2", found["required_acr_min"], "Р2: пол «2»")
	_, hides := found["hide_existence"]
	require.False(t, hides, "Р2: флага сокрытия существования нет")
	t.Logf("перепись: записей каталога %d · запись %s найдена", len(entries), resetAccessKeysFQN)
}

// nonTestGoFiles — разобранные не-тестовые файлы Go модуля (без порождённых
// заглушек `pkg/api`).
func nonTestGoFiles(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
	root := platformtree.RequirePath(t, "services/iam")
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "testdata" || rel == filepath.Join("pkg", "api") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = f
		return nil
	}))
	require.NotEmpty(t, out, "обход не нашёл ни одного файла Go — предпосылка сломана")
	return out, fset
}

// TestResetAccessKeys_LMR08_ReasonIsDeclaredOnceAndNoPasswordRemover — причина
// одной константой; операторов снятия строк способа входа — те же три.
func TestResetAccessKeys_LMR08_ReasonIsDeclaredOnceAndNoPasswordRemover(t *testing.T) {
	files, fset := nonTestGoFiles(t)
	var reasonAt, controlAt, deleteAt []string
	for rel, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(x.Value)
				if err != nil {
					return true
				}
				switch v {
				case "access-keys-reset":
					reasonAt = append(reasonAt, rel+":"+strconv.Itoa(fset.Position(x.Pos()).Line))
				case "second-factor-reset":
					controlAt = append(controlAt, rel)
				}
			case *ast.BinaryExpr:
				// `… + "… DELETE FROM " + loginMethodsTable`: сложение левоассоциативно,
				// поэтому литерал, стоящий перед именем таблицы, — самый правый
				// операнд левой части.
				id, ok := x.Y.(*ast.Ident)
				if !ok || id.Name != "loginMethodsTable" || x.Op != token.ADD {
					return true
				}
				left := x.X
				for {
					b, ok := left.(*ast.BinaryExpr)
					if !ok {
						break
					}
					left = b.Y
				}
				lit, ok := left.(*ast.BasicLit)
				if !ok {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err == nil && strings.HasSuffix(strings.TrimRight(v, " \t\n"), "DELETE FROM") {
					deleteAt = append(deleteAt, rel+":"+strconv.Itoa(fset.Position(lit.End()).Line))
				}
			}
			return true
		})
	}
	t.Logf("перепись: файлов %d · литералов причины %d %v · контроль (соседняя причина) %d · операторов снятия строк способа %d %v",
		len(files), len(reasonAt), reasonAt, len(controlAt), len(deleteAt), deleteAt)
	require.Len(t, controlAt, 1, "КОНТРОЛЬ: распознаватель находит константу соседней причины ровно однажды")
	require.Len(t, reasonAt, 1, "LMR-08: причина `access-keys-reset` объявлена одной константой у носителя")
	require.Contains(t, reasonAt[0], "internal/domain/", "LMR-08: константа — у носителя (домен сессии)")
	require.Len(t, deleteAt, 3, "LMR-08: операторов снятия строк способа входа — три, как на 8b0379e2a (П-х)")
	for _, at := range deleteAt {
		require.Contains(t, at, "internal/repo/kaname/pg/login_method_repo.go", "оператор снятия строк способа вне хранилища способов")
	}
}

// TestResetAccessKeys_LMR08_FormerNamesAreGone — прежние имена глагола
// (редакции 1–4) не заводятся нигде вне приёмок и записей ревью.
func TestResetAccessKeys_LMR08_FormerNamesAreGone(t *testing.T) {
	root := platformtree.RequirePath(t, "services/iam")
	former := []string{
		"Reset" + "LoginMethods", "login-methods" + "-reset", "login_methods" + "_reset", "LOGIN_METHODS" + "_NOT_ENROLLED",
	}
	files, hits := 0, []string{}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || rel == filepath.Join("docs", "engineering", "acceptance") ||
				rel == filepath.Join("docs", "specs", "reviews") {
				return filepath.SkipDir
			}
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files++
		for _, name := range former {
			if strings.Contains(string(data), name) {
				hits = append(hits, rel+" ← "+name)
			}
		}
		return nil
	}))
	t.Logf("перепись: файлов прочитано %d · попаданий прежних имён %d %v", files, len(hits), hits)
	require.Positive(t, files, "обход пуст — предпосылка сломана")
	require.Empty(t, hits, "LMR-08: прежних имён глагола в дереве нет")
}
