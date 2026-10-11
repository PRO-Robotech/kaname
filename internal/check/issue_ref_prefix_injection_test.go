// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Инъекция гейта «ссылка на задачу другого репозитория несёт его имя» — В ОБЕ
// СТОРОНЫ (задача kaname#387).
//
// Вход — НАСТОЯЩИЕ строки дерева, читаемые из файлов, а не переписанные сюда:
// перепиши их — и доказанное относилось бы к копии. Мир собирается во
// временном каталоге и проходит ту же AuditBareIssueRefs, что судит дерево.
//
// Оси:
//  1. НАСТОЯЩАЯ ССЫЛКА БЕЗ ПРЕФИКСА — строка дерева с `kacho#<N>`, у которой
//     снят префикс: находка ровно одна, с её номером. Близнец — та же строка
//     как есть: молчание. Дельта — один факт, префикс.
//  2. ЗАКОННЫЙ БЛИЗНЕЦ ИЗ ДИАПАЗОНА — настоящая ссылка на задачу службы
//     (`#337`): молчание.
//  3. ГРАНИЦА ПОТОЛКА — номер потолка молчит, следующий за ним — находка.
//  4. НЕ-ССЫЛКИ — сущность разметки, путь, цвет, длинный номер: молчание; та же
//     строка с голым номером — находка (иначе молчание ничего не доказывало бы).
//  5. ИСКЛЮЧЕНИЕ И ПОЗВОЛЕНИЕ — действуют на свой путь и свой номер, а не шире.
//  6. ПУСТОЙ ВХОД — ошибка, а не «чисто».
package check_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// realLine — первая строка файла дерева, содержащая needle; её отсутствие —
// отказ пробы, а не пропуск: вход переехал, и поправить координату надо здесь.
func realLine(t *testing.T, rel, needle string) string {
	t.Helper()
	body, err := os.ReadFile(platformtree.RequirePath(t, rel)) // #nosec G304 -- путь-константа своего дерева
	require.NoError(t, err)
	for _, l := range strings.Split(string(body), "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("%s: строки с %q нет — настоящий вход инъекции переехал; поправьте координату ЗДЕСЬ", rel, needle)
	return ""
}

// unmask — знак номера в голой форме. Голые ссылки выше потолка пишутся в этом
// файле через «№»: файл лежит в дереве, которое судит тот же гейт, и буквальная
// инъекция была бы находкой о самой пробе.
func unmask(s string) string { return strings.ReplaceAll(s, "№", "#") }

// auditOne — мир из одного файла под rel с телом body.
func auditOne(t *testing.T, rel, body string) ([]check.BareIssueRef, check.IssueRefCensus) {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	f, c, err := check.AuditBareIssueRefs(root, []string{rel}, check.KanameNumberCeiling)
	require.NoError(t, err)
	require.Equal(t, 1, c.Read, "мир не прочитан — молчание ничего не утверждало бы")
	return f, c
}

const (
	injForeignFile   = "cmd/kaname/serve.go"
	injForeignNeedle = "kacho#1406"
	injForeignNumber = 1406
	injOwnFile       = "cmd/kaname/sa_key_issuance_warning_reach_test.go"
	injOwnNeedle     = "(задача #337)"
)

func TestBareIssueRefInjection_RealForeignRefWithoutPrefixIsFound(t *testing.T) {
	t.Parallel()
	line := realLine(t, injForeignFile, injForeignNeedle)
	stripped := strings.Replace(line, injForeignNeedle, "#"+strconv.Itoa(injForeignNumber), 1)
	require.NotEqual(t, line, stripped)

	f, _ := auditOne(t, injForeignFile, stripped+"\n")
	require.Lenf(t, f, 1, "строка дерева без префикса обязана дать ровно одну находку: %q", stripped)
	require.Equal(t, injForeignNumber, f[0].Number)
	require.Equal(t, 1, f[0].Line)

	twin, _ := auditOne(t, injForeignFile, line+"\n")
	require.Emptyf(t, twin, "та же строка С ПРЕФИКСОМ — законна: %q", line)
}

func TestBareIssueRefInjection_RealOwnRefIsSilent(t *testing.T) {
	t.Parallel()
	line := realLine(t, injOwnFile, injOwnNeedle)
	f, c := auditOne(t, injOwnFile, line+"\n")
	require.Emptyf(t, f, "ссылка на задачу службы из диапазона — законна: %q", line)
	require.Equalf(t, 1, c.Bare, "перепись обязана видеть законную ссылку, иначе молчание — слепота")
}

func TestBareIssueRefInjection_CeilingIsTheBoundary(t *testing.T) {
	t.Parallel()
	at := "// задача #" + strconv.Itoa(check.KanameNumberCeiling) + "\n"
	above := "// задача #" + strconv.Itoa(check.KanameNumberCeiling+1) + "\n"
	f, _ := auditOne(t, "x/a.go", at)
	require.Empty(t, f, "номер потолка — номер службы")
	f, _ = auditOne(t, "x/a.go", above)
	require.Len(t, f, 1, "номер выше потолка задачей службы быть не может")
}

func TestBareIssueRefInjection_NonReferencesAreSilentAndTheirTwinsAreNot(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, quiet, loud string }{
		{"сущность разметки", "<code>&#1234;</code>", "<code>№1234;</code>"},
		{"путь", "см. issues/#1234", "см. issues №1234"},
		{"имя репозитория", "PRO-Robotech/kacho#1234", "PRO-Robotech №1234"},
		{"цвет", "color: #15161d;", "color: №15161;"},
		{"длинный номер", "id #123456", "id №12345"},
		{"повтор знака", "##1234 заголовок", "# №1234 заголовок"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := auditOne(t, "x/a.md", tc.quiet+"\n")
			require.Emptyf(t, f, "не ссылка: %q", tc.quiet)
			f, _ = auditOne(t, "x/a.md", unmask(tc.loud)+"\n")
			require.Lenf(t, f, 1, "близнец с голым номером — ссылка: %q", tc.loud)
		})
	}
}

func TestBareIssueRefInjection_ExclusionAndAllowanceAreNotWider(t *testing.T) {
	t.Parallel()
	body := unmask("-- задача №2117\n")
	f, c := auditOne(t, "internal/migrations/20990101000000_x.sql", body)
	require.Empty(t, f, "применённая миграция вне суждения")
	require.Equal(t, 1, c.Excluded["internal/migrations/*.sql"])
	f, _ = auditOne(t, "internal/migrations/x_test.go", unmask("// задача №2117\n"))
	require.Len(t, f, 1, "исключение — только .sql, Go-проба рядом судится")

	a := check.IssueRefAllowances()[0]
	num := "#" + strconv.Itoa(a.Number)
	f, c = auditOne(t, a.Path, "// "+num+"\n")
	require.Empty(t, f)
	require.Equal(t, 1, c.Allowed[check.AllowanceKey(a)])
	f, _ = auditOne(t, a.Path, "// #"+strconv.Itoa(a.Number+1)+"\n")
	require.Len(t, f, 1, "позволение — на свой номер, а не на файл")
	f, _ = auditOne(t, "x/other.go", "// "+num+"\n")
	require.Len(t, f, 1, "позволение — на свой файл, а не на номер")
}

func TestBareIssueRefInjection_EmptyInputIsAnError(t *testing.T) {
	t.Parallel()
	_, _, err := check.AuditBareIssueRefs(t.TempDir(), nil, check.KanameNumberCeiling)
	require.Error(t, err, "ноль поданного — не «чисто»")
	_, _, err = check.AuditBareIssueRefs(t.TempDir(), []string{"a"}, 0)
	require.Error(t, err, "нулевой потолок сделал бы находкой всякий номер")
}
