// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verdict_subject_glue_test.go — СУБЪЕКТ ВЫДАЧИ ОСТАЁТСЯ ИНДЕКСИРУЕМЫМ ВХОДОМ
// (порт с монорепо `internal/repohygiene/verdictsubjectglue_test.go`,
// держатель `TestVerdictSubjectIsComparedByColumnPairNotByGlue`, снят
// вынесением службы доступа — `kacho#2597`; Г3 приёмки R7-1).
//
// # Предмет
//
// Склейка `subject_type || ':' || subject_id` в предикате отбора выводит обе
// колонки из-под любого индекса: сравнивать приходится ВЫЧИСЛЕННОЕ значение, а
// оно отбирает строки только после того, как они прочитаны. Пока склейка
// стоит на пути принятия решения, «выдача называет этого субъекта» перестаёт
// быть сужением и становится фильтром — работа растёт с числом выдач в
// облаке, а не с числом выдач спрашиваемому.
//
// # Что считается находкой, а что законным близнецом
//
// Находка — склейка в ПРЕДИКАТЕ (`ON`, `WHERE`, `HAVING`, `AND`, `OR`): там
// она отбирает строки. Законный близнец — та же склейка в СПИСКЕ ВЫБОРКИ: там
// она ничего не отбирает, а называет ответ.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь-константа обхода (без
// префикса `services/iam/`). Осталось дословно: обе константы колонок, разбор
// клаузы по ближайшему справа ключевому слову, снятие SQL-комментариев,
// граница объёма (собранный на лету SQL и миграции не покрыты), имя держателя.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// verdictGlueRootRel — путь принятия решения и обратных вопросов к нему, от
// корня модуля. Перечень объявлен здесь, потому что он и есть ОБЪЁМ гейта.
const verdictGlueRootRel = "internal/repo/kaname/pg/relverdict"

const (
	glueLeft  = "subject_type"
	glueRight = "subject_id"
)

type glueFinding struct {
	file, clause string
	line         int
	text         string
}

type glueCensus struct {
	files      int
	literals   int
	occurrence int
	projection int
}

func TestVerdictSubjectIsComparedByColumnPairNotByGlue(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	dir := filepath.Join(root, filepath.FromSlash(platformtree.Under(prefix, verdictGlueRootRel)))

	findings, c := collectSubjectGlue(t, dir)

	if c.files == 0 || c.literals == 0 {
		t.Fatalf("предпосылка гейта не выполнена: файлов %d, литералов с SQL %d. "+
			"Либо каталог переехал, либо разбор перестал узнавать запросы — в обоих "+
			"случаях вердикт «чисто» ничего не значит", c.files, c.literals)
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: файлов %d, литералов с SQL %d, склеек субъекта встречено %d, "+
		"из них в списке выборки (законные близнецы) %d, находок %d",
		c.files, c.literals, c.occurrence, c.projection, len(findings))

	for _, f := range findings {
		t.Errorf("%s:%d: субъект выдачи сравнивается склейкой в предикате (%s): %s\n"+
			"    Склейка выводит обе колонки из-под индекса: отбор идёт по вычисленному "+
			"значению, то есть уже по прочитанным строкам. Сравнение обязано идти ПАРОЙ "+
			"КОЛОНОК (subject_type, subject_id).", f.file, f.line, f.clause, f.text)
	}
}

func collectSubjectGlue(t *testing.T, dir string) ([]glueFinding, glueCensus) {
	t.Helper()
	var (
		out []glueFinding
		c   glueCensus
	)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог пути вердикта не читается (%s): %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- путь из перечня каталога этого модуля
		if rerr != nil {
			t.Fatalf("файл %s: %v", name, rerr)
		}
		c.files++
		f, cc := auditFileForSubjectGlue(name, body)
		out = append(out, f...)
		c.literals += cc.literals
		c.occurrence += cc.occurrence
		c.projection += cc.projection
	}
	return out, c
}

func auditFileForSubjectGlue(name string, body []byte) ([]glueFinding, glueCensus) {
	var (
		out []glueFinding
		c   glueCensus
	)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, body, 0)
	if err != nil {
		return nil, c
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		sql, uerr := strconv.Unquote(lit.Value)
		if uerr != nil || !strings.Contains(sql, glueLeft) {
			return true
		}
		c.literals++
		base := fset.Position(lit.Pos()).Line
		f, cc := auditSQLForSubjectGlue(name, base, stripGlueSQLLineComments(sql))
		out = append(out, f...)
		c.occurrence += cc.occurrence
		c.projection += cc.projection
		return true
	})
	return out, c
}

func auditSQLForSubjectGlue(file string, baseLine int, sql string) ([]glueFinding, glueCensus) {
	var (
		out []glueFinding
		c   glueCensus
	)
	for off := 0; ; {
		i := strings.Index(sql[off:], glueLeft)
		if i < 0 {
			break
		}
		at := off + i
		off = at + len(glueLeft)

		end := at + 64
		if end > len(sql) {
			end = len(sql)
		}
		win := sql[at:end]
		if !strings.Contains(win, "||") || !strings.Contains(win, glueRight) {
			continue
		}
		c.occurrence++
		clause := clauseAt(sql, at)
		if clause == "projection" {
			c.projection++
			continue
		}
		out = append(out, glueFinding{
			file: file, line: baseLine + strings.Count(sql[:at], "\n"),
			clause: clause, text: strings.TrimSpace(strings.SplitN(win, "\n", 2)[0]),
		})
	}
	return out, c
}

func clauseAt(sql string, off int) string {
	head := strings.ToUpper(sql[:off])
	type kw struct{ word, clause string }
	words := []kw{
		{"SELECT", "projection"},
		{" ON ", "predicate"}, {"\nON ", "predicate"},
		{"WHERE", "predicate"}, {"HAVING", "predicate"},
		{" AND ", "predicate"}, {"\nAND ", "predicate"},
		{" OR ", "predicate"}, {"\nOR ", "predicate"},
	}
	best, clause := -1, "projection"
	for _, w := range words {
		if i := strings.LastIndex(head, w.word); i > best {
			best, clause = i, w.clause
		}
	}
	return clause
}

// stripGlueSQLLineComments убирает комментарии SQL — иначе гейт читал бы
// объяснение защиты как саму защиту.
func stripGlueSQLLineComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
