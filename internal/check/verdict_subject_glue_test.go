// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verdict_subject_glue_test.go — субъект выдачи остаётся индексируемым входом:
// на пути принятия решения он сравнивается ПАРОЙ КОЛОНОК, а не склейкой
// (держатель, названный `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
// §6 — `TestVerdictSubjectIsComparedByColumnPairNotByGlue`).
//
// # Предмет
//
// Склейка `subject_type || ':' || subject_id` в предикате отбора выводит обе
// колонки из-под любого индекса: сравнивать приходится ВЫЧИСЛЕННОЕ значение, а
// вычисленное значение отбирает строки только после того, как они прочитаны.
// Пока склейка стоит на пути принятия решения, «выдача называет этого
// субъекта» перестаёт быть сужением и становится фильтром — то есть работа
// растёт с числом выдач в облаке, а не с числом выдач спрашиваемому.
//
// # Граница, и она намеренная
//
// Предмет — склейка СУБЪЕКТА ВЫДАЧИ, и только она. Склейка ЧЛЕНА ГРУППЫ
// (`member_type || ':' || member_id`) в границы этого гейта не входит: на пути
// принятия решения её нет вовсе — членство ищется парой колонок, — а
// оставшиеся места суть проекция обратных вопросов. Гейт на них обязан
// молчать: покраснев, он дал бы находку вне предмета.
//
// # Что считается находкой, а что законным близнецом
//
// Находка — склейка в предикате (`ON`, `WHERE`, `HAVING`, `AND`, `OR`): там
// она отбирает строки. Законный близнец — та же склейка в списке выборки: там
// она ничего не отбирает, а называет ответ.
//
// # Объём и его граница, названная честно
//
// Гейт читает строковые литералы прод-кода пути вердикта, разбирая Go по
// синтаксическому дереву: иначе SQL внутри Go-комментария читался бы как код.
// Внутри литерала снимаются SQL-комментарии — комментарий, объясняющий запрет,
// не должен считаться его нарушением. Собранный на лету SQL и миграции не
// покрыты, и это сказано здесь, а не подразумевается.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `verdict_subject_glue_injection_test.go`.
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

// verdictGlueRoot — путь принятия решения, ОТНОСИТЕЛЬНО корня СВОЕГО модуля.
//
// Перечень объявлен здесь, потому что он и есть ОБЪЁМ гейта, и печатается в
// переписи вместе с числом прочитанных файлов.
const verdictGlueRoot = "internal/repo/kaname/pg/relverdict"

// gluePattern — склейка субъекта выдачи в любой форме написания алиаса.
//
// Ищется по ЯДРУ (`|| ':' ||` между двумя колонками субъекта), а не по точной
// строке с алиасом: алиас таблицы свободен, и предикат, привязанный к нему,
// нашёл бы ноль на первом же переименовании — то есть молчал бы ровно там, где
// должен говорить.
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
	occurrence int // склеек субъекта встречено всего
	projection int // из них в списке выборки — законные близнецы
}

func verdictGlueModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}
	return root
}

func TestVerdictSubjectIsComparedByColumnPairNotByGlue(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(verdictGlueModuleRoot(t), filepath.FromSlash(verdictGlueRoot))
	findings, c := collectSubjectGlue(t, dir)

	// ПРОВЕРКА СВОЕЙ ПРЕДПОСЫЛКИ. Запрет обоснован тем, что в этих файлах есть
	// SQL и в нём есть колонки субъекта. Перестанет разбор их узнавать — «ноль
	// находок» будет означать «ноль прочитанного», и гейт станет зелен навсегда.
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
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- путь-константа своего дерева
		if err != nil {
			t.Fatalf("файл %s: %v", name, err)
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
		sql, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.Contains(sql, glueLeft) {
			return true
		}
		c.literals++
		base := fset.Position(lit.Pos()).Line
		f, cc := auditSQLForSubjectGlue(name, base, stripSQLLineComments(sql))
		out = append(out, f...)
		c.occurrence += cc.occurrence
		c.projection += cc.projection
		return true
	})
	return out, c
}

// auditSQLForSubjectGlue — разбор ИСПОЛНЯЕМОЙ части: комментарии сняты
// вызывающим, а положение склейки определяется КЛАУЗОЙ, в которой она стоит.
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

		// Склейка — это `subject_type || ':' || …subject_id`. Хвост берётся
		// коротким окном: длиннее склейки он не бывает, а брать до конца строки
		// значило бы засчитать соседнее упоминание колонки за склейку.
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

// clauseAt — в какой клаузе стоит смещение: в списке выборки или в предикате.
//
// Разбор идёт НАЗАД по ключевым словам: ближайшее слева определяет клаузу.
// Полноценного разбора SQL в дереве нет, и объявлять его здесь значило бы
// обещать больше, чем сделано; этого различения запрету достаточно, потому что
// оно отделяет ровно два состояния — «отбирает строки» и «называет ответ».
func clauseAt(sql string, off int) string {
	head := strings.ToUpper(sql[:off])
	type kw struct {
		word, clause string
	}
	// Порядок не важен: берётся САМОЕ ПРАВОЕ вхождение любого из них.
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

// stripSQLLineComments убирает комментарии SQL.
//
// Иначе гейт читал бы объяснение защиты как саму защиту: слово-предмет запрета
// в комментарии, разбирающем этот же класс, сделало бы находку неотличимой от
// собственного объяснения.
func stripSQLLineComments(s string) string {
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
