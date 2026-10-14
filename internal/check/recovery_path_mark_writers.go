// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// recovery_path_mark_writers.go — у отметки открытого пути восстановления
// (колонка строки личности; имя — в объявлении пробы) ДВА писателя, и оба названы (задача
// PRO-Robotech/kaname#608, приёмка `active-identity-has-a-way-in.md` AWI-10,
// §5 инв. 4):
//
//   - ставит её ТОЛЬКО миграция переноса — файл, который отметку заводит;
//   - снимает её ТОЛЬКО запись завершения восстановления (Ф5-30) — один
//     оператор в одном файле кода Go.
//
// Отметку, которую ставит продукт, инвариант базы перестал бы отличать от
// вновь произведённого тупика: личность без способа входа снова стала бы
// производимой — только с отметкой. Поэтому судится КАЖДОЕ упоминание колонки:
//
//   - в коде Go — строковый литерал (узел разбора, а не подстрока исходника:
//     комментарий, объясняющий отметку, законен). Литерал, называющий колонку,
//     законен ровно в одной форме — снятие `<колонка> = NULL` в объявленном
//     файле; любое иное упоминание (установка, чтение, обрывок склейки) —
//     находка с координатой. Склейка из нескольких литералов не прячет
//     писателя: обрывок с именем колонки без снятия сам является находкой;
//   - в миграциях — файл, называющий колонку: законен только объявленный файл
//     переноса.
//
// Перепись печатается отдельно от находок: разобранных файлов Go, файлов
// миграций, упоминаний. Пустой обход и ноль снимающих операторов — отказ, а не
// зелёное: «писателей ноль» неотличимо от «колонки нет».

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RecoveryPathMarkDecl — объявление предмета: имя колонки, где живёт
// единственный снимающий оператор и какой файл миграции отметку ставит.
// Приходит ПАРАМЕТРОМ из файла пробы: литерал имени колонки в этом файле сделал
// бы гейт своей же первой находкой, а файл пробы в корпус не входит.
type RecoveryPathMarkDecl struct {
	Column        string
	ClearerFile   string
	MigrationFile string
}

// RecoveryPathMarkCensus — объём осмотренного и найденное.
type RecoveryPathMarkCensus struct {
	GoFiles       int
	SQLFiles      int
	GoMentions    int
	Clearers      []string
	SQLMentioners []string
	Findings      []string
}

// RecoveryPathMarkWriters судит дерево: goFiles — непроверочный код Go (путь →
// текст), sqlFS — миграции.
func RecoveryPathMarkWriters(goFiles map[string]string, sqlFS fs.FS, decl RecoveryPathMarkDecl) (RecoveryPathMarkCensus, error) {
	var c RecoveryPathMarkCensus
	if decl.Column == "" || decl.ClearerFile == "" || decl.MigrationFile == "" {
		return c, fmt.Errorf("объявление предмета неполно: %+v", decl)
	}
	column := strings.ToLower(decl.Column)
	clearForm := regexp.MustCompile(`(?is)\bset\b.*\b` + regexp.QuoteMeta(column) + `\s*=\s*null\b`)
	setForm := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(column) + `\s*=\s*([^\s,)]+)`)
	pfs, err := parseAll(goFiles)
	if err != nil {
		return c, err
	}
	c.GoFiles = len(pfs)
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				text = lit.Value
			}
			if !strings.Contains(strings.ToLower(text), column) {
				return true
			}
			c.GoMentions++
			at := fmt.Sprintf("%s:%d", pf.rel, pf.fset.Position(lit.Pos()).Line)
			if pf.rel == decl.ClearerFile && clearForm.MatchString(text) && !recoveryPathSetsValue(setForm, text) {
				c.Clearers = append(c.Clearers, at)
				return true
			}
			c.Findings = append(c.Findings, fmt.Sprintf("%s: литерал называет отметку открытого пути вне единственного снимающего оператора — третий писатель либо читатель отметки", at))
			return true
		})
	}

	entries, err := fs.ReadDir(sqlFS, ".")
	if err != nil {
		return c, fmt.Errorf("миграции не читаются: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		c.SQLFiles++
		body, rerr := fs.ReadFile(sqlFS, e.Name())
		if rerr != nil {
			return c, fmt.Errorf("миграция %s не читается: %w", e.Name(), rerr)
		}
		if !strings.Contains(strings.ToLower(string(body)), column) {
			continue
		}
		c.SQLMentioners = append(c.SQLMentioners, e.Name())
		if e.Name() != decl.MigrationFile {
			c.Findings = append(c.Findings, fmt.Sprintf("%s: миграция называет отметку открытого пути, а ставит её только перенос %s", e.Name(), decl.MigrationFile))
		}
	}

	switch {
	case c.GoFiles == 0 || c.SQLFiles == 0:
		c.Findings = append(c.Findings, fmt.Sprintf("обход пуст: файлов Go %d, миграций %d — проверять нечего, и это не зелёное", c.GoFiles, c.SQLFiles))
	case len(c.Clearers) != 1:
		c.Findings = append(c.Findings, fmt.Sprintf("снимающих операторов отметки в %s — %d, а должен быть ровно один (запись завершения восстановления): %v", decl.ClearerFile, len(c.Clearers), c.Clearers))
	}
	if len(c.SQLMentioners) == 0 {
		c.Findings = append(c.Findings, fmt.Sprintf("ни одна миграция не называет отметку — перенос %s отсутствует, и предмет гейта не существует", decl.MigrationFile))
	}
	sort.Strings(c.Findings)
	return c, nil
}

// recoveryPathSetsValue — литерал, который где-то ставит колонке значение,
// отличное от NULL: снимающий оператор такой записи не несёт.
func recoveryPathSetsValue(setForm *regexp.Regexp, text string) bool {
	for _, m := range setForm.FindAllStringSubmatch(text, -1) {
		if !strings.EqualFold(m[1], "null") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(text), "insert")
}
