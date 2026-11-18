// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// G101SuppressionCensus — прочитанные исходники и координаты подавлений G101.
// Порождённый публичный API исключается только по своему каталогу pkg/api.
// Остальные исходники, включая тесты и порождённые файлы, входят в перепись.
type G101SuppressionCensus struct {
	Files int
	Lines int
	Sites []string
}

// ScanG101Suppressions читает именно комментарии: строковый литерал с текстом
// директивы не меняет настройку gosec и находкой не является.
func ScanG101Suppressions(rel string, src []byte) (G101SuppressionCensus, error) {
	if !strings.HasSuffix(rel, ".go") || strings.HasPrefix(rel, "pkg/api/") {
		return G101SuppressionCensus{}, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return G101SuppressionCensus{}, fmt.Errorf("разбор %s: %w", rel, err)
	}
	lines := strings.Count(string(src), "\n")
	if len(src) > 0 && src[len(src)-1] != '\n' {
		lines++
	}
	c := G101SuppressionCensus{Files: 1, Lines: lines}
	for _, group := range file.Comments {
		rules, position, offset, found := g101SuppressionDirective(group)
		if !found || !g101ListedRule(rules) {
			continue
		}
		if position == token.NoPos {
			return G101SuppressionCensus{}, fmt.Errorf("координата директивы в %s не установлена", rel)
		}
		// Физическая координата не подменяется директивой строки исходника.
		// AST удаляет CR, поэтому смещение считаем строками, а не байтами.
		line := fset.PositionFor(position, false).Line + offset
		c.Sites = append(c.Sites, fmt.Sprintf("%s:%d: подавление G101 вне pkg/api", rel, line))
	}
	return c, nil
}

// g101SuppressionDirective повторяет порядок findNoSecDirective gosec v2.28.0:
// сначала первый маркер в нормализованной группе, затем отдельные директивы.
func g101SuppressionDirective(group *ast.CommentGroup) (string, token.Pos, int, bool) {
	if args, found := g101SuppressionArgs(group.Text()); found {
		for i, comment := range group.List {
			// Нормализация удаляет служебные комментарии, например go:generate.
			single := *group
			single.List = group.List[i : i+1]
			if !strings.Contains(single.Text(), "#nosec") {
				continue
			}
			if index := strings.Index(comment.Text, "#nosec"); index >= 0 {
				return args, comment.Pos(), strings.Count(comment.Text[:index], "\n"), true
			}
		}
		return args, token.NoPos, 0, true
	}
	for _, comment := range group.List {
		if args, found := strings.CutPrefix(comment.Text, "//gosec:disable"); found {
			if len(args) == 0 || args[0] == ' ' {
				return strings.TrimSpace(args), comment.Pos(), 0, true
			}
		}
	}
	return "", token.NoPos, 0, false
}

// g101SuppressionArgs повторяет findNoSecTag из gosec v2.28.0: маркер
// распознаётся в начале очищенного текста либо строки с отступом из пробелов
// и табуляций. Первое вхождение внутри прозы не открывает поиск следующего.
func g101SuppressionArgs(text string) (string, bool) {
	const marker = "#nosec"
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, marker) {
		return text[len(marker):], true
	}
	if index := strings.Index(text, marker); index > 0 {
		for i := index - 1; i >= 0; i-- {
			if text[i] == '\n' {
				return text[index+len(marker):], true
			}
			if text[i] != ' ' && text[i] != '\t' {
				break
			}
		}
	}
	return "", false
}

// g101ListedRule читает тот же список идентификаторов, что astVisitor.ignore
// в gosec v2.28.0: G и три цифры без требования границы слова. Обоснование
// после первого разделителя не входит в список. Пустой список распознанных
// правил подавляет все правила, включая G101; отдельный G304 этого не делает.
func g101ListedRule(args string) bool {
	args, _, _ = strings.Cut(args, "--")
	directive := strings.TrimSpace(args)
	listed := false
	for i := 0; i < len(directive); {
		if directive[i] == 'G' && i+4 <= len(directive) {
			valid := true
			for j := 1; j < 4; j++ {
				if directive[i+j] < '0' || directive[i+j] > '9' {
					valid = false
					break
				}
			}
			if valid {
				listed = true
				if directive[i:i+4] == "G101" {
					return true
				}
				i += 4
				continue
			}
		}
		i++
	}
	return !listed
}

// Add складывает переписи, не теряя объём законных файлов без находок.
func (c *G101SuppressionCensus) Add(other G101SuppressionCensus) {
	c.Files += other.Files
	c.Lines += other.Lines
	c.Sites = append(c.Sites, other.Sites...)
}

// Judge отличает чистое дерево от пустого обхода и печатает координаты отказа.
func (c G101SuppressionCensus) Judge() error {
	if c.Files == 0 {
		return fmt.Errorf("проверка НЕ ИСПОЛНЯЛАСЬ: осмотрено 0 файлов Go вне pkg/api")
	}
	if len(c.Sites) != 0 {
		sites := append([]string(nil), c.Sites...)
		sort.Strings(sites)
		return fmt.Errorf("осмотрено %d файлов Go, %d строк: %s", c.Files, c.Lines, strings.Join(sites, "\n"))
	}
	return nil
}
