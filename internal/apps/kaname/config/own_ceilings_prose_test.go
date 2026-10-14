// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// own_ceilings_prose_test.go — ЧИСЛО СОБСТВЕННЫХ ПОТОЛКОВ ЖИВЁТ В ОДНОМ МЕСТЕ:
// в таблице `config.OwnCeilingKnobs` (задачи kaname#282, kaname#236).
//
// # Предмет
//
// Потолок ключей доступа (Ф7) пришёл в таблицу, профиль и чарт, а проза вокруг
// осталась на прежнем числе: оператор читал, что обязан назвать меньше величин,
// чем требует страж старта. Правка по предикату с перечнем каталогов закрыла
// названные каталоги и пропустила композиционный корень и страницу API — они в
// перечень не входили. Перечень каталогов стареет так же молча, как число.
//
// Поэтому здесь судится ВЕСЬ модуль, а не перечень каталогов: каждый текстовый
// исходник (код, чарт, профиль, страница сайта, контракт). Проза, назвавшая
// число собственных потолков словом или цифрой, — находка; находка называет
// координату и то, что держит таблица. Сходство с таблицей НЕ оправдывает
// число: верное сегодня станет ложью со следующей строкой таблицы, поэтому
// проза ссылается на таблицу, а не повторяет её длину.
//
// # Что считается называнием числа
//
// Числительное (количественное или порядковое, слово либо цифры) рядом со словом
// «собственный/свой/own» и словом «потолок/ceiling» в одной строке, в любом
// порядке этих двух соседей: «<число> собственных потолка»,
// «собственные <число> потолка», «свои <число> потолка», «<число> own ceilings».
// Потолки фундамента, модуля и темпа к собственным не относятся и не судятся:
// у них нет слова «собственный» рядом.
//
// # Исключения — записью с причиной, и запись истекает сама
//
// Применённая миграция верна на своей ревизии и не правится (ban #5); приёмка
// описывает свою ревизию и привязана к отпечатку содержимого. Запись исключения,
// которой нечего исключать, — находка: предмет ушёл, запись пережила его.

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ownCeilingProseExemption — каталог, чья проза описывает СВОЮ ревизию.
type ownCeilingProseExemption struct {
	Prefix string
	Why    string
}

var ownCeilingProseExemptions = []ownCeilingProseExemption{
	{
		Prefix: "internal/migrations/",
		Why:    "применённая миграция верна на своей ревизии и не правится (ban #5)",
	},
	{
		Prefix: "docs/engineering/acceptance/",
		Why:    "приёмка описывает свою ревизию, вердикт привязан к отпечатку содержимого",
	},
}

// ownCeilingProseExts — текстовые исходники, в которых живёт проза о потолках.
var ownCeilingProseExts = map[string]bool{
	".go": true, ".md": true, ".mdx": true, ".yaml": true, ".yml": true,
	".tpl": true, ".proto": true, ".sql": true, ".txt": true,
}

// ownCeilingProseSkipDirs — каталоги, которые не являются исходником модуля.
var ownCeilingProseSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".docusaurus": true, "build": true,
}

const (
	wordEdge = `(?:^|[^\p{L}\p{N}_])`
	numWord  = `(?:\p{N}+|` +
		`од(?:ин|на|но|ного|ной|ному|ним)|дв(?:а|е|ух|ум|умя)|тр(?:и|[её]х|[её]м|емя)|` +
		`четыр(?:е|[её]х|[её]м|ьмя)|пят(?:ь|и|ью)|шест(?:ь|и|ью)|сем(?:ь|и|ью)|` +
		`трет(?:ий|ья|ье|ьего|ьей|ьему)|четв[её]рт(?:ый|ая|ое|ого|ой|ому)|пят(?:ый|ая|ое|ого|ой|ому)|` +
		`one|two|three|four|five|six|seven|third|fourth|fifth)`
	ownWord  = `(?:собственн\p{L}*|сво(?:и|их|им|ими|й|я|е|ё|его|ей|ему)|own)`
	ceilWord = `(?:потол\p{L}*|ceilings?)`
	gap      = `[\s*#/>|-]+`
)

// ownCeilingCountRe — число рядом с «собственный» и «потолок», в двух порядках:
// «<число> [её] собственных потолка» и «собственные <число> потолка». Между
// числом и «собственный» допускается только местоимение: иное слово рвёт связь
// («код 57014 от собственного потолка оператора» числа потолков не называет).
var ownCeilingCountRe = regexp.MustCompile(`(?i)` + wordEdge + `(` +
	numWord + gap + `(?:(?:её|ее|its)` + gap + `)?` + ownWord + gap + ceilWord +
	`|` + ownWord + gap + numWord + gap + ceilWord + `)`)

type ownCeilingProseFinding struct {
	Path string
	Line int
	Text string
}

type ownCeilingProseCensus struct {
	Files    int
	Lines    int
	ByRoot   map[string]int
	Exempted map[string]int
	Findings []ownCeilingProseFinding
}

// scanOwnCeilingProse обходит дерево `root` и возвращает перепись и находки.
func scanOwnCeilingProse(root string, exemptions []ownCeilingProseExemption) (ownCeilingProseCensus, error) {
	c := ownCeilingProseCensus{ByRoot: map[string]int{}, Exempted: map[string]int{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && ownCeilingProseSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !ownCeilingProseExts[filepath.Ext(path)] {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		f, openErr := os.Open(path) // #nosec G304 -- исходник обходимого дерева
		if openErr != nil {
			return openErr
		}
		defer func() { _ = f.Close() }()
		c.Files++
		c.ByRoot[strings.SplitN(rel, "/", 2)[0]]++
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		n := 0
		for sc.Scan() {
			n++
			c.Lines++
			line := sc.Text()
			if !ownCeilingCountRe.MatchString(line) {
				continue
			}
			if ex, ok := exemptionOf(rel, exemptions); ok {
				c.Exempted[ex.Prefix]++
				continue
			}
			c.Findings = append(c.Findings, ownCeilingProseFinding{Path: rel, Line: n, Text: strings.TrimSpace(line)})
		}
		return sc.Err()
	})
	return c, err
}

func exemptionOf(rel string, exemptions []ownCeilingProseExemption) (ownCeilingProseExemption, bool) {
	for _, ex := range exemptions {
		if strings.HasPrefix(rel, ex.Prefix) {
			return ex, true
		}
	}
	return ownCeilingProseExemption{}, false
}

// ownCeilingProseVerdict превращает перепись в перечень отказов. Пустой обход —
// отказ, а не зелёное: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func ownCeilingProseVerdict(c ownCeilingProseCensus, exemptions []ownCeilingProseExemption, tableLen int) []string {
	var out []string
	if c.Files == 0 || c.Lines == 0 {
		return []string{fmt.Sprintf("обход не прочитал ни одного исходника (файлов %d, строк %d) — вердикта нет", c.Files, c.Lines)}
	}
	for _, f := range c.Findings {
		out = append(out, fmt.Sprintf("%s:%d: проза называет число собственных потолков («%s»), а число живёт "+
			"в таблице config.OwnCeilingKnobs (сейчас строк %d) — сошлитесь на таблицу, не повторяя её длину",
			f.Path, f.Line, f.Text, tableLen))
	}
	for _, ex := range exemptions {
		if c.Exempted[ex.Prefix] == 0 {
			out = append(out, fmt.Sprintf("исключение %s (%s) нечего исключать — запись пережила свой предмет, снимите её",
				ex.Prefix, ex.Why))
		}
	}
	sort.Strings(out)
	return out
}

// ownCeilingProseModuleRoot — подъём до ПЕРВОГО маркера модуля: за корень своего
// модуля обход не выходит.
func ownCeilingProseModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("объявление модуля не найдено выше %s", dir)
		}
		dir = parent
	}
}

// TestOwnCeilingCountLivesOnlyInTheTable — по всему модулю проза не выписывает
// число собственных потолков; число держит одна таблица.
func TestOwnCeilingCountLivesOnlyInTheTable(t *testing.T) {
	root := ownCeilingProseModuleRoot(t)
	c, err := scanOwnCeilingProse(root, ownCeilingProseExemptions)
	if err != nil {
		t.Fatalf("обход %s: %v", root, err)
	}
	t.Logf("перепись: файлов %d · строк %d · по корням %v · исключено %v · находок %d · строк таблицы %d",
		c.Files, c.Lines, c.ByRoot, c.Exempted, len(c.Findings), len(config.OwnCeilingKnobs))

	// Предпосылка: обход доходит до каждого вида места, где проза о потолках
	// жила, — композиционный корень, пакет настройки, чарт, сайт документации.
	for _, top := range []string{"cmd", "internal", "deploy", "docs"} {
		if c.ByRoot[top] == 0 {
			t.Errorf("предпосылка: обход не прочитал ни одного исходника под %s/ — гейт слеп к нему", top)
		}
	}
	for _, msg := range ownCeilingProseVerdict(c, ownCeilingProseExemptions, len(config.OwnCeilingKnobs)) {
		t.Error(msg)
	}
}
