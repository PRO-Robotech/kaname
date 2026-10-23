// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// self_service_freshness_named_paths_test.go — ОКНО СВЕЖЕСТИ ОПИСАНО ТЕМИ ЖЕ
// ПУТЯМИ, КОТОРЫМ СЛУЖБА ТРЕБУЕТ СВЕЖЕЙ СЕССИИ (kaname#734).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Окно `authn.self-service-freshness` описывалось как действующее только на
// заведение и подтверждение второго фактора. Полоса требует свежей сессии ещё
// у заведения пароля, запроса смены адреса, регистрации и снятия ключа доступа,
// выхода из своих сессий. Оператор, меняющий окно, не знал, что меняет защиту
// этих глаголов.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ
//
//	перечень  ВЫВОДИТСЯ из таблиц путей `docs/content/api/auth-lane.mdx`: путь
//	          под окном — строка таблицы, где колонка сессии говорит «да,
//	          свежая» либо описание — «из свежей сессии». Выписанный здесь
//	          перечень разошёлся бы с таблицей молча;
//	описания  каждое место, описывающее окно оператору, называет ВСЕ эти пути и
//	          ТОЛЬКО их: лишний путь обещает защиту, которой нет.
//
// Мест четыре, у каждого свой распознаватель границы описания — перечень в
// `freshnessDescriptions`. Описание, которого распознаватель не нашёл, — отказ,
// а не молчание: иначе снятие описания целиком было бы зелёным.
package deploy_test

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// freshnessTableRow узнаёт строку таблицы путей полосы: метод и путь первой
// ячейки и остаток строки.
var freshnessTableRow = regexp.MustCompile(`^\s*<tr><td><code>((?:GET|POST|PUT|PATCH|DELETE) [^<]+)</code></td>(.*)$`)

// freshWord — слово «свежий» в любой форме, но не «освежает»: граница слова в
// RE2 латинская, поэтому слева — не кириллическая буква.
var freshWord = regexp.MustCompile(`(^|[^а-яёА-ЯЁ])свеж`)

// namedPath узнаёт путь, названный описанием: в обратных кавычках (профили,
// Go) либо в `<code>` (MDX). Сущности HTML снимаются до разбора.
var namedPath = regexp.MustCompile("(?:`|<code>)((?:GET|POST|PUT|PATCH|DELETE) /[^`<]+)(?:`|</code>)")

// gatedPaths выводит из текста таблиц пути под окном свежести.
func gatedPaths(doc string) (gated map[string]bool, rows int) {
	gated = map[string]bool{}
	for _, line := range strings.Split(doc, "\n") {
		m := freshnessTableRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rows++
		if freshWord.MatchString(m[2]) {
			gated[html.UnescapeString(m[1])] = true
		}
	}
	return gated, rows
}

// namedPaths — пути, которые называет описание.
func namedPaths(text string) map[string]bool {
	named := map[string]bool{}
	for _, m := range namedPath.FindAllStringSubmatch(html.UnescapeString(text), -1) {
		named[m[1]] = true
	}
	return named
}

// freshnessMismatch — расхождение описания с таблицей в обе стороны.
func freshnessMismatch(gated, named map[string]bool) (missing, extra []string) {
	for p := range gated {
		if !named[p] {
			missing = append(missing, p)
		}
	}
	for p := range named {
		if !gated[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// commentBlockAbove — сплошной блок строк комментария (`#` либо `//`)
// непосредственно над первой строкой, которую узнаёт key.
func commentBlockAbove(text string, key *regexp.Regexp, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if !key.MatchString(line) {
			continue
		}
		var block []string
		for j := i - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), prefix); j-- {
			block = append([]string{lines[j]}, block...)
		}
		return strings.Join(block, "\n")
	}
	return ""
}

// exampleEntry — запись образца в комментарии базового профиля: строка ключа
// и строки продолжения, отбитые глубже ключа, до следующего ключа образца.
func exampleEntry(text string, key *regexp.Regexp) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		m := key.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		keyCol := m[2]
		entry := []string{line}
		for _, next := range lines[i+1:] {
			body := strings.TrimPrefix(strings.TrimLeft(next, " "), "#")
			if !strings.HasPrefix(strings.TrimLeft(next, " "), "#") {
				break
			}
			// Колонка начала текста строки продолжения: следующий ключ образца
			// стоит на той же колонке, что ключ, и закрывает запись.
			text := strings.TrimLeft(body, " ")
			col := len(next) - len(text)
			if text == "" || (col <= keyCol && !strings.HasPrefix(text, "#")) {
				break
			}
			entry = append(entry, next)
		}
		return strings.Join(entry, "\n")
	}
	return ""
}

// freshnessDescription — место, описывающее окно оператору.
type freshnessDescription struct {
	name    string
	file    string
	extract func(text string) string
}

// freshnessDescriptions — каждое место, где окно описано оператору.
var freshnessDescriptions = []freshnessDescription{
	{
		name: "боевой профиль, комментарий над ключом",
		file: "deploy/values.prod.yaml",
		extract: func(text string) string {
			return commentBlockAbove(text, regexp.MustCompile(`^\s*selfServiceFreshness:`), "#")
		},
	},
	{
		name: "базовый профиль, образец ключа",
		file: "deploy/values.yaml",
		extract: func(text string) string {
			return exampleEntry(text, regexp.MustCompile(`^\s*#\s*(selfServiceFreshness):`))
		},
	},
	{
		name: "настройки службы, комментарий поля",
		file: "internal/apps/kaname/config/config.go",
		extract: func(text string) string {
			return commentBlockAbove(text, regexp.MustCompile(`^\s*SelfServiceFreshness\s+time\.Duration`), "//")
		},
	},
	{
		name: "страница конфигурации, строка переменной окружения",
		file: "docs/content/install/configuration.mdx",
		extract: func(text string) string {
			return firstLineMatching(text, regexp.MustCompile(`^\s*<tr><td><code>KANAME_AUTHN&#95;&#95;SELF_SERVICE_FRESHNESS</code></td>`))
		},
	},
	{
		name: "страница конфигурации, строка ключа настроек",
		file: "docs/content/install/configuration.mdx",
		extract: func(text string) string {
			return firstLineMatching(text, regexp.MustCompile(`^\s*<tr><td><code>authn\.self-service-freshness</code>`))
		},
	},
}

// firstLineMatching — первая строка, которую узнаёт re.
func firstLineMatching(text string, re *regexp.Regexp) string {
	for _, line := range strings.Split(text, "\n") {
		if re.MatchString(line) {
			return line
		}
	}
	return ""
}

func TestSelfServiceFreshnessDescriptionsNameEveryGatedPath(t *testing.T) {
	root := serviceRoot(t)
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("%s не прочитан: %v", rel, err)
		}
		return string(raw)
	}

	gated, rows := gatedPaths(read("docs/content/api/auth-lane.mdx"))
	if rows == 0 || len(gated) == 0 {
		t.Fatalf("таблицы путей полосы: строк %d, под окном свежести %d — сверять не с чем", rows, len(gated))
	}

	// Распознаватель доказан до обхода на синтетике в обе стороны: описание с
	// полным перечнем молчит, без одного пути и с лишним — называет расхождение.
	{
		var all []string
		for p := range gated {
			all = append(all, "`"+p+"`")
		}
		whole := namedPaths(strings.Join(all, ", "))
		if m, e := freshnessMismatch(gated, whole); len(m)+len(e) != 0 {
			t.Fatalf("распознаватель краснит полный перечень: недостаёт %v, лишние %v", m, e)
		}
		short := namedPaths(strings.Join(all[1:], ", ") + ", <code>POST /iam/v1/auth/login</code>")
		if m, e := freshnessMismatch(gated, short); len(m) != 1 || len(e) != 1 {
			t.Fatalf("распознаватель молчит на неполном перечне с лишним путём: недостаёт %v, лишние %v", m, e)
		}
	}

	for _, d := range freshnessDescriptions {
		t.Run(d.name, func(t *testing.T) {
			text := d.extract(read(d.file))
			if strings.TrimSpace(text) == "" {
				t.Fatalf("%s: описание окна свежести не найдено — судить нечего", d.file)
			}
			named := namedPaths(text)
			missing, extra := freshnessMismatch(gated, named)
			for _, p := range missing {
				t.Errorf("%s: описание окна не называет `%s`, а служба требует там свежей сессии — оператор, меняющий окно, не знает, что меняет его защиту", d.file, p)
			}
			for _, p := range extra {
				t.Errorf("%s: описание окна называет `%s`, а таблица свежести там не требует — обещана защита, которой нет", d.file, p)
			}
			t.Logf("%s: строк таблицы путей %d · под окном %d · названо описанием %d", d.file, rows, len(gated), len(named))
		})
	}
}
