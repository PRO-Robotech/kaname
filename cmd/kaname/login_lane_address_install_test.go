// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_lane_address_install_test.go — адрес полосы входа, которого требует
// страж посадки, назван оператору в INSTALL.md (kaname#258, п.4).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// [requireLoginLaneTLS] отказывает боевому старту без адреса полосы входа, и
// умолчания у адреса нет. Таблица обязательных величин INSTALL §3 порождается из
// стража НАСТРОЙКИ и этого стража не видит BY CONSTRUCTION: он — стадия
// «посадка» (INSTALL §5). Значит, строка об адресе живёт ВНЕ порождённого блока,
// иначе оператор узнаёт о ручке отказом на стенде.
//
// Имя ключа выводится из имени переменной, которое печатает отказ стража
// ([knobLoginLane]), тем же правилом, каким его выводит INSTALL §3 (точка — два
// подчёркивания, дефис — одно): переименование ручки роняет эту пробу, а не
// оставляет документ называть прежнее имя.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	installGeneratedBegin = "<!-- ПОРОЖДЕНО: обязательные величины — начало -->"
	installGeneratedEnd   = "<!-- ПОРОЖДЕНО: обязательные величины — конец -->"
)

// keyOfEnv — путь ключа настройки из имени переменной: префикс службы снят,
// `__` — точка, `_` — дефис, регистр нижний.
func keyOfEnv(env string) string {
	rest := strings.ToLower(strings.TrimPrefix(env, "KANAME_"))
	parts := strings.Split(rest, "__")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(p, "_", "-")
	}
	return strings.Join(parts, ".")
}

// installVisibleBlocks — утверждения INSTALL, которые оператор ЧИТАЕТ как
// объявление: текст вне порождённого блока, без HTML-комментариев (их не видно
// на странице) и без блоков кода (там пример либо прежняя, снятая ручка).
// Единица утверждения — блок markdown: абзац (строки до пустой) целиком, а
// строка таблицы и пункт списка — каждый отдельно. Ключ и переменная в соседних
// строках одного абзаца — одно утверждение, перенесённое по ширине; в соседних
// строках таблицы — два разных. Возвращает блоки и число прочитанных строк
// вне порождённого блока (перепись).
func installVisibleBlocks(text string) (blocks []string, outside int) {
	var (
		inGenerated, inComment bool
		fence                  string
		cur                    []string
	)
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, line := range strings.Split(text, "\n") {
		switch strings.TrimSpace(line) {
		case installGeneratedBegin:
			flush()
			inGenerated = true
			continue
		case installGeneratedEnd:
			inGenerated = false
			continue
		}
		if inGenerated {
			continue
		}
		outside++
		trimmed := strings.TrimLeft(line, " ")
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) && strings.Trim(strings.TrimSpace(trimmed), fence[:1]) == "" {
				fence = ""
			}
			continue
		}
		if !inComment && len(line)-len(trimmed) < 4 &&
			(strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")) {
			flush()
			fence = trimmed[:3]
			for _, r := range trimmed[3:] {
				if string(r) != fence[:1] {
					break
				}
				fence += fence[:1]
			}
			continue
		}
		visible, stillInComment := stripHTMLComments(line, inComment)
		inComment = stillInComment
		v := strings.TrimSpace(visible)
		switch {
		case v == "":
			// Пустая строка (или целиком комментарий) — граница абзаца, только
			// если строка и в источнике пуста; строка-комментарий абзаца не рвёт.
			if strings.TrimSpace(line) == "" {
				flush()
			}
		case strings.HasPrefix(v, "|"), isListItem(v):
			flush()
			cur = append(cur, visible)
			if strings.HasPrefix(v, "|") {
				flush()
			}
		case strings.HasPrefix(v, "#"):
			flush()
			blocks = append(blocks, visible)
		default:
			cur = append(cur, visible)
		}
	}
	flush()
	return blocks, outside
}

// stripHTMLComments — видимая часть строки; inComment — открыт ли комментарий
// на входе, второе значение — открыт ли он на выходе.
func stripHTMLComments(line string, inComment bool) (string, bool) {
	var b strings.Builder
	for line != "" {
		if inComment {
			end := strings.Index(line, "-->")
			if end < 0 {
				return b.String(), true
			}
			line = line[end+len("-->"):]
			inComment = false
			continue
		}
		start := strings.Index(line, "<!--")
		if start < 0 {
			b.WriteString(line)
			break
		}
		b.WriteString(line[:start])
		line = line[start+len("<!--"):]
		inComment = true
	}
	return b.String(), inComment
}

// isListItem — начало пункта списка: `- `, `* `, `+ ` либо `N. `.
func isListItem(v string) bool {
	if strings.HasPrefix(v, "- ") || strings.HasPrefix(v, "* ") || strings.HasPrefix(v, "+ ") {
		return true
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	return i > 0 && strings.HasPrefix(v[i:], ". ")
}

// installNamesKnob — суждение над ПРОИЗВОЛЬНЫМ текстом: сколько видимых
// утверждений вне порождённого блока называют и ключ, и переменную. Возвращает
// число прочитанных строк вне блока (перепись) и число назвавших утверждений.
func installNamesKnob(text, key, env string) (outside, naming int) {
	blocks, outside := installVisibleBlocks(text)
	for _, b := range blocks {
		if strings.Contains(b, key) && strings.Contains(b, env) {
			naming++
		}
	}
	return outside, naming
}

func TestInstallNamesTheLoginLaneAddressTheLandingGuardDemands(t *testing.T) {
	key := keyOfEnv(knobLoginLane)
	require.Equal(t, "api-server.login-lane-endpoint", key,
		"вывод ключа из переменной разошёлся с правилом INSTALL §3 — проба судила бы не ту ручку")

	path := filepath.Join("..", "..", "INSTALL.md")
	raw, err := os.ReadFile(path) // #nosec G304 -- путь из корня службы
	require.NoErrorf(t, err, "INSTALL.md не читается: %s", path)

	outside, naming := installNamesKnob(string(raw), key, knobLoginLane)
	t.Logf("ПЕРЕПИСЬ: строк INSTALL вне порождённого блока %d · видимых утверждений, назвавших %s и %s, %d",
		outside, key, knobLoginLane, naming)
	require.NotZero(t, outside, "вне порождённого блока НЕТ строк — судить нечего, это не зелёное")
	require.NotZerof(t, naming, "INSTALL.md не называет ВНЕ порождённого блока адрес полосы входа "+
		"(%s, переменная %s), а страж посадки без него отказывает боевому старту: оператор узнает о "+
		"ручке отказом на стенде", key, knobLoginLane)
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

func TestInstallNamesKnobInjection(t *testing.T) {
	key, env := "api-server.login-lane-endpoint", "KANAME_API_SERVER__LOGIN_LANE_ENDPOINT"
	row := "| `" + key + "` | переменная `" + env + "` | боевой режим | … |"
	for name, tc := range map[string]struct {
		text string
		want int
	}{
		"строка вне блока — найдена":      {text: "# §5\n" + row + "\n", want: 1},
		"строка внутри блока — не в счёт": {text: installGeneratedBegin + "\n" + row + "\n" + installGeneratedEnd + "\n", want: 0},
		"только ключ без переменной":      {text: "`" + key + "`\n", want: 0},
		"только переменная без ключа":     {text: "`" + env + "`\n", want: 0},
		"ни строки": {text: "# §5\n", want: 0},
		"после блока — снова в счёт": {text: installGeneratedBegin + "\n" + installGeneratedEnd + "\n" + row + "\n", want: 1},
		// M1: строка внутри HTML-комментария оператору не видна.
		"M1 строка в однострочном HTML-комментарии — не в счёт":  {text: "<!-- " + row + " -->\n", want: 0},
		"M1 строка в многострочном HTML-комментарии — не в счёт": {text: "<!--\nснято:\n" + row + "\n-->\n", want: 0},
		"M1 близнец: после закрытого комментария — в счёт":       {text: "<!-- примечание -->\n" + row + "\n", want: 1},
		// M2: строка в блоке кода — пример либо прежняя ручка, а не объявление.
		"M2 строка в блоке кода — не в счёт":              {text: "```text\n# прежняя ручка, снята\n" + row + "\n```\n", want: 0},
		"M2 строка в блоке кода под тильдами — не в счёт": {text: "~~~\n" + row + "\n~~~\n", want: 0},
		"M2 близнец: после закрытого блока — в счёт":      {text: "```\nx\n```\n" + row + "\n", want: 1},
		// L2: абзац, перенесённый на две строки, — одно утверждение.
		"L2 ключ и переменная в соседних строках абзаца — в счёт":  {text: "Адрес полосы — `" + key + "`\n(переменная `" + env + "`).\n", want: 1},
		"L2 близнец: соседние строки таблицы — разные утверждения": {text: "| `" + key + "` | … |\n| `" + env + "` | … |\n", want: 0},
		"L2 близнец: разные абзацы — не в счёт":                    {text: "`" + key + "`\n\n`" + env + "`\n", want: 0},
		"L2 близнец: соседние пункты списка — не в счёт":           {text: "- `" + key + "`\n- `" + env + "`\n", want: 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, naming := installNamesKnob(tc.text, key, env)
			require.Equal(t, tc.want, naming)
		})
	}
}
