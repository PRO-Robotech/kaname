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
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	gmast "github.com/yuin/goldmark/extension/ast"
	gmtext "github.com/yuin/goldmark/text"
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

// installMarkdown — разборщик CommonMark с таблицами GFM: так INSTALL.md
// читает страница. Ручной разбор строк не знал вложения: блок кода в цитате
// (`> ```…`) либо в пункте списка читался абзацем — судить надо узел разбора,
// а не строку.
var installMarkdown = goldmark.New(goldmark.WithExtensions(extension.Table))

// installVisibleBlocks — утверждения INSTALL, которые оператор ЧИТАЕТ как
// объявление: текст вне порождённого блока, без HTML-комментариев (их не видно
// на странице) и без блоков кода (там пример либо прежняя, снятая ручка) — на
// любой глубине вложения в цитаты и пункты списков.
// Единица утверждения — блок разбора: абзац целиком (строки, перенесённые по
// ширине, — одно утверждение), строка таблицы, текст пункта списка, заголовок.
// Ключ и переменная в соседних строках одного абзаца — одно утверждение; в
// соседних строках таблицы и в соседних пунктах — разные.
// Возвращает блоки и число прочитанных строк вне порождённого блока (перепись).
func installVisibleBlocks(text string) (blocks []string, outside int) {
	var kept []string
	inGenerated := false
	for _, line := range strings.Split(text, "\n") {
		switch strings.TrimSpace(line) {
		case installGeneratedBegin:
			inGenerated = true
			continue
		case installGeneratedEnd:
			// Порождённый блок — граница блока разбора: соседние абзацы не сливаются.
			inGenerated = false
			kept = append(kept, "")
			continue
		}
		if inGenerated {
			continue
		}
		outside++
		kept = append(kept, line)
	}
	source := []byte(strings.Join(kept, "\n"))
	doc := installMarkdown.Parser().Parse(gmtext.NewReader(source))
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n.Kind() {
		case ast.KindCodeBlock, ast.KindFencedCodeBlock, ast.KindHTMLBlock:
			return ast.WalkSkipChildren, nil
		case ast.KindParagraph, ast.KindTextBlock, ast.KindHeading,
			gmast.KindTableHeader, gmast.KindTableRow:
			var b strings.Builder
			visibleInlineText(&b, n, source)
			blocks = append(blocks, b.String())
			return ast.WalkSkipChildren, nil
		}
		return ast.WalkContinue, nil
	})
	return blocks, outside
}

// visibleInlineText — видимый текст строчных потомков узла: инлайн-код —
// текст, HTML-комментарий и прочий сырой HTML — нет; ячейки строки таблицы
// разделены `|`.
func visibleInlineText(b *strings.Builder, n ast.Node, source []byte) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch t := c.(type) {
		case *ast.RawHTML:
			continue
		case *ast.Text:
			b.Write(t.Segment.Value(source))
			if t.SoftLineBreak() || t.HardLineBreak() {
				b.WriteByte('\n')
			}
			continue
		case *ast.String:
			b.Write(t.Value)
			continue
		case *gmast.TableCell:
			b.WriteString("| ")
		}
		visibleInlineText(b, c, source)
	}
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
	stmt := "Адрес полосы — `" + key + "` (переменная `" + env + "`)."
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
		"L2 ключ и переменная в соседних строках абзаца — в счёт":            {text: "Адрес полосы — `" + key + "`\n(переменная `" + env + "`).\n", want: 1},
		"L2 близнец: соседние строки таблицы — разные утверждения":           {text: "| ключ | как задать |\n|---|---|\n| `" + key + "` | … |\n| `" + env + "` | … |\n", want: 0},
		"L2 строка настоящей таблицы — в счёт":                               {text: "| ключ | как задать |\n|---|---|\n" + row + "\n", want: 1},
		"L2 близнец: ключ в шапке, переменная в строке — разные утверждения": {text: "| `" + key + "` | x |\n|---|---|\n| `" + env + "` | … |\n", want: 0},
		"L2 близнец: разные абзацы — не в счёт":                              {text: "`" + key + "`\n\n`" + env + "`\n", want: 0},
		"L2 близнец: соседние пункты списка — не в счёт":                     {text: "- `" + key + "`\n- `" + env + "`\n", want: 0},
		// M3: отступной блок кода (4 пробела либо табуляция после пустой строки) — тот же класс, что M2.
		"M3 строка в отступном блоке кода — не в счёт":              {text: "Пример:\n\n    " + row + "\n", want: 0},
		"M3 утверждение в отступном блоке кода — не в счёт":         {text: "Пример:\n\n    " + stmt + "\n", want: 0},
		"M3 отступной блок в начале документа — не в счёт":          {text: "    " + stmt + "\n", want: 0},
		"M3 отступ табуляцией — не в счёт":                          {text: "Пример:\n\n\t" + stmt + "\n", want: 0},
		"M3 блок кода внутри пункта списка — не в счёт":             {text: "- пункт\n\n      " + stmt + "\n", want: 0},
		"M3 близнец: та же строка без отступа — в счёт":             {text: "Пример:\n\n" + stmt + "\n", want: 1},
		"M3 близнец: отступ без пустой строки — продолжение абзаца": {text: "Пример:\n    " + stmt + "\n", want: 1},
		"M3 близнец: абзац-продолжение пункта списка — в счёт":      {text: "- пункт\n\n    " + stmt + "\n", want: 1},
		"M3 близнец: после отступного блока — в счёт":               {text: "    код\n\n" + stmt + "\n", want: 1},
		// M4: `<!--` внутри инлайн-кода — текст, а не начало комментария.
		"M4 `<!--` в инлайн-коде не прячет следующую строку":  {text: "Комментарий открывается `<!--`.\n" + row + "\n", want: 1},
		"M4 близнец: настоящий комментарий после инлайн-кода": {text: "`x` <!--\n" + row + "\n-->\n", want: 0},
		// Q: блоки кода, вложенные в цитату либо в пункт списка, — тот же класс,
		// что M2 и M3: префикс цитаты `> ` и отступ пункта не делают код текстом.
		"Q1 огороженный блок кода в цитате — не в счёт":               {text: "> ```text\n> " + row + "\n> ```\n", want: 0},
		"Q1 огороженный блок кода в цитате без пробела — не в счёт":   {text: ">```\n>" + stmt + "\n>```\n", want: 0},
		"Q2 отступной блок кода в цитате — не в счёт":                 {text: "> пример:\n>\n>     " + stmt + "\n", want: 0},
		"Q3 огороженный блок кода в пункте списка — не в счёт":        {text: "- пункт\n\n  ```\n  " + stmt + "\n  ```\n", want: 0},
		"Q4 блок кода в цитате внутри пункта списка — не в счёт":      {text: "- пункт\n  > ```\n  > " + stmt + "\n  > ```\n", want: 0},
		"Q5 блок кода во вложенной цитате — не в счёт":                {text: "> > ```\n> > " + stmt + "\n> > ```\n", want: 0},
		"Q1 близнец: абзац в цитате — в счёт":                         {text: "> " + stmt + "\n", want: 1},
		"Q1 близнец: абзац в цитате после блока кода в ней — в счёт":  {text: "> ```\n> x\n> ```\n>\n> " + stmt + "\n", want: 1},
		"Q2 близнец: отступ в цитате без пустой строки — в счёт":      {text: "> пример:\n>     " + stmt + "\n", want: 1},
		"Q3 близнец: абзац в пункте списка после блока кода — в счёт": {text: "- пункт\n\n  ```\n  x\n  ```\n\n  " + stmt + "\n", want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, naming := installNamesKnob(tc.text, key, env)
			require.Equal(t, tc.want, naming)
		})
	}
}
