// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptancecanonvalues_test.go — величина канона, названная КЛАУЗОЙ СЦЕНАРИЯ
// приёмки, обязана быть той, которую производитель объявляет СЕГОДНЯ.
//
// # Что стережётся
//
// Число, верное для другой ревизии. Канон правят, и всякая его величина есть
// функция ревизии: `#1820` сдвинул пять величин разом. Сценарий, пиннувший
// литерал, становится неисполнимым — и МОЛЧА: машинного читателя у него нет,
// красноты он не даёт, а сверяющий сценарий по приёмке получает расхождение и
// тратит заход.
//
// # Судится ТОЛЬКО клауза сценария — и это несущее различение
//
// Приёмки полны чисел канона, и подавляющее большинство из них — ЗАПИСИ ЗАМЕРА
// («мой замер», стенограммы кругов, таблицы проверок). Они свидетельствуют о
// замере, который был ВЕРЕН на своей ревизии, и правка сделала бы ложной верную
// запись. Гейт их не трогает by construction: он читает только строки клауз
// `Дано` / `Когда` / `Тогда` и их продолжение.
//
// Замер, ради которого различение введено (`#2075`, ревизия `975512cbd`):
// вхождений пяти сдвинутых величин в корпусе приёмок — **35**, из них клауз
// сценария — **2**, записей замера — **33**. Предикат, не различающий род,
// потребовал бы переписать тридцать три верные записи.
//
// # Единица «байт» принимается в ОБЕИХ формах, и граница названа
//
// Канон меряется двумя единицами (§0.7): тело блока и тело плюс баннер. Число,
// названное клаузой, засчитывается, если совпадает с ЛЮБОЙ из двух: какую из
// них имел в виду автор, машинно не решается. Гейт ловит величину, не
// производимую НИ ОДНОЙ единицей, — то есть просроченную; подмену единицы он не
// ловит, и это граница, а не пропуск.
//
// # Способность падать
//
// Доказана инъекцией по каждой оси с законным близнецом
// (`TestAcceptanceCanonValues_CanFailAndStaysSilent`): просроченная величина —
// находка, сегодняшняя — молчание, то же число ВНЕ клаузы — молчание.
package modelrender_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// acceptanceDir — корпус приёмок iam.
const acceptanceDir = "../../docs/engineering/acceptance"

var (
	// clauseHeadRe — начало клаузы сценария.
	clauseHeadRe = regexp.MustCompile(`^\s*[-*]\s*\*\*(Дано|Когда|Тогда)`)
	// bulletHeadRe — начало ЛЮБОГО пункта: им клауза и обрывается.
	bulletHeadRe = regexp.MustCompile(`^\s*[-*]\s*\*\*`)
	// canonPairRe — число рядом с единицей канона, в обоих порядках. Разметка
	// выделения между ними законна и встречается чаще голой формы.
	canonPairRe = regexp.MustCompile(
		`(?i)(\d[\d\x{00a0}\x{2009} ]*\d|\d)\s*\*{0,2}\s*(байт\p{Cyrillic}*|Б\b|символ\p{Cyrillic}*|симв\b|блок\p{Cyrillic}*|внутриблочн\p{Cyrillic}*)` +
			`|(байт\p{Cyrillic}*|символ\p{Cyrillic}*|симв\b|блок\p{Cyrillic}*|внутриблочн\p{Cyrillic}*)\s*\*{0,2}\s*(\d[\d\x{00a0}\x{2009} ]*\d|\d)`)
	// digitsRe — цифры числа без разделителей разрядов.
	digitsRe = regexp.MustCompile(`\d`)
)

// producedBy — производит ли какая-нибудь единица канона это число для этой
// величины. Величины берутся у СОСЕДНЕГО гейта (`measureCanon` из
// `headerunits_test.go`): второй кодец разошёлся бы с первым молча, и разошёлся
// бы именно там, где расхождение не видно — оба отвечают «сходится» на верном
// входе.
//
// Перечень ожидаемого возвращается вторым значением: находка обязана называть
// не только «не сходится», но и с чем именно.
func canonProducedBy(m canonCensus, unit string, value int) (bool, []int) {
	var want []int
	switch {
	case strings.HasPrefix(unit, "блок"):
		want = []int{m.Blocks}
	case strings.HasPrefix(unit, "внутриблочн"):
		want = []int{m.Comments}
	case strings.HasPrefix(unit, "симв"):
		want = []int{m.BodyRunes, m.FileRunes}
	default: // байт / Б
		want = []int{m.BodyBytes, m.FileBytes}
	}
	for _, w := range want {
		if w == value {
			return true, want
		}
	}
	return false, want
}

// parseGrouped читает число, записанное с разделителями разрядов.
func parseGrouped(s string) (int, bool) {
	digits := strings.Join(digitsRe.FindAllString(s, -1), "")
	if digits == "" {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	return n, err == nil
}

// auditAcceptanceCanonValues разбирает корпус и ВОЗВРАЩАЕТ находки: к *testing.T
// не обращается, иначе проба способности падать роняла бы саму себя.
func auditAcceptanceCanonValues(dir string, m canonCensus) (findings []string, files, clauseLines, pairs int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"корпус приёмок не прочитан: " + err.Error()}, 0, 0, 0
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		body, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- обход корпуса приёмок
		if rerr != nil {
			findings = append(findings, "приёмка "+name+" не прочитана: "+rerr.Error())
			continue
		}
		files++
		inClause := false
		for i, ln := range strings.Split(string(body), "\n") {
			switch {
			case clauseHeadRe.MatchString(ln):
				inClause = true
			case bulletHeadRe.MatchString(ln), strings.TrimSpace(ln) == "":
				// Клауза обрывается СЛЕДУЮЩИМ пунктом либо пустой строкой:
				// продолжение клаузы переносится отступом, а не пунктом.
				inClause = false
			}
			if !inClause {
				continue
			}
			clauseLines++
			for _, mt := range canonPairRe.FindAllStringSubmatch(ln, -1) {
				num, unit := mt[1], mt[2]
				if num == "" {
					num, unit = mt[4], mt[3]
				}
				value, ok := parseGrouped(num)
				if !ok {
					continue
				}
				pairs++
				produced, want := canonProducedBy(m, strings.ToLower(unit), value)
				if produced {
					continue
				}
				wanted := make([]string, 0, len(want))
				for _, w := range want {
					wanted = append(wanted, strconv.Itoa(w))
				}
				findings = append(findings, name+":"+strconv.Itoa(i+1)+
					" клауза сценария называет «"+num+" "+unit+"», которых производитель "+
					"не производит НИ ОДНОЙ единицей (сегодня: "+strings.Join(wanted, " либо ")+")"+
					"\n    строка: "+strings.TrimSpace(ln)+
					"\n    величина канона есть функция его ревизии: сценарий с просроченным литералом "+
					"неисполним, и молча — машинного читателя у него нет")
			}
		}
	}

	if files == 0 || clauseLines == 0 {
		findings = append(findings, "обход пуст: приёмок прочитано "+strconv.Itoa(files)+
			", строк клауз "+strconv.Itoa(clauseLines)+" — «находок 0» неотличимо от «прочитано 0»")
	}
	return findings, files, clauseLines, pairs
}

func TestAcceptanceScenarioCanonValuesAreTodays(t *testing.T) {
	m := measureCanon()
	findings, files, clauseLines, pairs := auditAcceptanceCanonValues(acceptanceDir, m)
	for _, f := range findings {
		t.Error(f)
	}
	if files == 0 || clauseLines == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: приёмок прочитано %d · строк клауз %d · пар «число+единица» осмотрено %d · находок %d",
		files, clauseLines, pairs, len(findings))
	t.Logf("производитель: блоков %d · байт %d (тело) либо %d (файл) · символов %d либо %d · внутриблочных %d",
		m.Blocks, m.BodyBytes, m.FileBytes, m.BodyRunes, m.FileRunes, m.Comments)
}

// ─────────────────────────────────────────────────────────────────────────────
// Доказательство способности упасть. Инъекция идёт по КОПИИ во временном
// каталоге: правка настоящих приёмок ради пробы оборвала бы соседнюю сессию в
// том же дереве. Каждый случай меняет РОВНО ОДИН факт против законного
// близнеца.

// injMeasure — производитель с заведомо известными величинами. Числа взяты не
// с дерева намеренно: инъекция обязана падать от подставленного факта, а не от
// того, что канон в этот день такой.
var injMeasure = canonCensus{
	Blocks: 32, BodyBytes: 90721, BodyRunes: 66911,
	FileBytes: 112362, FileRunes: 86340, Comments: 739,
}

// canonInjDir кладёт один синтетический документ во временный каталог.
func canonInjDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if body == "" {
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, "acceptance.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAcceptanceCanonValues_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
		why  string
	}{
		{
			name: "законный близнец: клауза называет сегодняшнюю величину",
			doc:  "**`X-01` Сценарий**\n\n- **Тогда:** перепись печатает «байт **112 362**».\n",
			why:  "верная клауза обязана молчать, иначе первый ложный срабат отключит гейт",
		},
		{
			name: "законный близнец: величина ЕДИНИЦЫ A, а не B",
			doc:  "**`X-01` Сценарий**\n\n- **Дано:** тело всех блоков — **90 721** байт.\n",
			why:  "обе единицы канона законны; гейт ловит величину, не производимую НИ ОДНОЙ",
		},
		{
			name: "просроченная величина в клаузе — находка",
			doc:  "**`X-01` Сценарий**\n\n- **Тогда:** перепись печатает «байт **110717**».\n",
			want: "не производит НИ ОДНОЙ единицей",
			why:  "сценарий с просроченным литералом неисполним, и молча",
		},
		{
			name: "просрочена ДРУГАЯ единица — внутриблочные комментарии",
			doc:  "**`X-01` Сценарий**\n\n- **Дано:** канон с **720** внутриблочными комментариями.\n",
			want: "720 внутриблочными",
			why:  "гейт обязан судить каждую величину, а не одну самую заметную",
		},
		{
			name: "та же величина ВНЕ клаузы — запись замера, гейт молчит",
			// Против первого законного близнеца изменён РОВНО ОДИН факт: рядом
			// с верной клаузой дописана запись замера с просроченными числами.
			doc: "**`X-01` Сценарий**\n\n- **Тогда:** перепись печатает «байт **112 362**».\n\n" +
				"## §0.7 Мой замер\n\n| величина | заявлено | мой замер |\n|---|---|---|\n" +
				"| файл, байт | 110 717 | **110 717** |\n\nКанон нёс 720 внутриблочных комментариев.\n",
			why: "запись замера верна на своей ревизии: правка сделала бы ложной верную запись",
		},
		{
			name: "клауза оборвана следующим пунктом — число за ней не судится",
			doc: "**`X-01` Сценарий**\n\n- **Тогда:** перепись печатает «блоков **32**».\n" +
				"- **Производитель:** П-17 (сверка доказывает 110717 байт).\n",
			why: "пункт «Производитель» клаузой не является; иначе гейт судил бы записи замера",
		},
		{
			name: "разделитель разрядов неразрывным пробелом читается",
			doc:  "**`X-01` Сценарий**\n\n- **Тогда:** «байт **110 717**».\n",
			want: "не производит НИ ОДНОЙ единицей",
			why:  "распознаватель, знающий только обычный пробел, видел бы «110» и молчал",
		},
		{
			name: "каталог пуст — обход пуст, а не «чисто»",
			doc:  "",
			want: "обход пуст",
			why:  "«находок 0» обязано быть отличимо от «прочитано 0»",
		},
		{
			name: "приёмка без единой клаузы — обход пуст",
			doc:  "# Документ\n\nПроза без сценариев.\n",
			want: "обход пуст",
			why:  "документ, потерявший сценарии, не есть зелёный вердикт",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := canonInjDir(t, tc.doc)
			findings, files, clauseLines, pairs := auditAcceptanceCanonValues(dir, injMeasure)
			joined := strings.Join(findings, "\n")
			t.Logf("перепись случая: приёмок %d · строк клауз %d · пар %d · находок %d",
				files, clauseLines, pairs, len(findings))
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("законный близнец обязан молчать (%s), а гейт сказал:\n%s", tc.why, joined)
				}
				return
			}
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("гейт обязан назвать «%s» (%s), а сказал:\n%s", tc.want, tc.why, joined)
			}
		})
	}
}

// TestAcceptanceCanonValues_ProducerIsTheSameCodecAsTheProduct закрепляет
// предпосылку: величины берутся у ТОГО ЖЕ разбора, что и продукт. Второй кодец
// разошёлся бы с первым молча — на верном входе оба отвечают «сходится».
func TestAcceptanceCanonValues_ProducerIsTheSameCodecAsTheProduct(t *testing.T) {
	m := measureCanon()
	if m.Blocks == 0 || m.FileBytes == 0 {
		t.Fatal("обход пуст: канон разобрался в ноль блоков — сверять нечего")
	}
	for _, tc := range []struct {
		unit  string
		value int
		want  bool
	}{
		{"байт", m.FileBytes, true},
		{"байт", m.BodyBytes, true},
		{"байт", m.FileBytes + 1, false},
		{"внутриблочн", m.Comments, true},
		{"внутриблочн", m.Comments - 1, false},
		{"блок", m.Blocks, true},
		{"симв", m.BodyRunes, true},
		{"симв", m.FileRunes, true},
	} {
		got, want := canonProducedBy(m, tc.unit, tc.value)
		if got != tc.want {
			t.Errorf("единица %q, величина %d: производится=%v, ожидалось %v (сегодня %v)",
				tc.unit, tc.value, got, tc.want, want)
		}
	}
	t.Logf("перепись производителя: блоков %d · байт %d/%d · символов %d/%d · внутриблочных %d",
		m.Blocks, m.BodyBytes, m.FileBytes, m.BodyRunes, m.FileRunes, m.Comments)
}
