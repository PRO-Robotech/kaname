// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// headerunits_test.go — величины замера в шапке пакета НАЗЫВАЮТ свою единицу и
// воспроизводятся разбором канона.
//
// # Предмет
//
// Две строки одной таблицы шапки считали РАЗНЫМ и были обозначены одинаково:
// «65 828 Б» — счёт символами, «110 717 Б» — байтами. Число без единицы не
// проверяется; число с ЧУЖОЙ единицей рядом с правильным хуже, чем без единицы
// вовсе: оно выглядит сопоставимым, и на нём строят посылку (так и вышло — из
// этой таблицы задача #1847 взяла своё число).
//
// # Что судится
//
// Каждая величина шапки названа своей единицей (`Б` либо `симв`) и совпадает с
// разбором канона: блоков · тело в байтах · тело в символах · файл в байтах ·
// файл в символах · внутриблочных комментариев.
//
// # Почему гейт, а не внимание
//
// Шапка объявляет ЗАМЕР дерева, а дерево движется. Величина, которую никто не
// пересчитывает, стареет молча и остаётся на вид измеренной. Красное здесь —
// не поломка, а требование пересчитать шапку вместе с каноном.
package modelrender_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho-iam/internal/modelrender"
)

// canonFile — файл, чью шапку сверяем.
const canonFile = "canon.go"

// headerValueRe — величина шапки с ЕДИНИЦЕЙ. Единица обязательна: форма
// «32 блока · 65 828» без неё под этот распознаватель не подпадает и потому
// красным не станет — поэтому наличие обязательных величин проверяется отдельно.
//
// # Граница РАЗДЕЛИТЕЛЯ единицы, и она измерена, а не предположена
//
// Первая редакция заканчивалась `\b`. В RE2 это ГРАНИЦА СЛОВА ПО ASCII, и после
// кириллической буквы она не наступает НИКОГДА: распознаватель находил в шапке
// ноль величин при двух написанных, то есть молчал — не краснел и не зеленел.
// Ровно тот класс, который корпус требует от гейта: форма, о которой
// распознаватель не знает, оказывается вне наблюдения.
var headerValueRe = regexp.MustCompile(`([\d ]*\d)\s*(Б|симв)(?:[^\pL]|$)`)

// canonCensus — то же, что объявляет шапка, но посчитанное разбором.
type canonCensus struct {
	Blocks, BodyBytes, BodyRunes, FileBytes, FileRunes, Comments int
}

func measureCanon() canonCensus {
	dsl := authzmodel.DSL
	c := canonCensus{FileBytes: len(dsl), FileRunes: len([]rune(dsl))}
	for _, b := range modelrender.SplitCanon([]byte(dsl)) {
		c.Blocks++
		c.BodyBytes += len(b.Body)
		c.BodyRunes += len([]rune(string(b.Body)))
		for _, ln := range strings.Split(string(b.Body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "#") {
				c.Comments++
			}
		}
	}
	return c
}

// headerNumbers — величины, названные шапкой, приведённые к числу вместе с
// единицей. Разделители разрядов снимаются: шапка пишет их неразрывным
// пробелом, и распознаватель, знающий только обычный, видел бы «65» вместо
// «65 828».
func headerNumbers(text string) map[string][]int {
	out := map[string][]int{}
	for _, m := range headerValueRe.FindAllStringSubmatch(text, -1) {
		digits := strings.NewReplacer(" ", "", " ", "").Replace(m[1])
		n, err := strconv.Atoi(digits)
		if err != nil {
			continue
		}
		out[m[2]] = append(out[m[2]], n)
	}
	return out
}

// auditHeaderUnits ВОЗВРАЩАЕТ находки: разбор, обращающийся к *testing.T,
// инъекции не поддаётся — подставная шапка роняла бы саму пробу способности
// падать.
func auditHeaderUnits(header string, got canonCensus) (findings []string, valuesWithUnit int) {
	if strings.TrimSpace(header) == "" {
		return []string{"обход пуст: шапка пакета не прочитана — гейт судил бы о непрочитанном"}, 0
	}
	if got.Blocks == 0 {
		return []string{"обход пуст: канон разобрался в ноль блоков — сверять нечего"}, 0
	}

	byUnit := map[string]map[int]bool{}
	for unit, vals := range headerNumbers(header) {
		byUnit[unit] = map[int]bool{}
		for _, v := range vals {
			byUnit[unit][v] = true
			valuesWithUnit++
		}
	}
	if valuesWithUnit == 0 {
		return []string{"в шапке нет ни одной величины с названной единицей — предмет гейта " +
			"отсутствует, а «находок 0» неотличимо от «прочитано 0»"}, 0
	}

	known := map[string]map[int]bool{
		"Б":    {got.BodyBytes: true, got.FileBytes: true},
		"симв": {got.BodyRunes: true, got.FileRunes: true},
	}
	units := make([]string, 0, len(byUnit))
	for unit := range byUnit {
		units = append(units, unit)
	}
	sort.Strings(units)
	for _, unit := range units {
		vals := make([]int, 0, len(byUnit[unit]))
		for v := range byUnit[unit] {
			vals = append(vals, v)
		}
		sort.Ints(vals)
		for _, v := range vals {
			if !known[unit][v] {
				findings = append(findings, fmt.Sprintf(
					"шапка называет %d %s — разбор канона такой величины в этой единице НЕ даёт.\n"+
						"    разбор: тело %d Б / %d симв · файл %d Б / %d симв\n"+
						"    величина либо просрочена, либо посчитана в другой единице, чем обозначена",
					v, unit, got.BodyBytes, got.BodyRunes, got.FileBytes, got.FileRunes))
			}
		}
	}
	// Обязательные: обе единицы у ТЕЛА названы. Без этого таблица снова
	// сравнивала бы несравнимое, ничего не нарушая формально.
	if !byUnit["Б"][got.BodyBytes] {
		findings = append(findings, fmt.Sprintf("шапка не называет тело блоков в байтах (%d Б) — "+
			"строка единицы A остаётся несопоставимой со строкой единицы B", got.BodyBytes))
	}
	if !byUnit["симв"][got.BodyRunes] {
		findings = append(findings, fmt.Sprintf("шапка не называет тело блоков в символах (%d симв)", got.BodyRunes))
	}
	if !strings.Contains(header, strconv.Itoa(got.Comments)) {
		findings = append(findings, fmt.Sprintf("шапка не называет число внутриблочных комментариев (%d)", got.Comments))
	}
	return findings, valuesWithUnit
}

// packageHeader — текст до объявления пакета.
func packageHeader(body string) string {
	if i := strings.Index(body, "\npackage "); i > 0 {
		return body[:i]
	}
	return body
}

func TestCanonHeaderNamesItsUnitAndReproducesTheMeasurement(t *testing.T) {
	raw, err := os.ReadFile(canonFile)
	if err != nil {
		t.Fatalf("шапка не прочитана: %v", err)
	}
	got := measureCanon()
	findings, withUnit := auditHeaderUnits(packageHeader(string(raw)), got)
	for _, f := range findings {
		t.Error(f)
	}
	if got.Blocks == 0 || withUnit == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: величин с единицей в шапке %d · блоков %d · тело %d Б / %d симв · "+
		"файл %d Б / %d симв · внутриблочных комментариев %d",
		withUnit, got.Blocks, got.BodyBytes, got.BodyRunes, got.FileBytes, got.FileRunes, got.Comments)
}

// ─────────────────────────────────────────────────────────────────────────────
// Доказательство способности упасть. Инъекция идёт по ПОДСТАВНОЙ шапке: правка
// настоящей ради пробы оборвала бы соседнюю сессию в том же дереве.

func TestCanonHeaderUnits_CanFailAndStaysSilent(t *testing.T) {
	got := canonCensus{Blocks: 32, BodyBytes: 89017, BodyRunes: 65828, FileBytes: 110717, FileRunes: 85314, Comments: 720}
	good := "// тело 89017 Б · 65828 симв · файл 110717 Б · 85314 симв · 720 комментариев\n"

	cases := []struct {
		name   string
		header string
		want   string
		why    string
	}{
		{
			name:   "законный близнец: обе единицы названы и сходятся",
			header: good,
			why:    "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора",
		},
		{
			name:   "символы обозначены байтами",
			header: "// тело 65828 Б · файл 110717 Б · 720 комментариев\n",
			want:   "шапка называет 65828 Б",
			why:    "ровно предмет #1857: две строки одной таблицы считают разным под одним обозначением",
		},
		{
			name:   "величина просрочена",
			header: "// тело 89017 Б · 65828 симв · файл 999999 Б · 85314 симв · 720 комментариев\n",
			want:   "шапка называет 999999 Б",
			why:    "шапка объявляет замер дерева, а дерево движется: непересчитанная величина стареет молча",
		},
		{
			name:   "единица не названа вовсе",
			header: "// тело 89017 · 65828 · файл 110717 · 720 комментариев\n",
			want:   "нет ни одной величины с названной единицей",
			why:    "число без единицы не проверяется — предмет гейта в этой шапке отсутствует",
		},
		{
			name:   "названа одна сторона из двух",
			header: "// тело 89017 Б · файл 110717 Б · 85314 симв · 720 комментариев\n",
			want:   "не называет тело блоков в символах",
			why:    "односторонняя таблица возвращает несопоставимость: сравнивать байт со символом снова нечем",
		},
		{
			name:   "шапка пуста",
			header: "   \n",
			want:   "обход пуст",
			why:    "«находок 0» обязано быть отличимо от «прочитано 0»",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, _ := auditHeaderUnits(tc.header, got)
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законной шапке то, чего в ней нет — первое же ложное "+
						"срабатывание снимает гейт.\nнаходки:\n  %s", strings.Join(findings, "\n  "))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s", tc.why)
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("разбор покраснел не на том: ждали %q\nнаходки:\n  %s",
					tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}
