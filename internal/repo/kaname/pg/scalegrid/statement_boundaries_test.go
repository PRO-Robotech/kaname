// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"strings"
	"testing"
)

// ГРАНИЦЫ ОПЕРАТОРОВ ПРОВЕРЯЮТСЯ НА ВСЕХ ФОРМАХ, КОТОРЫЕ ОБЕЩАЕТ ШАПКА
//
// Шапки четырёх отчётов утверждают: «границы операторов тоже разбираются —
// точка с запятой внутри литерала, имени в кавычках и тела в долларовых
// кавычках оператора не кончает». Проверено это было на трёх формах из
// четырёх: строка с обратным слэшем (`E'…\'…'`) распознавателю известна не
// была.
//
// Цена ошибки здесь НЕ «один потерянный оператор». Разошедшись, пропуск
// литерала съедает ВЕСЬ ОСТАВШИЙСЯ ТЕКСТ файла: незакрытая кавычка тянется до
// конца. Замер на трёх операторах — комментарий с такой строкой, затем правка
// измеряемой таблицы, затем индекс на ней:
//
//	операторов выделено 1 из 3, вердикт false
//
// Экземпляров в корпусе сегодня ноль, поэтому отказ МОЛЧАЛИВЫЙ и ждёт первой
// такой миграции.
func TestStatementBoundariesKnowEveryLawfulStringForm(t *testing.T) {
	measured := []string{"access_bindings"}

	// tail — то, что обязано пережить любой литерал перед ним. Один и тот же у
	// всех случаев: отличие каждой пары — РОВНО форма литерала.
	const tail = "ALTER TABLE kaname.access_bindings ADD COLUMN note text;\n" +
		"CREATE INDEX ab_note_idx ON kaname.access_bindings (note);\n"

	cases := []struct {
		name    string
		literal string
		// statements — сколько операторов обязано выделиться ВСЕГО (литерал + хвост).
		statements int
	}{
		{
			name:       "обычная строка",
			literal:    "COMMENT ON TABLE kaname.limits IS 'простая заметка';\n",
			statements: 3,
		},
		{
			name: "обычная строка с УДВОЕННОЙ кавычкой",
			// Единственный способ внести кавычку в обычную строку.
			literal:    "COMMENT ON TABLE kaname.limits IS 'it''s a note';\n",
			statements: 3,
		},
		{
			name: "обычная строка с обратным слэшем",
			// При standard_conforming_strings=on (умолчание) обратный слэш в
			// обычной строке — обычный знак, и кавычку он НЕ экранирует.
			literal:    "COMMENT ON TABLE kaname.limits IS 'путь C:\\\\tmp';\n",
			statements: 3,
		},
		{
			name: "СТРОКА С ЭКРАНИРОВАНИЕМ: E'…\\'…'",
			// Здесь обратный слэш экранирует кавычку ВСЕГДА. Прежний пропуск
			// этой формы не знал, кончал литерал на `\'` и дальше съедал весь
			// хвост файла.
			literal:    "COMMENT ON TABLE kaname.limits IS E'it\\'s a note';\n",
			statements: 3,
		},
		{
			name:       "строка с экранированием, слэш в НИЖНЕМ регистре",
			literal:    "COMMENT ON TABLE kaname.limits IS e'it\\'s a note';\n",
			statements: 3,
		},
		{
			name: "строка с экранированием и УДВОЕННЫМ слэшем перед кавычкой",
			// `\\` — это слэш, и кавычка за ним литерал ЗАКРЫВАЕТ.
			literal:    "COMMENT ON TABLE kaname.limits IS E'путь C:\\\\';\n",
			statements: 3,
		},
		{
			name:       "точка с запятой ВНУТРИ строки с экранированием",
			literal:    "COMMENT ON TABLE kaname.limits IS E'сначала одно; потом другое\\'';\n",
			statements: 3,
		},
		{
			name:       "имя в кавычках с точкой с запятой",
			literal:    "COMMENT ON TABLE kaname.\"limits;odd\" IS 'заметка';\n",
			statements: 3,
		},
		{
			name: "долларовые кавычки с точкой с запятой в теле",
			literal: "CREATE FUNCTION kaname.noop() RETURNS void LANGUAGE plpgsql AS $b$\n" +
				"BEGIN PERFORM 1; RETURN; END;\n$b$;\n",
			statements: 3,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "-- +goose Up\n" + c.literal + tail
			got := sqlStatements(src)
			if len(got) != c.statements {
				var shown []string
				for _, s := range got {
					if len(s) > 70 {
						s = s[:70] + "…"
					}
					shown = append(shown, strings.Join(strings.Fields(s), " "))
				}
				t.Fatalf("операторов выделено %d, ожидалось %d — незакрытый литерал съедает "+
					"ВЕСЬ оставшийся текст, а не один оператор:\n  %s",
					len(got), c.statements, strings.Join(shown, "\n  "))
			}
			// Хвост обязан не просто выделиться, а быть УВИДЕННЫМ предикатом.
			if !migrationTouches(src, measured, scopeReadPlan, corpusIndex{}) {
				t.Fatalf("правка измеряемой таблицы в хвосте ПОТЕРЯНА: отчёт о стоимости " +
					"вердикта остался бы «свежим», когда план чтения уже другой")
			}
		})
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ ко всему набору: тот же хвост над НЕИЗМЕРЯЕМОЙ таблицей
	// молчит. Без него «краснеет всегда» прошло бы каждый случай выше.
	twin := "-- +goose Up\nCOMMENT ON TABLE kaname.limits IS E'it\\'s a note';\n" +
		"ALTER TABLE kaname.limits ADD COLUMN note text;\n"
	if migrationTouches(twin, measured, scopeReadPlan, corpusIndex{}) {
		t.Fatal("тот же хвост над НЕИЗМЕРЯЕМОЙ таблицей признан влияющим: предикат " +
			"отвечает одинаково на всё, и случаи выше ничего не держат")
	}
	t.Logf("перепись: форм литерала проверено %d; законный близнец над неизмеряемой молчит",
		len(cases))
}

// ВНЕШНЯЯ ТАБЛИЦА — ТАБЛИЦА (третий вид той же корзины)
//
// В словаре безвредных стояла запись `foreign` с доводом «это своя таблица, не
// измеряемая». Довод противоречил и коду, и пробе одного с ним диффа: разбор
// СОЗДАНИЯ внешнюю таблицу уже брал как таблицу, а правку и снятие — нет.
//
// Внешняя таблица носит имя в той же схеме и тем же именем читается запросом
// вердикта. Оговорка «внешняя» говорит, где лежат данные, а не чьё имя стоит
// субъектом.
func TestForeignTableIsATable(t *testing.T) {
	measured := []string{"access_bindings"}

	cases := []struct {
		name string
		sql  string
		want bool
	}{
		{"создание внешней таблицы с именем измеряемой", "CREATE FOREIGN TABLE kaname.access_bindings (id text) SERVER s;", true},
		{"правка внешней таблицы измеряемого имени", "ALTER FOREIGN TABLE kaname.access_bindings ADD COLUMN note text;", true},
		{"снятие внешней таблицы измеряемого имени", "DROP FOREIGN TABLE kaname.access_bindings;", true},
		{"ЗАКОННЫЙ БЛИЗНЕЦ: та же правка ЧУЖОЙ внешней таблицы", "ALTER FOREIGN TABLE kaname.limits ADD COLUMN note text;", false},
		{"ЗАКОННЫЙ БЛИЗНЕЦ: снятие ЧУЖОЙ внешней таблицы", "DROP FOREIGN TABLE kaname.limits;", false},
		// Обёртка данных и сервер таблицами не являются — но и безвредными
		// видами не объявлены: их в каталоге миграций нет, значит доказать
		// безвредность не на чем. Исход осторожный, и это ВИДНО, а не молчит.
		{"обёртка данных — вид незнакомый, судится осторожно", "CREATE FOREIGN DATA WRAPPER kaname_fdw HANDLER kaname.h;", true},
		{"сервер — вид незнакомый, судится осторожно", "CREATE SERVER kaname_srv FOREIGN DATA WRAPPER kaname_fdw;", true},
	}
	var influencing, ignored int
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := migrationTouches(c.sql, measured, scopeReadPlan, corpusIndex{})
			if got != c.want {
				t.Fatalf("вердикт %v, ожидался %v", got, c.want)
			}
			if got {
				influencing++
			} else {
				ignored++
			}
		})
	}
	// Незнакомый вид обязан НАЗЫВАТЬ себя, а не просто краснеть: находка без
	// координаты требует от читателя той же работы заново.
	if got := ddlStatementOf("CREATE FOREIGN DATA WRAPPER kaname_fdw HANDLER kaname.h;",
		corpusIndex{}); got.unknownObject != "foreign data" {
		t.Fatalf("незнакомый вид назван %q, ожидалось \"foreign data\"", got.unknownObject)
	}
	t.Logf("перепись инъекции: случаев %d; признано влияющими %d; отсеяно %d",
		len(cases), influencing, ignored)
	if influencing == 0 || ignored == 0 {
		t.Fatal("инъекция односторонняя")
	}
}
