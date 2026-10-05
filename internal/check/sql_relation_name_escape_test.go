// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSQLEscape_RangeEdgeHasANamedOutcome — экранирование на краю диапазона
// даёт НАЗВАННЫЙ исход, и назван он по базе, а не по удобству разбора. Каждая
// строка сверена с postgres:16-alpine (16.15) 2026-09-16 одним запросом вида
// `SELECT E'…'` / `SELECT U&'…'`. Молчаливое усечение здесь запрещено
// (`kaname#161`), но и «отказ раскрытия» там, где база значение ПРИНИМАЕТ,
// был бы пропуском имени — см. `\563`.
func TestSQLEscape_RangeEdgeHasANamedOutcome(t *testing.T) {
	t.Run("E-строка, \\ooo — младший байт, как strtoul → unsigned char у базы", func(t *testing.T) {
		for in, want := range map[string]string{
			`\137`: "_",    // в диапазоне: контроль
			`\377`: "\xff", // верх диапазона байта
			`\563`: "s",    // 371 → 115: база читает E'method\563' как 'methods' — отказ дал бы ПРОПУСК
			`\777`: "\xff", // 511 → 255: байт, который база затем отвергнет кодировкой UTF8, но лексика даёт его
			`\400`: "\x00", // 256 → 0
		} {
			require.Equal(t, want, sqlUnbackslash(in), "%q", in)
		}
	})
	t.Run("E-строка, \\u и \\U — ноль и выше U+10FFFF база отвергает, экранирование остаётся как написано", func(t *testing.T) {
		for in, want := range map[string]string{
			`\u0041`:      "A",          // контроль, четыре знака
			`\U00000041`:  "A",          // контроль, восемь знаков
			`\U0010FFFF`:  "\U0010FFFF", // верх диапазона кодовой точки — принимается
			`\U00110000`:  `\U00110000`, // база: invalid Unicode escape value
			`\UFFFFFFFF`:  `\UFFFFFFFF`, // rune(v) дал бы отрицательное и U+FFFD молча
			`\u0000`:      `\u0000`,     // ноль база отвергает так же
			`\U00000000`:  `\U00000000`,
			`\U00110000x`: `\U00110000x`, // остаток после отказа читается дальше как есть
		} {
			require.Equal(t, want, sqlUnbackslash(in), "%q", in)
		}
	})
	t.Run("U&-константа — тот же предел; шестизначная форма его достигает", func(t *testing.T) {
		for in, want := range map[string]string{
			`\0041`:    "A",          // контроль, четыре знака
			`\+000041`: "A",          // контроль, шесть знаков
			`\+10FFFF`: "\U0010FFFF", // верх диапазона — принимается
			`\+110000`: `\+110000`,   // база: invalid Unicode escape value
			`\+FFFFFF`: `\+FFFFFF`,   // максимум шести знаков — предел ДОСТИЖИМ, проверка не мёртвая
			`\0000`:    `\0000`,      // ноль база отвергает
		} {
			require.Equal(t, want, sqlUnicodeUnescape(in, '\\'), "%q", in)
		}
	})
	t.Run("E-строка, суррогаты — пару база склеивает, одиночный и короткую форму отвергает (kaname#174)", func(t *testing.T) {
		// Сверено с postgres:16-alpine (16.15) 2026-10-04: пара склеивается и через
		// смешение \u и \U; одиночный старший, одиночный младший и \u с неполными
		// цифрами — отказ константы. Отказ — тот же названный исход, что у края
		// диапазона: экранирование остаётся как написано, коса граничит имя.
		for in, want := range map[string]string{
			`a\uD83D\uDE00`:         "a\U0001F600",     // пара — один знак: иначе ПРОПУСК имени вне BMP
			`a\U0000D83D\U0000DE00`: "a\U0001F600",     // та же пара восьмизначной формой
			`a\uD83D\U0000DE00`:     "a\U0001F600",     // и смешанной
			`a\uD83D`:               `a\uD83D`,         // база: invalid Unicode surrogate pair
			`a\uD83Dx`:              `a\uD83Dx`,        // старший, за которым не младший
			`a\uDE00`:               `a\uDE00`,         // одиночный младший
			`a\uD83D\\uDE00`:        "a\\uD83D\\uDE00", // за старшим экранированная коса: старший как написано, коса раскрыта
			`a\u12`:                 `a\u12`,           // база: invalid Unicode escape — не «как \c»
			`a\U0041`:               `a\U0041`,         // неполная восьмизначная форма — так же
		} {
			require.Equal(t, want, sqlUnbackslash(in), "%q", in)
		}
	})
	t.Run("U&-константа, суррогаты — старший без младшего не отбрасывается молча (kaname#174)", func(t *testing.T) {
		for in, want := range map[string]string{
			`a\D83D\DE00`:       "a\U0001F600", // контроль: пара склеивается
			`a\+00D83D\+00DE00`: "a\U0001F600", // шестизначной формой
			`a\D83D\+00DE00`:    "a\U0001F600", // смешанной
			`a\D83Dx`:           `a\D83Dx`,     // база: invalid Unicode surrogate pair — прежде старший пропадал
			`a\D83D`:            `a\D83D`,      // старший в конце
			`a\DE00`:            `a\DE00`,      // одиночный младший — прежде U+FFFD
		} {
			require.Equal(t, want, sqlUnicodeUnescape(in, '\\'), "%q", in)
		}
	})
}
