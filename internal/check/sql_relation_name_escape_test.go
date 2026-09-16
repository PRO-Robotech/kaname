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
}
