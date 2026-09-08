// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package refusaldomain

import "testing"

// export_test.go — сброс объявления ДЛЯ ПРОБ.
//
// Живёт в `_test.go` намеренно: в поставку он не входит, поэтому «объявить и
// передумать» не становится возможностью боевого кода. Без него состояние «не
// объявлено» было бы непроверяемым — то есть страж [Require] остался бы
// утверждением о самом себе.

// ResetForTest возвращает пакет в состояние «суффикс не объявлен» и
// восстанавливает прежнее объявление по окончании пробы: соседняя проба того же
// набора не обязана знать, что эта делала с объявлением процесса.
func ResetForTest(t *testing.T) {
	t.Helper()
	mu.Lock()
	prev := declared
	declared = ""
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		declared = prev
		mu.Unlock()
	})
}
