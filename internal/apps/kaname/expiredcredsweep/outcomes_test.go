// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package expiredcredsweep_test

// outcomes_test.go — набор исходов прогона ЗАКРЫТ, и он объявлен там же, откуда
// его читает приёмник величин (задача продукта #2499).
//
// # Почему это отдельная проба
//
// Исходы стояли строковыми литералами по месту — три вхождения в одном файле.
// Приёмник величин заводит клетки по перечню, и перечень, собранный вторым
// местом, разошёлся бы с производителем молча: исход без клетки присутствовал бы
// нулём и выглядел исправным наблюдением.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"
)

// TestOutcomeSetIsClosedAndFullyProducible — образ разбора лежит в объявленном
// наборе и покрывает его целиком.
//
// Обход ПОЛНЫЙ: у разбора два двоичных довода, значит входов четыре, и
// перечислить их можно все. Объявленный исход, которого разбор не даёт ни при
// каком входе, — клетка, присутствующая нулём навсегда.
func TestOutcomeSetIsClosedAndFullyProducible(t *testing.T) {
	declared := map[string]bool{}
	for _, o := range expiredcredsweep.Outcomes() {
		declared[o] = true
	}
	require.Len(t, declared, 3, "исходов прогона объявлено не три")

	produced := map[string]bool{}
	for _, failed := range []bool{false, true} {
		for _, dryRun := range []bool{false, true} {
			o := expiredcredsweep.OutcomeFor(failed, dryRun)
			require.Truef(t, declared[o], "вход (failed=%v, dryRun=%v) дал исход %q вне набора",
				failed, dryRun, o)
			produced[o] = true
		}
	}
	require.Len(t, produced, len(declared),
		"объявлен исход, которого разбор не даёт НИ ПРИ КАКОМ входе")
}
