// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// Набор шагов пост-коммитной материализации объявлен ОДИН раз — у коллектора,
// который заводит по клетке на каждую пару «шаг × исход» ещё до первого
// наблюдения. Этот use-case производит значения, но объявления не держит: иначе
// они разъехались бы, и разъехались бы МОЛЧА, потому что обе стороны продолжали
// бы компилироваться.
//
// Цена расхождения несимметрична и потому проверяется в ОБЕ стороны:
//
//   - шаг, который use-case эмитит, а коллектор не объявил, появится в метриках
//     только после первого срабатывания — то есть ровно та неразличимость «не
//     исполнялось / не провязано», ради снятия которой клетки и заводятся;
//   - шаг, который коллектор объявил, а use-case не эмитит, — вечный ноль без
//     производителя: следующий читатель примет его за сломанную ветку и пойдёт
//     чинить то, чего нет.
//
// Проба живёт здесь, а не у коллектора: константы шагов приватны для этого
// пакета, и увидеть их может только он. Импорт адаптера наблюдаемости — из
// тестового файла, прод-код use-case его по-прежнему не знает (порт узкий).
func TestPostCommitStepConstantsMatchTheDeclaredLabelSet(t *testing.T) {
	t.Parallel()

	produced := []string{
		stepForwardAdditive, stepForwardGuarded,
		stepResidualRead, stepResidualWithdraw,
	}
	declared := append([]string(nil), metrics.RegisterPostCommitSteps...)
	sort.Strings(produced)
	sort.Strings(declared)

	t.Logf("шагов эмитируется: %d; объявлено коллектором: %d", len(produced), len(declared))

	if strings.Join(produced, ",") != strings.Join(declared, ",") {
		t.Fatalf("набор шагов разошёлся:\n  эмитируется: %v\n  объявлено:   %v\n\n"+
			"Лишний слева — шаг, чья клетка не заводится нулём, поэтому до первого "+
			"срабатывания он неотличим от непровязанного. Лишний справа — вечный ноль "+
			"без производителя, который читается как сломанная ветка.", produced, declared)
	}

	producedOutcomes := []string{outcomeOK, outcomeError}
	declaredOutcomes := append([]string(nil), metrics.RegisterPostCommitOutcomes...)
	sort.Strings(producedOutcomes)
	sort.Strings(declaredOutcomes)
	if strings.Join(producedOutcomes, ",") != strings.Join(declaredOutcomes, ",") {
		t.Fatalf("набор исходов разошёлся: эмитируется %v, объявлено %v",
			producedOutcomes, declaredOutcomes)
	}
}
