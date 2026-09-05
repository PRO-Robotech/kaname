// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// role_updated_at_test.go — время правки роли ДОЕЗЖАЕТ до контракта (#1873).
//
// Последнее звено цепочки, и самое тихое: перевод стоит под условием непустоты
// (`if !r.UpdatedAt.IsZero()`), поэтому при непроизводящем хранилище поле молча
// не приезжало никогда, а код выглядел исправным. Условие остаётся — у ответа
// мутации вычисленного состояния не бывает, — но теперь у него есть ОБЕ стороны,
// и обе проверяются здесь.
//
// Производителя величины держит `role_updated_at_integration_test.go` в repo:
// там утверждается, что хранилище её выдаёт и двигает. Здесь — что перевод её не
// теряет.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleUpdatedAtReachesTheContract(t *testing.T) {
	// Микросекунды намеренно непустые: конвенция требует усечения до СЕКУНД на
	// проводе (`api-conventions.md` §Gotcha'и), и без дробной части утверждение
	// об усечении было бы вакуумным.
	updated := time.Date(2026, 9, 5, 11, 22, 33, 456789000, time.UTC)
	created := time.Date(2026, 9, 1, 8, 0, 0, 987654000, time.UTC)

	r := roleWithComputedState()
	r.CreatedAt = created
	r.UpdatedAt = updated

	got := roleToPb(t, r)

	require.NotNil(t, got.GetUpdatedAt(),
		"поле объявлено контрактом и не приезжает: класс «возможность объявлена и "+
			"неисполнима» — арендатор видит его в сгенерированных клиентах и не "+
			"получает ни одним вызовом")
	assert.Equal(t, updated.Truncate(time.Second), got.GetUpdatedAt().AsTime().UTC(),
		"время правки обязано приезжать усечённым до секунд: микросекунды базы на провод не текут")

	// Положительный контроль на СОСЕДА: без него проба зеленела бы на переводе,
	// заполняющем обе метки одной величиной.
	require.NotNil(t, got.GetCreatedAt())
	assert.Equal(t, created.Truncate(time.Second), got.GetCreatedAt().AsTime().UTC())
	assert.NotEqual(t, got.GetCreatedAt().AsTime(), got.GetUpdatedAt().AsTime(),
		"две метки склеились в одну — различие «создано» и «правлено» перестало быть выразимым")

	// Отрицательная сторона того же условия: непроизведённая величина приезжает
	// ОТСУТСТВИЕМ, а не нулём эпохи. Ответ мутации вычисленного состояния не
	// несёт, и «не вычислено» обязано быть отличимо от «правлено в 1970».
	bare := roleWithComputedState()
	bare.UpdatedAt = time.Time{}
	assert.Nil(t, roleToPb(t, bare).GetUpdatedAt(),
		"нулевое время приехало значением: клиент прочитал бы «роль правлена в начале эпохи»")
}
