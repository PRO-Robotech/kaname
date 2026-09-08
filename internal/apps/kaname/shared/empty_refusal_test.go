// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Отказ НИКОГДА не уходит клиенту с пустым текстом.
//
// ПРЕДМЕТ. Снятие префикса sentinel'а устроено как «отрезать `<sentinel>: ` и
// отдать остаток». На обёртке без текста — `fmt.Errorf("%w: %s", sentinel, "")` —
// остаток пуст, и клиент получает КОД БЕЗ ЕДИНОГО СЛОВА о том, что делать
// дальше. В журнале это неотличимо от потери сообщения, а `api-conventions.md`
// §Error-format требует обратного: тон отказа — часть контракта.
//
// ПОЧЕМУ ПРОБА ПАРНАЯ. «Сообщение непусто» зеленеет на мапперe, который вернул
// бы что угодно; поэтому рядом стоит положительная половина — обычная обёртка
// доезжает ДОСЛОВНО, без имени sentinel'а.
func TestRefusalNeverReachesTheClientWithAnEmptyMessage(t *testing.T) {
	t.Parallel()

	// ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА: обычная обёртка доезжает дословно.
	full := MapRepoErr(fmt.Errorf("%w: project prj-1 has reached its limit of 4 things", iamerr.ErrQuotaExceeded))
	require.Equal(t, "project prj-1 has reached its limit of 4 things", status.Convert(full).Message(),
		"предложение производителя — контракт и доезжает целиком")

	// ОТРИЦАТЕЛЬНАЯ ПОЛОВИНА: обёртка без текста не даёт отказа без сообщения.
	empty := MapRepoErr(fmt.Errorf("%w: %s", iamerr.ErrQuotaExceeded, ""))
	assert.NotEmpty(t, status.Convert(empty).Message(),
		"отказ с пустым текстом хуже неверного: клиент видит код и ни слова о том, "+
			"что делать дальше")
	assert.Equal(t, iamerr.ErrQuotaExceeded.Error(), status.Convert(empty).Message(),
		"пустой остаток замещается текстом самого sentinel'а")
}
