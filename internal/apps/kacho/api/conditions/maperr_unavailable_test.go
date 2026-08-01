// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package conditions

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// Недоступное хранилище прав отвечает UNAVAILABLE, а не INTERNAL.
//
// Разница не косметическая: INTERNAL означает «у нас сломалось, повторять
// бессмысленно», UNAVAILABLE — «сосед недоступен, повтори». Локальный mapErr
// ветви для этого sentinel'а не имел, поэтому недоступность хранилища прав
// доезжала до вызывающего как внутренняя ошибка.
//
// Отправитель у этого sentinel'а живой и единственный: проверка проектной
// области в service.ConditionsCRUDService.List/Get отдаёт его, когда хранилище
// прав не ответило. Общий shared.MapRepoErr эту ветвь несёт — расходился именно
// локальный маппер.
func TestMapErr_UnavailableIsNotInternal(t *testing.T) {
	err := mapErr(iamerr.Wrapf(iamerr.ErrUnavailable, "authorization store unavailable"))

	require.Equal(t, codes.Unavailable, status.Code(err),
		"недоступность соседа обязана быть повторяемой, а не выглядеть внутренней поломкой")
}
