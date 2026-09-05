// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// errors_internal_fixed_text_test.go — деталь остаётся В ЦЕПОЧКЕ для журнала и
// НЕ доходит до клиента (#666).
//
// Комментарии на этом пути обещают журналу деталь. Обещание держится с двух
// сторон сразу: деталь обязана быть в цепочке (иначе журналу нечего писать) и
// обязана не быть на проводе (иначе это утечка). Проба утверждает обе стороны
// одним и тем же значением — порознь каждая половина зеленела бы на дефекте
// другой.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

func TestMapRepoErr_InternalKeepsDetailInTheChainAndNotOnTheWire(t *testing.T) {
	// Так выглядит цепочка после моста SQLSTATE: сама деталь плюс контекст
	// вызывающего.
	wrapped := fmt.Errorf("list changed limits: %w",
		iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 53300"))

	// Сторона журнала: деталь в цепочке есть — иначе «отказ есть, причину назвать
	// нечем» становится штатным состоянием.
	require.Contains(t, wrapped.Error(), "sqlstate 53300",
		"деталь обязана дожить до журнала: без неё причину отказа назвать нечем")

	// Сторона провода: клиент получает фиксированный текст.
	st, ok := status.FromError(MapRepoErr(wrapped))
	require.True(t, ok)
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal error", st.Message(),
		"текст INTERNAL фиксирован: ни кода состояния, ни контекста вызывающего на проводе быть не может")
}
