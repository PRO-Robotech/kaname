// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

// refusal_text_never_carries_the_cause_test.go — переводчик этого пакета не
// отдаёт вызывающему текст ПОЛУЧЕННОЙ ошибки на признаке недоступности
// (задача #2464). Утверждение — `internal/testsupport/refusaltext`.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/refusaltext"
)

func TestBootstrapTokenRefusalTextNeverCarriesTheCause(t *testing.T) {
	// Нулевой use-case годен намеренно: переводчик читает у себя только
	// логгер, и его отсутствие проверяет сам (`logErr`). Дублёр логгера сюда
	// не ставится — предмет пробы в том, что видит ВЫЗЫВАЮЩИЙ.
	u := &MintUseCase{}
	translate := func(err error) error { return u.mapErr(context.Background(), "probe", err) }

	refusaltext.Probe{
		Translate:       translate,
		Positive:        iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", "sva-probe"),
		PositiveCode:    codes.NotFound,
		PositiveMessage: "ServiceAccount sva-probe not found",
	}.Run(t)
}
