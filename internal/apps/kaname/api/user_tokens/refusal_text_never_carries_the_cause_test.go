// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// refusal_text_never_carries_the_cause_test.go — переводчик этого пакета не
// отдаёт вызывающему текст ПОЛУЧЕННОЙ ошибки на признаке недоступности
// (задача #2464). Утверждение — `internal/testsupport/refusaltext`.

import (
	"testing"

	"google.golang.org/grpc/codes"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/refusaltext"
)

func TestUserTokensRefusalTextNeverCarriesTheCause(t *testing.T) {
	refusaltext.Probe{
		Translate:       mapPGErr,
		Positive:        iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", "usr-probe"),
		PositiveCode:    codes.NotFound,
		PositiveMessage: "User usr-probe not found",
	}.Run(t)
}
