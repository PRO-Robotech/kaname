// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// refusal_text_never_carries_the_cause_test.go — перевод отказа решателя в
// статус не отдаёт вызывающему текст ПОЛУЧЕННОЙ ошибки на признаке
// недоступности (задача #2464). Утверждение — `internal/testsupport/refusaltext`.
//
// Переводчик здесь не отдельная функция, а ветвь глагола, поэтому под пробу
// он подаётся замыканием через дублёра решателя: предмет пробы — то, что
// увидит ВЫЗЫВАЮЩИЙ по проводу, а не форма кода.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/refusaltext"
)

func TestInternalIAMRefusalTextNeverCarriesTheCause(t *testing.T) {
	translate := func(err error) error {
		h := newCheckHandler(&fakeAuthorizer{result: &service.CheckResult{}, err: err})
		_, cerr := h.Check(context.Background(), &iamv1.CheckRequest{
			SubjectId: "user:usr_probe", Relation: "viewer", Object: "vpc_network:enp_probe",
		})
		return cerr
	}

	refusaltext.Probe{
		Translate: translate,
		// Законный близнец этой ветви — не «не найдено» (её у глагола нет), а
		// verbatim-полоса неверного аргумента: её текст адресован вызывающему
		// и обязан доехать дословно.
		Positive:        errors.New("Illegal argument relation: required"),
		PositiveCode:    codes.InvalidArgument,
		PositiveMessage: "Illegal argument relation: required",
	}.Run(t)
}
