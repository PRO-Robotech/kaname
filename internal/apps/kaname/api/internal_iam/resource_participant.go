// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package internal_iam

import (
	"context"
	"errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// WithResourceTxBeginner меняет только двери этого UC: emitAttempt, publish
// и отдельный отказный аудит RecordRefusal. Действительные admission/catalog/parent проверки остаются на месте.
// Явный nil не возвращает legacy beginner, переданный исходному constructor.
func (uc *RegisterResourceUseCase) WithResourceTxBeginner(beginner service.TxBeginner) *RegisterResourceUseCase {
	if beginner == nil {
		beginner = closedResourceBeginner{}
	}
	uc.txb = beginner
	return uc
}

type closedResourceBeginner struct{}

func (closedResourceBeginner) Begin(context.Context) (service.Tx, error) {
	return nil, errors.New("resource participant is absent")
}
