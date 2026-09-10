// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// refusal_text_never_carries_the_cause_test.go — переводчик этого пакета не
// отдаёт вызывающему текст ПОЛУЧЕННОЙ ошибки на признаке недоступности
// (задача #2464).
//
// Утверждение живёт в `internal/testsupport/refusaltext`: предмет у всех
// переводчиков службы один, и копия утверждения здесь разошлась бы с
// соседними — тем же способом, каким разошлись сами переводчики.
//
// Проба сверяет СООБЩЕНИЕ, а не код: код `UNAVAILABLE` верен и с эхом, и без
// него, поэтому проба на коде осталась бы зелёной при вернувшемся эхе.

import (
	"testing"

	"google.golang.org/grpc/codes"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/testsupport/refusaltext"
)

func TestSAKeysRefusalTextNeverCarriesTheCause(t *testing.T) {
	refusaltext.Probe{
		Translate: mapPGErr,
		// Законный близнец: отказ, адресованный вызывающему. Его текст —
		// контракт, и он обязан доехать дословно.
		Positive:        iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", "sva-probe"),
		PositiveCode:    codes.NotFound,
		PositiveMessage: "ServiceAccount sva-probe not found",
	}.Run(t)
}
