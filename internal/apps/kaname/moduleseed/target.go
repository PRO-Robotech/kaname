// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed

// target.go — второй рубеж kaname#965: выдача посева действует только на ярус
// целиком.
//
// Писатель цели выдачи не получает вовсе (`Writer.GrantRole`,
// `Writer.GrantRelation` — субъект, форма, якорь), и колонка цели строки берёт
// умолчание — весь ярус. Значит выдача с любой другой целью, дошедшая до
// писателя, легла бы шире объявленной, и легла бы молча. Первый рубеж —
// загрузчик манифеста (`manifest.ErrObjectRefInManifest`); этот отказ
// существует затем, что применителю вправе подать манифест и не загрузчик, а
// цель, которой писатель не пишет, обязана останавливать запись, а не
// пропускаться.
//
// Суждение стоит ДО транзакции и по всем выдачам сразу: отказ не оставляет ни
// одной строки посева этого манифеста — ни выдачи, ни личности, ни группы.

import (
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ErrBindingTargetNotWholeScope — выдача посева действует не на ярус целиком.
var ErrBindingTargetNotWholeScope = errors.New("moduleseed: seed access binding target is not allInScope")

// seedTargetWholeScope — единственная цель, которую писатель посева исполняет:
// он цели не пишет, и строка получает умолчание колонки.
const seedTargetWholeScope = "allInScope"

// refuseNarrowedTargets — первая выдача, чья цель не `allInScope`.
func refuseNarrowedTargets(seed *manifest.Seed) error {
	for i, b := range seed.AccessBindings {
		if b.Target == seedTargetWholeScope {
			continue
		}
		return fmt.Errorf("выдача seed.accessBindings[%d]: %w: цель %q, а писатель посева цели не "+
			"пишет — строка получила бы умолчание колонки, весь ярус, вместо объявленного; "+
			"посев исполняет только %q, и ни одна строка этого манифеста не записана",
			i, ErrBindingTargetNotWholeScope, b.Target, seedTargetWholeScope)
	}
	return nil
}
