// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed

// target.go — второй рубеж kaname#965: посев исполняет выдачу только на ярус
// целиком.
//
// Первый рубеж — загрузчик манифеста (`manifest.ErrObjectRefInManifest`): объект
// адресуется идентификатором, который присваивает запись, а манифест
// применяется на каждом старте и вернул бы ссылку снова. Этот отказ стоит
// затем, что манифест применителю вправе подать и не загрузчик: цель, которую
// посев не исполняет, останавливает запись, а не пропускается.
//
// Суждение стоит ДО транзакции: все выдачи судятся до первой записи, и отказ
// не оставляет ни одной строки посева этого манифеста — ни выдачи, ни
// личности, ни группы.

import (
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// ErrBindingTargetNotWholeScope — выдача посева действует не на ярус целиком.
var ErrBindingTargetNotWholeScope = errors.New("moduleseed: seed access binding target is not allInScope")

// refuseNarrowedTargets — первая выдача, чья цель не `allInScope`.
func refuseNarrowedTargets(seed *manifest.Seed) error {
	for i, b := range seed.AccessBindings {
		if b.Target == manifest.TargetAllInScope {
			continue
		}
		return fmt.Errorf("выдача seed.accessBindings[%d]: %w: цель %q — посев исполняет только %q; "+
			"ни одна строка этого манифеста не записана",
			i, ErrBindingTargetNotWholeScope, b.Target, manifest.TargetAllInScope)
	}
	return nil
}
