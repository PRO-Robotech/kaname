// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_delivery_source.go — адаптер доставки манифестов для глаголов
// `InternalModuleService`.
//
// # Почему перечитывание, а не снимок старта
//
// Путь старта читает доставку ОДИН раз и применяет прочитанное. Глагол, взявший
// тот же снимок, применял бы состояние источника на момент пуска процесса —
// то есть оператор, поправивший манифест, увидел бы план по СТАРОМУ содержимому
// и не смог бы отличить это от «правка не доехала». Поэтому здесь читается
// каталог доставки заново, в момент запроса.
//
// # Второго разбора не заводится
//
// Обход и разбор — те же (`manifest.LoadDelivered`), что у пути старта; этот тип
// только переводит его перепись в форму, которую объявил use-case, и различает
// ТРИ состояния доставки, потому что чинятся они в трёх разных местах.

import (
	"context"

	moduleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// manifestDeliverySource — `moduleapp.DeliverySource` над каталогом доставки,
// объявленным посадкой.
type manifestDeliverySource struct {
	cfg config.ManifestsConfig
}

// newManifestDeliverySource — конструктор адаптера.
func newManifestDeliverySource(cfg config.ManifestsConfig) *manifestDeliverySource {
	return &manifestDeliverySource{cfg: cfg}
}

// Read перечитывает каталог доставки.
//
// Перепись возвращается ВСЕГДА, в том числе вместе с отказом: без неё оператор
// не отличит «прочитано ноль манифестов» от «находок ноль», а отказ доставки —
// от расхождения каталога.
func (s *manifestDeliverySource) Read(context.Context) (moduleapp.Delivery, error) {
	if s.cfg.Dir == "" {
		// Доставка посадкой НЕ ОБЪЯВЛЕНА. Это отдельное состояние, а не пустая
		// доставка: чинится оно посадкой, и отказ обязан назвать именно её.
		return moduleapp.Delivery{Declared: false}, nil
	}
	report, err := manifest.LoadDelivered(s.cfg.Dir)
	return moduleapp.Delivery{
		Declared:      true,
		ManifestsRead: report.ManifestsRead,
		Findings:      len(report.Findings),
		Manifests:     report.Manifests,
	}, err
}

// Соответствие порту — на этапе сборки: композиция, собравшая адаптер, не
// умеющий перечитывать доставку, не должна компилироваться вовсе.
var _ moduleapp.DeliverySource = (*manifestDeliverySource)(nil)
