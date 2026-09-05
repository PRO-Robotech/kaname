// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles

// rightsexport.go — привязка порта `RightsExport` к экспортёру прав
// (задача продукта #1998).
//
// # Почему привязка, а не вызов экспортёра прямо из применителя
//
// Экспортёру нужны две величины, которых у применителя нет и не должно быть:
// каталожный факт и записи каталога прав. Собирает их композиционный корень —
// он же и собирает эту привязку. Применитель говорит с ПОРТОМ, объявленным у
// него самого, и о каталоге не знает ничего.
//
// # Почему это не «адаптер» в каталоге адаптеров
//
// Здесь нет ни транспорта, ни хранилища: привязка чистая, состояния не держит и
// зовёт функцию соседнего пакета. Класть её в `repo/` либо `clients/` значило бы
// объявить инфраструктурой то, что ею не является.

import (
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest/roleexport"
)

// catalogRightsExport — производитель правил над каталогом прав.
type catalogRightsExport struct {
	facts   roleexport.VerbFacts
	actions []roleexport.Action
}

// ErrRightsExportIncomplete — производителя правил собрать не из чего.
//
// Отказ, а не пустой производитель: перечень, полный по НУЛЮ классов, полон
// тривиально, и поимённое право свелось бы к пустому набору классов — то есть
// молча. Отказать здесь дешевле, чем отличать потом «перечень неполон» от
// «сверять было нечем».
var ErrRightsExportIncomplete = errors.New(
	"moduleroles: производитель правил роли собран без каталога прав")

// NewRightsExport собирает производителя правил роли.
//
// Обе величины обязательны, и обе проверяются ЗДЕСЬ: собранный производитель
// либо годен, либо не существует, и третьего состояния — «есть, но отвечает
// ни о чём» — у него нет by construction.
func NewRightsExport(facts roleexport.VerbFacts, actions []roleexport.Action) (RightsExport, error) {
	if facts == nil {
		return nil, fmt.Errorf("%w: каталожный факт не подан", ErrRightsExportIncomplete)
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("%w: привязано ноль действий каталога прав — полноту "+
			"поимённого перечня считать нечем", ErrRightsExportIncomplete)
	}
	return catalogRightsExport{facts: facts, actions: actions}, nil
}

// ExportRoleRules — правила ролей манифеста ПОСЛЕ проверки полноты поимённых
// перечней. Роль, чей перечень не полон, в результат не попадает целиком.
func (e catalogRightsExport) ExportRoleRules(m *manifest.Manifest) (map[string][]domain.Rule, []error) {
	rules, faults, _ := roleexport.ExportRoleRules(e.facts, m, e.actions)
	return rules, faults
}
