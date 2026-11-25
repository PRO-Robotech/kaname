// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// UserAccessLabelsWriter принимает правку пользователя в подготовленной транзакции.
// labels=nil сохраняет обычные метки. Любая переданная карта заменяет своё поле
// целиком. Карта accessLabels обязательна, пустая карта означает очистку.
// Исполнитель подтверждает record_writer на пользователе, apply для изменённых
// ключей и выдачу добавленного доступа по актуальным источникам после ожиданий.
// В той же транзакции удерживает pending и фиксирует запись, аудит, пересчёт
// и точный терминальный ответ в operations. Для no-op также завершает pending.
// changed сообщает о фактическом изменении хотя бы одной карты после фиксации.
type UserAccessLabelsWriter interface {
	// CreateUserAccessLabelsOperation сохраняет pending с защитой от прежнего
	// resolver, который мог бы принять существование User за успех обновления.
	CreateUserAccessLabelsOperation(context.Context, operations.Operation) error
	UpdateUserAccessLabels(ctx context.Context, id domain.UserID, labels, accessLabels domain.Labels, actor domain.Subject, pending operations.Operation) (committed operations.Operation, changed bool, err error)
}
