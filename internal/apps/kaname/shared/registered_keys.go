// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RegisteredKeys — узкий порт приёма выдачи и роли (kaname#963, приёмка
// `unregistration-revokes-its-grants.md`, Р8, Д6): какие из названных ключей
// объектов сейчас зарегистрированы. Ключ, зарегистрированный на приёме,
// запись держит замком строки регистрации и отказывает, если строки уже нет
// (`domain.AccessBinding.HeldTargets`, `domain.Role.HeldNames`); свободный ключ —
// ключ по ATC-03, судить его нечем. Реализация — *repo/kaname/pg.RegisteredKeys.
type RegisteredKeys interface {
	RegisteredOf(ctx context.Context, keys []domain.ResourceRef) ([]domain.ResourceRef, error)
}
