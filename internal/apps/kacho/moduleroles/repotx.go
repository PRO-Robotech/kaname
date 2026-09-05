// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

// repotx.go — мост между портом применителя и репозиторием сервиса.
//
// # Почему мост тонкий и почему он ЗДЕСЬ
//
// Порт `TxRunner` описывает потребность use-case: «исполни это под одной
// транзакцией записи». Репозиторий сервиса даёт её через единственное в дереве
// объявление паттерна писательской транзакции — `shared.DoWithWriteTx`. Своя
// последовательность begin→commit→rollback здесь была бы вторым местом об одном
// предмете и разошлась бы с первым молча.
//
// Мост живёт рядом с use-case, а не в репозитории: обратное направление
// заставило бы слой адаптеров знать о применителе. Его дом переезжает в
// композиционный корень вместе с тем, кто применитель зовёт (форма поставки —
// задача #1036, глагол — #1034).
//
// # Что мост НЕ прячет
//
// Отказы приезжают уже приведёнными к gRPC-статусу — это свойство
// `shared.DoWithWriteTx`, единственного объявления паттерна. Применитель их не
// перетолковывает: тексты отказов базы суть часть контракта, и своя проза
// поверх них скрыла бы имя нарушенного ограничения.

// repoTxRunner — `TxRunner` над репозиторием сервиса.
type repoTxRunner struct {
	repo kachorepo.Repository
}

// NewRepoTxRunner собирает исполнителя транзакций над репозиторием сервиса.
func NewRepoTxRunner(repo kachorepo.Repository) TxRunner { return repoTxRunner{repo: repo} }

// RunInWriteTx исполняет fn под одной писательской транзакцией. Строка роли и
// её проекция сегментов ложатся вместе либо не ложатся вовсе.
func (r repoTxRunner) RunInWriteTx(ctx context.Context, fn func(context.Context, RoleWriter) error) error {
	return shared.DoWithWriteTxVoid(ctx, r.repo, func(ctx context.Context, w kachorepo.Writer) error {
		return fn(ctx, w.RolesW())
	})
}
