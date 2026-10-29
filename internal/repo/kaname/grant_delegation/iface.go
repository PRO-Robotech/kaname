// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grant_delegation — порты хранилища делегирований права выдавать
// (задача PRO-Robotech/kaname#986). Делегирование — часть домена выдач: его
// читатель и писатель достигаются через читателя и писателя выдач
// (`access_binding.ReaderIface.GrantDelegations`,
// `access_binding.WriterIface.GrantDelegationsW`), поэтому запись делегирования,
// выдач по нему и их следствий идёт ОДНОЙ транзакцией писателя.
package grant_delegation

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ReaderIface — чтения делегирований и фактов, которые спрашивает
// делегированный путь права выдавать.
type ReaderIface interface {
	// Get — делегирование по идентификатору; нет — ErrNotFound.
	Get(ctx context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error)
	// ActiveFor — ДЕЙСТВУЮЩЕЕ делегирование пары «аккаунт, делегат»; нет —
	// ErrNotFound. Пара однозначна: частичная уникальность по действующим (Д1).
	ActiveFor(ctx context.Context, accountID domain.AccountID, delegate domain.ServiceAccountID) (domain.GrantDelegation, error)
	// List — делегирования аккаунта курсором `(created_at, id)` по возрастанию.
	List(ctx context.Context, accountID domain.AccountID, filter PageFilter) ([]domain.GrantDelegation, string, error)
	// TargetObjectAccount — зарегистрирован ли объект цели и в каком аккаунте
	// лежит его проект (Д7). Проект ищется обходом цепи регистрации вверх до узла
	// `project`: у репозитория реестра цепь из двух звеньев (репозиторий → реестр
	// → проект). Незарегистрированный — `registered = false`; зарегистрированный
	// без проекта в цепи — пустой аккаунт.
	TargetObjectAccount(ctx context.Context, ref domain.ResourceRef) (registered bool, accountID domain.AccountID, err error)
}

// WriterIface — мутации делегирований; все — на транзакции писателя выдач.
type WriterIface interface {
	// Insert — заведение делегирования. Второе действующее делегирование пары —
	// 23505 частичной уникальности, ErrAlreadyExists с текстом Р6.
	Insert(ctx context.Context, d domain.GrantDelegation) (domain.GrantDelegation, error)
	// LockForRevoke — строка делегирования под `FOR UPDATE`: первый замок
	// транзакции отзыва делегирования (запись выдачи держит ту же строку
	// `FOR SHARE`). Нет строки — ErrNotFound.
	LockForRevoke(ctx context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error)
	// MarkRevoked — CAS `ACTIVE → REVOKED`; 0 строк — ErrFailedPrecondition
	// «already revoked».
	MarkRevoked(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, at time.Time) (domain.GrantDelegation, error)
	// ActiveBindingIDs — действующие выдачи делегирования под `FOR UPDATE`, по
	// возрастанию id (порядок замков отзыва по снятию регистрации, kaname#963).
	ActiveBindingIDs(ctx context.Context, id domain.GrantDelegationID) ([]domain.AccessBindingID, error)
	// RevokeBindingForDelegation — CAS отзыва выдачи с причиной
	// DELEGATION_REVOKED; защита от удаления условием не является. false — строку
	// уже отозвал параллельный отзыв.
	RevokeBindingForDelegation(ctx context.Context, id domain.AccessBindingID, revokedBy domain.UserID, at time.Time) (bool, error)
	// HoldActive — строка делегирования под `FOR SHARE` по ЗАХВАЧЕННОМУ id с
	// перепроверкой `status = 'ACTIVE'` (условие CE-09): запись выдачи делегатом
	// ждёт фиксации отзыва и судит по его исходу. false — делегирования нет либо
	// оно отозвано. Отдаёт аккаунт делегирования — писатель аудита выдачи (Р5).
	HoldActive(ctx context.Context, id domain.GrantDelegationID) (domain.AccountID, bool, error)
	// AccountOf — аккаунт делегирования: писатель аудита выдачи, несущей ссылку
	// (Р5, `tenant_account_id`).
	AccountOf(ctx context.Context, id domain.GrantDelegationID) (domain.AccountID, error)
}

// PageFilter — страница перечня делегирований аккаунта.
type PageFilter struct {
	PageSize  int32
	PageToken string
}
