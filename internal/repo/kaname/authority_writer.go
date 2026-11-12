// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AuthorityFenceMode выбирается до открытия транзакции. Нулевого режима нет.
type AuthorityFenceMode uint8

const (
	AuthorityFenceAccounts AuthorityFenceMode = iota + 1
	AuthorityFenceGlobal
	// MaxAuthorityFenceAccounts ограничивает размер плана до обращения к БД.
	// Если полный набор неизвестен или больше предела, вызывающий выбирает Global
	// заранее; открытый Accounts writer нельзя повысить до Global.
	MaxAuthorityFenceAccounts = 256
)

var ErrInvalidAuthorityFencePlan = errors.New("invalid authority writer fence plan")

// AuthorityFencePlan содержит полный заранее классифицированный набор аккаунтов.
// Global требует пустого Accounts; Accounts — непустого. Существование аккаунтов
// и правильность классификации проверяются будущим потребителем внутри writer.
type AuthorityFencePlan struct {
	Mode     AuthorityFenceMode
	Accounts []domain.AccountID
}

// AuthorityFence описывает только полученные барьеры и время после их ожидания.
// Это НЕ доказательство authority, admission, bundle identity или strict mode.
// Accounts возвращает отдельную копию полного логического набора, даже если
// физические ключи разных аккаунтов столкнулись в хеше.
type AuthorityFence interface {
	Mode() AuthorityFenceMode
	Accounts() []domain.AccountID
	DecisionAt() time.Time
}

// AuthorityWriter удерживает барьеры до обычного Commit/Rollback. Старый Writer
// не изменён и в протоколе не участвует. До общего подключения писателей,
// проверки bundle и DB attestation этот порт не делает публичные gates безопасными.
type AuthorityWriter interface {
	Writer
	AuthorityFence() AuthorityFence
}

// AuthorityWriterFactory — отдельный порт: действующий Repository не расширяется
// требованием, которое старые адаптеры ещё не исполняют.
type AuthorityWriterFactory interface {
	AuthorityWriter(context.Context, AuthorityFencePlan) (AuthorityWriter, error)
}
