// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

type CanonicalSourceKind string

const (
	CanonicalAccountOwner  CanonicalSourceKind = "account_owner"
	CanonicalClusterAdmin  CanonicalSourceKind = "cluster_admin"
	CanonicalUserSelf      CanonicalSourceKind = "user_self"
	MaxCanonicalSourcePage                     = 256
)

var ErrCanonicalSourceInvalid = errors.New("invalid canonical actor source")
var ErrCanonicalSourceFence = errors.New("canonical actor source outside authority fence")

// Фильтр принимает только конкретного actor. After — непрозрачный ключ страницы,
// а не утверждение полноты или действительности внешнего факта.
type CanonicalSourceFilter struct {
	Actor domain.Subject
	After string
	Limit int
}

// CanonicalDirectSource — сырая строка текущего производителя, не attestation.
// ExpiresAt определяет пригодность в DecisionAt, но не новый TTL выдачи.
type CanonicalDirectSource struct {
	SourceKind                     CanonicalSourceKind
	SourceID                       string
	AccountID                      domain.AccountID
	ObjectType, ObjectID, Relation string
	Recipient                      domain.Subject
	Condition                      CanonicalSourceCondition
	ExpiresAt                      *time.Time
}
type CanonicalSourceCondition struct{ Name, Parameters string }

// CanonicalCreatorSource несёт факт создателя, а НЕ самостоятельную выдачу.
// Он предназначен для проверки creator selector; прямого creator relation нет.
type CanonicalCreatorSource struct {
	SourceID             string
	AccountID            domain.AccountID
	ObjectType, ObjectID string
	Creator              domain.Subject
}
