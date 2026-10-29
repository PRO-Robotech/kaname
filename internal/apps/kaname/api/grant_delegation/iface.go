// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grant_delegation — use-case'ы службы GrantDelegationService:
// делегирование права выдавать (задача PRO-Robotech/kaname#986, приёмка
// docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md).
//
// Право на каждом глаголе решает обработчик (`HANDLER_DECIDES`): право выдавать
// на аккаунте — три прежних пути (`requireAccountGrantAuthority`),
// у `Get` к ним добавляется «вызывающий — делегат». Делегированного пути у
// глаголов этой службы нет: делегат делегирований не заводит и не отзывает.
package grant_delegation

import (
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)

// Типы аудита делегирования (Р5).
const (
	auditEventCreated = "iam.grant_delegation.created"
	auditEventRevoked = "iam.grant_delegation.revoked"
)
