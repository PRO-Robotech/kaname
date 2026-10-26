// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)

// MembersGrantAuthority — порт Р3 (kaname#1037, приёмка
// role-rights-stay-within-what-is-named.md): добавить участника в группу, у
// которой есть действующие выдачи, можно только с правом выдавать на каждой их
// области — иначе добавляющий выдал бы участнику больше, чем вправе выдать сам.
// Реализует access_binding.ScopeGrantAuthority (там же, где право выдавать у
// `AccessBindingService.Create`), провязывает корень службы.
//
// Ответ: nil — разрешено (в том числе выдач у группы нет);
// `authzguard.PermissionDenied()` — отказ, побайтово как отказ без права;
// `authzguard.AuthzBackendUnavailable()` — хранилище отношений не ответило.
type MembersGrantAuthority interface {
	RequireForGroup(ctx context.Context, id domain.GroupID) error
}
