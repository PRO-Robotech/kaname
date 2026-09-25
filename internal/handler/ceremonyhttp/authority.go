// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// SessionResolver — чтение сессии нашего входа по носителю: тот же вариант
// использования, что отвечает краю (`humansession.ResolveUseCase`). Момент
// последнего предъявления он не двигает и отсечку не применяет — церемония
// спрашивает, КТО вошёл, а отзыв выданного читается на предъявлении (01).
type SessionResolver interface {
	Execute(ctx context.Context, bearer domain.SessionBearer) (humansession.SessionView, bool, error)
}

// SessionAuthority — производитель шва «авторитет входа»: НАШ вход (Ф1), а не
// переходный поверх сессии поставщика (приёмка Р1, Р2).
type SessionAuthority struct {
	resolve SessionResolver
}

var _ LoginAuthority = (*SessionAuthority)(nil)

// NewSessionAuthority — шов над чтением сессии.
func NewSessionAuthority(resolve SessionResolver) (*SessionAuthority, error) {
	if resolve == nil {
		return nil, errors.New("ceremonyhttp: login authority needs the session resolver")
	}
	return &SessionAuthority{resolve: resolve}, nil
}

// Resolve — субъект, сессия, момент и уровень аутентификации; found=false —
// сессии нет (носителя нет, он неизвестен, сессия снята либо истекла).
func (a *SessionAuthority) Resolve(ctx context.Context, bearer domain.SessionBearer) (Login, bool, error) {
	view, found, err := a.resolve.Execute(ctx, bearer)
	if err != nil || !found {
		return Login{}, false, err
	}
	return Login{
		Subject:   string(view.User.ID),
		SessionID: string(view.Session.ID),
		AuthTime:  view.Session.AuthenticatedAt,
		Level:     view.Session.AssuranceLevel,
		ExpiresAt: view.Session.ExpiresAt,
	}, true, nil
}
