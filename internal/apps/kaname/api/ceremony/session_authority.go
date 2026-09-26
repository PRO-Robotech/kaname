// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// SessionResolver — чтение сессии нашего входа по носителю: тот же вариант
// использования, что отвечает краю (`humansession.ResolveUseCase`). Момент
// последнего предъявления он не двигает.
//
// Отсечку субъекта он не применяет, и здесь это не мягкий проход: её судит
// выдача семейства тем же оператором, что и живость сессии
// (`pg.OAuthCeremonyRepo.IssueAuthorizationCode`), а сессия, отрезанная
// отсечкой, получает вызов аутентификации, а не код.
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
		return nil, errors.New("ceremony: login authority needs the session resolver")
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
