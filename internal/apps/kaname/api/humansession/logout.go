// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// logout.go — ВЫХОД (Р4, Р5; Ф3-15…18): три записи одним исходом — снятие своей
// записи · отсечка моментом на единицу разрешения раньше первой аутентификации
// личности нашей посадкой с причиной `logout` и актором-человеком · событие.
// Идемпотентно: второй выход, выход без носителя, выход с носителем, которого
// хранилище не знает, — тот же исход и ни одной записи (Ф1-18, Ф3-18).
//
// Отказ хранилища — глагол НЕ выполнен, носитель у клиента цел (Ф1-58):
// неполученный ответ авторитета не есть «выход состоялся».

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// AuditSessionLoggedOut — событие выхода (Р14).
const AuditSessionLoggedOut = "iam.session.logged_out"

// LogoutUseCase — выход.
type LogoutUseCase struct {
	store    Store
	observer Observer
	now      func() time.Time
	logger   *slog.Logger
}

// NewLogoutUseCase — построение.
func NewLogoutUseCase(store Store, observer Observer, now func() time.Time, logger *slog.Logger) (*LogoutUseCase, error) {
	if store == nil {
		return nil, fmt.Errorf("logout: session store required")
	}
	if observer == nil {
		observer = NopObserver{}
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &LogoutUseCase{store: store, observer: observer, now: now, logger: logger}, nil
}

// Execute — выход по носителю. Возвращает, была ли снята запись (для журнала
// и проб; ответ клиенту от этого не зависит).
func (uc *LogoutUseCase) Execute(ctx context.Context, bearer domain.SessionBearer) (ended bool, err error) {
	if bearer.IsZero() {
		return false, nil
	}
	now := uc.now().UTC()
	resolved, reason, err := uc.store.Resolve(ctx, bearer.Digest(), now)
	if err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	if reason != SessionFound {
		// «Сессии нет» на выходе — тот же 200 и ни одной записи (Ф3-18); причина
		// — только в клетке.
		uc.observer.NoSessionObserved(reason)
		return false, nil
	}
	w, err := uc.store.Writer(ctx)
	if err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	ended, err = w.EndSession(ctx, resolved.Session.ID, now, domain.RevokeReasonLogout)
	if err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	if !ended {
		// Гонка с параллельным выходом: запись уже снята — ничего не пишем.
		return false, nil
	}
	cutoff, err := revocationMoment(ctx, w, resolved.Session)
	if err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: resolved.User.ID, RevokeBefore: cutoff, Reason: domain.RevokeReasonLogout,
	}, resolved.User.ID); err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditSessionLoggedOut,
		TenantAccountID: string(resolved.User.AccountID),
		Payload: map[string]any{
			"user_id":    string(resolved.User.ID),
			"session_id": string(resolved.Session.ID),
			"methods":    resolved.Session.PresentedMethods,
		},
	}); err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		uc.observer.LogoutStoreFailureObserved()
		return false, ErrStoreUnavailable
	}
	return true, nil
}

// revocationMoment — момент отсечки выхода и смены пароля (Р4, Р5, Ф1 §4.2):
// на единицу разрешения хранилища (микросекунда) РАНЬШЕ первой аутентификации
// личности нашей посадкой. Память первой аутентификации пишет только выдача;
// если её нет (запись посеяна мимо выдачи), берётся момент самой сессии — он
// не позже первой, и это сказано в журнале, а не проглочено.
func revocationMoment(ctx context.Context, w Writer, s domain.HumanSession) (time.Time, error) {
	first, found, err := w.FirstAuthentication(ctx, s.UserID)
	if err != nil {
		return time.Time{}, err
	}
	if !found || first.After(s.AuthenticatedAt) {
		first = s.AuthenticatedAt
	}
	return first.Add(-time.Microsecond), nil
}
