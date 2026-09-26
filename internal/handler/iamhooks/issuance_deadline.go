// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks

// issuance_deadline.go — предел времени на КАЖДОЕ обращение полос выдачи к
// своей базе (задача kaname#389).
//
// Полосы, чеканящие токен человеку (хук выпуска и хук обновления), зовёт
// поставщик, и контекст запроса несёт ЕГО срок — либо никакого. До этой обёртки
// под своим пределом шло одно чтение отсечки отзыва-всех (kaname#379), а
// соседние обращения тех же полос — разрешение субъекта, ключа, персонального
// токена и запись аудита — ждали неотвечающую базу столько, сколько ждал
// поставщик. Одна полоса, несущая разный предел на разных обращениях, — то же
// расхождение, что обёртка отсечки снимала между полосами.

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// IssuancePorts — всё, чем полосы выдачи обращаются к своей базе.
//
// Перечень закрыт типом: сборка полос получает базу только через эти поля, и
// обёртка [WithCallDeadline] оборачивает каждое. Порт, заведённый позже рядом,
// попадает под пробу обёртки обходом полей этого типа, а не по памяти.
type IssuancePorts struct {
	// Users — строка человека по внешнему субъекту: хук обновления и путь
	// интерактивной сессии хука выпуска.
	Users UserLookupPort
	// ServiceAccounts — ключ служебной учётки и сама учётка.
	ServiceAccounts service.TokenEnrichmentSAPort
	// UserTokens — персональный токен человека и его владелец.
	UserTokens service.TokenEnrichmentUserTokenPort
	// Cutoffs — отсечка отзыва-всех человека.
	Cutoffs revocationpolicy.Lookup
	// Audit — запись журнала выдачи и отказа.
	Audit AuditEmitter
}

// WithCallDeadline оборачивает КАЖДЫЙ порт полос выдачи одним пределом на
// вызов.
//
// Предел судится обёрткой отсечки ([revocationpolicy.WithDeadline]) — одной на
// все полосы: неположительная величина отказывает построением
// ([revocationpolicy.ErrLimitNotPositive]) и здесь, и на токен-эндпоинте, а не
// двумя разными правилами о ней. Остальные порты оборачиваются той же, уже
// принятой величиной.
//
// Неподанный порт остаётся неподанным: у полос «порт не провязан» — своя
// ветвь, и обёртка над пустотой прошла бы её мимо.
func WithCallDeadline(p IssuancePorts, timeout time.Duration) (IssuancePorts, error) {
	cutoffs, err := revocationpolicy.WithDeadline(p.Cutoffs, timeout)
	if err != nil {
		return IssuancePorts{}, fmt.Errorf("iamhooks: issuance lanes: %w", err)
	}
	out := IssuancePorts{Cutoffs: cutoffs}
	if p.Users != nil {
		out.Users = deadlineUsers{inner: p.Users, timeout: timeout}
	}
	if p.ServiceAccounts != nil {
		out.ServiceAccounts = deadlineServiceAccounts{inner: p.ServiceAccounts, timeout: timeout}
	}
	if p.UserTokens != nil {
		out.UserTokens = deadlineUserTokens{inner: p.UserTokens, timeout: timeout}
	}
	if p.Audit != nil {
		out.Audit = deadlineAudit{inner: p.Audit, timeout: timeout}
	}
	return out, nil
}

// deadlineUsers — строка человека со СВОИМ пределом на вызов.
type deadlineUsers struct {
	inner   UserLookupPort
	timeout time.Duration
}

func (d deadlineUsers) FindByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.FindByExternalID(ctx, externalID)
}

func (d deadlineUsers) GetByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.GetByID(ctx, id)
}

// deadlineServiceAccounts — ключ служебной учётки со СВОИМ пределом на вызов.
type deadlineServiceAccounts struct {
	inner   service.TokenEnrichmentSAPort
	timeout time.Duration
}

func (d deadlineServiceAccounts) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.LookupByOAuthClientID(ctx, id)
}

func (d deadlineServiceAccounts) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.GetServiceAccount(ctx, id)
}

func (d deadlineServiceAccounts) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.FindByExternalSubject(ctx, issuer, sub)
}

// deadlineUserTokens — персональный токен со СВОИМ пределом на вызов.
type deadlineUserTokens struct {
	inner   service.TokenEnrichmentUserTokenPort
	timeout time.Duration
}

func (d deadlineUserTokens) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.LookupByOAuthClientID(ctx, id)
}

func (d deadlineUserTokens) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.GetUser(ctx, id)
}

// deadlineAudit — запись журнала со СВОИМ пределом на вызов.
type deadlineAudit struct {
	inner   AuditEmitter
	timeout time.Duration
}

func (d deadlineAudit) Emit(ctx context.Context, evt AuditEvent) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.Emit(ctx, evt)
}
