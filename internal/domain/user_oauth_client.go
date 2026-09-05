// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// UserOAuthClient — персональный access-токен пользователя.
//
// private_key_jwt: kacho-iam генерирует пару ключей ECDSA P-256 на каждый токен,
// держит SPKI public PEM плюс алгоритм и возвращает приватный PEM вызывающему
// ровно один раз. Секрет не существует at-rest.
//
// Клиентом это удостоверение называется по идентификатору ЭТОЙ строки: им
// подписывается `client_assertion`, и по нему же разрешает клиента наш реестр
// утверждений. Второго имени у него нет.
//
// N:1 — у одного User может быть несколько токенов.
type UserOAuthClient struct {
	ID     UserOAuthClientID
	UserID UserID
	// OAuthClientID — идентификатор клиента у ВНЕШНЕГО поставщика.
	//
	// У строк нового выпуска ПУСТ и обязан быть пуст: выдача больше не заводит
	// клиента у поставщика, а пустое значение здесь означает ровно это —
	// регистрации нет. Непустое значение принадлежит строке прежнего выпуска и
	// держит окно двух издателей: отчеканенные поставщиком токены таких строк
	// действительны до своего истечения.
	//
	// На пути разрешения клиента эта колонка НЕ участвует (см.
	// repo/kacho/pg.AssertionClientRepo).
	OAuthClientID   OAuthClientID
	Description     Description
	CreatedByUserID UserID
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time

	// PublicKeyPEM — SPKI-encoded ECDSA P-256 публичный ключ удостоверения.
	// По нему проверяется подпись `client_assertion` на пути выдачи токена.
	PublicKeyPEM string
	// KeyAlgorithm — JOSE alg зарегистрированного ключа. Всегда "ES256" для новых
	// токенов.
	KeyAlgorithm string

	// CredentialKind — вид удостоверения. ЗАПИСЫВАЕТСЯ при вставке; читателем
	// не вычисляется и из состава прочих полей не выводится.
	CredentialKind CredentialKind
	// SecretHash — sha256 по идентификатору строки И секретной части вместе,
	// 32 байта. Непуст ТОЛЬКО у вида SECRET. Сам секрет не хранится нигде: он
	// существует только в теле ответа, полученного вызывающим выдачи.
	SecretHash []byte

	// Name — человекочитаемое имя токена, выставляется на Issue (create-only,
	// immutable — ресурс несёт только Issue/List/Revoke). Пусто для legacy-строк.
	Name OAuthClientName
	// Labels — произвольные метки токена, выставляются на Issue (create-only,
	// immutable). Пусто для legacy-строк.
	Labels Labels
}

// Validate — self-validating инвариант доменной сущности.
func (c UserOAuthClient) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.ID.Validate())
	// Зеркало поставщика проверяется, только когда оно ЕСТЬ. Пустое — законный
	// вход: у строки нового выпуска регистрации у поставщика нет вовсе, и
	// требовать от неё годного чужого идентификатора значило бы требовать
	// назвать то, чего не существует.
	if c.OAuthClientID != "" {
		errs = multierr.Append(errs, c.OAuthClientID.Validate())
	}
	errs = multierr.Append(errs, c.Description.Validate())
	if c.UserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument user_id: required"))
	}
	if c.CreatedByUserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument created_by_user_id: required"))
	}
	if c.ExpiresAt != nil && !c.CreatedAt.IsZero() && !c.ExpiresAt.After(c.CreatedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expires_at: must be > created_at"))
	}
	switch c.KeyAlgorithm {
	case "", "ES256", "RS256", "EdDSA":
		// allowed; empty kept for потенциальных legacy-строк.
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("Illegal argument key_algorithm: must be one of {ES256,RS256,EdDSA}"))
	}
	errs = multierr.Append(errs, c.Name.Validate())
	errs = multierr.Append(errs, c.Labels.Validate())
	return errs
}

// UserOAuthClientID — новый формат `uoc<17-crockford>` (corelib `ids.NewID`, без
// подчёркивания). id существующих строк immutable, поэтому валидатор принимает и
// legacy `uoc_<17-crockford>`.
type UserOAuthClientID string

var uocIDRe = regexp.MustCompile(`^uoc_?[0-9a-hjkmnp-tv-z]{17}$`)

func (id UserOAuthClientID) Validate() error {
	if !uocIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^uoc_?[0-9a-hjkmnp-tv-z]{17}$")
	}
	return nil
}
