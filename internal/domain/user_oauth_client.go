// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// UserOAuthClient — персональный access-токен пользователя (Hydra static
// client).
//
// private_key_jwt: kacho-iam генерирует пару ключей ECDSA P-256 на каждый токен,
// регистрирует публичный JWK в Hydra (`token_endpoint_auth_method =
// private_key_jwt`) и возвращает приватный PEM вызывающему ровно один раз. Hydra
// хранит только JWK; kacho-iam держит SPKI public PEM (для диагностики) плюс
// алгоритм. Секрет не существует at-rest.
//
// N:1 — у одного User может быть несколько токенов.
type UserOAuthClient struct {
	ID              UserOAuthClientID
	UserID          UserID
	OAuthClientID   OAuthClientID
	Description     Description
	CreatedByUserID UserID
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time

	// PublicKeyPEM — SPKI-encoded ECDSA P-256 публичный ключ, зарегистрированный
	// в Hydra как JWK.
	PublicKeyPEM string
	// KeyAlgorithm — JOSE alg зарегистрированного ключа. Всегда "ES256" для новых
	// токенов.
	KeyAlgorithm string

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
	errs = multierr.Append(errs, c.OAuthClientID.Validate())
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
