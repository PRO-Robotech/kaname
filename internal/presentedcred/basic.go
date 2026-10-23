// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package presentedcred

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// BasicCredentialResolver проверяет секрет, срок и живость владельца одной
// существующей полосой авторитета. Реализация ограничивает каждое обращение к БД.
type BasicCredentialResolver interface {
	ResolveBasic(context.Context, string) (domain.BasicCredential, error)
}

// verifyBasic не кеширует положительный вердикт: снятие строки действует при
// следующем предъявлении. Марка выбрана до JWT, и отказ не меняет полосу.
func (r *Reader) verifyBasic(ctx context.Context, raw string) (verified, error) {
	parsed, err := credsecret.Parse(raw)
	if err != nil {
		return verified{}, r.refuse("malformed basic credential")
	}
	if r.cfg.BasicCredentials == nil {
		return verified{}, r.basicUnavailable()
	}
	credential, err := r.cfg.BasicCredentials.ResolveBasic(ctx, raw)
	if errors.Is(err, domain.ErrBasicCredentialRefused) {
		return verified{}, r.refuse("basic credential refused")
	}
	if err != nil {
		return verified{}, r.basicUnavailable()
	}
	if (credential.PrincipalType != "user" && credential.PrincipalType != "service_account") ||
		credential.PrincipalID == "" || credential.CredentialID != parsed.CredentialID ||
		!credential.ExpiresAt.After(r.now()) {
		return verified{}, r.refuse("basic credential authority returned no live identity")
	}
	return verified{
		principal:    operations.Principal{Type: credential.PrincipalType, ID: credential.PrincipalID, DisplayName: credential.DisplayName},
		acr:          "1",
		credentialID: credential.CredentialID,
	}, nil
}

// basicUnavailable отличает отказ зависимости от негодного секрета, не
// раскрывая ни предъявленную строку, ни ошибку базы в ответе или журнале.
func (r *Reader) basicUnavailable() error {
	r.unavailable.Add(1)
	r.logger.Error("basic credential authority unavailable")
	return status.Error(codes.Unavailable, "credential authority unavailable")
}
