// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrytokenwire — composition-root adapters binding the registry
// `/iam/token` shim use-case to iam infrastructure:
//
//   - HydraExchangeAdapter — brokers the client_credentials + private_key_jwt
//     exchange with Hydra's public token endpoint, mapping issuer-unavailability
//     to the use-case's fail-closed sentinel. Пользуется им АНОНИМНЫЙ поток на
//     контуре, ещё не переведённом на нашу чеканку.
//
//   - SAClientLookupAdapter — обратный резолв ключа служебной учётки по
//     client_id. Живёт ТОЛЬКО ради окна перехода #1143: полоса предъявленного
//     удостоверения принимает базовый токен доступа, а ключевой материал — лишь
//     пока оператор держит окно открытым. Предикат снятия — снятие ручки
//     `api-server.registry-token.key-material-window-until`.
//
// These are thin adapters over already-tested primitives; they carry no policy.
package registrytokenwire

import (
	"context"
	"errors"
	"fmt"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// ── Hydra token exchange ────────────────────────────────────────────────────

// hydraClientCredentials — the Hydra public token endpoint (satisfied by
// clients.HydraTokenClient).
type hydraClientCredentials interface {
	ClientCredentials(ctx context.Context, req clients.ClientCredentialsRequest) (clients.TokenResponse, error)
}

// HydraExchangeAdapter — the TokenExchanger backed by Hydra's public token
// endpoint. Issuer unavailability is surfaced as the use-case's fail-closed
// sentinel; a Hydra rejection is returned as-is (the use-case collapses it to a
// 401 challenge).
type HydraExchangeAdapter struct {
	client hydraClientCredentials
}

// NewHydraExchange — builder.
func NewHydraExchange(c hydraClientCredentials) *HydraExchangeAdapter {
	return &HydraExchangeAdapter{client: c}
}

var _ registrytokenuc.TokenExchanger = (*HydraExchangeAdapter)(nil)

// Exchange brokers the client_credentials + private_key_jwt exchange.
func (a *HydraExchangeAdapter) Exchange(ctx context.Context, in registrytokenuc.ExchangeInput) (registrytokenuc.ExchangeOutput, error) {
	out, err := a.client.ClientCredentials(ctx, clients.ClientCredentialsRequest{
		ClientAssertion: in.ClientAssertion,
		Audience:        in.Audience,
		Scope:           in.Scope,
	})
	if err != nil {
		if errors.Is(err, clients.ErrHydraUnavailable) {
			// Причина ОБОРАЧИВАЕТСЯ, а не подменяется: наружу отказ всё равно
			// уйдёт фиксированным текстом (собирает use-case), а в журнал
			// попадёт то, что ответила сеть. Голый sentinel здесь означал бы
			// пересказ собственного решения об отказе — ровно то, что стоило
			// двадцати минут разбора на живом стенде у соседней выдачи.
			return registrytokenuc.ExchangeOutput{}, fmt.Errorf("%w: %w",
				registrytokenuc.ErrIssuerUnavailable, err)
		}
		// Hydra rejection (invalid_client / invalid_grant) — collapsed to 401
		// upstream; no raw Hydra detail is propagated.
		return registrytokenuc.ExchangeOutput{}, registrytokenuc.ErrInvalidCredentials
	}
	return registrytokenuc.ExchangeOutput{AccessToken: out.AccessToken, ExpiresIn: out.ExpiresIn}, nil
}

// saClientByIDReader — reverse lookup of an SA-OAuth-client by Hydra client_id,
// plus the ServiceAccount it belongs to (satisfied by the SA repo). The account
// read is part of this port because the docker path decides on the account's
// state, and a port that could not answer for it would leave that decision
// resting on a field nobody loaded.
type saClientByIDReader interface {
	GetByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error)
	GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
}

// ── SA-key lookup by client_id ──────────────────────────────────────────────

// SAClientLookupAdapter — resolves the registered SA-key for a Hydra client_id.
type SAClientLookupAdapter struct {
	repo saClientByIDReader
}

// NewSAClientLookup — builder.
func NewSAClientLookup(repo saClientByIDReader) *SAClientLookupAdapter {
	return &SAClientLookupAdapter{repo: repo}
}

var _ registrytokenuc.SAClientLookup = (*SAClientLookupAdapter)(nil)

// KeyByClientID returns the registered key material for a Hydra client_id,
// together with whether the owning ServiceAccount may authenticate.
//
// The owner's state is resolved here, on the lookup, because the validator
// decides on it: a lookup that returned only key material would hand back a
// zero value for the state, and every docker login in the platform would be
// refused by a check that never saw a row.
func (a *SAClientLookupAdapter) KeyByClientID(ctx context.Context, clientID string) (registrytokenuc.RegisteredKey, error) {
	row, err := a.repo.GetByOAuthClientID(ctx, domain.OAuthClientID(clientID))
	if err != nil {
		return registrytokenuc.RegisteredKey{}, fmt.Errorf("registrytokenwire: lookup client %s: %w", clientID, err)
	}
	sa, err := a.repo.GetServiceAccount(ctx, row.SvaID)
	if err != nil {
		return registrytokenuc.RegisteredKey{}, fmt.Errorf("registrytokenwire: lookup service account %s: %w", row.SvaID, err)
	}
	return registrytokenuc.RegisteredKey{
		ClientID:       string(row.OAuthClientID),
		KeyID:          string(row.ID),
		Subject:        string(row.SvaID),
		PublicKeyPEM:   row.PublicKeyPEM,
		KeyAlgorithm:   row.KeyAlgorithm,
		ExpiresAt:      row.ExpiresAt,
		SubjectEnabled: sa.MayAuthenticate(),
		// Сужение адресатов, объявленное при выдаче ключа (#1136). Читается ЗДЕСЬ
		// и уезжает в выдачу: колонка, которую пишут и не читают, невидима
		// отовсюду — её нет ни в ответе, ни в решении.
		DeclaredAudiences: row.DeclaredAudiences,
	}, nil
}
