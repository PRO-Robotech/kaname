// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrytokenwire — composition-root adapters binding the registry
// `/iam/token` shim use-case to iam infrastructure:
//
//   - LocalMintAdapter (local_minter.go) — НАШ подписант, единственный издатель
//     полосы.
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
	"fmt"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// saClientByIDReader — lookup of an SA key by its client id (the id of its row;
// kaname#362), plus the ServiceAccount it belongs to (satisfied by the SA repo).
// The account read is part of this port because the docker path decides on the
// account's state, and a port that could not answer for it would leave that
// decision resting on a field nobody loaded.
type saClientByIDReader interface {
	GetByClientID(ctx context.Context, clientID domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error)
	GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
}

// ── SA-key lookup by client_id ──────────────────────────────────────────────

// SAClientLookupAdapter — resolves the registered SA-key for a client id.
type SAClientLookupAdapter struct {
	repo saClientByIDReader
}

// NewSAClientLookup — builder.
func NewSAClientLookup(repo saClientByIDReader) *SAClientLookupAdapter {
	return &SAClientLookupAdapter{repo: repo}
}

var _ registrytokenuc.SAClientLookup = (*SAClientLookupAdapter)(nil)

// KeyByClientID returns the registered key material for a client id,
// together with whether the owning ServiceAccount may authenticate.
//
// The owner's state is resolved here, on the lookup, because the validator
// decides on it: a lookup that returned only key material would hand back a
// zero value for the state, and every docker login in the platform would be
// refused by a check that never saw a row.
func (a *SAClientLookupAdapter) KeyByClientID(ctx context.Context, clientID string) (registrytokenuc.RegisteredKey, error) {
	row, err := a.repo.GetByClientID(ctx, domain.SAOAuthClientID(clientID))
	if err != nil {
		return registrytokenuc.RegisteredKey{}, fmt.Errorf("registrytokenwire: lookup client %s: %w", clientID, err)
	}
	sa, err := a.repo.GetServiceAccount(ctx, row.SvaID)
	if err != nil {
		return registrytokenuc.RegisteredKey{}, fmt.Errorf("registrytokenwire: lookup service account %s: %w", row.SvaID, err)
	}
	return registrytokenuc.RegisteredKey{
		ClientID:       string(row.ID),
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
