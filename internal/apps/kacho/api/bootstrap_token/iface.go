// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// iface.go — narrow port interfaces for the bootstrap-token use-case.
//
// Clean Architecture: the use-case depends on these; concrete adapters live in
// internal/repo/kacho/pg (BootstrapStore) and internal/bootstraptokenwire
// (LocalMinter, over the platform token signer), wired in cmd/kacho-iam. No
// pgx / grpc imports here (only the domain DTOs, mirroring sa_keys).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЗДЕСЬ БОЛЬШЕ НЕТ — И ПОЧЕМУ ЭТО СНЯТО, А НЕ ОТСТАВЛЕНО (задача #1119)
//
// Здесь стояли два порта к внешнему поставщику удостоверений: заведение его
// OAuth-клиента (`OAuthClientAdmin.CreateOAuthClient`) и обмен подписанного
// утверждения на токен (`TokenExchanger.Exchange`), плюс признак его
// недоступности. Оба сняты вместе со своим предметом: удостоверение чеканит
// НАШ подписант (`LocalMinter`), и дороги к поставщику на этом пути нет вовсе.
//
// Отставить их «на случай посадки без своей чеканки» было бы хуже, чем снять.
// Порт без вызывающего неотличим от исправного, а страж старта, требующий
// пригодного адреса и якоря для стороны, с которой процесс не разговаривает,
// отправляет оператора чинить дорогу, по которой никто не пойдёт.
//
// Техника, ради которой эти порты стоило перечитать перед снятием, — обёртывание
// причины отказа так, чтобы наружу ушёл фиксированный текст, а в журнал приехало
// то, что ответила сеть, — ПЕРЕНЕСЕНА на нашу полосу
// (`bootstraptokenwire.localMint`, проба `cause_survives_test.go`), а не
// потеряна вместе с ними.
package bootstrap_token

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// BootstrapStore — the singleton provisioning port for the bootstrap OAuth-client
// mapping (a service_account_oauth_clients row). LockAndGet serialises concurrent
// first-callers via a transaction-scoped advisory lock (released on commit/
// rollback) so the mapping row is written exactly once and the losers read the
// winner's row instead of colliding on it (IBT-03); UNIQUE(sva_id) on the mapping
// is the DB backstop.
//
// Строка соответствия остаётся и после перевода на свою чеканку: это НАША запись
// о бутстрап-клиенте — его идентификатор, его открытый ключ и его алгоритм, —
// а не зеркало чужой регистрации. Ею же резолвится состав утверждений
// выпускаемого токена.
type BootstrapStore interface {
	// LockAndGet takes the bootstrap provisioning advisory lock within tx, then
	// returns the existing mapping (found=false when not yet provisioned).
	LockAndGet(ctx context.Context, tx service.Tx) (c domain.ServiceAccountOAuthClient, found bool, err error)
	// InsertMapping persists the mapping row within tx (public key only; the
	// private half is env-held, never stored).
	InsertMapping(ctx context.Context, tx service.Tx, c domain.ServiceAccountOAuthClient) error
}
