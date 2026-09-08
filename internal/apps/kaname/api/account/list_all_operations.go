// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// list_all_operations.go — ListAllOperationsUseCase backing
// AccountService.ListAllOperations.
//
// Account-scoped public feed: returns ALL IAM operations whose denormalized
// operations.account_id == the given account (corelib ListFilter.AccountID,
// DB-level partial-index filter — not software aggregation).
// This is the server-side scope the IAM "Operations" nav page consumes; the VPC
// client-side fan-out pattern does not apply (IAM is not project-scoped).
//
// Authorisation = "cluster-admin OR self (account owner) OR account-admin (FGA
// admin@account)" — the same authority rule as access_binding.requireAccountAdmin
// / ListByAccount. Distinct from the per-resource AccountService.ListOperations,
// which filters by the account's own resource_id rows.
//
// ЯРУС: административный, и потому выдача здесь НЕ сужается по создателю
// операции — в отличие от всех per-resource списков, которые сужены
// (operations.ListForCaller). Обоснование — сама политика ярусов: администратор
// аккаунта может всё в пределах аккаунта, каскадом; аудит чужих действий внутри
// СВОЕЙ тенантности — это и есть предмет данного RPC («ListAll»), а не побочный
// эффект. Сужение по создателю сделало бы его тождественным per-resource списку
// и убрало бы единственную поверхность, на которой владелец аккаунта видит, что
// в его аккаунте происходило.
//
// Прежняя редакция этого комментария обосновывала отсутствие фильтра «паритетом
// с существующими per-resource списками». После их сужения такое обоснование
// стало ложным, поэтому заменено на настоящее — ярус доступа.
//
// Границы яруса: гейт ниже пропускает ТОЛЬКО кластерного администратора,
// владельца аккаунта и делегированного администратора аккаунта. Обычный тенант с
// правом на список сюда не попадает вовсе.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ListAllOperationsUseCase aggregates every IAM operation of one account scope.
type ListAllOperationsUseCase struct {
	repo      Repo
	opsRepo   operations.Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

// NewListAllOperationsUseCase wires the use-case.
func NewListAllOperationsUseCase(r Repo, opsRepo operations.Repo) *ListAllOperationsUseCase {
	return &ListAllOperationsUseCase{repo: r, opsRepo: opsRepo}
}

// WithRelationStore wires the FGA client for the delegated account-admin path.
// When unset (unit tests / degraded mode) only the account owner is allowed
// (fail-closed for non-owners).
func (u *ListAllOperationsUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListAllOperationsUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// Execute returns the account-scoped operations (cursor-paginated) and the
// next_page_token. Malformed account id → InvalidArgument (first statement);
// missing / forbidden account → PermissionDenied (existence hiding, parity with
// requireAccountAdmin).
func (u *ListAllOperationsUseCase) Execute(ctx context.Context, accountID string, pageSize int64, pageToken string) ([]operations.Operation, string, error) {
	if err := shared.ValidateResourceID(accountID, domain.PrefixAccount, "account"); err != nil {
		return nil, "", err
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}
	if err := u.requireAccountViewAuthority(ctx, accountID); err != nil {
		return nil, "", err
	}

	ops, next, err := u.opsRepo.List(ctx, operations.ListFilter{
		AccountID: accountID,
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	if err != nil {
		// Classified by what the STORE answered, never by whether a cursor was
		// supplied — see shared.MapOperationsListErr.
		return nil, "", shared.MapOperationsListErr(err)
	}
	return ops, next, nil
}

// requireAccountViewAuthority allows the caller iff either:
//   - caller is the Account owner (bootstrap path), or
//   - caller holds the FGA `admin` relation on `account:<id>` (delegated).
//
// Mirrors access_binding.requireAccountAdmin. Missing account → PermissionDenied
// (existence-leak prevention: a stranger cannot distinguish missing vs forbidden).
func (u *ListAllOperationsUseCase) requireAccountViewAuthority(ctx context.Context, accountID string) error {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	acct, gerr := rd.Accounts().Get(ctx, domain.AccountID(accountID))
	if gerr != nil {
		return authzguard.PermissionDenied()
	}

	// Path 0 — cluster-admin short-circuit: a cluster-admin may audit ANY
	// account's operations even without a per-account admin-tuple. nil-safe inside
	// IsClusterAdminE (unwired relations → (false, nil) → fall through).
	//
	// E-форма: исходов у надзора три. Путь 2 ниже свой отказ уже разводит, но он
	// спрашивает про ДРУГОЙ кортеж — ответив на него «нет», хранилище оставило бы
	// неполадку надзора невидимой, и аудитор прочитал бы её как «не положено».
	admin, aerr := authzguard.IsClusterAdminE(ctx, u.relations)
	if aerr != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if admin {
		return nil
	}

	// Path 1 — owner of the Account.
	if authzguard.IsSelf(ctx, string(acct.OwnerUserID)) {
		return nil
	}

	// Path 2 — delegated admin via FGA.
	//
	// Исходы вопроса разведены: «хранилище ответило нет» и «хранилище не
	// ответило» — разные отказы. Прежде здесь стояло `if cerr == nil && allowed`,
	// после чего управление уходило на безусловный `PermissionDenied` — то есть
	// неполадка хранилища прав сообщала аудитору, что ему не положено, и повтор
	// выглядел бессмысленным.
	if u.relations != nil {
		if subject, ok := authzguard.PrincipalSubject(ctx); ok {
			object := fmt.Sprintf("account:%s", strings.ToLower(accountID))
			allowed, cerr := u.relations.Check(ctx, subject, "admin", object)
			if cerr != nil {
				return authzguard.AuthzBackendUnavailable()
			}
			if allowed {
				return nil
			}
		}
	}

	return authzguard.PermissionDenied()
}
