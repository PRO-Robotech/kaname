// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
// Authorisation = "self (account owner) OR account-admin (FGA admin@account)" —
// the same authority rule as access_binding.requireAccountAdmin / ListByAccount.
// Distinct from the per-resource AccountService.ListOperations (which filters by
// the account's own resource_id rows); this one filters by the account_id
// column to aggregate every child resource's operations (no per-creator
// filter — viewer-scope parity with the existing per-resource lists).

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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
		if pageToken != "" {
			return nil, "", status.Error(codes.InvalidArgument, "invalid page_token")
		}
		return nil, "", status.Error(codes.Internal, "list operations failed")
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
	// IsClusterAdmin (unwired relations → false → fall through to owner/FGA paths).
	if u.relations != nil && authzguard.IsClusterAdmin(ctx, u.relations) {
		return nil
	}

	// Path 1 — owner of the Account.
	if authzguard.IsSelf(ctx, string(acct.OwnerUserID)) {
		return nil
	}

	// Path 2 — delegated admin via FGA.
	if u.relations != nil {
		if subject, ok := authzguard.PrincipalSubject(ctx); ok {
			object := fmt.Sprintf("account:%s", strings.ToLower(accountID))
			allowed, cerr := u.relations.Check(ctx, subject, "admin", object)
			if cerr == nil && allowed {
				return nil
			}
		}
	}

	return authzguard.PermissionDenied()
}
