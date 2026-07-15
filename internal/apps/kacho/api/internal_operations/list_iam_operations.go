// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package internal_operations — InternalOperationsService.ListIamOperations.
// Cluster-wide admin feed of ALL IAM operations.
//
// Запрет #6: registered ONLY on the internal listener (:9091), never external.
// AuthN+AuthZ applies on every listener: the backend listener is NOT exempt — this
// use-case runs a per-user ReBAC Check (system_admin @ cluster:<singleton>) so a
// caller that bypasses the api-gateway and dials :9091 directly is rejected
// without system_admin. The gateway permission-catalog entry (required_relation
// system_admin, object cluster, acr_min 2) is the front-door gate; this gate is
// the additive defense-in-depth one (mirrors cluster.requireClusterSystemAdmin).
package internal_operations

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ListIamOperationsUseCase lists every IAM operation of the cluster, optionally
// narrowed to one account_id. Admin-tier gated.
type ListIamOperationsUseCase struct {
	opsRepo operations.Repo
	// checker — narrow ReBAC port (Check). Satisfied by clients.RelationStore.
	// nil → fail-closed (never silently allow an unwired admin gate).
	checker authzguard.RelationChecker
}

// NewListIamOperationsUseCase wires the use-case.
func NewListIamOperationsUseCase(opsRepo operations.Repo) *ListIamOperationsUseCase {
	return &ListIamOperationsUseCase{opsRepo: opsRepo}
}

// WithAdminChecker wires the per-user system_admin@cluster ReBAC checker
// (defense-in-depth). nil-safe: an unwired checker fails closed.
func (u *ListIamOperationsUseCase) WithAdminChecker(checker authzguard.RelationChecker) *ListIamOperationsUseCase {
	u.checker = checker
	return u
}

// Execute enforces the admin-tier gate, then returns the cluster-wide (or
// account-filtered) operation page. accountID == "" → no account filter
// (full cluster scope). Garbage page_token → InvalidArgument.
func (u *ListIamOperationsUseCase) Execute(ctx context.Context, accountID string, pageSize int64, pageToken string) ([]operations.Operation, string, error) {
	if err := u.requireClusterSystemAdmin(ctx); err != nil {
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

// requireClusterSystemAdmin — defense-in-depth gate. Returns PermissionDenied
// (verbatim, non-leaking) on every failure mode: anonymous principal, nil
// checker, checker backend error, or explicit deny. Mirrors
// cluster.requireClusterSystemAdmin (the highest-blast pattern).
func (u *ListIamOperationsUseCase) requireClusterSystemAdmin(ctx context.Context) error {
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" || authzguard.IsAnonymous(ctx) {
		return authzguard.PermissionDenied()
	}
	if u.checker == nil {
		return authzguard.PermissionDenied()
	}
	allowed, err := u.checker.Check(ctx,
		"user:"+principal,
		"system_admin",
		"cluster:"+domain.ClusterSingletonID,
	)
	if err != nil || !allowed {
		return authzguard.PermissionDenied()
	}
	return nil
}
