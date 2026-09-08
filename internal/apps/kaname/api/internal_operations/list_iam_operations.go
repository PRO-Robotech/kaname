// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ListIamOperationsUseCase lists every IAM operation of the cluster, optionally
// narrowed to one account_id. Admin-tier gated.
//
// ЯРУС: внутренний, кластерный администратор (system_admin @ cluster), RPC живёт
// только на internal-листенере. Выдача здесь НЕ сужается по создателю операции —
// в отличие от всех tenant-facing списков, которые сужены
// (operations.ListForCaller). Это ровно тот случай, который godoc
// operations.Repo.List называет законным: несуженный путь — для доверенного
// внутреннего вызывающего, уже авторизованного иначе. Кластерный аудит по
// определению обязан видеть чужие операции; сужение по создателю обнулило бы
// смысл RPC.
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
// (full cluster scope). A listing failure is classified by what the STORE said
// (shared.MapOperationsListErr): a page format the store rejected stays
// InvalidArgument with its field named, and anything else — an unreachable
// database above all — is reported as a store failure. This feed is what a
// cluster administrator reads during an incident, so mislabelling an outage as
// a bad cursor sends the one person who can fix it to the wrong place.
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
		return nil, "", shared.MapOperationsListErr(err)
	}
	return ops, next, nil
}

// requireClusterSystemAdmin — defense-in-depth gate, non-leaking on every failure
// mode: anonymous principal, nil checker or explicit deny → PermissionDenied; a
// checker that could not be reached → Unavailable, because nothing was decided.
// Mirrors cluster.requireClusterSystemAdmin (the highest-blast pattern).
//
// The distinction matters most here: this feed is what an operator reads DURING
// an incident, and an outage of the model would otherwise read to them as "your
// admin grant is gone" at the exact moment they need it.
func (u *ListIamOperationsUseCase) requireClusterSystemAdmin(ctx context.Context) error {
	// The subject is resolved to the principal's own type — see
	// cluster.requireClusterSystemAdmin for why "user:" joined to the id is a
	// string rather than a policy.
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return authzguard.PermissionDenied()
	}
	if u.checker == nil {
		return authzguard.PermissionDenied()
	}
	allowed, err := u.checker.Check(ctx,
		subject,
		"system_admin",
		"cluster:"+domain.ClusterSingletonID,
	)
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if !allowed {
		return authzguard.PermissionDenied()
	}
	return nil
}
