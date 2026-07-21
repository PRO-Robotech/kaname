// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// grpc_register.go — registration of gRPC handlers onto public / internal servers.
// Pure wiring: no business logic, no env reads.
package main

import (
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/handler"
)

// registerPublicServices — публичные RPC + OperationService на внешний listener.
func registerPublicServices(srv *grpc.Server, svcs *services, opsRepo operations.Repo) {
	operationpb.RegisterOperationServiceServer(srv, handler.NewOperationHandler(opsRepo))
	if svcs != nil && svcs.accountHandler != nil {
		iamv1.RegisterAccountServiceServer(srv, svcs.accountHandler)
	}
	if svcs != nil && svcs.projectHandler != nil {
		iamv1.RegisterProjectServiceServer(srv, svcs.projectHandler)
	}
	if svcs != nil && svcs.userHandler != nil {
		iamv1.RegisterUserServiceServer(srv, svcs.userHandler)
	}
	if svcs != nil && svcs.serviceAccountHandler != nil {
		iamv1.RegisterServiceAccountServiceServer(srv, svcs.serviceAccountHandler)
	}
	if svcs != nil && svcs.groupHandler != nil {
		iamv1.RegisterGroupServiceServer(srv, svcs.groupHandler)
	}
	if svcs != nil && svcs.roleHandler != nil {
		iamv1.RegisterRoleServiceServer(srv, svcs.roleHandler)
	}
	if svcs != nil && svcs.accessBindingHandler != nil {
		iamv1.RegisterAccessBindingServiceServer(srv, svcs.accessBindingHandler)
	}
	// AuthZ — public RPCs.
	if svcs != nil && svcs.authorizeHandler != nil {
		iamv1.RegisterAuthorizeServiceServer(srv, svcs.authorizeHandler)
	}
	if svcs != nil && svcs.conditionsHandler != nil {
		iamv1.RegisterConditionsServiceServer(srv, svcs.conditionsHandler)
	}
	// PermissionCatalogService — RBAC rules-model G: PUBLIC sync read of the
	// backend-driven grantable role-rule taxonomy (GET /iam/v1/permissionCatalog).
	// Platform metadata (NOT infra-sensitive, G-D3) → public listener;
	// authenticated-floor enforced in-use-case (anonymous fail-closed).
	if svcs != nil && svcs.permissionCatalogHandler != nil {
		iamv1.RegisterPermissionCatalogServiceServer(srv, svcs.permissionCatalogHandler)
	}
	// SAKey (Class A static service-account keys via Hydra).
	// Workload Identity Federation (FederationExchangeService) removed.
	if svcs != nil && svcs.saKeysHandler != nil {
		iamv1.RegisterSAKeyServiceServer(srv, svcs.saKeysHandler)
	}
	// UserToken (персональные access-токены пользователя via Hydra). Public под
	// /iam/v1/users/{id}/tokens — зеркало SAKeyService на iam_user.
	if svcs != nil && svcs.userTokensHandler != nil {
		iamv1.RegisterUserTokenServiceServer(srv, svcs.userTokensHandler)
	}
}

// registerInternalServices — kacho-only/admin RPC на internal listener.
func registerInternalServices(srv *grpc.Server, svcs *services, pool *pgxpool.Pool, dsn string, logger *slog.Logger) {
	_ = pool
	_ = dsn
	_ = logger
	if svcs != nil && svcs.internalUserHandler != nil {
		iamv1.RegisterInternalUserServiceServer(srv, svcs.internalUserHandler)
	}
	if svcs != nil && svcs.internalIAMHandler != nil {
		iamv1.RegisterInternalIAMServiceServer(srv, svcs.internalIAMHandler)
	}
	// AuthZ — internal-only admin RPCs.
	if svcs != nil && svcs.internalAuthorizeHandler != nil {
		iamv1.RegisterInternalAuthorizeServiceServer(srv, svcs.internalAuthorizeHandler)
	}
	// AuthorizeService ALSO on the internal listener — RBAC rules-model consumer
	// list-filter edge. The SAME handler instance
	// already registered on the public listener (registerPublicServices) is
	// re-registered here so consumers (kacho-vpc / kacho-compute / kacho-nlb) can
	// call AuthorizeService.ListObjects (per-object List filter) / BatchCheck /
	// Check over the verified-mTLS :9091 service→service edge they already reuse
	// for InternalIAMService.Check — instead of a separate public :9090 conn.
	//
	// This does NOT violate ban #6: ban #6 forbids Internal.* methods on the
	// PUBLIC surface. The inverse — a PUBLIC service ADDITIONALLY exposed on the
	// cluster-internal :9091 — is the established service→service pattern (the
	// internal listener is not tenant-facing). The internal interceptor chain
	// (CallerPolicy floor: verified module cert required in prod; AuthorizeService
	// is NOT gateway-fronted, NOT in ReadFloorRPCs, NOT acr-floored) admits any
	// verified module SA. ListObjects accepts an EXPLICIT subject and filters from
	// the END-USER's authz view, so the caller-authz is "this module MAY query
	// authz decisions" (verified-cert floor) — NOT "this module has access to the
	// objects" (which is the explicit-subject's view).
	if svcs != nil && svcs.authorizeHandler != nil {
		iamv1.RegisterAuthorizeServiceServer(srv, svcs.authorizeHandler)
	}
	// OpaBundleService + TrustPolicyService removed.
	// InternalClusterService — cluster admin RBAC (NOT on public TLS;
	// ban #6 — Internal.* not on external endpoint).
	if svcs != nil && svcs.internalClusterHandler != nil {
		iamv1.RegisterInternalClusterServiceServer(srv, svcs.internalClusterHandler)
	}
	// InternalSessionRevocationsService — token revocation
	// (logout / force-logout write + IsRevoked hot-path + admin ListByUser).
	// Internal-only (запрет #6); the api-gateway logout handler + refresh-hook
	// drive it. Registering it here closes the P0 gap where Revoke returned
	// codes.Unimplemented and token revocation was inert.
	if svcs != nil && svcs.sessionRevocationsHandler != nil {
		iamv1.RegisterInternalSessionRevocationsServiceServer(srv, svcs.sessionRevocationsHandler)
	}
	// InternalOperationsService — cluster-wide admin operations
	// feed. Internal-only (запрет #6): NEVER registered on the external listener
	// (registerPublicServices). Admin-tier gated by the gateway permission-catalog
	// (system_admin@cluster, acr=2) AND the in-handler ReBAC Check; the internal
	// listener's authz interceptor chain also enforces it via
	// authzguard.GatewayFrontedInternalRPCs (caller-policy + acr-floor).
	if svcs != nil && svcs.internalOperationsHandler != nil {
		iamv1.RegisterInternalOperationsServiceServer(srv, svcs.internalOperationsHandler)
	}
	// InternalBootstrapTokenService — non-interactive bootstrap RS256 token mint
	// (#58). Internal-only (ban #6): NEVER on the external listener. The mTLS
	// listener boundary is the gate (permission="<exempt>"); the caller-policy
	// (authzguard.GatewayFrontedInternalRPCs) restricts the dialer to the gateway SA.
	if svcs != nil && svcs.internalBootstrapTokenHandler != nil {
		iamv1.RegisterInternalBootstrapTokenServiceServer(srv, svcs.internalBootstrapTokenHandler)
	}
}
