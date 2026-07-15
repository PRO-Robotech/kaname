// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hooks_mux.go — HTTP mux composition for AuthN hooks listener.
// Hydra hooks (token + refresh), DPoP replay cache.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	reconcileapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	handlerinternal "github.com/PRO-Robotech/kacho/services/iam/internal/handler/iamhooks"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// buildHooksMux — собирает HTTP mux для AuthN hooks.
//
// kachoRepo / opsRepo / relationStore прокидываются из composition root
// (serve.go) — provision hook (Kratos user-provisioning, C4) строит
// UpsertFromIdentityUseCase из тех же зависимостей, что wiring.go, и
// переиспользует уже-собранный OpenFGA-клиент (не дублирует его).
func buildHooksMux(
	pool *pgxpool.Pool,
	kachoRepo kachorepo.Repository,
	opsRepo operations.Repo,
	relationStore *clients.OpenFGAHTTPClient,
	cfg config.Config,
	logger *slog.Logger,
) http.Handler {
	hookSecret := cfg.AuthN.ResolveHookSharedSecret()
	domain := cfg.AuthN.ResolveDomain()
	hydraIssuer := cfg.AuthN.ResolveHydraIssuer()

	// Repo adapters (pool-scoped).
	users := kachopg.NewUserPoolRepo(pool)
	auditPg := kachopg.NewAuditEmitterAdapter(pool)
	revsPg := kachopg.NewSessionRevocationsAdapter(pool)

	// Adapter shims между port-iface'ами handler-слоя и repo-adapter'ами.
	auditAdapter := &handlerinternal.AuditAdapter{EmitFn: auditPg.Emit}

	saClientRepo := kachopg.NewSAOAuthClientRepo(pool)
	saPort := &tokenEnrichSAAdapter{pool: pool, saClients: saClientRepo}

	// User-token principal mapping: минтованный из UserOAuthClient токен резолвится
	// в принципал `user:<id>` (net-new относительно SA-key → serviceAccount:<id>).
	userClientRepo := kachopg.NewUserOAuthClientRepo(pool)
	userTokenPort := &tokenEnrichUserTokenAdapter{userClients: userClientRepo, users: users}

	tokenEnricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: domain, HydraIssuer: hydraIssuer},
		users,
	).WithSAPort(saPort).WithUserTokenPort(userTokenPort)
	tokenHook := handlerinternal.NewTokenHookHandler(
		handlerinternal.TokenHookConfig{
			HookSharedSecret: hookSecret,
			Domain:           domain,
			HydraIssuer:      hydraIssuer,
		},
		tokenEnricher,
		auditAdapter,
		logger,
	)
	refreshHook := handlerinternal.NewRefreshHookHandler(
		handlerinternal.RefreshHookConfig{
			HookSharedSecret: hookSecret,
			Domain:           domain,
			HydraIssuer:      hydraIssuer,
		},
		users,
		revsPg,
		auditAdapter,
		logger,
	)

	// Provision hook (C4): Kratos registration/login → UpsertFromIdentity.
	// Reuse the SAME repo/opsRepo/relationStore the gRPC InternalUserService
	// wiring uses (wiring.go) — same bootstrap + FGA-tuple side-effects, no
	// duplicate OpenFGA client. rbac-contract-a-flat-fallout: ALSO wire the owner-
	// binding reconciler so the Kratos provision-hook signup path (the LIVE
	// signup path) forward-materializes the bootstrap owner's per-object content
	// access — parity with the gRPC InternalUserService wiring (wiring.go). Without
	// it the LIVE signup user is 403 on their own account's content until the sweep.
	provisionReconciler := reconcileapp.New(kachopg.NewReconcileAdapter(pool), logger)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(provisionReconciler)
	provisionHook := handlerinternal.NewProvisionHookHandler(
		handlerinternal.ProvisionHookConfig{HookSharedSecret: hookSecret},
		&userProvisionAdapter{uc: userUpsert},
		logger,
	)

	mux := handlerinternal.NewMux(handlerinternal.Handlers{
		TokenHook:     tokenHook,
		RefreshHook:   refreshHook,
		ProvisionHook: provisionHook,
		// /readyz отражает доступность критичных зависимостей: коннект к БД и
		// поднятый LRO-worker. /healthz остается чистым liveness.
		Readiness: []handlerinternal.ReadinessChecker{
			{Name: "database", Check: pool.Ping},
			{Name: "lro-worker", Check: func(context.Context) error {
				if operations.Ready() {
					return nil
				}
				return errors.New("lro worker not ready")
			}},
		},
	})
	wrapped := handlerinternal.LoggerMiddleware(mux, func(method, path string, status int) {
		logger.Info("hooks http", "method", method, "path", path, "status", status)
	})
	return wrapped
}

// userProvisionAdapter maps the iamhooks.UserProvisioner port to the
// UpsertFromIdentityUseCase. Composition-root shim so the
// handler stays free of the use-case package / operations types. The use-case
// returns an LRO Operation; the hook only needs the synchronous accept/reject
// signal (the bootstrap TX itself runs inside operations.Run), so we discard
// the Operation and surface only the error.
type userProvisionAdapter struct {
	uc *userapp.UpsertFromIdentityUseCase
}

func (a *userProvisionAdapter) Provision(ctx context.Context, in handlerinternal.ProvisionInput) error {
	_, err := a.uc.Execute(ctx, userapp.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(in.ExternalID),
		Email:       domain.Email(in.Email),
		DisplayName: domain.DisplayName(in.DisplayName),
	})
	return err
}

// tokenEnrichSAAdapter — pool-scoped read adapter for
// service.TokenEnrichmentSAPort. The SAOAuthClient pool repo already serves
// the hydra_client_id reverse lookup; the ServiceAccount reader in
// `service_account_repo.go` is tx-scoped, so we issue a single short-lived
// read tx per lookup (no row locks; auto-rollback on return).
type tokenEnrichSAAdapter struct {
	pool      *pgxpool.Pool
	saClients *kachopg.SAOAuthClientRepo
}

func (a *tokenEnrichSAAdapter) LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.GetByOAuthClientID(ctx, hydraClientID)
}

// FindByExternalSubject — federation-in: resolve the SA mapping by
// (external OIDC issuer, external sub) against `trusted_subjects`.
func (a *tokenEnrichSAAdapter) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.FindByExternalSubject(ctx, issuer, sub)
}

func (a *tokenEnrichSAAdapter) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	var sa domain.ServiceAccount
	row := a.pool.QueryRow(ctx,
		`SELECT id, account_id, name, description, created_at
		   FROM service_accounts WHERE id = $1`, string(id))
	var name, description string
	if err := row.Scan(
		(*string)(&sa.ID), (*string)(&sa.AccountID),
		&name, &description, &sa.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
		}
		return domain.ServiceAccount{}, fmt.Errorf("scan service_account %s: %w", id, err)
	}
	sa.Name = domain.SvcAccountName(name)
	sa.Description = domain.Description(description)
	return sa, nil
}

// tokenEnrichUserTokenAdapter — pool-scoped read adapter for
// service.TokenEnrichmentUserTokenPort. Резолвит принципал `user:<id>` для токена,
// минтованного из UserOAuthClient (личный access-токен) — обратный lookup по
// hydra_client_id + чтение владеющего User.
type tokenEnrichUserTokenAdapter struct {
	userClients *kachopg.UserOAuthClientRepo
	users       *kachopg.UserPoolRepo
}

func (a *tokenEnrichUserTokenAdapter) LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.UserOAuthClient, error) {
	return a.userClients.GetByOAuthClientID(ctx, hydraClientID)
}

func (a *tokenEnrichUserTokenAdapter) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	return a.users.GetByID(ctx, id)
}
