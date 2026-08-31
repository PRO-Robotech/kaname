// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hooks_mux.go — HTTP mux composition for AuthN hooks listener.
// Hydra hooks (token + refresh), DPoP replay cache.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/observability/health"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	reconcileapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	handlerinternal "github.com/PRO-Robotech/kacho/services/iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// errLROWorkerNotReady — сентинел чекера готовности.
//
// На провод он НЕ попадает: общий носитель отдаёт наружу только ИМЯ упавшей
// зависимости, а причину оставляет процессу — наружу не текут ни детали ошибки,
// ни внутренние координаты. Текст поэтому адресован разбирающему, и слово он
// повторяет соседское (`services/compute`): один и тот же отказ, названный в
// двух сервисах по-разному, разводит операционный словарь на ровном месте.
var errLROWorkerNotReady = errors.New("LRO dispatcher loop not running")

// buildHooksMux — собирает HTTP mux для AuthN hooks и агрегатор его
// диагностической поверхности.
//
// Агрегатор ВОЗВРАЩАЕТСЯ, а не остаётся внутри: гашение обязано перевести
// готовность в отказ ДО остановки слушателей, а знает о гашении корень.
//
// kachoRepo / opsRepo / relationStore прокидываются из composition root
// (serve.go) — provision hook (Kratos user-provisioning, C4) строит
// UpsertFromIdentityUseCase из тех же зависимостей, что wiring.go, и
// переиспользует уже собранную дверь решения (не дублирует её).
func buildHooksMux(
	pool *pgxpool.Pool,
	kachoRepo kachorepo.Repository,
	opsRepo operations.Repo,
	relationStore clients.RelationStore,
	metricsReg *metrics.Registry,
	cfg config.Config,
	logger *slog.Logger,
) (http.Handler, *health.Aggregator) {
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
	saPort := &tokenEnrichSAAdapter{saClients: saClientRepo}

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
		// The SAME revocation adapter the refresh hook holds. Both hooks ask the
		// same question about the same row; one reader is what keeps the two
		// answers from drifting apart.
		revsPg,
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
	// duplicate decision door. rbac-contract-a-flat-fallout: ALSO wire the owner-
	// binding reconciler so the Kratos provision-hook signup path (the LIVE
	// signup path) forward-materializes the bootstrap owner's per-object content
	// access — parity with the gRPC InternalUserService wiring (wiring.go). Without
	// it the LIVE signup user is 403 on their own account's content until the sweep.
	provisionReconciler := reconcileapp.New(kachopg.NewReconcileAdapter(pool), logger)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kachoRepo, opsRepo).
		WithLogger(logger).
		WithReconciler(provisionReconciler).
		// ЖИВОЙ путь первого входа: именно здесь активируются приглашения на
		// настоящем трафике. Счётчик без этой провязки был бы всегда нулевым.
		WithActivationObserver(metricsReg.InviteActivationRecorder())
	provisionHook := handlerinternal.NewProvisionHookHandler(
		handlerinternal.ProvisionHookConfig{HookSharedSecret: hookSecret},
		&userProvisionAdapter{uc: userUpsert},
		logger,
	)

	// Recovery hook: завершение восстановления пароля. До этой проводки провайдер
	// бил в ЛЕГАСИ gRPC-порт с REST-подобным путём — тот же дефект, что чинили у
	// заведения пользователя: событие не доезжало никогда, а восстановивший
	// доступ оставался заблокированным, и прежние сессии переживали
	// восстановление. Use-case существовал всё это время; не хватало маршрута.
	recoveryUC := userapp.NewOnRecoveryCompletedUseCase(kachoRepo, opsRepo).WithLogger(logger)
	recoveryHook := handlerinternal.NewRecoveryHookHandler(
		handlerinternal.RecoveryHookConfig{HookSharedSecret: hookSecret},
		&userRecoveryAdapter{uc: recoveryUC},
		logger,
	)

	// Готовность СТРОИТСЯ из именованных зависимостей и отдаётся отдельным путём
	// от живости; чарт пробирует именно её. Что именно проверяет каждая — вопрос
	// композиционного корня: он один знает, чья это база и чей исполнитель
	// операций. Носитель — ОБЩИЙ, тот же, что у остальных шести сервисов.
	healthAgg := health.New([]health.Checker{
		{Name: "database", Check: pool.Ping},
		{Name: "lro-worker", Check: func(context.Context) error {
			if operations.Ready() {
				return nil
			}
			return errLROWorkerNotReady
		}},
	})

	mux := handlerinternal.NewMux(handlerinternal.Handlers{
		TokenHook:     tokenHook,
		RefreshHook:   refreshHook,
		ProvisionHook: provisionHook,
		RecoveryHook:  recoveryHook,
		Health:        healthAgg,
	})
	wrapped := handlerinternal.LoggerMiddleware(mux, func(method, path string, status int) {
		logger.Info("hooks http", "method", method, "path", path, "status", status)
	})
	return wrapped, healthAgg
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

// userRecoveryAdapter — узкий адаптер порта завершения восстановления. Тот же
// приём, что у заведения пользователя: транспорт не тянет типы бизнес-слоя, а
// composition root переводит DTO обработчика во вход use-case.
type userRecoveryAdapter struct {
	uc *userapp.OnRecoveryCompletedUseCase
}

func (a *userRecoveryAdapter) CompleteRecovery(ctx context.Context, in handlerinternal.RecoveryInput) error {
	_, err := a.uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID:  domain.ExternalSubject(in.ExternalID),
		RecoveryJTI: in.RecoveryJTI,
		Email:       domain.Email(in.Email),
	})
	return err
}

// tokenEnrichSAAdapter — pool-scoped read adapter for
// service.TokenEnrichmentSAPort. Every read it forwards belongs to the
// SAOAuthClient pool repo, which serves both the hydra_client_id reverse lookup
// and the ServiceAccount row behind it.
//
// The ServiceAccount read used to be a query written out here instead. Living
// in the composition root, it was reachable by no test, and it selected only
// the identity fields — so `enabled` arrived false for every account and the
// mint path could not have judged the state even if it had tried to.
type tokenEnrichSAAdapter struct {
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
	return a.saClients.GetServiceAccount(ctx, id)
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
