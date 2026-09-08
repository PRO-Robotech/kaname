// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"

	"github.com/PRO-Robotech/kacho/pkg/schemaguard"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// buildHooksMux — собирает HTTP mux для AuthN hooks и ВОЗВРАЩАЕТ носитель
// готовности вместе с ним.
//
// Носитель отдаётся наружу, а не остаётся внутри, ровно ради одного: гашение.
// `SetShuttingDown` переводит `/readyz` в 503 ДО остановки серверов, и знает о
// начале гашения только тот, кто его запускает (`serve.go`). Оставить носитель
// здесь значило бы иметь механизм и не иметь того, кто его дёрнет, — у шести
// соседних сервисов эта провязка есть, и её отсутствие было бы расхождением,
// которому нечем себя выдать (#1752).
//
// kanameRepo / opsRepo / relationStore прокидываются из composition root
// (serve.go) — provision hook (Kratos user-provisioning, C4) строит
// UpsertFromIdentityUseCase из тех же зависимостей, что wiring.go, и
// переиспользует уже собранную дверь решения (не дублирует её).
func buildHooksMux(
	pool *pgxpool.Pool,
	kanameRepo kanamerepo.Repository,
	opsRepo operations.Repo,
	relationStore clients.RelationStore,
	// catalogSource — каталожный факт из живых строк (задача #1816): ЖИВОЙ путь
	// первого входа материализует доступ тем же реконсайлером, что и gRPC-путь,
	// и обязан читать тот же каталог.
	catalogSource catalog.Source,
	metricsReg *metrics.Registry,
	cfg config.Config,
	logger *slog.Logger,
) (http.Handler, *health.Aggregator) {
	hookSecret := cfg.AuthN.ResolveHookSharedSecret()
	domain := cfg.AuthN.ResolveDomain()
	hydraIssuer := cfg.AuthN.ResolveHydraIssuer()

	// Repo adapters (pool-scoped).
	users := kanamepg.NewUserPoolRepo(pool)
	auditPg := kanamepg.NewAuditEmitterAdapter(pool)
	revsPg := kanamepg.NewSessionRevocationsAdapter(pool)

	// Adapter shims между port-iface'ами handler-слоя и repo-adapter'ами.
	auditAdapter := &handlerinternal.AuditAdapter{EmitFn: auditPg.Emit}

	saClientRepo := kanamepg.NewSAOAuthClientRepo(pool)
	saPort := &tokenEnrichSAAdapter{saClients: saClientRepo}

	// User-token principal mapping: минтованный из UserOAuthClient токен резолвится
	// в принципал `user:<id>` (net-new относительно SA-key → serviceAccount:<id>).
	userClientRepo := kanamepg.NewUserOAuthClientRepo(pool)
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
		// The SAME producer the token hook enriches with. One claim set per
		// principal, whichever lane asks for it.
		tokenEnricher,
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
	provisionReconciler := reconcileapp.New(kanamepg.NewReconcileAdapter(pool, catalogSource), logger, catalogSource)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kanameRepo, opsRepo).
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
	recoveryUC := userapp.NewOnRecoveryCompletedUseCase(kanameRepo, opsRepo).WithLogger(logger)
	recoveryHook := handlerinternal.NewRecoveryHookHandler(
		handlerinternal.RecoveryHookConfig{HookSharedSecret: hookSecret},
		&userRecoveryAdapter{uc: recoveryUC},
		logger,
	)

	// Готовность строит ОБЪЯВЛЕННЫЙ носитель (`pkg/observability/health`), а не
	// своя форма в handler-слое (#1752): срок на чекер, различение
	// «носитель не провязан»/«носитель ответил», перевод в 503 на гашении и
	// зеркало результата — свойства, которые он уже решил, и решать их второй
	// раз по месту значило бы завести расхождение, которому нечем себя выдать.
	//
	// ЧТО именно проверяется — по-прежнему решает композиционный корень: он один
	// знает, какая база своя и к кому сервис ходит.
	healthAgg := health.New([]health.Checker{
		{Name: "database", Check: pool.Ping},
		// ВЕРСИЯ СХЕМЫ — ОТДЕЛЬНАЯ ИМЕНОВАННАЯ ЗАВИСИМОСТЬ, а не часть
		// проверки базы. Мигратор идёт при каждом раскате, поэтому откат
		// выкатки ставит ПРЕЖНИЙ образ на НОВУЮ схему; база при этом
		// отвечает на `Ping`, и без этого чекера под объявлялся бы готовым и
		// получал трафик (`pkg/schemaguard`, задача #1734). Отдельное имя
		// обязательно: оператор обязан отличить «база недоступна» от «образ
		// не той версии, что схема», не читая кода.
		//
		// Набор миграций читается как встроенные байты, у базы спрашивается
		// ОДИН `SELECT` применённой версии — least-privilege serve-бинаря
		// сохраняется, схему он по-прежнему не меняет.
		{Name: schemaguard.CheckerName, Check: schemaguard.CheckFromFS(
			migrations.FS, schemaguard.PgxVersionReader(pool))},
		{Name: "lro-worker", Check: func(context.Context) error {
			if operations.Ready() {
				return nil
			}
			return errors.New("lro worker not ready")
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
	saClients *kanamepg.SAOAuthClientRepo
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
	userClients *kanamepg.UserOAuthClientRepo
	users       *kanamepg.UserPoolRepo
}

func (a *tokenEnrichUserTokenAdapter) LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.UserOAuthClient, error) {
	return a.userClients.GetByOAuthClientID(ctx, hydraClientID)
}

func (a *tokenEnrichUserTokenAdapter) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	return a.users.GetByID(ctx, id)
}
