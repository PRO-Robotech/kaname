// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hooks_mux.go — HTTP mux composition for AuthN hooks listener.
// Hydra hooks (token + refresh), DPoP replay cache.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/servicecontract"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// buildHooksMux — собирает HTTP mux для AuthN hooks.
//
// Живости и готовности здесь больше нет (kaname#360): они на диагностической
// поверхности, которая есть при любой посадке, а этот mux собирается только
// там, где есть внешний поставщик (hooksLaneSurface).
//
// kanameRepo / opsRepo / bindingReconciler прокидываются из
// composition root (serve.go) — provision hook (Kratos user-provisioning, C4)
// строит UpsertFromIdentityUseCase из тех же зависимостей, что wiring.go, и
// переиспользует уже собранную дверь решения (не дублирует её).
//
// `relationStore` и `catalogSource` здесь БОЛЬШЕ НЕ ПРИНИМАЮТСЯ. Первый не читался
// уже на стволе — шапка обещала «FGA-tuple side-effects», которых на этой полосе
// нет; второй осиротел вместе с построением реконсайлера, снятым выше (#116).
// Параметр, который никто не читает, — объявление зависимости, которой нет:
// следующий провяжет его «как положено» и будет прав по форме и неправ по делу.
//
// Реконсайлер тоже ПРОКИДЫВАЕТСЯ, а не строится здесь, и это не единообразие
// ради единообразия: собранный здесь экземпляр не нёс приёмника размера, поэтому
// материализации живой полосы первого входа в гистограмму не попадали, а она
// выглядела полной (#116). Измерение, провязанное к одному из двух экземпляров,
// молчит о втором, и молчание это неотличимо от отсутствия трафика.
func buildHooksMux(
	pool *pgxpool.Pool,
	kanameRepo kanamerepo.Repository,
	opsRepo operations.Repo,
	// bindingReconciler — ТОТ ЖЕ экземпляр, что у пути запроса (`wiring.go`), а не
	// второй, собранный здесь. До #116 он собирался здесь и БЕЗ приёмника размера:
	// живая полоса первого входа материализовала привязки мимо гистограммы, и та
	// читалась как полная. Параметром, а не построением: второй экземпляр — это
	// решение о наблюдаемости, принятое побочным эффектом.
	bindingReconciler *reconcileapp.Reconciler,
	metricsReg *metrics.Registry,
	cfg config.Config,
	logger *slog.Logger,
) http.Handler {
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
	tokenHook, refreshHook := buildIssuanceHooks(issuanceHookConfig{
		hookSecret:  hookSecret,
		domain:      domain,
		hydraIssuer: hydraIssuer,
	}, issuanceHookPorts{
		users:    users,
		enricher: tokenEnricher,
		cutoffs:  revsPg,
		audit:    auditAdapter,
	}, logger)

	// Provision hook (C4): Kratos registration/login → UpsertFromIdentity.
	// Reuse the SAME repo/opsRepo/relationStore the gRPC InternalUserService
	// wiring uses (wiring.go) — same bootstrap + FGA-tuple side-effects, no
	// duplicate decision door. rbac-contract-a-flat-fallout: ALSO wire the owner-
	// binding reconciler so the Kratos provision-hook signup path (the LIVE
	// signup path) forward-materializes the bootstrap owner's per-object content
	// access — parity with the gRPC InternalUserService wiring (wiring.go). Without
	// it the LIVE signup user is 403 on their own account's content until the sweep.
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kanameRepo, opsRepo).
		WithLogger(logger).
		WithReconciler(bindingReconciler).
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

	mux := handlerinternal.NewMux(handlerinternal.Handlers{
		TokenHook:     tokenHook,
		RefreshHook:   refreshHook,
		ProvisionHook: provisionHook,
		RecoveryHook:  recoveryHook,
		// ИСХОД КАЖДОГО ОБРАЩЕНИЯ СТАНОВИТСЯ ВЕЛИЧИНОЙ (#2495). До этой провязки
		// живой путь входа человека не производил ни одной: «полоса отказывает»
		// и «поставщик не настроен звать хук» давали одинаково ненаблюдаемые
		// картины — в первом случае росли строки журнала, во втором их не было
		// вовсе, а отсутствие строк тревогой не бывает.
		//
		// Наборы приходят ИЗ ОБЪЯВЛЯЮЩЕГО ПАКЕТА: он один держит соответствие
		// пути и обработчика и разбор состояния ответа. Перевод делает корень —
		// единственное место, которое знает и полосу, и реестр величин.
		LaneObserver: metricsReg.AuthnHooksRecorder(
			handlerinternal.Routes(), handlerinternal.LaneOutcomes()),
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

// issuanceHookConfig — объявленная настройка обеих полос хука, чеканящих токен
// человеку. У полос она одна: секрет обратного вызова, домен и издатель.
type issuanceHookConfig struct {
	hookSecret  string
	domain      string
	hydraIssuer string
}

// issuanceHookPorts — готовые порты обеих полос хука, чеканящих токен человеку.
//
// Порты, а не пул: сборка полос обязана проверяться без базы, и проба сборки
// подаёт сюда своего читателя отсечки, чтобы увидеть, с чем его позвали.
type issuanceHookPorts struct {
	users    handlerinternal.UserLookupPort
	enricher *service.TokenEnrichmentService
	cutoffs  revocationpolicy.Lookup
	audit    handlerinternal.AuditEmitter
}

// buildIssuanceHooks собирает обе полосы хука, чеканящие токен человеку: хук
// выпуска и хук обновления.
//
// Одна сборка на обе полосы, а не две провязки рядом: читатель отсечки у них
// ОДИН экземпляр, и производитель состава утверждений — тоже один.
//
// Читатель отсечки оборачивается здесь ОДИН раз — той же обёрткой и тем же
// объявленным пределом на вызов, что у токен-эндпоинта
// ([revocationpolicy.WithDeadline], [credentialLanePeerTimeout]). Без неё
// чтение шло бы с контекстом запроса поставщика, у которого своего предела нет,
// и одно чтение одной строки несло бы разный предел на разных полосах. Предел
// закреплён пробой через эту сборку
// (`TestIssuanceHookLanesReadTheCutoffUnderTheDeclaredLimit`).
func buildIssuanceHooks(
	cfg issuanceHookConfig,
	ports issuanceHookPorts,
	logger *slog.Logger,
) (*handlerinternal.TokenHookHandler, *handlerinternal.RefreshHookHandler) {
	cutoffs := revocationpolicy.WithDeadline(ports.cutoffs, credentialLanePeerTimeout)
	tokenHook := handlerinternal.NewTokenHookHandler(
		handlerinternal.TokenHookConfig{
			HookSharedSecret: cfg.hookSecret,
			Domain:           cfg.domain,
			HydraIssuer:      cfg.hydraIssuer,
		},
		ports.enricher,
		cutoffs,
		ports.audit,
		logger,
	)
	refreshHook := handlerinternal.NewRefreshHookHandler(
		handlerinternal.RefreshHookConfig{
			HookSharedSecret: cfg.hookSecret,
			Domain:           cfg.domain,
			HydraIssuer:      cfg.hydraIssuer,
		},
		ports.users,
		// The SAME producer the token hook enriches with. One claim set per
		// principal, whichever lane asks for it.
		ports.enricher,
		cutoffs,
		ports.audit,
		logger,
	)
	return tokenHook, refreshHook
}

// hooksLaneSurface — профиль поверхности вебхуков провайдера личности.
//
// # Поднимается ПОСАДКОЙ (kaname#360)
//
// Хуки Hydra (token, refresh) и Kratos (provision, recovery) зовёт внешний
// поставщик, и только он. Под `authn.identity-provider=own` поставщика нет:
// полоса не собирается (build не зовётся), слушатель не поднимается, и ни
// один путь `/iam/v1/hooks/*` не отвечает. Отсутствие названо причиной в
// профиле поверхности — самоотчёт о подъёме отличает решение от недосмотра.
//
// Посадку судит ЕДИНСТВЕННЫЙ предикат (`HasExternalIdentityProvider`): им же
// корень решает дорогу к поставщику и запись зеркала его ключей. Держит
// `hooks_lane_posture_test.go`.
//
// build — сборка обработчика полосы; зовётся, только когда поверхность
// поднимается.
func hooksLaneSurface(cfg config.Config, mode servicecontract.Mode, logger *slog.Logger,
	tlsCfg *tls.Config, build func() http.Handler,
) (servicecontract.SurfaceDescriptor, error) {
	addr := hooksListenAddress(cfg)
	var handler http.Handler
	if cfg.AuthN.HasExternalIdentityProvider() {
		handler = build()
	}
	if handler == nil {
		tlsCfg = nil
	}
	return iamHTTPSurface(servicecontract.Surface{
		Name:   "вебхуки провайдера личности",
		Mode:   mode,
		Logger: logger,
		// Причина — ОДНА СТРОКА ЛИТЕРАЛОМ с именем ручки, как у полосы входа:
		// перечень поверхностей (`tools/surfaceroster`) выводит ключ адреса из
		// этой строки разбором, и причина, собранная переменной, выпала бы из
		// него молча вместе с маршрутом поверхности.
		Addr: addrAxis(addr, "вебхуки поставщика личности поднимаются только посадкой с внешним "+
			"поставщиком по адресу "+knobHooks+": под authn.identity-provider=own поставщика нет, и "+
			"хуки Hydra (token, refresh) и Kratos (provision, recovery) не собираются — вход, заведение "+
			"и восстановление человека исполняет полоса входа службы; при внешнем поставщике "+
			"незаданный адрес значит, что обогащение токена и заведение пользователя по первому "+
			"входу на этой посадке не обслуживаются"),
		Handler: handler,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.Value[servicecontract.SurfaceAuthMech](
			"общий секрет провайдера, проверяется обработчиком на каждом запросе"),
		TLS: tlsCfg,
	})
}

// hooksListenAddress — адрес, на котором корень ПОДНИМАЕТ слушатель вебхуков;
// пусто — не поднимает.
//
// Читателей два, и порознь они разошлись бы молча: построитель поверхности и
// страж транспорта HTTP-рёбер. Под `own` слушателя нет, и страж, получивший
// адрес из настройки, требовал бы TLS у двери, которой не будет, — посадка
// `own` без сертификата несуществующего слушателя не стартовала бы.
func hooksListenAddress(cfg config.Config) string {
	if !cfg.AuthN.HasExternalIdentityProvider() {
		return ""
	}
	return cfg.AuthN.HooksHTTPListenAddress()
}
