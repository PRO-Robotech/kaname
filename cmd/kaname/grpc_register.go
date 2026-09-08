// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// grpc_register.go — registration of gRPC handlers onto public / internal servers.
// Pure wiring: no business logic, no env reads.
package main

import (
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/operations/operationspb"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	quotav1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// registerPublicServices — публичные RPC + OperationService на внешний listener.
func registerPublicServices(srv grpc.ServiceRegistrar, svcs *services, opsRepo operations.Repo) {
	operationpb.RegisterOperationServiceServer(srv, operationspb.NewHandler(opsRepo))
	if svcs != nil && svcs.accountHandler != nil {
		iamv1.RegisterAccountServiceServer(srv, svcs.accountHandler)
	}
	if svcs != nil && svcs.projectHandler != nil {
		iamv1.RegisterProjectServiceServer(srv, svcs.projectHandler)
	}
	// Квоты личности. Регистрируется, ТОЛЬКО когда чтение собрано: иначе метод
	// отвечал бы пустым набором на каждый запрос — то есть «у вас нет пределов»,
	// ровно то утверждение, которое контракт запрещает делать.
	// Незарегистрированный метод отвечает `Unimplemented`, и это честно.
	if svcs != nil && svcs.identityQuotaHandler != nil {
		quotav1.RegisterIdentityQuotaServiceServer(srv, svcs.identityQuotaHandler)
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
	// MembershipService — чтение принадлежности человека аккаунту.
	//
	// ТОЛЬКО ЗДЕСЬ, и на внутренний слушатель НЕ едет. Довод решает сам по себе:
	// регистрация НЕДЕЛИМА ПО МЕТОДАМ — общий слой переписывает все методы
	// дескриптора, списка методов у вызывающего нет by construction. Значит
	// вынести туда нельзя ни один метод, не увезя всю службу; а на внутреннем
	// слушателе края нет, и единственный гейт этих чтений — пообъектная проверка
	// КРАЯ по аккаунту из пути — там не исполняется вовсе.
	//
	// Второй довод сильнее первого по последствиям: для службы, не внесённой ни
	// в один перечень внутренней цепочки, пол системного читателя не
	// применяется, пол уровня доверия тоже, а политика вызывающего пропускает
	// любой проверенный модуль — и анти-анонимного стража на той цепочке нет
	// вовсе, она спрашивает про сертификат, а не про принципала.
	//
	// Прецедент единственной публичной службы, дополнительно выставленной на
	// внутренний слушатель (AuthorizeService ниже), сюда НЕ переносится: её
	// методы принимают ЯВНОГО субъекта и отвечают из его вида, тогда как здесь
	// субъект вопроса — аккаунт из пути, и вид вызывающего в ответе не участвует.
	if svcs != nil && svcs.membershipHandler != nil {
		iamv1.RegisterMembershipServiceServer(srv, svcs.membershipHandler)
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
	// LimitService — административная поверхность пределов на ПУБЛИЧНОМ
	// слушателе (ADM-1 S1, #878).
	//
	// ЗАПРЕТ 6 НЕ СМЯГЧЁН: наружу выставлен публичный `LimitService`, а не
	// `InternalLimitService`. Переезжает ГЛАГОЛ, а не разрешение для внутреннего
	// сервиса, — тем же приёмом, каким ADM-1 S1 опубликовал поверхность пула
	// адресов. Доступ закрывает не место вызова, а отношение `system_admin` @
	// `cluster`, которое подстановочный кортеж `user:*` НЕ выполняет.
	//
	// ЧТО ЭТО ЧИНИТ: без публичного адреса страница пределов консоли получала
	// 404 — отказ, неотличимый от «такого раздела нет вовсе». Теперь отказ
	// честен: 403 у того, кому не положено, и 200 у администратора.
	if svcs != nil && svcs.limitPublicHandler != nil {
		iamv1.RegisterLimitServiceServer(srv, svcs.limitPublicHandler)
	}
}

// registerInternalServices — kacho-only/admin RPC на internal listener.
func registerInternalServices(srv grpc.ServiceRegistrar, svcs *services, pool *pgxpool.Pool, dsn string, logger *slog.Logger) {
	_ = pool
	_ = dsn
	_ = logger
	if svcs != nil && svcs.internalUserHandler != nil {
		iamv1.RegisterInternalUserServiceServer(srv, svcs.internalUserHandler)
	}
	if svcs != nil && svcs.internalIAMHandler != nil {
		iamv1.RegisterInternalIAMServiceServer(srv, svcs.internalIAMHandler)
	}
	// Служебных RPC администрирования хранилища отношений здесь больше нет: их
	// предметом было чужое хранилище — его кортежи, его модель, его store id, — и
	// вместе с ним снята вся служба.
	// AuthorizeService ALSO on the internal listener — RBAC rules-model consumer
	// list-filter edge. The SAME handler instance
	// already registered on the public listener (registerPublicServices) is
	// re-registered here so consumers (kacho-vpc / kacho-compute / kacho-nlb) can
	// call AuthorizeService.BatchCheck / Check over the verified-mTLS :9091
	// service→service edge they already reuse for InternalIAMService.Check —
	// instead of a separate public :9090 conn.
	//
	// Перечисления объектов в этом перечне больше нет: оно снято с контракта
	// стадией S6 (эпик #747). Сужение списка идёт пообъектной проверкой СТРАНИЦЫ,
	// прочитанной курсором из своей БД, — то есть тем самым `BatchCheck`, ради
	// которого ребро и держится.
	//
	// This does NOT violate ban #6: ban #6 forbids Internal.* methods on the
	// PUBLIC surface. The inverse — a PUBLIC service ADDITIONALLY exposed on the
	// cluster-internal :9091 — is the established service→service pattern (the
	// internal listener is not tenant-facing). The internal interceptor chain
	// (CallerPolicy floor: verified module cert required in prod; AuthorizeService
	// is NOT gateway-fronted, NOT in ReadFloorRPCs, NOT acr-floored) admits any
	// verified module SA. Запрос принимает ЯВНОГО субъекта и отвечает из его
	// авторизационного вида, so the caller-authz is "this module MAY query
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
	// InternalInteractiveClientService — lifecycle of the OAuth2 client a HUMAN
	// signs in through (IAM-INT-1). Internal-only (ban #6): NEVER registered on
	// the external listener. Gateway-fronted admin surface — the caller policy
	// admits only the api-gateway SA, the read floor covers Get/List, and the
	// catalog carries the step-up floor acr=2 on the three mutations.
	if svcs != nil && svcs.interactiveClientHandler != nil {
		iamv1.RegisterInternalInteractiveClientServiceServer(srv, svcs.interactiveClientHandler)
	}
	// InternalModuleService — четыре глагола над строками каталога прав ОДНОГО
	// модуля: план, применение, два чтения (задача #1034). Internal-only
	// (запрет #6): НИКОГДА не регистрируется на внешнем слушателе, и префикс
	// `Internal` в имени службы — действующий дискриминатор, а не привычка
	// именования.
	//
	// Гейт права стоит В ХЕНДЛЕРЕ, первым стейтментом каждого из четырёх
	// глаголов (`system_admin` на синглтоне `cluster`, fail-closed). Он и есть
	// ЕДИНСТВЕННАЯ авторизация этой поверхности: своего рубежа сверх
	// транспортного внутренний слушатель не несёт, а объявленная контрактом
	// ступень подтверждения личности к этим методам сегодня не применяется —
	// решение записано приёмкой, а не оставлено умолчанием. Поэтому регистрация
	// без гейта не существует ни в одном коммите: они внесены одним изменением.
	//
	// Краю служба не фронтится: REST-маршрута к ней нет и в этой под-фазе не
	// будет, поэтому в перечень методов, фронтящихся краем, она не вносится —
	// внесение дало бы поверхность, недостижимую ни для кого.
	if svcs != nil && svcs.moduleHandler != nil {
		iamv1.RegisterInternalModuleServiceServer(srv, svcs.moduleHandler)
	}
	// InternalLimitService — resource-count ceilings (issue #291). Internal-only
	// (ban #6): NEVER registered on the external listener. The five CRUD verbs are
	// gateway-fronted admin surface; Resolve / ListChangedSince are dialled
	// directly by owner services and carry the narrow `quota_reader` relation
	// both at the edge catalog and in-handler.
	if svcs != nil && svcs.limitHandler != nil {
		iamv1.RegisterInternalLimitServiceServer(srv, svcs.limitHandler)
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
	// (#58). Internal-only (ban #6): NEVER on the external listener, and NOT
	// fronted by the api-gateway at all (no REST route — there it would be
	// credential-free). The gate is the caller-policy's explicit
	// client-certificate SPIFFE allow-list
	// (authzguard.SANRestrictedInternalRPCs + authn.bootstrap-mint.allowed-client-sans),
	// not the listener boundary; permission="<exempt>" means only "no ReBAC Check
	// is possible before the first token exists".
	if svcs != nil && svcs.internalBootstrapTokenHandler != nil {
		iamv1.RegisterInternalBootstrapTokenServiceServer(srv, svcs.internalBootstrapTokenHandler)
	}
}
