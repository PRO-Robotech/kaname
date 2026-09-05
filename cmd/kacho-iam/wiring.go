// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wiring.go — composition-builder for the kacho-iam service bundle.
// Holds the `services` struct (single composition point), buildServices
// (per-resource handler wiring), and buildAuthZServices (AuthorizeService),
// and the small adapter types they need.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/access_binding"
	reconcileapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/account"
	authorizeapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/authorize"
	bootstraptoken "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/bootstrap_token"
	clusterapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/cluster"
	groupapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/group"
	identityquotaapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/identityquota"
	interactiveclientapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/interactive_client"
	internaliamapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/internal_iam"
	internaloperationsapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/internal_operations"
	limitapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/limit"
	membershipapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/membership"
	moduleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	permissioncatalogapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/permission_catalog"
	projectapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/project"
	roleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/role"
	sakeysapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/sa_keys"
	serviceaccountapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/service_account"
	sessionrevapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/session_revocations"
	userapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user"
	usertokensapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user_tokens"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/observability/metrics"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

// services — собранный набор бизнес-сервисов (один composition-point вместо
// россыпи локальных переменных в runServe). Заполняется buildServices,
// используется register{Public,Internal}Services.
type services struct {
	accountHandler        *accountapp.Handler
	projectHandler        *projectapp.Handler
	userHandler           *userapp.Handler
	internalUserHandler   *userapp.InternalHandler
	serviceAccountHandler *serviceaccountapp.Handler
	groupHandler          *groupapp.Handler
	// membershipHandler — MembershipService: чтение принадлежности человека
	// аккаунту. Регистрируется ТОЛЬКО на публичном слушателе — см. довод у
	// registerPublicServices.
	membershipHandler    *membershipapp.Handler
	roleHandler          *roleapp.Handler
	accessBindingHandler *accessbindingapp.Handler
	// internalIAMHandler — InternalIAMService (LookupSubject for the
	// api-gateway auth-interceptor; Check delegates to AuthorizeService).
	internalIAMHandler *internaliamapp.Handler

	// AuthZ core handlers.
	authorizeHandler *authorizeapp.Handler

	// permissionCatalogHandler — PermissionCatalogService.ListPermissionCatalog
	// (RBAC rules-model G): PUBLIC sync read of the backend-driven grantable
	// role-rule taxonomy. Platform metadata (not infra-sensitive — G-D3),
	// authenticated-floor; registered on the public listener.
	permissionCatalogHandler *permissioncatalogapp.Handler

	// SAKey handler — public.
	saKeysHandler *sakeysapp.Handler

	// UserToken handler — public (персональные access-токены пользователя).
	userTokensHandler *usertokensapp.Handler

	// internalClusterHandler — InternalClusterService: cluster admin
	// RBAC management. Internal-only (запрет #6), registered on port 9091.
	internalClusterHandler *clusterapp.Handler

	// interactiveClientHandler — InternalInteractiveClientService: lifecycle of
	// the OAuth2 client a HUMAN signs in through (IAM-INT-1). Internal-only.
	interactiveClientHandler *interactiveclientapp.Handler

	// moduleHandler — InternalModuleService: четыре глагола над строками
	// каталога прав ОДНОГО модуля (план, применение, два чтения). Internal-only
	// (запрет #6), регистрируется на :9091 и НИКОГДА на внешнем слушателе.
	//
	// Гейт права стоит в use-case первым стейтментом и является ЕДИНСТВЕННОЙ
	// авторизацией этой поверхности: ступень подтверждения личности к ней
	// сегодня не применяется — решение записано в приёмке, а не умолчание.
	moduleHandler *moduleapp.Handler

	// limitHandler — InternalLimitService: the ceiling on how many resources of
	// one kind a tenant may hold, plus the two reads owner-services live on
	// (Resolve / ListChangedSince). Internal-only (ban #6), registered on :9091.
	limitHandler *limitapp.Handler

	// limitPublicHandler — та же административная поверхность пределов на
	// ПУБЛИЧНОМ слушателе (ADM-1 S1, #878). Тонкий транспорт поверх УЖЕ
	// собранного `limitHandler`: не копия его зависимостей, а он сам, — поэтому
	// «оба пути делают одно» держится построением, а не совпадением сборки.
	limitPublicHandler *limitapp.PublicHandler

	// identityQuotaHandler — чтение квот, носителем которых является личность
	// (число аккаунтов). ТОЛЬКО чтение: величину назначает администратор облака.
	identityQuotaHandler *identityquotaapp.Handler

	// sessionRevocationsHandler — InternalSessionRevocationsService:
	// token revocation on logout / force-logout + the api-gateway
	// IsRevoked hot-path. Internal-only (запрет #6), registered on port 9091.
	sessionRevocationsHandler *sessionrevapp.Handler

	// internalOperationsHandler — InternalOperationsService.ListIamOperations:
	// cluster-wide admin feed of all IAM operations.
	// Internal-only (запрет #6), registered on port 9091; admin-tier gated
	// (system_admin@cluster ReBAC Check in-handler + gateway permission-catalog).
	internalOperationsHandler *internaloperationsapp.Handler

	// internalBootstrapTokenHandler — InternalBootstrapTokenService.MintBootstrapToken:
	// non-interactive bootstrap RS256 token mint (#58). Internal-only (ban #6),
	// registered on port 9091 ONLY, and reachable ONLY by a direct mTLS gRPC dial
	// (no REST route on the api-gateway — there it would be credential-free).
	// The gate is authzguard.CallerPolicy's explicit client-certificate SPIFFE
	// allow-list (authn.bootstrap-mint.allowed-client-sans); permission="<exempt>"
	// only means there is no ReBAC Check (no relation exists before the first
	// token), NOT that authN is waived.
	internalBootstrapTokenHandler *bootstraptoken.Handler

	// ownGates — ЗНАЧЕНИЕ, КОТОРОЕ ДЕРЖАТ СОБСТВЕННЫЕ СТРАЖИ iam: дверь решения
	// поверх реляционной формы.
	//
	// Выставлено наружу потому, что не все стражи собираются здесь. Потолок чтения
	// на внутреннем слушателе собирается в `runServe`, и ему до сих пор отдавали
	// ГОЛЫЙ транспорт — то есть решение о доступе на каждом читающем RPC
	// внутреннего слушателя уходило мимо двери. Снаружи это выглядело исправно:
	// страж есть, провязан, исполняется на каждом запросе.
	//
	// Пока у `runServe` не было доступа к этому значению, «отдать стражу
	// правильное» было невыполнимо — не из-за недосмотра, а из-за раскладки.
	// Поле закрывает именно это.
	ownGates *authzcascade.Client
}

// ownGateWiringComplaint reports why iam's own authorization gates cannot be trusted with
// this wiring, or "" when they can. The composition root turns a complaint into a refusal to
// start; it is a separate function so the refusal is testable — an os.Exit inside the builder
// can only be read, not exercised, and a guard nobody can exercise is one nobody knows works.
//
// Условие ОДНО, и оно осталось от четырёх не потому, что требования ослабли, а
// потому, что три из них были условиями ЧУЖОГО транспорта: второй шанс поверх
// доехавших очередью кортежей, страничное чтение структурных фактов и предъявление
// решения сравнению форм. Ни у одного из трёх больше нет предмета — решение
// принимает форма своей базой, и то, чем её дополняли, она читает первым же
// вопросом.
//
// Оставшееся условие — что двери есть чем отвечать. Дверь без формы отвечала бы
// ОШИБКОЙ на каждый вопрос, а не отказом (см. authzcascade.ErrFormNotWired), то
// есть служба поднялась бы и не отвечала бы ни на один вопрос о доступе. Отказ в
// старте называет это прямо: рантайм-диагностика оператору, который иначе не
// поймёт, почему поднявшаяся служба ничего не решает.
//
// NOT gated on the authentication mode. Every deployed stand runs production
// posture, and a guard absent from the stands where anyone would notice it firing is not a
// guard.
//
// The message names the knob and the consequence deliberately: it is what an operator sees
// when the stand will not come up, and a refusal that does not say what to fix cannot be
// acted on.
func ownGateWiringComplaint(store *authzcascade.Client) string {
	if !store.FormReachable() {
		return "источник вердикта о доступе не провязан: дверь решения собрана без " +
			"реляционной формы, и КАЖДЫЙ вопрос о доступе вернул бы ошибку, а не ответ " +
			"(проверьте строку подключения к базе службы прав)"
	}
	// Условия ПОЗИЦИИ РУБИЛЬНИКА здесь больше нет: рубильник переключал источник
	// вердикта потипово, пока источников было два. Источник один — переключать
	// нечего, и условие снято вместе со своим предметом, а не оставлено пустым.
	return ""
}

// buildServices создает все repo'ы поверх pool и собирает бизнес-сервисы.
// Composition root passes a fully-configured decision door — wiring
// of every per-resource use-case is unconditional (no fallback stub).
// opsRepo is the FULL corelib repo (operations.NewRepo), not the narrow
// operations.Repo: the cluster-admin use-cases finalize their Operation
// metadata on the terminal write (the grant id exists only after the mutation),
// and that capability must be proven at compile time, not type-asserted here.
func buildServices(pool, slavePool *pgxpool.Pool, opsRepo operations.FullRepo,
	kachoRepo kachorepo.Repository,
	// membershipRepo — УЗКИЙ корень чтения членства, приходящий ОТДЕЛЬНЫМ
	// параметром, а не выуживаемый приведением типа из соседнего.
	//
	// Причина названа у самого порта: расширить общий корень значило бы
	// потребовать нового метода от 46 дублёров в 25 файлах проб соседних
	// ресурсов. Приведение типа здесь было бы дешевле по строкам и хуже по
	// существу — оно превращает провязку в утверждение о том, какая реализация
	// пришла, и это утверждение проверялось бы в рантайме, а не сборкой.
	membershipRepo membershipapp.Repo,
	// catalogSource — КАТАЛОЖНЫЙ ФАКТ из ЖИВЫХ строк (задача #1816): какие пары
	// грантуемы и какие глаголы объявлены. Приходит отдельным параметром, а не
	// спрашивается у литерала внутри use-case'ов: ответ на него может измениться
	// в работающем процессе — снятием строки, — и читатель на литерале
	// продолжил бы считать снятый тип живым до следующего перезапуска.
	catalogSource catalog.Source,
	// catalogRows — ЧИТАТЕЛЬ строк каталога, тот же экземпляр, что прочитал их
	// страж паритета на старте. Приходит параметром, а не собирается здесь
	// заново: читатель живого множества в дереве ОДИН, и второй его экземпляр
	// был бы вторым местом об одном предмете — расходиться им нечем сегодня и
	// есть чем завтра.
	catalogRows moduleapp.CatalogStateSource,
	metricsReg *metrics.Registry,
	cfg config.Config, tokenSigner *tokensigner.Signer, logger *slog.Logger) *services {
	_ = slavePool // kachoRepo is built and passed in by main()

	// relationStore — ТО значение, которое получают собственные стражи iam, и
	// причина, по которой страж не может спросить «мимо»: другого значения для него
	// в корне нет.
	//
	// Форма собирается на ВЕДУЩЕМ пуле намеренно. Вопрос о доступе читает строки,
	// закоммиченные только что — выдачу, сделанную этим же запросом, — а это ровно
	// то, на чём отстаёт реплика: отзыв, действующий «с коммита», на реплике
	// действовал бы «с момента, когда доехало».
	verdictAsker := relverdict.NewAsker(pool)
	relationStore := authzcascade.Wrap(verdictAsker)
	// Разбор оснований выходит НАРУЖУ, а не копится в никуда.
	//
	// Форма считает две вещи, у которых нет иного признака: сколько раз доступ
	// выдан меточной ветвью (по каждой оси отдельно) и сколько отказов дано по
	// основанию «типа нет в словаре модели». Оба состояния, при которых что-то
	// сломано, снаружи выглядят как исправная работа: ось, переставшая
	// спрашиваться, не выдаёт прав по меткам, а опечатка в имени типа отбирает
	// доступ, — и то и другое арендатор читает как «прав не выдали».
	//
	// Провязка ЗДЕСЬ, у единственного места, где собран сам носитель. Величины
	// копились с тех пор, когда их читало теневое сравнение форм; сравнения
	// больше нет, а форма стала единственным источником вердикта — то есть
	// считаются они теперь на живом пути решения о доступе, и читателя у них не
	// было ни одного (#1224).
	//
	// Читается СНИМОК носителя, а не запомненное число: коллектор спрашивает
	// источник на каждом сборе.
	metricsReg.NewRelationVerdictGroundsCollector(func() metrics.RelationVerdictGrounds {
		mirror, iamDirect, earlyStops := verdictAsker.LabelArmGrounds()
		return metrics.RelationVerdictGrounds{
			LabelArmMirror:        mirror,
			LabelArmIAMDirect:     iamDirect,
			EarlyStops:            earlyStops,
			UndeclaredTypeDenials: verdictAsker.UndeclaredTypeDenials(),
		}
	})
	// Отказ в старте, а не надежда: дверь без формы отвечала бы ошибкой на каждый
	// вопрос о доступе, и служба была бы Ready, не решая ничего.
	//
	// NOT conditioned on the authentication mode: every deployed stand runs production
	// posture, and a guard absent from the stands where anyone would notice it firing is
	// not a guard.
	if complaint := ownGateWiringComplaint(relationStore); complaint != "" {
		logger.Error("refusing to start: " + complaint)
		os.Exit(1)
	}

	// rsabReconciler — the SINGLE per-object materialization engine (RBAC
	// explicit-model 2026 P4). Shared by AccessBinding.Create, the Role.Update
	// membership fan-out, AND the P6 Account.Create owner auto-binding
	// materialization (C-01/C-01b). Created once here so every consumer drives the
	// same instance.
	rsabReconciler := reconcileapp.New(kachopg.NewReconcileAdapter(pool, catalogSource), logger, catalogSource)
	if metricsReg != nil {
		// Размер материализации привязки — измерение, не потолок. Он ничего не
		// отвергает: величина, которой привязка может достичь, не измерена, а предел,
		// назначенный до замера, либо отвергнет законную выдачу, либо не отвергнет
		// ничего, оставаясь на вид контролем.
		rsabReconciler = rsabReconciler.WithSizeRecorder(metricsReg.NewBindingMaterializationRecorder())
	}

	// AccountService.
	accountCreate := accountapp.NewCreateAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	accountUpdate := accountapp.NewUpdateAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// A LABEL change flips iam-direct selector membership, so removing a label an
		// ARM_LABELS grant matches is a REVOCATION. The cross-service twin already gets
		// this: vpc/compute/nlb re-call RegisterResource on a label update and that runs
		// the object-forward in-process (its delete-stale guard hands an object with
		// existing members to the FULL recompute, which strips the stale tuples). Without
		// the same wiring here, the iam-native path had only the co-committed reconcile
		// event, so revoke latency became the depth of the FIFO reconcile queue —
		// measured 7m30s of queue plus a 65s sweep before the tuple died.
		WithObjectReconciler(rsabReconciler)
	accountDelete := accountapp.NewDeleteAccountUseCase(kachoRepo, opsRepo)
	accountGet := accountapp.NewGetAccountUseCase(kachoRepo).WithRelationStore(relationStore)
	// listScanRec — съём стоимости страницы для списков с добором (#653).
	// Один экземпляр на сборку: гистограммы размечены видом ресурса.
	listScanRec := metricsReg.NewListScanRecorder()

	accountList := accountapp.NewListAccountsUseCase(kachoRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	accountListAllOps := accountapp.NewListAllOperationsUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	accountHandler := accountapp.NewHandler(accountCreate, accountUpdate, accountDelete, accountGet, accountList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo)).
		WithListAllOperations(accountListAllOps)

	// ProjectService.
	projectCreate := projectapp.NewCreateProjectUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// rbac-contract-a-flat: synchronously materialize the owner's
		// per-object admin/v_* tuple on a freshly-created project (sync ReconcileObject
		// post-commit through the shared rsabReconciler's sync-FGA writer) so a GET right
		// after the Operation reports done does not race the async fga_outbox drain (403).
		WithObjectReconciler(rsabReconciler)
	projectUpdate := projectapp.NewUpdateProjectUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		// A LABEL change flips iam-direct selector membership, so removing a label an
		// ARM_LABELS grant matches is a REVOCATION. The cross-service twin already gets
		// this: vpc/compute/nlb re-call RegisterResource on a label update and that runs
		// the object-forward in-process (its delete-stale guard hands an object with
		// existing members to the FULL recompute, which strips the stale tuples). Without
		// the same wiring here, the iam-native path had only the co-committed reconcile
		// event, so revoke latency became the depth of the FIFO reconcile queue —
		// measured 7m30s of queue plus a 65s sweep before the tuple died.
		WithObjectReconciler(rsabReconciler)
	projectDelete := projectapp.NewDeleteProjectUseCase(kachoRepo, opsRepo)
	projectGet := projectapp.NewGetProjectUseCase(kachoRepo).WithRelationStore(relationStore)
	projectList := projectapp.NewListProjectsUseCase(kachoRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	projectHandler := projectapp.NewHandler(projectCreate, projectUpdate, projectDelete, projectGet, projectList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// UserService + InternalUserService.
	userGet := userapp.NewGetUserUseCase(kachoRepo).WithRelationStore(relationStore)
	userList := userapp.NewListUsersUseCase(kachoRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	userUpdate := userapp.NewUpdateUserUseCase(kachoRepo, opsRepo).
		// Same revoke-latency fix as accountUpdate above: iam.user is label-selectable,
		// so a label clear is a REVOCATION, and without the in-process object-forward it
		// waited out the FIFO reconcile queue (measured 7m30s + a 65s sweep) instead of
		// converging in-process the way the cross-service RegisterResource path does.
		WithObjectReconciler(rsabReconciler, logger)
	userDelete := userapp.NewDeleteUserUseCase(kachoRepo, opsRepo)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kachoRepo, opsRepo).
		WithLogger(logger).
		WithReconciler(rsabReconciler).
		WithActivationObserver(metricsReg.InviteActivationRecorder())
	userInvite := userapp.NewInviteUserUseCase(kachoRepo, opsRepo, relationStore).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	userOnRecovery := userapp.NewOnRecoveryCompletedUseCase(kachoRepo, opsRepo).
		WithLogger(logger)
	// Block/Unblock — административный запрет участию и его снятие. Два РАЗНЫХ
	// типа, поэтому перестановка их здесь — ошибка компиляции, а не контроль,
	// тихо ставший своей противоположностью.
	userBlock := userapp.NewBlockUserUseCase(kachoRepo, opsRepo)
	userUnblock := userapp.NewUnblockUserUseCase(kachoRepo, opsRepo)
	// Исключение из аккаунта — пара к приглашению: тот вводит человека в
	// аккаунт, этот выводит (#1127). Строку личности не трогает.
	userRemoveFromAccount := userapp.NewRemoveFromAccountUseCase(kachoRepo, opsRepo)
	userHandler := userapp.NewHandler(userGet, userList, userUpdate, userDelete, userInvite,
		userBlock, userUnblock, userRemoveFromAccount).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))
	internalUserHandler := userapp.NewInternalHandler(userUpsert, userGet, userOnRecovery)

	// ServiceAccountService.
	saCreate := serviceaccountapp.NewCreateServiceAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	saUpdate := serviceaccountapp.NewUpdateServiceAccountUseCase(kachoRepo, opsRepo).
		// Same revoke-latency fix as accountUpdate above: iam.serviceAccount is
		// label-selectable, so a label clear is a REVOCATION, and without the in-process
		// object-forward it waited out the FIFO reconcile queue (measured 7m30s + a 65s
		// sweep) instead of converging in-process the way the cross-service
		// RegisterResource path does.
		WithObjectReconciler(rsabReconciler, logger)
	saDelete := serviceaccountapp.NewDeleteServiceAccountUseCase(kachoRepo, opsRepo)
	saGet := serviceaccountapp.NewGetServiceAccountUseCase(kachoRepo).WithRelationStore(relationStore)
	saList := serviceaccountapp.NewListServiceAccountsUseCase(kachoRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	// Disable / Enable — the writers for the state that decides whether a service
	// account may authenticate. The state was read by the token hook, by key
	// issuance and by the docker-token validator long before anything could set
	// it; until these were wired, the only way to move it was a statement against
	// the database by hand.
	saDisable := serviceaccountapp.NewDisableServiceAccountUseCase(kachoRepo, opsRepo)
	saEnable := serviceaccountapp.NewEnableServiceAccountUseCase(kachoRepo, opsRepo)
	saHandler := serviceaccountapp.NewHandler(saCreate, saUpdate, saDelete, saGet, saList, saDisable, saEnable).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// GroupService.
	groupCreate := groupapp.NewCreateGroupUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	groupUpdate := groupapp.NewUpdateGroupUseCase(kachoRepo, opsRepo).
		// Same revoke-latency fix as accountUpdate above: iam.group is label-selectable,
		// so a label clear is a REVOCATION. Group.Update was the last path with NEITHER
		// half — no co-committed reconcile event and no in-process object-forward — so a
		// revoke converged only when the 30s periodic sweep happened to reach the binding.
		// The event (added in doUpdate) is the at-least-once backstop; this wiring adds the
		// accelerator the cross-service RegisterResource path runs in-process, without
		// which revoke latency is the depth of the FIFO reconcile queue (measured 7m30s).
		WithObjectReconciler(rsabReconciler, logger)
	groupDelete := groupapp.NewDeleteGroupUseCase(kachoRepo, opsRepo)
	groupGet := groupapp.NewGetGroupUseCase(kachoRepo).WithRelationStore(relationStore)
	groupList := groupapp.NewListGroupsUseCase(kachoRepo).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	groupAdd := groupapp.NewAddMemberUseCase(kachoRepo, opsRepo)
	groupRemove := groupapp.NewRemoveMemberUseCase(kachoRepo, opsRepo)
	// ListMembers names the group in the request, so it re-asks the model about
	// that group on `v_list` — the same relation the front door requires, and the
	// layer its two sibling reads already carry.
	groupListMembers := groupapp.NewListMembersUseCase(kachoRepo).WithRelationStore(relationStore)
	groupHandler := groupapp.NewHandler(groupCreate, groupUpdate, groupDelete, groupGet, groupList,
		groupAdd, groupRemove, groupListMembers).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// MembershipService — чтение членства на аккаунт-скоупных путях.
	//
	// Ни клиента модели прав, ни фильтра страницы здесь НЕТ, и это утверждение,
	// а не пропуск: единственный гейт этих чтений — пообъектная проверка КРАЯ по
	// аккаунту из пути, а строки отбираются тем же аккаунтом в условии запроса.
	// Провязать сюда второй замок значило бы заменить проверку края кодом,
	// который можно забыть в следующей ветке.
	membershipHandler := membershipapp.NewHandler(
		membershipapp.NewGetMembershipUseCase(membershipRepo),
		membershipapp.NewListMembershipsUseCase(membershipRepo),
	)

	// RoleService.
	roleCreate := roleapp.NewCreateRoleUseCase(kachoRepo, opsRepo, catalogSource).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	// Role.Update of an active role's permissions reconciles the FGA
	// tuples of every active binding of that role in the SAME writer-tx (atomic,
	// ban #10) via the access_binding RoleTupleReconciler (it owns the FGA
	// tuple-builder + the persisted emitted-tuple store). Without it a permission
	// downgrade left orphan FGA tuples = standing privilege.
	// The resource-scoped AccessBinding reconciler is
	// shared between AccessBinding.Create (post-commit selector materialization),
	// the serve.go worker (event drain + sweep + expiry), AND the Role.Update
	// membership fan-out (a rules change re-materializes the role.rules
	// ARM_LABELS membership of every active binding, eager-revoking removed rules by
	// rule_fp). One use-case over the pg ReconcileAdapter (Clean Architecture port).
	// NOTE: rsabReconciler is created once near the top of buildServices (shared
	// with the Account.Create owner auto-binding materialization).
	roleUpdate := roleapp.NewUpdateRoleUseCase(kachoRepo, opsRepo, catalogSource).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(kachoRepo, rsabReconciler)).
		// Same revoke-latency fix as accountUpdate above, for the role AS AN OBJECT
		// (iam.role is label-selectable, so clearing one of the ROLE's own labels is a
		// REVOCATION of access TO the role — orthogonal to the rules fan-out wired
		// above, which covers what the role GRANTS). Without the in-process
		// object-forward it waited out the FIFO reconcile queue (measured 7m30s + a 65s
		// sweep) instead of converging in-process the way the cross-service
		// RegisterResource path does.
		WithObjectReconciler(rsabReconciler, logger)
	roleDelete := roleapp.NewDeleteRoleUseCase(kachoRepo, opsRepo)
	// roleGet — D-1 fix: system roles are served to all (catalog floor, exempt);
	// CUSTOM roles enforce per-object via the SAME FGA v_list set as List
	// (read==enforce, D-45). relationStore is always non-nil, so a custom-role Get
	// fails closed on an FGA outage (Unavailable, D-47) — never a body leak.
	roleGet := roleapp.NewGetRoleUseCase(kachoRepo, catalogSource).WithRelationStore(relationStore)
	// roleList — per-object scope-filtered: the FGA v_list set on
	// iam_role is intersected with the catalog (system roles bypass). relationStore
	// is always non-nil, so List fails closed on an FGA outage (D-47).
	roleList := roleapp.NewListRolesUseCase(kachoRepo, catalogSource).WithRelationStore(relationStore).
		WithListScanRecorder(listScanRec)
	roleHandler := roleapp.NewHandler(roleCreate, roleUpdate, roleDelete, roleGet, roleList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// AccessBindingService. (rsabReconciler is created above — shared with the
	// Role.Update membership fan-out; the same instance drives Create + worker.)
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	// abDelete — relationStore drives the grant-authority gate, and ONLY that. The
	// post-commit tuple-removal it also used to drive is gone with the external store:
	// the in-tx EmitRelationDelete is now the whole mechanism, because a trigger folds
	// the journal row into the direct fact in the SAME commit. The deny is therefore
	// observable at Operation-done by construction, not by a second write racing it.
	abDelete := accessbindingapp.NewDeleteAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	// Revoke — F10 (IAM-1-28) SOFT-revoke (status ACTIVE→REVOKED, row retained for
	// audit-retention), contrast with Delete=HARD. Same grant-authority +
	// deletion_protection gate as Delete; same post-commit synchronous FGA
	// tuple-removal so deny is observable at Operation-done.
	abRevoke := accessbindingapp.NewRevokeAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger)
	// Update — P6 (C-03): clear deletion_protection so a protected binding can be
	// deleted. Same grant-authority gate as Create/Delete. WithObjectReconciler adds the
	// post-commit label re-materialization: iam.accessBinding is label-selectable, so
	// clearing a label an ARM_LABELS grant matches is a REVOCATION, and without an
	// in-process pass its latency is the depth of the FIFO reconcile queue (one worker,
	// ~5 events/s of FULL O(scope) recomputes — measured 7m30s enqueue→drain on the
	// sibling iam.project path). The co-committed reconcile event stays the backstop.
	abUpdate := accessbindingapp.NewUpdateAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	// D-6 (T3.3): the AB read RPCs union the existing self/granted floor with the
	// label-selector visibility (viewer ∪ v_list on iam_access_binding). relationStore
	// (the decision door) satisfies BOTH RelationStore (Check) and RelationQueries
	// (the contextual and paged forms); WithRelationQueries wires the per-object
	// visibility floor.
	abGet := accessbindingapp.NewGetAccessBindingUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	abListByScope := accessbindingapp.NewListByScopeUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// F11 (IAM-1-32): the unified List — viewer ∪ v_list push-down (same
	// RelationQueries floor as the other AB reads) PLUS the D-9 cluster-admin
	// super-gate (RelationStore), without which a cluster-admin — who holds no
	// per-object tuple on iam_access_binding — would get an empty page here while
	// every sibling read returns the full set.
	// Соседняя поверхность верхнего яруса супер-доступа читается ОТСЮДА ЖЕ
	// (#914, решение 2): выдают и отзывают кластерного администратора своим
	// глаголом, но спрашивающий «кто имеет доступ» обязан получать полный ответ
	// из ОДНОЙ точки чтения — иначе две поверхности об одном предмете расходятся
	// молча. Читатель тот же, что обслуживает `InternalClusterService.ListAdmins`:
	// второй завёл бы второй способ ответить на один вопрос.
	abList := accessbindingapp.NewListUseCase(kachoRepo).
		WithRelationStore(relationStore).
		WithRelationQueries(relationStore).
		WithClusterAdmins(kachopg.NewClusterAdminGrantReader(pool)).
		WithListScanRecorder(listScanRec)
	// ListBySubject — тот же вопрос, что и у ListSubjectPrivileges («какие выдачи
	// есть у этого субъекта»), поэтому и допуск у него ТОТ ЖЕ, единым предикатом
	// (#1352). Оба порта обязательны: RelationStore решает полосы надзора облака
	// и делегированного распорядителя, RelationQueries сужает СТРАНИЦУ полосы
	// распорядителя построчно (#1354). Непровязанный порт этим чтением
	// ОТКАЗЫВАЕТ — провязка здесь не удобство, а условие работоспособности полосы.
	abListBySub := accessbindingapp.NewListBySubjectUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	abListByAcc := accessbindingapp.NewListByAccountUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// ListSubjectPrivileges — enriched self|account-admin read.
	// RelationStore wired so the delegated-admin (FGA admin@account) authz path
	// resolves admins who are not the home-account owner (D-4 path b);
	// RelationQueries — пообъектный вопрос, которым СТРАНИЦА сужается по правам
	// вызывающего (#1354). Непровязанный порт этим чтением ОТКАЗЫВАЕТ, поэтому
	// провязка здесь — не удобство, а условие работоспособности полосы
	// распорядителя аккаунта.
	abListSubjPriv := accessbindingapp.NewListSubjectPrivilegesUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// ListAssignableRoles — roles valid to bind on a resource,
	// scope_group-annotated. Same grant-authority gate as ListByScope/Create
	// (RelationStore wired so the delegated-admin + cluster-scope authority paths
	// resolve).
	abListAssignable := accessbindingapp.NewListAssignableRolesUseCase(kachoRepo).
		WithRelationStore(relationStore, logger)
	// ListByRole audit (same grant-authority scope-filter as
	// the other List RPCs) + ExpandAccess effective-principal audit
	// (resolves group usersets via the door's ListSubjects).
	abListByRole := accessbindingapp.NewListByRoleUseCase(kachoRepo).
		WithRelationStore(relationStore, logger)
	// ExpandAccess: the decision door doubles as the userset expander (ListSubjects)
	// AND the RelationStore for the per-object grant-authority gate (В3 — a caller may
	// expand "who can do X" only on objects they are authorized to administer, the
	// SAME requireGrantAuthority predicate ListByScope/ListByRole enforce).
	abExpandAccess := accessbindingapp.NewExpandAccessUseCase(relationStore).
		WithGrantAuthority(kachoRepo, relationStore, logger)
	abHandler := accessbindingapp.NewHandler(abCreate, abDelete, abGet, abListByScope, abListBySub, abListByAcc,
		abListSubjPriv).
		WithUpdate(abUpdate).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo)).
		WithList(abList).
		WithListAssignableRoles(abListAssignable).
		WithListByRole(abListByRole).
		WithExpandAccess(abExpandAccess).
		WithRevoke(abRevoke)

	// ── AuthZ core wiring ─────────────────────────────────────────────────
	authzServices := buildAuthZServices(pool, opsRepo, kachoRepo, relationStore,
		metricsReg, cfg.AuthN.Mode.IsProduction(), logger)
	// InternalIAMService — LookupSubject (for the api-gateway
	// auth-interceptor) + Check (delegates to AuthorizeService.CheckRelation
	// — same FGA + OPA pipeline). Internal listener only, port 9091: never on
	// the external endpoint (ban #6). "gRPC-direct only" used to stand here and
	// is wrong — the api-gateway also exposes these two over REST on its
	// INTERNAL mux; internal-only is the invariant, gRPC-direct is not.
	lookupSubject := internaliamapp.NewLookupSubjectUseCase(kachoRepo)
	// SEC-C — FGA-proxy: RegisterResource / UnregisterResource enqueue the
	// owner-hierarchy tuple into kacho_iam.fga_outbox in one writer-tx, out of which
	// a trigger folds the direct fact in the same commit. Least-priv enforced via the
	// ReBAC gate (cert-cert→SA → fga_writer@cluster:cluster_kacho_root); the gate's
	// RelationChecker is the same Check surface (relationStore).
	// β (epic «Resource-scoped AccessBinding»): the same writer-tx also UPSERTs
	// /DELETEs the kacho_iam.resource_mirror row (labels + parent-scope of the
	// owner object) — atomic co-commit with the owner-tuple emit (ban #10 — D-β3).
	// γ (epic «Resource-scoped AccessBinding»): the SAME writer-tx also (D4)
	// backfills parent_account_id from projects.account_id same-DB and (Q1=(c))
	// enqueues a resource_reconcile_outbox event so the reconciler re-evaluates
	// affected selector/byName memberships — all atomic with the mirror UPSERT/
	// DELETE (ban #10).
	registerResourceUC := internaliamapp.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
		// Имя типа КАТАЛОГА читается у ЖИВОЙ строки, в транзакции записи зеркала
		// (kacho#1990). Параметр, а не опция: запасной путь «переводим словарём
		// сборки» молчалив — верный ответ на посеянных типах и неверный на
		// заведённых применением манифеста в работающем процессе.
		kachopg.NewCatalogTypeReader(),
	).
		WithReconcile(kachopg.NewReconcileEventEmitter()).
		WithAccountResolver(kachopg.NewProjectAccountResolver()).
		// Design-B instant-visibility (VBC-15): after the owner-tuple + mirror co-commit,
		// drive a SYNCHRONOUS ReconcileObject (shared rsabReconciler's sync-FGA writer) so
		// the creator's per-object v_get materializes before the consumer's create-Operation
		// reports done — a create→immediate-GET resolves ALLOW without racing the async
		// reconcile-outbox drain. nil-safe + non-fatal (the drain + sweep are the backstop).
		WithObjectReconciler(rsabReconciler, logger).
		// УКАЗАТЕЛЬ ОБЛАСТИ БОЛЬШЕ НЕ ПРИМЕНЯЕТСЯ ВТОРЫМ ПИСАТЕЛЕМ.
		//
		// Он применялся напрямую в чужое хранилище — в обе стороны, после коммита, —
		// потому что реконсайлер его не выводит, а значит никто другой не снял бы его
		// вовремя: ярус администратора аккаунта достаёт объекты ЧЕРЕЗ этот указатель, и
		// пережившее снятие ребро оставляло бы ему доступ к ресурсу, который уже
		// отвечает 404.
		//
		// Строка журнала, положенная той же транзакцией, делает то же самое и раньше:
		// прямой факт складывается из неё триггером в момент коммита. Догонять нечего.
		// A teardown must take away EVERY relationship this proxy could have written on
		// the object, not only the one the consumer was able to name. The consumer names
		// the scope pointer because that is all it holds; the creator's own `owner` was
		// written from an identity nobody stores afterwards, so the store is the only
		// side that can still name it. Without this reader that relationship outlived its
		// object silently — the withdrawal was emitted, delivered and marked sent with no
		// error, while the model went on deriving all five verbs from what it left behind.
		//
		// The bare transport is used deliberately: this needs the STRONG object listing,
		// and it must not travel the cascade wrapper, whose job is to widen answers to
		// questions rather than to enumerate what is physically there.
		WithResidualTupleReader(kachopg.NewResidualTupleReader(pool))
	// Both post-commit steps above are best-effort: they front a durable queue, so a
	// failure costs latency and never the change. That is what makes a permanently broken
	// one invisible — one WARN and a product that keeps working, slower, forever. The
	// recorder counts RUNS as well as FAILURES, so "never refused" stays distinguishable
	// from "never reached", and it labels WHICH materialization path each registration
	// took, so a regression back onto the EXCLUSIVE recompute is a visible shift between
	// two series instead of latency somebody has to notice. nil-safe: without a metrics
	// registry the steps still run and still log, they are just not counted.
	if metricsReg != nil {
		registerResourceUC = registerResourceUC.WithMetrics(metricsReg.NewRegisterPostCommitRecorder())
	}
	regGate := authzguard.NewRelationWriteGate(relationStore).
		WithProductionMode(cfg.AuthN.Mode.IsProduction())
	// Session-revocation writer. Pool-scoped adapter over
	// session_revocations — SHARED by ForceLogout (here), the
	// InternalSessionRevocationsService Revoke path, and the refresh-hook reader
	// (one table, one fan-out).
	sessionRevAdapter := kachopg.NewSessionRevocationsAdapter(pool)
	// Instrument the authz Check hot path at the adapter boundary (Clean
	// Architecture): the metrics decorator wraps the CheckRelation port the
	// InternalIAMService gate calls per-RPC (vpc/compute/nlb), recording the
	// kacho_iam_authz_check_* histogram + decision counter without the
	// AuthorizeService use-case importing prometheus. nil registry → plain
	// authorizer (metrics disabled).
	var checkAuthz internaliamapp.Authorizer = authzServices.authorizeSvc
	if metricsReg != nil {
		checkAuthz = metrics.NewInstrumentedAuthorizer(authzServices.authorizeSvc, metricsReg)
	}
	internalIAMHandler := internaliamapp.NewHandler(lookupSubject, checkAuthz).
		// PollSubjectChanges drains subject_change_outbox for api-gateway
		// authz-cache invalidation. Internal-only (port 9091).
		//
		// Журнал процесса адаптеру НАЗЫВАЕТСЯ, а не берётся умолчанием: чтение
		// идёт окном до границы устоявшегося, и удержание границы
		// незавершившимся писателем — единственное состояние, в котором край
		// молчит при живых событиях. Без жалобы в журнал процесса оно
		// неотличимо от «событий нет» (kacho#1374).
		WithSubjectChange(service.NewSubjectChangeService(
			kachopg.NewSubjectChangeRepo(pool, logger))).
		// SEC-C — FGA-proxy RPCs + ReBAC authz gate.
		WithResourceRegistrar(registerResourceUC, regGate).
		// #1142 — авторитет о предъявленном базовом секрете. Край зовёт его на
		// промахе своего кэша вердикта; отзыв доходит до предъявления тем, что
		// резолв не находит СНЯТОЙ строки.
		WithBasicCredentialResolver(kachopg.NewBasicCredentialRepo(pool)).
		WithLogger(logger).
		// ForceLogout records a session revocation.
		WithSessionRevoker(sessionRevAdapter).
		// ...and ENDS the session at the provider. The cutoff alone stops tokens
		// from being issued but leaves the browser holding a live session, which
		// then presents its original authentication instant forever and is
		// refused forever, with nothing prompting a re-login. Same lever the
		// self-service logout at the edge already pulls for its own caller.
		WithProviderSessions(
			mustProviderAdminClient(cfg),
			&forceLogoutSubjectResolver{users: kachopg.NewUserPoolRepo(pool)},
		).
		// ForceLogout returns an Operation — the row it names is persisted here,
		// before the cutoff is written and terminally after it, so the id the
		// admin gets back is queryable and the force-logout shows up in the
		// operation list like every other mutation.
		WithOperations(opsRepo).
		// Defense-in-depth ReBAC gate for ForceLogout (security.md "AuthN+AuthZ
		// ВЕЗДЕ"): require the authenticated principal hold system_admin@cluster.
		// relationStore satisfies authzguard.RelationChecker; nil-safe fail-closed.
		WithAdminChecker(relationStore).
		// F5 (IAM-1-13): GetRoleCompiled — Internal-only compiled-permission
		// projection (two-projection; public RoleService carries only rules[]).
		WithRoleCompiledReader(roleapp.NewGetRoleCompiledUseCase(kachoRepo))

	// ── InternalSessionRevocationsService ─────────────────────────────────
	// Revoke (logout / force-logout) + IsRevoked (api-gateway hot-path) +
	// ListByUser (admin audit). Shares the session_revocations table with the
	// refresh-hook reader. Internal-only (запрет #6).
	//
	// ListByUser answers about the user NAMED IN THE REQUEST, so it is authorized
	// against that user through the same relation store UserService.Get uses. The
	// listener's own gates narrow the calling MODULE and never read `user_id`;
	// unwired, the RPC serves nobody but the caller themselves.
	sessionRevocationsHandler := sessionrevapp.NewHandler(
		sessionrevapp.NewRevokeUseCase(sessionRevAdapter, opsRepo),
		sessionRevAdapter,
	).WithRelationStore(relationStore).
		// SessionCutoffOf — отсечка субъекта на полосу БРАУЗЕРНОЙ сессии края.
		// Читатель ТОТ ЖЕ, которым пользуются хуки выдачи: два ответа об одной
		// отсечке разошлись бы молча, и разошлись бы там, где расхождение
		// означает «выведен по одной полосе и работает по другой».
		WithCutoffReader(kachopg.NewUserTokenRevocationRepo(pool))

	// ── SAKey wiring (Class A static SA keys via Hydra) ───────────────────
	saKeysH := buildSAKeysHandler(pool, opsRepo, cfg, metricsReg.CompensationRecorder(), logger)

	// ── UserToken wiring (персональные access-токены пользователя via Hydra) ──
	userTokensH := buildUserTokensHandler(pool, opsRepo, cfg, logger)

	// ── InternalBootstrapTokenService — non-interactive bootstrap token mint (#58) ──
	// Чеканит НАШ подписант: дороги к внешнему поставщику на этом пути нет ни
	// одной (задача #1119). Сборка — bootstrap_token.go.
	bootstrapTokenH, bootstrapErr := buildBootstrapTokenHandler(pool, cfg, tokenSigner, logger)
	// Отказ построения здесь — «контур включён, а выпускать нечем». Это отказ в
	// СТАРТЕ, а не деградация: стенд, поднявшийся Ready с неработающей чеканкой
	// бутстрапа, сообщает о беде на первом запросе — то есть тогда, когда
	// кластер поднимают и чинить уже поздно.
	if bootstrapErr != nil {
		log.Fatalf("bootstrap-token mint: %v", bootstrapErr)
	}

	// ── InternalClusterService ────────────────────────────────────────────
	clusterReader := kachopg.NewClusterReader(pool)
	clusterGrantWriter := kachopg.NewClusterAdminGrantWriter(pool)
	clusterGrantReader := kachopg.NewClusterAdminGrantReader(pool)
	clusterRelEmitter := kachopg.NewFGAOutboxEmitter()
	clusterTxb := kachopg.NewPoolTxBeginner(pool)
	clusterSubjectState := kachopg.NewSubjectStateReader(pool)

	clusterGetUC := clusterapp.NewGetClusterUseCase(clusterReader)
	// Durable audit_outbox emitter — emits the
	// iam.cluster_admin.{granted,revoked} compliance row atomically inside the
	// grant/revoke writer-tx (запрет #10). Shared stateless adapter.
	clusterAuditEmitter := kachopg.NewAuditOutboxEmitter(pool)
	// Defense-in-depth ReBAC gate (security.md "AuthN+AuthZ ВЕЗДЕ"): the
	// highest-blast cluster-admin RPCs must run their OWN per-RPC system_admin
	// Check, not rely solely on the gateway caller-policy. relationStore
	// (the decision door) satisfies authzguard.RelationChecker. nil-safe
	// fail-closed inside the use-case if ever unwired.
	clusterGrantUC := clusterapp.NewGrantAdminUseCase(
		clusterGrantWriter, clusterGrantReader, clusterRelEmitter, clusterTxb, opsRepo,
	).WithSubjectStateReader(clusterSubjectState).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterRevokeUC := clusterapp.NewRevokeAdminUseCase(
		clusterGrantWriter, clusterRelEmitter, clusterTxb, opsRepo,
	).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterListUC := clusterapp.NewListAdminsUseCase(clusterGrantReader)
	internalClusterHandler := clusterapp.NewHandler(clusterGetUC, clusterGrantUC, clusterRevokeUC, clusterListUC)

	// ── InternalInteractiveClientService — interactive-login client (IAM-INT-1) ──
	// The audience stamped on every client this service registers is the EDGE's
	// audience — the same `https://{API_DOMAIN}` the bootstrap mint requests and
	// the gateway verifies. It is iam's decision, never a request field (Р2): a
	// caller-supplied audience can be set but cannot be set correctly, and a wrong
	// one is refused by the edge long after the client was created.
	interactiveAudience := os.Getenv("KACHO_IAM_INTERACTIVE_CLIENT_AUDIENCE")
	if interactiveAudience == "" {
		interactiveAudience = "https://" + cfg.AuthN.ResolveDomain()
	}
	interactiveRepo := kachopg.NewInteractiveClientRepo(pool)
	interactiveProvider := clients.NewInteractiveClientProvider(mustProviderAdminClient(cfg))
	interactiveClientHandler := interactiveclientapp.NewHandler(
		interactiveclientapp.NewGetUseCase(interactiveRepo),
		interactiveclientapp.NewListUseCase(interactiveRepo),
		// Компенсация полусделанной регистрации — durable намерение, прямое
		// снятие как запасной путь (см. buildSAKeysHandler).
		interactiveclientapp.NewCreateUseCase(interactiveRepo, interactiveProvider, opsRepo,
			[]string{interactiveAudience}, logger).
			WithCompensationEmitter(clients.NewProviderCompensationOutbox(pool).
				WithEmitObserver(metricsReg.CompensationRecorder())),
		interactiveclientapp.NewUpdateUseCase(interactiveRepo, opsRepo, logger),
		interactiveclientapp.NewDeleteUseCase(interactiveRepo, interactiveProvider, opsRepo, logger),
	)

	// ── InternalOperationsService — cluster-wide admin op feed ────────────────
	// security.md "AuthN+AuthZ ВЕЗДЕ": the in-handler ReBAC gate (relationStore
	// satisfies authzguard.RelationChecker) enforces system_admin@cluster even
	// when the caller bypasses the api-gateway and dials :9091 directly. nil-safe
	// fail-closed inside the use-case if ever unwired.
	internalOperationsUC := internaloperationsapp.NewListIamOperationsUseCase(opsRepo).
		WithAdminChecker(relationStore)
	internalOperationsHandler := internaloperationsapp.NewHandler(internalOperationsUC)

	// ── InternalLimitService — resource-count ceilings (issue #291, S1) ───────
	// Two audiences, two gates. The five CRUD verbs are admin surface and are
	// gated by the catalog (system_admin @ cluster) at the edge. Resolve /
	// ListChangedSince are dialled by the OWNER services that do the counting,
	// so they carry the narrow `quota_reader` relation instead — the same
	// least-privilege shape the fga-proxy authority uses, and NOT the cluster
	// read tier, which would hand an owner service the whole cluster-scoped read
	// surface to learn two numbers.
	//
	// The checker is wired here and nowhere else: an unwired gate fails CLOSED
	// inside the use-case, because an unauthorised read of the platform's
	// ceilings is not a lesser failure than an unauthorised write.
	limitRepo := kachopg.NewLimitRepo(pool)
	limitHandler := limitapp.NewHandler(
		limitapp.NewGetUseCase(limitRepo),
		limitapp.NewListUseCase(limitRepo),
		limitapp.NewCreateUseCase(limitRepo, opsRepo, logger),
		limitapp.NewUpdateUseCase(limitRepo, opsRepo, logger),
		limitapp.NewDeleteUseCase(limitRepo, opsRepo, logger),
		limitapp.NewResolveUseCase(limitRepo).WithQuotaReaderChecker(relationStore),
		limitapp.NewListChangedUseCase(limitRepo, limitRepo).WithQuotaReaderChecker(relationStore),
	)

	// ── IdentityQuotaService — квоты, носителем которых является ЛИЧНОСТЬ ──
	// Сегодня такой вид один — число аккаунтов, — и он единственный, чей носитель
	// не проект и не аккаунт: аккаунт есть корень аренды, и потолок над ним лежит
	// на том, что существует ДО него.
	//
	// Читается ТОЛЬКО о себе: поля запроса, которым можно было бы назвать чужую
	// личность, у контракта нет. Без этой поверхности потолок над аккаунтом
	// ограничивал бы невидимо — а самообслуживаемое создание аккаунта есть первое
	// действие, к которому платформа приглашает, и отказ на нём без объяснения
	// неотличим от поломки.
	identityQuotaHandler := identityquotaapp.NewHandler(kachopg.NewIdentityQuotaRepo(pool))

	// ── PermissionCatalogService — RBAC rules-model G public catalog ──
	// In-code projection (authzmap + domain): no repo, no peer-call. Stateless.
	permissionCatalogHandler := permissioncatalogapp.NewHandler(
		permissioncatalogapp.NewListPermissionCatalogUseCase(catalogSource))

	// ── InternalModuleService — каталог прав ОДНОГО модуля (задача #1034) ──
	//
	// Применитель здесь — ГЛАГОЛЬНЫЙ (`NewVerbApplier`), а не тот, которым
	// пользуется путь старта: он сверяет опору БЕЗУСЛОВНО и требует
	// подтверждения с обоими потолками. Различает их ТИП, а не флаг — подать
	// сюда стартовый нельзя, и это проверяет сборка.
	//
	// Производитель ПЛАНОВОГО состояния (отпечаток модуля и оценки последствий)
	// приходит отдельным портом. Непровязанный, он означает отказ `Plan`, и отказ
	// этот закрывает и `Apply`: подтверждения, которое тот требует, взять негде.
	//
	// Провязан он ЗДЕСЬ и над ТЕМ ЖЕ пулом, что писатель, — иначе отпечаток,
	// показанный планом, читался бы из другой базы, чем сверяет CAS применения.
	// Оценка последствий при этом идёт читающей транзакцией (`READ ONLY`), а её
	// предикаты — те же, что вставляет в свои операторы писатель.
	moduleApplier := modulecatalog.NewVerbApplier(kachopg.NewCatalogWriteRepo(pool))
	modulePlanState := kachopg.NewCatalogPlanRepo(pool)
	moduleDelivery := newManifestDeliverySource(cfg.Manifests)
	moduleHandler := moduleapp.NewHandler(
		moduleapp.NewPlanUseCase(moduleDelivery, catalogRows, modulePlanState).
			WithAdminChecker(relationStore),
		moduleapp.NewApplyUseCase(moduleDelivery, moduleApplier, opsRepo, logger).
			WithAdminChecker(relationStore),
		moduleapp.NewGetUseCase(catalogRows).WithAdminChecker(relationStore),
		moduleapp.NewListUseCase(catalogRows).WithAdminChecker(relationStore),
	)

	return &services{
		accountHandler:         accountHandler,
		projectHandler:         projectHandler,
		userHandler:            userHandler,
		internalUserHandler:    internalUserHandler,
		serviceAccountHandler:  saHandler,
		groupHandler:           groupHandler,
		membershipHandler:      membershipHandler,
		roleHandler:            roleHandler,
		accessBindingHandler:   abHandler,
		internalIAMHandler:     internalIAMHandler,
		internalClusterHandler: internalClusterHandler,

		// interactive-login client lifecycle.
		interactiveClientHandler: interactiveClientHandler,

		// каталог прав одного модуля — план, применение, два чтения.
		moduleHandler: moduleHandler,

		// resource-count ceilings (admin CRUD + owner-facing resolve/delta).
		limitHandler:       limitHandler,
		limitPublicHandler: limitapp.NewPublicHandler(limitHandler),

		// квоты личности — единственная поверхность, читаемая о себе самом.
		identityQuotaHandler: identityQuotaHandler,

		// token revocation (logout / force-logout).
		sessionRevocationsHandler: sessionRevocationsHandler,

		// cluster-wide admin operations feed.
		internalOperationsHandler: internalOperationsHandler,

		// non-interactive bootstrap token mint (#58).
		internalBootstrapTokenHandler: bootstrapTokenH,

		// AuthZ core.
		authorizeHandler: authzServices.authorize,

		// RBAC rules-model G — public grantable role-rule catalog.
		permissionCatalogHandler: permissionCatalogHandler,

		// SAKey (Class A static keys via Hydra).
		saKeysHandler: saKeysH,

		// UserToken (персональные access-токены пользователя via Hydra).
		userTokensHandler: userTokensH,

		// ЗНАЧЕНИЕ, которое держат стражи, собираемые в runServe.
		ownGates: relationStore,
	}
}

// mustProviderAdminClient builds the single client every provider-admin consumer
// in this process shares, resolving the hop's trust anchor once.
//
// Fatal on an unusable anchor, deliberately and at the composition root: the
// alternative — carrying on against the system root store — is the state nobody
// can see, because the operator has configured verification against the internal
// CA, the process is not doing it, and everything works until a certificate
// rotates. Config.Validate has already refused a production configuration that
// omits the anchor while addressing the hop over TLS; this catches the anchor
// that is named but unreadable, which only opening the file can tell.
func mustProviderAdminClient(cfg config.Config) *clients.HydraAdminClient {
	c, err := clients.NewHydraAdminClientWithCA(
		cfg.AuthN.ResolveHydraAdminURL(),
		// Читается ЧЕРЕЗ НАСТРОЙКУ, а не прямым обращением к окружению: ручка,
		// прочитанная здесь напрямую, невидима проверке настройки при старте, и
		// полосность посадки оказалась бы неполной ровно на неё (задача #1125).
		cfg.AuthN.ResolveHydraAdminToken(),
		cfg.AuthN.ResolveHydraAdminCAFile(),
	)
	if err != nil {
		log.Fatalf("provider-admin client: %v", err)
	}
	return c
}

// saKeyIssuanceIsOurs — переведён ли контур выдачи ключей служебных учёток на
// свою чеканку (задача #1120, подфаза Ф4б эпика #896).
//
// ПРЕДИКАТ — ЭНДПОИНТ ОБМЕНА, А НЕ ПОДПИСАНТ. Ключ служебной учётки предъявляет
// подписанное утверждение ВНЕШНИЙ вызывающий, и обменивает он его на нашем
// токен-эндпоинте. Подписант без эндпоинта дал бы ключ, которому некуда пойти:
// зеркала уже нет, а своей дороги ещё нет. Настройка при этом требует включённой
// чеканки от включённого эндпоинта (`ClientTokenConfig.Validate`), поэтому
// «эндпоинт включён» влечёт «подписант есть», а не наоборот.
//
// Отдельная функция, а не ветка внутри сборки: выбор полосы — утверждение о том,
// как посадка выдаёт удостоверение, и его надо уметь спросить, не собирая контур
// целиком (тот же довод, что у выбора полосы обмена докер-токена).
func saKeyIssuanceIsOurs(cfg config.Config) bool {
	// Само условие живёт в настройке (`Config.SAKeyIssuanceIsOurs`), а не здесь:
	// читателей у него два — эта сборка и страж старта над требованием
	// связанного токена (задача #1137), — и две копии одного условия разошлись
	// бы молча. Функция остаётся точкой, которую спрашивают, не собирая контур.
	return cfg.SAKeyIssuanceIsOurs()
}

// buildSAKeysHandler wires the SAKeyService handler — Class A static SA-keys
// via Hydra OAuth2 client_credentials.
func buildSAKeysHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config,
	compObs clients.CompensationEmitObserver, logger *slog.Logger) *sakeysapp.Handler {
	saClientRepo := kachopg.NewSAOAuthClientRepo(pool)

	hydraAdminURL := cfg.AuthN.ResolveHydraAdminURL()
	hydraAdmin := mustProviderAdminClient(cfg)

	// Durable audit_outbox emitter — emits iam.sa_key.issued /
	// iam.sa_key.revoked rows inside the SAKey worker-tx, atomic with the
	// key-mapping mutation (запрет #10). Payload carries no key material.
	auditEmitter := kachopg.NewAuditOutboxEmitter(pool)

	issueUC := sakeysapp.NewIssueSAKeyUseCase(saClientRepo, kachopg.NewPoolTxBeginner(pool), hydraAdmin, opsRepo)
	// Переведён ли контур выдачи ключей на свою чеканку (задача #1120). Решается
	// ЗДЕСЬ, в единственном месте сборки: «переведён» — свойство посадки, и
	// use-case его не выводит.
	ownIssuance := saKeyIssuanceIsOurs(cfg)
	if ownIssuance {
		issueUC.WithOwnIssuance()
	}
	// Always whitelist the configured registry service audience on every issued
	// SA-key's Hydra client (#320) — the SAME value the `/iam/token` Docker-
	// Registry shim requests during the client_credentials exchange
	// (serve.go passes it as registrytokenwire.BuildConfig.Service). Without it
	// Hydra rejects a docker-login exchange as an un-whitelisted audience.
	issueUC.RegistryAudience = cfg.APIServer.RegistryToken.TokenService()
	// Перечень доверенных издателей федеративного ключа — НАША таблица (#1124):
	// писатель провязан здесь, читает её проверка утверждения на пути запроса.
	issueUC.WithTrustedIssuerWriter(kachopg.NewTrustedIssuerRepo(pool))
	// Wire the post-Issue secret redactor. After the Operation is
	// MarkDone'd with plaintext client_secret, this pg adapter clears the
	// client_secret field in the proto-marshalled response_data (BYTEA) via a
	// single-statement UPDATE on the operations row. Idempotent.
	issueUC.WithResponseRedactor(kachopg.NewOpsResponseRedactor(pool, "kacho_iam"))
	issueUC.WithAuditEmitter(auditEmitter)
	// Grace-окно перед затиранием одноразового private_key_pem: поллящий клиент
	// (docker-login / CI / UI) должен успеть прочитать ключ из op.response до его
	// вычистки. Без окна затирание выигрывало гонку и клиент получал пустое поле.
	issueUC.WithRedactGrace(cfg.AuthN.SAKeyRedactGrace)
	// Lifetime discipline for the machine credential. A service-account key is
	// what a machine authenticates with, and machine principals are exempt from
	// step-up (a machine has no second factor) — that exemption holds only while
	// the credential itself is time-bounded. DefaultTTL replaces the old
	// "ttl_seconds omitted ⇒ never expires"; MaxTTL is the inclusive ceiling;
	// AccessTokenLifespan pins the per-client token TTL so minted tokens do not
	// inherit whatever the identity provider defaults to.
	issueUC.DefaultTTL = cfg.AuthN.SAKeyDefaultTTL
	issueUC.MaxTTL = cfg.AuthN.SAKeyMaxTTL
	issueUC.AccessTokenLifespan = cfg.AuthN.SAKeyAccessTokenTTL
	// Sender-constrained tokens for the machine credential. Issuance half of the
	// binding control; the gateway enforces the other half. Must be enabled
	// FIRST — enforcement without issuance can only reject.
	issueUC.BindDPoP = cfg.AuthN.SAKeyBindDPoP
	// Surface redaction failures (error / give-up / recovered panic) of the
	// detached redaction goroutine — the only place a key can stay un-redacted.
	issueUC.WithLogger(logger)
	// Durable-приёмник компенсирующих намерений. Клиент у провайдера создаётся ДО
	// коммита нашей строки (строка обязана нести назначенный провайдером
	// client_id), поэтому провал коммита обязан снять созданное. Прямой вызов
	// снятия остаётся ЗАПАСНЫМ путём: он сам может отказать, а процесс — умереть
	// между провалом и уборкой; durable намерение доставит дренаж.
	issueUC.WithCompensationEmitter(clients.NewProviderCompensationOutbox(pool).WithEmitObserver(compObs))
	revokeUC := sakeysapp.NewRevokeSAKeyUseCase(saClientRepo, kachopg.NewPoolTxBeginner(pool), hydraAdmin, opsRepo)
	revokeUC.WithAuditEmitter(auditEmitter)
	// Surface the post-commit Hydra orphan-cleanup warning (eventual-consistency).
	revokeUC.WithLogger(logger)
	listKeysUC := sakeysapp.NewListSAKeysUseCase(saClientRepo)

	// Посадка контура печатается ВСЕГДА, включая непереведённую: «зеркала больше
	// не заводим» иначе невидимо ниоткуда, а оператору, разбирающему выдачу, это
	// первое, что нужно знать — у ключа, выданного переведённым контуром, записи у
	// прежнего издателя нет и искать её негде.
	logger.Info("sa_keys wired",
		"hydra_admin", hydraAdminURL,
		"own_issuance", ownIssuance)

	return sakeysapp.NewHandler(issueUC, revokeUC, listKeysUC)
}

// buildUserTokensHandler wires the UserTokenService handler — персональные
// access-токены пользователя (поток private_key_jwt к НАШЕМУ издателю).
//
// Клиента у внешнего поставщика этот контур не заводит и не снимает (#1121),
// поэтому ни клиента администрирования поставщика, ни приёмника компенсирующих
// намерений здесь нет: компенсировать нечего — единственный след выдачи это своя
// строка, и она либо закоммичена, либо откачена.
func buildUserTokensHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config,
	logger *slog.Logger) *usertokensapp.Handler {
	userClientRepo := kachopg.NewUserOAuthClientRepo(pool)

	// Durable audit_outbox emitter — эмитит iam.user_token.{issued,revoked} строки
	// внутри worker-tx, атомарно с token-mapping-мутацией (запрет #10). Payload без
	// key material.
	auditEmitter := kachopg.NewAuditOutboxEmitter(pool)

	issueUC := usertokensapp.NewIssueUserTokenUseCase(userClientRepo, kachopg.NewPoolTxBeginner(pool), opsRepo)
	// Post-Issue секрет-редактор: после MarkDone с plaintext private_key_pem этот
	// pg-adapter затирает поле в proto-marshalled response_data (BYTEA) одним UPDATE.
	issueUC.WithResponseRedactor(kachopg.NewOpsResponseRedactor(pool, "kacho_iam"))
	issueUC.WithAuditEmitter(auditEmitter)
	// Grace-окно перед затиранием одноразового private_key_pem: поллящий клиент
	// (CLI/UI) должен успеть прочитать ключ из op.response до вычистки.
	issueUC.WithRedactGrace(cfg.AuthN.UserTokenRedactGrace)
	// Surface redaction-сбоев detached redaction-goroutine.
	issueUC.WithLogger(logger)
	revokeUC := usertokensapp.NewRevokeUserTokenUseCase(userClientRepo, kachopg.NewPoolTxBeginner(pool), opsRepo)
	revokeUC.WithAuditEmitter(auditEmitter)
	listUC := usertokensapp.NewListUserTokensUseCase(userClientRepo)

	logger.Info("user_tokens wired", "provider_client_registration", "none")

	return usertokensapp.NewHandler(issueUC, revokeUC, listUC)
}

// authzServiceBundle — handlers produced by buildAuthZServices.
type authzServiceBundle struct {
	authorize *authorizeapp.Handler
	// authorizeSvc — raw AuthorizeService use-case, exposed so the
	// InternalIAMService.Check gate can delegate to the SAME FGA pipeline.
	authorizeSvc *service.AuthorizeService
}

// buildAuthZServices собирает AuthorizeService поверх ДВЕРИ РЕШЕНИЯ.
//
// Значение одно, и это главное изменение снятия движка: край и собственные стражи
// спрашивают ОДИН объект. Прежде их было два — голый транспорт у края и обёрнутый
// у стражей, — и держались они порознь именно потому, что край добавлял к ответу
// движка то, чего обёртка не добавляла. Добавлять больше нечего: цепь областей и
// надзор администратора облака форма поднимает своим планом, поэтому «два ответа
// на один вопрос» перестало быть возможным by construction, а не по договорённости.
func buildAuthZServices(pool *pgxpool.Pool, opsRepo operations.Repo,
	kachoRepo kachorepo.Repository, ownGates *authzcascade.Client,
	metricsReg *metrics.Registry,
	prodMode bool, logger *slog.Logger) authzServiceBundle {
	_ = opsRepo // операции здесь больше не создаются: их создавал снятый писатель кортежей

	// ClusterAdminChecker — плоский надзор администратора облака. Он спрашивает о
	// типе `cluster`, то есть о ДРУГОМ объекте, чем тот, о котором идёт вопрос, —
	// поэтому потиповое переключение источника его и не захватывало. Теперь он
	// спрашивает ту же дверь: одна форма отвечает на оба вопроса.
	authSvc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           ownGates,
		ClusterAdminChecker: ownGates,
	})
	whoAmIUC := authorizeapp.NewWhoAmIUseCase(kachoRepo, ownGates)
	// WithCallerAuthority wires the caller-authority gate (a tenant principal may
	// only query authz decisions about itself, a resource it administers, or as a
	// cluster-admin). The SAME decision door answers the authority Check; a
	// verified module PDP peer passes through. This gate is not a second opinion
	// behind a narrower gateway check — the catalog entry these RPCs carry is
	// answered by every authenticated subject, so it is the only one there is.
	//
	// WithInsecureAnonymousPeer is the EXCEPTION for a stand without mTLS, where
	// the public and internal listeners cannot be told apart. Fail-closed is the
	// default; only a non-production AuthN mode opts out.
	// Полоса КРАЯ наблюдается ЗДЕСЬ, на границе адаптера: между транспортом
	// публичной службы и решателем встаёт декоратор, считающий вопросы края и
	// вопросы сужателя списочной выдачи. До него счётчик владельца прав видел
	// одну полосу из трёх, и всякое «проверок в секунду», снятое с него, было
	// занижено — на пути чтения по идентификатору ровно вдвое (задача #772).
	//
	// nil-реестр даёт неинструментированный решатель — ровно как у соседней
	// полосы `CheckRelation` выше по файлу.
	var edgeAuthz authorizeapp.Authorizer = authSvc
	if metricsReg != nil {
		edgeAuthz = metrics.NewInstrumentedSubjectAuthorizer(authSvc, metricsReg)
	}
	authzH := authorizeapp.NewHandler(edgeAuthz, whoAmIUC).
		WithCallerAuthority(ownGates).
		WithInsecureAnonymousPeer(!prodMode)

	return authzServiceBundle{
		authorize:    authzH,
		authorizeSvc: authSvc,
	}
}

// forceLogoutSubjectResolver names a kacho user to the identity provider.
//
// Composition-root shim: the use-case states what it needs (a `users.id` → the
// provider's subject) without taking a repository type. The provider keys its
// login sessions on the subject it issued, which is a different namespace from
// `users.id` — handing it the wrong one would delete nothing and report success.
type forceLogoutSubjectResolver struct {
	users *kachopg.UserPoolRepo
}

func (r *forceLogoutSubjectResolver) ExternalIDOf(ctx context.Context, id domain.UserID) (string, error) {
	u, err := r.users.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	return string(u.ExternalID), nil
}
