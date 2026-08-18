// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	reconcileapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	authorizeapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/authorize"
	bootstraptoken "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/bootstrap_token"
	clusterapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/cluster"
	groupapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/group"
	identityquotaapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/identityquota"
	interactiveclientapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/interactive_client"
	internalauthorizeapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_authorize"
	internaliamapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam/shadowverdict"
	internaloperationsapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_operations"
	limitapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/limit"
	permissioncatalogapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/permission_catalog"
	projectapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/project"
	roleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/role"
	sakeysapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/sa_keys"
	serviceaccountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/service_account"
	sessionrevapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/session_revocations"
	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	usertokensapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user_tokens"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/bootstraptokenwire"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
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
	roleHandler           *roleapp.Handler
	accessBindingHandler  *accessbindingapp.Handler
	// internalIAMHandler — InternalIAMService (LookupSubject for the
	// api-gateway auth-interceptor; Check delegates to AuthorizeService).
	internalIAMHandler *internaliamapp.Handler

	// AuthZ core handlers.
	authorizeHandler         *authorizeapp.Handler
	internalAuthorizeHandler *internalauthorizeapp.Handler

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

	// limitHandler — InternalLimitService: the ceiling on how many resources of
	// one kind a tenant may hold, plus the two reads owner-services live on
	// (Resolve / ListChangedSince). Internal-only (ban #6), registered on :9091.
	limitHandler *limitapp.Handler

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

	// relationStore — shared OpenFGA client. Always non-nil: buildOpenFGAClient
	// returns a client whatever the environment holds.
	//
	// It is NOT a refusal to start. On an empty KACHO_IAM_OPENFGA_STORE_ID the
	// composition root logs a loud WARN and carries on, and the client then FAILS
	// CLOSED — Check denies, Read/Write return ErrNotConfigured (→ UNAVAILABLE).
	// That soft pass is deliberate and load-bearing: the store id is provisioned by
	// the openfga-bootstrap Job, a helm `post-install,post-upgrade` hook, which runs
	// only AFTER `helm upgrade --wait` sees the release Ready. An iam that refused to
	// start without the id would never become Ready, the hook would never run, and
	// the id would never be written — the first install would deadlock on itself.
	//
	// Said this plainly because the previous edition said the opposite ("composition
	// root fails fast on missing …STORE_ID"), and a security comment that contradicts
	// its code invites the next reader to "fix" the code to match it (#654).
	//
	// Reused by runServe for the fga_outbox drainer.
	relationStore *clients.OpenFGAHTTPClient

	// ownGates — ЗНАЧЕНИЕ, КОТОРОЕ ДЕРЖАТ СОБСТВЕННЫЕ СТРАЖИ iam: тот же клиент,
	// обёрнутый вторым шансом и предъявляющий каждое решение сравнению.
	//
	// Выставлено наружу потому, что не все стражи собираются здесь. Потолок
	// чтения на внутреннем слушателе собирается в `runServe`, и ему до сих пор
	// отдавали ГОЛЫЙ транспорт — то есть решение о доступе на каждом читающем
	// RPC внутреннего слушателя уходило движку и мимо второго шанса, и мимо
	// сравнения. Снаружи это выглядело исправно: страж есть, провязан,
	// исполняется на каждом запросе.
	//
	// Пока у `runServe` не было доступа к обёрнутому значению, «отдать стражу
	// правильное» было невыполнимо — не из-за недосмотра, а из-за раскладки.
	// Поле закрывает именно это.
	ownGates *authzcascade.Client
}

// ownGateWiringComplaint reports why iam's own authorization gates cannot be trusted with
// this wiring, or "" when they can. The composition root turns a complaint into a refusal to
// start; it is a separate function so the refusal is testable — an os.Exit inside the builder
// can only be read, not exercised, and a guard nobody can exercise is one nobody knows works.
//
// Neither condition is gated on the authentication mode. Every deployed stand runs production
// posture, and a guard absent from the stands where anyone would notice it firing is not a
// guard.
//
// The message names the knob and the consequence deliberately: it is what an operator sees
// when the stand will not come up, and a refusal that does not say what to fix cannot be
// acted on.
func ownGateWiringComplaint(store *authzcascade.Client, facts *authzcascade.Resolver) string {
	// The second chance is a CORRECTNESS condition: without it iam's own gates answer from
	// delivered relations only, and disagree with the gate the api-gateway asks about the
	// same subject and the same object.
	if !store.SecondChanceReachable() {
		return "iam's own authorization gates would answer from delivered relations only, " +
			"disagreeing with the gate the api-gateway asks (structural-fact resolver not " +
			"wired into the relation store)"
	}
	// The page read is a CONTRACT condition, and refusing to start over it is deliberate.
	// Without it the gates stay correct and every list filter resolves one object at a time —
	// measured at 200 primary transactions for a page of 100, while page size is part of the
	// contract up to 1000 and narrowing it to fit a budget is forbidden. That is a broken
	// contract at scale rather than a slow path, and it is invisible from outside until a
	// large page arrives. A control whose absence nobody can notice is not a control.
	if !facts.BatchReachable() {
		return "the structural page read is not wired, so every list filter would resolve " +
			"one object at a time and a contract-sized page would not fit its request budget"
	}
	// Сравнение — условие НАБЛЮДАЕМОСТИ, и отказ в старте по нему тоже намеренный.
	//
	// Без него ответы остаются прежними, поэтому пропажа ничем себя не выдаёт: обе
	// формы живы, решения принимает движок, а расхождение никем не считается. Ровно
	// в этом состоянии переключать источник вердикта потипово нельзя — страж чтения
	// спрашивает ТИПО-НЕЗАВИСИМО, и на первом же переключённом типе один вопрос
	// получил бы два действующих ответа. Провязка при этом выглядит исполненной:
	// значение собрано, стражам роздано, вызовы идут.
	if !store.ComparatorWired() {
		return "собственные стражи iam принимали бы решения о доступе, не предъявляя их " +
			"сравнению форм (сравнитель не провязан в значение, которое стражам выдаёт " +
			"композиционный корень): расхождение двух форм осталось бы несчитанным, и " +
			"переключать источник вердикта потипово в этом состоянии нельзя"
	}
	return ""
}

// buildServices создает все repo'ы поверх pool и собирает бизнес-сервисы.
// Composition root passes a fully-configured OpenFGA HTTP client — wiring
// of every per-resource use-case is unconditional (no fallback stub).
// opsRepo is the FULL corelib repo (operations.NewRepo), not the narrow
// operations.Repo: the cluster-admin use-cases finalize their Operation
// metadata on the terminal write (the grant id exists only after the mutation),
// and that capability must be proven at compile time, not type-asserted here.
func buildServices(pool, slavePool *pgxpool.Pool, opsRepo operations.FullRepo,
	kachoRepo kachorepo.Repository,
	fgaTransport *clients.OpenFGAHTTPClient,
	metricsReg *metrics.Registry,
	cfg config.Config, logger *slog.Logger) *services {
	_ = slavePool // kachoRepo is built and passed in by main()

	// structuralFacts — the facts the super-access cascade resolves over, read from iam's
	// OWN committed rows (internal/authzcascade). Built on a PRIMARY-ONLY repository,
	// deliberately: the rows it reads are ones that were just committed, which is exactly
	// what a replica lags on, so a replica read would swap one delivery pipeline for
	// another. WithBatch adds the page-shaped read of the same facts — measured, a page
	// that derives them one object at a time costs a transaction per object, and page size
	// is part of the contract up to 1000.
	structuralRepo := kachopg.NewStructuralFactsRepo(pool)
	structuralFacts := authzcascade.New(kachopg.New(pool, nil)).
		WithBatch(authzcascade.BatchSourceFunc(
			func(ctx context.Context) (authzcascade.StructuralSnapshot, error) {
				return structuralRepo.StructuralSnapshot(ctx)
			}))

	// relationStore — THE relation value iam's own gates receive, and the reason a gate
	// cannot ask the store without the second chance the edge gives: there is no other
	// value here to hand it. Everything below wires this; the bare transport is used only
	// where the subject of the question is DELIVERY itself (the boot verify gate) or where
	// a concrete field of the client is needed.
	// shadow — сравнитель форм. Собирается ЗДЕСЬ, до стражей, потому что его
	// держат ДВОЕ: край (`AuthorizeService`) и обёртка, через которую решения
	// принимают собственные стражи iam. Один экземпляр на обоих — иначе счётчики
	// разъедутся на два перечня об одном предмете, и доля сравнённого будет
	// считаться от разных знаменателей у края и у стражей.
	shadow := shadowverdict.New(relverdict.NewAsker(pool), logger)
	relationStore := authzcascade.Wrap(fgaTransport, structuralFacts).WithComparator(shadow)
	// Refuse to run gates that have silently gone back to waiting for a queue. Losing
	// either half of this in a refactor would put iam's own answers back out of step with
	// the edge's, and nothing else would say so.
	//
	// NOT conditioned on the authentication mode: every deployed stand runs production
	// posture, and a guard absent from the stands where anyone would notice it firing is
	// not a guard.
	if complaint := ownGateWiringComplaint(relationStore, structuralFacts); complaint != "" {
		logger.Error("refusing to start: " + complaint)
		os.Exit(1)
	}

	// rsabReconciler — the SINGLE per-object materialization engine (RBAC
	// explicit-model 2026 P4). Shared by AccessBinding.Create, the Role.Update
	// membership fan-out, AND the P6 Account.Create owner auto-binding
	// materialization (C-01/C-01b). Created once here so every consumer drives the
	// same instance.
	rsabReconciler := reconcileapp.New(kachopg.NewReconcileAdapter(pool), logger).
		// rbac-contract-a-flat-syncfga: wire the SYNCHRONOUS direct-FGA writer so the
		// create-path materialization applies the owner/creator per-object tuples to
		// OpenFGA right after the reconcile writer-tx commits — closing the
		// read-after-write race where a Check immediately after Operation-done would
		// otherwise miss the still-undrained fga_outbox tuple (403). The durable
		// fga_outbox enqueue + async drainer remain the at-least-once backstop (idempotent
		// re-apply). relationStore is always non-nil here — buildOpenFGAClient returns a
		// client whatever the environment holds; before the store id is provisioned that
		// client fails CLOSED rather than the process refusing to start (see the field's
		// doc on kachoServices).
		WithSyncFGA(kachopg.NewSyncFGAWriter(relationStore, logger))
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
	accountList := accountapp.NewListAccountsUseCase(kachoRepo).WithRelationStore(relationStore)
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
	projectList := projectapp.NewListProjectsUseCase(kachoRepo).WithRelationStore(relationStore)
	projectHandler := projectapp.NewHandler(projectCreate, projectUpdate, projectDelete, projectGet, projectList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// UserService + InternalUserService.
	userGet := userapp.NewGetUserUseCase(kachoRepo).WithRelationStore(relationStore)
	userList := userapp.NewListUsersUseCase(kachoRepo).WithRelationStore(relationStore)
	userUpdate := userapp.NewUpdateUserUseCase(kachoRepo, opsRepo).
		// Same revoke-latency fix as accountUpdate above: iam.user is label-selectable,
		// so a label clear is a REVOCATION, and without the in-process object-forward it
		// waited out the FIFO reconcile queue (measured 7m30s + a 65s sweep) instead of
		// converging in-process the way the cross-service RegisterResource path does.
		WithObjectReconciler(rsabReconciler, logger)
	userDelete := userapp.NewDeleteUserUseCase(kachoRepo, opsRepo)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
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
	userHandler := userapp.NewHandler(userGet, userList, userUpdate, userDelete, userInvite,
		userBlock, userUnblock).
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
	saList := serviceaccountapp.NewListServiceAccountsUseCase(kachoRepo).WithRelationStore(relationStore)
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
	groupList := groupapp.NewListGroupsUseCase(kachoRepo).WithRelationStore(relationStore)
	groupAdd := groupapp.NewAddMemberUseCase(kachoRepo, opsRepo)
	groupRemove := groupapp.NewRemoveMemberUseCase(kachoRepo, opsRepo)
	// ListMembers names the group in the request, so it re-asks the model about
	// that group on `v_list` — the same relation the front door requires, and the
	// layer its two sibling reads already carry.
	groupListMembers := groupapp.NewListMembersUseCase(kachoRepo).WithRelationStore(relationStore)
	groupHandler := groupapp.NewHandler(groupCreate, groupUpdate, groupDelete, groupGet, groupList,
		groupAdd, groupRemove, groupListMembers).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// RoleService.
	roleCreate := roleapp.NewCreateRoleUseCase(kachoRepo, opsRepo).
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
	roleUpdate := roleapp.NewUpdateRoleUseCase(kachoRepo, opsRepo).
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
	roleGet := roleapp.NewGetRoleUseCase(kachoRepo).WithRelationStore(relationStore)
	// roleList — per-object scope-filtered: the FGA v_list set on
	// iam_role is intersected with the catalog (system roles bypass). relationStore
	// is always non-nil, so List fails closed on an FGA outage (D-47).
	roleList := roleapp.NewListRolesUseCase(kachoRepo).WithRelationStore(relationStore)
	roleHandler := roleapp.NewHandler(roleCreate, roleUpdate, roleDelete, roleGet, roleList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// AccessBindingService. (rsabReconciler is created above — shared with the
	// Role.Update membership fan-out; the same instance drives Create + worker.)
	abCreate := accessbindingapp.NewCreateAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	// abDelete — relationStore drives BOTH the grant-authority gate AND the
	// synchronous post-commit tuple-removal: after the revoke writer-tx commits, the
	// persisted emitted-set is removed from OpenFGA via DeleteTuples so the deny is
	// observable at Operation-done (revoke ≈ grant latency — mirror of create's
	// post-commit FGA materialization). The in-tx EmitRelationDelete + fga_outbox
	// drainer remain the at-least-once idempotent backstop.
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
	// (the concrete OpenFGA client) satisfies BOTH RelationStore (Check) and
	// RelationQueries (ListObjects); WithRelationQueries wires the ListObjects floor.
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
	abList := accessbindingapp.NewListUseCase(kachoRepo).
		WithRelationStore(relationStore).
		WithRelationQueries(relationStore)
	abListBySub := accessbindingapp.NewListBySubjectUseCase(kachoRepo)
	abListByAcc := accessbindingapp.NewListByAccountUseCase(kachoRepo).
		WithRelationStore(relationStore, logger).
		WithRelationQueries(relationStore)
	// ListSubjectPrivileges — enriched self|account-admin read.
	// RelationStore wired so the delegated-admin (FGA admin@account) authz path
	// resolves admins who are not the home-account owner (D-4 path b).
	abListSubjPriv := accessbindingapp.NewListSubjectPrivilegesUseCase(kachoRepo).
		WithRelationStore(relationStore, logger)
	// ListAssignableRoles — roles valid to bind on a resource,
	// scope_group-annotated. Same grant-authority gate as ListByScope/Create
	// (RelationStore wired so the delegated-admin + cluster-scope authority paths
	// resolve).
	abListAssignable := accessbindingapp.NewListAssignableRolesUseCase(kachoRepo).
		WithRelationStore(relationStore, logger)
	// ListByRole audit (same grant-authority scope-filter as
	// the other List RPCs) + ExpandAccess effective-principal audit
	// (resolves group usersets via the OpenFGA client's ListSubjects).
	abListByRole := accessbindingapp.NewListByRoleUseCase(kachoRepo).
		WithRelationStore(relationStore, logger)
	// ExpandAccess: the OpenFGA client doubles as the userset expander (ListSubjects)
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
	authzServices := buildAuthZServices(pool, opsRepo, kachoRepo, fgaTransport, relationStore,
		structuralFacts, shadow, cfg.AuthN.Mode.IsProduction(), logger)
	// Читатель счётчиков теневого сравнения. Бандл выносит сравнитель наружу
	// именно ради этого: сравнение намеренно ни на что не влияет, и отсюда его
	// слепое пятно — сравнитель, которого не спросили ни разу, снаружи неотличим
	// от согласного. Поэтому наружу идёт и число решений, и число сравнений, а не
	// одни расхождения.
	//
	// Величины читаются У САМОГО сравнителя на каждом сборе: второй накопитель
	// рядом разошёлся бы с настоящим ровно там, где расхождение не видно, — оба
	// отвечают «ноль» на нулевом трафике.
	//
	// Проверка реестра — та же, что у двух провязок наблюдаемости ниже: подпись
	// функции nil допускает, хотя процесс всегда передаёт построенный реестр.
	// Ветка на гейт не влияет — он смотрит на вызов, а не на условие, под которым
	// тот стоит.
	//
	// Свойство «читатель есть» держит гейт по дереву
	// TestDeclaredAccumulatorsHaveANonTestReader: провязка наблюдаемости всюду
	// необязательна и nil-безопасна, поэтому её пропажу не поймает ни компилятор,
	// ни проба самого коллектора — она останется зелёной, считая в пустоту.
	if metricsReg != nil {
		metricsReg.NewShadowVerdictCollector(func() metrics.ShadowVerdictCounts {
			counts := authzServices.shadow.Counters()
			return metrics.ShadowVerdictCounts{
				Decisions:  counts.Decisions,
				Compared:   counts.Compared,
				Diverged:   counts.Diverged,
				Unfinished: counts.Unfinished,
			}
		})
	}

	// InternalIAMService — LookupSubject (for the api-gateway
	// auth-interceptor) + Check (delegates to AuthorizeService.CheckRelation
	// — same FGA + OPA pipeline). Internal listener only, port 9091: never on
	// the external endpoint (ban #6). "gRPC-direct only" used to stand here and
	// is wrong — the api-gateway also exposes these two over REST on its
	// INTERNAL mux; internal-only is the invariant, gRPC-direct is not.
	lookupSubject := internaliamapp.NewLookupSubjectUseCase(kachoRepo)
	// SEC-C — FGA-proxy: RegisterResource / UnregisterResource enqueue the
	// owner-hierarchy tuple into kacho_iam.fga_outbox in one writer-tx (drainer
	// applies it). Least-priv enforced via the ReBAC gate (cert-cert→SA →
	// fga_writer@iam_fgaproxy:system); the gate's RelationChecker is the same
	// OpenFGA Check surface (relationStore).
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
	).
		WithReconcile(kachopg.NewReconcileEventEmitter()).
		WithAccountResolver(kachopg.NewProjectAccountResolver()).
		// Design-B instant-visibility (VBC-15): after the owner-tuple + mirror co-commit,
		// drive a SYNCHRONOUS ReconcileObject (shared rsabReconciler's sync-FGA writer) so
		// the creator's per-object v_get materializes before the consumer's create-Operation
		// reports done — a create→immediate-GET resolves ALLOW without racing the async
		// reconcile-outbox drain. nil-safe + non-fatal (the drain + sweep are the backstop).
		WithObjectReconciler(rsabReconciler, logger).
		// The containment pointer (object→project) is the ONE tuple this use-case owns
		// outright: the reconciler never derives it, so nothing else can remove it
		// promptly. Applying it directly here — in BOTH directions, after the commit —
		// is what keeps a withdrawal from leaving the account-administrator tier with
		// standing access to a resource that already answers 404, since that tier
		// reaches objects THROUGH the pointer rather than through any per-object grant.
		// nil-safe + non-fatal: the durable outbox drain remains the backstop.
		WithTupleApplier(clients.NewHierarchyTupleApplier(relationStore), logger).
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
		WithResidualTupleReader(clients.NewResidualTupleReader(fgaTransport))
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
		WithSubjectChange(service.NewSubjectChangeService(kachopg.NewSubjectChangeRepo(pool))).
		// WriteCreatorTuple — sync FGA write для
		// per-resource creator-tuple (vpc/compute/nlb после Create).
		// Local relationStore (line ~522) is in scope here within buildServices.
		WithRelationWriter(relationStore).
		// SEC-C — FGA-proxy RPCs + ReBAC authz gate.
		WithResourceRegistrar(registerResourceUC, regGate).
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
	).WithRelationStore(relationStore)

	// ── SAKey wiring (Class A static SA keys via Hydra) ───────────────────
	saKeysH := buildSAKeysHandler(pool, opsRepo, cfg, metricsReg.CompensationRecorder(), logger)

	// ── UserToken wiring (персональные access-токены пользователя via Hydra) ──
	userTokensH := buildUserTokensHandler(pool, opsRepo, cfg, metricsReg.CompensationRecorder(), logger)

	// ── InternalBootstrapTokenService — non-interactive bootstrap token mint (#58) ──
	// The requested token audience is the gateway audience (https://{API_DOMAIN});
	// override via KACHO_IAM_BOOTSTRAP_TOKEN_AUDIENCE, else derived from the domain.
	bootstrapAudience := os.Getenv("KACHO_IAM_BOOTSTRAP_TOKEN_AUDIENCE")
	if bootstrapAudience == "" {
		bootstrapAudience = "https://" + cfg.AuthN.ResolveDomain()
	}
	// SigningKeyPEM comes from authn.bootstrap-mint.signing-key-env (default
	// KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM) — the SAME accessor Config.Validate
	// uses to decide whether the mint is enabled, so the boot-guard and the
	// runtime can never disagree about it. Empty → mint disabled (fail-closed).
	bootstrapTokenH, bootstrapErr := bootstraptokenwire.Build(pool, bootstraptokenwire.BuildConfig{
		SigningKeyPEM:     cfg.AuthN.BootstrapMint.ResolveSigningKeyPEM(),
		HydraAdmin:        mustProviderAdminClient(cfg),
		HydraTokenURL:     cfg.AuthN.ResolveHydraTokenURL(),
		HydraTokenCAFile:  cfg.AuthN.ResolveHydraTokenCAFile(),
		AssertionAudience: cfg.AuthN.ResolveHydraTokenEndpoint(),
		GatewayAudience:   bootstrapAudience,
		Logger:            logger,
	})
	// Same reasoning as mustProviderAdminClient: an anchor that is named but
	// unreadable is only discoverable by opening the file, and carrying on against
	// the system root store is the state nobody can see.
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
	// (*clients.OpenFGAHTTPClient) satisfies authzguard.RelationChecker. nil-safe
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
		permissioncatalogapp.NewListPermissionCatalogUseCase())

	return &services{
		accountHandler:         accountHandler,
		projectHandler:         projectHandler,
		userHandler:            userHandler,
		internalUserHandler:    internalUserHandler,
		serviceAccountHandler:  saHandler,
		groupHandler:           groupHandler,
		roleHandler:            roleHandler,
		accessBindingHandler:   abHandler,
		internalIAMHandler:     internalIAMHandler,
		internalClusterHandler: internalClusterHandler,

		// interactive-login client lifecycle.
		interactiveClientHandler: interactiveClientHandler,

		// resource-count ceilings (admin CRUD + owner-facing resolve/delta).
		limitHandler: limitHandler,

		// квоты личности — единственная поверхность, читаемая о себе самом.
		identityQuotaHandler: identityQuotaHandler,

		// token revocation (logout / force-logout).
		sessionRevocationsHandler: sessionRevocationsHandler,

		// cluster-wide admin operations feed.
		internalOperationsHandler: internalOperationsHandler,

		// non-interactive bootstrap token mint (#58).
		internalBootstrapTokenHandler: bootstrapTokenH,

		// AuthZ core.
		authorizeHandler:         authzServices.authorize,
		internalAuthorizeHandler: authzServices.internalAuthorize,

		// RBAC rules-model G — public grantable role-rule catalog.
		permissionCatalogHandler: permissionCatalogHandler,

		// SAKey (Class A static keys via Hydra).
		saKeysHandler: saKeysH,

		// UserToken (персональные access-токены пользователя via Hydra).
		userTokensHandler: userTokensH,

		// Expose the TRANSPORT so runServe can reuse the same instance for the
		// fga_outbox drainer wiring. The drainer writes tuples; it asks no
		// authorization question, so it has nothing to gain from the wrapper.
		relationStore: fgaTransport,

		// И ОТДЕЛЬНО — обёрнутое значение для тех стражей, что собираются в
		// runServe. Два поля рядом намеренно: разница между ними и есть разница
		// между «пишет кортежи» и «принимает решение о доступе», и выбор между
		// ними перестаёт быть догадкой на месте вызова.
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
		os.Getenv("KACHO_IAM_HYDRA_ADMIN_TOKEN"),
		cfg.AuthN.ResolveHydraAdminCAFile(),
	)
	if err != nil {
		log.Fatalf("provider-admin client: %v", err)
	}
	return c
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
	// Always whitelist the configured registry service audience on every issued
	// SA-key's Hydra client (#320) — the SAME value the `/iam/token` Docker-
	// Registry shim requests during the client_credentials exchange
	// (serve.go passes it as registrytokenwire.BuildConfig.Service). Without it
	// Hydra rejects a docker-login exchange as an un-whitelisted audience.
	issueUC.RegistryAudience = cfg.APIServer.RegistryToken.TokenService()
	// Register exact-subject jwt-bearer trust-grants for federated (k8s/CI) keys —
	// the same Hydra admin client carries the trust-grant endpoint.
	issueUC.WithTrustGrantAdmin(hydraAdmin)
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

	logger.Info("sa_keys wired", "hydra_admin", hydraAdminURL)

	return sakeysapp.NewHandler(issueUC, revokeUC, listKeysUC)
}

// buildUserTokensHandler wires the UserTokenService handler — персональные
// access-токены пользователя via Hydra OAuth2 client_credentials + private_key_jwt.
// Зеркалит buildSAKeysHandler, подставляя User вместо ServiceAccount.
func buildUserTokensHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config,
	compObs clients.CompensationEmitObserver, logger *slog.Logger) *usertokensapp.Handler {
	userClientRepo := kachopg.NewUserOAuthClientRepo(pool)

	hydraAdminURL := cfg.AuthN.ResolveHydraAdminURL()
	hydraAdmin := mustProviderAdminClient(cfg)

	// Durable audit_outbox emitter — эмитит iam.user_token.{issued,revoked} строки
	// внутри worker-tx, атомарно с token-mapping-мутацией (запрет #10). Payload без
	// key material.
	auditEmitter := kachopg.NewAuditOutboxEmitter(pool)

	issueUC := usertokensapp.NewIssueUserTokenUseCase(userClientRepo, kachopg.NewPoolTxBeginner(pool), hydraAdmin, opsRepo)
	// Post-Issue секрет-редактор: после MarkDone с plaintext private_key_pem этот
	// pg-adapter затирает поле в proto-marshalled response_data (BYTEA) одним UPDATE.
	issueUC.WithResponseRedactor(kachopg.NewOpsResponseRedactor(pool, "kacho_iam"))
	issueUC.WithAuditEmitter(auditEmitter)
	// Grace-окно перед затиранием одноразового private_key_pem: поллящий клиент
	// (CLI/UI) должен успеть прочитать ключ из op.response до вычистки.
	issueUC.WithRedactGrace(cfg.AuthN.UserTokenRedactGrace)
	// Surface redaction-сбоев detached redaction-goroutine.
	issueUC.WithLogger(logger)
	// Durable-приёмник компенсирующих намерений — см. buildSAKeysHandler:
	// та же сага, тот же провайдер, тот же повод.
	issueUC.WithCompensationEmitter(clients.NewProviderCompensationOutbox(pool).WithEmitObserver(compObs))
	revokeUC := usertokensapp.NewRevokeUserTokenUseCase(userClientRepo, kachopg.NewPoolTxBeginner(pool), hydraAdmin, opsRepo)
	revokeUC.WithAuditEmitter(auditEmitter)
	// Surface the post-commit Hydra orphan-cleanup warning (eventual-consistency).
	revokeUC.WithLogger(logger)
	listUC := usertokensapp.NewListUserTokensUseCase(userClientRepo)

	logger.Info("user_tokens wired", "hydra_admin", hydraAdminURL)

	return usertokensapp.NewHandler(issueUC, revokeUC, listUC)
}

// authzServiceBundle — handlers produced by buildAuthZServices.
type authzServiceBundle struct {
	authorize         *authorizeapp.Handler
	internalAuthorize *internalauthorizeapp.Handler
	// authorizeSvc — raw AuthorizeService use-case, exposed so the
	// InternalIAMService.Check gate can delegate to the SAME FGA pipeline.
	authorizeSvc *service.AuthorizeService
	// shadow — сравнитель форм, провязанный в тот же use-case. Вынесен наружу,
	// чтобы у его счётчиков был читатель: «ноль расхождений» без числа решений и
	// доли сравнённых — утверждение ни о чём.
	shadow *shadowverdict.Comparator
}

// buildAuthZServices wires AuthorizeService + InternalAuthorizeService against a
// fully-configured OpenFGA HTTP client.
//
// The FGA model is the sole policy gate: AuthorizeService does not evaluate any
// additional guardrail overlay after the FGA Check.
// fgaTransport is the bare client; ownGates is the value iam's own gates hold (the same
// client, wrapped so a denied question gets the second chance the edge gives). Both are
// passed rather than one derived here: AuthorizeService gives that second chance ITSELF and
// asks the cheap flat cluster super-gate first, so routing it through the wrapper would make
// a cloud administrator pay a structural read before the gate that was going to admit him.
// The two must nevertheless never disagree, which is asserted on the observable answer in
// service/own_gates_agree_with_edge_integration_test.go.
func buildAuthZServices(pool *pgxpool.Pool, opsRepo operations.Repo,
	kachoRepo kachorepo.Repository, fgaTransport *clients.OpenFGAHTTPClient,
	ownGates *authzcascade.Client, structuralFacts *authzcascade.Resolver,
	shadow *shadowverdict.Comparator,
	prodMode bool, logger *slog.Logger) authzServiceBundle {
	modelID := fgaTransport.AuthorizationModel
	logger.Info("openfga extended client wired for AuthZ",
		"endpoint", fgaTransport.Endpoint, "store_id", fgaTransport.StoreID, "model_id", modelID)

	// AuthorizeService use-case. ClusterAdminChecker wires the flat cluster-admin
	// short-circuit (RBAC explicit-model 2026 P5, D-9): the same OpenFGA client
	// answers the single super-gate Check (cluster:…#system_admin) — when the
	// caller is a cluster-admin, Check/CheckRelation ALLOW before the per-object
	// resolve.
	// StructuralFacts wires the request-time source of the super-access cascade's
	// parent pointers (internal/authzcascade). Without it the cascade resolves only
	// over pointers the fga_outbox drainer has already delivered, which makes the
	// three tiers exactly as delivery-dependent as the flat index they were chosen
	// over.
	//
	// It is the SAME resolver the own-gate wrapper uses — built once by the caller — so the
	// two surfaces cannot come to derive facts from different places.
	// Теневое сравнение формы E с движком (XC-12). Отвечает по-прежнему движок;
	// форма E спрашивается РЯДОМ — на каждом вопросе решения о доступе, который
	// этот use-case отвечает, и ДО обращения к движку, — и ни один её исход не
	// меняет ответа вызывающему.
	//
	// Провязка здесь, а не у транспорта: сравнивать надо окончательный вердикт (к
	// ответу движка ниже добавляются надзор администратора облака и структурный
	// запасной путь), и одно место покрывает все вопросы, а не тот один, у чьего
	// обработчика оказалось написано.
	// Сравнитель приходит СОБРАННЫМ от вызывающего: тот же экземпляр держит
	// обёртка собственных стражей. Собрать второй здесь значило бы завести две
	// меры одного предмета — у края своя, у стражей своя, — и «доля сравнённого»
	// перестала бы иметь один знаменатель.
	authSvc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           fgaTransport,
		ModelID:             modelID,
		ClusterAdminChecker: fgaTransport,
		StructuralFacts:     structuralFacts,
		Shadow:              shadow,
	})
	// Refuse to run a cascade that has silently gone back to waiting for a queue.
	// The fallback needs BOTH a resolver and an Authorizer that can carry contextual
	// tuples; losing either in a refactor would leave every tier below the cloud
	// administrator dependent on delivery again, and nothing else would say so.
	//
	// NOT conditioned on the authentication mode. Every deployed stand runs production
	// posture, and a stand that takes a different authorization path than production is
	// the divergence that rule forbids — the guard would then be absent from the only
	// stands where anyone would notice it firing.
	if !authSvc.StructuralFallbackReachable() {
		logger.Error("refusing to start: the super-access cascade would depend on outbox delivery " +
			"(structural-fact resolver or contextual-tuple Check not wired)")
		os.Exit(1)
	}
	whoAmIUC := authorizeapp.NewWhoAmIUseCase(kachoRepo, ownGates)
	// WithCallerAuthority wires the caller-authority gate (a tenant principal may
	// only query authz decisions about itself, a resource it administers, or as a
	// cluster-admin). The SAME OpenFGA client answers the authority Check; a
	// verified module PDP peer passes through. This gate is not a second opinion
	// behind a narrower gateway check — the catalog entry these RPCs carry is
	// answered by every authenticated subject, so it is the only one there is.
	//
	// WithInsecureAnonymousPeer is the EXCEPTION for a stand without mTLS, where
	// the public and internal listeners cannot be told apart. Fail-closed is the
	// default; only a non-production AuthN mode opts out.
	authzH := authorizeapp.NewHandler(authSvc, whoAmIUC).
		WithCallerAuthority(ownGates).
		WithInsecureAnonymousPeer(!prodMode)

	// RelationProjector — used by InternalAuthorizeService.
	tupleWriter := service.NewRelationProjector(fgaTransport)
	internalAuthH := internalauthorizeapp.NewHandler(tupleWriter, opsRepo, modelID)

	return authzServiceBundle{
		authorize:         authzH,
		authorizeSvc:      authSvc,
		internalAuthorize: internalAuthH,
		shadow:            shadow,
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
