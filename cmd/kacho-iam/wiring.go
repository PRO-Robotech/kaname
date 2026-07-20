// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// wiring.go — composition-builder for the kacho-iam service bundle.
// Holds the `services` struct (single composition point), buildServices
// (per-resource handler wiring), and buildAuthZServices (AuthorizeService),
// and the small adapter types they need.
package main

import (
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	reconcileapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	authorizeapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/authorize"
	clusterapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/cluster"
	conditionsapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/conditions"
	groupapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/group"
	internalauthorizeapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_authorize"
	internaliamapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	internaloperationsapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_operations"
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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
	conditionsHandler        *conditionsapp.Handler
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

	// sessionRevocationsHandler — InternalSessionRevocationsService:
	// token revocation on logout / force-logout + the api-gateway
	// IsRevoked hot-path. Internal-only (запрет #6), registered on port 9091.
	sessionRevocationsHandler *sessionrevapp.Handler

	// internalOperationsHandler — InternalOperationsService.ListIamOperations:
	// cluster-wide admin feed of all IAM operations.
	// Internal-only (запрет #6), registered on port 9091; admin-tier gated
	// (system_admin@cluster ReBAC Check in-handler + gateway permission-catalog).
	internalOperationsHandler *internaloperationsapp.Handler

	// relationStore — shared OpenFGA client. Always non-nil (composition root
	// fails fast on missing KACHO_IAM_OPENFGA_STORE_ID). Reused by runServe
	// for the fga_outbox drainer.
	relationStore *clients.OpenFGAHTTPClient
}

// buildServices создает все repo'ы поверх pool и собирает бизнес-сервисы.
// Composition root passes a fully-configured OpenFGA HTTP client — wiring
// of every per-resource use-case is unconditional (no fallback stub).
func buildServices(pool, slavePool *pgxpool.Pool, opsRepo operations.Repo,
	kachoRepo kachorepo.Repository,
	relationStore *clients.OpenFGAHTTPClient,
	metricsReg *metrics.Registry,
	cfg config.Config, logger *slog.Logger) *services {
	_ = slavePool // kachoRepo is built and passed in by main()

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
		// re-apply). relationStore is always non-nil here (composition root fails fast).
		WithSyncFGA(kachopg.NewSyncFGAWriter(relationStore, logger))

	// AccountService.
	accountCreate := accountapp.NewCreateAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	accountUpdate := accountapp.NewUpdateAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger)
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
		WithRelationStore(relationStore, logger)
	projectDelete := projectapp.NewDeleteProjectUseCase(kachoRepo, opsRepo)
	projectGet := projectapp.NewGetProjectUseCase(kachoRepo).WithRelationStore(relationStore)
	projectList := projectapp.NewListProjectsUseCase(kachoRepo).WithRelationStore(relationStore)
	projectHandler := projectapp.NewHandler(projectCreate, projectUpdate, projectDelete, projectGet, projectList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// UserService + InternalUserService.
	userGet := userapp.NewGetUserUseCase(kachoRepo).WithRelationStore(relationStore)
	userList := userapp.NewListUsersUseCase(kachoRepo).WithRelationStore(relationStore)
	userUpdate := userapp.NewUpdateUserUseCase(kachoRepo, opsRepo)
	userDelete := userapp.NewDeleteUserUseCase(kachoRepo, opsRepo)
	userUpsert := userapp.NewUpsertFromIdentityUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithReconciler(rsabReconciler)
	userInvite := userapp.NewInviteUserUseCase(kachoRepo, opsRepo, relationStore).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	userOnRecovery := userapp.NewOnRecoveryCompletedUseCase(kachoRepo, opsRepo).
		WithLogger(logger)
	userHandler := userapp.NewHandler(userGet, userList, userUpdate, userDelete, userInvite).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))
	internalUserHandler := userapp.NewInternalHandler(userUpsert, userGet, userOnRecovery)

	// ServiceAccountService.
	saCreate := serviceaccountapp.NewCreateServiceAccountUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	saUpdate := serviceaccountapp.NewUpdateServiceAccountUseCase(kachoRepo, opsRepo)
	saDelete := serviceaccountapp.NewDeleteServiceAccountUseCase(kachoRepo, opsRepo)
	saGet := serviceaccountapp.NewGetServiceAccountUseCase(kachoRepo).WithRelationStore(relationStore)
	saList := serviceaccountapp.NewListServiceAccountsUseCase(kachoRepo).WithRelationStore(relationStore)
	saHandler := serviceaccountapp.NewHandler(saCreate, saUpdate, saDelete, saGet, saList).
		WithListOperations(shared.NewListOperationsUseCase(opsRepo))

	// GroupService.
	groupCreate := groupapp.NewCreateGroupUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger).
		WithObjectReconciler(rsabReconciler)
	groupUpdate := groupapp.NewUpdateGroupUseCase(kachoRepo, opsRepo)
	groupDelete := groupapp.NewDeleteGroupUseCase(kachoRepo, opsRepo)
	groupGet := groupapp.NewGetGroupUseCase(kachoRepo).WithRelationStore(relationStore)
	groupList := groupapp.NewListGroupsUseCase(kachoRepo).WithRelationStore(relationStore)
	groupAdd := groupapp.NewAddMemberUseCase(kachoRepo, opsRepo)
	groupRemove := groupapp.NewRemoveMemberUseCase(kachoRepo, opsRepo)
	groupListMembers := groupapp.NewListMembersUseCase(kachoRepo)
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
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(kachoRepo, rsabReconciler))
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
	// deleted. Same grant-authority gate as Create/Delete.
	abUpdate := accessbindingapp.NewUpdateAccessBindingUseCase(kachoRepo, opsRepo).
		WithRelationStore(relationStore, logger)
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
		WithListAssignableRoles(abListAssignable).
		WithListByRole(abListByRole).
		WithExpandAccess(abExpandAccess).
		WithRevoke(abRevoke)

	// ── AuthZ core wiring ─────────────────────────────────────────────────
	authzServices := buildAuthZServices(pool, opsRepo, kachoRepo, relationStore, cfg.Conditions, cfg.AuthN.Mode.IsProduction(), logger)

	// InternalIAMService — LookupSubject (for the api-gateway
	// auth-interceptor) + Check (delegates to AuthorizeService.CheckRelation
	// — same FGA + OPA pipeline). gRPC-direct only, port 9091.
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
		WithObjectReconciler(rsabReconciler, logger)
	regGate := authzguard.NewRelationWriteGate(relationStore).
		WithProductionMode(cfg.AuthN.Mode.IsProduction())
	// Session-revocation writer. Pool-scoped adapter over
	// session_revocations — SHARED by ForceLogout (here), the
	// InternalSessionRevocationsService Revoke path, and the refresh-hook reader
	// (one table, one fan-out). JWKS read port for GetJWKSStatus.
	sessionRevAdapter := kachopg.NewSessionRevocationsAdapter(pool)
	jwksRepo := kachopg.NewOIDCJwksKeyRepo(pool)
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
		// ForceLogout records a session revocation; GetJWKSStatus
		// reports current signing-key status.
		WithSessionRevoker(sessionRevAdapter).
		WithJWKSStatus(jwksRepo, cfg.AuthN.JWKSRotationDuration()).
		// Defense-in-depth ReBAC gate for ForceLogout (security.md "AuthN+AuthZ
		// ВЕЗДЕ"): require the authenticated principal hold system_admin@cluster.
		// relationStore satisfies authzguard.RelationChecker; nil-safe fail-closed.
		WithAdminChecker(relationStore)

	// ── InternalSessionRevocationsService ─────────────────────────────────
	// Revoke (logout / force-logout) + IsRevoked (api-gateway hot-path) +
	// ListByUser (admin audit). Shares the session_revocations table with the
	// refresh-hook reader. Internal-only (запрет #6).
	sessionRevocationsHandler := sessionrevapp.NewHandler(
		sessionrevapp.NewRevokeUseCase(sessionRevAdapter),
		sessionRevAdapter,
	)

	// ── SAKey wiring (Class A static SA keys via Hydra) ───────────────────
	saKeysH := buildSAKeysHandler(pool, opsRepo, cfg, logger)

	// ── UserToken wiring (персональные access-токены пользователя via Hydra) ──
	userTokensH := buildUserTokensHandler(pool, opsRepo, cfg, logger)

	// ── InternalClusterService ────────────────────────────────────────────
	clusterReader := kachopg.NewClusterReader(pool)
	clusterGrantWriter := kachopg.NewClusterAdminGrantWriter(pool)
	clusterGrantReader := kachopg.NewClusterAdminGrantReader(pool)
	clusterRelEmitter := kachopg.NewFGAOutboxEmitter()
	clusterTxb := kachopg.NewPoolTxBeginner(pool)
	clusterUserChecker := kachopg.NewUserExistenceChecker(pool)

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
	).WithUserChecker(clusterUserChecker).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterRevokeUC := clusterapp.NewRevokeAdminUseCase(
		clusterGrantWriter, clusterRelEmitter, clusterTxb, opsRepo,
	).WithAdminChecker(relationStore).
		WithAuditEmitter(clusterAuditEmitter)
	clusterListUC := clusterapp.NewListAdminsUseCase(clusterGrantReader)
	internalClusterHandler := clusterapp.NewHandler(clusterGetUC, clusterGrantUC, clusterRevokeUC, clusterListUC)

	// ── InternalOperationsService — cluster-wide admin op feed ────────────────
	// security.md "AuthN+AuthZ ВЕЗДЕ": the in-handler ReBAC gate (relationStore
	// satisfies authzguard.RelationChecker) enforces system_admin@cluster even
	// when the caller bypasses the api-gateway and dials :9091 directly. nil-safe
	// fail-closed inside the use-case if ever unwired.
	internalOperationsUC := internaloperationsapp.NewListIamOperationsUseCase(opsRepo).
		WithAdminChecker(relationStore)
	internalOperationsHandler := internaloperationsapp.NewHandler(internalOperationsUC)

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

		// token revocation (logout / force-logout).
		sessionRevocationsHandler: sessionRevocationsHandler,

		// cluster-wide admin operations feed.
		internalOperationsHandler: internalOperationsHandler,

		// AuthZ core.
		authorizeHandler:         authzServices.authorize,
		conditionsHandler:        authzServices.conditions,
		internalAuthorizeHandler: authzServices.internalAuthorize,

		// RBAC rules-model G — public grantable role-rule catalog.
		permissionCatalogHandler: permissionCatalogHandler,

		// SAKey (Class A static keys via Hydra).
		saKeysHandler: saKeysH,

		// UserToken (персональные access-токены пользователя via Hydra).
		userTokensHandler: userTokensH,

		// Expose relationStore so runServe can reuse the same instance for the
		// fga_outbox drainer wiring.
		relationStore: relationStore,
	}
}

// buildSAKeysHandler wires the SAKeyService handler — Class A static SA-keys
// via Hydra OAuth2 client_credentials.
func buildSAKeysHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config, logger *slog.Logger) *sakeysapp.Handler {
	saClientRepo := kachopg.NewSAOAuthClientRepo(pool)

	hydraAdminURL := cfg.AuthN.ResolveHydraAdminURL()
	hydraAdmin := clients.NewHydraAdminClient(hydraAdminURL, os.Getenv("KACHO_IAM_HYDRA_ADMIN_TOKEN"))

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
	// вычистки. Без окна затирание выигрывало гонку и клиент получал "<redacted>".
	issueUC.WithRedactGrace(cfg.AuthN.SAKeyRedactGrace)
	// Surface redaction failures (error / give-up / recovered panic) of the
	// detached redaction goroutine — the only place a key can stay un-redacted.
	issueUC.WithLogger(logger)
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
func buildUserTokensHandler(pool *pgxpool.Pool, opsRepo operations.Repo, cfg config.Config, logger *slog.Logger) *usertokensapp.Handler {
	userClientRepo := kachopg.NewUserOAuthClientRepo(pool)

	hydraAdminURL := cfg.AuthN.ResolveHydraAdminURL()
	hydraAdmin := clients.NewHydraAdminClient(hydraAdminURL, os.Getenv("KACHO_IAM_HYDRA_ADMIN_TOKEN"))

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
	conditions        *conditionsapp.Handler
	internalAuthorize *internalauthorizeapp.Handler
	// authorizeSvc — raw AuthorizeService use-case, exposed so the
	// InternalIAMService.Check gate can delegate to the SAME FGA pipeline.
	authorizeSvc *service.AuthorizeService
}

// buildAuthZServices wires AuthorizeService + ConditionsService +
// InternalAuthorizeService against a fully-configured OpenFGA HTTP client.
//
// The FGA model is the sole policy gate: AuthorizeService does not evaluate any
// additional guardrail overlay after the FGA Check.
func buildAuthZServices(pool *pgxpool.Pool, opsRepo operations.Repo,
	kachoRepo kachorepo.Repository, relationStore *clients.OpenFGAHTTPClient,
	condCfg config.ConditionsConfig, prodMode bool, logger *slog.Logger) authzServiceBundle {
	modelID := relationStore.AuthorizationModel
	logger.Info("openfga extended client wired for AuthZ",
		"endpoint", relationStore.Endpoint, "store_id", relationStore.StoreID, "model_id", modelID)

	// AuthorizeService use-case. ClusterAdminChecker wires the flat cluster-admin
	// short-circuit (RBAC explicit-model 2026 P5, D-9): the same OpenFGA client
	// answers the single super-gate Check (cluster:…#system_admin) — when the
	// caller is a cluster-admin, Check/CheckRelation ALLOW before the per-object
	// resolve.
	authSvc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           relationStore,
		ModelID:             modelID,
		ClusterAdminChecker: relationStore,
	})
	whoAmIUC := authorizeapp.NewWhoAmIUseCase(kachoRepo, relationStore)
	// WithCallerAuthority wires the inner defense-in-depth caller-authority gate
	// (a tenant principal may only query authz decisions about itself, a resource
	// it administers, or as a cluster-admin). The SAME OpenFGA client answers the
	// authority Check; anonymous/system module PDP peer calls pass through.
	// WithProductionMode makes the inner caller-authority gate fail-closed for an
	// anonymous/system principal without a verified module cert (the public-listener
	// authorization-oracle bypass); dev-mode stays permissive (no mTLS to gate on).
	authzH := authorizeapp.NewHandler(authSvc, whoAmIUC).
		WithCallerAuthority(relationStore).
		WithProductionMode(prodMode)

	// RelationProjector — used by InternalAuthorizeService.
	tupleWriter := service.NewRelationProjector(relationStore)
	internalAuthH := internalauthorizeapp.NewHandler(tupleWriter, opsRepo, modelID)

	// ConditionsService — Postgres-backed.
	condRepo := kachopg.NewConditionsRepo(pool)
	condEvaluator := service.NewBuiltinEvaluatorWithCache(condCfg.CacheSize, condCfg.CacheTTL())
	condSvc := service.NewConditionsCRUDService(condRepo, opsRepo, condEvaluator)
	// In-service authz: reads require `viewer` and mutations require `editor` on
	// the condition's owning project(folder) scope (cluster-admin short-circuits),
	// mirroring the sibling IAM resources. Without this, ConditionsService had no
	// server-side authorization (cross-tenant BOLA read + tamper).
	condSvc.WithRelationStore(relationStore)
	// Durable audit_outbox emitter — emits
	// iam.condition.created / .updated / .deleted rows inside the ConditionsService
	// worker-tx, atomic with the conditions-row mutation (запрет #10). Payload
	// carries only non-secret compliance dimensions (actor / condition_id /
	// expression name), never the opaque params blob.
	condSvc.WithAuditEmitter(kachopg.NewAuditOutboxEmitter(pool), kachopg.NewPoolTxBeginner(pool))
	conditionsH := conditionsapp.NewHandler(condSvc)

	return authzServiceBundle{
		authorize:         authzH,
		authorizeSvc:      authSvc,
		conditions:        conditionsH,
		internalAuthorize: internalAuthH,
	}
}
