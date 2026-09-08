// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"

	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
)

// auditTenantAccountID derives the Account scope for the audit_outbox
// tenant_account_id column from an AccessBinding. For account-scoped bindings
// the resource itself IS the account; for project / cluster / cross-service
// scopes it is left empty (NULL in audit_outbox) — the binding_id + resource_*
// fields in the event_payload already make the event fully queryable, and
// resolving a project's owning account would require an extra read on the
// compliance path. Tenant scoping is a best-effort query convenience, not a
// correctness requirement.
func auditTenantAccountID(b domain.AccessBinding) string {
	if b.ResourceType == "account" {
		return b.ResourceID
	}
	return ""
}

func marshalAB(b domain.AccessBinding) (*anypb.Any, error) {
	var dst *iamv1.AccessBinding
	if err := dto.Transfer(dto.FromTo(b, &dst)); err != nil {
		return nil, fmt.Errorf("dto.Transfer AccessBinding: %w", err)
	}
	return anypb.New(dst)
}

// labelsFromProto converts a protobuf own-resource label map into domain.Labels
// (parity with account/serviceAccount/user/role handlers). nil/empty → empty
// (non-nil) map. Maps the binding's OWN labels (Create/UpdateAccessBindingRequest.labels)
// — making the AccessBinding label-selectable (D-6).
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}

// fgaBindingObjectType — the rights-model object type of an AccessBinding.
const fgaBindingObjectType = "iam_access_binding"

// bindingVisibleToCaller answers the DIRECT per-object question "may the ctx
// principal read iam_access_binding:<id>?", evaluated on the ONE object being
// read. The predicate is NOT spelled here: it is whatever authzfilter answers
// for this type, which is the relation the catalog gates a single-object Get on.
//
// Two independent things changed here, both already applied. Shape: this
// replaces the previous "enumerate every visible binding, then look for this id
// in the result", because the external relations engine capped that enumeration
// server-side (default 1000) with no continuation token, so past that population a
// caller's OWN granted binding fell outside the returned prefix and Get answered 403
// forever. The engine is gone; the SHAPE is what mattered and it stays. Predicate: this used to ask the
// `viewer ∪ v_list` union (D-6 label-selectable binding visibility); the union
// was dropped because tier and verb relations are deliberately decoupled, so it
// diverged from the read gate in both directions. See the internal/authzfilter
// package doc for both.
//
// Fail-closed: the resolver unwired (nil port) or an unresolvable / anonymous
// principal → (false, nil) = deny; an FGA error → UNAVAILABLE.
func bindingVisibleToCaller(ctx context.Context, rq clients.RelationQueries, id string) (bool, error) {
	if rq == nil {
		return false, nil
	}
	subject, ok := authzguard.PrincipalSubject(ctx) // fail-closed: anon / empty / unknown → ""
	if !ok {
		return false, nil
	}
	visible, err := authzfilter.Visible(ctx, rq, subject, fgaBindingObjectType, id)
	if err != nil {
		return false, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}

// visibleBindingIDsOnPage resolves the principal's READ visibility (the relation
// authzfilter reports for this type — the one gating a single-object Get, no
// longer the former `viewer ∪ v_list` union)
// for the bindings ON THE PAGE the caller already read from the iam database.
// Returns (set, ok): ok=false when the resolver is unwired (no RelationQueries) —
// callers then rely solely on the self/granted floor.
//
// Cost is proportional to the PAGE, not to the number of iam_access_binding
// objects in the store, and — unlike the ListObjects enumeration it replaces —
// the answer is never silently truncated (internal/authzfilter package doc).
//
// Fail-closed: an FGA error on ANY object → UNAVAILABLE (never an unfiltered
// leak, never an owner-only fallback; parity with role.List D-47 / security.md).
// An anonymous / empty-subject principal yields an empty set (default-deny).
func visibleBindingIDsOnPage(ctx context.Context, rq clients.RelationQueries, ids []string) (map[string]bool, bool, error) {
	if rq == nil {
		return nil, false, nil
	}
	subject, ok := authzguard.PrincipalSubject(ctx) // fail-closed: anon / empty / unknown → ""
	if !ok {
		return map[string]bool{}, true, nil
	}
	visible, err := authzfilter.VisibleSet(ctx, rq, subject, fgaBindingObjectType, ids)
	if err != nil {
		return nil, true, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, true, nil
}

// bindingIDs projects a binding page to its bare ids (the input of
// visibleBindingIDsOnPage).
func bindingIDs(rows []domain.AccessBinding) []string {
	out := make([]string, 0, len(rows))
	for _, b := range rows {
		out = append(out, string(b.ID))
	}
	return out
}

// requireGrantAuthority — package-level function shared by Create and Delete.
// Verifies the calling principal is authorised to create or delete an
// AccessBinding on the given grant scope.
//
// Authority is granted when EITHER holds:
//   - the principal owns the owning Account (bootstrap path — every Account
//     owner can administer their own tree), OR
//   - the principal holds an FGA `admin` relation on the scope object
//     (delegated administration — an account-admin who is not the owner can
//     still grant roles within their scope).
//
// This replaces the old owner-only `requireOwnerOfResource` plus an
// identity-equality self-grant guard, which together blocked owners from
// granting roles to other users (peer-access, matrix model 4).
func requireGrantAuthority(ctx context.Context, repo Repo, relations clients.RelationStore, resourceType, resourceID string) error {
	// Path 0 — cluster-admin short-circuit (RBAC explicit-model 2026 P5, D-9 / КФ-2).
	// After the access-cascade is contracted a cluster-admin no longer holds an
	// account/project-tier admin-tuple, so the ordinary owner/FGA-admin paths below
	// would deny them. The flat super-gate (cluster:…#system_admin) keeps a
	// cluster-admin able to grant on ANY scope (D-06 — foreign account) and to manage
	// the binding objects themselves (D-07 — iam_access_binding). Additive: it runs
	// ALONGSIDE the existing paths, not instead of them. nil-safe via the guard inside
	// IsClusterAdminE (unwired relations → (false, nil) → fall through).
	//
	// E-форма, а не булева: у надзора ТРИ исхода. Прежде «хранилище прав не
	// ответило» терялось внутри обёртки и сходилось с «не положено» — вызывающий
	// получал отказ в правах и повтор считал бессмысленным. Полагаться на то, что
	// неполадку заметит Путь 2 ниже, нельзя: он спрашивает про ДРУГОЙ кортеж и на
	// свой вопрос ответ получить может.
	admin, aerr := authzguard.IsClusterAdminE(ctx, relations)
	if aerr != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if admin {
		return nil
	}

	return grantAuthorityBeyondClusterAdmin(ctx, repo, relations, resourceType, resourceID)
}

// grantAuthorityBeyondClusterAdmin — та же полоса, что и у requireGrantAuthority,
// НО без Пути 0: вызывающий уже спросил супер-гейт и промахнулся.
//
// # Зачем это отдельная функция
//
// Вопрос супер-гейта не зависит ни от типа области, ни от её идентификатора —
// он про ЛИЧНОСТЬ вызывающего. На одиночном глаголе (Create / Delete) разницы
// нет, и там полоса зовётся целиком. На СТРАНИЦЕ разница и есть предмет: вопрос,
// одинаковый для всех её строк, обязан задаваться однажды за запрос, а не по
// разу на строку. Стоимость страницы принадлежит ЗАПРОСУ (`security.md`
// §«Фильтрация — страница → проверка страницы»), а `page_size` доходит до 1000.
//
// Исход этой функции для строки ТОТ ЖЕ, что у requireGrantAuthority, когда
// супер-гейт ответил «не админ, ошибки нет»: вызывающий обязан воспроизвести
// Путь 0 сам и различить три его исхода — да · нет · спросить не удалось.
func grantAuthorityBeyondClusterAdmin(ctx context.Context, repo Repo, relations clients.RelationStore, resourceType, resourceID string) error {
	var ownerUserID string
	// The owner-path resolves the owning Account via the DB reader. It is only
	// relevant for the hierarchy scope-types (account/project); for every other
	// object-type (cluster / leaf FGA object like compute.instance) authority is
	// granted ONLY by the FGA admin path below, so the reader is not needed. Skip
	// it entirely when repo is nil — callers that authorize purely through FGA
	// (ExpandAccess on a leaf object via delegated admin) wire only the
	// RelationStore. ListByScope/Create/Delete always wire a non-nil repo, so
	// this nil-guard does not weaken any existing caller.
	if repo != nil && (resourceType == "account" || resourceType == "project") {
		rd, err := repo.Reader(ctx)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		defer func() { _ = rd.Rollback(ctx) }()

		switch resourceType {
		case "account":
			acct, gerr := rd.Accounts().Get(ctx, domain.AccountID(resourceID))
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			ownerUserID = string(acct.OwnerUserID)
		case "project":
			proj, gerr := rd.Projects().Get(ctx, domain.ProjectID(resourceID))
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			acct, gerr := rd.Accounts().Get(ctx, proj.AccountID)
			if gerr != nil {
				return shared.MapRepoErr(gerr)
			}
			ownerUserID = string(acct.OwnerUserID)
		}
	}
	// Non-hierarchy scopes (cluster / org / cross-service / leaf FGA objects like
	// compute.instance) have no DB-side "owner": authority is granted ONLY by the
	// FGA admin/system_admin path below (e.g. cluster admins hold `system_admin`
	// on cluster:cluster_root). No owner-fallback path — ownerUserID stays
	// empty so only Path 2 can authorize them.

	// Path 1 — owner of the owning Account.
	if ownerUserID != "" && authzguard.IsSelf(ctx, ownerUserID) {
		return nil
	}

	// Path 2 — delegated admin: principal holds `admin` on the scope object in FGA.
	// We call fgaHoldsScopeAdmin (NOT fgaHoldsAdmin) here: Path 0 above ALREADY ran
	// the cluster-admin short-circuit (IsClusterAdmin) and missed, so re-checking it
	// inside fgaHoldsAdmin would be a redundant identical FGA round-trip (#9). The
	// scope-only variant performs just the per-scope admin-tuple Check.
	scopeAdmin, scopeErr := fgaHoldsScopeAdminE(ctx, relations, resourceType, resourceID)
	if scopeErr != nil {
		// «Спросить не удалось» ≠ «не положено»: вызывающий обязан узнать, что
		// повтор осмыслен.
		return authzguard.AuthzBackendUnavailable()
	}
	if scopeAdmin {
		return nil
	}

	return authzguard.PermissionDenied()
}

// fgaAdminObject builds the canonical FGA object string for an authority Check
// (`<lower-type>:<id>`). Centralised so every grant/read-authority gate targets
// the SAME object — the prior per-site copies disagreed on id casing.
func fgaAdminObject(resourceType, resourceID string) string {
	return fmt.Sprintf("%s:%s", strings.ToLower(resourceType), resourceID)
}

// fgaHoldsAdminE reports whether the ctx principal holds delegated-admin authority
// on the scope object: EITHER it is a cluster-admin (flat super-gate) OR it holds
// the FGA `admin` relation on the scope object. This is the entry-point for the
// DIRECT call-sites (ListSubjectPrivileges, D-07) that have NOT already run the
// cluster-admin short-circuit. requireGrantAuthority does NOT use this — it ran
// Path 0 (IsClusterAdmin) itself and calls fgaHoldsScopeAdmin to avoid a redundant
// cluster-admin Check (#9).
//
// Fail-closed: false when the FGA client is unwired (unit tests / degraded mode),
// the caller is anonymous, or the principal id is empty.
func fgaHoldsAdminE(ctx context.Context, relations clients.RelationStore, resourceType, resourceID string) (bool, error) {
	if relations == nil || authzguard.IsAnonymous(ctx) {
		return false, nil
	}
	// Cluster-admin short-circuit (RBAC explicit-model 2026 P5, D-9 / КФ-2): the
	// flat super-gate covers the direct call-sites (ListSubjectPrivileges, D-07)
	// so a cluster-admin retains delegated-admin visibility after the
	// access-cascade is contracted. Checked before the per-scope admin tuple.
	//
	// E-форма и здесь: вызывающий у этой функции — списочный, и неполадка на
	// супер-гейте меняет ЕГО ответ, а не просто «не срабатывает».
	admin, aerr := authzguard.IsClusterAdminE(ctx, relations)
	if aerr != nil {
		return false, aerr
	}
	if admin {
		return true, nil
	}
	return fgaHoldsScopeAdminE(ctx, relations, resourceType, resourceID)
}

// fgaHoldsScopeAdminE reports whether the ctx principal holds the FGA `admin`
// relation on the scope object — the per-scope admin-tuple Check ONLY (no
// cluster-admin short-circuit). Used by requireGrantAuthority's Path 2, which has
// already evaluated the cluster-admin super-gate in Path 0 (#9 — avoids a duplicate
// cluster-admin round-trip).
//
// Возвращает ТРИ исхода, а не два: `(true, nil)` — держит; `(false, nil)` —
// хранилище ответило «нет»; `(false, err)` — хранилище не ответило. Последнее
// отказом в правах не является и обязано доехать до вызывающего: на списочном
// пути проглоченная неполадка даёт молча суженную страницу.
//
// Fail-closed по вырожденным входам остаётся: FGA не провязан, вызывающий
// анонимен либо неизвестного вида → `(false, nil)`.
func fgaHoldsScopeAdminE(ctx context.Context, relations clients.RelationStore, resourceType, resourceID string) (bool, error) {
	if relations == nil {
		return false, nil
	}
	subject, ok := authzguard.PrincipalSubject(ctx) // fail-closed: anon / empty / unknown → ""
	if !ok {
		return false, nil
	}
	allowed, err := relations.Check(ctx, subject, "admin", fgaAdminObject(resourceType, resourceID))
	if err != nil {
		// Неполадка хранилища прав — НЕ отказ в правах. Прежде эта функция
		// заканчивалась `return err == nil && allowed`, то есть исход у обоих
		// ответов был один: `false`. Шесть списочных путей строили по нему
		// страницу и отдавали well-formed `200` с молча суженным набором,
		// неотличимым от настоящего отзыва прав.
		return false, err
	}
	return allowed, nil
}

// requireGrantAuthorityViaCreate — shim allowing CreateAccessBindingUseCase to
// call the package-level requireGrantAuthority without exposing its fields.
func (u *CreateAccessBindingUseCase) requireGrantAuthority(ctx context.Context, resourceType, resourceID string) error {
	return requireGrantAuthority(ctx, u.repo, u.relations, resourceType, resourceID)
}

// validateGlobalAllSelector enforces the Q-2 GLOBAL+all policy (RBAC explicit-model
// 2026 P5, A-05/A-05b/A-05c) SYNC on the Create request path:
//
//   - GLOBAL == the cluster scope (resource_type == "cluster"; there is no separate
//     GLOBAL tier in the proto/domain enum — cluster:cluster_root IS the
//     cluster-wide anchor).
//   - A role with an ARM_ANCHOR (selector=all) rule bound at GLOBAL would require
//     per-object materialization over the WHOLE cluster — forbidden for an ordinary
//     role (A-05). The single exception is THE system cluster-admin role (pinned id,
//     `*.*.*`), whose GLOBAL+all binding is the D-9 cluster-relation, not per-object
//     (A-05c). The `owner` role shares the `*.*.*` shape but is matched out by id
//     (#8), so an owner@GLOBAL+all binding is rejected like any other ordinary role.
//   - GLOBAL + names/labels (no ARM_ANCHOR rule) is finite and legal (A-05b).
//
// Only triggers for the cluster scope: account/project-scoped ARM_ANCHOR bindings
// materialize within a bounded scope and are unaffected. A non-cluster role read
// error is mapped through shared.MapRepoErr (a missing role keeps its existing
// FAILED_PRECONDITION contract via the worker — this gate stays silent on
// not-found, returning it so doCreate's role-read produces the canonical text).
func (u *CreateAccessBindingUseCase) validateGlobalAllSelector(ctx context.Context, b domain.AccessBinding) error {
	if strings.ToLower(string(b.ResourceType)) != "cluster" {
		return nil // GLOBAL gate applies only to the cluster (GLOBAL) scope.
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	role, err := rd.Roles().Get(ctx, b.RoleID)
	if err != nil {
		// A missing/mis-read role is NOT this gate's concern — let doCreate's
		// in-tx role-read raise the canonical FAILED_PRECONDITION ("Role … not
		// found") so the contract is unchanged. Returning nil here lets Create
		// proceed to the worker which surfaces the proper error.
		return nil
	}
	// A rules-role with an ARM_ANCHOR (selector=all) rule, that is NOT the system
	// cluster-admin role, cannot be bound at GLOBAL.
	if role.Rules.HasAnchorRule() && !role.IsClusterAdminRole() {
		return status.Error(codes.InvalidArgument,
			"GLOBAL scope requires names or labels selector for non-cluster-admin roles")
	}
	return nil
}

// callerIsSubjectOf — самопол выдачи: принципал названным субъектом ЭТОЙ выдачи.
//
// Судится ВЕСЬ набор `Subjects`, а не легаси-первый `SubjectID`. До #2049 оба
// самопола читали только `SubjectID` (= `Subjects[0]`), поэтому субъект,
// стоящий в мультисубъектной выдаче не первым, своей же выдачи не видел:
// самопол он не проходил и уезжал в ветвь права выдавать, которой у него нет.
// Направление отказа безопасное (меньше доступа, не больше) — оттого дефект был
// тихим: жалуется только тот, кому не показали.
//
// Набор наполняет путь чтения (`ListSubjects` / `projectSubjectsBatch`) той же
// читающей транзакцией, что и саму строку. У легаси-строки без детей набор пуст
// — тогда судится легаси-первый, и старая полоса не отзывается: это не запасной
// путь, а единственный субъект такой выдачи.
func callerIsSubjectOf(ctx context.Context, b domain.AccessBinding) bool {
	for _, s := range b.Subjects {
		if authzguard.IsSelf(ctx, string(s.ID)) {
			return true
		}
	}
	return authzguard.IsSelf(ctx, string(b.SubjectID))
}
