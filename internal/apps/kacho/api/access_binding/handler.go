// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package access_binding — AccessBindingService.
//
// Особенность: Create strict — дубль активного grant'а (5-tuple WHERE
// revoked_at IS NULL) поднимает 23505 из partial UNIQUE
// access_bindings_active_grant_uniq (migration 0003) → gRPC AlreadyExists
// с фиксированным текстом «these permissions are already granted to <subject_id> on
// <res_type>:<res_id>». Идемпотентный ON CONFLICT-upsert удален.
// Each Create/Delete emits outbox-event to invalidate authz-cache.
package access_binding

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/filter"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type Handler struct {
	iamv1.UnimplementedAccessBindingServiceServer

	create                *CreateAccessBindingUseCase
	update                *UpdateAccessBindingUseCase
	delete                *DeleteAccessBindingUseCase
	get                   *GetAccessBindingUseCase
	list                  *ListUseCase
	listByScope           *ListByScopeUseCase
	listBySubject         *ListBySubjectUseCase
	listByAccount         *ListByAccountUseCase
	listSubjectPrivileges *ListSubjectPrivilegesUseCase
	listAssignableRoles   *ListAssignableRolesUseCase
	listOp                *shared.ListOperationsUseCase

	// ListByRole audit + ExpandAccess effective-principal audit.
	listByRole   *ListByRoleUseCase
	expandAccess *ExpandAccessUseCase

	// revoke — soft-revoke (F10 IAM-1-28), contrast with hard delete.
	revoke *RevokeAccessBindingUseCase
}

func NewHandler(c *CreateAccessBindingUseCase, d *DeleteAccessBindingUseCase, g *GetAccessBindingUseCase,
	lbs *ListByScopeUseCase, lbsub *ListBySubjectUseCase, lba *ListByAccountUseCase,
	lsp *ListSubjectPrivilegesUseCase) *Handler {
	return &Handler{
		create: c, delete: d, get: g,
		listByScope: lbs, listBySubject: lbsub, listByAccount: lba,
		listSubjectPrivileges: lsp,
	}
}

// WithUpdate wires the P6 deletion_protection Update use-case (C-03).
func (h *Handler) WithUpdate(uc *UpdateAccessBindingUseCase) *Handler {
	h.update = uc
	return h
}

// WithListOperations wires the per-resource operation-listing use-case.
// Mirrors the core resources.
// WithList wires the unified List use-case (redesign-2026 F11).
func (h *Handler) WithList(uc *ListUseCase) *Handler {
	h.list = uc
	return h
}

func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

// WithListAssignableRoles wires the assignable-roles read use-case.
func (h *Handler) WithListAssignableRoles(uc *ListAssignableRolesUseCase) *Handler {
	h.listAssignableRoles = uc
	return h
}

// WithListByRole wires the audit read "who holds role R".
func (h *Handler) WithListByRole(uc *ListByRoleUseCase) *Handler {
	h.listByRole = uc
	return h
}

// WithExpandAccess wires the effective-principal audit "who can do X".
func (h *Handler) WithExpandAccess(uc *ExpandAccessUseCase) *Handler {
	h.expandAccess = uc
	return h
}

// WithRevoke wires the soft-revoke use-case (F10 IAM-1-28).
func (h *Handler) WithRevoke(uc *RevokeAccessBindingUseCase) *Handler {
	h.revoke = uc
	return h
}

// ListOperations — sync read of the operations recorded for the access binding
// (resource_id=acb-…: Create + Delete ops). Malformed id → InvalidArgument
// (first statement); well-formed-but-no-ops → empty list, not NotFound (parity).
// Viewer-tier authz is enforced by the api-gateway permission-catalog.
func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListAccessBindingOperationsRequest) (*iamv1.ListAccessBindingOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetAccessBindingId(), domain.PrefixAccessBinding, "access binding"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetAccessBindingId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListAccessBindingOperationsResponse{Operations: out, NextPageToken: next}, nil
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateAccessBindingRequest) (*operationpb.Operation, error) {
	// redesign-2026 F7: the scope-anchor is the dotted scopeType (iam.cluster |
	// iam.account | iam.project) + scopeId. Pre-Phase-0 the scopeType is REQUIRED
	// (explicit — prefix-derivation is B3-gated). scopeTypeToBare rejects an empty /
	// non-dotted / unknown value sync (INVALID_ARGUMENT, first statement) and maps
	// the dotted wire form to the bare within-service anchor kind.
	rt, err := scopeTypeToBare(req.GetScopeType())
	if err != nil {
		return nil, err
	}
	rid := req.GetScopeId()
	// F8: target is REQUIRED (least-privilege). A missing/empty target → sync
	// INVALID_ARGUMENT first statement; an unknown per-object type → sync
	// INVALID_ARGUMENT (closed-table). Before any Operation is minted.
	tgt, err := targetFromProto(req.GetTarget())
	if err != nil {
		return nil, err
	}
	b := domain.AccessBinding{
		SubjectType: domain.SubjectType(req.GetSubjectType()),
		SubjectID:   domain.SubjectID(req.GetSubjectId()),
		// Canonical multi-subject input. When set it is canonical; the legacy single
		// subject_type/subject_id (above) is normalized against it in the use-case
		// (conflict → INVALID_ARGUMENT).
		Subjects:     subjectsFromProto(req.GetSubjects()),
		RoleID:       domain.RoleID(req.GetRoleId()),
		ResourceType: domain.ResourceType(rt),
		ResourceID:   rid,
		// Derive Scope from the bare anchor kind. The migration 0005 BEFORE INSERT
		// trigger applies the same mapping if Scope is SCOPE_UNSPECIFIED at the
		// SQL layer; setting it here lets domain Validate() cross-check (rt, rid)
		// consistency before the request reaches the writer.
		Scope: domain.DeriveFromResourceType(rt),
		// deletion_protection is settable on Create so admins / the owner
		// auto-binding can protect a binding up-front.
		DeletionProtection: req.GetDeletionProtection(),
		// labels — own-resource tenant-facing метки самого binding-ресурса,
		// делают AccessBinding label-selectable (catalog-видимость).
		Labels: labelsFromProto(req.GetLabels()),
		// F8: object-selection under the anchor (allInScope | per-object resources).
		Target: tgt,
		// Lifetime. Optional; when set the binding is eager-revoked by the
		// reconcile sweep once it elapses (status REVOKED + tuple removal), so
		// what the caller asks for is what actually happens. The floor is enforced
		// in the use-case, before any Operation is minted.
		ExpiresAt: expiresAtFromProto(req.GetExpiresAt()),
	}
	op, err := h.create.Execute(ctx, b)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteAccessBindingRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.AccessBindingID(req.GetAccessBindingId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Revoke — soft-revoke of the binding (F10 IAM-1-28): the row is retained with
// status ACTIVE→REVOKED (audit-retention), the emitted FGA-tuple set is removed.
// Contrast with Delete (hard row-removal). Thin transport: parse → use-case → format.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeAccessBindingRequest) (*operationpb.Operation, error) {
	op, err := h.revoke.Execute(ctx, domain.AccessBindingID(req.GetAccessBindingId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Update — mutate the {deletion_protection, labels} set on a binding (T3.3-IMM-01):
// clear/toggle deletion_protection so a protected owner-binding can subsequently be
// deleted (C-03), and set own-resource labels (D-6 label-selectability). Any other
// mask path → INVALID_ARGUMENT (update_mask discipline enforced in the use-case).
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateAccessBindingRequest) (*operationpb.Operation, error) {
	var mask []string
	if req.GetUpdateMask() != nil {
		mask = req.GetUpdateMask().GetPaths()
	}
	var labels domain.Labels
	if l := req.GetLabels(); l != nil {
		labels = labelsFromProto(l)
	}
	op, err := h.update.Execute(ctx,
		domain.AccessBindingID(req.GetAccessBindingId()), mask, req.GetDeletionProtection(), labels)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetAccessBindingRequest) (*iamv1.AccessBinding, error) {
	b, err := h.get.Execute(ctx, domain.AccessBindingID(req.GetAccessBindingId()))
	if err != nil {
		return nil, err
	}
	pb, err := abToPb(b)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return pb, nil
}

// List — the unified read (redesign-2026 F11). Page format is validated FIRST
// (page_size + page_token), BEFORE the use-case's listauthz visibility short-circuit,
// so a garbage token / page_size>1000 is INVALID_ARGUMENT regardless of grant state.
// Then the optional whitelist filter is parsed (unknown key → INVALID_ARGUMENT).
func (h *Handler) List(ctx context.Context, req *iamv1.ListAccessBindingsRequest) (*iamv1.ListAccessBindingsResponse, error) {
	// (1) page_size: >1000 → InvalidArgument (no silent clamp), as the FIRST check.
	if _, err := corevalidate.PageSize("page_size", req.GetPageSize()); err != nil {
		return nil, err
	}
	// (2) page_token format: garbage → InvalidArgument, BEFORE listauthz.
	//
	// Форма токена этого списка — граница ВИДИМОЙ последовательности (#645), а не
	// сырой страницы. Общая ValidatePageToken приняла бы токен прежней формы, и
	// обход, начатый до выкатки, продолжился бы приблизительно — молча пропуская
	// строки.
	if _, err := shared.DecodeVisiblePageToken("page_token", req.GetPageToken()); err != nil {
		return nil, err
	}
	// (3) whitelist filter: subject/role/scope/scopeId; unknown key → InvalidArgument.
	f, err := parseABListFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	f.PageSize = safeconv.ClampNonNegInt32(req.GetPageSize())
	f.PageToken = req.GetPageToken()
	// (4) lifecycle: soft-revoked rows are retained for audit (F10) and were
	// reachable ONLY through the legacy ListByAccount/ListByRole — the canonical
	// List could not answer "who USED to hold this". A dedicated flag (not a filter
	// key) so it COMPOSES with the single-predicate filter expression; default
	// false keeps parity with those two RPCs.
	f.IncludeRevoked = req.GetIncludeRevoked()
	// (5) account scope: the account⇒child-project fan-out (#1737). Like
	// include_revoked it is a dedicated field, NOT a filter key, so it composes
	// with the single-predicate filter expression — and the two axes the question
	// "what does THIS subject hold in THIS account" needs can be named at once.
	//
	// Its FORMAT is judged by the use-case, not here: the empty-grant
	// short-circuit lives there, and a guard on this side would leave the second
	// caller of that use-case unprotected (api-conventions.md §Gotcha'и).
	f.AccountID = req.GetAccountId()

	page, err := h.list.Execute(ctx, f)
	if err != nil {
		return nil, err
	}
	return listPageToProto(page)
}

// abListFilterFields — the closed whitelist of List filter keys (F11).
var abListFilterFields = []string{"subject", "role", "scope", "scopeId"}

// parseABListFilter parses the optional single-predicate whitelist filter into the
// repo ListFilter. An unknown key, an unsupported operator or a malformed
// expression → INVALID_ARGUMENT. The `scope` value is the dotted scope-type
// (iam.account|iam.project|iam.cluster), mapped to the bare within-service anchor
// kind; an unknown dotted scope → INVALID_ARGUMENT.
func parseABListFilter(expr string) (repoab.ListFilter, error) {
	ast, err := filter.Parse(expr, abListFilterFields)
	if err != nil {
		return repoab.ListFilter{}, shared.InvalidArg("filter", err.Error())
	}
	var f repoab.ListFilter
	if ast == nil {
		return f, nil // empty filter → no predicate
	}
	// The operator is part of the expression, not decoration. All four keys hold
	// exact identifiers — a subject id, a role id, a scope kind, a scope id — and a
	// substring of an identifier addresses nothing, so CONTAINS has no meaning here.
	// Taking ast.Value and building `=` regardless would answer a substring question
	// with an equality page under a 200, which api-conventions.md
	// §"Принято-и-проигнорировано — ЗАПРЕЩЕНО" rules out: implement, refuse by name,
	// or drop from the contract. This is the second outcome, and it names both the
	// operator and the key so the caller learns which token was not honoured (#460).
	//
	// It stands BEFORE the switch on purpose: `scope CONTAINS "x"` must be refused
	// for its operator, not for the value failing the dotted-scope vocabulary — the
	// second message would send the caller to fix the wrong token.
	if ast.Op != filter.OpEquals {
		return repoab.ListFilter{}, shared.InvalidArg("filter", fmt.Sprintf(
			"Operator %s is not supported for filter field %q. AccessBinding filters compare exact identifiers, so only = is accepted",
			ast.Op, ast.Field))
	}
	switch ast.Field {
	case "subject":
		f.SubjectID = ast.Value
	case "role":
		f.RoleID = ast.Value
	case "scope":
		bare, ok := domain.ScopeTypeFromDotted(ast.Value)
		if !ok {
			return repoab.ListFilter{}, shared.InvalidArg("filter", "Illegal argument scope")
		}
		f.ScopeType = bare
	case "scopeId":
		f.ScopeID = ast.Value
	}
	return f, nil
}

func (h *Handler) ListByScope(ctx context.Context, req *iamv1.ListAccessBindingsByScopeRequest) (*iamv1.ListAccessBindingsResponse, error) {
	// One coordinate, one name: prefer the canonical dotted scope_type/scope_id
	// (parity with Create + AccessBinding), fall back to the legacy bare
	// resource_type/resource_id. An unknown dotted value → sync INVALID_ARGUMENT.
	scopeType, scopeID, err := scopeCoordinate(
		req.GetScopeType(), req.GetScopeId(), req.GetResourceType(), req.GetResourceId())
	if err != nil {
		return nil, err
	}
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// раньше, чем читает страницу, а сужение int64→int32 ниже насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.listByScope.Execute(ctx,
		domain.ResourceType(scopeType), scopeID,
		repoab.PageFilter{PageSize: safeconv.ClampNonNegInt32(req.GetPageSize()), PageToken: req.GetPageToken()},
	)
	if err != nil {
		return nil, err
	}
	return listToProto(rows, next)
}

func (h *Handler) ListBySubject(ctx context.Context, req *iamv1.ListAccessBindingsBySubjectRequest) (*iamv1.ListAccessBindingsResponse, error) {
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// (self-only) раньше, чем читает страницу, а сужение int64→int32 ниже насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.listBySubject.Execute(ctx,
		domain.SubjectType(req.GetSubjectType()), domain.SubjectID(req.GetSubjectId()),
		repoab.PageFilter{PageSize: safeconv.ClampNonNegInt32(req.GetPageSize()), PageToken: req.GetPageToken()},
	)
	if err != nil {
		return nil, err
	}
	return listToProto(rows, next)
}

func (h *Handler) ListByAccount(ctx context.Context, req *iamv1.ListAccessBindingsByAccountRequest) (*iamv1.ListAccessBindingsResponse, error) {
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// раньше, чем читает страницу, а сужение int64→int32 ниже насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.listByAccount.Execute(ctx,
		req.GetAccountId(),
		repoab.AccountPageFilter{
			PageSize:          safeconv.ClampNonNegInt32(req.GetPageSize()),
			PageToken:         req.GetPageToken(),
			SubjectTypeFilter: req.GetSubjectTypeFilter(),
			IncludeRevoked:    req.GetIncludeRevoked(),
		},
	)
	if err != nil {
		return nil, err
	}
	return listToProto(rows, next)
}

// ListByRole — sync audit "who holds role R". Each row carries
// the dual subjects[]/legacy projection; the use-case enforces the
// per-row grant-authority scope-filter.
func (h *Handler) ListByRole(ctx context.Context, req *iamv1.ListAccessBindingsByRoleRequest) (*iamv1.ListAccessBindingsResponse, error) {
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// (grant-authority scope-filter) раньше, чем читает страницу, а сужение
	// int64→int32 ниже насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.listByRole.Execute(ctx,
		req.GetRoleId(),
		repoab.ListByRoleFilter{
			PageSize:       safeconv.ClampNonNegInt32(req.GetPageSize()),
			PageToken:      req.GetPageToken(),
			IncludeRevoked: req.GetIncludeRevoked(),
		},
	)
	if err != nil {
		return nil, err
	}
	return listToProto(rows, next)
}

// ExpandAccess — sync effective-principal audit "who can do <relation> on
// <object>". Resolves group usersets to concrete principals.
func (h *Handler) ExpandAccess(ctx context.Context, req *iamv1.ExpandAccessRequest) (*iamv1.ExpandAccessResponse, error) {
	principals, truncated, err := h.expandAccess.Execute(ctx,
		req.GetObjectType(), req.GetObjectId(), req.GetRelation(), int(req.GetMaxResults()))
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Principal, 0, len(principals))
	for _, p := range principals {
		out = append(out, &iamv1.Principal{
			Type: subjectTypeToProto(p.Type),
			Id:   string(p.ID),
		})
	}
	return &iamv1.ExpandAccessResponse{Principals: out, Truncated: truncated}, nil
}

// ListSubjectPrivileges — sync, enriched read of a subject's DIRECT privileges
// role_name is resolved server-side via the repo JOIN; authz
// is "self OR account-admin of the subject's home Account" (use-case).
func (h *Handler) ListSubjectPrivileges(ctx context.Context, req *iamv1.ListSubjectPrivilegesRequest) (*iamv1.ListSubjectPrivilegesResponse, error) {
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// (self OR account-admin) раньше, чем читает страницу, а сужение int64→int32
	// ниже насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, next, err := h.listSubjectPrivileges.Execute(ctx,
		domain.SubjectType(req.GetSubjectType()), domain.SubjectID(req.GetSubjectId()),
		repoab.PageFilter{PageSize: safeconv.ClampNonNegInt32(req.GetPageSize()), PageToken: req.GetPageToken()},
	)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.SubjectPrivilege, 0, len(rows))
	for _, p := range rows {
		out = append(out, subjectPrivilegeToProto(p))
	}
	return &iamv1.ListSubjectPrivilegesResponse{Privileges: out, NextPageToken: next}, nil
}

// ListAssignableRoles — sync read of the roles valid for binding on
// (resource_type, resource_id), each annotated with a server-computed
// scope_group. Thin transport: parse → use-case → format.
// resource_type/id validation, existence + grant-authority, and the
// isRoleAssignable filter all live in the use-case.
func (h *Handler) ListAssignableRoles(ctx context.Context, req *iamv1.ListAssignableRolesRequest) (*iamv1.ListAssignableRolesResponse, error) {
	// Same one-coordinate-one-name resolution as ListByScope: the role picker and
	// the Create it feeds must speak the SAME vocabulary.
	scopeType, scopeID, err := scopeCoordinate(
		req.GetScopeType(), req.GetScopeId(), req.GetResourceType(), req.GetResourceId())
	if err != nil {
		return nil, err
	}
	// Формат страницы — по СЫРОМУ запросу, ДО use-case'а: он замыкается по правам
	// (grant-authority) раньше, чем читает страницу, а сужение int64→int32 ниже
	// насыщающее.
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	roles, next, err := h.listAssignableRoles.Execute(ctx,
		scopeType, scopeID,
		reporole.ListFilter{PageSize: safeconv.ClampNonNegInt32(req.GetPageSize()), PageToken: req.GetPageToken()},
	)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.AssignableRole, 0, len(roles))
	for _, r := range roles {
		out = append(out, assignableRoleToProto(r))
	}
	return &iamv1.ListAssignableRolesResponse{Roles: out, NextPageToken: next}, nil
}

// ----- helpers -----

// assignableRoleToProto maps the lean domain projection to the proto
// AssignableRole. created_at truncated to seconds (api-conventions); scope_group
// carries the server-computed tier (the UI groups by it directly, D-4).
func assignableRoleToProto(r domain.AssignableRole) *iamv1.AssignableRole {
	return &iamv1.AssignableRole{
		RoleId:      string(r.RoleID),
		Name:        string(r.Name),
		Description: string(r.Description),
		IsSystem:    r.IsSystem,
		ScopeGroup:  scopeGroupToProto(r.ScopeGroup),
		CreatedAt:   shared.TimestampProto(r.CreatedAt),
	}
}

func scopeGroupToProto(g domain.RoleScopeGroup) iamv1.ScopeGroup {
	switch g {
	case domain.RoleScopeGroupSystem:
		return iamv1.ScopeGroup_SYSTEM
	case domain.RoleScopeGroupAccount:
		return iamv1.ScopeGroup_ACCOUNT
	case domain.RoleScopeGroupProject:
		return iamv1.ScopeGroup_PROJECT
	default:
		return iamv1.ScopeGroup_SCOPE_GROUP_UNSPECIFIED
	}
}

// subjectPrivilegeToProto maps the enriched domain projection to the proto
// SubjectPrivilege. created_at/expires_at are truncated to seconds
// (api-conventions).
//
// Two projections are deliberately dual-written:
//   - the scope anchor is emitted under BOTH the canonical dotted
//     `scope_type`/`scope_id` and the legacy bare `resource_type`/`resource_id`
//     (see scope_coordinate.go) so no client breaks while the names converge;
//   - `derivation` reflects HOW the subject holds the privilege — DIRECT, or
//     GROUP with `via_group_id` naming the carrying group.
func subjectPrivilegeToProto(p domain.SubjectPrivilege) *iamv1.SubjectPrivilege {
	return &iamv1.SubjectPrivilege{
		BindingId: string(p.BindingID),
		RoleId:    string(p.RoleID),
		RoleName:  string(p.RoleName),
		// Legacy spelling of the scope anchor — kept populated for back-compat.
		ResourceType: string(p.ResourceType),
		ResourceId:   p.ResourceID,
		// Canonical spelling — identical in form/meaning to AccessBinding.scope_type.
		ScopeType:       domain.ScopeTypeToDotted(string(p.ResourceType)),
		ScopeId:         p.ResourceID,
		Scope:           scopeToProto(p.Scope),
		Status:          statusToProto(p.Status),
		CreatedAt:       shared.TimestampProto(p.CreatedAt),
		GrantedByUserId: string(p.GrantedByUserID),
		ExpiresAt:       expiresAtProto(p.ExpiresAt),
		Derivation:      derivationToProto(p.Derivation),
		ViaGroupId:      string(p.ViaGroupID),
	}
}

// derivationToProto maps the domain derivation to the proto enum. The domain zero
// value means DIRECT (a row produced without an explicit derivation is a direct
// grant), so UNSPECIFIED is never emitted — leaking it would make every
// pre-existing row look like an unknown derivation.
func derivationToProto(d domain.PrivilegeDerivation) iamv1.Derivation {
	if d == domain.DerivationGroup {
		return iamv1.Derivation_GROUP
	}
	return iamv1.Derivation_DIRECT
}

func scopeToProto(s domain.Scope) iamv1.AccessBinding_Scope {
	switch s {
	case domain.ScopeCluster:
		return iamv1.AccessBinding_CLUSTER
	case domain.ScopeAccount:
		return iamv1.AccessBinding_ACCOUNT
	case domain.ScopeProject:
		return iamv1.AccessBinding_PROJECT
	default:
		return iamv1.AccessBinding_SCOPE_UNSPECIFIED
	}
}

func statusToProto(s domain.AccessBindingStatus) iamv1.AccessBinding_Status {
	switch s {
	case domain.AccessBindingStatusPending:
		return iamv1.AccessBinding_PENDING
	case domain.AccessBindingStatusActive:
		return iamv1.AccessBinding_ACTIVE
	case domain.AccessBindingStatusRevoked:
		return iamv1.AccessBinding_REVOKED
	default:
		return iamv1.AccessBinding_STATUS_UNSPECIFIED
	}
}

// expiresAtFromProto maps the request's optional lifetime to the domain's
// nullable time. Absent stays absent — no lifetime is ever invented.
func expiresAtFromProto(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime().UTC()
	return &t
}

func expiresAtProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return shared.TimestampProto(*t)
}

func abToPb(b domain.AccessBinding) (*iamv1.AccessBinding, error) {
	any, err := marshalAB(b)
	if err != nil {
		return nil, err
	}
	var pb iamv1.AccessBinding
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}

func listPageToProto(page ListPage) (*iamv1.ListAccessBindingsResponse, error) {
	out := make([]*iamv1.AccessBinding, 0, len(page.Bindings))
	// records — ПОЛНОЕ перечисление поверхности выдач: те же выдачи плюс записи
	// двух соседних поверхностей. Вид называется дважды — полем `kind` и ветвью
	// `record`, — и оба прочтения строятся ЗДЕСЬ, одной функцией на вид: запись,
	// чей `kind` разошёлся с ветвью, читалась бы разными вызывающими по-разному.
	records := make([]*iamv1.GrantSurfaceRecord, 0,
		len(page.Bindings)+len(page.Memberships)+len(page.ClusterAdmins))
	for _, b := range page.Bindings {
		pb, err := abToPb(b)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		out = append(out, pb)
		records = append(records, &iamv1.GrantSurfaceRecord{
			Kind:   iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING,
			Record: &iamv1.GrantSurfaceRecord_Binding{Binding: pb},
		})
	}
	for _, m := range page.Memberships {
		records = append(records, &iamv1.GrantSurfaceRecord{
			Kind: iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP,
			Record: &iamv1.GrantSurfaceRecord_GroupMembership{
				GroupMembership: &iamv1.GroupMembershipRecord{
					GroupId:    string(m.GroupID),
					MemberType: string(m.MemberType),
					MemberId:   string(m.MemberID),
					AddedAt:    tsOrNil(m.AddedAt),
				},
			},
		})
	}
	for _, a := range page.ClusterAdmins {
		records = append(records, &iamv1.GrantSurfaceRecord{
			Kind: iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_CLUSTER_ADMIN,
			Record: &iamv1.GrantSurfaceRecord_ClusterAdmin{
				ClusterAdmin: &iamv1.ClusterAdminRecord{
					Id:          a.ClusterAdminGrantID,
					SubjectType: a.SubjectType,
					SubjectId:   a.SubjectID,
					GrantedAt:   tsOrNil(a.GrantedAt),
				},
			},
		})
	}
	var incomplete []string
	for _, g := range page.IncompleteMembershipGroups {
		incomplete = append(incomplete, string(g))
	}
	return &iamv1.ListAccessBindingsResponse{
		AccessBindings:               out,
		NextPageToken:                page.NextPageToken,
		Records:                      records,
		IncompleteMembershipGroupIds: incomplete,
	}, nil
}

// listToProto — проекция УСТАРЕВШЕГО семейства
// (ListByScope/ListBySubject/ListByRole/ListByAccount).
//
// Поле полного перечисления (`records`) она НЕ заполняет, и это сказано здесь и
// в комментарии самого поля, а не оставлено читателю как «ничего не найдено».
// Заполнять его отсюда было бы неверно вдвойне: у этих четырёх чтений нет ни
// вопроса о кластерном администраторе, ни своего вердикта видимости для
// соседних видов, — то есть перечисление вышло бы либо неполным, либо шире
// того, что вызывающему дозволено видеть.
func listToProto(rows []domain.AccessBinding, next string) (*iamv1.ListAccessBindingsResponse, error) {
	out := make([]*iamv1.AccessBinding, 0, len(rows))
	for _, b := range rows {
		pb, err := abToPb(b)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		out = append(out, pb)
	}
	return &iamv1.ListAccessBindingsResponse{AccessBindings: out, NextPageToken: next}, nil
}

// tsOrNil — отметка времени в ответе усечена до СЕКУНД, как у всякого
// timestamp'а этого контракта: микросекунды базы на провод не текут. Нулевое
// время остаётся НЕЗАПОЛНЕННЫМ, а не эпохой: «не задано» и «01.01.1970» —
// разные утверждения, и второе читается как факт.
func tsOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(time.Second))
}
