// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package role — RoleService.
package role

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type Handler struct {
	iamv1.UnimplementedRoleServiceServer

	create *CreateRoleUseCase
	update *UpdateRoleUseCase
	delete *DeleteRoleUseCase
	get    *GetRoleUseCase
	list   *ListRolesUseCase
	listOp *shared.ListOperationsUseCase
}

func NewHandler(c *CreateRoleUseCase, u *UpdateRoleUseCase, d *DeleteRoleUseCase,
	g *GetRoleUseCase, l *ListRolesUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateRoleRequest) (*operationpb.Operation, error) {
	// A-02: permissions is INTERNAL compiled/output-only — reject any client-sent
	// value as the first statement (before the use-case), so no role is created.
	// Intentionally reads the deprecated field precisely to reject client input.
	if len(req.GetPermissions()) > 0 { //nolint:staticcheck // A-02: deprecated field read solely to reject it
		return nil, shared.InvalidArg("permissions", "Illegal argument permissions (compiled/output-only)")
	}
	op, err := h.create.Execute(ctx, roleFromCreateReq(req))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateRoleRequest) (*operationpb.Operation, error) {
	in := UpdateRoleInput{
		ID:              domain.RoleID(req.GetRoleId()),
		ResourceVersion: req.GetResourceVersion(),
	}
	if name := req.GetName(); name != "" {
		n := domain.RoleName(name)
		in.Name = &n
	}
	if desc := req.GetDescription(); desc != "" {
		d := domain.Description(desc)
		in.Description = &d
	}
	if rules := req.GetRules(); rules != nil {
		in.Rules = rulesFromProto(rules)
	}
	// labels — own-resource метки (T3.3); НЕ путать с Rule.MatchLabels.
	if labels := req.GetLabels(); labels != nil {
		in.Labels = labelsFromProto(labels)
	}
	if mask := req.GetUpdateMask(); mask != nil {
		in.UpdateMask = append([]string{}, mask.GetPaths()...)
	}
	op, err := h.update.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteRoleRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.RoleID(req.GetRoleId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	r, err := h.get.Execute(ctx, domain.RoleID(req.GetRoleId()))
	if err != nil {
		return nil, err
	}
	pb, err := roleToPb(r)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal role")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	// #184: page_size > MaxPageSize → sync INVALID_ARGUMENT (no silent clamp).
	// First statement so a malformed page_size is rejected before any work.
	if _, err := corevalidate.PageSize("page_size", req.GetPageSize()); err != nil {
		return nil, err
	}
	filter := reporole.ListFilter{
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
		// #185: scope the catalog to a single Account (system + that Account's
		// custom roles). Empty → unscoped (subject to per-object visibility).
		AccountID: domain.AccountID(req.GetAccountId()),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Role, 0, len(rows))
	for _, r := range rows {
		pb, err := roleToPb(r)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal role")
		}
		out = append(out, pb)
	}
	return &iamv1.ListRolesResponse{Roles: out, NextPageToken: next}, nil
}

func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListRoleOperationsRequest) (*iamv1.ListRoleOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetRoleId(), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetRoleId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListRoleOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ----- helpers -----

// roleFromCreateReq maps a CreateRoleRequest into the domain.Role for the
// use-case. BOTH scope columns are mapped (account_id XOR project_id, #212) —
// the use-case enforces the XOR. IsSystem is always false (system roles are
// seeded by migration, never via this RPC).
func roleFromCreateReq(req *iamv1.CreateRoleRequest) domain.Role {
	return domain.Role{
		AccountID:   domain.AccountID(req.GetAccountId()),
		ProjectID:   domain.ProjectID(req.GetProjectId()),
		Name:        domain.RoleName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Rules:       rulesFromProto(req.GetRules()),
		// labels — own-resource метки самого ресурса Role (T3.3); НЕ путать с
		// Rule.MatchLabels (object-selector внутри правила).
		Labels:   labelsFromProto(req.GetLabels()),
		IsSystem: false,
	}
}

// rulesFromProto maps the authored proto rules into domain.Rule, preserving the
// selector arm (resource_names XOR match_labels). Empty input → empty slice.
func rulesFromProto(in []*iamv1.Rule) domain.Rules {
	out := make(domain.Rules, 0, len(in))
	for _, r := range in {
		out = append(out, domain.Rule{
			Module:        r.GetModule(),
			Resources:     append([]string(nil), r.GetResources()...),
			Verbs:         append([]string(nil), r.GetVerbs()...),
			ResourceNames: append([]string(nil), r.GetResourceNames()...),
			MatchLabels:   r.GetMatchLabels(),
		})
	}
	return out
}

func roleToPb(r domain.Role) (*iamv1.Role, error) {
	any, err := marshalRole(r)
	if err != nil {
		return nil, err
	}
	var pb iamv1.Role
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
