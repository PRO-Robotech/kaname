// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package project — use-case-структура ProjectService.
// Реализует iamv1.ProjectServiceServer.
package project

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

type Handler struct {
	iamv1.UnimplementedProjectServiceServer

	create *CreateProjectUseCase
	update *UpdateProjectUseCase
	delete *DeleteProjectUseCase
	get    *GetProjectUseCase
	list   *ListProjectsUseCase
	listOp *shared.ListOperationsUseCase
}

func NewHandler(c *CreateProjectUseCase, u *UpdateProjectUseCase, d *DeleteProjectUseCase,
	g *GetProjectUseCase, l *ListProjectsUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateProjectRequest) (*operationpb.Operation, error) {
	p := domain.Project{
		AccountID:   domain.AccountID(req.GetAccountId()),
		Name:        domain.ProjectName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Labels:      labelsFromProto(req.GetLabels()),
	}
	op, err := h.create.Execute(ctx, p)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateProjectRequest) (*operationpb.Operation, error) {
	in := UpdateProjectInput{
		ID: domain.ProjectID(req.GetProjectId()),
	}
	if name := req.GetName(); name != "" {
		n := domain.ProjectName(name)
		in.Name = &n
	}
	if desc := req.GetDescription(); desc != "" {
		d := domain.Description(desc)
		in.Description = &d
	}
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

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteProjectRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.ProjectID(req.GetProjectId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetProjectRequest) (*iamv1.Project, error) {
	p, err := h.get.Execute(ctx, domain.ProjectID(req.GetProjectId()))
	if err != nil {
		return nil, err
	}
	pb, err := projectToPb(p)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal project")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListProjectsRequest) (*iamv1.ListProjectsResponse, error) {
	filter := repoproject.ListFilter{
		AccountID: domain.AccountID(req.GetAccountId()),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Project, 0, len(rows))
	for _, p := range rows {
		pb, err := projectToPb(p)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal project")
		}
		out = append(out, pb)
	}
	return &iamv1.ListProjectsResponse{Projects: out, NextPageToken: next}, nil
}

func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListProjectOperationsRequest) (*iamv1.ListProjectOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetProjectId(), domain.PrefixProject, "project"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetProjectId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListProjectOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ----- shared utils (parity с account/handler.go) -----

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

func projectToPb(p domain.Project) (*iamv1.Project, error) {
	any, err := marshalProject(p)
	if err != nil {
		return nil, err
	}
	var pb iamv1.Project
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
