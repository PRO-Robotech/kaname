// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package group — GroupService + member-management.
package group

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
)

type Handler struct {
	iamv1.UnimplementedGroupServiceServer

	create       *CreateGroupUseCase
	update       *UpdateGroupUseCase
	delete       *DeleteGroupUseCase
	get          *GetGroupUseCase
	list         *ListGroupsUseCase
	addMember    *AddMemberUseCase
	removeMember *RemoveMemberUseCase
	listMembers  *ListMembersUseCase
	listOp       *shared.ListOperationsUseCase
}

func NewHandler(c *CreateGroupUseCase, u *UpdateGroupUseCase, d *DeleteGroupUseCase,
	g *GetGroupUseCase, l *ListGroupsUseCase,
	am *AddMemberUseCase, rm *RemoveMemberUseCase, lm *ListMembersUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l,
		addMember: am, removeMember: rm, listMembers: lm}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateGroupRequest) (*operationpb.Operation, error) {
	g := domain.Group{
		AccountID:   domain.AccountID(req.GetAccountId()),
		Name:        domain.GroupName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Labels:      labelsFromProto(req.GetLabels()),
	}
	op, err := h.create.Execute(ctx, g)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateGroupRequest) (*operationpb.Operation, error) {
	in := UpdateGroupInput{
		ID: domain.GroupID(req.GetGroupId()),
	}
	if name := req.GetName(); name != "" {
		n := domain.GroupName(name)
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

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteGroupRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.GroupID(req.GetGroupId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetGroupRequest) (*iamv1.Group, error) {
	g, err := h.get.Execute(ctx, domain.GroupID(req.GetGroupId()))
	if err != nil {
		return nil, err
	}
	pb, err := groupToPb(g)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal group")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListGroupsRequest) (*iamv1.ListGroupsResponse, error) {
	filter := repogroup.ListFilter{
		AccountID: domain.AccountID(req.GetAccountId()),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Group, 0, len(rows))
	for _, g := range rows {
		pb, err := groupToPb(g)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal group")
		}
		out = append(out, pb)
	}
	return &iamv1.ListGroupsResponse{Groups: out, NextPageToken: next}, nil
}

func (h *Handler) AddMember(ctx context.Context, req *iamv1.AddGroupMemberRequest) (*operationpb.Operation, error) {
	in := AddMemberInput{
		GroupID:    domain.GroupID(req.GetGroupId()),
		MemberType: domain.SubjectType(req.GetMemberType()),
		MemberID:   domain.SubjectID(req.GetMemberId()),
	}
	op, err := h.addMember.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) RemoveMember(ctx context.Context, req *iamv1.RemoveGroupMemberRequest) (*operationpb.Operation, error) {
	in := RemoveMemberInput{
		GroupID:    domain.GroupID(req.GetGroupId()),
		MemberType: domain.SubjectType(req.GetMemberType()),
		MemberID:   domain.SubjectID(req.GetMemberId()),
	}
	op, err := h.removeMember.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) ListMembers(ctx context.Context, req *iamv1.ListGroupMembersRequest) (*iamv1.ListGroupMembersResponse, error) {
	members, err := h.listMembers.Execute(ctx, domain.GroupID(req.GetGroupId()))
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.GroupMember, 0, len(members))
	for _, m := range members {
		pb, err := groupMemberToPb(m)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal group member")
		}
		out = append(out, pb)
	}
	return &iamv1.ListGroupMembersResponse{Members: out}, nil
}

func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListGroupOperationsRequest) (*iamv1.ListGroupOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetGroupId(), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetGroupId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListGroupOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ----- helpers -----

func groupToPb(g domain.Group) (*iamv1.Group, error) {
	any, err := marshalGroup(g)
	if err != nil {
		return nil, err
	}
	var pb iamv1.Group
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}

func groupMemberToPb(m domain.GroupMember) (*iamv1.GroupMember, error) {
	any, err := marshalGroupMember(m)
	if err != nil {
		return nil, err
	}
	var pb iamv1.GroupMember
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
