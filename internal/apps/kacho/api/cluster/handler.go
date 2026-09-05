// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// handler.go — thin gRPC transport layer for InternalClusterService.
//
// Запрет #6: this handler is registered ONLY on the internal listener (:9091).
// Never on the external TLS endpoint.
//
// Each method delegates immediately to the appropriate use-case; no business
// logic lives here — only request parsing and response formatting.

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Handler implements iamv1.InternalClusterServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalClusterServiceServer

	get    *GetClusterUseCase
	grant  *GrantAdminUseCase
	revoke *RevokeAdminUseCase
	list   *ListAdminsUseCase
}

// NewHandler assembles the Handler from the four use-cases.
// Composition root: cmd/kacho-iam/wiring.go.
func NewHandler(
	get *GetClusterUseCase,
	grant *GrantAdminUseCase,
	revoke *RevokeAdminUseCase,
	list *ListAdminsUseCase,
) *Handler {
	return &Handler{get: get, grant: grant, revoke: revoke, list: list}
}

// Get — returns the singleton cluster row.
func (h *Handler) Get(ctx context.Context, _ *iamv1.GetClusterRequest) (*iamv1.Cluster, error) {
	c, err := h.get.Execute(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return clusterToProto(c), nil
}

// GrantAdmin — grants cluster-admin authority to a subject (synchronous).
//
// REST default: `DELETE /iam/v1/internal/cluster/admins/{subject_id}` and
// `POST  /iam/v1/internal/cluster/admins` URL patterns don't carry
// subject_type — REST clients (UI/curl) typically omit it, defaulting
// to UNSPECIFIED. Since USER is the only supported value in this version
// (per validation in use-case), substitute UNSPECIFIED → USER here so
// REST callers don't see 400 "only 'user' supported".
func (h *Handler) GrantAdmin(ctx context.Context, req *iamv1.GrantClusterAdminRequest) (*operationpb.Operation, error) {
	st := req.GetSubjectType()
	if st == iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED {
		st = iamv1.ClusterGrantSubjectType_USER
	}
	return h.grant.Execute(ctx, st, req.GetSubjectId())
}

// RevokeAdmin — revokes cluster-admin authority from a subject (synchronous).
// Same UNSPECIFIED → USER default as GrantAdmin (REST URL only carries id).
func (h *Handler) RevokeAdmin(ctx context.Context, req *iamv1.RevokeClusterAdminRequest) (*operationpb.Operation, error) {
	st := req.GetSubjectType()
	if st == iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED {
		st = iamv1.ClusterGrantSubjectType_USER
	}
	return h.revoke.Execute(ctx, st, req.GetSubjectId())
}

// ListAdmins — returns all currently-active cluster admin entries.
func (h *Handler) ListAdmins(ctx context.Context, _ *iamv1.ListClusterAdminsRequest) (*iamv1.ListClusterAdminsResponse, error) {
	entries, err := h.list.Execute(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	admins := make([]*iamv1.ClusterAdminEntry, 0, len(entries))
	for _, e := range entries {
		admins = append(admins, clusterAdminEntryToProto(e))
	}
	return &iamv1.ListClusterAdminsResponse{Admins: admins}, nil
}

// ── DTO helpers ──────────────────────────────────────────────────────────────

func clusterToProto(c domain.Cluster) *iamv1.Cluster {
	var createdAt *timestamppb.Timestamp
	if !c.CreatedAt.IsZero() {
		createdAt = timestamppb.New(c.CreatedAt.Truncate(1_000_000_000))
	}
	return &iamv1.Cluster{
		Id:          string(c.ID),
		Name:        string(c.Name),
		Description: string(c.Description),
		CreatedAt:   createdAt,
	}
}

// clusterGrantSubjectTypeToProto maps the stored `subject_type` to the wire
// enum. It used to be hard-coded to USER — harmless while every row was a user
// grant, but migration 0058 seeds a cluster system_admin grant for the
// bootstrap-admin ServiceAccount, which ListAdmins then reported as a human
// USER holding an `sva…` id. An unrecognised value stays UNSPECIFIED rather
// than claiming a type the row does not carry.
func clusterGrantSubjectTypeToProto(subjectType string) iamv1.ClusterGrantSubjectType {
	switch domain.GrantSubjectType(subjectType) {
	case domain.GrantSubjectTypeUser:
		return iamv1.ClusterGrantSubjectType_USER
	case domain.GrantSubjectTypeServiceAccount:
		return iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT
	default:
		return iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED
	}
}

// clusterAdminGrantToProto — the ClusterAdminGrant resource, as declared for
// the `response` of GrantAdmin / RevokeAdmin. `rationale` has no column on the
// row, so it stays empty rather than being invented here.
func clusterAdminGrantToProto(g domain.ClusterAdminGrant) *iamv1.ClusterAdminGrant {
	return &iamv1.ClusterAdminGrant{
		Id:              string(g.ID),
		SubjectType:     clusterGrantSubjectTypeToProto(string(g.SubjectType)),
		SubjectId:       string(g.SubjectID),
		GrantedByUserId: g.GrantedBy,
		GrantedAt:       timestamppb.New(g.GrantedAt.Truncate(1_000_000_000)),
	}
}

func clusterAdminEntryToProto(e domain.ClusterAdminEntry) *iamv1.ClusterAdminEntry {
	return &iamv1.ClusterAdminEntry{
		ClusterAdminGrantId: e.ClusterAdminGrantID,
		SubjectType:         clusterGrantSubjectTypeToProto(e.SubjectType),
		SubjectId:           e.SubjectID,
		SubjectEmail:        e.SubjectEmail,
		GrantedByUserId:     e.GrantedByUserID,
		GrantedByEmail:      e.GrantedByEmail,
		GrantedAt:           timestamppb.New(e.GrantedAt.Truncate(1_000_000_000)),
	}
}
