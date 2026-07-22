// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler.go — gRPC handler for kacho.cloud.iam.v1.SAKeyService.
package sa_keys

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Handler — gRPC server impl.
type Handler struct {
	iamv1.UnimplementedSAKeyServiceServer
	issue  *IssueSAKeyUseCase
	revoke *RevokeSAKeyUseCase
	list   *ListSAKeysUseCase
}

// NewHandler constructs.
func NewHandler(issue *IssueSAKeyUseCase, revoke *RevokeSAKeyUseCase, list *ListSAKeysUseCase) *Handler {
	return &Handler{issue: issue, revoke: revoke, list: list}
}

// Issue implements SAKeyService.Issue.
//
// Identity-spoofing guard: `created_by_user_id` MUST come from the
// authenticated principal; request-body value is only accepted when it matches
// the principal (strict reject per OQ-3 — silent-override hides client bugs).
func (h *Handler) Issue(ctx context.Context, req *iamv1.IssueSAKeyRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" {
		return nil, authzguard.PermissionDenied()
	}
	// Admin/seed path (#60 SA-key analog): a service-account principal caller (the
	// acr-exempt #58 bootstrap-admin SA, or any system_admin SA the gateway
	// FGA-authorized for v_update@iam_service_account) is not a users(id) row, so it
	// cannot itself be the created_by — forcing created_by=principal would fail the
	// created_by FK (23503) as an opaque async code-9 (issue #60). For an SA caller
	// the use-case records created_by = the target SA's account OWNER (a valid users
	// row, deterministic — never a request-body value, so no spoofing), while the
	// REAL actor (the SA) is still captured in the durable audit_outbox event.
	callerIsServiceAccount := operations.PrincipalFromContext(ctx).Type == "service_account"
	if !callerIsServiceAccount {
		// user/system caller — anti-spoofing: a request-body created_by must match
		// the authenticated principal (or be empty).
		if rv := req.GetCreatedByUserId(); rv != "" && rv != principal {
			return nil, status.Error(codes.InvalidArgument,
				"Illegal argument created_by_user_id: must match authenticated principal or be empty")
		}
	}
	// Phase 3b: federated trusted-subjects passthrough. nil/empty slice keeps
	// Phase 3a private_key_jwt behaviour intact (no schema change for
	// existing callers).
	var ts []domain.TrustedSubject
	if raw := req.GetTrustedSubjects(); len(raw) > 0 {
		ts = make([]domain.TrustedSubject, 0, len(raw))
		for _, r := range raw {
			if r == nil {
				continue
			}
			ts = append(ts, domain.TrustedSubject{
				Issuer:         r.GetIssuer(),
				SubjectPattern: r.GetSubjectPattern(),
			})
		}
	}
	op, err := h.issue.Execute(ctx, IssueInput{
		ServiceAccountID:       domain.ServiceAccountID(req.GetServiceAccountId()),
		Description:            req.GetDescription(),
		TTLSeconds:             req.GetTtlSeconds(),
		CreatedByUserID:        principal,
		CallerIsServiceAccount: callerIsServiceAccount,
		TrustedSubjects:        ts,
		// Create-only metadata: name + labels are set on Issue and immutable
		// (the resource carries only Issue/List/Revoke — no Update).
		Name:   req.GetName(),
		Labels: labelsFromProto(req.GetLabels()),
		// Federation OUT — caller-supplied external audience(s).
		// Empty → use-case falls back to AudiencePrefix (kacho-internal).
		Audience: req.GetAudience(),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Revoke implements SAKeyService.Revoke.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeSAKeyRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	op, err := h.revoke.Execute(ctx, RevokeInput{
		ServiceAccountID: domain.ServiceAccountID(req.GetServiceAccountId()),
		KeyID:            domain.SAOAuthClientID(req.GetKeyId()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// List implements SAKeyService.List.
func (h *Handler) List(ctx context.Context, req *iamv1.ListSAKeysRequest) (*iamv1.ListSAKeysResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	rows, nextToken, err := h.list.Execute(ctx, ListInput{
		ServiceAccountID: domain.ServiceAccountID(req.GetServiceAccountId()),
		PageSize:         safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken:        req.GetPageToken(),
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	out := make([]*iamv1.ServiceAccountOAuthClient, 0, len(rows))
	for _, c := range rows {
		pb, err := saClientToProto(c)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal SA client")
		}
		out = append(out, pb)
	}
	return &iamv1.ListSAKeysResponse{Keys: out, NextPageToken: nextToken}, nil
}
