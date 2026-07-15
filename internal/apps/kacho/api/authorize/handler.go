// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authorize — AuthorizeService gRPC handler.
// Thin transport-layer wrapper around the service.AuthorizeService use-case.
//
// Subject binding: handler accepts subject directly from the protobuf
// request (api-gateway interceptor enforces that the caller can only query
// authz decisions about itself or about subjects in folders where the
// caller holds `iam.subjects.checkAuthorization` — that gating happens at
// the gateway, NOT here).
package authorize

import (
	"context"
	stderrors "errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Fixed client-facing messages for non-validation failures. Raw use-case /
// OpenFGA error text ("authz listObjects: <transport detail>", "authz
// unavailable: <raw>") embeds authz-backend topology (store id, endpoint,
// status) and MUST NOT reach the caller (CWE-209). The detailed error is
// logged server-side instead. Deterministic "Illegal argument …" validation
// text is safe and is surfaced verbatim.
const (
	msgAuthzUnavailable = "authorization backend unavailable"
	msgAuthzInternal    = "internal error"
)

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedAuthorizeServiceServer
	svc    *service.AuthorizeService
	whoAmI *WhoAmIUseCase
	// authority — FGA relation checker for the inner caller-authority gate
	// (caller_authority.go). Optional / nil-safe: when unset the gate can still
	// allow self-queries and passes through anonymous/system module PDP calls,
	// but denies a non-self tenant principal that cannot be proven cluster-admin
	// or resource-authority (fail-closed). Wired to the OpenFGA client in the
	// composition root via WithCallerAuthority.
	authority authzguard.RelationChecker
	// prodMode — production AuthN mode (cfg.AuthN.Mode.IsProduction()). It governs
	// the inner caller-authority gate's treatment of an anonymous/system principal
	// that carries NO verified module cert: in production such a caller is on the
	// PUBLIC listener (no module-cert floor) and is DENIED (fail-closed); in dev
	// (insecure listener, no mTLS at all) it is allowed (back-compat, mirroring
	// authzguard.CallerPolicy / RelationWriteGate). Set via WithProductionMode.
	prodMode bool
}

// NewHandler — builder. Both svc and whoAmI are required (composition root
// wires both unconditionally; nil at construction time means a wiring bug).
func NewHandler(svc *service.AuthorizeService, whoAmI *WhoAmIUseCase) *Handler {
	return &Handler{svc: svc, whoAmI: whoAmI}
}

// WithCallerAuthority injects the FGA relation checker used by the inner
// caller-authority defense-in-depth gate. Returns the receiver for chaining.
func (h *Handler) WithCallerAuthority(checker authzguard.RelationChecker) *Handler {
	h.authority = checker
	return h
}

// WithProductionMode toggles fail-closed enforcement of the inner
// caller-authority gate for anonymous/system principals without a verified
// module cert (the public-listener bypass). Defaults to dev-mode (permissive
// back-compat); the composition root enables it from cfg.AuthN.Mode.IsProduction().
// Returns the receiver for chaining.
func (h *Handler) WithProductionMode(prod bool) *Handler {
	h.prodMode = prod
	return h
}

// Check — see iamv1.AuthorizeServiceServer.
func (h *Handler) Check(ctx context.Context, req *iamv1.AuthorizeCheckRequest) (*iamv1.AuthorizeCheckResponse, error) {
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument subject: required")
	}
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument action: required")
	}
	// Inner defense-in-depth: a tenant principal may only Check about itself, a
	// resource it administers, or as a cluster-admin (caller_authority.go).
	if err := h.authorizeCaller(ctx, req.GetSubject(), req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.Check(ctx, service.CheckRequest{
		Subject: req.GetSubject(),
		Resource: service.ResourceRef{
			Type: req.GetResource().GetType(),
			ID:   req.GetResource().GetId(),
		},
		Action:           req.GetAction(),
		RequiredRelation: req.GetRequiredRelation(),
		Context:          structToMap(req.GetContext()),
	})
	if err != nil {
		// Validation errors → InvalidArgument (verbatim, safe); backend errors →
		// Unavailable/Internal with a fixed, redacted message (no raw pgx/FGA leak).
		// Backend-unavailable is classified by the typed iamerr.ErrUnavailable
		// sentinel (robust to error-text rewording), NOT an error-string prefix.
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if stderrors.Is(err, iamerr.ErrUnavailable) {
			slog.ErrorContext(ctx, "authorize backend unavailable", "op", "Check", "err", err.Error())
			return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
		}
		slog.ErrorContext(ctx, "authorize internal error", "op", "Check", "err", err.Error())
		return nil, status.Error(codes.Internal, msgAuthzInternal)
	}
	return &iamv1.AuthorizeCheckResponse{
		Allowed:              res.Allowed,
		DenyReasons:          res.DenyReasons,
		AuthorizationModelId: res.AuthorizationModelID,
		CheckedAt:            shared.TimestampProto(res.CheckedAt),
	}, nil
}

// BatchCheck — see iamv1.AuthorizeServiceServer.
func (h *Handler) BatchCheck(ctx context.Context, req *iamv1.BatchAuthorizeCheckRequest) (*iamv1.BatchAuthorizeCheckResponse, error) {
	if len(req.GetChecks()) > 100 {
		return nil, status.Errorf(codes.InvalidArgument, "Illegal argument checks: batch size %d > 100", len(req.GetChecks()))
	}
	// Inner defense-in-depth: gate every item's subject/resource before fanning
	// out — a single unauthorized item denies the whole batch (caller_authority.go).
	for _, c := range req.GetChecks() {
		if err := h.authorizeCaller(ctx, c.GetSubject(), c.GetResource()); err != nil {
			return nil, err
		}
	}
	reqs := make([]service.CheckRequest, 0, len(req.GetChecks()))
	for _, c := range req.GetChecks() {
		reqs = append(reqs, service.CheckRequest{
			Subject: c.GetSubject(),
			Resource: service.ResourceRef{
				Type: c.GetResource().GetType(),
				ID:   c.GetResource().GetId(),
			},
			Action:           c.GetAction(),
			RequiredRelation: c.GetRequiredRelation(),
			Context:          structToMap(c.GetContext()),
		})
	}
	results, err := h.svc.BatchCheck(ctx, reqs)
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		// Backend-unavailable fails the whole batch (mirror Check): surface a
		// retryable Unavailable with the fixed redacted text, never the raw FGA
		// transport error (endpoint/store id leak).
		if stderrors.Is(err, iamerr.ErrUnavailable) {
			slog.ErrorContext(ctx, "authorize backend unavailable", "op", "BatchCheck", "err", err.Error())
			return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
		}
		slog.ErrorContext(ctx, "authorize internal error", "op", "BatchCheck", "err", err.Error())
		return nil, status.Error(codes.Internal, msgAuthzInternal)
	}
	out := &iamv1.BatchAuthorizeCheckResponse{
		Responses: make([]*iamv1.AuthorizeCheckResponse, len(results)),
	}
	for i, r := range results {
		out.Responses[i] = &iamv1.AuthorizeCheckResponse{
			Allowed:              r.Allowed,
			DenyReasons:          r.DenyReasons,
			AuthorizationModelId: r.AuthorizationModelID,
			CheckedAt:            shared.TimestampProto(r.CheckedAt),
		}
	}
	return out, nil
}

// ListObjects — see iamv1.AuthorizeServiceServer.
func (h *Handler) ListObjects(ctx context.Context, req *iamv1.ListObjectsRequest) (*iamv1.ListObjectsResponse, error) {
	// Inner defense-in-depth: ListObjects has no single resource scope, so a
	// tenant caller may only enumerate its OWN visible objects or act as a
	// cluster-admin (caller_authority.go).
	if err := h.authorizeCaller(ctx, req.GetSubject(), nil); err != nil {
		return nil, err
	}
	res, err := h.svc.ListObjects(ctx, service.ListObjectsRequest{
		Subject:      req.GetSubject(),
		ResourceType: req.GetResourceType(),
		Action:       req.GetAction(),
		MaxResults:   int(req.GetMaxResults()),
		PageToken:    req.GetPageToken(),
		Context:      structToMap(req.GetContext()),
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.ErrorContext(ctx, "authorize backend unavailable", "op", "ListObjects", "err", err.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	}
	return &iamv1.ListObjectsResponse{
		ResourceIds: res.ResourceIDs,
		Truncated:   res.Truncated,
	}, nil
}

// ListSubjects — see iamv1.AuthorizeServiceServer.
func (h *Handler) ListSubjects(ctx context.Context, req *iamv1.ListSubjectsRequest) (*iamv1.ListSubjectsResponse, error) {
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument action: required")
	}
	// Inner defense-in-depth: ListSubjects enumerates WHO can act on a resource,
	// so a tenant caller must administer that resource or be a cluster-admin
	// (caller_authority.go) — otherwise it leaks the resource's authz graph.
	if err := h.authorizeCaller(ctx, "", req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.ListSubjects(ctx, service.ListSubjectsRequest{
		ResourceType:      req.GetResource().GetType(),
		ResourceID:        req.GetResource().GetId(),
		Action:            req.GetAction(),
		PageSize:          int(req.GetPageSize()),
		PageToken:         req.GetPageToken(),
		SubjectTypeFilter: req.GetSubjectTypeFilter(),
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.ErrorContext(ctx, "authorize backend unavailable", "op", "ListSubjects", "err", err.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	}
	return &iamv1.ListSubjectsResponse{
		Subjects:      res.Subjects,
		NextPageToken: res.NextPageToken,
	}, nil
}

// ExpandRelations — see iamv1.AuthorizeServiceServer.
func (h *Handler) ExpandRelations(ctx context.Context, req *iamv1.ExpandRelationsRequest) (*iamv1.ExpandRelationsResponse, error) {
	if req.GetResource() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument resource: required")
	}
	if req.GetRelation() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument relation: required")
	}
	// Inner defense-in-depth: ExpandRelations discloses the full userset tree of
	// a resource, so a tenant caller must administer that resource or be a
	// cluster-admin (caller_authority.go).
	if err := h.authorizeCaller(ctx, "", req.GetResource()); err != nil {
		return nil, err
	}
	res, err := h.svc.ExpandRelations(ctx, service.ExpandRequest{
		ResourceType: req.GetResource().GetType(),
		ResourceID:   req.GetResource().GetId(),
		Relation:     req.GetRelation(),
		MaxDepth:     int(req.GetMaxDepth()),
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "Illegal argument") {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.ErrorContext(ctx, "authorize backend unavailable", "op", "ExpandRelations", "err", err.Error())
		return nil, status.Error(codes.Unavailable, msgAuthzUnavailable)
	}
	return &iamv1.ExpandRelationsResponse{
		Resource:             &iamv1.ResourceRef{Type: res.Resource.Type, Id: res.Resource.ID},
		Relation:             res.Relation,
		Tree:                 treeToProto(res.Tree),
		AuthorizationModelId: res.AuthorizationModelID,
	}, nil
}

// treeToProto — service.ExpandTree → iamv1.UsersetTree (recursive).
func treeToProto(t *authztypes.ExpandTree) *iamv1.UsersetTree {
	if t == nil {
		return nil
	}
	out := &iamv1.UsersetTree{
		Leaves:    append([]string(nil), t.Leaves...),
		Truncated: t.Truncated,
	}
	for _, e := range t.Computed {
		out.Computed = append(out.Computed, &iamv1.ComputedUsersetEdge{
			Relation: e.Relation,
			Subtree:  treeToProto(e.Subtree),
		})
	}
	for _, e := range t.TupleToUserset {
		out.TupleToUserset = append(out.TupleToUserset, &iamv1.TupleToUsersetEdge{
			Parent:   &iamv1.ResourceRef{Type: e.ParentType, Id: e.ParentID},
			Relation: e.Relation,
			Subtree:  treeToProto(e.Subtree),
		})
	}
	return out
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// WhoAmI — see iamv1.AuthorizeServiceServer. Marshals the WhoAmI
// use-case result into the proto response shape. The use-case is the
// authoritative gate (anonymous → Unauthenticated); the handler is the
// thin transport wrapper.
func (h *Handler) WhoAmI(ctx context.Context, _ *iamv1.WhoAmIRequest) (*iamv1.WhoAmIResponse, error) {
	res, err := h.whoAmI.Execute(ctx)
	if err != nil {
		// use-case already returns status.Error for terminal cases
		// (Unauthenticated, Unavailable, NotFound). Anything else is
		// shaped through shared.MapRepoErr inside the use-case.
		return nil, err
	}
	accounts := make([]*iamv1.AccountMembership, 0, len(res.Accounts))
	for _, a := range res.Accounts {
		accounts = append(accounts, &iamv1.AccountMembership{
			AccountId:   string(a.AccountID),
			AccountName: a.AccountName,
			Roles:       append([]string(nil), a.Roles...),
		})
	}
	return &iamv1.WhoAmIResponse{
		Subject:       res.Subject,
		UserId:        string(res.UserID),
		Email:         res.Email,
		DisplayName:   res.DisplayName,
		SystemAdmin:   res.SystemAdmin,
		ClusterViewer: res.ClusterViewer,
		Accounts:      accounts,
		CheckedAt:     shared.TimestampProto(res.CheckedAt),
	}, nil
}
