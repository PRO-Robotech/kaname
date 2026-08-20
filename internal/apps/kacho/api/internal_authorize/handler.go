// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package internal_authorize — InternalAuthorizeService (kacho-only,
// port 9091) handler.
//
// Internal-only (ban #6: Internal.* not published on the external TLS endpoint) —
// NOT registered on the external TLS listener. Used by:
//
//   - admin-UI / oncall (ReadTuples, GetFGAStoreInfo).
//   - openfga-bootstrap-job (ReloadModel after model write).
//
// The handler is READ-ONLY with respect to the relation store. The former
// WriteTuples RPC — batch write straight into the engine, past
// `kacho_iam.fga_outbox` — was retired with zero callers (#788); writing a tuple
// is expressed as a journal row and nothing else.
//
// The former RunRegoTest RPC was retired from the proto: in-process Rego
// was out of scope; oncall runs `opa eval`
// against the staging bundle directly. No method exists on the embedded
// UnimplementedInternalAuthorizeServiceServer anymore.
package internal_authorize

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedInternalAuthorizeServiceServer
	writer *service.RelationProjector
	// modelID — the env-configured authorization_model_id the process is pinned
	// to. Immutable for the process lifetime: the OpenFGA client captures this id
	// at construction (composition root) and every Check/Write/ListObjects sends
	// it; nothing re-reads a handler field at evaluation time. ReloadModel reports
	// this id — it does NOT re-pin the live client (see ReloadModel).
	modelID string
}

// NewHandler — builder. modelID is the composition-root-configured
// authorization_model_id (the single source of truth) the process is pinned to.
//
// No operations repo is taken: every RPC of this service is a synchronous read,
// and the only Operation-producing method it ever had was the retired WriteTuples.
func NewHandler(writer *service.RelationProjector, modelID string) *Handler {
	return &Handler{writer: writer, modelID: modelID}
}

// ReadTuples — see iamv1.InternalAuthorizeServiceServer.
func (h *Handler) ReadTuples(ctx context.Context, req *iamv1.ReadTuplesRequest) (*iamv1.ReadTuplesResponse, error) {
	tuples, next, err := h.writer.ReadRaw(ctx,
		req.GetSubjectFilter(),
		req.GetRelationFilter(),
		req.GetObjectFilter(),
		int(req.GetPageSize()),
		req.GetPageToken(),
	)
	if err != nil {
		// Opaque UNAVAILABLE — never echo err.Error(): the raw OpenFGA transport
		// error carries the cluster-internal FGA endpoint host:port / connection
		// string (leak, applies on :9091 too). Fixed text mirrors authzguard.
		return nil, status.Error(codes.Unavailable, "authz backend unavailable")
	}
	pbs := make([]*iamv1.Tuple, 0, len(tuples))
	for _, t := range tuples {
		pb := &iamv1.Tuple{
			Subject:  t.User,
			Relation: t.Relation,
			Object:   t.Object,
		}
		if t.Condition != nil {
			pb.Condition = &iamv1.TupleCondition{
				Selector: &iamv1.TupleCondition_ConditionId{ConditionId: t.Condition.Name},
			}
		}
		pbs = append(pbs, pb)
	}
	return &iamv1.ReadTuplesResponse{
		Tuples:        pbs,
		NextPageToken: next,
	}, nil
}

// ReloadModel — reports the live authorization_model_id the process is pinned to.
//
// The pin is env-configured (KACHO_IAM_OPENFGA_MODEL_ID) and captured by the
// OpenFGA client at construction: every Check/Write/ListObjects sends that id for
// the process lifetime. A runtime re-pin is NOT supported — adopting a new model
// requires a process restart with the new env value. The caller-supplied
// authorization_model_id is therefore advisory only; this RPC reports the id
// currently in force and does not mutate live authz evaluation (doc-truthfulness:
// the handler previously mutated a field no evaluation path ever read).
func (h *Handler) ReloadModel(_ context.Context, _ *iamv1.ReloadModelRequest) (*iamv1.ReloadModelResponse, error) {
	return &iamv1.ReloadModelResponse{
		AuthorizationModelId: h.modelID,
		ReloadedAt:           shared.TimestampProto(time.Now().UTC()),
	}, nil
}

// GetFGAStoreInfo — see iamv1.InternalAuthorizeServiceServer.
func (h *Handler) GetFGAStoreInfo(ctx context.Context, _ *iamv1.GetFGAStoreInfoRequest) (*iamv1.GetFGAStoreInfoResponse, error) {
	info, err := h.writer.StoreInfo(ctx)
	if err != nil {
		// Opaque UNAVAILABLE — never echo err.Error() (FGA host:port / connection
		// string leak, applies on :9091 too). Fixed text mirrors authzguard.
		return nil, status.Error(codes.Unavailable, "authz backend unavailable")
	}
	resp := &iamv1.GetFGAStoreInfoResponse{
		StoreId:              info.StoreID,
		AuthorizationModelId: info.AuthorizationModelID,
		TupleCount:           info.TupleCount,
		ModelBuildSha:        info.ModelBuildSHA,
		FgaEngineVersion:     info.EngineVersion,
	}
	if !info.ModelCreatedAt.IsZero() {
		resp.ModelCreatedAt = shared.TimestampProto(info.ModelCreatedAt)
	}
	return resp, nil
}
