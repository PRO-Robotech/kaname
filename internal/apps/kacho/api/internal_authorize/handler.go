// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package internal_authorize — InternalAuthorizeService (kacho-only,
// port 9091) handler.
//
// Internal-only (ban #6: Internal.* not published on the external TLS endpoint) —
// NOT registered on the external TLS listener. Used by:
//
//   - kacho-iam outbox-worker (WriteTuples on AccessBinding lifecycle).
//   - admin-UI / oncall (ReadTuples, GetFGAStoreInfo).
//   - openfga-bootstrap-job (ReloadModel after model write).
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
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedInternalAuthorizeServiceServer
	writer *service.RelationProjector
	ops    operations.Repo
	// modelID — the env-configured authorization_model_id the process is pinned
	// to. Immutable for the process lifetime: the OpenFGA client captures this id
	// at construction (composition root) and every Check/Write/ListObjects sends
	// it; nothing re-reads a handler field at evaluation time. ReloadModel reports
	// this id — it does NOT re-pin the live client (see ReloadModel).
	modelID string
}

// NewHandler — builder. modelID is the composition-root-configured
// authorization_model_id (the single source of truth) the process is pinned to.
func NewHandler(writer *service.RelationProjector, ops operations.Repo, modelID string) *Handler {
	return &Handler{writer: writer, ops: ops, modelID: modelID}
}

// WriteTuples — see iamv1.InternalAuthorizeServiceServer.
func (h *Handler) WriteTuples(ctx context.Context, req *iamv1.WriteTuplesRequest) (*operationpb.Operation, error) {
	writes := protoTuplesToInternal(req.GetWrites())
	deletes := protoTuplesToInternal(req.GetDeletes())
	// OpenFGA's maxTuplesPerWrite (100) caps writes+deletes COMBINED per /write
	// request, and this admin path (writer.WriteRaw → WriteConditionalTuples) does
	// NOT chunk — so the guard must count both directions together, not each ≤100
	// independently (60+60 would pass a per-direction guard yet be rejected wholesale
	// by OpenFGA as a single 121-tuple request).
	if len(writes)+len(deletes) > 100 {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument writes/deletes: ≤100 combined per batch")
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		"InternalAuthorize.WriteTuples",
		&iamv1.WriteTuplesMetadata{IdempotencyKey: req.GetIdempotencyKey()},
	)
	if err != nil {
		// Opaque INTERNAL — never echo err.Error() (leak of pgx/DB driver text).
		return nil, status.Error(codes.Internal, "create operation failed")
	}
	if err := h.ops.Create(ctx, op); err != nil {
		return nil, status.Error(codes.Internal, "create operation failed")
	}
	operations.Run(ctx, h.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		ins, del, werr := h.writer.WriteRaw(ctx, writes, deletes)
		if werr != nil {
			return nil, werr
		}
		return anypb.New(&iamv1.WriteTuplesResult{
			Inserted: safeconv.IntToInt32(ins),
			Deleted:  safeconv.IntToInt32(del),
		})
	})
	return shared.OperationToProto(&op), nil
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

// ── helpers ──

func protoTuplesToInternal(tuples []*iamv1.Tuple) []authztypes.ConditionalTuple {
	out := make([]authztypes.ConditionalTuple, 0, len(tuples))
	for _, t := range tuples {
		tup := authztypes.ConditionalTuple{
			User:     t.GetSubject(),
			Relation: t.GetRelation(),
			Object:   t.GetObject(),
		}
		if cnd := t.GetCondition(); cnd != nil {
			name := cnd.GetConditionId()
			if name == "" {
				name = cnd.GetBuiltin().String()
			}
			tup.Condition = &authztypes.TupleConditionRef{
				Name:    name,
				Context: structToMap(cnd.GetContext()),
			}
		}
		out = append(out, tup)
	}
	return out
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}
