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
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/kacho-corelib/operations"
	"github.com/PRO-Robotech/kacho-corelib/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedInternalAuthorizeServiceServer
	writer *service.RelationProjector
	ops    operations.Repo
	// mu guards currentModelID: ReloadModel runs per-gRPC-goroutine and does a
	// read-modify-write on it, so concurrent invocations would race without it.
	mu sync.Mutex
	// currentModelID — the live authorization_model_id; captured at process start
	// from the injected config value and mutated by ReloadModel. Guarded by mu.
	currentModelID string
	// defaultModelID — the composition-root-configured model id (immutable). Used
	// as the fallback for an empty ReloadModel request instead of a request-time
	// os.Getenv read (which would drift from the model the process was started
	// with, and scatters config access into the transport layer).
	defaultModelID string
}

// NewHandler — builder. modelID is the composition-root-configured
// authorization_model_id (the single source of truth), used both as the initial
// live id and as the empty-request ReloadModel fallback.
func NewHandler(writer *service.RelationProjector, ops operations.Repo, modelID string) *Handler {
	return &Handler{writer: writer, ops: ops, currentModelID: modelID, defaultModelID: modelID}
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

// ReloadModel — see iamv1.InternalAuthorizeServiceServer.
func (h *Handler) ReloadModel(ctx context.Context, req *iamv1.ReloadModelRequest) (*iamv1.ReloadModelResponse, error) {
	newID := req.GetAuthorizationModelId()
	if newID == "" {
		// Fall back to the composition-root-configured default (injected at
		// construction) — NOT a request-time env read (config drift / layering).
		newID = h.defaultModelID
	}
	h.mu.Lock()
	if newID != "" {
		h.currentModelID = newID
	}
	current := h.currentModelID
	h.mu.Unlock()
	return &iamv1.ReloadModelResponse{
		AuthorizationModelId: current,
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
