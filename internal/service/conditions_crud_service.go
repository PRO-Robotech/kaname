// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// conditions_crud_service.go — ConditionsService CRUD use-cases.
//
// Standalone Condition resource (cnd_…) folder-scoped, referenced from
// AccessBinding.condition_ref.condition_id (oneof). Lifecycle:
//
//   - Create → status=CREATING; Operation worker runs `doCreate`:
//   - validates expression syntax via the local ConditionsEvaluator
//     (free-form CEL gets recognised builtin-form OR passes-through to
//     FGA-engine on next WriteAuthorizationModel);
//   - INSERT into `conditions` table;
//   - flips status=ACTIVE (immediate; we don't wait for OpenFGA model
//     re-write — that's done by the openfga-bootstrap-job under helm
//     hook annotations);
//   - Update → CAS on resource_version;
//   - Delete → flip status=DELETING (tombstone), then refcount check, then
//     hard-delete on Operation worker completion;
//   - Evaluate → request-time CEL eval via ConditionsEvaluator.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"

	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/condition"
)

// ConditionsTxWriter — tx-scoped mutation surface used by the audit-atomic
// worker path (each mutation commits together with its audit_outbox row in one
// tx, запрет #10). Takes the opaque service.Tx handle (the concrete pgx.Tx is
// recovered inside the pg adapter via txAsPgx) so the service layer stays
// pgx-free. Implemented by *kachopg.ConditionsRepo.
type ConditionsTxWriter interface {
	InsertTx(ctx context.Context, tx Tx, c domain.Condition) (domain.Condition, error)
	UpdateMutableTx(ctx context.Context, tx Tx, id domain.ConditionID, patch condition.UpdatePatch, expectedVersion int64) (domain.Condition, error)
	SetStatusTx(ctx context.Context, tx Tx, id domain.ConditionID, newStatus domain.ConditionStatus) error
	DeleteTx(ctx context.Context, tx Tx, id domain.ConditionID) error
	CountReferencesTx(ctx context.Context, tx Tx, id domain.ConditionID) (int64, error)
}

// ConditionsRepoPort — full repo interface bundling Reader + Writer +
// tx-scoped mutations.
type ConditionsRepoPort interface {
	condition.ReaderIface
	condition.WriterIface
	ConditionsTxWriter
}

// conditionsTxBeginner — opens a write tx for the audit-atomic worker path.
// Returns the opaque service.Tx; implemented by kachopg.NewPoolTxBeginner in
// the composition root.
type conditionsTxBeginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// conditionsAuditEmitter — port for emitting one durable audit_outbox row inside
// the ConditionsService worker-tx. Atomic with the condition
// mutation (запрет #10). Implemented by *kachopg.AuditOutboxEmitter. nil → emit
// is skipped (degraded/legacy wiring); the mutation contract is unchanged either
// way (purely-additive audit).
type conditionsAuditEmitter interface {
	EmitTx(ctx context.Context, tx Tx, ev AuditEvent) error
}

// ConditionsCRUDService — use-case bundle for the ConditionsService gRPC
// handler.
type ConditionsCRUDService struct {
	repo      ConditionsRepoPort
	ops       operations.Repo
	evaluator ConditionsEvaluator
	// txb — opens the worker-tx so the mutation + audit row commit atomically.
	// nil → the legacy pool-direct path is used (no audit row).
	txb conditionsTxBeginner
	// audit — durable audit_outbox emitter. nil → no audit row.
	audit conditionsAuditEmitter
}

// NewConditionsCRUDService — builder.
func NewConditionsCRUDService(repo ConditionsRepoPort, ops operations.Repo, eval ConditionsEvaluator) *ConditionsCRUDService {
	return &ConditionsCRUDService{repo: repo, ops: ops, evaluator: eval}
}

// WithAuditEmitter wires the durable audit_outbox emitter + worker-tx beginner
// so each ConditionsService mutation commits together with its audit row in one
// transaction (запрет #10). Composition-root only. A nil emitter
// or nil txb leaves the legacy pool-direct path active (no audit row); the
// mutation contract is unchanged either way (purely-additive audit).
func (s *ConditionsCRUDService) WithAuditEmitter(emitter conditionsAuditEmitter, txb conditionsTxBeginner) *ConditionsCRUDService {
	s.audit = emitter
	s.txb = txb
	return s
}

// auditEnabled reports whether the audit-atomic worker path is wired (both an
// emitter and a tx-beginner). When false, mutations fall back to the legacy
// pool-direct repo methods (no audit row).
func (s *ConditionsCRUDService) auditEnabled() bool {
	return s.audit != nil && s.txb != nil
}

// Get — fetch single Condition.
func (s *ConditionsCRUDService) Get(ctx context.Context, id domain.ConditionID) (domain.Condition, error) {
	if err := id.Validate(); err != nil {
		return domain.Condition{}, err
	}
	return s.repo.Get(ctx, id)
}

// List — page over conditions in folder.
func (s *ConditionsCRUDService) List(ctx context.Context, filter condition.ListFilter) ([]domain.Condition, string, error) {
	return s.repo.List(ctx, filter)
}

// CreateRequest — input.
type CreateConditionRequest struct {
	FolderID         string
	Name             string
	Description      string
	Labels           map[string]string
	Expression       string
	ParametersSchema json.RawMessage
}

// Create — sync handler returns Operation; the actual INSERT happens in
// `doCreate` via operations.Run.
func (s *ConditionsCRUDService) Create(ctx context.Context, req CreateConditionRequest) (*operations.Operation, error) {
	// Sync validation.
	c := domain.Condition{
		ID:               domain.ConditionID(ids.NewID(domain.PrefixConditionResource)),
		FolderID:         req.FolderID,
		Name:             req.Name,
		Description:      req.Description,
		Labels:           req.Labels,
		Expression:       req.Expression,
		ParametersSchema: domain.ConditionParametersSchema(req.ParametersSchema),
		Status:           domain.ConditionStatusCreating,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create condition (%s in folder %s)", c.Name, c.FolderID),
		&iamv1.CreateConditionMetadata{ConditionId: string(c.ID)},
	)
	if err != nil {
		return nil, err
	}
	if err := s.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	// Capture the verified caller principal SYNCHRONOUSLY (before the worker
	// goroutine is spawned) — the audit actor must be the authenticated
	// principal (anti-spoofing), never a request-body field.
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, s.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return s.doCreate(ctx, c, actor)
	})
	return &op, nil
}

func (s *ConditionsCRUDService) doCreate(ctx context.Context, c domain.Condition, actor string) (*anypb.Any, error) {
	if !s.auditEnabled() {
		// Legacy pool-direct path (no audit row).
		inserted, err := s.repo.Insert(ctx, c)
		if err != nil {
			return nil, err
		}
		if err := s.repo.SetStatus(ctx, inserted.ID, domain.ConditionStatusActive); err != nil {
			return marshalCondition(inserted)
		}
		inserted.Status = domain.ConditionStatusActive
		return marshalCondition(inserted)
	}

	// Audit-atomic path: Insert + flip-to-ACTIVE + audit row all commit in ONE
	// tx (запрет #10). A rolled-back Insert (e.g. conditions_folder_name_uniq
	// 23505) leaves neither the condition row nor an orphan audit row. Status
	// flips to ACTIVE in the same tx — the row alone is usable for admin
	// Evaluate; the full FGA model re-write is the bootstrap-job's job.
	tx, err := s.txb.Begin(ctx)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	inserted, err := s.repo.InsertTx(ctx, tx, c)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetStatusTx(ctx, tx, inserted.ID, domain.ConditionStatusActive); err != nil {
		return nil, err
	}
	inserted.Status = domain.ConditionStatusActive
	if aerr := s.audit.EmitTx(ctx, tx, AuditEvent{
		EventType: auditEventConditionCreated,
		Payload: conditionAuditPayload(
			actor, string(inserted.ID), "", inserted.Expression, nil),
	}); aerr != nil {
		return nil, aerr
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return marshalCondition(inserted)
}

// UpdateRequest — input.
type UpdateConditionRequest struct {
	ID               domain.ConditionID
	UpdateMask       []string
	Description      string
	Labels           map[string]string
	Expression       string
	ParametersSchema json.RawMessage
	ExpectedVersion  int64 // optional; 0 = "current"
}

// Update — handler.
func (s *ConditionsCRUDService) Update(ctx context.Context, req UpdateConditionRequest) (*operations.Operation, error) {
	if err := req.ID.Validate(); err != nil {
		return nil, err
	}
	// Validate mask vs known set.
	patch := condition.UpdatePatch{}
	maskSet := normaliseMask(req.UpdateMask)
	if maskSet["name"] || maskSet["folder_id"] {
		return nil, fmt.Errorf("Illegal argument update_mask: name and folder_id are immutable after Create")
	}
	for path := range maskSet {
		switch path {
		case "description", "labels", "expression", "parameters_schema":
		default:
			return nil, fmt.Errorf("Illegal argument update_mask: unknown path %q", path)
		}
	}
	if maskSet["description"] {
		d := req.Description
		patch.Description = &d
	}
	if maskSet["labels"] {
		patch.Labels = req.Labels
		patch.HasLabels = true
	}
	if maskSet["expression"] {
		if len(req.Expression) > 2048 {
			return nil, fmt.Errorf("Illegal argument expression: length must be <=2048")
		}
		e := req.Expression
		patch.Expression = &e
	}
	if maskSet["parameters_schema"] {
		patch.ParametersSchema = []byte(req.ParametersSchema)
		patch.HasParamsSchema = true
	}
	// If no mask provided → full-PATCH (silent ignore immutable per the
	// update_mask discipline). Use known fields only.
	if len(maskSet) == 0 {
		d := req.Description
		patch.Description = &d
		patch.Labels = req.Labels
		patch.HasLabels = req.Labels != nil
		if req.Expression != "" {
			e := req.Expression
			patch.Expression = &e
		}
		if len(req.ParametersSchema) > 0 {
			patch.ParametersSchema = []byte(req.ParametersSchema)
			patch.HasParamsSchema = true
		}
	}

	// Determine expected version: if caller didn't supply, do a read-then-CAS.
	expected := req.ExpectedVersion
	if expected == 0 {
		cur, err := s.repo.Get(ctx, req.ID)
		if err != nil {
			return nil, err
		}
		expected = cur.ResourceVersion
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update condition (%s)", req.ID),
		&iamv1.UpdateConditionMetadata{ConditionId: string(req.ID)},
	)
	if err != nil {
		return nil, err
	}
	if err := s.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	changedFields := patchChangedFields(patch)
	// Capture the verified caller principal synchronously (anti-spoofing).
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, s.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return s.doUpdate(ctx, req.ID, patch, expected, actor, changedFields)
	})
	return &op, nil
}

func (s *ConditionsCRUDService) doUpdate(ctx context.Context, id domain.ConditionID, patch condition.UpdatePatch, expected int64, actor string, changedFields []string) (*anypb.Any, error) {
	if !s.auditEnabled() {
		updated, err := s.repo.UpdateMutable(ctx, id, patch, expected)
		if err != nil {
			return nil, err
		}
		return marshalCondition(updated)
	}
	// Audit-atomic path: CAS-UPDATE + audit row commit in ONE tx (запрет #10).
	tx, err := s.txb.Begin(ctx)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	updated, err := s.repo.UpdateMutableTx(ctx, tx, id, patch, expected)
	if err != nil {
		return nil, err
	}
	if aerr := s.audit.EmitTx(ctx, tx, AuditEvent{
		EventType: auditEventConditionUpdated,
		Payload: conditionAuditPayload(
			actor, string(updated.ID), "", updated.Expression, changedFields),
	}); aerr != nil {
		return nil, aerr
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return marshalCondition(updated)
}

// Delete — flip to DELETING tombstone + refcheck + hard-delete.
func (s *ConditionsCRUDService) Delete(ctx context.Context, id domain.ConditionID) (*operations.Operation, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete condition (%s)", id),
		&iamv1.DeleteConditionMetadata{ConditionId: string(id)},
	)
	if err != nil {
		return nil, err
	}
	if err := s.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	// Capture the verified caller principal synchronously (anti-spoofing).
	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, s.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return s.doDelete(ctx, id, actor)
	})
	return &op, nil
}

func (s *ConditionsCRUDService) doDelete(ctx context.Context, id domain.ConditionID, actor string) (*anypb.Any, error) {
	if !s.auditEnabled() {
		// Legacy pool-direct path (no audit row).
		count, err := s.repo.CountReferences(ctx, id)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			return nil, fmt.Errorf("Condition %s is in use by %d AccessBindings — cleanup the bindings first", id, count)
		}
		if err := s.repo.SetStatus(ctx, id, domain.ConditionStatusDeleting); err != nil {
			return nil, err
		}
		if err := s.repo.Delete(ctx, id); err != nil {
			return nil, err
		}
		return marshalEmpty()
	}

	// Capture the expression name for the audit payload BEFORE the delete tx
	// (the row is gone after hard-delete). Get returns ErrNotFound for an
	// already-tombstoned/missing condition — surfaced as the Operation error.
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Audit-atomic path: refcheck + tombstone + hard-delete + audit row commit
	// in ONE tx (запрет #10). A rolled-back delete leaves no orphan audit row.
	tx, err := s.txb.Begin(ctx)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	count, err := s.repo.CountReferencesTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("Condition %s is in use by %d AccessBindings — cleanup the bindings first", id, count)
	}
	if err := s.repo.SetStatusTx(ctx, tx, id, domain.ConditionStatusDeleting); err != nil {
		return nil, err
	}
	if err := s.repo.DeleteTx(ctx, tx, id); err != nil {
		return nil, err
	}
	if aerr := s.audit.EmitTx(ctx, tx, AuditEvent{
		EventType: auditEventConditionDeleted,
		Payload: conditionAuditPayload(
			actor, string(id), "", cur.Expression, nil),
	}); aerr != nil {
		return nil, aerr
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	return marshalEmpty()
}

// EvaluateRequest — input.
type EvaluateConditionRequest struct {
	ID      domain.ConditionID
	Context map[string]any
	Params  map[string]any
}

// EvaluateResult — output.
type EvaluateConditionResult struct {
	Allowed     bool
	Trace       string
	EvaluatedAt time.Time
}

// Evaluate — admin diagnostic; runs the same evaluator the production
// AuthorizeService overlay would run.
func (s *ConditionsCRUDService) Evaluate(ctx context.Context, req EvaluateConditionRequest) (*EvaluateConditionResult, error) {
	if err := req.ID.Validate(); err != nil {
		return nil, err
	}
	c, err := s.repo.Get(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	condCtx := make(map[string]any, len(req.Context)+1)
	for k, v := range req.Context {
		condCtx[k] = v
	}
	if _, ok := condCtx["current_time"]; !ok {
		condCtx["current_time"] = time.Now().UTC().Unix()
	}
	allowed, trace, evalErr := s.evaluator.Evaluate(iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED, c.Expression, req.Params, condCtx)
	result := &EvaluateConditionResult{
		Allowed:     allowed,
		Trace:       trace,
		EvaluatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if evalErr != nil && evalErr.Error() != ErrUnsupportedExpression.Error() {
		result.Trace = evalErr.Error()
	}
	return result, nil
}

// ── helpers ──────────────────────────────────────────────────────

// patchChangedFields — the canonical changed_fields list for an Update audit
// row: the mutable paths the patch actually applies, in a stable order. A
// no-op patch yields nil (omitted from the payload).
func patchChangedFields(patch condition.UpdatePatch) []string {
	var fields []string
	if patch.Description != nil {
		fields = append(fields, "description")
	}
	if patch.HasLabels {
		fields = append(fields, "labels")
	}
	if patch.Expression != nil {
		fields = append(fields, "expression")
	}
	if patch.HasParamsSchema {
		fields = append(fields, "parameters_schema")
	}
	return fields
}

func normaliseMask(paths []string) map[string]bool {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		m[p] = true
	}
	return m
}

func marshalCondition(c domain.Condition) (*anypb.Any, error) {
	pb := conditionToProto(c)
	return anypb.New(pb)
}

func marshalEmpty() (*anypb.Any, error) {
	return anypb.New(&iamv1.DeleteConditionMetadata{})
}

// conditionToProto — domain → iamv1.Condition mapping (handler-shared).
func conditionToProto(c domain.Condition) *iamv1.Condition {
	pb := &iamv1.Condition{
		Id:          string(c.ID),
		FolderId:    c.FolderID,
		Name:        c.Name,
		Description: c.Description,
		Labels:      c.Labels,
		Expression:  c.Expression,
		Status:      conditionStatusToProto(c.Status),
	}
	if !c.CreatedAt.IsZero() {
		pb.CreatedAt = timestampSecsProto(c.CreatedAt)
	}
	if len(c.ParametersSchema) > 0 {
		// `Condition.parameters_schema` is google.protobuf.Struct — unmarshal
		// JSON object → Struct.
		s, err := jsonToStructpb([]byte(c.ParametersSchema))
		if err == nil {
			pb.ParametersSchema = s
		}
	}
	return pb
}

func conditionStatusToProto(s domain.ConditionStatus) iamv1.Condition_Status {
	switch s {
	case domain.ConditionStatusCreating:
		return iamv1.Condition_CREATING
	case domain.ConditionStatusActive:
		return iamv1.Condition_ACTIVE
	case domain.ConditionStatusDeleting:
		return iamv1.Condition_DELETING
	case domain.ConditionStatusError:
		return iamv1.Condition_ERROR
	}
	return iamv1.Condition_STATUS_UNSPECIFIED
}
