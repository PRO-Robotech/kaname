// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_tuple_writer.go — AccessBinding lifecycle → FGA tuple writes.
//
// Writer is invoked by:
//   - AccessBindingService.Create (sync wired in main.go via the
//     `WithRelationStore` helper). Writes a single tuple
//     `<subject>#<role-permission>@<resource-type>:<resource-id>` with
//     optional Conditional attachment when `condition_id` is set.
//   - AccessBindingService.Delete — remove the matching tuple.
//   - AccessBindingService.Update — diff conditions; treat as
//     Delete-old + Write-new.
//
// Idempotency: WriteConditionalTuples accepts already-exists silently
// (clients.OpenFGAHTTPClient).
//
// InternalAuthorizeService.WriteTuples / ReadTuples / GetFGAStoreInfo also
// rely on RelationProjector's underlying client.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// RelationWriter — port-iface narrowed to writer-needs.
type RelationWriter interface {
	WriteConditionalTuples(ctx context.Context, writes, deletes []authztypes.ConditionalTuple) error
	ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error)
	GetStoreInfo(ctx context.Context) (authztypes.StoreInfo, error)
}

// RelationProjector — service.
type RelationProjector struct {
	relations RelationWriter
}

// NewRelationProjector — builder.
func NewRelationProjector(relations RelationWriter) *RelationProjector {
	return &RelationProjector{relations: relations}
}

// AccessBindingTuple — denormalised AccessBinding view used by the writer.
type AccessBindingTuple struct {
	Subject      string // "user:usr_xxx" / "service_account:sva_xxx" / "group:grp_xxx#member"
	Relation     string // resolved from role permissions
	ResourceType string
	ResourceID   string
	Condition    *authztypes.TupleConditionRef // optional
}

// OnAccessBindingCreated — write tuple for a freshly-created binding.
func (w *RelationProjector) OnAccessBindingCreated(ctx context.Context, b AccessBindingTuple) error {
	if w.relations == nil {
		return fmt.Errorf("fga: writer not configured")
	}
	tup := authztypes.ConditionalTuple{
		User:      b.Subject,
		Relation:  b.Relation,
		Object:    fmt.Sprintf("%s:%s", b.ResourceType, b.ResourceID),
		Condition: b.Condition,
	}
	if err := w.relations.WriteConditionalTuples(ctx, []authztypes.ConditionalTuple{tup}, nil); err != nil {
		return fmt.Errorf("fga write tuple: %w", err)
	}
	return nil
}

// OnAccessBindingDeleted — remove tuple. Condition mismatch on the FGA
// side is also OK (idempotent).
func (w *RelationProjector) OnAccessBindingDeleted(ctx context.Context, b AccessBindingTuple) error {
	if w.relations == nil {
		return fmt.Errorf("fga: writer not configured")
	}
	// Deletes do not carry a Condition (FGA semantics: delete by triple).
	tup := authztypes.ConditionalTuple{
		User:     b.Subject,
		Relation: b.Relation,
		Object:   fmt.Sprintf("%s:%s", b.ResourceType, b.ResourceID),
	}
	if err := w.relations.WriteConditionalTuples(ctx, nil, []authztypes.ConditionalTuple{tup}); err != nil {
		return fmt.Errorf("fga delete tuple: %w", err)
	}
	return nil
}

// OnAccessBindingUpdated — diff old vs new conditions; if condition changed,
// re-write tuple (delete then add). For pure relation/subject changes also
// supported (they end up as delete-old + add-new pairs).
func (w *RelationProjector) OnAccessBindingUpdated(ctx context.Context, oldB, newB AccessBindingTuple) error {
	if w.relations == nil {
		return fmt.Errorf("fga: writer not configured")
	}
	if equalTupleCore(oldB, newB) && equalCondition(oldB.Condition, newB.Condition) {
		return nil // no-op
	}
	delTup := authztypes.ConditionalTuple{
		User:     oldB.Subject,
		Relation: oldB.Relation,
		Object:   fmt.Sprintf("%s:%s", oldB.ResourceType, oldB.ResourceID),
	}
	addTup := authztypes.ConditionalTuple{
		User:      newB.Subject,
		Relation:  newB.Relation,
		Object:    fmt.Sprintf("%s:%s", newB.ResourceType, newB.ResourceID),
		Condition: newB.Condition,
	}
	if err := w.relations.WriteConditionalTuples(ctx, []authztypes.ConditionalTuple{addTup}, []authztypes.ConditionalTuple{delTup}); err != nil {
		return fmt.Errorf("fga update tuple: %w", err)
	}
	return nil
}

// WriteRaw — pass-through used by InternalAuthorizeService.WriteTuples
// admin RPC.
func (w *RelationProjector) WriteRaw(ctx context.Context, writes, deletes []authztypes.ConditionalTuple) (inserted, deleted int, err error) {
	if w.relations == nil {
		return 0, 0, fmt.Errorf("fga: writer not configured")
	}
	if err := w.relations.WriteConditionalTuples(ctx, writes, deletes); err != nil {
		return 0, 0, err
	}
	return len(writes), len(deletes), nil
}

// ReadRaw — used by InternalAuthorizeService.ReadTuples.
func (w *RelationProjector) ReadRaw(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error) {
	if w.relations == nil {
		return nil, "", fmt.Errorf("fga: writer not configured")
	}
	// Trim trailing `*` wildcard in filters — FGA expects bare prefixes.
	subjectFilter = strings.TrimSuffix(subjectFilter, "*")
	objectFilter = strings.TrimSuffix(objectFilter, "*")
	return w.relations.ReadTuples(ctx, subjectFilter, relationFilter, objectFilter, pageSize, pageToken)
}

// StoreInfo — pass-through for InternalAuthorizeService.GetFGAStoreInfo.
func (w *RelationProjector) StoreInfo(ctx context.Context) (authztypes.StoreInfo, error) {
	if w.relations == nil {
		return authztypes.StoreInfo{}, fmt.Errorf("fga: writer not configured")
	}
	return w.relations.GetStoreInfo(ctx)
}

func equalTupleCore(a, b AccessBindingTuple) bool {
	return a.Subject == b.Subject && a.Relation == b.Relation &&
		a.ResourceType == b.ResourceType && a.ResourceID == b.ResourceID
}

func equalCondition(a, b *authztypes.TupleConditionRef) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Name != b.Name {
		return false
	}
	if len(a.Context) != len(b.Context) {
		return false
	}
	for k, v := range a.Context {
		if b.Context[k] != v {
			return false
		}
	}
	return true
}
