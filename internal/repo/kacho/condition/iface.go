// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package condition — CQRS port-iface'ы для kacho_iam.conditions
// (ConditionsService).
package condition

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.ConditionID) (domain.Condition, error)
	// List — page conditions in a folder, exclude DELETING tombstones.
	List(ctx context.Context, filter ListFilter) ([]domain.Condition, string, error)
	// CountReferences — best-effort count of access_bindings rows referencing
	// `condition_id` via the legacy access_binding_conditions table.
	// Used by Delete() request-path to surface FailedPrecondition before
	// flipping status to DELETING. Returns 0 if no references.
	CountReferences(ctx context.Context, id domain.ConditionID) (int64, error)
}

type WriterIface interface {
	// Insert — create new Condition row with status=CREATING.
	Insert(ctx context.Context, c domain.Condition) (domain.Condition, error)
	// UpdateMutable — update description / labels / expression /
	// parameters_schema; bumps resource_version atomically (CAS on
	// resource_version).
	UpdateMutable(ctx context.Context, id domain.ConditionID, patch UpdatePatch, expectedVersion int64) (domain.Condition, error)
	// SetStatus — flip status (CREATING→ACTIVE, ACTIVE→DELETING, etc.).
	SetStatus(ctx context.Context, id domain.ConditionID, newStatus domain.ConditionStatus) error
	// Delete — hard delete (after status=DELETING + no references).
	Delete(ctx context.Context, id domain.ConditionID) error
}

// ListFilter — pagination + optional folder scope.
type ListFilter struct {
	FolderID  string
	PageSize  int32
	PageToken string
	Filter    string // YC-style label= / name= filter (best-effort).
}

// UpdatePatch — fields to update (nil = unset). Mask is applied at handler
// level; this struct simply carries the new values for the fields the handler
// intends to overwrite.
type UpdatePatch struct {
	Description      *string
	Labels           map[string]string
	HasLabels        bool
	Expression       *string
	ParametersSchema []byte
	HasParamsSchema  bool
}
