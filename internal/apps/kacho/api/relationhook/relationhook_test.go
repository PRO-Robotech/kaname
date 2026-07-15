// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// relationhook_test.go — unit tests for the shared hierarchy-tuple writer.
package relationhook

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// recordingFGA — minimal clients.RelationStore capturing writes.
type recordingFGA struct {
	writes   []clients.RelationTuple
	writeErr error
}

func (r *recordingFGA) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return false, nil
}

func (r *recordingFGA) WriteTuples(ctx context.Context, tuples []clients.RelationTuple) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.writes = append(r.writes, tuples...)
	return nil
}

func (r *recordingFGA) DeleteTuples(ctx context.Context, tuples []clients.RelationTuple) error {
	return nil
}

var _ clients.RelationStore = (*recordingFGA)(nil)

func TestWriteHierarchyTuple_WritesParentPointer(t *testing.T) {
	fga := &recordingFGA{}
	WriteHierarchyTuple(context.Background(), fga, nil,
		"account", "acc_a", "account", "iam_group", "grp_x")

	if len(fga.writes) != 1 {
		t.Fatalf("expected 1 tuple write, got %d", len(fga.writes))
	}
	got := fga.writes[0]
	if got.User != "account:acc_a" {
		t.Errorf("User = %q, want account:acc_a", got.User)
	}
	if got.Relation != "account" {
		t.Errorf("Relation = %q, want account", got.Relation)
	}
	if got.Object != "iam_group:grp_x" {
		t.Errorf("Object = %q, want iam_group:grp_x", got.Object)
	}
}

func TestWriteHierarchyTuple_ProjectScope(t *testing.T) {
	fga := &recordingFGA{}
	WriteHierarchyTuple(context.Background(), fga, nil,
		"project", "prj_1", "project", "iam_access_binding", "acb_9")

	if len(fga.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(fga.writes))
	}
	got := fga.writes[0]
	if got.User != "project:prj_1" || got.Relation != "project" || got.Object != "iam_access_binding:acb_9" {
		t.Errorf("unexpected tuple: %+v", got)
	}
}

func TestWriteHierarchyTuple_NilWriterIsNoop(t *testing.T) {
	// Must not panic when no FGA client is wired.
	WriteHierarchyTuple(context.Background(), nil, nil,
		"account", "acc_a", "account", "iam_group", "grp_x")
}

func TestWriteHierarchyTuple_EmptyIDSkipped(t *testing.T) {
	fga := &recordingFGA{}
	WriteHierarchyTuple(context.Background(), fga, nil,
		"account", "", "account", "iam_group", "grp_x")
	WriteHierarchyTuple(context.Background(), fga, nil,
		"account", "acc_a", "account", "iam_group", "")
	if len(fga.writes) != 0 {
		t.Fatalf("empty-id tuples must be skipped, got %d writes", len(fga.writes))
	}
}

func TestWriteHierarchyTuple_WriteErrorIsNonFatal(t *testing.T) {
	fga := &recordingFGA{writeErr: errors.New("openfga unreachable")}
	// Must not panic / must return cleanly even when the write fails — the
	// resource row is already committed by the caller.
	WriteHierarchyTuple(context.Background(), fga, nil,
		"account", "acc_a", "account", "iam_role", "rol_z")
}
