// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_tuple_writer_test.go — unit tests for RelationProjector.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// mockWriter — minimal RelationWriter.
type mockWriter struct {
	writes    []clients.ConditionalTuple
	deletes   []clients.ConditionalTuple
	writeErr  error
	readResp  []clients.ConditionalTuple
	readNext  string
	storeInfo clients.StoreInfo
}

func (m *mockWriter) WriteConditionalTuples(ctx context.Context, writes, deletes []clients.ConditionalTuple) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writes = append(m.writes, writes...)
	m.deletes = append(m.deletes, deletes...)
	return nil
}
func (m *mockWriter) ReadTuples(ctx context.Context, sf, rf, of string, ps int, pt string) ([]clients.ConditionalTuple, string, error) {
	return m.readResp, m.readNext, nil
}
func (m *mockWriter) GetStoreInfo(ctx context.Context) (clients.StoreInfo, error) {
	return m.storeInfo, nil
}

func TestRelationProjector_OnCreate_WritesConditionalTuple(t *testing.T) {
	mw := &mockWriter{}
	w := NewRelationProjector(mw)
	err := w.OnAccessBindingCreated(context.Background(), AccessBindingTuple{
		Subject:      "user:usr_alice",
		Relation:     "editor",
		ResourceType: "vpc_network",
		ResourceID:   "vpcn_x",
		Condition:    &clients.TupleConditionRef{Name: "mfa_fresh"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(mw.writes) != 1 {
		t.Fatalf("expected 1 write; got %d", len(mw.writes))
	}
	got := mw.writes[0]
	if got.Object != "vpc_network:vpcn_x" {
		t.Errorf("object mismatch: %q", got.Object)
	}
	if got.Condition == nil || got.Condition.Name != "mfa_fresh" {
		t.Errorf("condition mismatch: %+v", got.Condition)
	}
}

func TestRelationProjector_OnDelete_RemovesByTriple(t *testing.T) {
	mw := &mockWriter{}
	w := NewRelationProjector(mw)
	err := w.OnAccessBindingDeleted(context.Background(), AccessBindingTuple{
		Subject:      "user:usr_bob",
		Relation:     "viewer",
		ResourceType: "compute_instance",
		ResourceID:   "vm1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(mw.deletes) != 1 {
		t.Fatalf("expected 1 delete; got %d", len(mw.deletes))
	}
}

func TestRelationProjector_OnUpdate_NoOp(t *testing.T) {
	mw := &mockWriter{}
	w := NewRelationProjector(mw)
	same := AccessBindingTuple{
		Subject:      "user:x",
		Relation:     "viewer",
		ResourceType: "y",
		ResourceID:   "1",
		Condition:    &clients.TupleConditionRef{Name: "mfa_fresh", Context: map[string]any{"k": "v"}},
	}
	if err := w.OnAccessBindingUpdated(context.Background(), same, same); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(mw.writes)+len(mw.deletes) != 0 {
		t.Errorf("no-op update should not call FGA; got %d writes / %d deletes", len(mw.writes), len(mw.deletes))
	}
}

func TestRelationProjector_OnUpdate_ChangesCondition(t *testing.T) {
	mw := &mockWriter{}
	w := NewRelationProjector(mw)
	oldB := AccessBindingTuple{Subject: "user:x", Relation: "viewer", ResourceType: "y", ResourceID: "1"}
	newB := AccessBindingTuple{Subject: "user:x", Relation: "viewer", ResourceType: "y", ResourceID: "1",
		Condition: &clients.TupleConditionRef{Name: "non_expired"}}
	if err := w.OnAccessBindingUpdated(context.Background(), oldB, newB); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(mw.writes) != 1 || len(mw.deletes) != 1 {
		t.Errorf("expected 1 write + 1 delete; got w=%d d=%d", len(mw.writes), len(mw.deletes))
	}
}

func TestRelationProjector_WriteRaw_NoClient_Errors(t *testing.T) {
	w := NewRelationProjector(nil)
	_, _, err := w.WriteRaw(context.Background(), nil, nil)
	if err == nil {
		t.Fatalf("expected error when no fga client")
	}
}

func TestRelationProjector_WriteRaw_Propagates(t *testing.T) {
	mw := &mockWriter{writeErr: errors.New("downstream")}
	w := NewRelationProjector(mw)
	_, _, err := w.WriteRaw(context.Background(), []clients.ConditionalTuple{{User: "user:x", Relation: "v", Object: "x:1"}}, nil)
	if err == nil {
		t.Fatalf("expected propagation")
	}
}

func TestEqualCondition(t *testing.T) {
	if !equalCondition(nil, nil) {
		t.Errorf("nil==nil should be true")
	}
	if equalCondition(&clients.TupleConditionRef{Name: "a"}, nil) {
		t.Errorf("non-nil vs nil should differ")
	}
	if !equalCondition(
		&clients.TupleConditionRef{Name: "mfa_fresh", Context: map[string]any{"k": "v"}},
		&clients.TupleConditionRef{Name: "mfa_fresh", Context: map[string]any{"k": "v"}},
	) {
		t.Errorf("equal conditions should be equal")
	}
}
