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
