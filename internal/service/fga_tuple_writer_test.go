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

// mockReader — minimal RelationReader. Записи у порта нет by construction:
// WriteRaw снят вместе с RPC (#788), и вернуть её нельзя, не расширив порт.
type mockReader struct {
	readResp  []clients.ConditionalTuple
	readNext  string
	readErr   error
	storeInfo clients.StoreInfo
}

func (m *mockReader) ReadTuples(ctx context.Context, sf, rf, of string, ps int, pt string) ([]clients.ConditionalTuple, string, error) {
	return m.readResp, m.readNext, m.readErr
}
func (m *mockReader) GetStoreInfo(ctx context.Context) (clients.StoreInfo, error) {
	return m.storeInfo, nil
}

func TestRelationProjector_ReadRaw_NoClient_Errors(t *testing.T) {
	w := NewRelationProjector(nil)
	if _, _, err := w.ReadRaw(context.Background(), "", "", "", 0, ""); err == nil {
		t.Fatalf("expected error when no fga client")
	}
}

func TestRelationProjector_ReadRaw_Propagates(t *testing.T) {
	w := NewRelationProjector(&mockReader{readErr: errors.New("downstream")})
	if _, _, err := w.ReadRaw(context.Background(), "", "", "", 0, ""); err == nil {
		t.Fatalf("expected propagation")
	}
}
