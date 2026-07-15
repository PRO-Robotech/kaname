// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// timestamp_test.go — Wave T conformance: GetFGAStoreInfo's ModelCreatedAt
// proto-response timestamp must be truncated to whole seconds (api-conventions).
package internal_authorize

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeRelWriter — minimal service.RelationWriter stub returning a micros-bearing
// ModelCreatedAt so the truncate-to-seconds conformance can be asserted.
type fakeRelWriter struct {
	info clients.StoreInfo
}

func (f *fakeRelWriter) WriteConditionalTuples(_ context.Context, _, _ []clients.ConditionalTuple) error {
	return nil
}

func (f *fakeRelWriter) ReadTuples(_ context.Context, _, _, _ string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

func (f *fakeRelWriter) GetStoreInfo(_ context.Context) (clients.StoreInfo, error) {
	return f.info, nil
}

func TestGetFGAStoreInfo_TruncatesModelCreatedAtToSeconds(t *testing.T) {
	created := time.Date(2026, 6, 16, 10, 20, 30, 123456789, time.UTC)
	w := service.NewRelationProjector(&fakeRelWriter{info: clients.StoreInfo{
		StoreID:              "store-1",
		AuthorizationModelID: "model-1",
		TupleCount:           5,
		ModelCreatedAt:       created,
	}})
	h := NewHandler(w, nil, "model-1")

	resp, err := h.GetFGAStoreInfo(context.Background(), &iamv1.GetFGAStoreInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.GetModelCreatedAt())
	assert.Zero(t, resp.GetModelCreatedAt().AsTime().Nanosecond(), "ModelCreatedAt sub-second leaked")
	assert.True(t, resp.GetModelCreatedAt().AsTime().Equal(created.Truncate(time.Second)))
}
