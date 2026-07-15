// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// reload_storeinfo_test.go — Wave Q test-debt (relates #122): unit coverage for
// InternalAuthorizeService.ReloadModel + .GetFGAStoreInfo, which previously had
// zero handler-level tests (only the truncate-to-seconds conformance for
// GetFGAStoreInfo existed in timestamp_test.go).
//
// These RPCs are internal-only (:9091, ban #6) and have no public REST route,
// so coverage is handler-unit via a fake service.RelationWriter (no live
// OpenFGA needed — the codebase already stubs the writer port). The fake mirrors
// the existing fakeRelWriter in timestamp_test.go but adds an error-injecting
// variant for the Unavailable negative path.
package internal_authorize

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// storeInfoFake — service.RelationWriter stub whose GetStoreInfo returns a
// configured StoreInfo (happy) or an injected error (Unavailable negative).
type storeInfoFake struct {
	info    clients.StoreInfo
	infoErr error
	readErr error
}

func (f *storeInfoFake) WriteConditionalTuples(_ context.Context, _, _ []clients.ConditionalTuple) error {
	return nil
}

func (f *storeInfoFake) ReadTuples(_ context.Context, _, _, _ string, _ int, _ string) ([]clients.ConditionalTuple, string, error) {
	if f.readErr != nil {
		return nil, "", f.readErr
	}
	return nil, "", nil
}

func (f *storeInfoFake) GetStoreInfo(_ context.Context) (clients.StoreInfo, error) {
	if f.infoErr != nil {
		return clients.StoreInfo{}, f.infoErr
	}
	return f.info, nil
}

// ── ReloadModel ──────────────────────────────────────────────────────────

// doc-truthfulness lock (audit r11): the model pin is env-configured and fixed for
// the process lifetime (the OpenFGA client captures it at construction; nothing
// re-reads a handler field at evaluation time). A caller-supplied id is advisory
// only — ReloadModel reports the id currently in force and does NOT adopt the
// requested one. A refactor that reintroduces a live-mutable-but-unread field fails here.
func TestReloadModel_ReportsPinnedID_RequestedIDNotAdopted(t *testing.T) {
	// Given a handler pinned to "model-old".
	w := service.NewRelationProjector(&storeInfoFake{})
	h := NewHandler(w, nil, "model-old")

	// When ReloadModel is called with a different requested id.
	resp, err := h.ReloadModel(context.Background(), &iamv1.ReloadModelRequest{
		AuthorizationModelId: "model-new",
	})

	// Then the response reports the pinned id — the requested id is not adopted
	// (runtime re-pin is unsupported; it requires a process restart).
	require.NoError(t, err)
	assert.Equal(t, "model-old", resp.GetAuthorizationModelId(),
		"requested id must not be adopted — the live pin is env-only")
}

func TestReloadModel_SetsReloadedAt(t *testing.T) {
	w := service.NewRelationProjector(&storeInfoFake{})
	h := NewHandler(w, nil, "model-old")

	before := time.Now().Add(-time.Second)
	resp, err := h.ReloadModel(context.Background(), &iamv1.ReloadModelRequest{
		AuthorizationModelId: "model-new",
	})

	require.NoError(t, err)
	require.NotNil(t, resp.GetReloadedAt(), "ReloadedAt must be populated")
	assert.False(t, resp.GetReloadedAt().AsTime().Before(before), "ReloadedAt must be ~now")
}

func TestReloadModel_EmptyID_KeepsCurrentWhenNoEnvFallback(t *testing.T) {
	w := service.NewRelationProjector(&storeInfoFake{})
	h := NewHandler(w, nil, "model-current")

	// When ReloadModel is called with an empty id, the injected default
	// (== the initial live id here) is (re-)applied.
	resp, err := h.ReloadModel(context.Background(), &iamv1.ReloadModelRequest{})

	// Then the configured id is reported (no overwrite to empty).
	require.NoError(t, err)
	assert.Equal(t, "model-current", resp.GetAuthorizationModelId())
}

func TestReloadModel_EmptyID_FallsBackToInjectedDefault(t *testing.T) {
	// A stale/divergent env value must NOT leak into the handler at request time:
	// the empty-request fallback is the composition-root-injected default, not
	// os.Getenv. Setting the env here proves it is ignored (no config drift).
	t.Setenv("KACHO_IAM_OPENFGA_MODEL_ID", "model-from-env")
	w := service.NewRelationProjector(&storeInfoFake{})
	h := NewHandler(w, nil, "model-configured")

	// When ReloadModel is called with an empty request id.
	resp, err := h.ReloadModel(context.Background(), &iamv1.ReloadModelRequest{})

	// Then the INJECTED default is reported — the divergent env value is ignored.
	require.NoError(t, err)
	assert.Equal(t, "model-configured", resp.GetAuthorizationModelId())
}

// ── GetFGAStoreInfo ──────────────────────────────────────────────────────

func TestGetFGAStoreInfo_ReturnsStoreMetadata(t *testing.T) {
	// Given a configured store.
	w := service.NewRelationProjector(&storeInfoFake{info: clients.StoreInfo{
		StoreID:              "store-abc",
		AuthorizationModelID: "model-xyz",
		TupleCount:           42,
		ModelBuildSHA:        "deadbeef",
		EngineVersion:        "1.2.3",
	}})
	h := NewHandler(w, nil, "model-xyz")

	// When GetFGAStoreInfo is called.
	resp, err := h.GetFGAStoreInfo(context.Background(), &iamv1.GetFGAStoreInfoRequest{})

	// Then store metadata is mapped onto the response.
	require.NoError(t, err)
	assert.Equal(t, "store-abc", resp.GetStoreId())
	assert.Equal(t, "model-xyz", resp.GetAuthorizationModelId())
	assert.EqualValues(t, 42, resp.GetTupleCount())
	assert.Equal(t, "deadbeef", resp.GetModelBuildSha())
	assert.Equal(t, "1.2.3", resp.GetFgaEngineVersion())
}

func TestGetFGAStoreInfo_BackendUnavailable_Unavailable(t *testing.T) {
	// Given a writer whose GetStoreInfo fails (OpenFGA unreachable).
	w := service.NewRelationProjector(&storeInfoFake{infoErr: errors.New("dial fga: connection refused")})
	h := NewHandler(w, nil, "model-xyz")

	// When GetFGAStoreInfo is called.
	resp, err := h.GetFGAStoreInfo(context.Background(), &iamv1.GetFGAStoreInfoRequest{})

	// Then the handler maps the backend error to codes.Unavailable.
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// leak-regression (audit r9): the raw OpenFGA transport error must never reach
// the gRPC status message — it carries the cluster-internal FGA host:port /
// connection string. The message must be the fixed opaque text, not err.Error().
func TestGetFGAStoreInfo_BackendUnavailable_OpaqueMessage(t *testing.T) {
	rawErr := "openfga storeinfo: dial tcp fga-host.internal:8080: connect: connection refused"
	w := service.NewRelationProjector(&storeInfoFake{infoErr: errors.New(rawErr)})
	h := NewHandler(w, nil, "model-xyz")

	_, err := h.GetFGAStoreInfo(context.Background(), &iamv1.GetFGAStoreInfoRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	msg := status.Convert(err).Message()
	assert.Equal(t, "authz backend unavailable", msg)
	assert.NotContains(t, msg, "fga-host.internal", "FGA host:port leaked into status message")
}

// ── ReadTuples ───────────────────────────────────────────────────────────

func TestReadTuples_BackendUnavailable_OpaqueMessage(t *testing.T) {
	// Given a writer whose ReadTuples fails (OpenFGA unreachable). The raw error
	// carries the FGA endpoint host:port — it must be scrubbed.
	rawErr := "openfga read: dial tcp fga-host.internal:8080: connect: connection refused"
	w := service.NewRelationProjector(&storeInfoFake{readErr: errors.New(rawErr)})
	h := NewHandler(w, nil, "model-xyz")

	resp, err := h.ReadTuples(context.Background(), &iamv1.ReadTuplesRequest{})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	msg := status.Convert(err).Message()
	assert.Equal(t, "authz backend unavailable", msg)
	assert.NotContains(t, strings.ToLower(msg), "fga-host.internal", "FGA host:port leaked into status message")
}
