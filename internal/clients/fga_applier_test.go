// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_applier_test.go — unit tests for FGAApplier + DecodeFGAOutboxEvent.
//
//	( /) — kacho-iam half of the fga_outbox drainer.
//
// Validates the drainer.Applier[FGAOutboxEvent] error-classification contract:
//
//   - happy write/delete → nil (drainer marks sent_at)
//   - "already exists" on write → drainer.ErrAlreadyApplied (idempotent success)
//   - "not found" on delete → drainer.ErrAlreadyApplied (idempotent success)
//   - malformed-tuple / 400-class permanent error → drainer.ErrPermanent
//   - transient (network / 5xx) → propagated as-is (drainer retries)
//   - unknown event_type → drainer.ErrPermanent
//   - decoder: malformed JSON / missing required field → drainer.ErrPermanent
package clients_test

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// ── recordingOpenFGAClient — mock RelationStore that captures calls and
// returns canned errors per call-index (or shared error). Thread-safe.
type recordingOpenFGAClient struct {
	mu          sync.Mutex
	writeCalls  [][]clients.RelationTuple
	deleteCalls [][]clients.RelationTuple
	writeErr    error
	deleteErr   error
}

func (c *recordingOpenFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, stderrors.New("Check not implemented for this mock")
}

func (c *recordingOpenFGAClient) WriteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCalls = append(c.writeCalls, tuples)
	return c.writeErr
}

func (c *recordingOpenFGAClient) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteCalls = append(c.deleteCalls, tuples)
	return c.deleteErr
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeFGAOutboxEvent
// ─────────────────────────────────────────────────────────────────────────────

func TestDecodeFGAOutboxEvent_Happy(t *testing.T) {
	payload := []byte(`{"user":"user:usr01","relation":"system_admin","object":"cluster:default"}`)
	e, err := clients.DecodeFGAOutboxEvent(payload)
	require.NoError(t, err)
	assert.Equal(t, "user:usr01", e.User)
	assert.Equal(t, "system_admin", e.Relation)
	assert.Equal(t, "cluster:default", e.Object)
}

func TestDecodeFGAOutboxEvent_MalformedJSON_ReturnsErrPermanent(t *testing.T) {
	payload := []byte(`{not json`)
	_, err := clients.DecodeFGAOutboxEvent(payload)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"malformed JSON must wrap drainer.ErrPermanent so drainer poisons row")
}

func TestDecodeFGAOutboxEvent_MissingUser_ReturnsErrPermanent(t *testing.T) {
	payload := []byte(`{"relation":"system_admin","object":"cluster:default"}`)
	_, err := clients.DecodeFGAOutboxEvent(payload)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent))
}

func TestDecodeFGAOutboxEvent_MissingRelation_ReturnsErrPermanent(t *testing.T) {
	payload := []byte(`{"user":"user:usr01","object":"cluster:default"}`)
	_, err := clients.DecodeFGAOutboxEvent(payload)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent))
}

func TestDecodeFGAOutboxEvent_MissingObject_ReturnsErrPermanent(t *testing.T) {
	payload := []byte(`{"user":"user:usr01","relation":"system_admin"}`)
	_, err := clients.DecodeFGAOutboxEvent(payload)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent))
}

// ─────────────────────────────────────────────────────────────────────────────
// FGAApplier — write path
// ─────────────────────────────────────────────────────────────────────────────

func TestNewFGAApplier_GrantWrite_Success(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{
		User:     "user:usr01",
		Relation: "system_admin",
		Object:   "cluster:default",
	}
	err := apply(context.Background(), "fga.tuple.write", ev)
	require.NoError(t, err)

	require.Len(t, mock.writeCalls, 1)
	require.Len(t, mock.writeCalls[0], 1)
	assert.Equal(t, clients.RelationTuple{
		User:     "user:usr01",
		Relation: "system_admin",
		Object:   "cluster:default",
	}, mock.writeCalls[0][0])
	assert.Empty(t, mock.deleteCalls, "write event should not call DeleteTuples")
}

func TestNewFGAApplier_GrantWrite_AlreadyExists_ReturnsErrAlreadyApplied(t *testing.T) {
	// Models OpenFGA reply "write a tuple which already exists" (HTTP 400 with
	// "already_exists" body). Our applier detects via error-text and returns
	// the drainer sentinel so the row is marked sent_at (idempotent).
	mock := &recordingOpenFGAClient{
		writeErr: stderrors.New("openfga write: bad request: cannot write a tuple which already exists in store: user user:usr01, relation system_admin, object cluster:default, errorCode: write_failed_due_to_invalid_input, code: already_exists"),
	}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.write", ev)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"already_exists error must map to drainer.ErrAlreadyApplied")
	// Must NOT be transient — applier should NOT cause drainer retry.
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent),
		"already-exists is idempotent success, not a poison")
}

func TestNewFGAApplier_GrantWrite_Malformed_ReturnsErrPermanent(t *testing.T) {
	// Models OpenFGA HTTP 400 with bad-tuple shape (e.g. user-type not declared
	// in the model). Retry will never succeed → poison.
	mock := &recordingOpenFGAClient{
		writeErr: stderrors.New("openfga write: status 400: validation_error: type 'badtype' is undefined in the authorization model"),
	}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "badtype:x", Relation: "rel", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.write", ev)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"400 validation-error must map to drainer.ErrPermanent")
}

func TestNewFGAApplier_GrantWrite_Transient_PropagatesError(t *testing.T) {
	// Models OpenFGA HTTP 503 or network drop — drainer must retry with backoff.
	transient := stderrors.New("openfga write: status 503: service unavailable")
	mock := &recordingOpenFGAClient{writeErr: transient}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.write", ev)
	require.Error(t, err)

	// Critical: NOT ErrAlreadyApplied, NOT ErrPermanent — those would mark
	// row as terminal in drainer. Transient must propagate raw so drainer
	// classifies as "transient retry" via the default branch.
	assert.False(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"5xx is not idempotent success")
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent),
		"5xx is transient, must retry")
	assert.Contains(t, err.Error(), "503", "raw error message preserved for last_error column")
}

// ─────────────────────────────────────────────────────────────────────────────
// FGAApplier — delete path
// ─────────────────────────────────────────────────────────────────────────────

func TestNewFGAApplier_RevokeDelete_Success(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.delete", ev)
	require.NoError(t, err)

	require.Len(t, mock.deleteCalls, 1)
	require.Len(t, mock.deleteCalls[0], 1)
	assert.Equal(t, clients.RelationTuple{
		User:     "user:usr01",
		Relation: "system_admin",
		Object:   "cluster:default",
	}, mock.deleteCalls[0][0])
	assert.Empty(t, mock.writeCalls, "delete event should not call WriteTuples")
}

func TestNewFGAApplier_RevokeDelete_NotFound_ReturnsErrAlreadyApplied(t *testing.T) {
	// Models OpenFGA reply "cannot_delete: tuple not found" → idempotent for
	// the drainer (tuple already gone — desired post-condition met).
	mock := &recordingOpenFGAClient{
		deleteErr: stderrors.New("openfga write: bad request: cannot delete a tuple which does not exist: user user:usr01, errorCode: write_failed_due_to_invalid_input, code: cannot_delete"),
	}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.delete", ev)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"cannot_delete (tuple already absent) must map to drainer.ErrAlreadyApplied")
}

func TestNewFGAApplier_RevokeDelete_Transient_PropagatesError(t *testing.T) {
	mock := &recordingOpenFGAClient{deleteErr: stderrors.New("openfga write: status 503: service unavailable")}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.delete", ev)
	require.Error(t, err)
	assert.False(t, stderrors.Is(err, drainer.ErrAlreadyApplied))
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent))
}

// ─────────────────────────────────────────────────────────────────────────────
// FGAApplier — unknown event_type
// ─────────────────────────────────────────────────────────────────────────────

func TestNewFGAApplier_UnknownEventType_ReturnsErrPermanent(t *testing.T) {
	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.weirdverb", ev)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"unknown event_type cannot be processed — must poison row")
	assert.Empty(t, mock.writeCalls)
	assert.Empty(t, mock.deleteCalls)
}

// ─────────────────────────────────────────────────────────────────────────────
// H2: REAL OpenFGAHTTPClient.writeOrDelete must surface the FGA 400 body so the
// applier classifier sees the idempotent-replay markers (already_exists /
// cannot_delete) and maps replay → ErrAlreadyApplied, NOT ErrPermanent poison.
//
// These tests exercise the real body-reading path against an httptest.Server
// returning the actual OpenFGA already-exists / cannot-delete reply shapes
// (errorCode: write_failed_due_to_invalid_input, code: already_exists/cannot_delete).
// They drive NewFGAApplier(realClient) so a regression in writeOrDelete (dropping
// the body) is caught end-to-end, not just in the text-classifier unit tests.
// ─────────────────────────────────────────────────────────────────────────────

// Realistic OpenFGA HTTP-400 reply for writing a tuple that already exists.
// Matches the shape pinned in TestNewFGAApplier_GrantWrite_AlreadyExists.
const fgaAlreadyExistsBody = `{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple ((user:usr01,system_admin,cluster:default), errorCode: already_exists) since it already exists"}`

// Realistic OpenFGA HTTP-400 reply for deleting a tuple that does not exist.
const fgaCannotDeleteBody = `{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple ((user:usr01,system_admin,cluster:default), errorCode: cannot_delete) which does not exist"}`

func newFGA400Server(t *testing.T, body string) (*httptest.Server, *clients.OpenFGAHTTPClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	// Endpoint is the host:port (the client builds "http://<endpoint>/stores/...").
	endpoint := strings.TrimPrefix(srv.URL, "http://")
	return srv, &clients.OpenFGAHTTPClient{
		Endpoint:           endpoint,
		StoreID:            "st_test",
		AuthorizationModel: "01MODEL",
	}
}

// assertIdempotentReplay — the drainer marks a row sent_at when the applier
// returns nil OR drainer.ErrAlreadyApplied. Both mean "desired post-condition
// already holds". The ONE thing that must never happen for a replay is
// ErrPermanent (poison) or a bare transient error (infinite retry).
func assertIdempotentReplay(t *testing.T, err error) {
	t.Helper()
	idempotentSuccess := err == nil || stderrors.Is(err, drainer.ErrAlreadyApplied)
	assert.True(t, idempotentSuccess,
		"idempotent replay must be success (nil or ErrAlreadyApplied), got: %v", err)
	assert.False(t, stderrors.Is(err, drainer.ErrPermanent),
		"idempotent replay must NOT be poisoned as ErrPermanent, got: %v", err)
}

func TestFGAApplier_RealClient_WriteAlreadyExists_IdempotentSuccess(t *testing.T) {
	_, client := newFGA400Server(t, fgaAlreadyExistsBody)
	apply := clients.NewFGAApplier(client)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.write", ev)
	assertIdempotentReplay(t, err)
}

func TestFGAApplier_RealClient_DeleteCannotDelete_IdempotentSuccess(t *testing.T) {
	_, client := newFGA400Server(t, fgaCannotDeleteBody)
	apply := clients.NewFGAApplier(client)

	ev := clients.FGAOutboxEvent{User: "user:usr01", Relation: "system_admin", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.delete", ev)
	assertIdempotentReplay(t, err)
}

// TestFGAApplier_RealClient_WriteValidationError_StillPermanent — guard: a
// genuine 400 (bad tuple shape) must STILL surface the body and be classified
// as ErrPermanent poison — the body-reading fix must not swallow real errors.
func TestFGAApplier_RealClient_WriteValidationError_StillPermanent(t *testing.T) {
	const validationBody = `{"code":"validation_error","message":"type 'badtype' is undefined in the authorization model"}`
	_, client := newFGA400Server(t, validationBody)
	apply := clients.NewFGAApplier(client)

	ev := clients.FGAOutboxEvent{User: "badtype:x", Relation: "rel", Object: "cluster:default"}
	err := apply(context.Background(), "fga.tuple.write", ev)
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"genuine 400 validation_error must remain ErrPermanent (no retry); got: %v", err)
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: drainer-pipeline emulation (decoder → applier)
// ─────────────────────────────────────────────────────────────────────────────

// TestApplierPipeline_DecodeThenApply_Happy mimics the drainer's two-step
// (decoder → applier) pipeline on a real payload shape coming from
// bootstrap_admin.go. Sanity check that the JSON keys round-trip correctly.
func TestApplierPipeline_DecodeThenApply_Happy(t *testing.T) {
	// Exact payload shape from internal/apps/kacho/seed/bootstrap_admin.go:124-128.
	payload := []byte(`{"object":"cluster:default","relation":"system_admin","user":"user:usr01"}`)

	ev, err := clients.DecodeFGAOutboxEvent(payload)
	require.NoError(t, err)

	mock := &recordingOpenFGAClient{}
	apply := clients.NewFGAApplier(mock)
	require.NoError(t, apply(context.Background(), "fga.tuple.write", ev))

	require.Len(t, mock.writeCalls, 1)
	assert.Equal(t, clients.RelationTuple{
		User:     "user:usr01",
		Relation: "system_admin",
		Object:   "cluster:default",
	}, mock.writeCalls[0][0])
}
