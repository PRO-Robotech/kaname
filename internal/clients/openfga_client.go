// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package clients — peer-сервисов клиенты (адаптеры).
//
// openfga_client.go — port-iface + HTTP impl для openfga операций
// (Check / Write / Delete / Read / ListObjects / Expand). In-memory stub
// lives in openfga_stub_test.go (test-only, never compiled into production).
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RelationTuple — стандартный FGA tuple struct.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

// RelationStore — port-iface для openfga-операций.
type RelationStore interface {
	// Check выполняет authorization check.
	Check(ctx context.Context, subject, relation, object string) (allowed bool, err error)

	// WriteTuples атомарно записывает batch tuples (idempotent: 409 = success).
	WriteTuples(ctx context.Context, tuples []RelationTuple) error

	// DeleteTuples атомарно удаляет batch tuples (idempotent: missing = success).
	DeleteTuples(ctx context.Context, tuples []RelationTuple) error
}

// (OpenFGAStubClient lives in openfga_stub_test.go — test-only.)

// ── HTTP REST implementation ──────────────────────────────────────────────

// OpenFGAHTTPClient — HTTP wrapper over the OpenFGA REST API
// (POST /stores/{id}/check, /write, /list-objects, /read, /expand).
//
// Per-operation timeouts are instance fields (not package-level vars) so they
// are populated by the composition root, not at package init() time. A zero
// value falls back to the defaults in openfga_extended.go (fgaTimeout).
type OpenFGAHTTPClient struct {
	Endpoint           string
	StoreID            string
	AuthorizationModel string

	// CheckTimeout / ListTimeout / WriteTimeout — per-operation context
	// deadlines. Zero ⇒ package defaults (see openfga_extended.go).
	CheckTimeout time.Duration
	ListTimeout  time.Duration
	WriteTimeout time.Duration
}

// ErrNotConfigured — returned by the HTTP methods if Endpoint/StoreID are
// empty. The composition root (cmd/kacho-iam) fails fast before constructing
// the client, so this only guards against a programmer wiring error.
var ErrNotConfigured = errors.New("openfga: HTTP client not configured")

type openfgaWriteRequest struct {
	AuthorizationModelID string `json:"authorization_model_id,omitempty"`
	Writes               *struct {
		TupleKeys []openfgaTupleKey `json:"tuple_keys"`
	} `json:"writes,omitempty"`
	Deletes *struct {
		TupleKeys []openfgaTupleKey `json:"tuple_keys"`
	} `json:"deletes,omitempty"`
}

type openfgaTupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type openfgaCheckRequest struct {
	AuthorizationModelID string          `json:"authorization_model_id,omitempty"`
	TupleKey             openfgaTupleKey `json:"tuple_key"`
	// Consistency — optional OpenFGA read-consistency preference. Empty ⇒ field
	// omitted ⇒ OpenFGA default (MINIMIZE_LATENCY). Set to
	// consistencyHigherConsistency only for the read-after-own-write confirm probe.
	Consistency string `json:"consistency,omitempty"`
}

type openfgaCheckResponse struct {
	Allowed bool `json:"allowed"`
}

// Check — per-RPC authz Check at OpenFGA's default (MINIMIZE_LATENCY) consistency:
// the hot enforcement gate stays cache/replica-eligible (low latency).
func (c *OpenFGAHTTPClient) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return c.check(ctx, subject, relation, object, "")
}

// CheckConsistent — Check forcing HIGHER_CONSISTENCY (strong read-after-write). Used
// by the owner-tuple confirm-gate (in-process iam probe): the tuple was written to
// the SAME store on this create path, so the probe must not be served a stale
// negative from a lagging replica. Idempotent / read-only, same contract as Check.
func (c *OpenFGAHTTPClient) CheckConsistent(ctx context.Context, subject, relation, object string) (bool, error) {
	return c.check(ctx, subject, relation, object, consistencyHigherConsistency)
}

// check is the shared Check transport; consistency is the OpenFGA `consistency`
// wire value ("" ⇒ omitted ⇒ default MINIMIZE_LATENCY).
func (c *OpenFGAHTTPClient) check(ctx context.Context, subject, relation, object, consistency string) (bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return false, ErrNotConfigured
	}
	// Bound the per-RPC authz Check to the configured CheckTimeout (default 200ms):
	// http.DefaultClient has no Timeout, so an OpenFGA that accepts the TCP connection
	// but stops responding (GC pause / overload / half-open TCP after a partition)
	// would otherwise hang the authz-interceptor goroutine forever instead of failing
	// closed within the FGA budget (D-47 "FGA outage → Unavailable"). Mirrors the
	// sibling CheckWithContext / c.do() paths, which are already time-bounded.
	cctx, cancel := context.WithTimeout(ctx, c.checkTimeout())
	defer cancel()
	body, _ := json.Marshal(openfgaCheckRequest{
		AuthorizationModelID: c.AuthorizationModel,
		TupleKey:             openfgaTupleKey{User: subject, Relation: relation, Object: object},
		Consistency:          consistency,
	})
	req, _ := http.NewRequestWithContext(cctx, http.MethodPost,
		fmt.Sprintf("http://%s/stores/%s/check", c.Endpoint, c.StoreID),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("openfga check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		//: a 400 is a client-side validation error (relation absent
		// on the object type, typed-wildcard object, ...) — such a Check can
		// never resolve, so it is a clean DENY, not an outage.
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool instead of being torn down — mirrors the sibling
		// writeOrDelete / listUsersOfType drain paths. Critical on the hot
		// authz path: a degraded OpenFGA emitting a burst of 400s must not also
		// churn fresh TCP connections (fd + TLS/handshake pressure).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Same drain-for-reuse rationale as the 400 branch above: a degraded
		// OpenFGA returning 5xx on every Check must not churn connections.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, fmt.Errorf("openfga check: status %d", resp.StatusCode)
	}
	var r openfgaCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, fmt.Errorf("openfga check decode: %w", err)
	}
	return r.Allowed, nil
}

// maxTuplesPerWriteRequest mirrors OpenFGA's default maxTuplesPerWrite (100): a
// single /write request may carry at most this many tuple_keys or OpenFGA rejects
// the WHOLE request with a 400 validation_error and applies NONE of them. The
// reconciler's create-path synchronous write (reconcile.applyAfterCommit) batches the
// entire tuple-set of one ReconcileObject pass, which exceeds 100 when the object is
// matched by multiple bounded `*.*` ARM_ANCHOR bindings on a populated account (the
// iam-access-binding read-after-write tail, #232). Chunking here keeps the sync-FGA
// reconciler path (WriteTuples/DeleteTuples) under the wire limit; the async fga_outbox
// drainer already applies row-by-row, so it is unaffected. The admin WriteRaw path
// (WriteConditionalTuples) does NOT chunk — it is bounded instead by the
// InternalAuthorize.WriteTuples handler's per-batch guard, which must count
// writes+deletes COMBINED against this same wire cap (OpenFGA's maxTuplesPerWrite counts
// both directions in one request). Set to exactly OpenFGA's documented
// default (100); the deploy does not lower the server limit (no maxTuplesPerWrite
// override in the umbrella chart).
const maxTuplesPerWriteRequest = 100

func (c *OpenFGAHTTPClient) WriteTuples(ctx context.Context, tuples []RelationTuple) error {
	return c.writeOrDeleteChunked(ctx, tuples, true)
}

func (c *OpenFGAHTTPClient) DeleteTuples(ctx context.Context, tuples []RelationTuple) error {
	return c.writeOrDeleteChunked(ctx, tuples, false)
}

// writeOrDeleteChunked splits the tuple-set into ≤maxTuplesPerWriteRequest batches and
// applies each in its own OpenFGA request, so a large fan-out is not rejected wholesale
// by OpenFGA's per-request limit. Each chunk keeps the idempotent already_exists /
// cannot_delete semantics of writeOrDelete; a chunk error aborts the rest (the
// at-least-once fga_outbox enqueue committed in the writer-tx is the backstop, and the
// caller — applyAfterCommit — logs best-effort).
func (c *OpenFGAHTTPClient) writeOrDeleteChunked(ctx context.Context, tuples []RelationTuple, write bool) error {
	if len(tuples) == 0 {
		return nil
	}
	for start := 0; start < len(tuples); start += maxTuplesPerWriteRequest {
		end := start + maxTuplesPerWriteRequest
		if end > len(tuples) {
			end = len(tuples)
		}
		if err := c.writeOrDelete(ctx, tuples[start:end], write); err != nil {
			return err
		}
	}
	return nil
}

func (c *OpenFGAHTTPClient) writeOrDelete(ctx context.Context, tuples []RelationTuple, write bool) error {
	if c.Endpoint == "" || c.StoreID == "" {
		return ErrNotConfigured
	}
	if len(tuples) == 0 {
		return nil
	}
	keys := make([]openfgaTupleKey, 0, len(tuples))
	for _, t := range tuples {
		keys = append(keys, openfgaTupleKey(t))
	}
	r := openfgaWriteRequest{AuthorizationModelID: c.AuthorizationModel}
	if write {
		r.Writes = &struct {
			TupleKeys []openfgaTupleKey `json:"tuple_keys"`
		}{TupleKeys: keys}
	} else {
		r.Deletes = &struct {
			TupleKeys []openfgaTupleKey `json:"tuple_keys"`
		}{TupleKeys: keys}
	}
	body, _ := json.Marshal(r)
	// Bound the write/delete request to the configured WriteTimeout (default
	// 1s): http.DefaultClient has no Timeout, so an OpenFGA that accepts the
	// TCP connection but stops responding (GC pause / overload / half-open TCP
	// after a partition) would otherwise hang the calling goroutine forever —
	// especially harmful for the detached, deadline-less access_binding
	// revoke retry loop (delete.go syncRemoveTuples), which has no caller-side
	// deadline to fall back on. Mirrors the sibling Check / WriteConditionalTuples
	// paths, which are already time-bounded.
	cctx, cancel := context.WithTimeout(ctx, c.writeTimeout())
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodPost,
		fmt.Sprintf("http://%s/stores/%s/write", c.Endpoint, c.StoreID),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("openfga write: %w", err)
	}
	defer resp.Body.Close()
	// Idempotent: 200 = success. On 400 we MUST read the body so the FGA error
	// vocabulary (already_exists / cannot_delete) reaches the caller —
	// otherwise a bare "status 400" is mis-classified as a permanent poison by
	// fga_applier.classifyFGA*Err (mirrors WriteConditionalTuples).
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		// Cap the 400-body read (io.LimitReader) like the sibling read paths
		// (openfga_list.go) so a misbehaving OpenFGA cannot spike memory / bloat
		// the error+log line with a multi-KB body. The idempotent markers
		// (already_exists / cannot_delete) appear within the first bytes.
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, maxErrBodyBytes))
		s := buf.String()
		// Idempotent replay: writing a tuple that already exists, or deleting
		// one that no longer exists, is a success at the adapter — the desired
		// post-condition already holds.
		if write && bytes.Contains([]byte(s), []byte("already_exists")) {
			return nil
		}
		if !write && bytes.Contains([]byte(s), []byte("cannot_delete")) {
			return nil
		}
		return fmt.Errorf("openfga write: bad request: %s", s)
	}
	return fmt.Errorf("openfga write: status %d", resp.StatusCode)
}

var _ RelationStore = (*OpenFGAHTTPClient)(nil)
