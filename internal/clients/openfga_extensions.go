// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_extensions.go — common types, interface, and HTTP transport
// helpers shared by the OpenFGAHTTPClient extension operations
// (Check / List / Expand / Read / Write / Store) split into sibling files.
//
// The original RelationStore interface stays in openfga_client.go.
package clients

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// ConditionalTuple / TupleConditionRef are neutral value types owned by
// internal/authztypes (so the service-layer ports can speak them without pinning
// to this adapter — dependency-rule fix). These aliases keep the adapter code
// ergonomic; the canonical definitions live in the leaf package.
type (
	// ConditionalTuple — alias of authztypes.ConditionalTuple.
	ConditionalTuple = authztypes.ConditionalTuple
	// TupleConditionRef — alias of authztypes.TupleConditionRef.
	TupleConditionRef = authztypes.TupleConditionRef
)

// RelationQueries — extension methods on the OpenFGA client port. Kept as
// a separate interface so production swap-in does not break the legacy
// RelationStore interface.
type RelationQueries interface {
	// CheckWithContext — Check with per-request CEL-context map. Used when
	// the tuple to be matched is Conditional.
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (allowed bool, err error)

	// ListObjects — return up to `maxResults` object ids (no type prefix)
	// the subject has `relation` on, within `objectType`.
	ListObjects(ctx context.Context, subject, relation, objectType string, condCtx map[string]any, maxResults int) ([]string, error)

	// ListSubjects — inverse of ListObjects. Returns ONLY the subjects on the
	// literal (object, relation) tuple: a flat /read that does NOT traverse
	// computed-userset cascades (admin⇒editor⇒viewer), scope_grant indirection
	// or group#member usersets. For the effective (graph-expanded) principal set
	// use ExpandRelations / ListUsers (see openfga_list.go).
	ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error)

	// Expand — Zanzibar userset tree for (object, relation).
	Expand(ctx context.Context, objectType, objectID, relation string) (*ExpandTree, error)

	// ReadTuples — filtered read; nil-zero filters are wildcard.
	ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]ConditionalTuple, string, error)

	// WriteConditionalTuples — write tuples with optional Conditional
	// attachments. Idempotent on duplicate.
	WriteConditionalTuples(ctx context.Context, writes, deletes []ConditionalTuple) error

	// GetStoreInfo — store_id, model_id, tuple_count, model_created_at,
	// engine_version (best-effort).
	GetStoreInfo(ctx context.Context) (StoreInfo, error)
}

// ── HTTP impl on top of OpenFGAHTTPClient ────────────────────────────────

// Default per-operation timeouts. Applied when the corresponding
// OpenFGAHTTPClient field is zero. Overridable per-instance by the
// composition root (see FGATimeouts / FGATimeoutsFromEnv).
const (
	defaultFGACheckTimeout = 200 * time.Millisecond
	defaultFGAListTimeout  = 1000 * time.Millisecond
	defaultFGAWriteTimeout = 1000 * time.Millisecond
)

// maxErrBodyBytes caps how much of a non-2xx OpenFGA response body is read into
// an error/log line, mirroring the sibling read paths (openfga_list.go
// listUsersOfType, hydra_* clients). A misbehaving / compromised OpenFGA that
// returns a multi-KB 400 body must not spike memory or bloat the interpolated
// error+log line.
const maxErrBodyBytes = 4096

// checkTimeout / listTimeout / writeTimeout — resolve the effective per-op
// deadline, falling back to the package default when the field is zero.
func (c *OpenFGAHTTPClient) checkTimeout() time.Duration {
	if c.CheckTimeout > 0 {
		return c.CheckTimeout
	}
	return defaultFGACheckTimeout
}

func (c *OpenFGAHTTPClient) listTimeout() time.Duration {
	if c.ListTimeout > 0 {
		return c.ListTimeout
	}
	return defaultFGAListTimeout
}

func (c *OpenFGAHTTPClient) writeTimeout() time.Duration {
	if c.WriteTimeout > 0 {
		return c.WriteTimeout
	}
	return defaultFGAWriteTimeout
}

// DefaultFGACheckTimeout / DefaultFGAListTimeout / DefaultFGAWriteTimeout —
// exported defaults for the composition root to use when resolving per-op
// timeouts from config/env.
const (
	DefaultFGACheckTimeout = defaultFGACheckTimeout
	DefaultFGAListTimeout  = defaultFGAListTimeout
	DefaultFGAWriteTimeout = defaultFGAWriteTimeout
)

// httpDoer interface — overridable in tests.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// retryClient — naive 3x exponential retry on 5xx + transport errors.
type retryClient struct {
	inner   httpDoer
	maxTry  int
	backoff time.Duration
}

func newRetryClient(c httpDoer, maxTry int, baseBackoff time.Duration) *retryClient {
	if c == nil {
		c = http.DefaultClient
	}
	if maxTry <= 0 {
		maxTry = 3
	}
	if baseBackoff <= 0 {
		baseBackoff = 20 * time.Millisecond
	}
	return &retryClient{inner: c, maxTry: maxTry, backoff: baseBackoff}
}

func (r *retryClient) Do(req *http.Request) (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response
	for attempt := 0; attempt < r.maxTry; attempt++ {
		if attempt > 0 {
			sleep := time.Duration(1<<uint(attempt-1)) * r.backoff // #nosec G115 -- attempt>0 guaranteed by enclosing branch; attempt-1 non-negative.
			select {
			case <-time.After(sleep):
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		// Re-set body on retry (Body is consumed on Do).
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}
		resp, err := r.inner.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		// Retry on 5xx; success and 4xx returned immediately.
		if resp.StatusCode < 500 {
			return resp, nil
		}
		lastResp = resp
		_ = resp.Body.Close()
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, errors.New("openfga: retry exhausted")
}

// fgaWireTupleKey — JSON shape for FGA tuple keys shared across all
// operations (check / write / read / list / expand).
type fgaWireTupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// fgaWireCondition — JSON shape for the Conditional-tuple attachment used
// by write requests and surfaced on read responses.
type fgaWireCondition struct {
	Name    string         `json:"name"`
	Context map[string]any `json:"context,omitempty"`
}

// do — common HTTP transport with retry. Wraps method/url/body construction.
func (c *OpenFGAHTTPClient) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		bb := body
		req.GetBody = func() (io.ReadCloser, error) {
			return &nopCloser{Reader: bytes.NewReader(bb)}, nil
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
	}
	return newRetryClient(http.DefaultClient, 3, 20*time.Millisecond).Do(req)
}

// nopCloser — io.ReadCloser shim for http.Request.GetBody.
type nopCloser struct {
	*bytes.Reader
}

func (n *nopCloser) Close() error { return nil }

// Compile-time assertion.
var _ RelationQueries = (*OpenFGAHTTPClient)(nil)
