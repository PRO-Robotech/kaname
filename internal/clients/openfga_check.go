// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_check.go — OpenFGAHTTPClient.CheckWithContext plus its wire
// request/response types. Conditional-tuple-aware Check with a
// per-request CEL-context map.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type fgaWireCheckRequest struct {
	AuthorizationModelID string          `json:"authorization_model_id,omitempty"`
	TupleKey             fgaWireTupleKey `json:"tuple_key"`
	Context              map[string]any  `json:"context,omitempty"`
	ContextualTuples     *struct {
		TupleKeys []fgaWireTupleKey `json:"tuple_keys"`
	} `json:"contextual_tuples,omitempty"`
	// Consistency — optional OpenFGA read-consistency preference (see
	// openfgaCheckRequest.Consistency). Empty ⇒ omitted ⇒ default MINIMIZE_LATENCY.
	Consistency string `json:"consistency,omitempty"`
}

type fgaWireCheckResponse struct {
	Allowed bool `json:"allowed"`
}

// CheckWithContext — see RelationQueries. Default (MINIMIZE_LATENCY) consistency.
func (c *OpenFGAHTTPClient) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	return c.checkWithContext(ctx, subject, relation, object, condCtx, "")
}

// CheckWithContextConsistent — CheckWithContext forcing HIGHER_CONSISTENCY (strong
// read-after-write). AuthorizeService.CheckRelation routes the owner-tuple
// confirm-gate probe here when the caller set CheckRequest.consistency =
// HIGHER_CONSISTENCY, so the probe never reads a stale-replica negative for a tuple
// just written to the same store.
func (c *OpenFGAHTTPClient) CheckWithContextConsistent(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	return c.checkWithContext(ctx, subject, relation, object, condCtx, consistencyHigherConsistency)
}

// checkWithContext is the shared CheckWithContext transport; consistency is the
// OpenFGA `consistency` wire value ("" ⇒ omitted ⇒ default MINIMIZE_LATENCY).
func (c *OpenFGAHTTPClient) checkWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any, consistency string) (bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return false, ErrNotConfigured
	}
	body, _ := json.Marshal(fgaWireCheckRequest{
		AuthorizationModelID: c.AuthorizationModel,
		TupleKey:             fgaWireTupleKey{User: subject, Relation: relation, Object: object},
		Context:              condCtx,
		Consistency:          consistency,
	})
	cctx, cancel := context.WithTimeout(ctx, c.checkTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/check", c.Endpoint, c.StoreID), body)
	if err != nil {
		return false, fmt.Errorf("openfga check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		//: a 400 is a client-side validation error — the relation
		// does not exist on the object's type, the object id is a typed
		// wildcard, etc. Such a Check can NEVER resolve to a path, so it is
		// semantically a DENY, not an outage. Returning an error here would
		// surface as `authz unavailable` and fail-closed to a misleading
		// 503; a clean deny (false, nil) yields the correct gRPC
		// PermissionDenied (403).
		//
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool instead of being torn down — mirrors the sibling
		// Check / writeOrDelete / listUsersOfType drain paths. Critical on the
		// hot authz path (CheckWithContext backs both the public authorize and
		// the internal per-RPC gate): a degraded OpenFGA emitting a burst of
		// 400s must not also churn fresh TCP connections (fd + handshake
		// pressure).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Same drain-for-reuse rationale as the 400 branch above: a degraded
		// OpenFGA returning non-200 on every Check must not churn connections.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, fmt.Errorf("openfga check: status %d", resp.StatusCode)
	}
	var r fgaWireCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, fmt.Errorf("openfga check decode: %w", err)
	}
	return r.Allowed, nil
}
