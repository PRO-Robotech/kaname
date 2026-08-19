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
	"net/http"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
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
	return c.checkWithContext(ctx, subject, relation, object, condCtx, "", nil)
}

// CheckWithContextualTuples — CheckWithContext plus tuples that hold for THIS
// request only. OpenFGA merges them into the tuple set for the duration of the
// Check, so they take part in graph resolution exactly as stored tuples do.
//
// Its one caller is the structural fallback in AuthorizeService: the tuples the
// super-access cascade derives over are projections of columns in rows iam has
// already committed, and supplying them here is what makes that cascade resolve
// from committed state instead of waiting for the outbox to deliver the same
// triples. Nothing is written — a contextual tuple has no effect outside the
// request that carried it.
func (c *OpenFGAHTTPClient) CheckWithContextualTuples(
	ctx context.Context, subject, relation, object string,
	condCtx map[string]any, contextual []authztypes.TupleKey,
) (bool, error) {
	return c.checkWithContext(ctx, subject, relation, object, condCtx, "", contextual)
}

// CheckWithContextConsistent — CheckWithContext forcing HIGHER_CONSISTENCY (strong
// read-after-write). AuthorizeService.CheckRelation routes the owner-tuple
// confirm-gate probe here when the caller set CheckRequest.consistency =
// HIGHER_CONSISTENCY, so the probe never reads a stale-replica negative for a tuple
// just written to the same store.
func (c *OpenFGAHTTPClient) CheckWithContextConsistent(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	return c.checkWithContext(ctx, subject, relation, object, condCtx, consistencyHigherConsistency, nil)
}

// checkWithContext is the shared CheckWithContext transport; consistency is the
// OpenFGA `consistency` wire value ("" ⇒ omitted ⇒ default MINIMIZE_LATENCY).
// contextual carries request-scoped tuples (nil ⇒ the field is omitted entirely).
func (c *OpenFGAHTTPClient) checkWithContext(
	ctx context.Context, subject, relation, object string,
	condCtx map[string]any, consistency string, contextual []authztypes.TupleKey,
) (bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return false, ErrNotConfigured
	}
	req := fgaWireCheckRequest{
		AuthorizationModelID: c.AuthorizationModel,
		TupleKey:             fgaWireTupleKey{User: subject, Relation: relation, Object: object},
		Context:              condCtx,
		Consistency:          consistency,
	}
	if len(contextual) > 0 {
		keys := make([]fgaWireTupleKey, 0, len(contextual))
		for _, t := range contextual {
			keys = append(keys, fgaWireTupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
		}
		req.ContextualTuples = &struct {
			TupleKeys []fgaWireTupleKey `json:"tuple_keys"`
		}{TupleKeys: keys}
	}
	body, _ := json.Marshal(req)
	var allowed bool
	rejected, err := c.fgaRead(ctx,
		fmt.Sprintf("http://%s/stores/%s/check", c.Endpoint, c.StoreID),
		body, c.checkTimeout(), fgaCheckMaxAttempts,
		func(resp *http.Response) error {
			var r fgaWireCheckResponse
			if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
				return err
			}
			allowed = r.Allowed
			return nil
		})
	if err != nil {
		return false, err
	}
	if rejected {
		// 400 — ошибка валидации вопроса, а не сбой: такой Check не разрешится
		// никогда, значит по смыслу это ОТКАЗ. Ошибка дала бы ложный 503 вместо
		// верного PermissionDenied (403). См. тот же разбор в openfga_client.go.
		return false, nil
	}
	return allowed, nil
}
