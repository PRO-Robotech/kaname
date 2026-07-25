// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_write.go — OpenFGAHTTPClient.WriteConditionalTuples plus its
// write-only wire request types (writes/deletes with optional Conditional
// attachments). Idempotent on already_exists / cannot_delete.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
)

type fgaWireTupleKeyWithCondition struct {
	User      string            `json:"user"`
	Relation  string            `json:"relation"`
	Object    string            `json:"object"`
	Condition *fgaWireCondition `json:"condition,omitempty"`
}

type fgaWireWriteRequest struct {
	AuthorizationModelID string `json:"authorization_model_id,omitempty"`
	Writes               *struct {
		TupleKeys []fgaWireTupleKeyWithCondition `json:"tuple_keys"`
	} `json:"writes,omitempty"`
	Deletes *struct {
		TupleKeys []fgaWireTupleKey `json:"tuple_keys"`
	} `json:"deletes,omitempty"`
}

// WriteConditionalTuples — see RelationQueries.
func (c *OpenFGAHTTPClient) WriteConditionalTuples(ctx context.Context, writes, deletes []ConditionalTuple) error {
	if c.Endpoint == "" || c.StoreID == "" {
		return ErrNotConfigured
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	r := fgaWireWriteRequest{AuthorizationModelID: c.AuthorizationModel}
	if len(writes) > 0 {
		wk := make([]fgaWireTupleKeyWithCondition, 0, len(writes))
		for _, t := range writes {
			tk := fgaWireTupleKeyWithCondition{
				User:     t.User,
				Relation: t.Relation,
				Object:   t.Object,
			}
			if t.Condition != nil && t.Condition.Name != "" {
				tk.Condition = &fgaWireCondition{
					Name:    t.Condition.Name,
					Context: t.Condition.Context,
				}
			}
			wk = append(wk, tk)
		}
		r.Writes = &struct {
			TupleKeys []fgaWireTupleKeyWithCondition `json:"tuple_keys"`
		}{TupleKeys: wk}
	}
	if len(deletes) > 0 {
		dk := make([]fgaWireTupleKey, 0, len(deletes))
		for _, t := range deletes {
			dk = append(dk, fgaWireTupleKey{
				User: t.User, Relation: t.Relation, Object: t.Object,
			})
		}
		r.Deletes = &struct {
			TupleKeys []fgaWireTupleKey `json:"tuple_keys"`
		}{TupleKeys: dk}
	}
	body, _ := json.Marshal(r)
	// Idempotent replay applies ONLY to a request carrying exactly ONE tuple in ONE
	// direction. OpenFGA's write is TRANSACTIONAL — a rejected request applies NONE
	// of its tuples — so "already exists" / "does not exist" equals "the desired
	// post-condition holds" only when that one tuple WAS the whole request. For a
	// MIXED batch (writes AND deletes) the write-duplicate marker would additionally
	// swallow the un-applied deletes: a revoke reported as applied while the tuple
	// survives (over-grant). For a multi-tuple single-direction batch it would lose
	// the siblings that never landed.
	var idempotent func(string) bool
	switch {
	case len(writes) == 1 && len(deletes) == 0:
		idempotent = idempotentWriteReply
	case len(deletes) == 1 && len(writes) == 0:
		idempotent = idempotentDeleteReply
	}
	// Retry while OpenFGA aborts the transaction on a concurrent-write conflict
	// (409 — nothing applied, safe to replay; see openfga_conflict.go). Each
	// attempt carries its own WriteTimeout deadline.
	return applyWithConflictRetry(ctx, func(ctx context.Context) error {
		cctx, cancel := context.WithTimeout(ctx, c.writeTimeout())
		defer cancel()
		resp, err := c.do(cctx, "POST",
			fmt.Sprintf("http://%s/stores/%s/write", c.Endpoint, c.StoreID), body)
		if err != nil {
			return fmt.Errorf("openfga write: %w", err)
		}
		defer resp.Body.Close()
		return readWriteReply(resp, idempotent)
	})
}
