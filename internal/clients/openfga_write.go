// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_write.go — OpenFGAHTTPClient.WriteConditionalTuples plus its
// write-only wire request types (writes/deletes with optional Conditional
// attachments). Idempotent on already_exists / cannot_delete.
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	cctx, cancel := context.WithTimeout(ctx, c.writeTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/write", c.Endpoint, c.StoreID), body)
	if err != nil {
		return fmt.Errorf("openfga write: %w", err)
	}
	defer resp.Body.Close()
	// Idempotent: 200 success; 400 with already-exists treated as success
	// (caller-side dedup via idempotency_key).
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		// Read body (capped) briefly; if it contains "already_exists" or
		// "cannot_delete" the write is idempotent. Cap via io.LimitReader like
		// the sibling read path (openfga_list.go) so a misbehaving OpenFGA cannot
		// spike memory / bloat the error+log line with a multi-KB body.
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, maxErrBodyBytes))
		s := buf.String()
		if bytes.Contains([]byte(s), []byte("already_exists")) ||
			bytes.Contains([]byte(s), []byte("cannot_delete")) {
			return nil
		}
		return fmt.Errorf("openfga write: bad request: %s", s)
	}
	return fmt.Errorf("openfga write: status %d", resp.StatusCode)
}
