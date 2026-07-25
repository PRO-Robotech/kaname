// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_read.go — OpenFGAHTTPClient.ReadTuples plus the read-only wire
// request/response types. The wire types are also consumed by
// ListSubjects (openfga_list.go) which builds on the same /read endpoint.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type fgaWireReadRequest struct {
	TupleKey          *fgaWireTupleKey `json:"tuple_key,omitempty"`
	PageSize          int              `json:"page_size,omitempty"`
	ContinuationToken string           `json:"continuation_token,omitempty"`
	// Consistency — OpenFGA read-consistency preference. Empty ⇒ omitted ⇒
	// OpenFGA default (MINIMIZE_LATENCY, replica/cache-eligible).
	Consistency string `json:"consistency,omitempty"`
}

type fgaWireReadResponse struct {
	Tuples []struct {
		Key       fgaWireTupleKey   `json:"key"`
		Condition *fgaWireCondition `json:"condition,omitempty"`
		Timestamp time.Time         `json:"timestamp"`
	} `json:"tuples"`
	ContinuationToken string `json:"continuation_token"`
}

// ReadTuples — see RelationQueries. OpenFGA's default (MINIMIZE_LATENCY)
// consistency: replica/cache-eligible, fine for a plain listing.
func (c *OpenFGAHTTPClient) ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]ConditionalTuple, string, error) {
	return c.readTuples(ctx, subjectFilter, relationFilter, objectFilter, pageSize, pageToken, "")
}

// ReadTuplesStrong is ReadTuples at HIGHER_CONSISTENCY — a strong read that
// bypasses replica lag / cache.
//
// Required by any read-MODIFY-write loop over the tuple store (the sync writer's
// read-then-write-delta, reconcile_adapter.go): such a loop terminates only
// because each already-exists rejection proves the racing writer committed a
// tuple our NEXT read will see, so the missing set strictly shrinks. Under
// OpenFGA HA (values.prod runs replicaCount>1 over one Postgres) a
// MINIMIZE_LATENCY read may serve a stale snapshot that does NOT show the
// racer's commit — the missing set then never shrinks and the loop burns its
// whole budget before abandoning the object. Mirrors ListObjects, which already
// always asks for HIGHER_CONSISTENCY.
func (c *OpenFGAHTTPClient) ReadTuplesStrong(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]ConditionalTuple, string, error) {
	return c.readTuples(ctx, subjectFilter, relationFilter, objectFilter, pageSize, pageToken, consistencyHigherConsistency)
}

func (c *OpenFGAHTTPClient) readTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken, consistency string) ([]ConditionalTuple, string, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, "", ErrNotConfigured
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	req := fgaWireReadRequest{
		PageSize:          pageSize,
		ContinuationToken: pageToken,
		Consistency:       consistency,
	}
	if subjectFilter != "" || relationFilter != "" || objectFilter != "" {
		req.TupleKey = &fgaWireTupleKey{
			User:     subjectFilter,
			Relation: relationFilter,
			Object:   objectFilter,
		}
	}
	body, _ := json.Marshal(req)
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/read", c.Endpoint, c.StoreID), body)
	if err != nil {
		return nil, "", fmt.Errorf("openfga read: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool — mirrors the sibling listUsersOfType drain path.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return nil, "", fmt.Errorf("openfga read: status %d", resp.StatusCode)
	}
	var r fgaWireReadResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, "", fmt.Errorf("openfga read decode: %w", err)
	}
	out := make([]ConditionalTuple, 0, len(r.Tuples))
	for _, t := range r.Tuples {
		tup := ConditionalTuple{
			User:     t.Key.User,
			Relation: t.Key.Relation,
			Object:   t.Key.Object,
		}
		if t.Condition != nil {
			tup.Condition = &TupleConditionRef{
				Name:    t.Condition.Name,
				Context: t.Condition.Context,
			}
		}
		out = append(out, tup)
	}
	return out, r.ContinuationToken, nil
}
