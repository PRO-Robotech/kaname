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
}

type fgaWireReadResponse struct {
	Tuples []struct {
		Key       fgaWireTupleKey   `json:"key"`
		Condition *fgaWireCondition `json:"condition,omitempty"`
		Timestamp time.Time         `json:"timestamp"`
	} `json:"tuples"`
	ContinuationToken string `json:"continuation_token"`
}

// ReadTuples — see RelationQueries.
func (c *OpenFGAHTTPClient) ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]ConditionalTuple, string, error) {
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
