// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_store.go — OpenFGAHTTPClient.GetStoreInfo and the StoreInfo
// type. Best-effort metadata fetch (store_id, model_id, model_created_at,
// engine_version) used by health/diagnostics surfaces.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// StoreInfo — FGA store metadata. Neutral value type owned by
// internal/authztypes (dependency-rule fix); alias kept for adapter ergonomics.
type StoreInfo = authztypes.StoreInfo

// GetStoreInfo — see RelationQueries.
func (c *OpenFGAHTTPClient) GetStoreInfo(ctx context.Context) (StoreInfo, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return StoreInfo{}, ErrNotConfigured
	}
	info := StoreInfo{
		StoreID:              c.StoreID,
		AuthorizationModelID: c.AuthorizationModel,
		EngineVersion:        "openfga/openfga (kacho-iam wire-compat)",
	}
	// Best-effort: fetch authorization-models to populate model_created_at.
	if _, createdAt, err := c.latestModel(ctx); err == nil {
		info.ModelCreatedAt = createdAt
	}
	return info, nil
}

// LatestAuthorizationModelID reports the id of the most recently written
// authorization model in the store.
//
// This is NOT the id this process evaluates against: that one is
// c.AuthorizationModel, pinned by env for the process lifetime (and, when unset,
// resolved by OpenFGA to "latest" on every call). The distinction is the whole
// point of the method — the two differ EXACTLY while a new model has landed and
// this process has not adopted it, which is the window that poisons the tuple
// outbox: an intent naming a relation the then-current model did not carry is
// refused with a 400, classified permanent (correctly — an identical retry cannot
// pass), and never tried again.
//
// The value is therefore consumed as a CHANGE SIGNAL, not as a truth about
// evaluation: something that could turn a permanent refusal into a passing write
// has happened. See fga_outbox_redrive_backstop.go.
//
// An empty id with a nil error means the store has no model yet — a legitimate
// pre-bootstrap state, not a failure, and not a change.
func (c *OpenFGAHTTPClient) LatestAuthorizationModelID(ctx context.Context) (string, error) {
	id, _, err := c.latestModel(ctx)
	return id, err
}

// latestModel reads the head of the store's authorization-model list. OpenFGA
// returns them most-recent-first, so page_size=1 is the newest one and the call
// stays O(1) regardless of how many models the store has accumulated.
func (c *OpenFGAHTTPClient) latestModel(ctx context.Context) (string, time.Time, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return "", time.Time{}, ErrNotConfigured
	}
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "GET",
		fmt.Sprintf("http://%s/stores/%s/authorization-models?page_size=1", c.Endpoint, c.StoreID),
		nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("openfga: read authorization-models: status %d", resp.StatusCode)
	}
	var r struct {
		AuthorizationModels []struct {
			ID        string    `json:"id"`
			SchemaVer string    `json:"schema_version"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"authorization_models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", time.Time{}, fmt.Errorf("openfga: decode authorization-models: %w", err)
	}
	if len(r.AuthorizationModels) == 0 {
		return "", time.Time{}, nil
	}
	return r.AuthorizationModels[0].ID, r.AuthorizationModels[0].CreatedAt, nil
}
