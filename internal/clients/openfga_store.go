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
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "GET",
		fmt.Sprintf("http://%s/stores/%s/authorization-models?page_size=1", c.Endpoint, c.StoreID),
		nil)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var r struct {
				AuthorizationModels []struct {
					ID        string    `json:"id"`
					SchemaVer string    `json:"schema_version"`
					CreatedAt time.Time `json:"created_at"`
				} `json:"authorization_models"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&r)
			if len(r.AuthorizationModels) > 0 {
				info.ModelCreatedAt = r.AuthorizationModels[0].CreatedAt
			}
		}
	}
	return info, nil
}
