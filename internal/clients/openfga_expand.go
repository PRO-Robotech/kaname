// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_expand.go — OpenFGAHTTPClient.Expand plus the Zanzibar
// userset-tree types (ExpandTree, ComputedEdge, TupleToUsersetEdge) and
// the expand-only wire request/response + tree conversion helper.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// The Zanzibar userset-tree types are neutral value types owned by
// internal/authztypes so the service-layer ports can speak them without pinning
// to this adapter (dependency-rule fix). These aliases keep the adapter's own
// code + method signatures ergonomic while the canonical definitions live in the
// leaf package.
type (
	// ExpandTree — Zanzibar userset tree node. Alias of authztypes.ExpandTree.
	ExpandTree = authztypes.ExpandTree
	// ComputedEdge — same-object userset. Alias of authztypes.ComputedEdge.
	ComputedEdge = authztypes.ComputedEdge
	// TupleToUsersetEdge — parent-resource cascade. Alias of authztypes.TupleToUsersetEdge.
	TupleToUsersetEdge = authztypes.TupleToUsersetEdge
)

type fgaWireExpandRequest struct {
	AuthorizationModelID string          `json:"authorization_model_id,omitempty"`
	TupleKey             fgaWireTupleKey `json:"tuple_key"`
}

type fgaWireExpandResponse struct {
	Tree struct {
		Root fgaWireUsersetTree `json:"root"`
	} `json:"tree"`
}

type fgaWireUsersetTree struct {
	Name string `json:"name,omitempty"`
	Leaf *struct {
		Users *struct {
			Users []string `json:"users"`
		} `json:"users,omitempty"`
		Computed *struct {
			Userset string `json:"userset"`
		} `json:"computed,omitempty"`
	} `json:"leaf,omitempty"`
	Union *struct {
		Nodes []fgaWireUsersetTree `json:"nodes"`
	} `json:"union,omitempty"`
}

// Expand — see RelationQueries.
func (c *OpenFGAHTTPClient) Expand(ctx context.Context, objectType, objectID, relation string) (*ExpandTree, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, ErrNotConfigured
	}
	body, _ := json.Marshal(fgaWireExpandRequest{
		AuthorizationModelID: c.AuthorizationModel,
		TupleKey: fgaWireTupleKey{
			Relation: relation,
			Object:   fmt.Sprintf("%s:%s", objectType, objectID),
		},
	})
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/expand", c.Endpoint, c.StoreID), body)
	if err != nil {
		return nil, fmt.Errorf("openfga expand: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool — mirrors the sibling listUsersOfType drain path.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return nil, fmt.Errorf("openfga expand: status %d", resp.StatusCode)
	}
	var r fgaWireExpandResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("openfga expand decode: %w", err)
	}
	return convertWireTree(&r.Tree.Root), nil
}

func convertWireTree(w *fgaWireUsersetTree) *ExpandTree {
	if w == nil {
		return nil
	}
	out := &ExpandTree{}
	if w.Leaf != nil && w.Leaf.Users != nil {
		out.Leaves = append(out.Leaves, w.Leaf.Users.Users...)
	}
	if w.Union != nil {
		for i := range w.Union.Nodes {
			out.Computed = append(out.Computed, ComputedEdge{
				Relation: w.Union.Nodes[i].Name,
				Subtree:  convertWireTree(&w.Union.Nodes[i]),
			})
		}
	}
	return out
}
