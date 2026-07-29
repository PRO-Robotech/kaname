// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_list.go — OpenFGAHTTPClient.ListObjects + ListSubjects with
// their list-only wire request/response types. ListObjects returns the
// objects of a given type a subject has a relation on; ListSubjects is
// the inverse, implemented via filtered Read.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type fgaWireListObjectsRequest struct {
	AuthorizationModelID string         `json:"authorization_model_id,omitempty"`
	User                 string         `json:"user"`
	Relation             string         `json:"relation"`
	Type                 string         `json:"type"`
	Context              map[string]any `json:"context,omitempty"`
	// Consistency — OpenFGA read-consistency preference (see openfgaCheckRequest.
	// Consistency). ListObjects always sends HIGHER_CONSISTENCY — see the method doc.
	Consistency string `json:"consistency,omitempty"`
}

type fgaWireListObjectsResponse struct {
	Objects []string `json:"objects"`
}

// ListObjects — see RelationQueries.
//
// Server cap (important): the wire request below carries NO page_size /
// max_results field, because OpenFGA's list-objects endpoint has none — it
// applies its OWN ceiling (OPENFGA_LIST_OBJECTS_MAX_RESULTS, default 1000) and
// returns no continuation token. The `maxResults` argument is therefore applied
// HERE, client-side, as a trim of an already-bounded response: it can only make
// the answer smaller. There is no way for this method to ask for more.
//
// Consistency: ListObjects always sends HIGHER_CONSISTENCY (strong read-after-write),
// unlike the hot per-RPC enforcement Check which keeps OpenFGA's cache-eligible
// default (MINIMIZE_LATENCY). ListObjects resolves a subject's VISIBLE set for a
// List RPC (list-authz), which is inherently a read-your-writes path: a subject that
// just created a resource — its owner tuple written synchronously to the primary —
// must see its OWN object on the very first List. Under the deployed multi-replica
// OpenFGA a default read can land on a lagging replica and omit the fresh object for
// seconds (the compute list-includes flake). Reading strong restores parity with the
// confirm-gate Check (CheckWithContextConsistent), which already resolves fresh. This
// is the same "strong-read only where read-your-writes correctness demands it"
// philosophy: List demands it; the hot single-object enforcement gate does not
// (covered by the confirm-gate / bounded client-retry). List RPCs are far lower
// frequency than per-RPC Checks, so the strong-read cost is bounded.
func (c *OpenFGAHTTPClient) ListObjects(ctx context.Context, subject, relation, objectType string, condCtx map[string]any, maxResults int) ([]string, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, ErrNotConfigured
	}
	body, _ := json.Marshal(fgaWireListObjectsRequest{
		AuthorizationModelID: c.AuthorizationModel,
		User:                 subject,
		Relation:             relation,
		Type:                 objectType,
		Context:              condCtx,
		Consistency:          consistencyHigherConsistency,
	})
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/list-objects", c.Endpoint, c.StoreID), body)
	if err != nil {
		return nil, fmt.Errorf("openfga listObjects: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool — mirrors the sibling listUsersOfType drain path.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return nil, fmt.Errorf("openfga listObjects: status %d", resp.StatusCode)
	}
	var r fgaWireListObjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("openfga listObjects decode: %w", err)
	}
	if maxResults > 0 && len(r.Objects) > maxResults {
		r.Objects = r.Objects[:maxResults]
	}
	// Strip "<objectType>:" prefix — FGA returns fully-qualified objects
	// ("vpc_network:enp...") but the contract specifies bare ids ("enp...").
	prefix := objectType + ":"
	stripped := make([]string, 0, len(r.Objects))
	for _, obj := range r.Objects {
		if len(obj) > len(prefix) && obj[:len(prefix)] == prefix {
			stripped = append(stripped, obj[len(prefix):])
		} else {
			stripped = append(stripped, obj) // unexpected format — pass through
		}
	}
	return stripped, nil
}

// ── ListUsers (graph-traversing concrete-principal resolution) ────────────────
//
// OpenFGA's POST /stores/{id}/list-users returns the CONCRETE users (per the
// `user_filters` types) that have `relation` on the object, natively traversing
// the WHOLE authorization graph — computed-userset cascades (admin⇒editor⇒viewer),
// scope_grant indirection (`g_*_<type> from <anchor>`), and group#member usersets.
// This is what ExpandAccess needs: a flat Read (ListSubjects) only sees literal
// tuples on the exact (object, relation) node and CANNOT resolve any indirection,
// so a rules-model grant (scope_grant / computed cascade) returned ZERO members.
//
// `user_filters` is restricted to the concrete principal types ({user},
// {service_account}); FGA then returns only `object`-form entries (no usersets /
// wildcards), so the result is exactly the set of concrete grantees with the
// group memberships already expanded by FGA (no hand-rolled recursion / cycle
// guard — the server bounds the walk).

type fgaWireUserTypeFilter struct {
	Type     string `json:"type"`
	Relation string `json:"relation,omitempty"`
}

type fgaWireListUsersObject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type fgaWireListUsersRequest struct {
	AuthorizationModelID string                  `json:"authorization_model_id,omitempty"`
	Object               fgaWireListUsersObject  `json:"object"`
	Relation             string                  `json:"relation"`
	UserFilters          []fgaWireUserTypeFilter `json:"user_filters"`
}

// OpenFGA v1.8.x enforces user_filters length == 1 per ListUsers request, so we
// issue one request per concrete principal type and merge (the WHOLE-graph
// traversal is performed per call — the only thing scoped per request is the
// returned principal TYPE).

// fgaWireListUsersResponse — `users[]` entries are a tagged union: an `object`
// (concrete principal — what the type-filtered query yields), a `userset`
// (group#member etc. — excluded by our concrete-type filters) or a `wildcard`
// (public access). We read only the `object` form; `userset`/`wildcard` entries
// are skipped (they are not concrete principals).
type fgaWireListUsersResponse struct {
	Users []struct {
		Object *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"object,omitempty"`
		Userset *struct {
			Type     string `json:"type"`
			ID       string `json:"id"`
			Relation string `json:"relation"`
		} `json:"userset,omitempty"`
		Wildcard *struct {
			Type string `json:"type"`
		} `json:"wildcard,omitempty"`
	} `json:"users"`
}

// ListUsersServerCap — OpenFGA's OWN server-side ceiling on a list-users
// response (`OPENFGA_LIST_USERS_MAX_RESULTS`; default 1000, and unset — hence
// default — on the deployed stand). Sibling of fgaListObjectsServerCap, and the
// same reasoning: the ceiling is applied by the SERVER, the reply is a bare
// `users[]` with NO continuation token, so a response of exactly this size is
// indistinguishable from "there were more" and must be reported as truncated.
//
// It has to be stated here because the answer carries no other trace: comparing
// the length against anything WE chose (a client-side trim, a caller's
// max_results) cannot see the cut — our own number is at least as large as
// whatever the server hands back, so the comparison is false by construction and
// the caller is told the answer is complete.
//
// Do NOT "fix" a truncated answer by raising this. It is an external, finite
// bound. That the deployment leaves it at the default is asserted, not assumed —
// see TestListUsersServerCap_DeploymentDoesNotOverrideIt.
const ListUsersServerCap = 1000

// ListUsers resolves the CONCRETE principals (FGA-prefixed: "user:<id>" /
// "service_account:<id>") that hold `relation` on `objectType:objectID`,
// traversing the full authorization graph. userTypes is the closed set of
// concrete principal types to resolve (e.g. {"user","service_account"}); a
// userset/wildcard entry in the response is skipped (not a concrete principal).
//
// The second result is the STORE's own truncation signal: at least one per-type
// answer came back at ListUsersServerCap, so the grantee set is a prefix and
// there is no way to ask for the rest. Callers must surface it rather than claim
// a complete set (ExpandAccess → `truncated`).
//
// fail-closed: any transport / non-200 / decode error is returned to the caller
// (ExpandAccess maps it to INTERNAL and returns no principals).
func (c *OpenFGAHTTPClient) ListUsers(ctx context.Context, objectType, objectID, relation string, userTypes []string) ([]string, bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, false, ErrNotConfigured
	}
	out := make([]string, 0)
	truncated := false
	for _, ut := range userTypes {
		users, cut, err := c.listUsersOfType(ctx, objectType, objectID, relation, ut)
		if err != nil {
			return nil, false, err
		}
		truncated = truncated || cut
		out = append(out, users...)
	}
	return out, truncated, nil
}

// listUsersOfType issues a single ListUsers request for ONE concrete principal
// type (OpenFGA v1.8.x rejects multi-type user_filters), returning the
// FGA-prefixed concrete principals ("<type>:<id>") and whether the SERVER cut
// this answer at its ceiling.
//
// The cut is measured on the RAW `users[]` length, BEFORE usersets/wildcards are
// dropped: the ceiling is applied by the server to what it emitted, so filtering
// first would make a cut answer look short and complete.
func (c *OpenFGAHTTPClient) listUsersOfType(ctx context.Context, objectType, objectID, relation, userType string) ([]string, bool, error) {
	body, _ := json.Marshal(fgaWireListUsersRequest{
		AuthorizationModelID: c.AuthorizationModel,
		Object:               fgaWireListUsersObject{Type: objectType, ID: objectID},
		Relation:             relation,
		UserFilters:          []fgaWireUserTypeFilter{{Type: userType}},
	})
	cctx, cancel := context.WithTimeout(ctx, c.listTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/list-users", c.Endpoint, c.StoreID), body)
	if err != nil {
		return nil, false, fmt.Errorf("openfga listUsers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain (capped) for connection reuse; never surface the body to callers
		// (ExpandAccess maps any error to a fixed INTERNAL — no FGA-internal leak).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, false, fmt.Errorf("openfga listUsers: status %d", resp.StatusCode)
	}
	var r fgaWireListUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, false, fmt.Errorf("openfga listUsers decode: %w", err)
	}
	truncated := len(r.Users) >= ListUsersServerCap
	out := make([]string, 0, len(r.Users))
	for _, u := range r.Users {
		// Only concrete objects are principals; usersets/wildcards are not the
		// filtered-for concrete types and are skipped.
		if u.Object == nil || u.Object.Type == "" || u.Object.ID == "" {
			continue
		}
		out = append(out, u.Object.Type+":"+u.Object.ID)
	}
	return out, truncated, nil
}

// ListSubjects — OpenFGA does not expose a 1:1 ListSubjects in stable
// upstream; this client implements it via a filtered Read on the exact
// (object, relation) node. Returns ONLY the direct-tuple subjects — no group
// or cascade expansion.
//
// DEPRECATED for principal-resolution: a flat Read sees only literal tuples on
// the exact (object, relation) node — it does NOT traverse computed usersets /
// scope_grant indirection. ExpandAccess now uses ListUsers (graph-traversing).
// Retained for any caller that genuinely needs the direct-tuple subjects.
func (c *OpenFGAHTTPClient) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, "", ErrNotConfigured
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	body, _ := json.Marshal(fgaWireReadRequest{
		TupleKey: &fgaWireTupleKey{
			Relation: relation,
			Object:   fmt.Sprintf("%s:%s", objectType, objectID),
		},
		PageSize:          pageSize,
		ContinuationToken: pageToken,
	})
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
	out := make([]string, 0, len(r.Tuples))
	for _, t := range r.Tuples {
		out = append(out, t.Key.User)
	}
	return out, r.ContinuationToken, nil
}
