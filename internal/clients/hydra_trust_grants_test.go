// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHydraAdminClient_CreateJWTBearerTrustGrant_ExactSubject — the grant is
// posted to /admin/trust/grants/jwt-bearer/issuers with the EXACT subject and
// allow_any_subject=false (a wildcard federation would let any pod of the cluster
// obtain a token).
func TestHydraAdminClient_CreateJWTBearerTrustGrant_ExactSubject(t *testing.T) {
	var body map[string]any
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"grant-1"}`))
	}))
	defer srv.Close()

	c := NewHydraAdminClient(srv.URL, "")
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	err := c.CreateJWTBearerTrustGrant(context.Background(), JWTBearerTrustGrant{
		Issuer:    "https://kube.cluster.local",
		Subject:   "system:serviceaccount:ci:deployer",
		Scope:     []string{"reg"},
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("CreateJWTBearerTrustGrant: %v", err)
	}
	if gotPath != "/admin/trust/grants/jwt-bearer/issuers" {
		t.Errorf("path = %q", gotPath)
	}
	if body["issuer"] != "https://kube.cluster.local" {
		t.Errorf("issuer = %v", body["issuer"])
	}
	if body["subject"] != "system:serviceaccount:ci:deployer" {
		t.Errorf("subject = %v", body["subject"])
	}
	if allow, _ := body["allow_any_subject"].(bool); allow {
		t.Errorf("allow_any_subject must be false, got true")
	}
}

// TestHydraAdminClient_CreateJWTBearerTrustGrant_Error — a Hydra 4xx surfaces as
// an error (the federated Issue rolls back on it).
func TestHydraAdminClient_CreateJWTBearerTrustGrant_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"conflict"}`))
	}))
	defer srv.Close()

	err := NewHydraAdminClient(srv.URL, "").CreateJWTBearerTrustGrant(context.Background(), JWTBearerTrustGrant{
		Issuer:  "https://kube.cluster.local",
		Subject: "system:serviceaccount:ci:deployer",
	})
	if err == nil {
		t.Fatal("expected error on Hydra 4xx")
	}
}
