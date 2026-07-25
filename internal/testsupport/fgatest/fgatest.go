// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package fgatest — exported real-OpenFGA test harness for cross-package
// integration tests (mirrors internal/repo/kacho/pg.NewTestPostgres for Postgres).
//
// New(t) spins a real openfga/openfga server in a testcontainer, transforms the
// canonical fga_model.fga (single source of truth, in-repo at
// proto/kacho/cloud/iam/v1/) into the JSON the WriteAuthorizationModel API accepts via the
// openfga/cli image, loads it, and returns the PRODUCTION clients.OpenFGAHTTPClient
// pointed at the running server. Use-case integration tests therefore exercise the
// SAME Check / ListObjects code path that runs in production — no in-memory stub.
//
// The helper lives in a non-_test.go file so it can be imported from other
// packages' *_test.go (same trick as pg.NewTestPostgres). It pulls in testing /
// testcontainers; that is acceptable for a test-only package never linked into a
// production binary (nothing under cmd/ imports it).
//
// Skipped under `go test -short` and when Docker / the openfga CLI are
// unavailable (t.Skip), so a Docker-less CI lane stays green.
package fgatest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

const (
	openfgaServerImage = "openfga/openfga:v1.8.4"
	openfgaCLIImage    = "openfga/cli:v0.7.13"
)

// Harness bundles the production FGA client with raw tuple helpers a test needs
// to seed the authorization state before exercising a use-case.
type Harness struct {
	// Client — the production clients.OpenFGAHTTPClient (satisfies both
	// RelationStore and RelationQueries) pointed at the running container. Inject
	// it directly into a use-case via WithRelationStore.
	Client *clients.OpenFGAHTTPClient

	base     string // scheme + host:port for raw harness seeding (http.Post)
	hostPort string // scheme-less host:port for the production client Endpoint
	store    string
	modelID  string
}

// New spins up a real OpenFGA server, creates a store, loads the canonical
// fga_model.fga and returns a ready Harness. Skips under -short / no Docker.
func New(t *testing.T) *Harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA integration test in -short mode")
	}
	return newFromModelJSON(t, transformModelToJSON(t, fgaModelPath(t)))
}

// NewFromModelJSON spins a real OpenFGA server and loads the given
// authorization-model JSON (an OpenFGA WriteAuthorizationModel body) instead of
// transforming the canonical fga_model.fga. Use it to exercise the DEPLOYED model
// (the openfga-bootstrap ConfigMap `model.json` block) with real Check/Write —
// i.e. to prove the artifact the bootstrap Job actually applies behaves as the
// canonical DSL says it should. Skipped under -short.
func NewFromModelJSON(t *testing.T, modelJSON []byte) *Harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA integration test in -short mode")
	}
	return newFromModelJSON(t, modelJSON)
}

func newFromModelJSON(t *testing.T, modelJSON []byte) *Harness {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        openfgaServerImage,
		Cmd:          []string{"run"},
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "8080")
	require.NoError(t, err)

	// hostPort — the scheme-less "host:port" the production OpenFGAHTTPClient
	// expects in Endpoint (it prepends "http://" itself in Check/Write/Read). base
	// carries the scheme for the harness's own raw http.Post seeding calls.
	hostPort := fmt.Sprintf("%s:%s", host, port.Port())
	h := &Harness{base: "http://" + hostPort, hostPort: hostPort}

	storeResp := h.post(t, "/stores", map[string]string{"name": "rbacreadtest"})
	h.store, _ = storeResp["id"].(string)
	require.NotEmpty(t, h.store, "create store failed: %v", storeResp)

	var modelBody map[string]any
	require.NoError(t, json.Unmarshal(modelJSON, &modelBody))
	mResp := h.post(t, fmt.Sprintf("/stores/%s/authorization-models", h.store), modelBody)
	h.modelID, _ = mResp["authorization_model_id"].(string)
	require.NotEmpty(t, h.modelID, "write model failed: %v", mResp)

	h.Client = &clients.OpenFGAHTTPClient{
		// Endpoint is scheme-less host:port — the production client prepends
		// "http://" in Check/Write/Read (matches cmd/kacho-iam/env.go wiring).
		Endpoint:           h.hostPort,
		StoreID:            h.store,
		AuthorizationModel: h.modelID,
	}
	return h
}

// Write inserts a tuple (user, relation, object) into the store. Idempotent:
// an already-existing tuple is a no-op (mirrors the production at-least-once
// drainer). Use it to seed the per-object grant the use-case will Check.
func (h *Harness) Write(t *testing.T, user, relation, object string) {
	t.Helper()
	out := h.post(t, fmt.Sprintf("/stores/%s/write", h.store), map[string]any{
		"authorization_model_id": h.modelID,
		"writes": map[string]any{"tuple_keys": []map[string]string{
			{"user": user, "relation": relation, "object": object},
		}},
	})
	if code, ok := out["code"].(string); ok {
		if bytes.Contains([]byte(fmt.Sprint(out["message"])), []byte("already exist")) {
			return
		}
		t.Fatalf("FGA write failed: code=%s msg=%v (%s %s %s)", code, out["message"], user, relation, object)
	}
}

func (h *Harness) post(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(h.base+path, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// fgaModelRelPath — the canonical authorization model, relative to the monorepo
// root. Single source of truth (see services/iam/internal/authzmap/
// fga_model_drift_test.go); the openfga-bootstrap ConfigMap is generated from it.
const fgaModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"

// fgaModelPath resolves the canonical fga_model.fga. Its absence is a HARD
// FAILURE, not a skip: this harness exists to prove authorization behaviour
// against the real model, and a proof that quietly does not run is worth nothing.
// (Docker-less and -short lanes have their own explicit skips; those are about
// the environment, this is about the source of truth being present.)
func fgaModelPath(t *testing.T) string {
	t.Helper()
	if p, ok := resolveFGAModel(); ok {
		return p
	}
	t.Fatalf("canonical authorization model %s not found walking up from the test's "+
		"working directory — the real-FGA proof has no model to load. Restore the file; "+
		"never let this degrade to a skip.", fgaModelRelPath)
	return ""
}

// resolveFGAModel walks up from the working directory to the monorepo root and
// returns the canonical model path.
func resolveFGAModel() (string, bool) {
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	dir := wd
	for {
		cand := filepath.Join(dir, fgaModelRelPath)
		if _, statErr := os.Stat(cand); statErr == nil {
			return cand, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// transformModelToJSON shells out to the openfga/cli image to transform the
// canonical DSL into the JSON the WriteAuthorizationModel API accepts. Same
// transform the deploy bootstrap uses.
func transformModelToJSON(t *testing.T, fgaPath string) []byte {
	t.Helper()
	// fgaPath is resolved by fgaModelPath: a fixed relative walk to the canonical
	// in-repo fga_model.fga, never attacker-controlled. Test-only helper.
	dsl, err := os.ReadFile(fgaPath) // #nosec G304 -- test-only, fixed canonical path (fgaModelPath)
	require.NoError(t, err)
	dockerHost := os.Getenv("DOCKER_HOST")
	args := []string{"run", "--rm", "-i", openfgaCLIImage, "model", "transform",
		string(dsl), "--input-format", "fga", "--output-format", "json"}
	// Fixed "docker" binary + pinned openfgaCLIImage; the only variable arg is the
	// canonical DSL content. Test-only harness, never linked into a prod binary.
	cmd := exec.Command("docker", args...) // #nosec G204 -- test-only, fixed image + binary
	if dockerHost != "" {
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+dockerHost)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("openfga/cli transform unavailable (%v): %s — skipping real-FGA proof", err, stderr.String())
	}
	return stdout.Bytes()
}
