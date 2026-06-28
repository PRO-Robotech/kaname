// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// syncfga_harness_test.go — self-contained real-OpenFGA scaffolding for the
// syncfga read-after-write integration test (package access_binding_test). It cannot
// reuse the internal-package fga_test_helpers_test.go harness (different test package),
// so it replicates the same minimal flow: transform the canonical fga_model.fga DSL→
// JSON via the openfga/cli image, start an openfga/openfga server (testcontainers),
// create a store, write the model, and expose a production OpenFGAHTTPClient pointed at
// it. Skipped under -short (needs Docker).

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

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

const (
	syncFGAServerImage = "openfga/openfga:v1.8.4"
	syncFGACLIImage    = "openfga/cli:v0.7.13"
)

// poolQuerier is the minimal pgx surface used by the test's raw-SQL lookups.
type poolQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// syncFGAHarness bundles the OpenFGA server base URL + store/model ids and a
// production OpenFGAHTTPClient (relations) pointed at the same server — the exact
// client the reconciler's sync-FGA writer uses, and the client the test Checks against.
type syncFGAHarness struct {
	base      string
	store     string
	modelID   string
	relations *clients.OpenFGAHTTPClient
}

// startOpenFGAFromModel boots OpenFGA, loads the canonical flat model, and returns a
// ready harness with a production OpenFGAHTTPClient.
func startOpenFGAFromModel(t *testing.T) *syncFGAHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA integration test in -short mode")
	}
	ctx := context.Background()
	modelJSON := syncFGATransformModel(t, syncFGAModelPath(t))

	req := testcontainers.ContainerRequest{
		Image:        syncFGAServerImage,
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
	h := &syncFGAHarness{base: fmt.Sprintf("http://%s:%s", host, port.Port())}

	storeResp := h.post(t, "/stores", map[string]string{"name": "syncfga_raw"})
	h.store, _ = storeResp["id"].(string)
	require.NotEmpty(t, h.store, "create store failed: %v", storeResp)

	var modelBody map[string]any
	require.NoError(t, json.Unmarshal(modelJSON, &modelBody))
	mResp := h.post(t, fmt.Sprintf("/stores/%s/authorization-models", h.store), modelBody)
	h.modelID, _ = mResp["authorization_model_id"].(string)
	require.NotEmpty(t, h.modelID, "write model failed: %v", mResp)

	// The production client the reconciler writes through AND the test Checks against.
	// Endpoint is host:port (no scheme — the client prefixes http:// itself).
	h.relations = &clients.OpenFGAHTTPClient{
		Endpoint:           fmt.Sprintf("%s:%s", host, port.Port()),
		StoreID:            h.store,
		AuthorizationModel: h.modelID,
	}
	return h
}

func (h *syncFGAHarness) post(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(h.base+path, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// syncFGAModelPath resolves the canonical fga_model.fga in the sibling kacho-proto
// checkout (single source of truth). Walk up from the package dir to find it.
func syncFGAModelPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for i := 0; i < 12; i++ {
		cand := filepath.Join(dir, "kacho-proto", "proto", "kacho", "cloud", "iam", "v1", "fga_model.fga")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("canonical fga_model.fga not found (kacho-proto sibling absent) — skipping real-FGA proof")
	return ""
}

// syncFGATransformModel shells out to the openfga/cli image to transform the canonical
// DSL into the JSON the WriteAuthorizationModel API accepts (same transform the deploy
// bootstrap uses).
func syncFGATransformModel(t *testing.T, fgaPath string) []byte {
	t.Helper()
	dsl, err := os.ReadFile(fgaPath)
	require.NoError(t, err)
	dockerHost := os.Getenv("DOCKER_HOST")
	args := []string{"run", "--rm", "-i", syncFGACLIImage, "model", "transform",
		string(dsl), "--input-format", "fga", "--output-format", "json"}
	cmd := exec.Command("docker", args...) //nolint:gosec // fixed image, test-only
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
