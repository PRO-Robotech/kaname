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
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// The server image is no longer named here — the server belongs to fgatest, which
// pins it. Only the transform is still this package's own.
const syncFGACLIImage = "openfga/cli:v0.7.13"

// syncFGARequireOrSkip converts a real-FGA-proof skip into a HARD failure when a
// CI enforcement env var is set (KACHO_IAM_REQUIRE_REAL_FGA or the drift-gate's
// KACHO_IAM_REQUIRE_FGA_MODEL), so the behavioral authz proof cannot silently
// vanish from a pipeline (a skipped test is neither red nor green). Mirrors the
// enforcement in internal/authzmap/fga_model_drift_test.go, which the earlier
// harnesses lacked. Without either var set it degrades to a documented skip for
// Docker-less / offline local runs.
func syncFGARequireOrSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv("KACHO_IAM_REQUIRE_REAL_FGA") != "" || os.Getenv("KACHO_IAM_REQUIRE_FGA_MODEL") != "" {
		t.Fatal(msg + " [KACHO_IAM_REQUIRE_REAL_FGA/KACHO_IAM_REQUIRE_FGA_MODEL set: refusing to skip a security gate]")
	}
	t.Skip(msg)
}

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

// startOpenFGAFromModel hands the calling test its OWN store on the shared OpenFGA
// server, with the canonical flat model loaded, and returns a ready harness whose
// relations field is the production OpenFGAHTTPClient pinned to that store.
//
// It used to boot its own openfga/openfga container per call. The server now comes
// from services/iam/internal/testsupport/fgatest (one per test binary, lazily), and
// the isolation a separate container gave is the store — OpenFGA scopes tuples,
// models, Check, ListObjects and Read by store, and fgatest proves both halves
// behaviourally in its own package (fgatest_test.go: TestOneServerManyStores).
//
// The model is still resolved and transformed HERE rather than through fgatest.New,
// so the skip posture stays exactly as it was: this package refuses to skip its
// real-FGA proof when KACHO_IAM_REQUIRE_REAL_FGA / KACHO_IAM_REQUIRE_FGA_MODEL is
// set, and it keeps the pinned-module fallback for the standalone-CI layout.
// fgatest's own canonical loader has neither. The transform is paid once per
// process (syncFGACanonicalModelJSON) instead of once per test.
func startOpenFGAFromModel(t *testing.T) *syncFGAHarness {
	t.Helper()
	if testing.Short() {
		syncFGARequireOrSkip(t, "skipping real-OpenFGA integration test in -short mode")
	}
	h := fgatest.NewFromModelJSON(t, syncFGACanonicalModelJSON(t))
	return &syncFGAHarness{
		// fgatest exposes the endpoint scheme-less (the production client prepends
		// the scheme itself); this harness's raw post() builds full URLs.
		base:    "http://" + h.Client.Endpoint,
		store:   h.Client.StoreID,
		modelID: h.Client.AuthorizationModel,
		// The production client the reconciler writes through AND the test Checks
		// against — the same one, already pinned to this test's store and model.
		relations: h.Client,
	}
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

// syncFGAModelRelPath — location of the canonical model inside the kacho-proto
// tree (both the sibling checkout and the Go-module directory share this layout).
const syncFGAModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"

// syncFGAModelPath resolves the canonical fga_model.fga (single source of truth).
// It tries, in order: (1) a sibling kacho-proto checkout (walk-up from the package
// dir — the workspace-dev layout), then (2) the PINNED kacho-proto Go module dir
// (`go list -m`) — the standalone-CI layout where kacho-proto is a module, not a
// sibling. Neither resolvable → env-gated skip/fatal (see syncFGARequireOrSkip).
func syncFGAModelPath(t *testing.T) string {
	t.Helper()
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 12; i++ {
			cand := filepath.Join(dir, syncFGAModelRelPath)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
			dir = filepath.Dir(dir)
		}
	}
	if out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}",
		"github.com/PRO-Robotech/kacho").Output(); err == nil {
		if modDir := strings.TrimSpace(string(out)); modDir != "" {
			cand := filepath.Join(modDir, syncFGAModelRelPath)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	syncFGARequireOrSkip(t, "canonical fga_model.fga not found (no kacho-proto sibling and not in the pinned module) — real-FGA proof cannot run")
	return ""
}

// syncFGACanonicalModel caches the transform for the process. It used to be paid
// per call, which meant an openfga/cli container per test on top of the server.
//
// The two error kinds are kept apart because their postures differ: an unreadable
// source of truth is a hard failure, a CLI that will not run is the env-gated skip
// syncFGARequireOrSkip decides on.
var syncFGACanonicalModel struct {
	once   sync.Once
	json   []byte
	stderr string // the CLI's own words, so the skip says why
	readEr error  // canonical DSL unreadable → HARD FAILURE
	cliErr error  // openfga/cli did not run   → syncFGARequireOrSkip
}

// syncFGACanonicalModelJSON returns the transformed canonical model, transforming
// it on first use.
//
// The verdicts live OUTSIDE the sync.Once deliberately: t.Skip / t.FailNow unwind
// the goroutine, and sync.Once marks itself done through a defer, so a verdict
// raised inside Do would leave the cache both "done" and empty — every later caller
// would get an empty model and fail somewhere unrelated.
func syncFGACanonicalModelJSON(t *testing.T) []byte {
	t.Helper()
	fgaPath := syncFGAModelPath(t)
	syncFGACanonicalModel.once.Do(func() {
		syncFGACanonicalModel.json, syncFGACanonicalModel.stderr,
			syncFGACanonicalModel.readEr, syncFGACanonicalModel.cliErr = syncFGATransformModel(fgaPath)
	})
	require.NoError(t, syncFGACanonicalModel.readEr)
	if syncFGACanonicalModel.cliErr != nil {
		syncFGARequireOrSkip(t, "openfga/cli transform unavailable (%v): %s — real-FGA proof cannot run",
			syncFGACanonicalModel.cliErr, syncFGACanonicalModel.stderr)
	}
	return syncFGACanonicalModel.json
}

// syncFGATransformModel shells out to the openfga/cli image to transform the canonical
// DSL into the JSON the WriteAuthorizationModel API accepts (same transform the deploy
// bootstrap uses).
//
// It returns errors instead of raising verdicts because it runs inside a sync.Once
// (see syncFGACanonicalModelJSON); the two kinds come back separately so the caller
// can keep the postures apart.
func syncFGATransformModel(fgaPath string) (modelJSON []byte, stderrText string, readEr, cliErr error) {
	dsl, err := os.ReadFile(fgaPath) // #nosec G304 -- test-only, path from syncFGAModelPath
	if err != nil {
		return nil, "", err, nil
	}
	dockerHost := os.Getenv("DOCKER_HOST")
	args := []string{"run", "--rm", "-i", syncFGACLIImage, "model", "transform",
		string(dsl), "--input-format", "fga", "--output-format", "json"}
	cmd := exec.Command("docker", args...) // #nosec G204 -- test-only, fixed binary + pinned image
	if dockerHost != "" {
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+dockerHost)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, stderr.String(), nil, err
	}
	return stdout.Bytes(), stderr.String(), nil, nil
}
