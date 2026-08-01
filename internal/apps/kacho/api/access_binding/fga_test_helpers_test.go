// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// fga_test_helpers_test.go — shared real-OpenFGA test scaffolding (testcontainers)
// for the surviving FGA integration tests (expand_access / group_member /
// list_objects_role_owner). Extracted from the removed scope_grant_fga_integration_test
// (RBAC explicit-model 2026 P4 dropped the binding-time scope_grant emit path + its
// assertions, but the FGA-client harness + canonical-model loader are still shared).
// Loads the canonical fga_model.fga DSL→JSON via the openfga/cli image and evaluates
// Check against a real openfga/openfga server. Skipped under -short (needs Docker).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// listObjects calls OpenFGA ListObjects and returns the bare ids (objType prefix
// stripped), sorted. Used by the role-owner list-objects FGA integration test.
func (c *fgaClient) listObjects(t *testing.T, user, relation, objType string) []string {
	t.Helper()
	out := c.post(t, fmt.Sprintf("/stores/%s/list-objects", c.store), map[string]any{
		"authorization_model_id": c.modelID,
		"user":                   user,
		"relation":               relation,
		"type":                   objType,
	})
	raw, _ := out["objects"].([]any)
	ids := make([]string, 0, len(raw))
	prefix := objType + ":"
	for _, o := range raw {
		s, _ := o.(string)
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			ids = append(ids, s[len(prefix):])
		} else {
			ids = append(ids, s)
		}
	}
	sort.Strings(ids)
	return ids
}

const (
	// The server image is no longer named here — the server belongs to fgatest,
	// which pins it. Only the transform is still this package's own.
	openfgaCLIImage = "openfga/cli:v0.7.13"
	fgaModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"
)

// fgaRequireOrSkip converts a real-FGA-proof skip into a HARD failure when a CI
// enforcement env var is set (KACHO_IAM_REQUIRE_REAL_FGA or the drift-gate's
// KACHO_IAM_REQUIRE_FGA_MODEL), so the behavioral authz proof cannot silently
// vanish from a pipeline (a skipped test is neither red nor green). Mirrors the
// enforcement in internal/authzmap/fga_model_drift_test.go, which these harnesses
// previously lacked. Without either var set it degrades to a documented skip for
// Docker-less / offline local runs.
func fgaRequireOrSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv("KACHO_IAM_REQUIRE_REAL_FGA") != "" || os.Getenv("KACHO_IAM_REQUIRE_FGA_MODEL") != "" {
		t.Fatal(msg + " [KACHO_IAM_REQUIRE_REAL_FGA/KACHO_IAM_REQUIRE_FGA_MODEL set: refusing to skip a security gate]")
	}
	t.Skip(msg)
}

// fgaModelPath resolves the canonical fga_model.fga (single source of truth). It
// tries, in order: (1) a sibling kacho-proto checkout (walk-up from the package
// dir — the workspace-dev layout), then (2) the PINNED kacho-proto Go module dir
// (`go list -m`) — the standalone-CI layout where kacho-proto is a module, not a
// sibling. Neither resolvable → env-gated skip/fatal (see fgaRequireOrSkip).
func fgaModelPath(t *testing.T) string {
	t.Helper()
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 12; i++ {
			cand := filepath.Join(dir, fgaModelRelPath)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
			dir = filepath.Dir(dir)
		}
	}
	if out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}",
		"github.com/PRO-Robotech/kacho").Output(); err == nil {
		if modDir := strings.TrimSpace(string(out)); modDir != "" {
			cand := filepath.Join(modDir, fgaModelRelPath)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	fgaRequireOrSkip(t, "canonical fga_model.fga not found (no kacho-proto sibling and not in the pinned module) — real-FGA proof cannot run")
	return ""
}

// canonicalModel caches the transform for the process. It used to be paid per
// call, which meant an openfga/cli container per test on top of the server.
//
// The two error kinds are kept apart because their postures differ: an unreadable
// source of truth is a hard failure, a CLI that will not run is the env-gated
// skip fgaRequireOrSkip decides on.
var canonicalModel struct {
	once   sync.Once
	json   []byte
	stderr string // the CLI's own words, so the skip says why
	readEr error  // canonical DSL unreadable → HARD FAILURE
	cliErr error  // openfga/cli did not run   → fgaRequireOrSkip
}

// canonicalModelJSON returns the transformed canonical model, transforming it on
// first use.
//
// The verdicts live OUTSIDE the sync.Once deliberately: t.Skip / t.FailNow unwind
// the goroutine, and sync.Once marks itself done through a defer, so a verdict
// raised inside Do would leave the cache both "done" and empty — every later
// caller would get an empty model and fail somewhere unrelated.
func canonicalModelJSON(t *testing.T) []byte {
	t.Helper()
	fgaPath := fgaModelPath(t)
	canonicalModel.once.Do(func() {
		canonicalModel.json, canonicalModel.stderr, canonicalModel.readEr, canonicalModel.cliErr =
			transformModelToJSON(fgaPath)
	})
	require.NoError(t, canonicalModel.readEr)
	if canonicalModel.cliErr != nil {
		fgaRequireOrSkip(t, "openfga/cli transform unavailable (%v): %s — real-FGA proof cannot run",
			canonicalModel.cliErr, canonicalModel.stderr)
	}
	return canonicalModel.json
}

// transformModelToJSON shells out to the openfga/cli image to transform the
// canonical DSL into the JSON the OpenFGA WriteAuthorizationModel API accepts.
// This is the SAME transform the deploy bootstrap uses (make openfga-model-json).
//
// It returns errors instead of raising verdicts because it runs inside a
// sync.Once (see canonicalModelJSON); the two kinds come back separately so the
// caller can keep the postures apart.
func transformModelToJSON(fgaPath string) (modelJSON []byte, stderrText string, readEr, cliErr error) {
	dsl, err := os.ReadFile(fgaPath) // #nosec G304 -- test-only, path from fgaModelPath
	if err != nil {
		return nil, "", err, nil
	}
	dockerHost := os.Getenv("DOCKER_HOST")
	args := []string{"run", "--rm", "-i", openfgaCLIImage, "model", "transform",
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

// fgaClient is a tiny HTTP client for the OpenFGA server REST API.
type fgaClient struct {
	base    string
	store   string
	modelID string
}

func (c *fgaClient) post(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(c.base+path, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (c *fgaClient) check(t *testing.T, user, relation, object string) bool {
	t.Helper()
	out := c.post(t, fmt.Sprintf("/stores/%s/check", c.store), map[string]any{
		"authorization_model_id": c.modelID,
		"tuple_key":              map[string]string{"user": user, "relation": relation, "object": object},
	})
	allowed, _ := out["allowed"].(bool)
	return allowed
}

func (c *fgaClient) write(t *testing.T, tuples []abrepo.RelationTuple) {
	t.Helper()
	// Write one tuple per call so an already-existing tuple (e.g. the per-(anchor,
	// type) linking tuple shared by two grants on the same scope) is an idempotent
	// no-op — mirroring the production at-least-once drainer — without aborting the
	// rest of the batch (OpenFGA's batch write rejects the WHOLE request on a dup).
	for _, tp := range tuples {
		out := c.post(t, fmt.Sprintf("/stores/%s/write", c.store), map[string]any{
			"authorization_model_id": c.modelID,
			"writes": map[string]any{"tuple_keys": []map[string]string{
				{"user": tp.User, "relation": tp.Relation, "object": tp.Object},
			}},
		})
		if code, ok := out["code"].(string); ok {
			if strings.Contains(fmt.Sprint(out["message"]), "already exist") {
				continue
			}
			t.Fatalf("FGA write failed: code=%s msg=%v (tuple %+v)", code, out["message"], tp)
		}
	}
}

func (c *fgaClient) delete(t *testing.T, tuples []abrepo.RelationTuple) {
	t.Helper()
	keys := make([]map[string]string, 0, len(tuples))
	for _, tp := range tuples {
		keys = append(keys, map[string]string{"user": tp.User, "relation": tp.Relation, "object": tp.Object})
	}
	c.post(t, fmt.Sprintf("/stores/%s/write", c.store), map[string]any{
		"authorization_model_id": c.modelID,
		"deletes":                map[string]any{"tuple_keys": keys},
	})
}

// startOpenFGA hands the calling test its OWN store on the shared OpenFGA server,
// with the canonical model loaded, and returns a ready client.
//
// It used to boot its own openfga/openfga container per call — 25 callers in this
// package, 25 servers per run, which made this the last per-test container starter
// in the tree. The server now comes from services/iam/internal/testsupport/fgatest
// (one per test binary, lazily); the isolation a separate container gave is the
// store, which is what OpenFGA scopes tuples, models, Check, ListObjects and Read
// by. That harness proves both halves behaviourally in its own package
// (fgatest_test.go: TestOneServerManyStores).
//
// The model is still resolved and transformed HERE rather than through
// fgatest.New, so the skip posture below stays exactly as it was: this package
// refuses to skip its real-FGA proof when KACHO_IAM_REQUIRE_REAL_FGA /
// KACHO_IAM_REQUIRE_FGA_MODEL is set, and it keeps the pinned-module fallback for
// the standalone-CI layout. fgatest's own canonical loader has neither, and
// borrowing it would have dropped both without saying so. The transform is paid
// once per process (canonicalModelJSON) instead of once per test.
func startOpenFGA(t *testing.T) *fgaClient {
	t.Helper()
	if testing.Short() {
		fgaRequireOrSkip(t, "skipping real-OpenFGA integration test in -short mode")
	}
	h := fgatest.NewFromModelJSON(t, canonicalModelJSON(t))
	return &fgaClient{
		// fgatest exposes the endpoint scheme-less (the production client prepends
		// the scheme itself); this raw harness posts full URLs.
		base:    "http://" + h.Client.Endpoint,
		store:   h.Client.StoreID,
		modelID: h.Client.AuthorizationModel,
	}
}

// hierarchyTuples wires a standard test topology into FGA:
//
//	account:acc_A → project:prj_P → {compute_instance:inst_x, storage_image:img_v,
//	                                 vpc_subnet:sub_y, vpc_network:net_w}
//	account:acc_B → project:prj_B → compute_instance:inst_z
func hierarchyTuples() []abrepo.RelationTuple {
	return []abrepo.RelationTuple{
		{User: "account:acc_A", Relation: "account", Object: "project:prj_P"},
		{User: "project:prj_P", Relation: "project", Object: "compute_instance:inst_x"},
		{User: "project:prj_P", Relation: "project", Object: "storage_image:img_v"},
		{User: "project:prj_P", Relation: "project", Object: "vpc_subnet:sub_y"},
		{User: "project:prj_P", Relation: "project", Object: "vpc_network:net_w"},
		{User: "project:prj_P", Relation: "project", Object: "vpc_address:addr5k"},
		{User: "account:acc_B", Relation: "account", Object: "project:prj_B"},
		{User: "project:prj_B", Relation: "project", Object: "compute_instance:inst_z"},
	}
}
