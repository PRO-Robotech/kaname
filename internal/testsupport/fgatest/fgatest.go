// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package fgatest gives a test binary ONE OpenFGA server and hands each test its
// own store.
//
// # The subject
//
// New(t) used to boot a real openfga/openfga container AND shell out to the
// openfga/cli image to transform the canonical DSL — per call. The cost is not
// what the tests prove, it is the harness: authzmap paid nine container starts
// before a single assertion ran, services/iam/internal/service nine more, and
// services/iam/internal/apps/kacho/api/access_binding twenty-five. `go test`
// applies its own 600s ceiling per package, and a package that crosses it is not
// finished slowly by `go test ./...` — it is not finished at ALL, however idle
// the machine.
//
// This is the same fix already landed for Postgres in internal/pgtest, applied to
// the other container this tree starts. Read that package's doc comment first;
// the reasoning below only says where OpenFGA differs.
//
// # Why a store is the isolation a container gave
//
// OpenFGA is natively multi-store, and a store is a first-class isolation
// boundary: its own tuples, its own authorization models, and every API that
// matters here — Write, Check, ListObjects, Read, Expand — is store-scoped by
// path. So the analogue of pgtest's "one server, a database per test" is one
// server, a STORE per test. Nothing crosses between two tests that did not cross
// between two containers, and the production clients.OpenFGAHTTPClient each test
// receives is pinned to its own StoreID, so a test cannot reach another's tuples
// even by accident.
//
// What DID change is worth stating rather than leaving to be discovered: a test
// that depended on being alone with the SERVER — on a restart, on server-wide
// metrics, on enumerating stores — does not have that any more, and such a test
// must keep its own container and say why. Nothing in this tree does; the tests
// here only ever ask questions about their own objects.
//
// # Why the server starts lazily
//
// Starting it from a TestMain would pay for a container in every run where every
// test skips — which is exactly what -short does to these tests. Starting it on
// first use means a package needs no reasoning about -short at all: no caller, no
// container, no cost. It also means a package needs no TestMain to USE this
// harness, which is why authzmap, readauthz and access_binding keep working with
// no file added.
//
// # The model transform is paid once too
//
// New() transforms the canonical fga_model.fga into the JSON the
// WriteAuthorizationModel API accepts by running the pinned openfga/cli image.
// That is a second container start per call, and it is cached for the process
// alongside the server. Writing the model INTO a store is a plain HTTP call and
// stays per-store, because models are store-scoped.
//
// # Skip posture is unchanged, deliberately
//
//   - -short skips (New / NewFromModelJSON, first statement);
//   - the openfga/cli transform failing to run skips — it is a statement about
//     the environment;
//   - the canonical fga_model.fga being missing FAILS — it is a statement about
//     the source of truth;
//   - the server failing to start FAILS — it always did (require.NoError on the
//     container), and inverting it would report "the real-FGA proofs did not run"
//     as green.
//
// The helper lives in a non-_test.go file so it can be imported from other
// packages' *_test.go (same trick as pgtest). It pulls in testing /
// testcontainers; that is acceptable for a test-only package never linked into a
// production binary (nothing under cmd/ imports it).
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
	"sync"
	"sync/atomic"
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
	// RelationStore and RelationQueries) pointed at the shared server AND at this
	// test's own store. Inject it directly into a use-case via WithRelationStore.
	Client *clients.OpenFGAHTTPClient

	base     string // scheme + host:port for raw harness seeding (http.Post)
	hostPort string // scheme-less host:port for the production client Endpoint
	store    string
	modelID  string
}

// New creates a store on the shared OpenFGA server, loads the canonical
// fga_model.fga into it and returns a ready Harness. Skips under -short / when
// the openfga/cli transform cannot run.
func New(t *testing.T) *Harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA integration test in -short mode")
	}
	return newFromModelJSON(t, canonicalModelJSON(t))
}

// NewFromModelJSON creates a store on the shared OpenFGA server and loads the
// given authorization-model JSON (an OpenFGA WriteAuthorizationModel body)
// instead of transforming the canonical fga_model.fga. Use it to exercise the
// DEPLOYED model (the openfga-bootstrap ConfigMap `model.json` block) with real
// Check/Write — i.e. to prove the artifact the bootstrap Job actually applies
// behaves as the canonical DSL says it should. Skipped under -short.
func NewFromModelJSON(t *testing.T, modelJSON []byte) *Harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping real-OpenFGA integration test in -short mode")
	}
	return newFromModelJSON(t, modelJSON)
}

func newFromModelJSON(t *testing.T, modelJSON []byte) *Harness {
	t.Helper()
	base, hostPort := sharedServer(t)
	h := &Harness{base: base, hostPort: hostPort}

	// The store name is per-test only so a human watching the server can tell the
	// stores apart; nothing keys on it. Identity is the id the server assigns.
	name := fmt.Sprintf("fgatest-%04d", storeSeq.Add(1))
	storeResp := h.post(t, "/stores", map[string]string{"name": name})
	h.store, _ = storeResp["id"].(string)
	require.NotEmpty(t, h.store, "create store failed: %v", storeResp)
	t.Cleanup(h.deleteStore)

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

// Write inserts a tuple (user, relation, object) into THIS harness's store.
// Idempotent: an already-existing tuple is a no-op (mirrors the production
// at-least-once drainer). Use it to seed the per-object grant the use-case will
// Check.
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

// deleteStore removes this test's store from the shared server when the test
// ends — the counterpart of pgtest dropping its database. A failure is ignored on
// purpose: store ids are server-assigned and never reused, so an abandoned store
// is invisible to every other test; failing the cleanup would turn a tidiness
// problem into a red test.
func (h *Harness) deleteStore() {
	req, err := http.NewRequest(http.MethodDelete, h.base+"/stores/"+h.store, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// ── the one server, and the one model transform ───────────────────────────────

// server is the OpenFGA this test BINARY owns. One per process, because a test
// binary is one package.
var server struct {
	once      sync.Once
	base      string // scheme + host:port
	hostPort  string // scheme-less host:port
	err       error
	terminate func()
}

// storeSeq numbers the stores this process hands out. Only used for the store's
// display name; the identity a test is given is the server-assigned id.
var storeSeq atomic.Int64

// sharedServer boots the container on first use and returns its address. Once,
// whatever the number of callers and whatever their goroutines.
func sharedServer(t *testing.T) (base, hostPort string) {
	t.Helper()
	server.once.Do(func() {
		ctx := context.Background()
		req := testcontainers.ContainerRequest{
			Image:        openfgaServerImage,
			Cmd:          []string{"run"},
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
		}
		ctr, cerr := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req, Started: true,
		})
		if cerr != nil {
			server.err = fmt.Errorf("start openfga: %w", cerr)
			return
		}
		server.terminate = func() { _ = ctr.Terminate(context.Background()) }

		host, herr := ctr.Host(ctx)
		if herr != nil {
			server.err = fmt.Errorf("container host: %w", herr)
			return
		}
		port, perr := ctr.MappedPort(ctx, "8080")
		if perr != nil {
			server.err = fmt.Errorf("container port: %w", perr)
			return
		}
		server.hostPort = fmt.Sprintf("%s:%s", host, port.Port())
		server.base = "http://" + server.hostPort
	})
	// A server that will not start FAILS, it never skips — the posture the per-test
	// require.NoError had. Reported to EVERY caller, not just the one that lost the
	// race to run the Once, or the rest would proceed against an empty address.
	require.NoError(t, server.err, "fgatest: real OpenFGA unavailable")
	return server.base, server.hostPort
}

// Run terminates the shared server after a package's tests finish:
//
//	func TestMain(m *testing.M) { os.Exit(fgatest.Run(m.Run)) }
//
// and, where the package already hands its Postgres to pgtest:
//
//	func TestMain(m *testing.M) {
//		os.Exit(fgatest.Run(func() int { return pgtest.Run(m, pgtest.Config{…}) }))
//	}
//
// It is NOT required, and that is deliberate: this harness starts lazily and
// needs no per-package configuration, so demanding a TestMain would be ceremony
// for its own sake in packages that have none. Without Run the container is
// reaped by the testcontainers reaper when the test process exits — real cleanup,
// just not immediate, and absent only when the reaper is explicitly disabled
// (TESTCONTAINERS_RYUK_DISABLED). Wire it wherever a TestMain already exists.
func Run(inner func() int) int {
	code := inner()
	if server.terminate != nil {
		server.terminate()
	}
	return code
}

// canonicalModel is the transform of fga_model.fga, paid once per process. The
// two error kinds are kept apart because they have different postures: an
// unreadable source of truth is a failure, a missing CLI is a skip.
var canonicalModel struct {
	once   sync.Once
	json   []byte
	readEr error  // canonical DSL unreadable → HARD FAILURE
	cliErr error  // openfga/cli did not run   → SKIP (environment)
	stderr string // the CLI's own words, so the skip says why
}

// canonicalModelJSON returns the transformed canonical model, transforming it on
// first use.
//
// The verdicts live OUTSIDE the sync.Once on purpose: t.Skip / t.FailNow unwind
// the goroutine, and sync.Once marks itself done through a defer, so a verdict
// raised inside Do would leave the cache both "done" and empty — every later
// caller would then get an empty model and fail somewhere unrelated.
func canonicalModelJSON(t *testing.T) []byte {
	t.Helper()
	path := fgaModelPath(t)
	canonicalModel.once.Do(func() {
		canonicalModel.json, canonicalModel.stderr, canonicalModel.readEr, canonicalModel.cliErr =
			transformModelToJSON(path)
	})
	require.NoError(t, canonicalModel.readEr)
	if canonicalModel.cliErr != nil {
		t.Skipf("openfga/cli transform unavailable (%v): %s — skipping real-FGA proof",
			canonicalModel.cliErr, canonicalModel.stderr)
	}
	return canonicalModel.json
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
//
// It returns errors rather than raising verdicts because it runs inside a
// sync.Once (see canonicalModelJSON); the two kinds are returned separately so
// the caller can keep the postures apart.
func transformModelToJSON(fgaPath string) (modelJSON []byte, stderrText string, readEr, cliErr error) {
	// fgaPath is resolved by fgaModelPath: a fixed relative walk to the canonical
	// in-repo fga_model.fga, never attacker-controlled. Test-only helper.
	dsl, err := os.ReadFile(fgaPath) // #nosec G304 -- test-only, fixed canonical path (fgaModelPath)
	if err != nil {
		return nil, "", err, nil
	}
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
		return nil, stderr.String(), nil, err
	}
	return stdout.Bytes(), stderr.String(), nil, nil
}
