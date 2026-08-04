// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

// openfga_listusers_cap_test.go — the transport must report that the STORE cut
// its own answer.
//
// OpenFGA bounds list-users server-side (OPENFGA_LIST_USERS_MAX_RESULTS, default
// 1000) and returns a bare `users[]`: no continuation token, no "more" flag. The
// only observable trace of a cut is that the array arrived at the ceiling — so
// the detection belongs HERE, at the boundary that talks to the store. Anything
// further up compares against a number it chose itself and can never see it.
//
// The fake below reproduces the store exactly: a fixed number of concrete
// principals and nothing else, so the same test body holds before and after the
// fix.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// listUsersServer answers every list-users call with exactly n concrete users.
func listUsersServer(t *testing.T, n int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		users := make([]map[string]any, 0, n)
		for i := 0; i < n; i++ {
			users = append(users, map[string]any{
				"object": map[string]string{"type": "user", "id": fmt.Sprintf("usr%017d", i)},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestListUsers_AtServerCap_ReportsTruncated(t *testing.T) {
	c := &clients.OpenFGAHTTPClient{
		Endpoint: listUsersServer(t, clients.ListUsersServerCap), StoreID: "st_test",
	}

	users, truncated, err := c.ListUsers(context.Background(),
		"compute_instance", "inst_x", "viewer", []string{"user"})

	require.NoError(t, err)
	assert.Len(t, users, clients.ListUsersServerCap)
	assert.True(t, truncated,
		"an answer that arrived at the store's ceiling is a prefix; there is no token to fetch the rest, "+
			"so the only honest report is 'incomplete'")
}

func TestListUsers_BelowServerCap_ReportsComplete(t *testing.T) {
	c := &clients.OpenFGAHTTPClient{
		Endpoint: listUsersServer(t, clients.ListUsersServerCap-1), StoreID: "st_test",
	}

	_, truncated, err := c.ListUsers(context.Background(),
		"compute_instance", "inst_x", "viewer", []string{"user"})

	require.NoError(t, err)
	assert.False(t, truncated,
		"an answer below the ceiling was not cut — reporting it as incomplete would make the flag say nothing")
}

// One capped type is enough: the caller asked about the whole grantee set, and
// part of it is missing.
func TestListUsers_OneTypeCapped_WholeAnswerTruncated(t *testing.T) {
	c := &clients.OpenFGAHTTPClient{
		Endpoint: listUsersServer(t, clients.ListUsersServerCap), StoreID: "st_test",
	}

	_, truncated, err := c.ListUsers(context.Background(),
		"compute_instance", "inst_x", "viewer", []string{"user", "service_account"})

	require.NoError(t, err)
	assert.True(t, truncated)
}

// The premise of the constant, checked rather than assumed.
//
// ListUsersServerCap states a fact about the DEPLOYED store: it runs at
// OpenFGA's default ceiling. If a chart or values file ever sets
// OPENFGA_LIST_USERS_MAX_RESULTS, the constant silently stops describing reality
// and the truncation report goes back to being decorative — under-reporting if
// the deployment LOWERED the ceiling, which is the dangerous direction.
//
// So the constant carries its own expiry: the moment the deployment starts
// declaring a value, this fails and names the file to reconcile.
func TestListUsersServerCap_DeploymentDoesNotOverrideIt(t *testing.T) {
	deploy := filepath.Join(repoRootFromTest(t), "deploy")
	if _, err := os.Stat(deploy); err != nil {
		t.Fatalf("premise unverifiable: %s not readable (%v) — this gate must not pass by seeing nothing", deploy, err)
	}

	// The corpus is the git index, not the disk. `deploy/` carries git-ignored
	// content on any machine that has run the stand: the cluster secrets overlay
	// (**/values.*-ory.yaml) and the vendored subchart .tgz archives that
	// `helm dep update` unpacks there. Neither is the deployment this gate judges
	// — the deployment is what the commit declares — and reading them made the
	// verdict a property of the working directory, in both directions: red on a
	// file that will never be in the repository, and silent in a fresh checkout
	// where a locally-only declaration cannot be seen at all.
	files, err := treecorpus.Under(deploy)
	require.NoError(t, err, "the deploy corpus must come from the index; refusing beats walking the disk")

	var hits []string
	scanned := 0
	for _, path := range files {
		b, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		scanned++
		if strings.Contains(string(b), "OPENFGA_LIST_USERS_MAX_RESULTS") {
			hits = append(hits, path)
		}
	}
	require.Positive(t, scanned, "zero files read is not zero findings — the premise was never checked")
	t.Logf("scanned: %d tracked file(s) under %s", scanned, deploy)
	assert.Empty(t, hits,
		"the deployment now declares the store's list-users ceiling; clients.ListUsersServerCap "+
			"must be reconciled with it, otherwise a lowered ceiling is reported as a complete answer")
}

// repoRootFromTest walks up from the package directory to the module root.
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 12; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("module root (go.mod) not found above the package directory")
	return ""
}
