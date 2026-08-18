// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_store_id_soft_pass_test.go — the soft pass on an unprovisioned OpenFGA
// store id, pinned as a DECISION rather than left as an accident of the code.
//
// Six comments across cmd/kacho-iam, internal/clients and internal/service used to
// state that the composition root "fails fast" when KACHO_IAM_OPENFGA_STORE_ID is
// empty. It never did: it logs a WARN and carries on, and the client then fails
// CLOSED. `security.md` п.5 names that shape — a security comment contradicting its
// code — a trap, because the next reader repairs the CODE to match the comment. The
// comments are now true (#654); this file is what stops the repair from happening
// anyway, and it names WHY the soft pass is load-bearing so the reason is not left
// in a reviewer's memory.
//
// Why it is load-bearing, in one line an operator can verify: the store id is
// written by the openfga-bootstrap Job, a helm `post-install,post-upgrade` hook
// (deploy/helm/umbrella/charts/openfga-bootstrap/templates/openfga-bootstrap-job.yaml),
// and helm runs a post-install hook only after `helm upgrade --wait` sees the
// release Ready (deploy/Makefile). An iam that refused to start without the id
// would never become Ready ⇒ the hook would never run ⇒ the id would never be
// written. The first install would deadlock on itself.
//
// Both directions are asserted, because a test that only ever sees one of them says
// nothing about the discrimination:
//
//   - unprovisioned  → a client IS returned, it DENIES, and the WARN NAMES the knob;
//   - provisioned    → the same builder carries the id and logs no warning.

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// captureLogger returns a logger writing into buf at WARN-and-above severity, so a
// silent build is told apart from a warning one by the buffer's contents.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// TestBuildOpenFGAClient_UnprovisionedStoreID_FailsClosedWithoutRefusingToStart —
// the first-boot state. The builder must hand back a working client, that client
// must DENY rather than allow, and the operator must be told which knob is missing.
func TestBuildOpenFGAClient_UnprovisionedStoreID_FailsClosedWithoutRefusingToStart(t *testing.T) {
	t.Setenv("KACHO_IAM_OPENFGA_STORE_ID", "")
	t.Setenv("KACHO_IAM_OPENFGA_ENDPOINT", "127.0.0.1:1")

	logger, logBuf := captureLogger()
	c := buildOpenFGAClient(logger)

	require.NotNil(t, c,
		"the composition root must NOT refuse to start on an unprovisioned store id: the id is "+
			"written by a helm post-install hook that runs only after the release is Ready, so a "+
			"refusal here deadlocks the first install")
	require.Empty(t, c.StoreID, "the builder must not invent a store id")

	// FAIL-CLOSED, and asserted on the OBSERVABLE answer rather than on the code:
	// a client that returned allowed=true here would be an authz bypass on every
	// stand between the first boot and the re-roll. No network is reached — the
	// unconfigured branch answers before the request is built.
	allowed, err := c.Check(context.Background(), "user:u", "viewer", "iam_user:x")
	require.False(t, allowed, "unprovisioned store id must DENY, never allow")
	require.ErrorIs(t, err, clients.ErrNotConfigured,
		"the refusal must be the declared sentinel, so callers map it to UNAVAILABLE rather "+
			"than swallowing it as a plain denial")

	// The warning is part of the control: a soft pass nobody can see is
	// indistinguishable from a working store (security.md §Hardening п.8).
	warn := logBuf.String()
	require.Contains(t, warn, "KACHO_IAM_OPENFGA_STORE_ID",
		"the WARN must NAME the knob — an operator who cannot tell which value is missing "+
			"cannot act on it")
	require.Contains(t, strings.ToLower(warn), "fails closed")
}

// TestBuildOpenFGAClient_ProvisionedStoreID_NoWarning — the positive control. Without
// it the assertions above would pass on a builder that warned unconditionally, or on
// one that never wired the id at all.
func TestBuildOpenFGAClient_ProvisionedStoreID_NoWarning(t *testing.T) {
	t.Setenv("KACHO_IAM_OPENFGA_STORE_ID", "01JSTORE0000000000000000")
	t.Setenv("KACHO_IAM_OPENFGA_ENDPOINT", "127.0.0.1:1")

	logger, logBuf := captureLogger()
	c := buildOpenFGAClient(logger)

	require.NotNil(t, c)
	require.Equal(t, "01JSTORE0000000000000000", c.StoreID,
		"the provisioned id must reach the client, or the fail-closed branch would be permanent")
	require.Empty(t, logBuf.String(),
		"a provisioned store id must not warn: a warning printed on every boot stops being read, "+
			"and then the unprovisioned one goes unnoticed too")

	// And it is no longer in the unconfigured branch: the answer is now a transport
	// error against an address nothing listens on, NOT the sentinel.
	_, err := c.Check(context.Background(), "user:u", "viewer", "iam_user:x")
	require.Error(t, err)
	require.False(t, errors.Is(err, clients.ErrNotConfigured),
		"with the id provisioned the unconfigured branch must not be taken")
}
