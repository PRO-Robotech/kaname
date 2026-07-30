// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/secretsweep"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// secretSweepStore adapts the Postgres redactor to the use-case port. The port's
// types are declared by the caller, so the conversion lives here rather than
// letting the adapter's shape leak upwards.
type secretSweepStore struct{ inner *kachopg.OpsResponseRedactor }

func (s secretSweepStore) SweepStrandedSecrets(ctx context.Context, spec secretsweep.Spec) (secretsweep.Result, error) {
	targets := make([]kachopg.SecretSweepTarget, 0, len(spec.Targets))
	for _, t := range spec.Targets {
		targets = append(targets, kachopg.SecretSweepTarget{ResponseType: t.ResponseType, Fields: t.Fields})
	}
	res, err := s.inner.SweepStrandedSecrets(ctx, kachopg.SecretSweepSpec{
		Targets: targets, Settled: spec.Settled, Window: spec.Window, Limit: spec.Limit,
	})
	return secretsweep.Result{Scanned: res.Scanned, Redacted: res.Redacted}, err
}

// secretSweepWindow — how far back a sweep looks. The backstop covers a process
// restart, which is minutes; the bound is what keeps the cost of a sweep
// independent of the size of the operations table.
const secretSweepWindow = 24 * time.Hour

// secretSweepMargin — added to the longest configured grace window before a
// response is considered settled. The client is still polling for its credential
// during the grace window, and a key handed over as "" cannot be reissued, so the
// backstop must never be the one that wins that race.
const secretSweepMargin = 2 * time.Minute

// secretSweepBatch — rows per response type per sweep.
const secretSweepBatch = 200

// startSecretBackstop wires the durable clean-up of one-shot credentials staged in
// finished operation responses.
//
// The in-process clean-up is a goroutine detached from the issuing request; it is
// registered in no shutdown group, and the default termination grace is shorter
// than the credential grace window — so an ordinary rollout ends it mid-window.
// The row it was going to clean is done=true, which puts it outside the orphan
// reconciler's claim (done = false) by construction, and nothing ages operations
// out. Without this loop the plaintext stayed for the life of the cluster, silently:
// every branch that logs "key material may remain" runs inside the goroutine that
// no longer exists.
func startSecretBackstop(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger *slog.Logger) error {
	// The response types are derived from the messages themselves, never written
	// out as strings: a renamed message would otherwise leave a sweeper that
	// matches nothing and reports a clean table for ever.
	saKey, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	if err != nil {
		return fmt.Errorf("secret backstop: sa-key response type: %w", err)
	}
	userToken, err := anypb.New(&iamv1.IssueUserTokenResponse{})
	if err != nil {
		return fmt.Errorf("secret backstop: user-token response type: %w", err)
	}

	settled := cfg.AuthN.SAKeyRedactGrace
	if cfg.AuthN.UserTokenRedactGrace > settled {
		settled = cfg.AuthN.UserTokenRedactGrace
	}
	settled += secretSweepMargin

	sw := secretsweep.New(
		secretSweepStore{inner: kachopg.NewOpsResponseRedactor(pool, "kacho_iam")},
		secretsweep.Spec{
			Targets: []secretsweep.Target{
				// Both spellings are named on the machine-key response: the current
				// one-shot key and the legacy secret kept for wire compatibility. A
				// field the message does not carry is skipped.
				{ResponseType: saKey.TypeUrl, Fields: []string{"private_key_pem", "client_secret"}},
				{ResponseType: userToken.TypeUrl, Fields: []string{"private_key_pem"}},
			},
			Settled: settled,
			Window:  secretSweepWindow,
			Limit:   secretSweepBatch,
		},
		0, // default interval
		logger.With(slog.String("component", "secret_backstop")),
	)
	go sw.Run(ctx)
	logger.Info("one-shot credential backstop started",
		"settled_after", settled.String(), "window", secretSweepWindow.String())
	return nil
}
