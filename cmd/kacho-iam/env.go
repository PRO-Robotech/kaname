// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// env.go — env-driven helpers used by the composition root.
// Pure utilities: DSN masking + FGA per-operation timeout resolution +
// authz-provider selection + OpenFGA HTTP-client construction with strict
// required-config validation.
package main

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// authzProvider resolves the configured authorization-provider backend from
// the environment. KACHO_IAM_AUTHZ_PROVIDER selects which concrete adapter
// implements the abstract clients.RelationStore port; empty defaults to
// "openfga" (the only adapter shipped today). Swapping providers = add a new
// adapter file + a new case in buildRelationStore, then set this env var.
func authzProvider() string {
	return os.Getenv("KACHO_IAM_AUTHZ_PROVIDER")
}

// buildRelationStore constructs the authorization backend adapter selected by
// the provider string and returns it behind the provider-neutral
// clients.RelationStore port. The composition root depends on the abstract
// port; only this builder knows the concrete adapter.
//
// Provider selection (KACHO_IAM_AUTHZ_PROVIDER):
//   - "openfga" (and "" default) → OpenFGA HTTP adapter (buildOpenFGAClient).
//   - anything else              → fail-closed error (NO silent fallback): an
//     unknown provider must abort startup, not quietly pick a default.
//
// The OpenFGA adapter is returned as its concrete *clients.OpenFGAHTTPClient
// (it satisfies clients.RelationStore); callers that need the concrete client
// (per-operation field access, the fga_outbox applier) recover it via a type
// assertion at the single composition point in serve.go.
func buildRelationStore(provider string, logger *slog.Logger) (clients.RelationStore, error) {
	switch provider {
	case "", "openfga":
		return buildOpenFGAClient(logger), nil
	default:
		return nil, fmt.Errorf("unknown authz provider %q", provider)
	}
}

// maskDSN отдает DSN с замаскированным паролем — для безопасного логирования
// slave-URL. Возвращает оригинальную строку, если она не парсится как URL.
func maskDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, hasPwd := u.User.Password(); !hasPwd {
		return dsn
	}
	u.User = url.UserPassword(u.User.Username(), "***")
	return u.String()
}

// fgaTimeouts — resolved per-operation OpenFGA HTTP-client deadlines.
type fgaTimeouts struct {
	check time.Duration
	list  time.Duration
	write time.Duration
}

// fgaTimeoutsFromEnv resolves per-operation OpenFGA timeouts from environment
// variables. Kept in the composition root (main.go) so all env reads happen
// here, not at clients-package init() time.
//
//	KACHO_IAM_FGA_CHECK_TIMEOUT_MS         (default 200)
//	KACHO_IAM_FGA_LIST_OBJECTS_TIMEOUT_MS  (default 1000)
//	KACHO_IAM_FGA_WRITE_TIMEOUT_MS         (default 1000)
func fgaTimeoutsFromEnv() fgaTimeouts {
	return fgaTimeouts{
		check: envDurationMS("KACHO_IAM_FGA_CHECK_TIMEOUT_MS", clients.DefaultFGACheckTimeout),
		list:  envDurationMS("KACHO_IAM_FGA_LIST_OBJECTS_TIMEOUT_MS", clients.DefaultFGAListTimeout),
		write: envDurationMS("KACHO_IAM_FGA_WRITE_TIMEOUT_MS", clients.DefaultFGAWriteTimeout),
	}
}

// envDurationMS reads an integer-millisecond env var, returning def when unset
// or invalid (non-numeric / non-positive).
func envDurationMS(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

// buildOpenFGAClient constructs the shared OpenFGA HTTP client used by the
// AccessBinding/FGA-tuple writers, AuthorizeService and the fga_outbox drainer.
//
// The real HTTP client is ALWAYS used — there is no in-memory stub fallback
// (no mock-instead-of-real in production; the stub lives in
// clients/openfga_stub_test.go, test-only).
//
// store-id is provisioned at runtime by the openfga-bootstrap-job (it creates
// the store in OpenFGA, writes the id into a Secret, then re-rolls this
// Deployment). On the very first boot, before that job runs, store-id is empty;
// the client then **fails closed** — Check returns deny, Write/Read return
// ErrNotConfigured (Unavailable). This is NOT a degraded "mode": it is the real
// client honestly reporting that its backend is not provisioned yet, and it is
// required for the helm `--wait` install ordering (the pod must become Ready so
// the post-install bootstrap-job can run and then re-roll it). A loud WARN is
// logged so a genuine misconfiguration (no bootstrap-job) is visible.
//
//	KACHO_IAM_OPENFGA_STORE_ID   (runtime-provisioned; empty ⇒ fail-closed)
//	KACHO_IAM_OPENFGA_ENDPOINT   (default "kacho-umbrella-openfga:8080")
//	KACHO_IAM_OPENFGA_MODEL_ID   (optional; pinned authorization_model_id)
func buildOpenFGAClient(logger *slog.Logger) *clients.OpenFGAHTTPClient {
	storeID := os.Getenv("KACHO_IAM_OPENFGA_STORE_ID")
	endpoint := os.Getenv("KACHO_IAM_OPENFGA_ENDPOINT")
	if endpoint == "" {
		endpoint = "kacho-umbrella-openfga:8080"
	}
	modelID := os.Getenv("KACHO_IAM_OPENFGA_MODEL_ID")
	to := fgaTimeoutsFromEnv()
	c := &clients.OpenFGAHTTPClient{
		Endpoint:           endpoint,
		StoreID:            storeID,
		AuthorizationModel: modelID,
		CheckTimeout:       to.check,
		ListTimeout:        to.list,
		WriteTimeout:       to.write,
	}
	if storeID == "" {
		logger.Warn("openfga store-id not provisioned yet — authz fails CLOSED until the openfga-bootstrap-job writes KACHO_IAM_OPENFGA_STORE_ID and re-rolls this pod",
			"endpoint", endpoint)
	} else {
		logger.Info("openfga client wired",
			"endpoint", endpoint, "store_id", storeID, "model_id", modelID)
	}
	return c
}
