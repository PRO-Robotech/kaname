// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package bootstraptokenwire — composition-root wiring for the
// InternalBootstrapTokenService handler (#58). Assembles the bootstrap-token
// mint use-case (BootstrapStore pg adapter + Hydra Admin client + a Hydra
// token-exchange adapter over the existing HydraTokenClient) and its thin gRPC
// handler. Single wire-up call for cmd/kacho-iam.
package bootstraptokenwire

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	bootstraptoken "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/bootstrap_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// BuildConfig — composition inputs for the bootstrap-token mint handler.
type BuildConfig struct {
	// SigningKeyPEM — the bootstrap SA ES256 (P-256, PKCS#8) private key PEM,
	// supplied from a k8s Secret (KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM). Empty →
	// mint disabled (fail-closed).
	SigningKeyPEM string
	// HydraAdminURL / HydraAdminToken — Hydra Admin API for CreateOAuthClient.
	HydraAdminURL   string
	HydraAdminToken string
	// HydraTokenURL — the Hydra public token endpoint for the client_credentials
	// exchange.
	HydraTokenURL string
	// AssertionAudience — the `aud` of the client_assertion (the Hydra token
	// endpoint URL Hydra recognises).
	AssertionAudience string
	// GatewayAudience — the requested token `aud` (https://{API_DOMAIN}) — what the
	// production gateway accepts.
	GatewayAudience string
	// Logger — surfaces mint failures. nil → no logging.
	Logger *slog.Logger
}

// hydraExchange adapts *clients.HydraTokenClient to
// bootstraptoken.TokenExchanger, mapping issuer-unavailability to the use-case's
// fail-closed sentinel. The raw Hydra body never rides in the returned error.
type hydraExchange struct {
	client *clients.HydraTokenClient
}

func (a hydraExchange) Exchange(ctx context.Context, in bootstraptoken.ExchangeInput) (bootstraptoken.ExchangeOutput, error) {
	out, err := a.client.ClientCredentials(ctx, clients.ClientCredentialsRequest{
		ClientAssertion: in.ClientAssertion,
		Audience:        in.Audience,
		Scope:           in.Scope,
	})
	if err != nil {
		if errors.Is(err, clients.ErrHydraUnavailable) {
			return bootstraptoken.ExchangeOutput{}, bootstraptoken.ErrIssuerUnavailable
		}
		// A 4xx rejection (bad/expired assertion) — the use-case fails closed too.
		return bootstraptoken.ExchangeOutput{}, err
	}
	return bootstraptoken.ExchangeOutput{AccessToken: out.AccessToken, ExpiresIn: out.ExpiresIn}, nil
}

// Build assembles the bootstrap-token mint handler. Composition root only.
func Build(pool *pgxpool.Pool, cfg BuildConfig) *bootstraptoken.Handler {
	store := kachopg.NewBootstrapStore(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	hydraAdmin := clients.NewHydraAdminClient(cfg.HydraAdminURL, cfg.HydraAdminToken)
	exchanger := hydraExchange{client: clients.NewHydraTokenClient(cfg.HydraTokenURL)}

	uc := bootstraptoken.NewMintUseCase(store, txb, hydraAdmin, exchanger, bootstraptoken.Config{
		SigningKeyPEM:     cfg.SigningKeyPEM,
		AssertionAudience: cfg.AssertionAudience,
		GatewayAudience:   cfg.GatewayAudience,
	}).WithLogger(cfg.Logger)

	return bootstraptoken.NewHandler(uc)
}
