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
	// HydraAdmin — the provider-admin client used for CreateOAuthClient, built by
	// the composition root so the trust anchor of the hop is resolved (and an
	// unusable one refused) in ONE place rather than per consumer.
	HydraAdmin *clients.HydraAdminClient
	// HydraTokenURL — the Hydra public token endpoint for the client_credentials
	// exchange.
	HydraTokenURL string
	// HydraTokenCAFile — the anchor that hop is verified against when the profile
	// pins one. Empty ⇒ the default transport (a plaintext in-cluster address needs
	// no anchor); production refuses to claim https without one.
	HydraTokenCAFile string
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
//
// Returns an error when the anchor pinned for the provider's token endpoint cannot
// be used: this hop carries the minted bearer in the response body, so falling back
// to the system roots would leave it unverified while reading as configured.
func Build(pool *pgxpool.Pool, cfg BuildConfig) (*bootstraptoken.Handler, error) {
	store := kachopg.NewBootstrapStore(pool)
	txb := kachopg.NewPoolTxBeginner(pool)
	hydraAdmin := cfg.HydraAdmin
	tokenClient, err := clients.NewHydraTokenClientWithCA(cfg.HydraTokenURL, cfg.HydraTokenCAFile)
	if err != nil {
		return nil, err
	}
	exchanger := hydraExchange{client: tokenClient}

	uc := bootstraptoken.NewMintUseCase(store, txb, hydraAdmin, exchanger, bootstraptoken.Config{
		SigningKeyPEM:     cfg.SigningKeyPEM,
		AssertionAudience: cfg.AssertionAudience,
		GatewayAudience:   cfg.GatewayAudience,
	}).WithLogger(cfg.Logger)

	return bootstraptoken.NewHandler(uc), nil
}
