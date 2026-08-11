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
	"fmt"
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

// tokenExchanger — порт обмена: ровно тот метод провайдерского клиента, который
// нужен адаптеру.
//
// Заведён узким намеренно. Классификация отказа ниже — решение о ПОЛОСЕ ответа,
// и проверять его надо на настоящем адаптере, а не на копии его логики в пробе;
// без порта подставить сюда отвечающего было нечем.
type tokenExchanger interface {
	ClientCredentials(context.Context, clients.ClientCredentialsRequest) (clients.TokenResponse, error)
}

// hydraExchange adapts the provider token client to bootstraptoken.TokenExchanger,
// mapping issuer-unavailability to the use-case's fail-closed sentinel. The raw
// provider body never rides in the returned error.
type hydraExchange struct {
	exchange tokenExchanger
}

func (a hydraExchange) Exchange(ctx context.Context, in bootstraptoken.ExchangeInput) (bootstraptoken.ExchangeOutput, error) {
	out, err := a.exchange.ClientCredentials(ctx, clients.ClientCredentialsRequest{
		ClientAssertion: in.ClientAssertion,
		Audience:        in.Audience,
	})
	if err != nil {
		if errors.Is(err, clients.ErrHydraUnavailable) {
			// Причина ОБОРАЧИВАЕТСЯ, а не подменяется. Наружу отказ всё равно
			// уйдёт фиксированным текстом (собирается в use-case) — здесь
			// оракула нет; а в журнал попадёт то, что ответила сеть.
			//
			// Прежде тут стоял голый sentinel, и журнал получал пересказ
			// собственного решения об отказе. На живом стенде это стоило двадцати
			// минут разбора: провайдер был здоров, а имя, по которому шёл обмен,
			// не резолвилось — одна строка «no such host» закрыла бы вопрос сразу.
			return bootstraptoken.ExchangeOutput{}, fmt.Errorf("%w: %w",
				bootstraptoken.ErrIssuerUnavailable, err)
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
	exchanger := hydraExchange{exchange: tokenClient}

	uc := bootstraptoken.NewMintUseCase(store, txb, hydraAdmin, exchanger, bootstraptoken.Config{
		SigningKeyPEM:     cfg.SigningKeyPEM,
		AssertionAudience: cfg.AssertionAudience,
		GatewayAudience:   cfg.GatewayAudience,
	}).WithLogger(cfg.Logger)

	return bootstraptoken.NewHandler(uc), nil
}
