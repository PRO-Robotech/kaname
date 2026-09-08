// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bootstraptokenwire — composition-root wiring for the
// InternalBootstrapTokenService handler (#58). Assembles the bootstrap-token
// mint use-case (BootstrapStore pg adapter + НАШ подписант) and its thin gRPC
// handler. Single wire-up call for cmd/kaname.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ И ПОЧЕМУ ЭТО ГЛАВНОЕ (задача #1119, Ф4б эпика #896)
//
// Сборка держала к внешнему поставщику ДВЕ дороги: административного клиента для
// заведения его OAuth-клиента и клиента его токен-эндпоинта для обмена
// подписанного утверждения. Обе сняты: удостоверение чеканит НАШ подписант.
//
// Следствие, ради которого фаза и делается: у сборки не осталось ни одного
// поля, называющего адрес или якорь поставщика, — то есть свежий клон
// поднимается в боевой посадке, не дожидаясь, пока чужая сторона поднимется и
// узнает наш ключ.
package bootstraptokenwire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	bootstraptoken "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// ClaimsComposer — состав утверждений выпускаемого токена.
//
// Порт объявлен здесь узко и НАМЕРЕННО ведёт к тому же объявлению, каким состав
// собирается на остальных полосах выдачи: перевод чеканки не вправе тихо сменить
// принципала, а сменил бы он его именно так — второй сборкой утверждений, чьё
// расхождение с первой не выражено и потому не может покраснеть.
type ClaimsComposer interface {
	ClaimsForAssertionClient(ctx context.Context, client domain.AssertionClient, hookCtx service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error)
}

// TokenSigner — подписант с точки зрения этой сборки.
//
// Заведён портом, а не конкретным типом, ровно по той причине, по какой был
// заведён порт обмена у прежней полосы: классификация отказа ниже — решение о
// ПОЛОСЕ ответа, и проверять его надо на настоящем адаптере, а не на копии его
// логики в пробе.
type TokenSigner interface {
	Sign(ctx context.Context, req tokensigner.Request) (tokensigner.Token, error)
}

// localMint — НАШ подписант с точки зрения контура бутстрапа.
//
// Переходник без политики: субъект и адресат приходят от use-case, состав
// утверждений собирает единое объявление, а всё, что делает токен токеном —
// `kid`, срок, тип, издатель, — проставляет подписант.
type localMint struct {
	signer TokenSigner
	claims ClaimsComposer
}

var _ bootstraptoken.LocalMinter = localMint{}

// MintToken выпускает бутстрап-удостоверение.
func (m localMint) MintToken(ctx context.Context, in bootstraptoken.MintInput) (bootstraptoken.MintOutput, error) {
	if in.Audience == "" {
		// Незаданный адресат означал бы «любой», а удостоверение, годное любому
		// контуру, — это cluster-admin, предъявимый там, где его никто не ждёт.
		return bootstraptoken.MintOutput{}, errors.New("bootstrap token: audience is required")
	}

	claims, _, cerr := m.claims.ClaimsForAssertionClient(ctx, domain.AssertionClient{
		ID:      in.SAKeyID,
		Kind:    domain.AssertionClientServiceAccount,
		OwnerID: in.PrincipalID,
	}, service.TokenHookContext{
		GrantType:     tokenpolicy.GrantTypeClientCredentials,
		OAuthClientID: in.SAKeyID,
	})
	if cerr != nil {
		// Состав не собрался — токена нет. Пустой состав выглядел бы выданным
		// токеном и не нёс бы принципала: край принял бы его и не нашёл, за кого
		// он говорит.
		return bootstraptoken.MintOutput{}, fmt.Errorf("bootstrap token: claims: %w", cerr)
	}

	tok, serr := m.signer.Sign(ctx, tokensigner.Request{
		Subject:   in.PrincipalID,
		Audience:  []string{in.Audience},
		TokenType: tokenpolicy.TokenTypeAccess,
		TTL:       in.TTL,
		Claims:    claims,
	})
	if serr != nil {
		if errors.Is(serr, tokensigner.ErrNoSigningKey) {
			// Причина ОБОРАЧИВАЕТСЯ, а не подменяется. Наружу отказ уйдёт
			// фиксированным текстом (собирается в use-case) — оракула здесь нет;
			// а в журнал попадёт то, что ответила ключница.
			//
			// Приём перенесён с прежней полосы обмена, где он был куплен
			// разбором на живом стенде: голый признак давал журналу пересказ
			// собственного решения об отказе, и одна строка настоящей причины
			// закрывала бы вопрос сразу.
			return bootstraptoken.MintOutput{}, fmt.Errorf("%w: %w",
				bootstraptoken.ErrMintingUnavailable, serr)
		}
		// Прочий отказ подписи — дефект нашей провязки либо ключевого
		// материала: повтор его не лечит, и полоса ответа у него другая.
		return bootstraptoken.MintOutput{}, fmt.Errorf("bootstrap token: sign: %w", serr)
	}
	return bootstraptoken.MintOutput{
		AccessToken: tok.Token,
		IssuedAt:    tok.IssuedAt,
		ExpiresAt:   tok.ExpiresAt,
	}, nil
}

// BuildConfig — composition inputs for the bootstrap-token mint handler.
type BuildConfig struct {
	// SigningKeyPEM — the bootstrap ES256 (P-256, PKCS#8) private key PEM,
	// supplied from a k8s Secret (KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM). Empty →
	// mint disabled (fail-closed).
	SigningKeyPEM string
	// Signer — НАШ подписант. Обязателен, когда контур включён: выпускать иначе
	// нечем, и «включено, но нечем» здесь не выражается.
	Signer TokenSigner
	// Claims — состав утверждений. Обязателен вместе с подписантом: токен без
	// принципала край принял бы и не нашёл, за кого тот говорит.
	Claims ClaimsComposer
	// GatewayAudience — адресат выпускаемого удостоверения (https://{API_DOMAIN}).
	GatewayAudience string
	// TokenTTL — срок выпускаемого удостоверения; ноль → умолчание контура.
	TokenTTL time.Duration
	// Logger — surfaces mint failures. nil → no logging.
	Logger *slog.Logger
}

// Build assembles the bootstrap-token mint handler. Composition root only.
//
// Неполный вход при ВКЛЮЧЁННОМ контуре — отказ построения, а не деградация:
// собранный наполовину контур отвечал бы отказом на первом же запросе, и узнать
// об этом было бы неоткуда — стенд поднялся бы Ready.
func Build(pool *pgxpool.Pool, cfg BuildConfig) (*bootstraptoken.Handler, error) {
	store := kanamepg.NewBootstrapStore(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)

	var minter bootstraptoken.LocalMinter
	if cfg.SigningKeyPEM != "" {
		switch {
		case cfg.Signer == nil:
			return nil, errors.New("бутстрап-чеканка включена (ключ задан), а НАШ подписант не провязан: " +
				"включите свою чеканку токенов (authn.token-signing.enabled) — выпускать иначе нечем")
		case cfg.Claims == nil:
			return nil, errors.New("бутстрап-чеканка включена, а состав утверждений не провязан: " +
				"токен без принципала край принял бы и не нашёл, за кого он говорит")
		}
		minter = localMint{signer: cfg.Signer, claims: cfg.Claims}
	}

	uc := bootstraptoken.NewMintUseCase(store, txb, minter, bootstraptoken.Config{
		SigningKeyPEM:   cfg.SigningKeyPEM,
		GatewayAudience: cfg.GatewayAudience,
		MaxTTL:          cfg.TokenTTL,
	}).WithLogger(cfg.Logger)

	return bootstraptoken.NewHandler(uc), nil
}
