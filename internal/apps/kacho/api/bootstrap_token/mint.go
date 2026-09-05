// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// MaxTTL — срок бутстрап-удостоверения.
//
// С переводом на свою чеканку это решение стало НАШИМ: подпись наша, значит и
// срок наш, и он не выводится из чужого ответа. Величина мала намеренно — токен
// несёт cluster-admin и существует ради того, чтобы получить ПЕРВЫЙ доступ, а не
// чтобы им пользоваться.
const MaxTTL = 15 * time.Minute

// Config — mint policy + the env-held bootstrap key.
type Config struct {
	// SigningKeyPEM — the bootstrap ES256 (P-256, PKCS#8) private key PEM,
	// supplied from a k8s Secret. Empty → mint disabled (fail-closed,
	// ErrSigningKeyNotConfigured).
	//
	// Ключ ОСТАЁТСЯ и после перевода на свою чеканку, но роль у него одна из
	// двух прежних: он больше не подписывает утверждение поставщику — им
	// заводится открытая половина, записываемая в строку соответствия как наша
	// запись о ключе бутстрап-клиента. И он же остаётся ручкой, которой контур
	// включают: страж старта читает ЕЁ, поэтому «включено» у стража и у рантайма
	// не может разойтись.
	SigningKeyPEM string
	// GatewayAudience — адресат выпускаемого удостоверения (https://{API_DOMAIN}):
	// то, что принимает боевой край.
	GatewayAudience string
	// MaxTTL overrides the package default lifetime (zero → MaxTTL).
	MaxTTL time.Duration
}

// Result — the minted bootstrap token (transport-agnostic).
type Result struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	ExpiresAt   time.Time
	PrincipalID string
	IssuedAt    time.Time
}

// MintUseCase idempotently provisions the bootstrap client mapping (if absent)
// and mints a short-lived token for the bootstrap SA with OUR signer.
type MintUseCase struct {
	store  BootstrapStore
	txb    service.TxBeginner
	minter LocalMinter
	cfg    Config
	logger *slog.Logger
}

// NewMintUseCase constructs. MaxTTL falls back to the package default.
func NewMintUseCase(store BootstrapStore, txb service.TxBeginner, minter LocalMinter, cfg Config) *MintUseCase {
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = MaxTTL
	}
	return &MintUseCase{store: store, txb: txb, minter: minter, cfg: cfg}
}

// WithLogger wires the failure logger (composition root). nil → no logging.
func (u *MintUseCase) WithLogger(l *slog.Logger) *MintUseCase { u.logger = l; return u }

// Execute provisions (idempotently) and mints. Fail-closed: no signing key →
// UNAVAILABLE; nothing to sign with → UNAVAILABLE (no token, no leak).
//
// Срок НЕ является параметром запроса и никогда им не был: удостоверение
// подписано, и число в ответе не может укоротить подписанный предъявитель. Оно
// сообщает то, что стоит В ТОКЕНЕ, и берётся из него же — заниженный срок
// оставил бы живое cluster-admin удостоверение в обращении, потому что его никто
// не ищет: все считают, что оно умерло.
func (u *MintUseCase) Execute(ctx context.Context) (*Result, error) {
	if u.cfg.SigningKeyPEM == "" {
		u.logErr(ctx, "mint disabled", ErrSigningKeyNotConfigured)
		return nil, status.Error(codes.Unavailable, "bootstrap token minting is not configured")
	}
	if u.minter == nil {
		// Полусобранный контур — ОТКАЗ, а не тишина. Композиционный корень это
		// уже требует; здесь вторая, структурная половина того же требования.
		u.logErr(ctx, "mint disabled", errors.New("local minter is not wired"))
		return nil, status.Error(codes.Unavailable, "bootstrap token minting is not configured")
	}

	id, err := u.provision(ctx)
	if err != nil {
		return nil, err
	}

	out, merr := u.minter.MintToken(ctx, MintInput{
		SAKeyID:     id.SocID,
		PrincipalID: id.SvaID,
		Audience:    u.cfg.GatewayAudience,
		TTL:         u.cfg.MaxTTL,
	})
	// Fail-closed: нечем подписать / ключница не ответила ⇒ токена нет и
	// открытого отказа нет. Наружу — фиксированный текст (никакого оракула),
	// причина — в журнал.
	if merr != nil {
		u.logErr(ctx, "mint", merr)
		if errors.Is(merr, ErrMintingUnavailable) {
			return nil, status.Error(codes.Unavailable, "bootstrap token minting is unavailable")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	if out.AccessToken == "" {
		// Пустой токен при отсутствии ошибки — дефект НАШЕЙ провязки, и он
		// обязан отличаться от отказа подписанта: «выпустили ничто» не лечится
		// повтором.
		u.logErr(ctx, "mint", errors.New("minter returned an empty access token"))
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &Result{
		AccessToken: out.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(out.ExpiresAt.Sub(out.IssuedAt) / time.Second),
		ExpiresAt:   out.ExpiresAt.Truncate(time.Second),
		PrincipalID: id.SvaID,
		IssuedAt:    out.IssuedAt.Truncate(time.Second),
	}, nil
}

// provision ensures the bootstrap client mapping row exists, writing it exactly
// once under the transaction-scoped advisory lock (IBT-03). Returns the
// reconciled bootstrap identity.
func (u *MintUseCase) provision(ctx context.Context) (Identity, error) {
	id := DeriveIdentity()

	tx, err := u.txb.Begin(ctx)
	if err != nil {
		u.logErr(ctx, "begin tx", err)
		return Identity{}, status.Error(codes.Internal, "internal error")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	c, found, gerr := u.store.LockAndGet(ctx, tx)
	if gerr != nil {
		return Identity{}, u.mapErr(ctx, "lock-and-get", gerr)
	}

	if !found {
		pubPEM, kerr := publicKeyPEMFromPrivatePEM(u.cfg.SigningKeyPEM)
		if kerr != nil {
			u.logErr(ctx, "derive public key", kerr)
			return Identity{}, status.Error(codes.Internal, "internal error")
		}
		c = domain.ServiceAccountOAuthClient{
			ID:              domain.SAOAuthClientID(id.SocID),
			SvaID:           domain.ServiceAccountID(id.SvaID),
			OAuthClientID:   domain.OAuthClientID(id.ClientID),
			Description:     domain.Description("bootstrap-admin token-mint client (#58)"),
			CreatedByUserID: domain.UserID(id.CreatedByUserID),
			PublicKeyPEM:    pubPEM,
			KeyAlgorithm:    "ES256",
			Labels:          domain.Labels{},
			// Вид ЗАПИСЫВАЕТСЯ каждым писателем и читателем не вычисляется
			// (#1142). Здесь чеканится ключевая пара — значит KEYPAIR.
			// Неназванный вид отвергается закрытым словарём таблицы: это и
			// есть предмет ограничения — писатель, который вида не назвал.
			CredentialKind: domain.CredentialKindKeypair,
		}
		if ierr := u.store.InsertMapping(ctx, tx, c); ierr != nil {
			return Identity{}, u.mapErr(ctx, "insert mapping", ierr)
		}
	}

	if cerr := tx.Commit(ctx); cerr != nil {
		u.logErr(ctx, "commit", cerr)
		return Identity{}, status.Error(codes.Internal, "internal error")
	}
	committed = true

	// Reconcile from the committed mapping (loser-reuse path returns the
	// winner-provisioned values).
	id.SvaID = string(c.SvaID)
	id.SocID = string(c.ID)
	id.ClientID = string(c.OAuthClientID)
	return id, nil
}

// mapErr maps a repo error to a gRPC status, never leaking pgx/driver text.
func (u *MintUseCase) mapErr(ctx context.Context, action string, err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, iamerr.StripSentinel(err))
	}
	u.logErr(ctx, action, err)
	return status.Error(codes.Internal, "internal error")
}

func (u *MintUseCase) logErr(ctx context.Context, action string, err error) {
	if u.logger != nil {
		u.logger.ErrorContext(ctx, "bootstrap token mint failure",
			slog.String("action", action), slog.Any("err", err))
	}
}
