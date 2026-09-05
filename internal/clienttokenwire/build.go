// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clienttokenwire — сборка токен-эндпоинта платформы (задача #898,
// приёмка F2 §9.1 п. 11).
//
// # Зачем отдельный пакет сборки
//
// Эндпоинт состоит из четырёх частей, и три из них при полусобранной провязке
// выглядят исправными: проверяющий без потолка длительности принимает
// утверждение с любым сроком; выдача без перечня адресатов выдаёт токен,
// адресованный чему угодно; чтение реестра без предела времени висит на
// неотвечающем соседе, пока не кончатся горутины. Ни одно из трёх не
// проявляется отказом на положительном пути.
//
// Поэтому сборка — ОДНО место и ОДИН отказ: неполная провязка не поднимает
// сервис. Отказ в старте виден оператору сразу и называет величину; отказ на
// первом принятом чужом утверждении не виден никогда.
//
// # Почему величины приезжают ПАРАМЕТРОМ, а не читаются здесь
//
// Потолок длительности утверждения и допуск расхождения часов объявлены числом
// ровно в одном месте — `pkg/tokenpolicy`. Читай их сборка сама, страж стал бы
// тождественно истинным: константа не бывает незаданной. Приезжая параметром,
// они становятся тем, что подал композиционный корень, — и это уже проверяемо.
package clienttokenwire

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/clienttokenhttp"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// BuildConfig — вход сборки. Каждая величина обязательна.
type BuildConfig struct {
	// Logger — журнал исходов. Наружу все отказы аутентификации неразличимы,
	// поэтому различимость живёт здесь и в счётчиках.
	Logger *slog.Logger
	// ExpectedAudience — идентификатор НАШЕГО издателя: единственная
	// принимаемая форма адресата утверждения.
	ExpectedAudience string
	// AssertionLifetimeCeiling — потолок разницы «срок − момент выпуска» на
	// полосе аутентификации клиента.
	AssertionLifetimeCeiling time.Duration
	// FederatedLifetimeCeiling — тот же потолок на федеративной полосе, где
	// утверждение подписал внешний издатель (#1124). Отдельная величина, а не
	// та же: внешний издатель выпускает своей нагрузке токен со своим сроком.
	FederatedLifetimeCeiling time.Duration
	// ClockSkew — допуск расхождения часов, на обе стороны.
	ClockSkew time.Duration
	// Clock — источник времени. Вход, а не окружение.
	Clock func() time.Time
	// AllowedAudiences — объявленный перечень адресатов платформы.
	AllowedAudiences []string
	// DefaultAudience — адресат, когда запрос его не назвал.
	DefaultAudience string
	// TokenTTL — обычный срок выпускаемого токена.
	TokenTTL time.Duration
	// BodyCeiling — потолок тела запроса.
	BodyCeiling int64
	// PeerTimeout — предел времени КАЖДОГО внешнего вызова этого пути: чтения
	// реестра и допуска однократности.
	//
	// Обязателен, а не «разумное умолчание»: неотвечающий сосед без предела
	// вешает горутину навсегда, и горутины копятся до исчерпания процесса —
	// то есть отказ приходит не туда, где причина.
	PeerTimeout time.Duration
}

// New собирает эндпоинт из уже готовых портов.
//
// Разделено с провязкой от пула намеренно: сборка — то место, где живёт отказ,
// и она обязана проверяться без базы. Проверка, которой нужна база, гоняется
// реже, а страж обязан гоняться всегда.
func New(
	cfg BuildConfig,
	clients clientassertion.ClientResolver,
	issuers clientassertion.TrustedIssuerResolver,
	replay clientassertion.ReplayGuard,
	signer client_token.Signer,
	claims client_token.ClaimSource,
) (*clienttokenhttp.Handler, error) {
	if cfg.PeerTimeout <= 0 {
		return nil, fmt.Errorf("clienttokenwire: per-call timeout must be declared as a positive number " +
			"(got none) — an external call without its own deadline hangs on an unresponsive peer forever")
	}
	if strings.TrimSpace(cfg.ExpectedAudience) == "" {
		return nil, fmt.Errorf("clienttokenwire: expected assertion audience is required " +
			"(empty means 'accept any audience')")
	}
	if clients == nil {
		return nil, fmt.Errorf("clienttokenwire: client resolver is required")
	}
	if issuers == nil {
		// Перечень доверенных издателей — не «дополнительная возможность»:
		// эндпоинт объявляет федеративную выдачу, и без перечня она отвергала
		// бы всякое утверждение молча.
		return nil, fmt.Errorf("clienttokenwire: trusted issuer resolver is required")
	}
	if replay == nil {
		return nil, fmt.Errorf("clienttokenwire: replay guard is required")
	}

	verifier, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience:     cfg.ExpectedAudience,
		MaxLifetime:          cfg.AssertionLifetimeCeiling,
		MaxFederatedLifetime: cfg.FederatedLifetimeCeiling,
		ClockSkew:            cfg.ClockSkew,
		Clock:                cfg.Clock,
	},
		WithDeadlineResolver(clients, cfg.PeerTimeout),
		WithDeadlineIssuers(issuers, cfg.PeerTimeout),
		WithDeadlineReplay(replay, cfg.PeerTimeout))
	if err != nil {
		return nil, fmt.Errorf("clienttokenwire: verifier: %w", err)
	}

	issue, err := client_token.New(client_token.Config{
		AllowedAudiences: cfg.AllowedAudiences,
		DefaultAudience:  cfg.DefaultAudience,
		TokenTTL:         cfg.TokenTTL,
		Clock:            cfg.Clock,
	}, signer, claims)
	if err != nil {
		return nil, fmt.Errorf("clienttokenwire: issuance: %w", err)
	}

	h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
		BodyCeiling: cfg.BodyCeiling,
		Logger:      cfg.Logger,
	}, verifier, issue)
	if err != nil {
		return nil, fmt.Errorf("clienttokenwire: endpoint: %w", err)
	}
	return h, nil
}

// FromPool собирает эндпоинт от пула: реестр, способный к утверждению, и
// хранилище однократности берутся из своей базы.
func FromPool(
	pool *pgxpool.Pool,
	cfg BuildConfig,
	signer client_token.Signer,
	claims client_token.ClaimSource,
) (*clienttokenhttp.Handler, error) {
	if pool == nil {
		return nil, fmt.Errorf("clienttokenwire: pool is required")
	}
	return New(cfg,
		kachopg.NewAssertionClientRepo(pool),
		kachopg.NewTrustedIssuerRepo(pool),
		kachopg.NewClientAssertionReplayRepo(pool),
		signer, claims)
}

// ── предел времени на каждом внешнем вызове ─────────────────────────────────

// deadlineResolver — чтение реестра со СВОИМ пределом времени.
type deadlineResolver struct {
	inner   clientassertion.ClientResolver
	timeout time.Duration
}

// WithDeadlineResolver оборачивает чтение реестра собственным пределом.
//
// Обёртка, а не предел у вызывающего: вызывающих у порта больше одного, и
// предел, выставленный у каждого по отдельности, у одного из них рано или
// поздно не появится — молча, потому что отсутствие предела выглядит как его
// наличие ровно до того дня, когда сосед перестаёт отвечать.
func WithDeadlineResolver(inner clientassertion.ClientResolver, timeout time.Duration) clientassertion.ClientResolver {
	return deadlineResolver{inner: inner, timeout: timeout}
}

func (d deadlineResolver) ResolveAssertionClient(ctx context.Context, clientID string) (domain.AssertionClient, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.ResolveAssertionClient(ctx, clientID)
}

// deadlineIssuers — чтение перечня доверенных издателей со СВОИМ пределом.
type deadlineIssuers struct {
	inner   clientassertion.TrustedIssuerResolver
	timeout time.Duration
}

// WithDeadlineIssuers оборачивает чтение перечня собственным пределом.
//
// Тот же довод, что у чтения реестра: перечень лежит на пути АУТЕНТИФИКАЦИИ, и
// чтение без предела вешает горутину на неотвечающей базе — отказ приходит не
// туда, где причина.
func WithDeadlineIssuers(
	inner clientassertion.TrustedIssuerResolver, timeout time.Duration,
) clientassertion.TrustedIssuerResolver {
	return deadlineIssuers{inner: inner, timeout: timeout}
}

func (d deadlineIssuers) ResolveTrustedIssuer(ctx context.Context, issuer, subject string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.ResolveTrustedIssuer(ctx, issuer, subject)
}

// deadlineReplay — допуск однократности со СВОИМ пределом времени.
type deadlineReplay struct {
	inner   clientassertion.ReplayGuard
	timeout time.Duration
}

// WithDeadlineReplay оборачивает допуск однократности собственным пределом.
func WithDeadlineReplay(inner clientassertion.ReplayGuard, timeout time.Duration) clientassertion.ReplayGuard {
	return deadlineReplay{inner: inner, timeout: timeout}
}

func (d deadlineReplay) Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.Redeem(ctx, clientID, assertionID, expiresAt)
}
