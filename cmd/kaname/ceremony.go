// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony.go — сборка церемонии OAuth 2.1 `authorization_code` нашими силами
// (под-фаза LINE-A-1, задача PRO-Robotech/kacho#2721; приёмка
// `sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md`).
//
// # Где церемония существует — ровно под посадкой `own`
//
// Производитель шва «авторитет входа» — наш вход человека (Р1, Р2), а он
// поднимается только посадкой `own`. Под `external` интерактивный путь ведёт
// внешний поставщик, и второй, параллельный, вход не заводится (решение 1):
// сборка возвращает nil без ошибки, эндпоинт авторизации и обнаружения не
// монтируются, а виды выдачи `authorization_code` и `refresh_token` остаются
// вне перечня токен-эндпоинта.
//
// # Что собирается
//
// Эндпоинт авторизации и метаданные обнаружения — отдельными обработчиками для
// муксa поверхности выдачи; обмен и ротация — полосами токен-эндпоинта
// (`clienttokenhttp.CeremonyLanes`): поверхность выдачи одна, второй внешний
// слушатель об одном предмете не заводится.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// authorizationCeremony — собранная церемония.
type authorizationCeremony struct {
	authorize *ceremonyhttp.AuthorizeHandler
	discovery *ceremonyhttp.DiscoveryHandler
	exchange  *ceremony.ExchangeUseCase
	census    *ceremony.Census
}

// lanes — полосы обмена для токен-эндпоинта; nil-церемония — ни одной (и
// именно nil интерфейса, а не интерфейс с nil внутри: токен-эндпоинт судит
// отсутствие полос сравнением с nil).
func (c *authorizationCeremony) lanes() clienttokenhttp.CeremonyLanes {
	if c == nil {
		return nil
	}
	return c.exchange
}

// buildAuthorizationCeremony собирает церемонию. nil, nil — посадка без своего
// входа человека (законное состояние). Всякий иной неполный вход — ошибка,
// отказывающая в старте.
func buildAuthorizationCeremony(
	pool *pgxpool.Pool,
	cfg config.Config,
	signer *tokensigner.Signer,
	secrets ceremony.SecretVerifier,
	logger *slog.Logger,
) (*authorizationCeremony, error) {
	if cfg.AuthN.IdentityProvider != config.IdentityProviderOwn {
		return nil, nil
	}
	switch {
	case !cfg.AuthN.ClientToken.Enabled:
		return nil, fmt.Errorf("authorization ceremony: the own sign-in lane is up but the token endpoint is disabled — " +
			"a code would be issued that nothing can exchange")
	case signer == nil:
		return nil, fmt.Errorf("authorization ceremony: our signer is not wired — nothing to mint the bearer with")
	case secrets == nil:
		return nil, fmt.Errorf("authorization ceremony: client secret verifier is not wired")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(slog.String("component", "authorization_ceremony"))

	resolve, err := humansession.NewResolveUseCase(kanamepg.NewHumanSessionRepo(pool), humansession.NopObserver{}, time.Now)
	if err != nil {
		return nil, fmt.Errorf("authorization ceremony: %w", err)
	}
	store := kanamepg.NewAuthorizationCeremonyRepo(pool)
	clients := ceremonyClients{clients: kanamepg.NewInteractiveClientRepo(pool), secrets: store}
	census := ceremony.NewCensus()

	authorizeUC, err := ceremony.NewAuthorizeUseCase(clients, ownLoginAuthority{
		resolve: resolve, cutoffs: kanamepg.NewUserTokenRevocationRepo(pool),
	}, store, census, logger)
	if err != nil {
		return nil, fmt.Errorf("authorization ceremony: %w", err)
	}
	exchangeUC, err := ceremony.NewExchangeUseCase(ceremony.ExchangeConfig{
		AllowedAudiences: cfg.AuthN.ClientToken.AudienceList(),
		DefaultAudience:  cfg.AuthN.ClientToken.DefaultAudience,
		TokenTTL:         cfg.AuthN.ClientToken.TokenTTL,
		Clock:            time.Now,
	}, ceremony.ExchangeDeps{
		Clients: clients,
		Secrets: secrets,
		Store:   store,
		Signer:  signer,
		Users:   kanamepg.NewUserPoolRepo(pool),
		// Состав утверждений человека — ТОТ ЖЕ производитель, что у прочих
		// полос нашей чеканки (token_claims.go).
		Claims: newAssertionClaimsComposer(pool, cfg),
		Census: census,
		Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("authorization ceremony: %w", err)
	}
	discovery, err := ceremonyhttp.NewDiscoveryHandler(signer.Issuer())
	if err != nil {
		return nil, fmt.Errorf("authorization ceremony: discovery document: %w", err)
	}
	return &authorizationCeremony{
		authorize: ceremonyhttp.NewAuthorizeHandler(authorizeUC),
		discovery: discovery,
		exchange:  exchangeUC,
		census:    census,
	}, nil
}

// ownLoginAuthority — производитель шва «авторитет входа»: НАШ вход (Ф1).
// Сессия читается тем же вариантом использования, что отвечает краю, и
// отсечка субъекта применяется здесь же: край судит её на каждом
// предъявлении сессии, а церемония выдаёт удостоверение по сессии, которую
// край ещё не видел.
type ownLoginAuthority struct {
	resolve *humansession.ResolveUseCase
	cutoffs interface {
		RevokedBefore(ctx context.Context, userID string) (time.Time, bool, error)
	}
}

func (a ownLoginAuthority) Resolve(ctx context.Context, presented domain.SessionBearer) (ceremony.Authentication, bool, error) {
	view, found, err := a.resolve.Execute(ctx, presented)
	if err != nil {
		return ceremony.Authentication{}, false, err
	}
	if !found {
		return ceremony.Authentication{}, false, nil
	}
	cutoff, cut, err := a.cutoffs.RevokedBefore(ctx, string(view.User.ID))
	if err != nil {
		return ceremony.Authentication{}, false, err
	}
	// Включающе, как на крае: аутентифицированное в момент отсечки и раньше —
	// отозвано.
	if cut && !view.Session.AuthenticatedAt.After(cutoff) {
		return ceremony.Authentication{}, false, nil
	}
	return ceremony.Authentication{
		Subject:         view.User.ID,
		Session:         view.Session.ID,
		AuthenticatedAt: view.Session.AuthenticatedAt,
		Level:           view.Session.AssuranceLevel,
	}, true, nil
}

// ceremonyClients — чтение интерактивного клиента и его секрета.
type ceremonyClients struct {
	clients *kanamepg.InteractiveClientRepo
	secrets *kanamepg.AuthorizationCeremonyRepo
}

func (c ceremonyClients) InteractiveClient(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	got, err := c.clients.Get(ctx, id)
	if errors.Is(err, iamerr.ErrNotFound) {
		return domain.InteractiveClient{}, false, nil
	}
	if err != nil {
		return domain.InteractiveClient{}, false, err
	}
	return got, true, nil
}

func (c ceremonyClients) ClientSecret(ctx context.Context, id domain.InteractiveClientID) (ceremony.ClientSecret, bool, error) {
	return c.secrets.ClientSecret(ctx, id)
}

// ceremonySecretOutcomes — приёмник исходов проверяющего секрета клиента.
// Исход полосы (совпал · не совпал · материала нет · ёмкость · значение не
// читается) считает перепись церемонии своей клеткой на каждый — второй
// счётчик того же предмета здесь был бы копией.
type ceremonySecretOutcomes struct{}

func (ceremonySecretOutcomes) VerificationObserved(passwordverify.Outcome) {}

// secretVerifierPort — проверяющий как порт, БЕЗ интерфейса с nil внутри:
// сборка судит отсутствие проверяющего сравнением с nil.
func secretVerifierPort(v *passwordverify.Verifier) ceremony.SecretVerifier {
	if v == nil {
		return nil
	}
	return v
}
