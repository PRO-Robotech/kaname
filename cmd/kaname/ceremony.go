// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony.go — сборка церемонии OAuth 2.1 `authorization_code` нашими силами
// в композиционном корне (приёмка LINE-A-1; задачи PRO-Robotech/kaname#423 и
// #407): движок фундамента (`corelib/oauthceremony`) над хранилищами слоя
// доступа и адаптерами службы, шов входа над нашей сессией, поверхность —
// эндпоинт авторизации, метаданные обнаружения и полосы токен-эндпоинта.
//
// # Что сборка держит сама
//
//   - ПОДПИСАНТ — значение процесса: порт выпуска собран над ТЕМ ЖЕ
//     `*tokensigner.Signer`, что чеканит все токены службы, и часы выпуска —
//     часы церемонии (K5, `internal/ceremonyport`). Что собран именно он,
//     проверяет предъявитель: токен церемонии сверяется ключом и издателем
//     подписанта службы (пробы `TestLINEA1_*`, `bearerClaims`).
//   - ПОЛУЧАТЕЛЬ выданного — регистрация клиента церемонии
//     (`interactive_clients.audiences`): получателя штампуем мы, вызывающий его
//     не называет (приёмка Р6). Это ответ на условие п. 3 kaname#407 первой
//     ветвью: регистрация клиента ограничивает выдаваемого получателя.
//   - СЕКРЕТ клиента сверяет проверяющий ПОЛОСЫ ВХОДА — тот же пул вычислений,
//     под который посчитан бюджет памяти (`login.ValidateMemoryBudget`), с
//     приманкой того же класса, что пишет хешер паролей. Сверка церемонии
//     занимает не больше половины его ёмкости (`ceremonyport.ClientSecrets`):
//     поток на токен-эндпоинте не отнимает мест у входа людей, а ёмкость
//     меньше двух под церемонией — отказ старта.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// ceremonyOperationTimeout — срок ВСЕЙ операции церемонии (выдачи кода,
// обмена, оборота). Вызовы портов операции идут подряд, и каждый — один оператор
// базы порядка миллисекунды; предел одного вызова — credentialLanePeerTimeout.
// Операции отведено два таких предела: один вызов вправе исчерпать свой, и
// остальные укладываются во второй. Дольше — хранилище не отвечает, и клиент
// повторяет запрос, а не ждёт.
const ceremonyOperationTimeout = 2 * credentialLanePeerTimeout

// ceremonySurface — собранная поверхность церемонии.
type ceremonySurface struct {
	Authorize *ceremonyhttp.Authorize
	Discovery *ceremonyhttp.Discovery
	Token     *ceremonyhttp.TokenLane
	Census    *ceremonyhttp.Census
}

// ceremonyKeySource — публикуемый набор ключей как порт опознания токена.
// nil-указатель ключницы (своя чеканка выключена) в интерфейс не кладётся:
// пустой интерфейс и есть «набора нет», и сборка отказывает по нему явно.
func ceremonyKeySource(k *signingkeys.Keystore) ceremonyport.KeySetSource {
	if k == nil {
		return nil
	}
	return k
}

// buildCeremonySurface собирает церемонию.
//
// Возвращает nil, nil, когда церемонии на посадке нет: под `external` вход и
// интерактивный путь держит поставщик, а полосы церемонии живут на
// токен-эндпоинте — без него их некуда поставить. Всякий иной неполный вход —
// ошибка и отказ в старте.
func buildCeremonySurface(
	pool *pgxpool.Pool,
	cfg config.Config,
	signer *tokensigner.Signer,
	keys ceremonyport.KeySetSource,
	secrets ceremonyport.SecretChecker,
	logger *slog.Logger,
) (*ceremonySurface, error) {
	if cfg.AuthN.IdentityProvider != config.IdentityProviderOwn || !cfg.AuthN.ClientToken.Enabled {
		return nil, nil
	}
	switch {
	case signer == nil:
		return nil, errors.New("ceremony: own sign-in is on but our signer is not wired")
	case keys == nil:
		return nil, errors.New("ceremony: the published key set is not wired")
	case secrets == nil:
		return nil, errors.New("ceremony: the client secret checker is not wired")
	case logger == nil:
		return nil, errors.New("ceremony: a logger is required")
	}

	authorizeURL, tokenURL, err := ceremonyhttp.Endpoints(signer.Issuer())
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	store := kanamepg.NewOAuthCeremonyRepo(pool)
	vaults := kanamepg.NewCeremonyVaults(pool)
	issuer, err := ceremonyport.NewAccessTokens(signer, keys, store)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	grants, err := ceremonyport.NewGrants(store)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	clientSecrets, err := ceremonyport.NewClientSecrets(store, secrets)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	engine, err := oauthceremony.New(oauthceremony.Config{
		AuthorizationEndpoint: authorizeURL,
		TokenEndpoint:         tokenURL,
		// Срок токена доступа — тот же, что у машинных полос этого эндпоинта:
		// одна ручка срока выпускаемого токена на поверхность.
		AccessTokenLifespan: cfg.AuthN.ClientToken.TokenTTL,
		// Срок одного токена обновления — потолок семейства фундамента; семейство
		// кончается раньше вместе со своей сессией (граница выдачи и хранилища).
		RefreshTokenLifespan:      tokenpolicy.MaxRefreshTokenFamilyTTL,
		AuthorizationCodeLifespan: tokenpolicy.MaxAuthorizationCodeTTL,
		ScopeMatching:             oauthceremony.ScopeMatchingExact,
		// Токен обновления выдаётся вместе с токеном доступа каждым обменом
		// (приёмка Р8).
		RefreshTokenIssuance: oauthceremony.RefreshTokenIssuanceAlways,
		MinParameterEntropy:  ceremonyhttp.StateFloor,
		PortTimeout:          credentialLanePeerTimeout,
		OperationTimeout:     ceremonyOperationTimeout,
		NewGrantID:           ceremonyport.NewGrantID,
	}, oauthceremony.Ports{
		Clients:            vaults,
		AuthorizationCodes: vaults,
		AccessTokens:       vaults,
		RefreshTokens:      vaults,
		Grants:             grants,
		AccessTokenIssuer:  issuer,
		ClientSecrets:      clientSecrets,
		Transaction:        vaults,
	})
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}

	resolve, err := humansession.NewResolveUseCase(kanamepg.NewHumanSessionRepo(pool), nil, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	authority, err := ceremonyhttp.NewSessionAuthority(resolve)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	census := ceremonyhttp.NewCensus()
	authorize, err := ceremonyhttp.NewAuthorize(ceremonyhttp.AuthorizeConfig{
		Engine: engine, Clients: vaults, Authority: authority, Census: census, Logger: logger, Clock: time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	token, err := ceremonyhttp.NewTokenLane(engine, vaults, census, logger)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	discovery, err := ceremonyhttp.NewDiscovery(ceremonyhttp.DiscoveryConfig{
		Issuer:                signer.Issuer(),
		AuthorizationEndpoint: authorizeURL,
		TokenEndpoint:         tokenURL,
		// Виды выдачи токен-эндпоинта целиком: полосы церемонии и машинные.
		GrantTypes: append(token.Grants(), tokenpolicy.GrantTypeClientCredentials, tokenpolicy.GrantTypeJWTBearer),
		Scopes:     domain.CeremonyScopes(),
	})
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	logger.Info("own OAuth ceremony is on",
		slog.String("authorization_endpoint", authorizeURL),
		slog.String("token_endpoint", tokenURL),
		slog.String("access_token_lifespan", cfg.AuthN.ClientToken.TokenTTL.String()),
		slog.String("authorization_code_lifespan", tokenpolicy.MaxAuthorizationCodeTTL.String()),
		slog.Int("state_floor", ceremonyhttp.StateFloor))
	return &ceremonySurface{Authorize: authorize, Discovery: discovery, Token: token, Census: census}, nil
}
