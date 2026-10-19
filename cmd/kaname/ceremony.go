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
//   - СРОК операции — из ёмкости проверяющего и стоимости одной проверки,
//     откалиброванной при старте огибающей полосы входа
//     (`ceremonyOperationDeadline`): сверки ждут места вычисления по очереди,
//     и срок учитывает очередь (kaname#882).
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
	ceremonyapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/oauth_ceremony"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/exchangepace"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// ceremonyOperationDeadline — срок ВСЕЙ операции церемонии (выдачи кода,
// обмена, оборота): два предела вызова базы плюс очередь проверок секрета на
// процессоре (kaname#882).
//
// Слагаемых два, и они о разном:
//
//   - вызовы портов хранения идут подряд, и каждый — один оператор базы порядка
//     миллисекунды; предел одного вызова — credentialLanePeerTimeout. Им
//     отведено два таких предела: один вызов вправе исчерпать свой, и
//     остальные укладываются во второй;
//   - сверка секрета клиента — вычисление argon2id; начатое, оно отмены не
//     знает. Сверки и проверки входа людей ждут места вычисления по очереди
//     (мест не больше, чем процессоров, — `passwordverify`, места процессора),
//     и все места ёмкости, занятые разом, кончаются за ёмкость × стоимость
//     одной проверки, измеренной в одиночку на тех же процессорах. Это ОЦЕНКА,
//     а не предел: чеканка хеша (`passwordverify.Hasher`) идёт мимо мест
//     вычисления на тех же процессорах, и под ней очередь движется медленнее.
//     Предел — сам этот срок: ожидание места прерывается контекстом операции
//     (kaname#892), и сверка, не дождавшаяся места, кончается отказом к сроку,
//     а не ответом после него. Мост фундамента зовёт порт сверки со сроком
//     ОДНОГО вызова (`Config.PortTimeout`, credentialLanePeerTimeout), и этот
//     срок короче очереди; сверка ждёт места под сроком операции, который ей
//     видим через обёртку обмена (`ceremonyport.OperationScope`), а под сроком
//     порта идёт только чтение проверочного значения из базы. Стоимость —
//     потолок огибающей полосы входа (`passwordverify.Envelope.Floor`):
//     калибровка при старте самого дорогого класса среди лежащих в хранилище
//     и класса, которым пишутся и пароли, и секрет клиента, с запасом в
//     четверть. Класс, допущенный огибающей позже старта, срок не двигает.
//
// Срок без второго слагаемого считал каждый вызов «оператором базы» и
// отказывал по сроку всем одновременным обменам конфиденциального клиента
// разом: 0 из 16 под `-race` на узле кластера (kaname#818) и на одном
// процессоре (kaname#882, отказ `port_deadline` на выборке кода — срок
// операции съели сверки). Ёмкость — допуск по памяти — до числа процессоров не
// урезается: память проверки она уже держит, а на одном процессоре у сверки
// церемонии рядом с входом людей не осталось бы ни одного места. До числа
// процессоров урезаны места ВЫЧИСЛЕНИЯ: сверки сверх них не делят процессор
// и не кончаются все разом, а идут по одной, и операции за ними выходят к
// базе порознь, а не толпой на занятом процессоре.
// Дольше срока — хранилище не отвечает, и клиент повторяет запрос, а не ждёт.
func ceremonyOperationDeadline(capacity int, checkCost time.Duration) (time.Duration, error) {
	switch {
	case capacity <= 0:
		return 0, fmt.Errorf("ceremony: the secret checker capacity %d is not positive; the queue of checks is not counted", capacity)
	case checkCost <= 0:
		return 0, fmt.Errorf("ceremony: the cost of one secret check %v is not positive; the queue of checks is not counted", checkCost)
	}
	return 2*credentialLanePeerTimeout + time.Duration(capacity)*checkCost, nil
}

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
// Возвращает nil, nil, когда токен-эндпоинт выключен: полосы церемонии живут на
// нём, и без него их некуда поставить. Боевой старт с выключенным эндпоинтом
// отвергает проверка настройки раньше (`authn.client-token.enabled`), поэтому
// этот исход — только промежуточный шаг вне боевого режима. Всякий иной
// неполный вход — ошибка и отказ в старте.
func buildCeremonySurface(
	pool *pgxpool.Pool,
	cfg config.Config,
	signer *tokensigner.Signer,
	keys ceremonyport.KeySetSource,
	secrets ceremonyport.SecretChecker,
	secretCheckCost time.Duration,
	share ceremonyport.ShareObserver,
	source *issuingsource.Rule,
	logger *slog.Logger,
) (*ceremonySurface, error) {
	// Условие сборки — ТОТ ЖЕ предикат, что у стражей величин точки
	// авторизации и режима слушателя выдачи: три одинаковых условия разошлись
	// бы молча.
	if !cfg.AuthN.CeremonyAssembled() {
		return nil, nil
	}
	switch {
	case source == nil:
		return nil, errors.New("ceremony: the source address rule is not wired")
	case signer == nil:
		return nil, errors.New("ceremony: own sign-in is on but our signer is not wired")
	case keys == nil:
		return nil, errors.New("ceremony: the published key set is not wired")
	case secrets == nil:
		return nil, errors.New("ceremony: the client secret checker is not wired")
	case share == nil:
		return nil, errors.New("ceremony: the observer of the ceremony share of the checker is not wired")
	case logger == nil:
		return nil, errors.New("ceremony: a logger is required")
	}

	authorizeURL, tokenURL, err := ceremonyhttp.Endpoints(signer.Issuer())
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	// Сроки церемонии называет установка (kaname#318): страж старта уже принял
	// их в пределах потолков фундамента, и фундамент судит их ещё раз.
	lifespans := cfg.AuthN.Ceremony
	store := kanamepg.NewOAuthCeremonyRepo(pool)
	vaults, err := kanamepg.NewCeremonyVaults(pool, lifespans.RefreshTTL)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	// Правило выдачи удостоверениям человека (kaname#456, Р5б) — то же, что у
	// токен-эндпоинта, под тем же пределом; читает в транзакции
	// запроса обмена либо единицы работы оборота, которую держит церемония:
	// второй связи из пула в этом окне не берёт никто.
	issuanceRule, err := revocationpolicy.WithDeadline(kanamepg.NewCeremonyIssuanceRule(pool), credentialLanePeerTimeout)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	issuer, err := ceremonyport.NewAccessTokens(signer, keys, store, issuanceRule)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	grants, err := ceremonyport.NewGrants(store)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	clientSecrets, err := ceremonyport.NewClientSecrets(store, secrets, share)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	// Срок операции учитывает очередь проверок на процессоре: без неё
	// одновременные обмены отказывали бы по сроку разом.
	operationDeadline, err := ceremonyOperationDeadline(secrets.Capacity(), secretCheckCost)
	if err != nil {
		return nil, err
	}
	logger.Info("ceremony operation deadline",
		"secret_checker_capacity", secrets.Capacity(),
		"secret_check_cost", secretCheckCost.String(),
		"operation_deadline", operationDeadline.String())
	engine, exchangeUC, err := ceremonyExchange(oauthceremony.Config{
		AuthorizationEndpoint: authorizeURL,
		TokenEndpoint:         tokenURL,
		// Срок токена доступа — тот же, что у машинных полос этого эндпоинта:
		// одна ручка срока выпускаемого токена на поверхность.
		AccessTokenLifespan: cfg.AuthN.ClientToken.TokenTTL,
		// Срок одного токена обновления — срок семейства: токен семейства не
		// бывает годен дольше своего семейства. Предел семейства на обороте держит
		// граница выдачи и хранилища (рождение плюс тот же срок, не позже сессии).
		RefreshTokenLifespan:      lifespans.RefreshTTL,
		AuthorizationCodeLifespan: lifespans.CodeTTL,
		ScopeMatching:             oauthceremony.ScopeMatchingExact,
		// Токен обновления выдаётся вместе с токеном доступа каждым обменом
		// (приёмка Р8).
		RefreshTokenIssuance: oauthceremony.RefreshTokenIssuanceAlways,
		MinParameterEntropy:  ceremonyhttp.StateFloor,
		PortTimeout:          credentialLanePeerTimeout,
		OperationTimeout:     operationDeadline,
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
	}, vaults, credentialLanePeerTimeout)
	if err != nil {
		return nil, err
	}

	resolve, err := humansession.NewResolveUseCase(kanamepg.NewHumanSessionRepo(pool), nil, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	authority, err := ceremonyapp.NewSessionAuthority(resolve)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	// Сроки вызовов хранилища вариантов использования — та же величина, что
	// мост церемонии назначает каждому вызову порта (Config.PortTimeout): один
	// предел одного вызова хранилища на всю поверхность.
	authorizeUC, err := ceremonyapp.NewAuthorizeUseCase(ceremonyapp.AuthorizeDeps{
		Engine: engine, Clients: vaults, Authority: authority, Clock: time.Now,
		CallTimeout: credentialLanePeerTimeout, FamilyTTL: lifespans.RefreshTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	census := ceremonyhttp.NewCensus()
	authorizeCfg, err := ceremonyAuthorizePace(cfg, source, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	authorizeCfg.UseCase, authorizeCfg.Census, authorizeCfg.Logger = authorizeUC, census, logger
	authorize, err := ceremonyhttp.NewAuthorize(authorizeCfg)
	if err != nil {
		return nil, fmt.Errorf("ceremony: %w", err)
	}
	token, err := ceremonyhttp.NewTokenLane(exchangeUC, census, logger)
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
		slog.String("authorization_code_lifespan", lifespans.CodeTTL.String()),
		slog.String("refresh_token_lifespan", lifespans.RefreshTTL.String()),
		slog.Int("state_floor", ceremonyhttp.StateFloor),
		slog.Int("authorize_per_source_per_sec", cfg.AuthN.ClientToken.AuthorizePerSourcePerSec),
		slog.Int("authorize_in_flight_ceiling", cfg.AuthN.ClientToken.AuthorizeInFlightCeiling))
	return &ceremonySurface{Authorize: authorize, Discovery: discovery, Token: token, Census: census}, nil
}

// ceremonyExchange собирает церемонию фундамента и обмен над ней.
//
// Обмен идёт под сроком операции, видимым порту сверки секрета: мост
// фундамента даёт порту срок одного вызова, а сверка ждёт места вычисления до
// срока операции (kaname#892). Срок обёртки берётся из той же настройки, что
// срок операции церемонии (`Config.OperationTimeout`): две записи одного срока
// разошлись бы молча. Урегулирование запроса обмена — под сроком settle.
//
// Отделено от сборки поверхности затем, чтобы привязка обмена к сроку операции
// судилась без базы (ceremony_exchange_scope_test.go): обмен мимо обёртки
// оставлял бы зелёными и пробу обёртки, и пробы корня на одном процессоре.
func ceremonyExchange(cfg oauthceremony.Config, ports oauthceremony.Ports, units ceremonyapp.RequestUnits,
	settle time.Duration,
) (*oauthceremony.Ceremony, *ceremonyapp.ExchangeUseCase, error) {
	engine, err := oauthceremony.New(cfg, ports)
	if err != nil {
		return nil, nil, fmt.Errorf("ceremony: %w", err)
	}
	exchange, err := ceremonyport.NewOperationScope(engine, cfg.OperationTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("ceremony: %w", err)
	}
	exchangeUC, err := ceremonyapp.NewExchangeUseCase(ceremonyapp.ExchangeDeps{
		Engine: exchange, Units: units, SettleTimeout: settle,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ceremony: %w", err)
	}
	return engine, exchangeUC, nil
}

// ceremonyAuthorizePace — оси точки авторизации из настройки (приёмка
// ceremony-pace-is-named-by-number.md, П4 и П5): темп на источник, потолок
// одновременных и правило адреса источника.
//
// Отделено от сборки церемонии затем, чтобы переход «настройка → сборка» судился
// без базы: величина, которую страж требует, а корень не передаёт, оставляла бы
// обе стороны зелёными по своим пробам.
func ceremonyAuthorizePace(cfg config.Config, source *issuingsource.Rule, now func() time.Time) (ceremonyhttp.AuthorizeConfig, error) {
	if source == nil {
		return ceremonyhttp.AuthorizeConfig{}, errors.New("authorize pace: the source address rule is not wired")
	}
	pace, err := exchangepace.New(cfg.AuthN.ClientToken.AuthorizePerSourcePerSec, now)
	if err != nil {
		return ceremonyhttp.AuthorizeConfig{}, fmt.Errorf("authorize pace per source: %w", err)
	}
	return ceremonyhttp.AuthorizeConfig{
		Pace:            pace,
		InFlightCeiling: cfg.AuthN.ClientToken.AuthorizeInFlightCeiling,
		Source:          source.AuthorizePoint,
	}, nil
}
