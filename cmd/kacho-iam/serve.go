// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// serve.go — runServe: full lifecycle of the kacho-iam binary.
// Wires pools → repos → services → gRPC servers + HTTP listeners + drainers,
// then runs them in parallel with a shared shutdown trigger driven by
// SIGTERM / SIGINT or any task error.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho/pkg/authz"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
	"github.com/PRO-Robotech/kacho/pkg/servicehost"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
	"github.com/PRO-Robotech/kacho/services/iam/internal/registrytokenwire"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
)

// grpcStopper — поверхность graceful/forced остановки gRPC-сервера. *grpc.Server
// реализует ее; интерфейс делает stopGRPCBounded юнит-тестируемым без реального
// сервера и сетевого слушателя.
type grpcStopper interface {
	GracefulStop()
	Stop()
}

// stopGRPCBounded gives the server gracefulTimeout to drain in-flight RPCs and
// then forces Stop(): a stuck unary handler would otherwise hold GracefulStop
// forever and the shutdown would never complete.
func stopGRPCBounded(srv grpcStopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		srv.Stop()
	}
}

func runServe(cfg config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// logger.level was validated in main (cfg.Validate); SlogLevel cannot fail
	// here. Defensive fallback to INFO keeps the composition root total.
	logLevel, _ := cfg.Logger.SlogLevel()
	logger := observability.NewSloggerLevel(os.Stdout, logLevel)
	slog.SetDefault(logger)

	for _, w := range cfg.InsecureDevWarnings() {
		logger.Warn(w)
	}
	if cfg.AuthN.Mode == config.ModeProduction {
		logger.Warn("authn.mode=production: anonymous callers will be rejected (fail-closed)")
	}
	if cfg.AuthN.Mode == config.ModeProductionStrict {
		logger.Warn("authn.mode=production-strict: anonymous rejected + TLS+SSL strictly validated")
	}

	// Посадка процесса — ЧЕРЕЗ ЦЕНТРАЛЬНЫЙ ДЕСКРИПТОР, и до первого соединения
	// с базой (задача продукта #1406). Место выбрано не по вкусу: страж
	// шифрования до собственной базы, стоящий ПОСЛЕ открытия пула, судит
	// соединение, которое уже открыто, — то есть на боевой посадке с
	// `sslmode=disable` открытый канал успел бы состояться.
	posture, perr := describePosture(cfg, logger)
	if perr != nil {
		return fmt.Errorf("посадка процесса: %w", perr)
	}

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer pool.Close()

	// Загрузочный страж: посадка не вправе обещать базе больше соединений, чем
	// та принимает. Стоит СРАЗУ за созданием пула — до того, как процесс начнёт
	// открывать соединения по работе: проверка, отложенная дальше, узнаёт о
	// расхождении тогда же, когда о нём узнаёт арендатор.
	if err := assertConnBudgetFits(ctx, pool, cfg.Repository.Postgres.ReplicaBudget); err != nil {
		return err
	}

	// slave-pool wiring (read-replica). Если slave-url
	// настроен и отличается от master URL — отдельный pgxpool для read-TX'ов;
	// иначе slavePool = nil и kachopg.New() сделает fallback на master.
	var slavePool *pgxpool.Pool
	if slaveDSN := cfg.SlaveDSN(); slaveDSN != "" {
		slavePool, err = coredb.NewPool(ctx, slaveDSN)
		if err != nil {
			return fmt.Errorf("new slave pool: %w", err)
		}
		defer slavePool.Close()
		logger.Info("kacho-iam CQRS slave-pool enabled (read-replica)",
			"slave_url_masked", maskDSN(cfg.Repository.Postgres.SlaveURL))
	} else {
		logger.Info("kacho-iam CQRS slave-pool disabled — Reader-TX fallback to master")
	}

	// Schema = `kacho_iam`. cfg.DSN() уже несет
	// `options=-c search_path=kacho_iam,public` — unqualified-references из repo-кода
	// резолвятся в kacho_iam. operations-repo дополнительно передает схему явно
	// для квалификации SQL-операций.
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// Фоновая уборка терминальных строк таблицы операций.
	//
	// Строка заводится КАЖДОЙ мутацией — контракт объявляет мутации асинхронными,
	// и `Operation` возвращается вместо ресурса, — а снятия строк не было ни у
	// одного из восьми владельцев. Порог, предикат и расписание объявлены в
	// `pkg/operations` и `pkg/retention` ОДИН раз: восемь расписаний об одном
	// предмете разошлись бы молча.
	if _, err := operations.StartRetentionSweep(
		ctx, opsRepo, operations.DefaultRetentionConfig(),
		logger,
	); err != nil {
		return fmt.Errorf("фоновая уборка таблицы операций: %w", err)
	}

	// Cross-service gRPC dial — kacho-iam is a leaf-owner of Account/Project,
	// so it currently has no outbound peer-clients (other services dial in
	// for `iam.v1.ProjectService.Get` etc.).

	// kachoRepo is shared by all per-resource use-cases.
	kachoRepo := kachopg.New(pool, slavePool)

	// ВЫБОРА ПОСТАВЩИКА РЕШЕНИЯ О ДОСТУПЕ ЗДЕСЬ БОЛЬШЕ НЕТ.
	//
	// Он существовал, пока решение принимал внешний движок отношений: переменная
	// окружения выбирала адаптер, адаптер поднимался клиентом, клиент восстанавливался
	// конкретным типом ради полей, которых нет у порта. Ничего этого не осталось —
	// решение вычисляет реляционная форма в базе самой службы, и собирается она там же,
	// где всё остальное, что читает эту базу (см. buildServices).

	// Prometheus registry — owns the /metrics collectors. Created once and
	// shared by the metrics HTTP listener, the gRPC server interceptors (both
	// listeners) and the authz-Check decorator. Clean Architecture: prometheus
	// is imported only here (composition root) + the metrics adapter package.
	metricsReg := metrics.NewRegistry()

	// Состояние пулов соединений. До этой строки насыщение пула не наблюдалось
	// ничем: снаружи «запрос ждал свободного соединения» и «запрос сам по себе
	// медленный» выглядят одинаково — растянутой задержкой RPC, — а лечатся
	// противоположным (потолок пула против правки запроса). Разбор величин — у
	// коллектора в pkg/db.
	//
	// Пулов два, и метка `pool` их различает: без неё занятость реплики читалась
	// бы как занятость ведущего. Реплика регистрируется БЕЗУСЛОВНО, даже когда
	// slave-url не настроен и slavePool == nil: решение «пула нет — серий нет»
	// принимает коллектор, поэтому ветки здесь не нужно, а отсутствие серий
	// pool="replica" и есть честный ответ на «есть ли отдельный пул чтений».
	metricsReg.RegisterPoolStats("primary", pool)
	metricsReg.RegisterPoolStats("replica", slavePool)

	// Подключаем Prometheus-Recorder и логгер к default-registry LRO-worker'а и
	// поднимаем его dispatcher ДО приема трафика. Без этого default-registry держит
	// NopRecorder (live terminal-write/inflight метрики мертвы), а operations.Ready()
	// остается false до первого Run, поэтому readiness не отражает worker.
	// ConfigureDefault обязан предшествовать Start.
	lroRec := metricsReg.NewLRORecorder()
	// AccessBinding.Create dispatches on this default-registry. Operation.done means
	// the binding is durably committed; the binding's per-object access materializes
	// eventually-consistent (synchronous post-commit reconcile + co-committed event +
	// periodic sweep backstop), not gated on op.done.
	if err := operations.ConfigureDefault(
		operations.WithRecorder(lroRec),
		operations.WithLogger(logger),
	); err != nil {
		return fmt.Errorf("configure LRO default-registry: %w", err)
	}
	operations.Start()

	// Orphan-reconciler backstop: разрешает осиротевшие done=false операции умершего
	// процесса (kill-9 / истекший terminal-write budget) в терминал по
	// committed-реальности ресурса. Boot-sweep + периодический фон; non-fatal.
	startLROReconciler(ctx, pool, kachoRepo, lroRec, logger)

	// Durable backstop for one-shot credentials staged in FINISHED operation
	// responses. The reconciler above cannot cover them: its claim is done=false and
	// these rows are done=true by the time the credential is staged.
	if err := startSecretBackstop(ctx, pool, cfg, logger); err != nil {
		return fmt.Errorf("secret backstop: %w", err)
	}

	// Снятие истёкших удостоверений (задача #1264). Провязка ОБЯЗАТЕЛЬНА и
	// стоит рядом с уборщиком секретов: уборщик без вызывающего — механизм,
	// который выглядит существующим и не делает ничего, а таких в этом сервисе
	// уже два.
	startExpiredCredentialReclaim(ctx, pool, cfg, logger)

	// Своя чеканка токенов (задача #897): ключница, подписывающий ключ и
	// подписант. Собирается ДО поверхностей, потому что от неё зависят обе —
	// выдача докер-токена и публикация нашей записи набора.
	signingKeystore, tokenSigner, err := buildTokenSigning(ctx, pool, cfg, logger)
	if err != nil {
		return fmt.Errorf("своя чеканка токенов: %w", err)
	}
	startSigningKeySweeper(ctx, signingKeystore, logger)

	// Фоновая уборка таблиц, чей рост задаёт внешний (задача #1292). Три
	// предмета обслуживает ОДНА петля: три расписания об одном предмете
	// разошлись бы молча.
	if err := startRetentionSweeper(ctx, pool, cfg, metricsReg, logger); err != nil {
		return err
	}

	svcs := buildServices(pool, slavePool, opsRepo, kachoRepo, kachoRepo, metricsReg, cfg, tokenSigner, logger)

	// gRPC servers. PrincipalExtract-interceptor читает
	// x-kacho-principal-* metadata-headers, которые api-gateway auth-interceptor
	// прокидывает после JWT-валидации, и кладет в ctx через operations.WithPrincipal.
	// Use-case'ы вызывают operations.NewFromContext(ctx, ...) → реальный principal
	// попадает в operations.principal_*.
	productionMode := cfg.AuthN.Mode.IsProduction()
	// SEC-H (corelib SEC-B): per-listener opt-in server-side mTLS creds.
	// enable=false (default) → insecure (dev backward-compat, Сценарий
	// SEC-H-01); enable=true → RequireAndVerifyClientCert (server-cert +
	// client-CA), fail-closed на отсутствующем/мусорном cert-trio (no silent
	// insecure downgrade, Сценарий SEC-H-02). Public и internal listener —
	// два независимых per-edge ребра. Загружается отдельным envconfig-
	// loader'ом из KACHO_IAM_{PUBLIC,INTERNAL}_SERVER_MTLS_* (mirror vpc).
	mtlsCfg, err := config.LoadMTLS()
	if err != nil {
		return fmt.Errorf("load server mTLS config: %w", err)
	}
	publicServerCreds, err := mtlsCfg.PublicServerCreds()
	if err != nil {
		return fmt.Errorf("public listener mTLS creds: %w", err)
	}
	internalServerCreds, err := mtlsCfg.InternalServerCreds()
	if err != nil {
		return fmt.Errorf("internal listener mTLS creds: %w", err)
	}

	// HTTP-listener server-side TLS: the Hydra/Kratos hooks
	// listener (:9092) and the Prometheus /metrics listener (:9095) were
	// PLAINTEXT. Per-edge, default-off TLS (mirror SEC-H grpcsrv.TLSServer):
	// enable=false → nil *tls.Config → net.Listener stays plaintext
	// (byte-identical to today, dev/newman stand unchanged); enable=true →
	// per-edge clientAuthMode, объявленный полем TLS профиля поверхности
	// (server-tls-only = encryption
	// only, the default for both the HMAC-authed hooks edge and the no-scrape-cert
	// metrics edge; mutual = RequireAndVerifyClientCert). mtlsCfg.Validate()
	// fail-closes at boot if ANY edge is enabled with an incomplete cert-set for
	// its mode, or with an unknown clientAuthMode.
	if verr := mtlsCfg.Validate(); verr != nil {
		return fmt.Errorf("listener mTLS config invalid: %w", verr)
	}
	hooksTLSConfig, err := mtlsCfg.HooksServerTLSConfig()
	if err != nil {
		return fmt.Errorf("hooks listener mTLS config: %w", err)
	}
	metricsTLSConfig, err := mtlsCfg.MetricsServerTLSConfig()
	if err != nil {
		return fmt.Errorf("metrics listener mTLS config: %w", err)
	}
	// jwks-proxy listener server-TLS: ONE-WAY (server-tls-only by default —
	// registry-verifier presents only server-trust, never a client-cert; mutual
	// would break the verifier's "untouched" property). Default-off → nil → the
	// listener stays plaintext (dev byte-identical).
	jwksProxyTLSConfig, err := mtlsCfg.JWKSProxyServerTLSConfig()
	if err != nil {
		return fmt.Errorf("jwks-proxy listener mTLS config: %w", err)
	}
	// docker-token listener (:9096) server-TLS: ONE-WAY. По нему едет HTTP Basic,
	// чей пароль — приватный ключ ключа служебной учётки (сервер его не хранит,
	// срок жизни не ограничен), поэтому в production plaintext здесь запрещён —
	// requireRegistryTokenTLS ниже.
	registryTokenTLSConfig, err := mtlsCfg.RegistryTokenServerTLSConfig()
	if err != nil {
		return fmt.Errorf("registry-token listener mTLS config: %w", err)
	}

	// M1 — startup invariant: production mode MUST run the cluster-internal
	// listener (:9091) under mTLS RequireAndVerifyClientCert. Without it the
	// per-RPC caller policy has no verified module SAN to enforce — anyone
	// reaching :9091 would bypass authN/authZ. No silent insecure downgrade in
	// production. (Mirror this requirement on the public listener too —
	// tenant-facing :9090 must not run plaintext in prod.)
	if productionMode {
		if !mtlsCfg.InternalServerMTLS.Enable {
			return fmt.Errorf("production mode requires internal listener mTLS (RequireAndVerifyClientCert); refusing to start with insecure :9091")
		}
		if !mtlsCfg.PublicServerMTLS.Enable {
			return fmt.Errorf("production mode requires public listener mTLS (TLS); refusing to start with insecure :9090")
		}
	}
	if err := requireRegistryTokenTLS(productionMode,
		cfg.APIServer.RegistryToken.ListenAddress(), mtlsCfg); err != nil {
		return err
	}

	// Самоотчёт о security-posture: ПОСЛЕ boot-guard'ов (cfg.Validate() в main,
	// mtlsCfg.Validate() и production-гейт обоих gRPC-листенеров выше — конфиг
	// уже ПРИНЯТ процессом) и ДО подъёма листенеров. authz_check — факт проводки
	// PDP-бэкенда (iam гейтит свои RPC внутренними floor'ами поверх relation-store,
	// а не чужим Check). Production-posture гейт обязан утверждать на этом
	// наблюдаемом факте, а не на хранимом конфиге (см. observability.BootPosture).
	// Половина ПОЛНОТЫ ПРОВЯЗКИ у полосности посадки личности (задача #1125).
	// Стоит ЗДЕСЬ, а не в config.Validate(): настройка собранных объектов не
	// видит и выразить их отсутствие не может. Отказ — отдельный текст, и он
	// НЕ заменяется посадочной проверкой.
	//
	// Перепись печатается и на успешном старте: «ноль недостижимых записей»
	// обязано быть отличимо от «каталог не читали».
	laneWiring := observeLaneWiring(ctx, tokenSigner, logger)
	logger.Info("identity posture lane wiring", laneWiringCensus(laneWiring)...)
	if err := config.ValidateLaneWiring(cfg, laneWiring); err != nil {
		return fmt.Errorf("identity posture lane: %w", err)
	}

	observability.LogBootPosture(logger,
		bootPosture(posture, cfg, mtlsCfg, svcs.ownGates.FormReachable()))

	// Per-RPC CALLER policy for the internal listener (audit C1/C3/H3/M1). iam
	// does NOT re-ReBAC the end user here — the api-gateway is the platform's
	// single authZ front door (it validates the JWT and runs per-user ReBAC via
	// iam.Check). :9091 enforces only WHO MAY CALL each RPC:
	//   - Floor: every internal RPC requires a verified mTLS module cert (prod
	//     fail-closed; dev no-op, mirror RelationWriteGate).
	//   - Gateway-only: the gateway-fronted privileged admin RPCs
	//     (GatewayFrontedInternalRPCs) may ONLY be called by the api-gateway SA;
	//     a direct call from any other module → DENY in prod (closes C1/C3 — a
	//     compromised data-plane module cannot escalate via :9091).
	//   - SAN-restricted: MintBootstrapToken (SANRestrictedInternalRPCs) admits ONLY
	//     the client-certificate SPIFFE SANs an operator listed in
	//     authn.bootstrap-mint.allowed-client-sans — enforced in EVERY mode, and an
	//     empty list denies everyone (the cluster-admin mint has no default caller;
	//     it is also unreachable via the api-gateway, which carries no REST route
	//     for it). Config.Validate additionally refuses to boot a production binary
	//     whose mint is enabled with an empty list.
	// The fga-proxy writes (Register/Unregister) are NOT in the
	// gateway-only set and stay gated in-handler by RelationWriteGate (fga_writer)
	// — their callers are vpc/compute/nlb module SAs, not the gateway.
	internalCallerPolicy := authzguard.NewCallerPolicy(productionMode, authzguard.GatewayFrontedInternalRPCs()).
		WithSANAllowlist(map[string][]string{
			authzguard.BootstrapMintFullMethod: cfg.AuthN.BootstrapMint.AllowedSANs(),
		})

	// Per-RPC `system_viewer`-FLOOR on the internal READ-RPC set
	// (authN+authZ enforced everywhere: read-RPC gate viewer-tier). For
	// ReadFloorRPCs it requires the CALLER MODULE-SA (derived from the verified
	// mTLS SAN, same derivation as the fga-proxy gate) to hold the coarse cluster
	// relation `system_viewer@cluster:cluster_kacho_root`, via the SAME
	// RelationChecker port (the decision door) used by RelationWriteGate / iam.Check.
	// Default-OFF: dev/newman (prod=false) → NO-OP pass-through (newman stand
	// byte-identical). Prod fail-closed: no verified SAN → PermissionDenied;
	// FGA backend error → Unavailable. EXEMPT (NOT in ReadFloorRPCs): the PDP
	// Check (INV-FLOOR-5), secret-authed OnRecoveryCompleted + hot-path IsRevoked
	// (INV-FLOOR-6), and all mutations (fga_writer / system_admin / gateway-only;
	// INV-FLOOR-8). Chained AFTER internalCallerPolicy, mirroring its prod-mode
	// gating. The legitimate reader SAs — api-gateway, vpc and compute, and those
	// three only — are seeded system_viewer@cluster by migration 0014. The network
	// operator held one too, from SEC-L 0010; migration 0081 revoked it together
	// with the identity, so exactly three subjects can pass this floor.
	//
	// Порт получает `svcs.ownGates`, а НЕ голый транспорт. Здесь долго стоял
	// транспорт, и это давало ровно тот класс, который под-фаза закрывает:
	// решение о доступе на каждом читающем RPC внутреннего слушателя уходило
	// движку мимо второго шанса и мимо сравнения форм. Страж при этом
	// присутствовал, был провязан и исполнялся — снаружи неотличимо от
	// исправного.
	internalSystemViewerFloor := authzguard.NewSystemViewerFloor(svcs.ownGates, authzguard.ReadFloorRPCs()).
		WithProductionMode(productionMode)

	// Per-RPC `required_acr_min` (step-up) FLOOR on the internal
	// listener for the GATEWAY-FRONTED privileged RPCs (authN+authZ enforced
	// everywhere; "Internal = trusted, mTLS достаточно" is a FORBIDDEN assumption).
	// `required_acr_min` is enforced on the public path (gateway StepUpGate) but
	// the gateway DROPS the acr on the :9091 re-dial — so a gateway-fronted RPC
	// with acr_min>0 (InternalClusterService/{Get,GrantAdmin,RevokeAdmin,
	// ListAdmins} already carry acr_min=2) is not acr-enforced internally. This
	// floor closes that arm: for each gateway-fronted RPC whose catalog acr_min>0
	// it enforces `acr >= acr_min` (the SAME grpcsrv.ACRSatisfies ranking the
	// gateway uses), reading the acr from the FD-4-trusted ctx (forwarded only on
	// the mTLS-verified gateway→iam edge). Service-caller module SAs (vpc/compute
	// fgaproxy) are acr-EXEMPT (not user principals) — and internalCallerPolicy
	// already DENIES a non-gateway SAN on a gateway-fronted RPC BEFORE this floor,
	// so the exemption cannot be abused (5.4-06). Default-OFF: dev/newman
	// (prod=false) → NO-OP pass-through (newman stand byte-identical, 5.4-07).
	// Fail-closed in prod: absent/insufficient/untrusted acr on an acr-requiring
	// RPC → PermissionDenied with an RFC-9470 step-up signal in the status
	// details. FQN→acr_min comes from the embedded permission catalog. Chained
	// AFTER UnaryTrustedPrincipalExtract (sets acr) + internalCallerPolicy.
	permRegistry, err := seed.LoadPermissionRegistry(ctx, logger)
	if err != nil {
		return fmt.Errorf("load permission catalog (acr-floor): %w", err)
	}
	internalACRFloor := authzguard.NewACRFloor(permRegistry, authzguard.GatewayFrontedInternalRPCs()).
		WithProductionMode(productionMode)

	// Per-RPC CALLER policy for the PUBLIC listener (:9090) — the sibling of
	// internalCallerPolicy above, and for the same reason: iam does NOT re-ReBAC
	// the end user on its own listeners (the api-gateway is the single authZ front
	// door), so whoever reaches a public RPC with a forwarded identity acts with
	// that identity's authority. :9090 is NOT gateway-only — five consumer modules
	// dial ProjectService.Get on their request path and the namespace operator fans
	// out over AccountService.List → ProjectService.List — but they need exactly
	// those reads and nothing else. The policy admits the gateway everywhere and
	// every other verified module only on the RPC that names it
	// (PublicPeerCallableRPCs), so a compromised neighbour cannot reach the tenant
	// CRUD, the grant writes or the credential mints at all. prod fail-closed; dev
	// no-op (the newman stand has no mTLS, hence no verified certificate to decide
	// on). This is the second half of the narrowing: the forwarder allow-list below
	// decides WHO MAY SPEAK FOR A USER, this decides ON WHICH RPC.
	publicCallerPolicy := authzguard.NewPublicCallerPolicy(productionMode, authzguard.PublicPeerCallableRPCs())

	// Измеритель задержки — ОДИН на процесс, полос у него две.
	//
	// Тот же измеритель, что носитель входящего пути ставит остальным шести
	// сервисам: ряды iam ложатся в общее семейство платформы, и вопрос «где во
	// всей платформе вырос хвост» остаётся одним запросом. Слушателей iam строит
	// сам, минуя носитель, поэтому провязать измеритель обязан здесь — отказ
	// старта О13 сюда не достаёт.
	//
	// Две полосы: `OperationService` и пара `Internal*` служатся обоими
	// слушателями, и слитый ряд был бы средним двух разных величин — публичный
	// вызов приходит от арендатора через край, внутренний от соседнего модуля по
	// mTLS.
	//
	// Отказ регистрации — отказ подъёма, а не предупреждение: он означает
	// несогласованное объявление серии, и поднять процесс значило бы отдать ему
	// диагностическую поверхность без семейства, которого на ней не будет никогда.
	latency, err := grpcsrv.NewServerLatency(metricsReg.Registerer())
	if err != nil {
		return fmt.Errorf("измеритель задержки обслуженного вызова: %w", err)
	}

	// Anti-anonymous guard перед мутирующими RPC: минимальная защита от
	// анонимного создания Account/Project/AccessBinding/Group/SA/Role
	// в дополнение к вопросу о доступе через AuthorizeService.
	//
	// Порядок: измеритель задержки (оборачивает всё) → recovery → личность вызывающего
	// (identityUnary: сертификат, затем переданная личность от разрешённого
	// отправителя) → пер-RPC политика вызывающего → анти-аноним.
	publicUnary := append([]grpc.UnaryServerInterceptor{
		// Измеритель задержки первым — он оборачивает цепочку целиком, поэтому
		// длительность и код накрывают ВЕСЬ вызов, включая вопрос о доступе.
		// Стоя внутри решения о доступе, он оставил бы неизмеренным каждый отказ
		// по правам — то есть исход, ради которого метрику и смотрят.
		latency.UnaryServerInterceptor(grpcsrv.ListenerPublic),
		// Panic-recovery immediately inside metrics: a panic in any downstream
		// interceptor or handler becomes a logged codes.Internal for that ONE
		// request instead of crashing the whole PDP process (metrics still
		// records the Internal code because recovery is inner of it).
		grpcsrv.UnaryPanicRecovery(logger),
		// Outermost of the authz interceptors so it sees the refusal produced by
		// ANY of them and by the handler: attaches the machine-readable reason a
		// client keys on. It matters most where iam decides authorization itself
		// over the data (scope-filtered rows) — there the edge runs no per-RPC
		// check, so nothing else on the path names the action, and a refusal by
		// scope was byte-identical to a catalog miss. See deny_details.go.
		authzguard.DenyDetailUnary(permRegistry),
	}, identityUnary(cfg)...)
	publicUnary = append(publicUnary,
		publicCallerPolicy.Unary(),
		authzguard.AntiAnonymousUnary(logger),
	)
	publicStream := append([]grpc.StreamServerInterceptor{
		// Срок жизни подписки — своя серия и своя сетка корзин: это другая
		// величина, и общая с задержкой вызова не разрешала бы ни ту, ни другую.
		latency.StreamServerInterceptor(grpcsrv.ListenerPublic),
		grpcsrv.StreamPanicRecovery(logger),
	}, identityStream(cfg)...)
	publicStream = append(publicStream,
		publicCallerPolicy.Stream(),
		authzguard.AntiAnonymousStream(logger),
	)
	grpcSrv := grpcsrv.NewServer(
		publicServerCreds,
		grpc.ChainUnaryInterceptor(publicUnary...),
		grpc.ChainStreamInterceptor(publicStream...),
	)
	// Internal listener (port 9091) — network-segregated, but NOT trusted:
	// authN+authZ are enforced on EVERY internal RPC (security.md "authN+authZ
	// everywhere"; closes audit C1/C3/H3/M1).
	//
	// Interceptor chain order (each runs before the next):
	//  1. UnaryCertIdentityExtract — verified mTLS client-cert SAN (module
	//     identity) → ctx; insecure listener (dev) → no-op.
	//  2. UnaryTrustedPrincipalExtract — x-kacho-principal-* metadata → ctx, but
	//     trust-gated on the FD-4 invariant AND on the forwarder allow-list: the
	//     forwarded end-user principal is exposed downstream
	//     (operations.principal_* / audit / granted_by) ONLY when step 1 proved the
	//     peer mTLS-verified AND its certificate identity is one the operator
	//     listed in authn.trusted-forwarder-sans. On any other peer the metadata is
	//     DROPPED (carrier falls back to SystemPrincipal) so neither a cert-less
	//     caller nor a neighbouring module with its own legitimate certificate can
	//     FORGE the audit principal (anti-spoof). On the insecure dev listener it
	//     stays accepted (backward-compat). NOT trusted for authZ — the gateway
	//     already did per-user authZ. MUST run after UnaryCertIdentityExtract.
	//  3. internalCallerPolicy — per-RPC caller policy: floor (verified module
	//     cert on EVERY RPC) + gateway-only (privileged admin RPCs only from the
	//     api-gateway SA) — prod fail-closed, dev no-op — PLUS the SAN-restricted
	//     arm for the cluster-admin token mint, which admits only the explicitly
	//     allow-listed client-certificate SPIFFE SANs and is enforced in EVERY
	//     mode (an empty list denies everyone).
	//  4. internalSystemViewerFloor — per-RPC `system_viewer`-floor
	//     on the READ-RPC set (ReadFloorRPCs): the caller module-SA must hold
	//     `system_viewer@cluster:cluster_kacho_root` (relation-tier Check beyond
	//     the coarse mTLS floor above). Prod fail-closed (PermissionDenied /
	//     Unavailable); dev no-op. Exempt: PDP Check, secret webhooks, hot-path
	//     IsRevoked, all mutations. MUST run after internalCallerPolicy (it needs
	//     the same verified-SAN floor to have passed).
	//  5. internalACRFloor — per-RPC `required_acr_min` (step-up)
	//     floor on the GATEWAY-FRONTED set: for a gateway-fronted RPC whose catalog
	//     acr_min>0, the FD-4-trusted forwarded acr must satisfy it (else
	//     PermissionDenied + step-up signal). Module-SA callers / non-gateway RPCs
	//     are acr-exempt. Prod fail-closed; dev no-op. MUST run after
	//     UnaryTrustedPrincipalExtract (sets acr) + internalCallerPolicy (which
	//     denies a non-gateway SAN on a gateway-fronted RPC first, so the SA
	//     exemption cannot be abused).
	internalUnary := append([]grpc.UnaryServerInterceptor{
		// Измеритель задержки первым — здесь живёт горячий путь пер-RPC гейта
		// прав (`InternalIAMService.Check`), и его задержка есть задержка КАЖДОГО
		// вызова всей платформы: она входит слагаемым в чужие хвосты, поэтому
		// собственный ряд у неё обязан быть.
		latency.UnaryServerInterceptor(grpcsrv.ListenerInternal),
		// Panic-recovery immediately inside metrics — same rationale as the
		// public chain: a handler/interceptor panic on the PDP hot path must
		// not crash the process (fail-closed cluster-wide); it degrades to a
		// logged codes.Internal for that one request.
		grpcsrv.UnaryPanicRecovery(logger),
		// Same reason as on the public chain, and on the same terms: a refusal
		// this listener produces carries the machine-readable reason too, so a
		// client does not have to know which listener (or which layer) said no.
		// It appends — the step-up PreconditionFailure raised by the acr floor
		// below survives untouched. See deny_details.go.
		authzguard.DenyDetailUnary(permRegistry),
	}, identityUnary(cfg)...)
	internalUnary = append(internalUnary,
		internalCallerPolicy.Unary(),
		internalSystemViewerFloor.Unary(),
		internalACRFloor.Unary(),
	)
	internalStream := append([]grpc.StreamServerInterceptor{
		latency.StreamServerInterceptor(grpcsrv.ListenerInternal),
		grpcsrv.StreamPanicRecovery(logger),
	}, identityStream(cfg)...)
	internalStream = append(internalStream,
		internalCallerPolicy.Stream(),
		internalSystemViewerFloor.Stream(),
		internalACRFloor.Stream(),
	)
	internalSrv := grpcsrv.NewServer(
		internalServerCreds,
		grpc.ChainUnaryInterceptor(internalUnary...),
		grpc.ChainStreamInterceptor(internalStream...),
	)
	logger.Info("kacho-iam listener mTLS",
		"public_mtls", mtlsCfg.PublicServerMTLS.Enable,
		"internal_mtls", mtlsCfg.InternalServerMTLS.Enable,
		"hooks_mtls", mtlsCfg.HooksServerMTLS.Enable,
		"metrics_mtls", mtlsCfg.MetricsServerMTLS.Enable,
		"jwks_proxy_mtls", mtlsCfg.JWKSProxyServerMTLS.Enable)
	// Потолок темпа и одновременности НА ВЫЗЫВАЮЩЕГО. Регистрация идёт ЧЕРЕЗ
	// обёртку ограничителя: он получает дескриптор службы целиком и подставляет
	// допуск МЕЖДУ цепочкой звеньев и обработчиком — то есть ПОСЛЕ того, как
	// личность вызывающего установлена. Забыть метод здесь не на чем: перечня
	// методов у вызывающего нет.
	//
	// Служебные поверхности (здоровье, отражение) регистрирует конструктор
	// сервера ДО обёртки и под предел не попадают намеренно: отказ проверке
	// готовности означал бы перезапуск пода из-за нагрузки на API.
	publicAdmissionLimits, internalAdmissionLimits, err := admissionLimits(cfg)
	if err != nil {
		return err
	}
	// Ключи у слушателей РАЗНЫЕ, и это не деталь: публичный ключуется личностью
	// конечного пользователя (за краем сидит арендатор, и предел объявлен на
	// него), внутренний — личностью СЕРТИФИКАТА вызывающего модуля, потому что
	// запрос модуля несёт личности разных арендаторов и ключ по арендатору
	// дробил бы бюджет соседа на тысячу вёдер.
	publicAdmission, err := grpcsrv.NewAdmission("public", publicAdmissionLimits, grpcsrv.PrincipalSubject)
	if err != nil {
		return fmt.Errorf("ограничитель допуска публичного слушателя: %w", err)
	}
	internalAdmission, err := grpcsrv.NewAdmission("internal", internalAdmissionLimits, grpcsrv.CertIdentitySubject)
	if err != nil {
		return fmt.Errorf("ограничитель допуска внутреннего слушателя: %w", err)
	}
	admission := listenerAdmission{public: publicAdmission, internal: internalAdmission}
	admission.arm(logger, cfg)

	registerPublicServices(publicAdmission.Registrar(grpcSrv), svcs, opsRepo)
	registerInternalServices(internalAdmission.Registrar(internalSrv), svcs, pool, cfg.MigrateDSN(), logger)

	publicAddr := cfg.APIServer.ListenAddress()
	internalAddr := cfg.APIServer.InternalListenAddress()
	listener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", internalAddr)
	if err != nil {
		_ = listener.Close()
		return err
	}

	// ── НЕ-gRPC ПОВЕРХНОСТИ: четыре профиля ТОЙ ЖЕ функции ──────────────────
	//
	// Решение владельца (XC-7, в-1): не-gRPC слушатели входят в контур ОТДЕЛЬНЫМ
	// профилем, а не полями общего дескриптора. У iam их четыре, и предметы у них
	// РАЗНЫЕ — приём вебхуков провайдера личности, выдача docker-токена, зеркало
	// публичных ключей проверки, скрейп. Профиль их не смешивает: разницу несут
	// значения двух осей — откуда поверхность досягаема и чем аутентифицирует, — и
	// именно их пара судится (снаружи досягаемая поверхность с объявленным
	// ОТСУТСТВИЕМ аутентификации не поднимается вовсе).
	//
	// Что ушло вместе с ручной сборкой: каскад закрытий уже привязанных
	// слушателей на каждом последующем отказе (пять вложенных лестниц, из которых
	// одна теряла слушатель скрейпа), четыре одинаковых блока гашения в общем
	// триггере и четыре набора одних и тех же сроков, выписанных по месту.
	surfaceMode, merr := servicecontract.ParseMode(cfg.AuthN.Mode.String())
	if merr != nil {
		return fmt.Errorf("посадка процесса для профиля поверхностей: %w", merr)
	}

	// Контекст ЧЕТЫРЁХ поверхностей. Отдельный от корневого: гасить их надо по
	// общему триггеру остановки, который срабатывает и от сигнала, и от краха
	// любого из двух gRPC-слушателей.
	surfaceCtx, stopSurfaces := context.WithCancel(context.Background())
	defer stopSurfaces()

	// (1) Приём вебхуков провайдера личности (Hydra token/refresh, Kratos
	// provision). Cluster-internal-only (запрет #6), отдельный порт от gRPC.
	hooksAddr := cfg.AuthN.HooksHTTPListenAddress()
	// Носитель готовности отдаётся сюда, чтобы гашение переводило `/readyz` в
	// 503 ДО остановки серверов (см. triggerShutdown ниже). Без этого носитель
	// был бы, а дёрнуть его было бы некому (#1752).
	hooksHandler, hooksHealth := buildHooksMux(pool, kachoRepo, opsRepo, svcs.ownGates, metricsReg, cfg, logger)
	hooksSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "вебхуки провайдера личности",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(hooksAddr, "KACHO_IAM_HOOKS_HTTP_ADDR не задан профилем развёртывания: обогащение токена и заведение пользователя по первому входу на этой посадке не обслуживаются"),
		Handler: hooksHandler,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.Value[servicecontract.SurfaceAuthMech](
			"общий секрет провайдера, проверяется обработчиком на каждом запросе"),
		TLS: hooksTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности вебхуков: %w", err)
	}

	// (2) Скрейп. Никогда не публичная gRPC-поверхность: внутренняя
	// кардинальность туда не выносится (security.md).
	metricsAddr := cfg.APIServer.MetricsListenAddress()
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metricsReg.Handler())
	metricsSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "диагностика (/metrics)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(metricsAddr, "KACHO_IAM_METRICS_ADDR не задан профилем развёртывания: скрейпа на этой посадке нет"),
		Handler: metricsMux,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"снята осознанно: поверхность выставлена только на внутренний Service и несёт " +
				"счётчики процесса — ни секретов, ни данных арендатора на проводе нет"),
		TLS: metricsTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности диагностики: %w", err)
	}

	// (3) Выдача docker-токена (`/iam/token`, Registry v2 auth-server).
	//
	// Единственная ВНЕШНЕ досягаемая поверхность iam: `docker login` приходит
	// через вход кластера. Её аутентификация — предъявление БАЗОВОГО ТОКЕНА
	// ДОСТУПА (#1142), от которого сервер хранит только свёртку. Ключевой
	// материал в поле пароля снят задачей #1143 и принимается лишь пока открыто
	// объявленное оператором окно перехода (ручка ниже).
	registryTokenAddr := cfg.APIServer.RegistryToken.ListenAddress()
	// Мгновение окна перехода берётся у настройки РАЗОБРАННЫМ. Неразборчивое
	// значение сюда не доходит: его отвергает страж старта
	// `RegistryTokenConfig.Validate` — его зовёт `config.Config.Validate`, а её,
	// в свою очередь, `main` ДО `runServe`, и на её отказе процесс выходит
	// кодом 1. Отказ ниже поэтому недостижим на живой посадке и стоит здесь
	// затем, чтобы значение не оказалось использовано неразобранным, если
	// когда-нибудь эту функцию позовут в обход `main`.
	registryTokenKeyMaterialWindow, kmwErr := cfg.APIServer.RegistryToken.KeyMaterialWindowUntil()
	if kmwErr != nil {
		return fmt.Errorf("registry token shim: %w", kmwErr)
	}
	if !registryTokenKeyMaterialWindow.IsZero() {
		// Открытое окно — ОСЛАБЛЕНИЕ ПОСАДКИ, и оно обязано быть заметно в
		// самоотчёте процесса: посадка, о которой процесс молчит, отличима от
		// строгой только чтением настройки, а её при разборе инцидента читают
		// последней. Истёкшее окно называется тем же сообщением: ручка, которой
		// больше нечего открывать, — находка, а не норма.
		logger.Warn("docker token: key-material transition window is declared",
			"until", registryTokenKeyMaterialWindow.Format(time.RFC3339),
			"open_now", time.Now().Before(registryTokenKeyMaterialWindow),
			"knob", "api-server.registry-token.key-material-window-until",
			"effect", "the docker lane keeps accepting key material in the password field until that instant",
			"close_when", "kacho_iam_registry_token_credential_kind_total{outcome=\"key_material_accepted_in_window\"} stops growing")
	}
	var registryTokenHandler http.Handler
	if registryTokenAddr != "" {
		mux, berr := registrytokenwire.Build(pool, registrytokenwire.BuildConfig{
			Realm:             cfg.APIServer.RegistryToken.TokenIssuer(),
			Service:           cfg.APIServer.RegistryToken.TokenService(),
			HydraTokenURL:     cfg.AuthN.ResolveHydraTokenURL(),
			HydraTokenCAFile:  cfg.AuthN.ResolveHydraTokenCAFile(),
			AssertionAudience: cfg.AuthN.ResolveHydraTokenEndpoint(),
			Logger:            logger,
			// Приземление подписанта на НАСТОЯЩИЙ путь выдачи. Подписант без
			// производственного вызывающего — тот же класс, что хранилище без
			// читателя: он выглядит исправным, потому что его пробы зелены.
			Signer:   tokenSigner,
			TokenTTL: cfg.APIServer.RegistryToken.TokenTTL(),
			// ОКНО ПЕРЕХОДА ЛОМАЮЩЕГО ИЗМЕНЕНИЯ #1143 — уже РАЗОБРАННОЕ выше:
			// сборка полосы получает мгновение, а не строку, и своего разбора
			// не заводит. Второй разборщик того же значения разошёлся бы с
			// первым молча — и разошёлся бы именно там, где расхождение не
			// видно, потому что на годном входе оба отвечают одинаково.
			KeyMaterialWindowUntil: registryTokenKeyMaterialWindow,
			// Счётчик исходов провязывается БЕЗУСЛОВНО, а не вместе с окном:
			// он обязан считать и отказы прежнему виду, то есть работать именно
			// на посадке БЕЗ окна — иначе оператор, у которого обновление
			// сломало вход арендаторам, узнаёт об этом из жалобы.
			CredentialKindObserver: metricsReg.RegistryTokenCredentialKindRecorder(),
		})
		if berr != nil {
			return fmt.Errorf("registry token shim: %w", berr)
		}
		// Токен-эндпоинт платформы (задача #898) монтируется на ЭТУ ЖЕ
		// поверхность, а не заводит свою. Вид выдачи «учётные данные клиента»
		// задан формой запроса, а не нашим выбором порта; второй внешний
		// слушатель об одном предмете разошёлся бы с первым в периметре,
		// посадке TLS и профиле развёртывания — и разошёлся бы молча.
		//
		// Приземление, а не провязка на будущее: с этого места проверяющий
		// утверждение получает ПРОИЗВОДСТВЕННОГО вызывающего. Проверяющий без
		// него выглядит исправным ровно потому, что его пробы подают ему то,
		// что он умеет разобрать.
		clientTokenHandler, cterr := buildClientTokenEndpoint(pool, cfg, tokenSigner, logger)
		if cterr != nil {
			return fmt.Errorf("client token endpoint: %w", cterr)
		}
		if clientTokenHandler != nil {
			mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)
		}
		registryTokenHandler = mux
	}
	registryTokenSurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "выдача токенов (/iam/token, /iam/v1/token)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(registryTokenAddr, "KACHO_IAM_REGISTRY_TOKEN_ADDR не задан профилем развёртывания: docker login на этой посадке не обслуживается"),
		Handler: registryTokenHandler,
		Reach:   servicecontract.ReachExternal,
		Auth: servicecontract.Value[servicecontract.SurfaceAuthMech](
			"два вида предъявления, у каждого своя проверка на каждом запросе: подпись ключом " +
				"служебной учётки на пути docker-токена и подписанное утверждение клиента, " +
				"сверяемое открытым ключом из нашего реестра, на пути выдачи по учётным данным " +
				"клиента; второй выпускает НАШ подписант"),
		TLS: registryTokenTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности выдачи docker-токена: %w", err)
	}

	// jwksUpstreamTimeout — потолок ОДНОГО обращения зеркала к верхнему хопу.
	// Назван здесь потому, что клиент собирается в этом корне, а обработчику
	// обязана достаться ТА ЖЕ величина, с которой клиент построен: два места с
	// двумя числами — то, как они расходятся.
	const jwksUpstreamTimeout = 5 * time.Second

	// (4) Зеркало ПУБЛИЧНЫХ ключей проверки (`GET /.well-known/jwks.json`).
	//
	// Здесь аутентификация снята — и это ЗАДОКУМЕНТИРОВАННОЕ исключение, а не
	// упущение (security.md §AuthN+AuthZ ВЕЗДЕ): поверхность выставлена только на
	// внутренний Service, идёт по односторонней TLS и несёт исключительно
	// публичный материал. Профиль требует, чтобы это было СКАЗАНО — и говорит это
	// в журнале на каждом старте, а не только в чужом документе.
	//
	// Проверить обоснование можно по паре осей: снятие принято потому, что
	// досягаемость объявлена внутренней. Объяви кто-нибудь эту поверхность
	// внешней — старт бы отказал.
	jwksProxyAddr := cfg.APIServer.JWKSProxy.ListenAddress()
	var jwksProxyHandler http.Handler
	if jwksProxyAddr != "" {
		// Клиент верхнего хопа собирается ЗДЕСЬ, а не внутри зеркала: якорь хопа —
		// настройка развёртывания, и непригодная обязана отказать в старте, а не
		// деградировать зеркало, от которого зависит вся плоскость данных.
		jwksUpstreamClient, jerr := clients.ProviderHopHTTPClient(
			jwksUpstreamTimeout, cfg.AuthN.ResolveHydraJWKSCAFile(), clients.JWKSHopCASetting)
		if jerr != nil {
			return fmt.Errorf("jwks-proxy upstream: %w", jerr)
		}
		// Зеркало собирается ИМЕНОВАННЫМ: построенное прямо в аргументе, оно
		// никому не отдаёт своих счётчиков, и «отказов не было» тогда неотличимо
		// от «сюда никто не приходил» — а это разница между работающим зеркалом и
		// мёртвой плоскостью данных.
		jwksMirror := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{
			UpstreamURL: cfg.AuthN.ResolveHydraJWKSURL(),
			Client:      jwksUpstreamClient,
			Timeout:     jwksUpstreamTimeout,
			Logger:      logger.With(slog.String("component", "jwks_proxy")),
		})
		// Читатель счётчиков зеркала. Выданные считаются наравне с отказами
		// (security.md §Hardening-инвариант 8), а причина отказа держится отдельно:
		// «не ответил» проходит со временем, «по адресу не то» — никогда.
		// Свойство «читатель есть» держит гейт по дереву
		// TestDeclaredAccumulatorsHaveANonTestReader.
		metricsReg.NewJWKSMirrorCollector(func() metrics.JWKSMirrorCounts {
			stats := jwksMirror.Stats()
			return metrics.JWKSMirrorCounts{
				Served:        stats.Served,
				Unavailable:   stats.Unavailable,
				Misconfigured: stats.Misconfigured,
			}
		})
		// (4а) НАША запись публикуемого набора — проекция ключницы.
		//
		// Записей у публикатора теперь ДВЕ, и у каждой свой ОБЪЯВЛЕННЫЙ путь.
		// Объединять наборы в один документ было бы дешевле и уничтожило бы
		// ровно ту защиту, ради которой развязка заводится: ключ одного
		// издателя проверял бы токен, объявляющий другого.
		//
		// Запись зеркала остаётся на своём прежнем пути ДО последней фазы: её
		// адрес объявлен у каждого сегодняшнего потребителя, и перенос сменил
		// бы его у всех разом — цена, которой эта фаза не предусматривала.
		records := []jwksproxyhttp.Record{{
			Issuer:  cfg.AuthN.ResolveHydraIssuer(),
			Path:    jwksproxyhttp.WellKnownJWKSPath,
			Handler: jwksMirror,
		}}
		if signingKeystore != nil {
			ourKeySet := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
				Source: signingKeystore,
				Logger: logger.With(slog.String("component", "jwks_own_keyset")),
			})
			// Читатели величин. Выданные считаются наравне с отказами: пока
			// наружу выходят одни отказы, ноль в них отвечает сразу на два
			// вопроса — «отказов не было» и «сюда никто не приходил».
			metricsReg.NewOwnKeySetCollector(func() metrics.OwnKeySetCounts {
				st := ourKeySet.Stats()
				return metrics.OwnKeySetCounts{Served: st.Served, Unavailable: st.Unavailable, Empty: st.Empty}
			})
			metricsReg.NewSigningKeyCollector(func() metrics.SigningKeyCounts {
				st := signingKeystore.Stats()
				return metrics.SigningKeyCounts{
					Generated: st.Generated, Activated: st.Activated, Retired: st.Retired,
					Removed: st.Removed, Compromised: st.Compromised, Failures: st.Failures,
				}
			})
			records = append(records, jwksproxyhttp.Record{
				Issuer:  cfg.AuthN.TokenSigning.Issuer,
				Path:    cfg.AuthN.TokenSigning.ResolveKeySetPath(),
				Handler: ourKeySet,
			})
		}
		binding, berr := jwksproxyhttp.NewBinding(records)
		if berr != nil {
			// Издатель, объявленный принимаемым, но не имеющий записи
			// источника, — ОТКАЗ В СТАРТЕ, а не молчаливый перебор записей и
			// не путь, выведенный из самого издателя.
			return fmt.Errorf("привязка «издатель → источник набора»: %w", berr)
		}
		jwksMux, merr := jwksproxyhttp.NewMux(binding)
		if merr != nil {
			return fmt.Errorf("маршруты публикации набора: %w", merr)
		}
		// (4б) Авторитет отзыва НАШИХ токенов — на том же внутреннем
		// слушателе. Отзыв, который читается только на выдаче, отзывом не
		// является: предъявленное продолжало бы проходить до истечения срока,
		// и это состояние не сходится само.
		if signingKeystore != nil {
			// Обоснование снятия authN, выданное НАБОРУ КЛЮЧЕЙ, на эту
			// поверхность НЕ распространяется: там на проводе только
			// публичный материал, здесь — предъявленный токен. Слушатель,
			// который сертификата даже не запрашивает, оставил бы авторитету
			// нечем отказать, поэтому такой стенд не поднимается вовсе.
			if !mtlsCfg.JWKSProxyVerifiesCaller() {
				return fmt.Errorf(
					"авторитет отзыва не может быть выставлен на слушателе, который не запрашивает " +
						"клиентский сертификат: задайте KACHO_IAM_JWKSPROXY_SERVER_MTLS_CLIENTAUTHMODE=optional-mutual " +
						"(набор проверочных ключей при этом остаётся доступен без сертификата) " +
						"либо выключите свою чеканку authn.token-signing.enabled")
			}
			introspect := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
				Issuer:            cfg.AuthN.TokenSigning.Issuer,
				Keys:              signingKeystore,
				Revocations:       kachopg.NewMintedTokenRevocationRepo(pool),
				Logger:            logger.With(slog.String("component", "token_introspection")),
				RequireClientCert: true,
			})
			metricsReg.NewTokenIntrospectionCollector(func() metrics.IntrospectCounts {
				st := introspect.Stats()
				return metrics.IntrospectCounts{
					Active: st.Active, Inactive: st.Inactive, Unavailable: st.Unavailable,
				}
			})
			jwksMux.Handle(tokenintrospecthttp.IntrospectPath, introspect)
		}
		jwksProxyHandler = jwksMux
	}
	jwksProxySurface, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "зеркало публичных ключей проверки (/.well-known/jwks.json)",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis(jwksProxyAddr, "KACHO_IAM_JWKS_PROXY_ADDR не задан профилем развёртывания: плоскости данных реестра неоткуда взять ключи проверки, и её верификация останется закрытой"),
		Handler: jwksProxyHandler,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"снята ОСОЗНАННО и задокументированно (security.md §AuthN+AuthZ ВЕЗДЕ): внутренний " +
				"Service, односторонняя TLS, на проводе только публичный материал проверки " +
				"подписи — ни секретов, ни данных арендатора"),
		TLS: jwksProxyTLSConfig,
	})
	if err != nil {
		return fmt.Errorf("профиль поверхности зеркала ключей: %w", err)
	}

	httpSurfaces := []servicecontract.SurfaceDescriptor{
		hooksSurface, metricsSurface, registryTokenSurface, jwksProxySurface,
	}

	// Про четыре не-gRPC поверхности здесь больше не сообщается: о себе
	// докладывает каждая сама при подъёме, и доклад несёт то, чего эта строка не
	// несла никогда, — откуда поверхность досягаема и чем аутентифицирует.
	logger.Info("kacho-iam listening",
		"public_endpoint", publicAddr,
		"internal_endpoint", internalAddr)

	gracefulTimeout := cfg.APIServer.GracefulShutdown
	if gracefulTimeout <= 0 {
		gracefulTimeout = 10 * time.Second
	}

	// Enterprise SSO HTTP listeners (SCIM + SAML) are not part of this service;
	// identity federation flows exclusively through the Ory stack (Kratos/Hydra OIDC).

	// Параллельный запуск
	// public-сервера + internal-сервера + shutdown-waiter через
	// `parallel.ExecAbstract` (`github.com/H-BF/corlib/pkg/parallel`).
	// Failure-isolation: первая ошибка / SIGTERM / SIGINT триггерит
	// graceful-stop ОБОИХ серверов. sync.Once гарантирует, что параллельные
	// триггеры (SIGTERM пришел одновременно с crash internal'а) не сделают
	// двойной GracefulStop.
	// Собственная отмена счётчика допуска: он обязан вернуть управление и тогда,
	// когда гашение начал крах слушателя, а не сигнал. Общего контекста для
	// этого мало — он сигнальный.
	admissionCtx, stopAdmission := context.WithCancel(context.Background())
	defer stopAdmission()

	var shutdownOnce sync.Once
	triggerShutdown := func() {
		shutdownOnce.Do(func() {
			// ПЕРВЫМ делом — снять под из ротации: kubelet перестаёт слать
			// трафик ДО того, как серверы начнут отказывать. Порядок здесь и
			// есть предмет: флип после остановки не успевает ничего.
			hooksHealth.SetShuttingDown()
			stopAdmission()
			stopGRPCBounded(internalSrv, gracefulTimeout)
			stopGRPCBounded(grpcSrv, gracefulTimeout)
			// Четыре не-gRPC поверхности гасятся ОДНОЙ отменой их общего контекста.
			// Прежде здесь стояли четыре одинаковых блока со своим сроком в каждом,
			// и каждая новая поверхность требовала пятого — то есть место, где
			// поверхность забывают погасить, воспроизводилось при каждом добавлении.
			stopSurfaces()
		})
	}

	tasks := []func() error{
		// Счёт допущенных и отвергнутых по каждому слушателю. Печатается ВСЕГДА,
		// включая нули: «ноль отказов за всю жизнь контроля» обязано быть
		// заметно, иначе мёртвый ограничитель невидим.
		func() error {
			admission.report(admissionCtx, logger)
			return nil
		},
		// public gRPC server
		func() error {
			err := grpcSrv.Serve(listener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				triggerShutdown()
				return fmt.Errorf("public grpc server: %w", err)
			}
			return nil
		},
		// internal gRPC server (admin / kacho-only)
		func() error {
			err := internalSrv.Serve(internalListener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				logger.Error("internal grpc server stopped", "err", err)
				triggerShutdown()
				return fmt.Errorf("internal grpc server: %w", err)
			}
			return nil
		},
		// shutdown waiter: SIGTERM/SIGINT → graceful-stop обоих + дрейн LRO worker'ов.
		func() error {
			<-ctx.Done()
			triggerShutdown()
			drainCtx, cancelDrain := context.WithTimeout(context.Background(), 3*gracefulTimeout)
			defer cancelDrain()
			if err := operations.Wait(drainCtx); err != nil {
				logger.Warn("operations workers did not finish in time",
					"err", err, "active", operations.Active())
			}
			return nil
		},
	}

	// Четыре не-gRPC поверхности. Порты привязываются ЗДЕСЬ, до постановки задач:
	// занятый адрес есть ошибка посадки, и узнать о ней надо до того, как процесс
	// объявит себя поднявшимся. Прежде подъём целиком уезжал в задачу супервизора,
	// и отказ привязки становился кодом возврата процесса, успевшего сколько
	// угодно проработать.
	//
	// Ожидание ставится задачей ВСЕГДА, даже когда поверхность объявлена
	// выключенной: тогда оно сразу возвращается, а причина уже названа в журнале.
	// Условная постановка вернула бы то самое молчание, ради устранения которого
	// выключение стало объявлением.
	for _, surface := range httpSurfaces {
		wait, serr := servicehost.ServeSurface(surfaceCtx, surface)
		if serr != nil {
			stopSurfaces()
			return fmt.Errorf("поверхность %q: %w", surface.Spec().Name, serr)
		}
		tasks = append(tasks, func() error {
			if werr := wait(); werr != nil {
				logger.Error("не-gRPC поверхность остановлена с ошибкой",
					"surface", string(surface.Spec().Name), "err", werr)
				triggerShutdown()
				return fmt.Errorf("поверхность %q: %w", surface.Spec().Name, werr)
			}
			return nil
		})
	}
	// Enterprise SSO (SCIM + SAML) is not served by this listener set.

	// ДРЕНАЖА ЖУРНАЛА НАМЕРЕНИЙ ЗДЕСЬ НЕТ — снят вместе с адресатом.
	//
	// Он читал `kacho_iam.fga_outbox` и применял каждую строку к внешнему движку
	// отношений. Движка нет; журнал ОСТАЁТСЯ и остаётся не «на всякий случай»:
	// прямой факт, из которого форма собирает вердикт, складывается ИЗ ЭТОГО ЖУРНАЛА
	// триггером (миграция 0098). Снять журнал вместе с дренажом значило бы обесточить
	// источник собственного вердикта — и обесточить тихо: таблица осталась бы на
	// месте, запросы продолжили бы исполняться, а ответы поехали бы в сторону отказа.

	// ТОЛЧКА К КРАЮ ЗДЕСЬ НЕТ — направление развёрнуто (задача #1024).
	//
	// Здесь стоял дренаж `kacho_iam.subject_change_outbox`, который дозванивался до
	// края и гасил его кэш решений. Это было ребро ИЗ ЛИСТА ОБРАТНО К ПОТРЕБИТЕЛЮ:
	// iam объявлен листом графа рёбер — его зовут, он не зовёт никого, — а адрес края
	// был вдобавок ОБЯЗАТЕЛЬНОЙ ручкой, поэтому владелец прав не поднимался там, где
	// края нет вовсе. Именно это делало вынос iam отдельным продуктом невыразимым.
	//
	// Соединение открывает ПОТРЕБИТЕЛЬ: край сам читает журнал смены субъекта
	// курсором (`InternalIAMService.PollSubjectChanges`, провязано у края) и гасит
	// свой кэш сам. Владелец прав о крае больше не знает и знать ему нечем.
	//
	// ЖУРНАЛ ОСТАЁТСЯ и остаётся не «на всякий случай»: он и есть то, что читает
	// потребитель. Изменилась его природа — из очереди с доставкой он стал журналом
	// с курсором: выборка идёт по `id > $1`. Величин доставки у него больше НЕТ —
	// `sent_at`/`attempt_count`/`last_error`/`notified_at` сняты вместе с частичным
	// индексом по неотправленным строкам, после того как писателей не осталось
	// (миграция 20260829181500, задача #1396). Схема перестала обещать доставку,
	// которой нет, а не только перестала её выполнять.

	// Дренаж очереди компенсаций частично исполненной саги регистрации у
	// провайдера. Намерение записывается собственной транзакцией на неудачном
	// пути (компенсируемая транзакция откачена и нести его не может), а
	// исполняется ЗДЕСЬ — at-least-once, поэтому оно переживает и смерть
	// процесса, и недоступность самого провайдера.
	compensationDrainerTask, cerr := buildProviderCompensationDrainer(
		pool, cfg, metricsReg.CompensationRecorder(), logger)
	if cerr != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		return fmt.Errorf("provider compensation drainer wiring: %w", cerr)
	}
	tasks = append(tasks, func() (err error) {
		// Мёртвый дренаж не должен оставлять под тихо работающим: очередь без
		// исполнителя копит намерения, а занятое у провайдера не освобождается.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("provider compensation drainer panicked", "panic", r)
				err = fmt.Errorf("provider compensation drainer panic: %v", r)
			}
			if err != nil {
				triggerShutdown()
			}
		}()
		return compensationDrainerTask()
	})
	// Наблюдаемость очереди: глубина, возраст самой старой недоставленной
	// строки, число отравленных. Скан не мутирует таблицу и не может уронить
	// под — ошибки логируются.
	tasks = append(tasks, func() error {
		runProviderCompensationMetrics(ctx, pool, metricsReg.OutboxRecorder(), logger)
		return nil
	})
	// СКАНА ЖУРНАЛА СМЕНЫ СУБЪЕКТА ЗДЕСЬ НЕТ — у него больше нет предмета.
	//
	// Он мерил ДОСТАВКУ: возраст самой старой неотправленной строки и число
	// отравленных. Обе величины имеют смысл, только пока строки кто-то помечает
	// отправленными. С разворотом направления (задача #1024) таких не осталось:
	// потребитель читает журнал курсором. Колонки, по которым скан считал, сняты
	// следом (задача #1396) — теперь его нельзя не только осмыслить, но и написать.
	//
	// Оставленный скан отвечал бы РАСТУЩИМ возрастом на исправной службе — тревога,
	// которая звонит всегда, есть тревога, которую отключают первой. Ровно это уже
	// случилось у соседней очереди, и её разбор стоит абзацем выше в
	// `outbox_metrics_wiring.go`.
	// Журнал аудита: состояние очереди. Теперь у неё есть доставка (вывоз
	// ниже), поэтому величины сканера читаются как обычно: глубина падает,
	// возраст головы ограничен сверху. До появления приёмника они лишь делали
	// молчание слышимым — растущая глубина и стареющая голова были верным
	// описанием, а не сигналом сбоя.
	tasks = append(tasks, func() error {
		runAuditOutboxMetrics(ctx, pool, metricsReg.OutboxRecorder(), logger)
		return nil
	})
	// Журнал аудита: вывоз в приёмник. Строится ДО запуска задач, чтобы ошибка
	// сборки останавливала старт, а не всплывала фоном: журнал, который не
	// вывозится, снаружи неотличим от журнала, в котором нечего вывозить.
	auditShipper, err := buildAuditShipper(pool, metricsReg.OutboxRecorder(), logger)
	if err != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		return fmt.Errorf("audit shipper wiring: %w", err)
	}
	tasks = append(tasks, func() error {
		return auditShipper.Run(ctx)
	})
	// ВОЗВРАТА ОТРАВЛЕННЫХ СТРОК у журнала нет, и это следствие контракта
	// приёмника, а не упущение: класса «не приму никогда» у него не существует,
	// поэтому травить нечего — непринятая запись ждёт следующей попытки.

	// Рост числа ЛИЧНОСТЕЙ. Потолок на аккаунты личности (484002) обходится
	// заведением личностей, и это накопление не производила ни одна величина:
	// «личностей за всё время» и «сколько их появилось за час» не спрашивал
	// никто. Замер читает НАКОПИТЕЛЬНЫЙ журнал (задача #619) — падать этой величине
	// некуда, поэтому над ней определён рост, — и держит рядом счётчик своих
	// исходов, иначе ноль на витрине означал бы сразу и «личностей не было», и
	// «замер не снят». Это страховка, а не мера: отказ по такому порогу пришёл бы
	// следующему честному человеку, поэтому порог только наблюдается.
	identityGrowth := newIdentityGrowthSampler(kachopg.NewIdentityGrowthRepo(pool))
	metricsReg.NewIdentityGrowthCollector(identityGrowth.Counts)
	tasks = append(tasks, func() error {
		identityGrowth.Run(ctx, logger)
		return nil
	})

	// Bootstrap-admin reconciler. Grants `system_admin@cluster_kacho_root` to
	// the user identified by KACHO_IAM_BOOTSTRAP_ROOT_EMAIL and enqueues the
	// FGA tuple into the transactional fga_outbox, out of which a trigger folds the
	// direct fact in the same commit. The user row is mirrored only on first login /
	// fixture upsert — which races startup — so a one-shot call would skip and the
	// cluster-admin tuple would never be written at all (Bug B). The reconciler re-runs until the
	// grant commits; it is non-fatal by contract (best-effort startup
	// convenience, never a hard gate). No-op when the env is unset.
	bootstrapEmail := os.Getenv("KACHO_IAM_BOOTSTRAP_ROOT_EMAIL")
	bootstrapReconciler := seed.NewBootstrapReconciler(
		func(ctx context.Context) (seed.BootstrapAdminResult, error) {
			return seed.RunBootstrapAdmin(ctx, pool, logger, seed.BootstrapAdminInput{Email: bootstrapEmail})
		},
		seed.BootstrapReconcilerConfig{
			Interval: 10 * time.Second,
			Logger:   logger.With(slog.String("component", "bootstrap_admin_reconciler")),
		},
	)
	tasks = append(tasks, func() error {
		if bootstrapEmail == "" {
			logger.Info("bootstrap admin disabled (KACHO_IAM_BOOTSTRAP_ROOT_EMAIL unset)")
			return nil
		}
		logger.Info("bootstrap admin reconciler starting", "email", bootstrapEmail)
		// Non-fatal: reconciler errors must not crash the server. It returns
		// nil on convergence / terminal-skip / shutdown by design.
		return bootstrapReconciler.Run(ctx)
	})

	// γ reconciler-worker (epic «Resource-scoped AccessBinding», D7). Drains
	// resource_reconcile_outbox (Q1=(c) event-driven, written atomically by
	// RegisterResource) → re-evaluates the bindings referencing the changed
	// object (selector membership / byName containment / PENDING→ACTIVE verify),
	// AND periodically sweeps every selector binding (D12 defense-in-depth) +
	// expires TTL-elapsed bindings (D9 eager-revoke). In-process worker (no new
	// deploy); non-fatal by contract.
	reconcileAdapter := kachopg.NewReconcileAdapter(pool)
	reconcileEngine := reconcile.New(reconcileAdapter, logger.With(slog.String("component", "rsab_reconciler")))
	// resource_reconcile_outbox дренажится NOTIFY-driven (паритет с fga_outbox drainer):
	// AFTER INSERT триггер (миграция 0042) шлет pg_notify на канал
	// kacho_iam_resource_reconcile_outbox, reconcileAdapter LISTEN'ит его и будит worker —
	// смена меток ресурса материализует label-selector грант в пределах одного reconcile-
	// прохода, а не ждет poll-тика. DrainInterval теперь poll-fallback на пропущенный NOTIFY
	// (idle-conn-reset): NOTIFY несет latency, поэтому дефолт поднят со 150ms до 1s — реже
	// холостых claim'ов, а recovery при потере NOTIFY все равно ≤1s (и под 30s sweep'ом).
	// Sweep (полный проход) остается 30s как defense-in-depth. Оба интервала override-ятся env.
	//
	// Обе величины — ВТОРАЯ ступень цепочки отзыва гранта, и обе судятся при
	// старте: посадка, объявившая обход шире потолка политики, процесс не
	// поднимает. Пара читается ОДИН раз и той же парой уезжает в воркер —
	// прочтя ручку дважды, страж и воркер разошлись бы там, где переменную
	// меняли между вызовами. Разбор — `reconcile_window.go`.
	reconcileWindows := readReconcileWindows()
	if err := reconcileWindows.validate(authz.RevocationPolicy.MaterializationCeiling); err != nil {
		return err
	}
	reconcileWorker := seed.NewReconcileWorker(reconcileEngine, reconcileAdapter, seed.ReconcileWorkerConfig{
		SweepInterval: reconcileWindows.Sweep,
		DrainInterval: reconcileWindows.Drain,
		Notify:        reconcileAdapter,
		Logger:        logger.With(slog.String("component", "rsab_reconciler")),
	})
	tasks = append(tasks, func() error {
		logger.Info("rsab reconciler-worker starting (selector membership + containment + expiry)")
		return reconcileWorker.Run(ctx)
	})

	// RBAC explicit-model 2026 — MIGRATE-phase one-shot backfill
	// (singleton). On boot (best-effort, non-fatal): (1) owner-binding
	// data-backfill for any account a migration could not see (idempotent SQL); (2)
	// the reconcile-backfill SWEEP over every active binding under a process-wide
	// pg_advisory_lock so at N replicas exactly ONE executor runs it (chunked);
	// (3) the forward-aware verify-gate, logged as the contract-phase gate.
	// The steady-state reconciler-worker above keeps memberships converged
	// afterwards — the backfill just front-loads convergence before the next sweep.
	// ONE BackfillAdapter over the pool, shared by the backfill-runner and the
	// verify-gate.
	backfillAdapter := kachopg.NewBackfillAdapter(pool)
	backfillRunner := seed.NewBackfillRunner(
		reconcileEngine,
		backfillAdapter,
		seed.BackfillConfig{Logger: logger.With(slog.String("component", "p8_backfill"))},
	)
	verifyGate := seed.NewVerifyGate(reconcileEngine, backfillAdapter,
		logger.With(slog.String("component", "p8_verify_gate"))).
		// Design-B cutover gate: a REAL FGA Check per active binding's
		// required-relation triple — proves the materialized v_* tuple RESOLVES the
		// enforcement relation the catalog gates on, not merely that the ledger is
		// non-empty (the Design-A class-of-bug blind spot). nil-safe (degraded FGA →
		// non-fatal skip).
		WithRelationChecker(svcs.ownGates)
	// Разовая уборка выдач, чья область УЖЕ УДАЛЕНА (#810, продолжение #792).
	//
	// ПОЧЕМУ ПЕРЕД ПОДМЁТКОЙ РЕКОНСАЙЛА, А НЕ ПОСЛЕ. Подмётка обходит КАЖДУЮ
	// активную выдачу и материализует её кортежи — включая висячие. Пойди уборка
	// второй, тот же старт сперва выписал бы кортежи выдачам, которые сам же
	// сейчас снимет: лишняя работа, лишние строки очереди и пара «выдача-отзыв» на
	// одном ключе партиции. Уборка первой снимает строки до того, как подмётка их
	// увидит, и обходу нечего материализовать.
	//
	// ПОЧЕМУ ЭТО БЕЗОПАСНО ЗАПУСКАТЬ САМО. Обе таблицы — и `access_bindings`, и
	// `projects`/`accounts` — лежат в ОДНОЙ базе iam, то есть в одной единице
	// снятия и восстановления копии. Состояния «проекты потерялись, выдачи
	// остались» согласованное восстановление не производит by construction,
	// поэтому порога вида «слишком много, отказываюсь» здесь нет: на живом стенде
	// висячими были 145 выдач из 193, и любой правдоподобный порог отказал бы
	// ровно там, где уборка и нужна. Радиус одного старта ограничен потолком
	// прогона, каждая область оставляет событие аудита.
	orphanScopeSweeper := seed.NewOrphanScopeSweeper(kachoRepo, kachopg.NewOrphanScopeAdapter(pool),
		seed.OrphanScopeConfig{Logger: logger.With(slog.String("component", "orphan_scope_sweep"))})
	tasks = append(tasks, func() error {
		if ores, oerr := orphanScopeSweeper.RunOnce(ctx); oerr != nil {
			logger.Warn("orphan-scope sweep failed (next boot will retry)",
				slog.Any("err", oerr),
				slog.Int("scopes_revoked", ores.ScopesRevoked),
				slog.Int("bindings_revoked", ores.BindingsRevoked))
		}
		if oerr := seed.BackfillOwnerBindings(ctx, pool); oerr != nil {
			logger.Warn("p8 backfill: owner-binding data-backfill failed (sweep/next boot will retry)", slog.Any("err", oerr))
		}
		// Перепись встроенного доступа. Системные выдачи можно ОТОЗВАТЬ — это и есть
		// предмет #893/#895, — поэтому их отсутствие обязано быть видно оператору, а
		// не выглядеть поломкой продукта.
		seed.LogSystemGrantCensus(ctx, pool, logger.With(slog.String("component", "system_grants")))
		res, berr := backfillRunner.RunOnce(ctx)
		if berr != nil {
			logger.Warn("p8 backfill: reconcile-sweep failed (next boot/sweep will retry)", slog.Any("err", berr))
			return nil // non-fatal — never crash the server on a best-effort backfill
		}
		if res.Executed {
			report, verr := verifyGate.Verify(ctx)
			if verr != nil {
				logger.Warn("p8 verify-gate: verify failed", slog.Any("err", verr))
			} else {
				logger.Info("p8 verify-gate result (contract gated on no-access-loss)",
					slog.Bool("no_access_loss", report.NoAccessLoss),
					slog.Int("bindings_checked", report.BindingsChecked),
					slog.Int("failures", len(report.Failures)))
			}
			// Live forward-smoke (review #14 / КФ-4/H-06): Verify (active_members-
			// derived) provably CANNOT assert that a resource created in the contract
			// window forward-materializes its tuple — so drive a real ForwardSmoke
			// against an owner-binding (bounded-scope owner-content path). Best-effort,
			// non-fatal (parity with Verify): a brand-new cluster with no owner-binding
			// reports ran=false and the gate is logged as smoke-skipped.
			passed, ran, serr := verifyGate.RunBootForwardSmoke(ctx)
			switch {
			case serr != nil:
				logger.Warn("p8 verify-gate: forward-smoke failed", slog.Any("err", serr))
			case !ran:
				logger.Info("p8 verify-gate: forward-smoke skipped (no owner-binding to smoke yet)")
			default:
				logger.Info("p8 verify-gate forward-smoke result (forward-path liveness)",
					slog.Bool("forward_smoke_passed", passed))
			}
			// Design-B cutover gate (F-12 / VBC-19): relation-satisfies-action — a REAL
			// FGA Check per active binding's v_* required-relation triple. Logged as the
			// catalog-flip gate (the flip to v_* is permitted only when 100% resolve).
			relReport, rerr := verifyGate.VerifyRelationSatisfiesAction(ctx)
			if rerr != nil {
				logger.Warn("p8 verify-gate: relation-satisfies-action check failed", slog.Any("err", rerr))
			} else {
				logger.Info("p8 verify-gate relation-satisfies-action result (catalog-flip gate)",
					slog.Bool("no_access_loss", relReport.NoAccessLoss),
					slog.Int("bindings_checked", relReport.BindingsChecked),
					slog.Int("failures", len(relReport.Failures)))
			}
		}
		return nil
	})

	err = parallel.ExecAbstract(len(tasks), safeconv.IntToInt32(len(tasks)-1), func(i int) error {
		return tasks[i]()
	})
	cancel()
	return err
}

// identityUnary / identityStream — цепочка извлечения личности вызывающего,
// ОДНА на оба листенера.
//
// Пара, а не одиночный извлекатель: сначала классифицируется транспорт и
// снимается личность клиентского сертификата (CertIdentityExtract), и только
// потом переданная в метаданных личность конечного пользователя принимается —
// и только от пира, чья личность сертификата перечислена оператором.
//
// Список отправителей приходит ТОЛЬКО из конфигурации и никогда не задаётся
// здесь литералом: пустой список для corelib означает не «никому», а «любому
// пиру с проверенным сертификатом» (pkg/grpcsrv principalIsTrusted сужает круг
// лишь на непустом списке), и переданная личность становится субъектом решения о
// правах. Боевой режим на пустом списке не стартует (config.Validate →
// validateProductionTrustedForwarders).
//
// Почему список ОБЩИЙ на оба листенера. Законные отправители ходят и туда, и
// туда: api-gateway держит адреса обоих портов (KACHO_API_GATEWAY_IAM_GRPC :9090
// и ..._IAM_INTERNAL_GRPC :9091), consumer-модули берут проект на :9090 и зовут
// Check / fga-proxy на :9091, оператор пространств имён читает аккаунты и проекты
// на :9090. Внутренний периметр от сужения не освобождён — «internal = trusted»
// у нас запрещённое допущение. НА КАКОМ RPC отправитель вправе появиться,
// решают пер-RPC политики вызывающего (authzguard.PublicCallerPolicy на :9090,
// authzguard.CallerPolicy на :9091) — это ортогональный, второй слой.
func identityUnary(cfg config.Config) []grpc.UnaryServerInterceptor {
	return grpcsrv.PrincipalExtractUnary(cfg.AuthN.TrustedForwarders())
}

func identityStream(cfg config.Config) []grpc.StreamServerInterceptor {
	return grpcsrv.PrincipalExtractStream(cfg.AuthN.TrustedForwarders())
}

// requireRegistryTokenTLS — слушатель docker-token (`/iam/token`, :9096) в
// production обязан нести TLS.
//
// По этому сокету едет HTTP Basic, чей пароль — ПРИВАТНЫЙ КЛЮЧ ключа служебной
// учётки: сервер его не хранит вовсе (выводит SPKI из предъявленного и сверяет с
// сохранённым публичным), поэтому этот хоп — единственное место в системе, где
// приватный ключ транзитит. Срок жизни ключа не ограничен и ротации нет: снятый с
// провода, он предъявляется напрямую, без окна TTL — то есть ущерб не ограничен
// ничем, в отличие от короткоживущего bearer'а на соседней ноге, которая гейт
// получила давно.
//
// Пустой адрес ⇒ слушатель не поднимается, гейтить нечего. В dev — no-op
// (тот же порядок, что у прочих HTTP-рёбер: default-off, стенд байт-идентичен).
func requireRegistryTokenTLS(productionMode bool, addr string, mtlsCfg config.MTLSConfig) error {
	if !productionMode || strings.TrimSpace(addr) == "" {
		return nil
	}
	if !mtlsCfg.RegistryTokenServerMTLS.Enable {
		return fmt.Errorf("production mode requires TLS on the docker-token listener %s "+
			"(set KACHO_IAM_REGISTRYTOKEN_SERVER_MTLS_ENABLE=true with its cert/key): the "+
			"HTTP Basic password on this hop is the service-account key's private key, which "+
			"this server never stores and which never expires; refusing to start with it in the clear",
			addr)
	}
	return nil
}
