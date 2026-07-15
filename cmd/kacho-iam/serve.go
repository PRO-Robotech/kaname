// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// serve.go — runServe: full lifecycle of the kacho-iam binary.
// Wires pools → repos → services → gRPC servers + HTTP listeners + drainers,
// then runs them in parallel with a shared shutdown trigger driven by
// SIGTERM / SIGINT or any task error.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/grpcmw"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/jwksproxyhttp"
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

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer pool.Close()

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

	// Cross-service gRPC dial — kacho-iam is a leaf-owner of Account/Project,
	// so it currently has no outbound peer-clients (other services dial in
	// for `iam.v1.ProjectService.Get` etc.).

	// kachoRepo is shared by all per-resource use-cases.
	kachoRepo := kachopg.New(pool, slavePool)

	// Authorization backend — selected by KACHO_IAM_AUTHZ_PROVIDER (default
	// "openfga"). buildRelationStore returns the provider-neutral
	// clients.RelationStore port; an unknown provider fails closed (no silent
	// fallback). The real client is always used (no stub fallback — запрет #11).
	// store-id is provisioned at runtime by the openfga-bootstrap-job; until
	// then the client fails closed (see buildOpenFGAClient).
	relationStore, err := buildRelationStore(authzProvider(), logger)
	if err != nil {
		return fmt.Errorf("authz provider: %w", err)
	}
	// Recover the concrete OpenFGA client at this single composition point:
	// buildServices + the fga_outbox applier need per-operation field access
	// that the abstract port does not expose. The "openfga" provider is the
	// only adapter today, so the assertion always holds; a future provider
	// would adjust this wiring alongside its adapter.
	openfgaClient, ok := relationStore.(*clients.OpenFGAHTTPClient)
	if !ok {
		return fmt.Errorf("authz provider: relation store %T is not wired into the composition root", relationStore)
	}

	// Prometheus registry — owns the /metrics collectors. Created once and
	// shared by the metrics HTTP listener, the gRPC server interceptors (both
	// listeners) and the authz-Check decorator. Clean Architecture: prometheus
	// is imported only here (composition root) + the metrics adapter package.
	metricsReg := metrics.NewRegistry()

	// Подключаем Prometheus-Recorder и логгер к default-registry LRO-worker'а и
	// поднимаем его dispatcher ДО приема трафика. Без этого default-registry держит
	// NopRecorder (live terminal-write/inflight метрики мертвы), а operations.Ready()
	// остается false до первого Run, поэтому readiness не отражает worker.
	// ConfigureDefault обязан предшествовать Start.
	lroRec := metricsReg.NewLRORecorder()
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

	svcs := buildServices(pool, slavePool, opsRepo, kachoRepo, openfgaClient, metricsReg, cfg, logger)

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
	// per-edge clientAuthMode via tls.NewListener (server-tls-only = encryption
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
	// The fga-proxy writes (Register/Unregister/WriteCreatorTuple) are NOT in the
	// gateway-only set and stay gated in-handler by RelationWriteGate (fga_writer)
	// — their callers are vpc/compute/nlb module SAs, not the gateway.
	internalCallerPolicy := authzguard.NewCallerPolicy(productionMode, authzguard.GatewayFrontedInternalRPCs())

	// Per-RPC `system_viewer`-FLOOR on the internal READ-RPC set
	// (authN+authZ enforced everywhere: read-RPC gate viewer-tier). For
	// ReadFloorRPCs it requires the CALLER MODULE-SA (derived from the verified
	// mTLS SAN, same derivation as the fga-proxy gate) to hold the coarse cluster
	// relation `system_viewer@cluster:cluster_kacho_root`, via the SAME
	// RelationChecker port (openfgaClient) used by RelationWriteGate / iam.Check.
	// Default-OFF: dev/newman (prod=false) → NO-OP pass-through (newman stand
	// byte-identical). Prod fail-closed: no verified SAN → PermissionDenied;
	// FGA backend error → Unavailable. EXEMPT (NOT in ReadFloorRPCs): the PDP
	// Check (INV-FLOOR-5), secret-authed OnRecoveryCompleted + hot-path IsRevoked
	// (INV-FLOOR-6), and all mutations (fga_writer / system_admin / gateway-only;
	// INV-FLOOR-8). Chained AFTER internalCallerPolicy, mirroring its prod-mode
	// gating. The legitimate reader SAs (api-gateway/vpc/compute) are seeded
	// system_viewer@cluster by migration 0014 (vpc-operator already by SEC-L 0010).
	internalSystemViewerFloor := authzguard.NewSystemViewerFloor(openfgaClient, authzguard.ReadFloorRPCs()).
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

	// Anti-anonymous guard перед мутирующими RPC: минимальная защита от
	// анонимного создания Account/Project/AccessBinding/Group/SA/Role
	// в дополнение к OpenFGA Check via AuthorizeService.
	grpcSrv := grpcsrv.NewServer(
		publicServerCreds,
		grpc.ChainUnaryInterceptor(
			// Metrics interceptor first — wraps the full chain so the recorded
			// latency/code covers the whole RPC (request count + handling
			// seconds + grpc_code), for every public RPC including authz Check.
			metricsReg.UnaryServerInterceptor(),
			// Panic-recovery immediately inside metrics: a panic in any downstream
			// interceptor or handler becomes a logged codes.Internal for that ONE
			// request instead of crashing the whole PDP process (metrics still
			// records the Internal code because recovery is inner of it).
			grpcmw.UnaryRecovery(logger),
			// Public listener — trust-aware principal extraction (anti-spoof). The
			// forwarded x-kacho-principal-* metadata is exposed downstream ONLY when
			// the peer passed mTLS client-cert verification (UnaryCertIdentityExtract
			// sets the verified flag; UnaryTrustedPrincipalExtract drops the metadata
			// on an unverified/cert-less peer → SystemPrincipal fallback). Without
			// this a peer reaching :9090 could FORGE an arbitrary user identity.
			//
			// NO gateway-only forwarder allow-list: :9090 is a MULTI-forwarder
			// listener — besides the api-gateway (JWT-fronted user requests), every
			// verified consumer module (kacho-vpc/compute/nlb/geo) dials the
			// tenant-facing ProjectService.Get and forwards the end-user principal for
			// the tenant scope-filter. Pinning gateway-only would break that
			// cross-service project validation. The internal CA + RequireAndVerify
			// ClientCert on :9090 already gates the listener to verified kacho modules;
			// this layer only ensures an UNVERIFIED peer cannot forge a principal.
			//
			// On the insecure dev listener (no TLS) the trust invariant is inapplicable
			// and the principal is accepted as before (backward-compat, byte-identical
			// to the newman stand). CertIdentityExtract MUST run before Trusted.
			grpcsrv.UnaryCertIdentityExtract(),
			grpcsrv.UnaryTrustedPrincipalExtract(),
			authzguard.AntiAnonymousUnary(logger),
		),
		grpc.ChainStreamInterceptor(
			grpcmw.StreamRecovery(logger),
			grpcsrv.StreamCertIdentityExtract(),
			grpcsrv.StreamTrustedPrincipalExtract(),
			authzguard.AntiAnonymousStream(logger),
		),
	)
	// Internal listener (port 9091) — network-segregated, but NOT trusted:
	// authN+authZ are enforced on EVERY internal RPC (security.md "authN+authZ
	// everywhere"; closes audit C1/C3/H3/M1).
	//
	// Interceptor chain order (each runs before the next):
	//  1. UnaryCertIdentityExtract — verified mTLS client-cert SAN (module
	//     identity) → ctx; insecure listener (dev) → no-op.
	//  2. UnaryTrustedPrincipalExtract — x-kacho-principal-* metadata → ctx, but
	//     trust-gated on the FD-4 invariant: the forwarded end-user principal is
	//     exposed downstream (operations.principal_* / audit / granted_by) ONLY
	//     when step 1 proved the peer mTLS-verified. On an unverified TLS peer the
	//     metadata is DROPPED (carrier falls back to SystemPrincipal) so a caller
	//     reaching :9091 without a verified client-cert cannot FORGE the audit
	//     principal (anti-spoof). On the insecure dev listener it stays accepted
	//     (backward-compat). NOT trusted for authZ — the gateway already did
	//     per-user authZ. MUST run after UnaryCertIdentityExtract.
	//  3. internalCallerPolicy — per-RPC caller policy: floor (verified module
	//     cert on EVERY RPC) + gateway-only (privileged admin RPCs only from the
	//     api-gateway SA). Prod fail-closed; dev no-op.
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
	internalSrv := grpcsrv.NewServer(
		internalServerCreds,
		grpc.ChainUnaryInterceptor(
			// Metrics interceptor first — observe every internal RPC (the
			// per-RPC authz-gate InternalIAMService.Check hot path lives here).
			metricsReg.UnaryServerInterceptor(),
			// Panic-recovery immediately inside metrics — same rationale as the
			// public chain: a handler/interceptor panic on the PDP hot path must
			// not crash the process (fail-closed cluster-wide); it degrades to a
			// logged codes.Internal for that one request.
			grpcmw.UnaryRecovery(logger),
			grpcsrv.UnaryCertIdentityExtract(),
			grpcsrv.UnaryTrustedPrincipalExtract(),
			internalCallerPolicy.Unary(),
			internalSystemViewerFloor.Unary(),
			internalACRFloor.Unary(),
		),
		grpc.ChainStreamInterceptor(
			grpcmw.StreamRecovery(logger),
			grpcsrv.StreamCertIdentityExtract(),
			grpcsrv.StreamTrustedPrincipalExtract(),
			internalCallerPolicy.Stream(),
			internalSystemViewerFloor.Stream(),
			internalACRFloor.Stream(),
		),
	)
	logger.Info("kacho-iam listener mTLS",
		"public_mtls", mtlsCfg.PublicServerMTLS.Enable,
		"internal_mtls", mtlsCfg.InternalServerMTLS.Enable,
		"hooks_mtls", mtlsCfg.HooksServerMTLS.Enable,
		"metrics_mtls", mtlsCfg.MetricsServerMTLS.Enable,
		"jwks_proxy_mtls", mtlsCfg.JWKSProxyServerMTLS.Enable)
	registerPublicServices(grpcSrv, svcs, opsRepo)
	registerInternalServices(internalSrv, svcs, pool, cfg.MigrateDSN(), logger)

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

	// HTTP webhook listener (Hydra token/refresh hooks + Kratos provision hook).
	// Cluster-internal-only (запрет #6); отдельный порт от gRPC public/internal.
	hooksAddr := cfg.AuthN.HooksHTTPListenAddress()
	var hooksListener net.Listener
	if hooksAddr != "" {
		hooksListener, err = net.Listen("tcp", hooksAddr)
		if err != nil {
			_ = listener.Close()
			_ = internalListener.Close()
			return fmt.Errorf("hooks http listener: %w", err)
		}
		// Default-off: hooksTLSConfig is nil → plaintext (unchanged). When the
		// per-edge TLS is enabled the raw TCP listener is wrapped so every hooks
		// connection is encrypted; the clientAuthMode (server-tls-only by default
		// for the HMAC-authed Hydra/Kratos webhooks) is baked into hooksTLSConfig.
		if hooksTLSConfig != nil {
			hooksListener = tls.NewListener(hooksListener, hooksTLSConfig)
		}
	}

	// Prometheus /metrics HTTP listener — SEPARATE cluster-internal port
	// (default :9095). Never the public tenant gRPC surface: exposing the
	// registry there would leak internal cardinality (security.md). Empty
	// endpoint disables it.
	metricsAddr := cfg.APIServer.MetricsListenAddress()
	var metricsListener net.Listener
	if metricsAddr != "" {
		metricsListener, err = net.Listen("tcp", metricsAddr)
		if err != nil {
			_ = listener.Close()
			_ = internalListener.Close()
			if hooksListener != nil {
				_ = hooksListener.Close()
			}
			return fmt.Errorf("metrics http listener: %w", err)
		}
		// Default-off: metricsTLSConfig is nil → plaintext (unchanged). When
		// enabled the listener is wrapped so /metrics is served over TLS; the
		// clientAuthMode (server-tls-only by default — no scrape client cert yet)
		// is baked into metricsTLSConfig.
		if metricsTLSConfig != nil {
			metricsListener = tls.NewListener(metricsListener, metricsTLSConfig)
		}
	}

	// Docker Registry v2 `/iam/token` auth-server HTTP listener — a SEPARATE,
	// EXTERNAL-reachable port (default :9096; TLS terminated at the ingress, like
	// hooks/metrics). Docker clients hit `/iam/token` through the edge; the shim
	// verifies the SA-key and BROKERS a token from Ory Hydra (the issuer). The
	// data-plane verifies the returned token against Hydra's JWKS — which it now
	// fetches from the cluster-internal jwks-proxy mirror below (:9097), NOT from
	// this `/iam/token` listener (which carries no JWKS endpoint). Distinct from the
	// cluster-internal hooks (:9092) / metrics (:9095) / jwks-proxy (:9097)
	// listeners. Disabled (WARN-skip, never a boot block) only when the endpoint is
	// empty — the shim needs no JWKS encryption key (it mints nothing).
	registryTokenAddr := cfg.APIServer.RegistryToken.ListenAddress()
	var registryTokenListener net.Listener
	var registryTokenHTTPServer *http.Server
	if registryTokenAddr != "" {
		registryTokenListener, err = net.Listen("tcp", registryTokenAddr)
		if err != nil {
			_ = listener.Close()
			_ = internalListener.Close()
			if hooksListener != nil {
				_ = hooksListener.Close()
			}
			if metricsListener != nil {
				_ = metricsListener.Close()
			}
			return fmt.Errorf("registry token http listener: %w", err)
		}
		registryTokenMux := registrytokenwire.Build(pool, registrytokenwire.BuildConfig{
			Realm:             cfg.APIServer.RegistryToken.TokenIssuer(),
			Service:           cfg.APIServer.RegistryToken.TokenService(),
			HydraTokenURL:     cfg.AuthN.ResolveHydraTokenURL(),
			AssertionAudience: cfg.AuthN.ResolveHydraTokenEndpoint(),
		})
		registryTokenHTTPServer = &http.Server{
			Handler:           registryTokenMux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
	}

	// Cluster-INTERNAL Hydra-JWKS proxy HTTP listener (default :9097) — a SEPARATE
	// cluster-internal port serving GET /.well-known/jwks.json as a short-TTL
	// caching reverse-proxy of Hydra's PUBLIC JWKS. The data-plane (kacho-registry)
	// fetches its verification keys from iam here instead of dialing Hydra directly;
	// Hydra stays the token issuer/signer (iam mints NOTHING — the served kids are
	// Hydra's actual signing kids, never iam's own oidc_jwks_keys kacho-* kids).
	// Served ONLY on the kacho-iam-internal Service (never external, ban #6; the
	// Service wiring lives in kacho-deploy) over ONE-WAY server-TLS. The route is
	// UNAUTHENTICATED-BY-DESIGN (public OIDC verification keys) — a conscious,
	// documented exception to authN-on-every-listener (security.md), justified by
	// internal-only surface + server-TLS + only-public-material. Empty endpoint
	// disables it (WARN-skip, never a boot block).
	jwksProxyAddr := cfg.APIServer.JWKSProxy.ListenAddress()
	var jwksProxyListener net.Listener
	var jwksProxyHTTPServer *http.Server
	if jwksProxyAddr != "" {
		jwksProxyListener, err = net.Listen("tcp", jwksProxyAddr)
		if err != nil {
			_ = listener.Close()
			_ = internalListener.Close()
			if hooksListener != nil {
				_ = hooksListener.Close()
			}
			if metricsListener != nil {
				_ = metricsListener.Close()
			}
			if registryTokenListener != nil {
				_ = registryTokenListener.Close()
			}
			return fmt.Errorf("jwks-proxy http listener: %w", err)
		}
		// Default-off: jwksProxyTLSConfig is nil → plaintext (dev). When enabled the
		// listener is wrapped so /.well-known/jwks.json is served over one-way
		// server-TLS (internal-CA leaf; the leaf serverHosts already covers
		// kacho-iam-internal).
		if jwksProxyTLSConfig != nil {
			jwksProxyListener = tls.NewListener(jwksProxyListener, jwksProxyTLSConfig)
		}
		jwksProxyHandler := jwksproxyhttp.NewHandler(jwksproxyhttp.Config{
			UpstreamURL: cfg.AuthN.ResolveHydraJWKSURL(),
			Logger:      logger.With(slog.String("component", "jwks_proxy")),
		})
		jwksProxyHTTPServer = &http.Server{
			Handler:           jwksproxyhttp.NewMux(jwksProxyHandler),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
	}

	logger.Info("kacho-iam listening",
		"public_endpoint", publicAddr,
		"internal_endpoint", internalAddr,
		"hooks_http_endpoint", hooksAddr,
		"metrics_http_endpoint", metricsAddr,
		"registry_token_http_endpoint", registryTokenAddr,
		"jwks_proxy_http_endpoint", jwksProxyAddr)

	gracefulTimeout := cfg.APIServer.GracefulShutdown
	if gracefulTimeout <= 0 {
		gracefulTimeout = 10 * time.Second
	}

	// Build HTTP hooks mux.
	var hooksHTTPServer *http.Server
	if hooksListener != nil {
		hooksMux := buildHooksMux(pool, kachoRepo, opsRepo, openfgaClient, cfg, logger)
		hooksHTTPServer = &http.Server{
			Handler:           hooksMux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
	}

	// Build the /metrics HTTP server (promhttp over the shared registry).
	var metricsHTTPServer *http.Server
	if metricsListener != nil {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metricsReg.Handler())
		metricsHTTPServer = &http.Server{
			Handler:           metricsMux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
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
	var shutdownOnce sync.Once
	triggerShutdown := func() {
		shutdownOnce.Do(func() {
			stopGRPCBounded(internalSrv, gracefulTimeout)
			stopGRPCBounded(grpcSrv, gracefulTimeout)
			if hooksHTTPServer != nil {
				shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelShutdown()
				_ = hooksHTTPServer.Shutdown(shutdownCtx)
			}
			if metricsHTTPServer != nil {
				shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelShutdown()
				_ = metricsHTTPServer.Shutdown(shutdownCtx)
			}
			if registryTokenHTTPServer != nil {
				shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelShutdown()
				_ = registryTokenHTTPServer.Shutdown(shutdownCtx)
			}
			if jwksProxyHTTPServer != nil {
				shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancelShutdown()
				_ = jwksProxyHTTPServer.Shutdown(shutdownCtx)
			}
		})
	}

	tasks := []func() error{
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

	// HTTP hooks listener + DPoP-cleanup loop.
	if hooksHTTPServer != nil && hooksListener != nil {
		tasks = append(tasks, func() error {
			logger.Info("kacho-iam HTTP hooks listener serving", "addr", hooksListener.Addr().String())
			err := hooksHTTPServer.Serve(hooksListener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				triggerShutdown()
				return fmt.Errorf("hooks http server: %w", err)
			}
			return nil
		})
	}

	// Prometheus /metrics HTTP listener (separate internal port).
	if metricsHTTPServer != nil && metricsListener != nil {
		tasks = append(tasks, func() error {
			logger.Info("kacho-iam /metrics listener serving", "addr", metricsListener.Addr().String())
			err := metricsHTTPServer.Serve(metricsListener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				triggerShutdown()
				return fmt.Errorf("metrics http server: %w", err)
			}
			return nil
		})
	}

	// Registry v2 `/iam/token` auth-server HTTP listener (separate external port).
	if registryTokenHTTPServer != nil && registryTokenListener != nil {
		tasks = append(tasks, func() error {
			logger.Info("kacho-iam registry token listener serving", "addr", registryTokenListener.Addr().String())
			err := registryTokenHTTPServer.Serve(registryTokenListener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				triggerShutdown()
				return fmt.Errorf("registry token http server: %w", err)
			}
			return nil
		})
	}

	// Cluster-internal Hydra-JWKS proxy HTTP listener (separate internal port :9097).
	if jwksProxyHTTPServer != nil && jwksProxyListener != nil {
		tasks = append(tasks, func() error {
			logger.Info("kacho-iam jwks-proxy listener serving", "addr", jwksProxyListener.Addr().String())
			err := jwksProxyHTTPServer.Serve(jwksProxyListener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				triggerShutdown()
				return fmt.Errorf("jwks-proxy http server: %w", err)
			}
			return nil
		})
	}
	// Enterprise SSO (SCIM + SAML) is not served by this listener set.

	// fga_outbox drainer. Watches kacho_iam.fga_outbox via LISTEN/NOTIFY
	// (channel `kacho_iam_fga_outbox` set up by migration 0002), drains
	// pending tuples at startup, and applies each row to OpenFGA via
	// clients.NewFGAApplier (Write/Delete tuples; idempotent on 400-already-
	// exists / 400-cannot-delete; retry on 5xx; poison on validation_error).
	// OpenFGA is required in production (composition root fails fast above
	// when KACHO_IAM_OPENFGA_STORE_ID is empty) — the drainer always runs.
	fgaDrainer, derr := drainer.New[clients.FGAOutboxEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.fga_outbox",
			Channel:      "kacho_iam_fga_outbox",
			BatchSize:    32,
			PollFallback: 30 * time.Second,
			MaxAttempts:  10,
			BackoffMin:   1 * time.Second,
			BackoffMax:   30 * time.Second,
			ApplyTimeout: 5 * time.Second,
		},
		clients.DecodeFGAOutboxEvent,
		clients.NewFGAApplier(svcs.relationStore),
		logger.With(slog.String("component", "fga_outbox_drainer")),
	)
	if derr != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		if hooksListener != nil {
			_ = hooksListener.Close()
		}
		if registryTokenListener != nil {
			_ = registryTokenListener.Close()
		}
		if jwksProxyListener != nil {
			_ = jwksProxyListener.Close()
		}
		return fmt.Errorf("fga_outbox drainer init: %w", derr)
	}
	tasks = append(tasks, func() (err error) {
		// Dead drainer must not leave the pod silently serving: a fatal exit (or a
		// panic in Run) is escalated to a full shutdown so the deployment restarts
		// instead of accepting writes whose owner-tuples never reach OpenFGA.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("fga_outbox drainer panicked", "panic", r)
				err = fmt.Errorf("fga_outbox drainer panic: %v", r)
			}
			if err != nil {
				triggerShutdown()
			}
		}()
		logger.Info("kacho-iam fga_outbox drainer starting",
			"table", "kacho_iam.fga_outbox",
			"channel", "kacho_iam_fga_outbox")
		if rerr := fgaDrainer.Run(ctx); rerr != nil {
			logger.Error("fga_outbox drainer exited with error", "err", rerr)
			return fmt.Errorf("fga_outbox drainer: %w", rerr)
		}
		logger.Info("kacho-iam fga_outbox drainer stopped cleanly")
		return nil
	})

	// subject_change_outbox push-drainer. Drains kacho_iam.subject_change_outbox
	// via the corelib generic Drainer[T] → InternalAuthzCacheService.InvalidateSubject
	// on the api-gateway internal mTLS port (9091). Required at startup — the
	// gateway-internal address is mandatory; sub-second push invalidation
	// removes the 30s poll-loop convergence window.
	subjectChangeDrainerTask, err := buildSubjectChangeDrainer(ctx, pool, logger)
	if err != nil {
		_ = listener.Close()
		_ = internalListener.Close()
		if hooksListener != nil {
			_ = hooksListener.Close()
		}
		if registryTokenListener != nil {
			_ = registryTokenListener.Close()
		}
		if jwksProxyListener != nil {
			_ = jwksProxyListener.Close()
		}
		return fmt.Errorf("subject_change drainer wiring: %w", err)
	}
	tasks = append(tasks, subjectChangeDrainerTask)

	// Bootstrap-admin reconciler. Grants `system_admin@cluster_kacho_root` to
	// the user identified by KACHO_IAM_BOOTSTRAP_ROOT_EMAIL and enqueues the
	// FGA tuple into the transactional fga_outbox (drained above). The user
	// row is mirrored only on first login / fixture upsert — which races
	// startup — so a one-shot call would skip and the cluster-admin tuple
	// would never reach OpenFGA (Bug B). The reconciler re-runs until the
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
	reconcileWorker := seed.NewReconcileWorker(reconcileEngine, reconcileAdapter, seed.ReconcileWorkerConfig{
		SweepInterval: envDurationMS("KACHO_IAM_RECONCILE_SWEEP_INTERVAL_MS", 30*time.Second),
		DrainInterval: envDurationMS("KACHO_IAM_RECONCILE_DRAIN_INTERVAL_MS", 1*time.Second),
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
		WithRelationChecker(openfgaClient)
	tasks = append(tasks, func() error {
		if oerr := seed.BackfillOwnerBindings(ctx, pool); oerr != nil {
			logger.Warn("p8 backfill: owner-binding data-backfill failed (sweep/next boot will retry)", slog.Any("err", oerr))
		}
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
