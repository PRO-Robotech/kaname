// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_drainer_wiring.go — subject_change_outbox push-drainer wiring.
//
// Builds a corelib generic Drainer[SubjectChangeEvent] (parity with the
// FGA outbox drainer) that:
//
//   - LISTENs on kacho_iam_subject_outbox_added channel via the local
//     pgxpool (запрет #8: gateway has no pool on kacho-iam DB);
//   - claims subject_change_outbox rows via CAS + FOR UPDATE SKIP LOCKED;
//   - decodes payload jsonb → clients.SubjectChangeEvent;
//   - applies via InternalAuthzCacheServiceClient.InvalidateSubject on
//     api-gateway's internal mTLS listener (port 9091).
//
// Env vars (sole config knobs, no YAML — internal infra):
//
//   - KACHO_IAM_GATEWAY_INTERNAL_ADDR — host:port of api-gateway internal
//     gRPC listener (e.g. "kacho-api-gateway-internal:9091"). REQUIRED —
//     empty → startup fails (sub-second cache invalidation is part of the
//     authz contract, not optional).
//
//   - KACHO_IAM_GATEWAY_INTERNAL_TLS_INSECURE — "true" → plaintext transport
//     (dev / kind only). Default false → TLS via system trust store.
//
//   - KACHO_IAM_GATEWAY_INTERNAL_TLS_CLIENT_CERT / _CLIENT_KEY — optional
//     PEM paths; when both set, the dial presents a client certificate
//     (mTLS). When unset, server-authenticated TLS (system roots) is used.
//
//   - KACHO_IAM_GATEWAY_INTERNAL_TLS_CA — optional PEM path overriding the
//     system root pool for verifying the gateway server certificate.
//
//   - KACHO_IAM_GATEWAY_INTERNAL_TLS_SERVER_NAME — optional SNI / verification
//     override (defaults to the host part of the dial address).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	apigatewayv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/apigateway/v1"
	"github.com/PRO-Robotech/kacho/pkg/grpcclient"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

const (
	envGatewayInternalAddr       = "KACHO_IAM_GATEWAY_INTERNAL_ADDR"
	envGatewayInternalInsecure   = "KACHO_IAM_GATEWAY_INTERNAL_TLS_INSECURE"
	envGatewayInternalClientCert = "KACHO_IAM_GATEWAY_INTERNAL_TLS_CLIENT_CERT"
	envGatewayInternalClientKey  = "KACHO_IAM_GATEWAY_INTERNAL_TLS_CLIENT_KEY"
	envGatewayInternalCA         = "KACHO_IAM_GATEWAY_INTERNAL_TLS_CA"
	envGatewayInternalServerName = "KACHO_IAM_GATEWAY_INTERNAL_TLS_SERVER_NAME"
)

// buildSubjectChangeDrainer — wires the subject-change push-drainer. The
// gateway-internal address is REQUIRED; a missing address or a transport
// misconfiguration returns an error that halts startup. Runtime errors from
// drainer.Run propagate via the returned task.
func buildSubjectChangeDrainer(
	ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger,
) (func() error, error) {
	_ = ctx // drainer.Run receives its own ctx from the parallel.ExecAbstract caller below

	addr := os.Getenv(envGatewayInternalAddr)
	if addr == "" {
		return nil, fmt.Errorf("%s is required (api-gateway internal gRPC host:port)", envGatewayInternalAddr)
	}

	creds, err := gatewayDialCreds(addr, logger)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(addr, gatewayDialOpts(creds)...)
	if err != nil {
		return nil, fmt.Errorf("dial api-gateway internal: %w", err)
	}
	cli := apigatewayv1.NewInternalAuthzCacheServiceClient(conn)

	d, err := drainer.New[clients.SubjectChangeEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.subject_change_outbox",
			Channel:      "kacho_iam_subject_outbox_added",
			BatchSize:    64,
			PollFallback: 30 * time.Second,
			MaxAttempts:  10,
			BackoffMin:   200 * time.Millisecond,
			BackoffMax:   10 * time.Second,
			ApplyTimeout: 3 * time.Second,
		},
		clients.DecodeSubjectChange,
		clients.NewSubjectChangeApplier(cli),
		logger.With(slog.String("component", "subject_change_drainer")),
	)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("init subject_change drainer: %w", err)
	}

	logger.Info("subject_change drainer enabled",
		"gateway_internal_addr", addr,
		"channel", "kacho_iam_subject_outbox_added",
		"latency_target", "≤1s (push) / ≤30s (poll-fallback)")

	return func() error {
		defer func() { _ = conn.Close() }()
		// drainer's own ctx comes from the runServe outer ctx via the
		// parallel.ExecAbstract task closure; we close conn on shutdown.
		return d.Run(ctx)
	}, nil
}

// gatewayDialOpts — seam-функция (тестируемая): creds (gatewayDialCreds) + idle
// keepalive. Вынесена отдельно, т.к. grpc.NewClient не отдает опции назад.
func gatewayDialOpts(creds credentials.TransportCredentials) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpcclient.KeepaliveDialOption(true),
	}
}

// gatewayDialCreds resolves the transport credentials for the api-gateway
// internal gRPC dial:
//
//   - KACHO_IAM_GATEWAY_INTERNAL_TLS_INSECURE=true → plaintext (dev / kind);
//   - otherwise TLS. The root pool is the system pool unless _TLS_CA points
//     at a PEM bundle. When both _TLS_CLIENT_CERT and _TLS_CLIENT_KEY are set
//     the dial presents a client certificate (mTLS).
func gatewayDialCreds(addr string, logger *slog.Logger) (credentials.TransportCredentials, error) {
	if os.Getenv(envGatewayInternalInsecure) == "true" {
		logger.Warn("subject_change drainer dialing gateway over plaintext (dev mode)",
			"addr", addr, "env", envGatewayInternalInsecure)
		return insecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	// Server name for verification: explicit override or host part of addr.
	// net.SplitHostPort handles IPv6 literals ("[::1]:9091" → "::1") correctly,
	// unlike a naive LastIndex(":") split.
	if sn := os.Getenv(envGatewayInternalServerName); sn != "" {
		tlsCfg.ServerName = sn
	} else if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		tlsCfg.ServerName = host
	}

	// Root CA pool — system roots by default; PEM override when provided.
	if caPath := os.Getenv(envGatewayInternalCA); caPath != "" {
		pem, err := os.ReadFile(caPath) // #nosec G304 G703 -- trusted operator-config path (env KACHO_IAM_GATEWAY_INTERNAL_CA), not request/user input

		if err != nil {
			return nil, fmt.Errorf("read gateway TLS CA %q: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gateway TLS CA %q: no certificates parsed", caPath)
		}
		tlsCfg.RootCAs = pool
	}

	// Optional client certificate (mTLS).
	certPath := os.Getenv(envGatewayInternalClientCert)
	keyPath := os.Getenv(envGatewayInternalClientKey)
	switch {
	case certPath != "" && keyPath != "":
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load gateway mTLS client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		logger.Info("subject_change drainer dialing gateway with mTLS", "addr", addr)
	case certPath != "" || keyPath != "":
		return nil, fmt.Errorf("both %s and %s must be set for mTLS (got only one)",
			envGatewayInternalClientCert, envGatewayInternalClientKey)
	default:
		logger.Info("subject_change drainer dialing gateway with server-authenticated TLS", "addr", addr)
	}

	return credentials.NewTLS(tlsCfg), nil
}
