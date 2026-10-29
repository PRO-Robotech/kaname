// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront_test

// internal_front_check_lane_test.go — полоса HTTP внутреннего Check не шире
// полосы gRPC (SEC-1017-1, kaname#987 вместе с kaname#984).
//
// # Предмет
//
// Обработчик внутреннего Check сужает ДОВОД по личности вызывающего: плоскость
// данных спрашивает только об объектах своего модуля (kaname#987). Личность он
// берёт у пира gRPC. Через собственный внутренний REST-фронт пиром оказывается
// сам фронт: личности за ним обработчик не видит, и сужение не применяется.
// Фронт при этом пускает держателя ЛЮБОГО листа внутреннего центра — и
// плоскость данных чужого модуля, и лист вне перечня, которому gRPC-полоса
// отказывает полом.
//
// # Как судится
//
// Всё настоящее, кроме решателя: фронт `restfront.NewInternal` на HTTPS со
// взаимным TLS, его хоп — gRPC-слушатель со взаимным TLS, извлекателем личности
// сертификата и политикой вызывающего в боевом режиме, обработчик внутреннего
// Check с тем же перечнем личностей. Решатель — счётчик с ответом «да»: проба
// судит, дошёл ли вопрос до решения, а не само решение.
//
// Каждая строка таблицы сравнивает ОДИН лист на двух полосах. Близнецы: край
// через фронт спрашивает о том же чужом объекте и получает ответ решателя;
// плоскость данных по gRPC спрашивает о своём объекте и получает его же.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/restfront"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Личности мира пробы: домен — набора `moduleroster`.
const (
	laneFrontSAN     = "spiffe://" + moduleroster.DomainName + "/ns/kaname/sa/kaname"
	laneDataPlaneSAN = "spiffe://" + moduleroster.DomainName + "/ns/registry-data/sa/kacho-registry"
	laneEdgeSAN      = "spiffe://" + moduleroster.DomainName + "/ns/kacho/sa/kacho-api-gateway"
	laneOutsiderSAN  = "spiffe://" + moduleroster.DomainName + "/ns/intruder/sa/kacho-vpc"

	laneForeignObject = "vpc_network:enp_x"         // домен vpc — чужой плоскости данных registry
	laneOwnObject     = "registry_repository:rep_x" // домен registry — свой
)

// laneRoster — плоскость данных registry, модуль-владелец vpc и край.
func laneRoster(t *testing.T) moduleidentity.Roster {
	t.Helper()
	r, err := moduleidentity.Parse(servicesan.NewForm("kacho-{service}"), []string{
		"registry-data/kacho-registry=data-plane",
		"kacho/kacho-vpc=module-writer",
		"kacho/kacho-api-gateway=edge",
	})
	require.NoError(t, err)
	return r
}

// countingAuthorizer — решатель, который отвечает «да» и считает вопросы.
type countingAuthorizer struct{ calls atomic.Int64 }

func (a *countingAuthorizer) CheckRelation(context.Context, service.CheckRelationRequest) (*service.CheckResult, error) {
	a.calls.Add(1)
	return &service.CheckResult{Allowed: true, CheckedAt: time.Now().UTC()}, nil
}

// laneWorld — поднятые слушатель, фронт и центр.
type laneWorld struct {
	t     *testing.T
	ca    *laneCA
	grpc  string // адрес gRPC-слушателя
	front string // адрес HTTPS внутреннего фронта
	authz *countingAuthorizer
}

func newLaneWorld(t *testing.T) *laneWorld {
	t.Helper()
	ca := newLaneCA(t)
	roster := laneRoster(t)
	d := moduleroster.Domain()
	authz := &countingAuthorizer{}

	policy := authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs()).
		WithOwnFrontHop(laneFrontSAN).
		WithModuleRoster(roster)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(ca.serverTLS(t))),
		grpc.ChainUnaryInterceptor(grpcsrv.UnaryCertIdentityExtract(d), policy.Unary()),
	)
	iamv1.RegisterInternalIAMServiceServer(srv, internal_iam.NewHandler(nil, authz).WithModuleRoster(roster))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hopCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, laneFrontSAN)},
		RootCAs:      ca.pool(),
		MinVersion:   tls.VersionTLS12,
	})
	front, err := restfront.NewInternal(ctx, lis.Addr().String(),
		[]grpc.DialOption{grpc.WithTransportCredentials(hopCreds)},
		authzguard.InternalFrontAdmission(true, roster, d))
	require.NoError(t, err)
	hs := httptest.NewUnstartedServer(front)
	hs.TLS = ca.serverTLS(t)
	hs.StartTLS()
	t.Cleanup(hs.Close)

	return &laneWorld{t: t, ca: ca, grpc: lis.Addr().String(), front: hs.URL, authz: authz}
}

// overHTTP — внутренний Check через фронт листом san: код HTTP и тело.
func (w *laneWorld) overHTTP(san, object string) (int, map[string]any) {
	w.t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{w.ca.leaf(w.t, san)},
		RootCAs:      w.ca.pool(),
		MinVersion:   tls.VersionTLS12,
	}}}
	t := w.t
	body, err := json.Marshal(map[string]string{"subjectId": "user:usr_alice", "relation": "viewer", "object": object})
	require.NoError(t, err)
	resp, err := client.Post(w.front+"/iam/v1/internal/iam:check", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "запрос к фронту листом %s", san)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	require.NoErrorf(t, json.Unmarshal(raw, &out), "тело фронта не JSON: %s", raw)
	return resp.StatusCode, out
}

// overGRPC — внутренний Check прямо слушателю листом san: код gRPC.
func (w *laneWorld) overGRPC(san, object string) codes.Code {
	w.t.Helper()
	conn, err := grpc.NewClient(w.grpc, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{w.ca.leaf(w.t, san)},
		RootCAs:      w.ca.pool(),
		MinVersion:   tls.VersionTLS12,
	})))
	require.NoError(w.t, err)
	defer func() { _ = conn.Close() }()
	_, err = iamv1.NewInternalIAMServiceClient(conn).Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_alice", Relation: "viewer", Object: object,
	})
	return status.Code(err)
}

// TestInternalFront_CheckLaneIsNoWiderThanGRPC — SEC-1017-1.
func TestInternalFront_CheckLaneIsNoWiderThanGRPC(t *testing.T) {
	for name, tc := range map[string]struct {
		san, object string
		grpc        codes.Code // исход той же личности на gRPC-полосе
		httpStatus  int
	}{
		"плоскость данных registry о чужом типе": {
			san: laneDataPlaneSAN, object: laneForeignObject, grpc: codes.PermissionDenied, httpStatus: http.StatusForbidden,
		},
		"лист вне перечня": {
			san: laneOutsiderSAN, object: laneOwnObject, grpc: codes.PermissionDenied, httpStatus: http.StatusForbidden,
		},
		// Сужение довода хопу неисполнимо: личности за ним обработчик не видит.
		// Поэтому плоскость данных фронт не пускает вовсе — полоса HTTP уже
		// gRPC-полосы, а не шире.
		"плоскость данных registry о своём типе": {
			san: laneDataPlaneSAN, object: laneOwnObject, grpc: codes.OK, httpStatus: http.StatusForbidden,
		},
		"близнец: край о том же чужом объекте": {
			san: laneEdgeSAN, object: laneForeignObject, grpc: codes.OK, httpStatus: http.StatusOK,
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newLaneWorld(t)

			require.Equal(t, tc.grpc, w.overGRPC(tc.san, tc.object), "gRPC-полоса листа %s", tc.san)
			before := w.authz.calls.Load()
			code, body := w.overHTTP(tc.san, tc.object)
			require.Equalf(t, tc.httpStatus, code, "HTTP-полоса листа %s: %v", tc.san, body)
			if tc.httpStatus == http.StatusOK {
				require.Equal(t, true, body["allowed"], "близнец: ответ решателя")
				require.Equal(t, before+1, w.authz.calls.Load(), "близнец: решатель не спрошен")
				return
			}
			require.EqualValues(t, codes.PermissionDenied, body["code"], "форма отказа фронта")
			require.Equal(t, "permission denied", body["message"], "текст отказа фронта")
			require.Equal(t, before, w.authz.calls.Load(), "решатель спрошен через фронт")
		})
	}
}

// laneCA — тестовый внутренний центр: серверный лист на 127.0.0.1 и
// клиентские листы с URI SAN.
type laneCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newLaneCA(t *testing.T) *laneCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "внутренний центр пробы"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &laneCA{cert: cert, key: key}
}

func (c *laneCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

func (c *laneCA) issue(t *testing.T, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// leaf — клиентский лист с URI SAN san.
func (c *laneCA) leaf(t *testing.T, san string) tls.Certificate {
	t.Helper()
	u, err := url.Parse(san)
	require.NoError(t, err)
	return c.issue(t, &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}})
}

// serverTLS — взаимный TLS слушателя: лист на 127.0.0.1, клиентский лист обязателен.
func (c *laneCA) serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	srv := c.issue(t, &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	return &tls.Config{
		Certificates: []tls.Certificate{srv},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    c.pool(),
		MinVersion:   tls.VersionTLS12,
	}
}

// TestInternalFront_RefusesToBuildWithoutAnAdmission — фронт без названного
// допуска не собирается: молчание значило бы «пускать всех», то есть прежнюю
// дыру.
func TestInternalFront_RefusesToBuildWithoutAnAdmission(t *testing.T) {
	_, err := restfront.NewInternal(context.Background(), "127.0.0.1:1", nil, nil)
	require.EqualError(t, err, "внутренний REST-фронт: допуск предъявителя не назван")
}
