// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ntf_grant_fixture_selfcheck_integration_test.go — фикстура проб K5/K3
// судится ОТДЕЛЬНО от предмета: каждое её средство обязано дать свой исход на
// дереве, где предмета нет. Красный здесь — сломанный вопрос, а не отсутствие
// ответа; поэтому самопроверка не трогает ни звена Р2 корня, ни службы выдачи.
package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// ntfPeerSAN — сервер здоровья, записывающий проверенный SAN пира: им
// фикстура доказывает, что лист с точным SAN проходит рукопожатие и личность
// видна слушателю.
type ntfPeerSAN struct {
	healthpb.UnimplementedHealthServer
	saw chan string
}

func (s *ntfPeerSAN) Check(ctx context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	san, _ := grpcsrv.CertIdentityFromContext(ctx)
	if p, ok := peer.FromContext(ctx); ok && p.AuthInfo == nil {
		san = "без-tls"
	}
	s.saw <- san
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func TestNTF1Fixture_EveryMeansHoldsBeforeTheSubjectIsAsked(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: фикстура судится исходом, а не чтением")
	}

	t.Run("лист с точным SAN проходит рукопожатие, личность видна слушателю", func(t *testing.T) {
		cfg, err := ntfConfig(t, "")
		require.NoError(t, err, "фикстура: настройка без ключа не загрузилась")
		pki := newNTFPKI(t)
		rec := &ntfPeerSAN{saw: make(chan string, 1)}
		lis := ntfServe(t, pki, identityUnary(cfg), func(s grpc.ServiceRegistrar) { healthpb.RegisterHealthServer(s, rec) })
		_, err = healthpb.NewHealthClient(lis.dial(t, ntfNotifySAN)).Check(context.Background(), &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		require.Equal(t, ntfNotifySAN, <-rec.saw)
	})

	db := newNTFDB(t)
	door, _ := ntfDoor(db)

	t.Run("журнал операторов видит вопрос двери о ленте с его субъектом", func(t *testing.T) {
		requireWireSeesDoorQuestions(t, db, door)
	})

	t.Run("посев строки F01 заводит читателя ленты", func(t *testing.T) {
		ntfApply(t, db, ntfProbeManifest)
		require.Equal(t, 1, ntfFactCount(t, db, "service:notify", "reader", "notification_feed", "probe"))
	})

	t.Run("посеянный администратор кластера признан дверью", func(t *testing.T) {
		_ = ntfAdminCtx(t, db, door)
	})

	t.Run("таблица операций читается", func(t *testing.T) {
		_ = ntfOperationsCount(t, db)
	})
}
