// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// internal_instance_admission_test.go — ключ лимита внутреннего слушателя —
// экземпляр вызывающего, потолок модуля — отдельным уровнем (kaname#992).
//
// Пробы DoD:
//
//  1. экземпляр A модуля доведён до 429 — экземпляр B того же модуля получает
//     обычный ответ;
//  2. законный близнец: суммарный поток экземпляров сверх потолка модуля — 429.
//
// Допуск собирается ТЕМ ЖЕ построителем и той же обёрткой регистратора, что у
// корня; время заморожено, поэтому вёдра не пополняются между вызовами, и счёт
// токенов точен.

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// capturedRegistrar запоминает дескриптор, который ему отдала обёртка.
type capturedRegistrar struct{ desc *grpc.ServiceDesc }

func (c *capturedRegistrar) RegisterService(sd *grpc.ServiceDesc, _ any) { c.desc = sd }

// instanceCtx — вызов экземпляра модуля vpc с адреса addr.
func instanceCtx(addr string) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 40000}})
	return grpcsrv.WithCertIdentityIn(ctx, grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
}

// TestInternalAdmission_NoisyInstanceDoesNotStarveItsNeighbour — DoD пп. 1–2.
func TestInternalAdmission_NoisyInstanceDoesNotStarveItsNeighbour(t *testing.T) {
	module := grpcsrv.AdmissionLimits{ReadPerSec: 4, MutationPerSec: 4, BurstFactor: 1, InFlight: 100}
	frozen := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	clock := grpcsrv.WithAdmissionClock(func() time.Time { return frozen })
	l, err := newInternalAdmissions(module, instanceAdmissionLimits(module), clock)
	if err != nil {
		t.Fatalf("ограничители не собраны — условие пробы не создано: %v", err)
	}

	reg := &capturedRegistrar{}
	l.internalRegistrar(reg).RegisterService(&grpc.ServiceDesc{
		ServiceName: "kaname.cloud.iam.v1.InternalIAMService",
		Methods: []grpc.MethodDesc{{
			MethodName: "Check",
			Handler: func(_ any, ctx context.Context, _ func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
				final := func(context.Context, any) (any, error) { return "ok", nil }
				if ic == nil {
					return final(ctx, nil)
				}
				return ic(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.InternalIAMService/Check"}, final)
			},
		}},
	}, nil)
	if reg.desc == nil || len(reg.desc.Methods) != 1 {
		t.Fatal("обёртка регистратора не отдала дескриптор — условие пробы не создано")
	}
	call := func(ctx context.Context) error {
		_, err := reg.desc.Methods[0].Handler(nil, ctx, func(any) error { return nil }, nil)
		return err
	}
	exhausted := func(err error) bool { return status.Code(err) == codes.ResourceExhausted }

	a, b, c := instanceCtx("10.0.0.1"), instanceCtx("10.0.0.2"), instanceCtx("10.0.0.3")
	for i := 0; i < 2; i++ {
		if err := call(a); err != nil {
			t.Fatalf("экземпляр A, вызов %d в пределах своего ведра отвергнут: %v", i+1, err)
		}
	}
	if err := call(a); !exhausted(err) {
		t.Fatalf("экземпляр A сверх своего ведра: %v, ожидался ResourceExhausted — шумный экземпляр "+
			"расходует потолок всего модуля", err)
	}
	for i := 0; i < 2; i++ {
		if err := call(b); err != nil {
			t.Fatalf("экземпляр B того же модуля получил отказ после шума A (вызов %d): %v", i+1, err)
		}
	}
	// Близнец: потолок модуля выбран суммой A и B — третий экземпляр со свежим
	// своим ведром получает отказ уровня модуля.
	if err := call(c); !exhausted(err) {
		t.Fatalf("суммарный поток экземпляров сверх потолка модуля: %v, ожидался ResourceExhausted", err)
	}
}

// TestInstanceAdmissionLimits_LeaveHalfOfTheModuleToNeighbours — величины
// уровня экземпляра по умолчанию: половина потолка модуля по каждой оси темпа
// и одновременности, кратность всплеска та же; одновременность не ниже одного.
func TestInstanceAdmissionLimits_LeaveHalfOfTheModuleToNeighbours(t *testing.T) {
	got := instanceAdmissionLimits(grpcsrv.AdmissionLimits{ReadPerSec: 100, MutationPerSec: 20, BurstFactor: 2, InFlight: 64})
	want := grpcsrv.AdmissionLimits{ReadPerSec: 50, MutationPerSec: 10, BurstFactor: 2, InFlight: 32}
	if got != want {
		t.Fatalf("величины экземпляра %v, ожидались %v", got, want)
	}
	if one := instanceAdmissionLimits(grpcsrv.AdmissionLimits{ReadPerSec: 1, MutationPerSec: 1, BurstFactor: 1, InFlight: 1}); one.InFlight != 1 {
		t.Fatalf("одновременность экземпляра %d при потолке модуля 1 — ведро, не пропускающее ни одного запроса", one.InFlight)
	}
}

// TestInstanceSubject_KeysByIdentityAndAddress — ключ экземпляра: личность
// сертификата и адрес пира; без проверенной личности — «не назван».
func TestInstanceSubject_KeysByIdentityAndAddress(t *testing.T) {
	a, b := instanceSubject(instanceCtx("10.0.0.1")), instanceSubject(instanceCtx("10.0.0.2"))
	if a == "" || a == b {
		t.Fatalf("экземпляры одного модуля с разных адресов дали ключи %q и %q", a, b)
	}
	if got := instanceSubject(context.Background()); got != "" {
		t.Fatalf("вызов без проверенной личности дал ключ %q", got)
	}
}
