// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// public_chain_bench_test.go — цена цепочки публичного слушателя на ПРАВИЛЬНОЙ
// форме идентификатора (приёмка `non-empty-project-is-not-deleted.md` §11.6,
// §11.7 «число»; условие KE-14 разбора kaname#168).
//
// Цепочку собирает сборщик корня `publicListenerChain` — тот же, что уезжает в
// слушатель, поэтому замер до звена формы и после него отличается ровно этим
// звеном. Вызывающий — служебная учётка, переданная краем по проверенному
// сертификату: так в замер не входит проверка подписи предъявленного
// удостоверения, чей разброс (десятки микросекунд) заслонил бы искомую разницу
// в единицы наносекунд. Решатель разрешает, и дверь кеширует положительный
// ответ — замеряется установившийся путь допущенного вызова.
//
// Сравнение — `benchstat` двух прогонов `-count=10` одним слотом внешнего
// кластера: на коммите до звена формы и после; порог — прирост медианы не
// больше 1000 нс на вызов и ноль новых выделений памяти.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// benchAllowAll — решатель, разрешающий всё: замеряется путь допущенного.
type benchAllowAll struct{}

func (benchAllowAll) Check(context.Context, string, string, string) (bool, error) { return true, nil }

func BenchmarkPublicListenerChain_WellFormedID(b *testing.B) {
	catalog, err := seed.LoadPermissionRegistry(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatalf("каталог прав не загружен: %v", err)
	}
	chain := testPublicChain(b, testPublicChainInputs{catalog: catalog, decider: benchAllowAll{}, prodMode: true})
	ctx := metadata.NewIncomingContext(verifiedCertPeer(b, fwdGatewaySAN), metadata.Pairs(
		grpcsrv.MDKeyPrincipalType, "service_account", grpcsrv.MDKeyPrincipalID, "sva-benchchain000001"))
	req := &iamv1.GetProjectRequest{ProjectId: domain.PrefixProject + "00000000000notfnd"}
	info := &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"}
	handler := func(context.Context, any) (any, error) { return nil, nil }

	// Близнец до замера: вызов обязан дойти до обработчика, иначе замерялся
	// бы отказ, а не путь допущенного.
	if _, err := chain(ctx, req, info, handler); err != nil {
		b.Fatalf("допущенный вызов не дошёл до обработчика — замер беспредметен: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := chain(ctx, req, info, handler); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFormLink_WellFormedID — звено формы В ОДИНОЧКУ с боевым судьёй на
// правильной форме: цена самой ступени без цены места в цепочке (каждое звено
// цепочки gRPC обходится ещё одним замыканием на вызов, и это свойство
// цепочки, а не ступени). Ожидание §11.6 — ноль выделений памяти.
func BenchmarkFormLink_WellFormedID(b *testing.B) {
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: benchAllowAll{}})
	if err != nil {
		b.Fatalf("дверь не собрана: %v", err)
	}
	link, err := door.FormUnary(publicIDForm{})
	if err != nil {
		b.Fatalf("звено формы не собрано: %v", err)
	}
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva-benchchain000001"})
	req := &iamv1.GetProjectRequest{ProjectId: domain.PrefixProject + "00000000000notfnd"}
	info := &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"}
	handler := func(context.Context, any) (any, error) { return nil, nil }
	if _, err := link(ctx, req, info, handler); err != nil {
		b.Fatalf("правильная форма отвергнута звеном — замер беспредметен: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := link(ctx, req, info, handler); err != nil {
			b.Fatal(err)
		}
	}
}
