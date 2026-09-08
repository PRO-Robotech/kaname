// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles_test

// refusal_domain_test.go — отказ применителя называет ПРОДУКТ, а не платформу
// (задача продукта #2099, сценарий WIRE-3-01 приёмки WIRE-1).
//
// Пара, а не одно утверждение: рядом с доменом проверяется, что признак полосы
// НЕ ИЗМЕНИЛСЯ. Клиент ключуется на признак, и менять его вместе с доменом
// значило бы сломать привязку дважды за одно изменение — приёмка требует ровно
// обратного.

import (
	"context"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

func TestRefusalCarriesTheProductsOwnDomain(t *testing.T) {
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}

	_, err := applierUnderTest(t, newStore()).Apply(context.Background(),
		clusterManifest("vpc", "vpc.network.admin",
			[]manifest.Rule{{Module: "compute", Resources: []string{"disk"}, Classes: []string{"get"}}}),
		moduleroles.BootActorID)
	if err == nil {
		t.Fatalf("правило называет снятый тип — применение обязано отказать")
	}

	info := errorInfoOf(t, err)
	want := refusaldomain.For(refusaldomain.ServiceIAM)
	if want == "" {
		t.Fatalf("суффикс не объявлен — утверждение о домене беспредметно")
	}
	if got := info.GetDomain(); got != want {
		t.Fatalf("домен отказа = %q, ожидался %q", got, want)
	}
	// Половина «признак не менялся»: без неё домен мог бы приехать вместе с
	// новым токеном, и клиент потерял бы привязку, которую мы обещали сохранить.
	if got := info.GetReason(); got != moduleroles.LaneRejectedByDomain {
		t.Fatalf("признак полосы = %q, ожидался прежний %q", got, moduleroles.LaneRejectedByDomain)
	}
	// И половина «домен перестал называть платформу»: без неё проба зеленела бы
	// на объявлении, вернувшем прежний суффикс.
	if got := info.GetDomain(); got == "iam.kacho.cloud" {
		t.Fatalf("домен отказа по-прежнему называет платформу: %q", got)
	}
}

// errorInfoOf — машинный признак отказа.
func errorInfoOf(t *testing.T, err error) *errdetails.ErrorInfo {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ не является статусом gRPC: %v", err)
	}
	for _, d := range st.Details() {
		if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			return ei
		}
	}
	t.Fatalf("у отказа нет `ErrorInfo`: %v", err)
	return nil
}
