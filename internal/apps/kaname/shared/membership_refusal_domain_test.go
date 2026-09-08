// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// membership_refusal_domain_test.go — отказ «членство несёт права» называет
// ПРОДУКТ, а не платформу (задача продукта #2099, сценарий WIRE-3-01 приёмки
// WIRE-1).
//
// Пара та же, что у соседнего производителя: домен сменился, признак полосы —
// нет.

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

func TestMembershipRefusalCarriesTheProductsOwnDomain(t *testing.T) {
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}

	refused := MapRepoErr(iamerr.Wrapf(iamerr.ErrMembershipCarriesRights,
		"membership carries rights"))

	st, ok := status.FromError(refused)
	if !ok {
		t.Fatalf("отказ не является статусом gRPC: %v", refused)
	}
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			info = ei
		}
	}
	if info == nil {
		t.Fatalf("у отказа нет `ErrorInfo`: %v", refused)
	}

	want := refusaldomain.For(refusaldomain.ServiceIAM)
	if want == "" {
		t.Fatalf("суффикс не объявлен — утверждение о домене беспредметно")
	}
	if got := info.GetDomain(); got != want {
		t.Fatalf("домен отказа = %q, ожидался %q", got, want)
	}
	if got := info.GetReason(); got != reasonMembershipCarriesRights {
		t.Fatalf("признак полосы = %q, ожидался прежний %q", got, reasonMembershipCarriesRights)
	}
	if got := info.GetDomain(); got == "iam.kacho.cloud" {
		t.Fatalf("домен отказа по-прежнему называет платформу: %q", got)
	}
}
