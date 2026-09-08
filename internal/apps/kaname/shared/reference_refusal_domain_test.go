// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// reference_refusal_domain_test.go — отказ по ссылке называет ПРОДУКТ, а не
// платформу, и берёт домен у СВОЕГО объявления (задача продукта #2099).
//
// Отдельная проба, а не строка в соседней: этот производитель брал домен у
// константы модуля УЧЁТА ВЕЛИЧИН — предмета, который из службы выпиливается
// целиком. То есть до этой правки отказ по ссылке переставал бы собираться
// вместе с чужим модулем, и связь эта нигде не была выражена.

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

func TestReferenceRefusalCarriesTheProductsOwnDomain(t *testing.T) {
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}
	want := refusaldomain.For(refusaldomain.ServiceIAM)
	if want == "" {
		t.Fatalf("суффикс не объявлен — утверждение о домене беспредметно")
	}

	for _, c := range []struct {
		name   string
		err    error
		reason string
	}{
		{"ссылаемого нет", iamerr.Wrapf(iamerr.ErrReferenceMissing, "project not found"), reasonReferenceMissing},
		{"ещё используется", iamerr.Wrapf(iamerr.ErrReferenceInUse, "still referenced"), reasonReferenceInUse},
	} {
		t.Run(c.name, func(t *testing.T) {
			st, ok := status.FromError(MapRepoErr(c.err))
			if !ok {
				t.Fatalf("отказ не является статусом gRPC")
			}
			var info *errdetails.ErrorInfo
			for _, d := range st.Details() {
				if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo {
					info = ei
				}
			}
			if info == nil {
				t.Fatalf("у отказа нет `ErrorInfo`")
			}
			if got := info.GetDomain(); got != want {
				t.Fatalf("домен отказа = %q, ожидался %q", got, want)
			}
			// Признак полосы не менялся: клиент ключуется на него, и менять его
			// вместе с доменом значило бы сломать привязку дважды.
			if got := info.GetReason(); got != c.reason {
				t.Fatalf("признак полосы = %q, ожидался прежний %q", got, c.reason)
			}
		})
	}
}
