// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

// positionlostdomain_test.go — отказ «позиция утрачена» называет ПРОДУКТ, а не
// платформу (задача службы kaname#48, сценарий WIRE-3-01 приёмки WIRE-1).
//
// # Почему проба отдельная, а не строка в круговом проходе
//
// Круговой проход (`positionlost_test.go`) утверждает, что производитель и
// распознаватель сходятся; домен в нём проверен лишь на непустоту — и это
// правильно для его предмета: распознаватель домена не читает вовсе. Предмет
// ЗДЕСЬ другой — чем продукт называет себя перед тем, кто читает пару
// «домен + признак», не разбирая прозы. Слить их значило бы завести пробу,
// падающую по двум разным причинам.
//
// # Пара и её половины
//
// Домен сменился, признак полосы — НЕТ. Клиент ключуется на признак, и менять
// его вместе с доменом значило бы сломать привязку дважды за одно изменение
// (WIRE-3-01, дословно).

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// TestPositionLostCarriesTheProductsOwnDomain — несущее утверждение.
func TestPositionLostCarriesTheProductsOwnDomain(t *testing.T) {
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}

	info := errorInfoOf(t, subjectchange.PositionLost(599))

	want := refusaldomain.For(refusaldomain.ServiceIAM)
	if want == "" {
		t.Fatalf("суффикс не объявлен — утверждение о домене беспредметно")
	}
	if got := info.GetDomain(); got != want {
		t.Fatalf("домен отказа = %q, ожидался %q", got, want)
	}
	if got := info.GetDomain(); got == "iam.kacho.cloud" {
		t.Fatalf("домен отказа по-прежнему называет платформу: %q", got)
	}
	if got := info.GetReason(); got != subjectchange.ReasonPositionLost {
		t.Fatalf("признак полосы = %q, ожидался прежний %q", got, subjectchange.ReasonPositionLost)
	}
}

// TestPositionLostTokenDidNotChangeWithTheDomain — положительный близнец, и он
// несущий: без него «домен сменился» неотличимо от «сменилось всё, и привязка
// клиента сломана дважды».
//
// Значение признака утверждается ДОСЛОВНО, а не сверкой с собственной
// константой: сверка с константой зеленела бы при её переименовании, то есть
// ровно при том, что здесь и запрещено.
func TestPositionLostTokenDidNotChangeWithTheDomain(t *testing.T) {
	if got := subjectchange.ReasonPositionLost; got != "SUBJECT_CHANGE_POSITION_LOST" {
		t.Fatalf("признак полосы = %q, ожидался прежний %q", got, "SUBJECT_CHANGE_POSITION_LOST")
	}

	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}
	if got := errorInfoOf(t, subjectchange.PositionLost(1)).GetReason(); got != "SUBJECT_CHANGE_POSITION_LOST" {
		t.Fatalf("признак полосы на проводе = %q, ожидался прежний %q",
			got, "SUBJECT_CHANGE_POSITION_LOST")
	}
}

// errorInfoOf — деталь отказа либо провал пробы.
func errorInfoOf(t *testing.T, err error) *errdetails.ErrorInfo {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ не является статусом gRPC: %v", err)
	}
	for _, d := range st.Details() {
		if info, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			return info
		}
	}
	t.Fatalf("у отказа нет `ErrorInfo`: %v", err)
	return nil
}
