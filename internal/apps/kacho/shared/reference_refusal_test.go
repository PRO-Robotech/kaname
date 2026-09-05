// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// reference_refusal_test.go — две стороны отказа по ссылке различимы МАШИННО, а
// не только прозой.
//
// Конвенция запрещает вызывающему разбирать текст сообщения: тон стабилен, но не
// парсибелен. Значит различение, живущее только в прозе, для клиента-программы
// не существует. Полоса едет в `google.rpc.ErrorInfo.reason` — тем же способом,
// каким его уже возит отказ учёта величин.

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

func reasonOf(t *testing.T, err error) (codes.Code, string, string) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("не статус: %v", err)
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return st.Code(), info.GetReason(), st.Message()
		}
	}
	return st.Code(), "", st.Message()
}

func TestReferenceRefusalCarriesItsLane(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason string
		wantText   string
	}{
		{
			name:       "ссылаемого ресурса нет",
			err:        iamerr.Wrapf(iamerr.ErrReferenceMissing, "Account acc_1 not found"),
			wantReason: "REFERENCE_MISSING",
			wantText:   "Account acc_1 not found",
		},
		{
			name:       "ресурс ещё используется",
			err:        iamerr.Wrapf(iamerr.ErrReferenceInUse, "role is in use by access bindings"),
			wantReason: "REFERENCE_IN_USE",
			wantText:   "role is in use by access bindings",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, reason, text := reasonOf(t, MapRepoErr(c.err))
			if code != codes.FailedPrecondition {
				t.Errorf("код = %v; ожидался FAILED_PRECONDITION", code)
			}
			if reason != c.wantReason {
				t.Errorf("признак = %q; ожидался %q", reason, c.wantReason)
			}
			if text != c.wantText {
				t.Errorf("текст = %q; контракт-тон = %q", text, c.wantText)
			}
		})
	}

	t.Run("две полосы несут РАЗНЫЕ признаки", func(t *testing.T) {
		_, a, _ := reasonOf(t, MapRepoErr(iamerr.Wrapf(iamerr.ErrReferenceMissing, "x")))
		_, b, _ := reasonOf(t, MapRepoErr(iamerr.Wrapf(iamerr.ErrReferenceInUse, "x")))
		if a == b {
			t.Fatalf("обе полосы дали один признак %q — машинно они неразличимы", a)
		}
	})
}

// TestPlainFailedPreconditionCarriesNoReferenceLane — положительный контроль в
// обратную сторону. Без него утверждения выше зеленели бы на реализации,
// клеящей признак ссылки КАЖДОМУ отказу предусловия: тогда «REFERENCE_MISSING»
// перестал бы что-либо означать.
func TestPlainFailedPreconditionCarriesNoReferenceLane(t *testing.T) {
	code, reason, _ := reasonOf(t, MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition, "account is not active")))
	if code != codes.FailedPrecondition {
		t.Fatalf("код = %v; ожидался FAILED_PRECONDITION", code)
	}
	if reason != "" {
		t.Fatalf("на отказе, не связанном со ссылкой, стоит признак ссылки %q", reason)
	}
}
