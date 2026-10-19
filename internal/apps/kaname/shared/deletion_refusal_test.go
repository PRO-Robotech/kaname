// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared_test

// deletion_refusal_test.go — признак и metadata отказа снятия по содержимому
// (kaname#725, приёмка `deletion-refusals-name-the-remainder-and-the-step.md`,
// Р3): клиент решает по `reason` и `metadata`, а не по тексту.

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

func deletionErrorInfo(t *testing.T, err error) (*status.Status, *errdetails.ErrorInfo) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("ожидался gRPC-статус, получено %v", err)
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return st, ei
		}
	}
	t.Fatalf("у отказа нет ErrorInfo: %v", err)
	return nil, nil
}

// TestDeletionRefusalCarriesTheFirstHolderInMetadata — DRS-02/DRS-05: код 9,
// текст дословно, `REFERENCE_IN_USE` и `{resource_type, resource_id, remaining}`.
func TestDeletionRefusalCarriesTheFirstHolderInMetadata(t *testing.T) {
	const text = "User usr_u has active access bindings and cannot be deleted: AccessBinding acb_b on account acc_f is revoked by an administrator of that account (active bindings: 1)"
	err := shared.MapRepoErr(iamerr.NamedHold(text, &iamerr.Holder{
		ResourceType: "access_binding", ResourceID: "acb_b", Remaining: 1,
	}))
	st, ei := deletionErrorInfo(t, err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("код = %v; ожидался FAILED_PRECONDITION", st.Code())
	}
	if st.Message() != text {
		t.Fatalf("текст\n got: %q\nwant: %q", st.Message(), text)
	}
	if ei.GetReason() != "REFERENCE_IN_USE" || ei.GetDomain() != refusaldomain.For(refusaldomain.ServiceIAM) {
		t.Fatalf("признак = %q/%q", ei.GetReason(), ei.GetDomain())
	}
	want := map[string]string{"resource_type": "access_binding", "resource_id": "acb_b", "remaining": "1"}
	if len(ei.GetMetadata()) != len(want) {
		t.Fatalf("metadata = %v; ожидалось %v", ei.GetMetadata(), want)
	}
	for k, v := range want {
		if ei.GetMetadata()[k] != v {
			t.Fatalf("metadata[%s] = %q; ожидалось %q (всё: %v)", k, ei.GetMetadata()[k], v, ei.GetMetadata())
		}
	}
}

// TestDeletionRefusalWithoutHolderHasEmptyMetadata — DRS-14: держащего нет —
// признак есть, ключей в metadata нет вовсе (не пустые строки).
func TestDeletionRefusalWithoutHolderHasEmptyMetadata(t *testing.T) {
	const text = "User usr_u has active access bindings and cannot be deleted: nothing holds it now, retry the deletion"
	err := shared.MapRepoErr(iamerr.NamedHold(text, nil))
	st, ei := deletionErrorInfo(t, err)
	if st.Code() != codes.FailedPrecondition || st.Message() != text {
		t.Fatalf("статус = %v %q", st.Code(), st.Message())
	}
	if ei.GetReason() != "REFERENCE_IN_USE" {
		t.Fatalf("признак = %q; ожидался REFERENCE_IN_USE", ei.GetReason())
	}
	if len(ei.GetMetadata()) != 0 {
		t.Fatalf("metadata обязан быть пуст, получено %v", ei.GetMetadata())
	}
}
