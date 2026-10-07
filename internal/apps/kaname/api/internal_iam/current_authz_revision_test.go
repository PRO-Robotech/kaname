// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// current_authz_revision_test.go — исходы транспорта метода токена версии прав
// (приёмка NTF-3, Р30 «Производитель токена»; NTF3-179 (г)). Поведение за
// настоящим слушателем — полнота снимка и круг вызывающих — держит проба корня
// `cmd/kaname/current_authz_revision_integration_test.go`; здесь — то, чего она
// не создаёт: дверь отказала не правом, читатель не провязан, база отказала.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// fakeAuthzRevision — дублёр порта чтения токена.
type fakeAuthzRevision struct {
	tok   string
	err   error
	calls int
}

func (f *fakeAuthzRevision) Current(context.Context) (string, error) {
	f.calls++
	return f.tok, f.err
}

func carHandler(gate *fakeGate, rev authzRevisionReader) *Handler {
	h := NewHandler(nil, nil).WithResourceRegistrar(nil, gate)
	if rev != nil {
		h = h.WithAuthzRevision(rev)
	}
	return h
}

func carReason(t *testing.T, err error) string {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.GetReason()
		}
	}
	return ""
}

// Круг пройден — ответ несёт ровно то, что отдал читатель.
func TestCurrentAuthzRevision_InCircleGetsTheReadersToken(t *testing.T) {
	rev := &fakeAuthzRevision{tok: "10:12:10"}
	resp, err := carHandler(&fakeGate{domain: "storage"}, rev).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.NoError(t, err)
	require.Equal(t, "10:12:10", resp.GetAuthzRev())
	require.Equal(t, 1, rev.calls)
}

// Дверь отказала правом — PERMISSION_DENIED с признаком контракта, читатель не
// вызван: вызывающий вне круга не узнаёт и того, что база жива.
func TestCurrentAuthzRevision_OutsideCircleIsRefusedWithTheReason(t *testing.T) {
	rev := &fakeAuthzRevision{tok: "10:12:10"}
	_, err := carHandler(&fakeGate{err: status.Error(codes.PermissionDenied, "permission denied")}, rev).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, "permission denied", status.Convert(err).Message())
	require.Equal(t, "AUTHZ_DENIED", carReason(t, err))
	require.Zero(t, rev.calls, "читатель вызван до решения двери")
}

// Близнец по одному факту: дверь не ответила (база прав недоступна) —
// UNAVAILABLE как есть, без признака отказа в праве.
func TestCurrentAuthzRevision_GateUnavailableIsNotARefusal(t *testing.T) {
	rev := &fakeAuthzRevision{tok: "10:12:10"}
	_, err := carHandler(&fakeGate{err: status.Error(codes.Unavailable, "authz backend unavailable")}, rev).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Empty(t, carReason(t, err))
	require.Zero(t, rev.calls)
}

// Читатель не провязан — fail-closed UNAVAILABLE.
func TestCurrentAuthzRevision_UnwiredReaderFailsClosed(t *testing.T) {
	_, err := carHandler(&fakeGate{domain: "storage"}, nil).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// База отказала — классифицированный отказ без текста драйвера.
func TestCurrentAuthzRevision_StoreRefusalIsClassified(t *testing.T) {
	rev := &fakeAuthzRevision{err: iamerr.Wrapf(iamerr.ErrUnavailable, "dial tcp 10.0.0.7:5432: refused")}
	_, err := carHandler(&fakeGate{domain: "storage"}, rev).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.NotContains(t, status.Convert(err).Message(), "10.0.0.7")

	rev = &fakeAuthzRevision{err: errors.New("pq: relation does not exist")}
	_, err = carHandler(&fakeGate{domain: "storage"}, rev).
		CurrentAuthzRevision(context.Background(), &iamv1.CurrentAuthzRevisionRequest{})
	require.Equal(t, codes.Internal, status.Code(err))
	require.NotContains(t, status.Convert(err).Message(), "relation does not exist")
}
