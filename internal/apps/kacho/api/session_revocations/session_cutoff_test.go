// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// fakeCutoffs — читатель отсечки. Три исхода задаются явно: именно их различение
// и есть предмет RPC.
type fakeCutoffs struct {
	before time.Time
	found  bool
	err    error
	asked  []string
}

func (f *fakeCutoffs) RevokedBefore(_ context.Context, userID string) (time.Time, bool, error) {
	f.asked = append(f.asked, userID)
	return f.before, f.found, f.err
}

// TestSessionCutoffOf_ReportsTheCutoff — отсечка есть: ответ несёт И признак, И
// момент. Признак отдельным полем не для красоты — см. ниже парную пробу.
func TestSessionCutoffOf_ReportsTheCutoff(t *testing.T) {
	at := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	f := &fakeCutoffs{before: at, found: true}
	h := (&Handler{}).WithCutoffReader(f)

	resp, err := h.SessionCutoffOf(context.Background(),
		&iamv1.SessionCutoffOfRequest{UserId: "usr-1"})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if !resp.GetFound() {
		t.Fatal("отсечка есть, а ответ говорит, что её нет")
	}
	if got := resp.GetRevokeBefore().AsTime(); !got.Equal(at) {
		t.Fatalf("момент отсечки %v, ожидался %v", got, at)
	}
	if len(f.asked) != 1 || f.asked[0] != "usr-1" {
		t.Fatalf("спрошено %v, ожидался ровно один вопрос про usr-1", f.asked)
	}
}

// TestSessionCutoffOf_AbsentCutoffIsNotAnError — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ и
// одновременно контракт: отсутствие отзыва — обычное состояние человека, а не
// отсутствие ресурса.
//
// Отвечать на него тоном промаха значило бы утверждать, что человека не
// существует; отвечать ошибкой — заставить край закрыться на каждом, кого никто
// не отзывал.
func TestSessionCutoffOf_AbsentCutoffIsNotAnError(t *testing.T) {
	h := (&Handler{}).WithCutoffReader(&fakeCutoffs{found: false})

	resp, err := h.SessionCutoffOf(context.Background(),
		&iamv1.SessionCutoffOfRequest{UserId: "usr-1"})
	if err != nil {
		t.Fatalf("отсутствие отсечки не ошибка, получено: %v", err)
	}
	if resp.GetFound() {
		t.Fatal("отсечки нет, а ответ говорит, что есть")
	}
	if resp.GetRevokeBefore() != nil {
		t.Fatalf("момент назван при отсутствующей отсечке: %v", resp.GetRevokeBefore())
	}
}

// TestSessionCutoffOf_EmptySubjectIsRefusedByName — пустой субъект отвергается с
// именем поля, а не уезжает в хранилище и не возвращается ответом «отзыва нет».
func TestSessionCutoffOf_EmptySubjectIsRefusedByName(t *testing.T) {
	f := &fakeCutoffs{}
	h := (&Handler{}).WithCutoffReader(f)

	_, err := h.SessionCutoffOf(context.Background(), &iamv1.SessionCutoffOfRequest{UserId: "  "})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("код %s, ожидался INVALID_ARGUMENT", status.Code(err))
	}
	if len(f.asked) != 0 {
		t.Fatalf("хранилище спрошено про пустого субъекта: %v", f.asked)
	}
}

// TestSessionCutoffOf_UnwiredReaderFailsClosed — непровязанный читатель обязан
// ОТКАЗЫВАТЬ, а не отвечать «отсечки нет».
//
// Ответ «нет» от непровязанного читателя для края неотличим от настоящего
// «человека не отзывали» — то есть непровязка молча снимала бы контроль.
func TestSessionCutoffOf_UnwiredReaderFailsClosed(t *testing.T) {
	_, err := (&Handler{}).SessionCutoffOf(context.Background(),
		&iamv1.SessionCutoffOfRequest{UserId: "usr-1"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("код %s, ожидался UNAVAILABLE", status.Code(err))
	}
}

// TestSessionCutoffOf_StoreErrorDoesNotLeak — текст ошибки хранилища несёт
// координаты соединения. Наружу уходит фиксированный текст; утверждается
// СООБЩЕНИЕ, а не только код.
func TestSessionCutoffOf_StoreErrorDoesNotLeak(t *testing.T) {
	const leak = "host=pg-iam.kacho.svc user=kacho_iam dbname=kacho_iam"
	h := (&Handler{}).WithCutoffReader(&fakeCutoffs{err: errors.New(leak)})

	_, err := h.SessionCutoffOf(context.Background(),
		&iamv1.SessionCutoffOfRequest{UserId: "usr-1"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("код %s, ожидался INTERNAL", status.Code(err))
	}
	if msg := status.Convert(err).Message(); msg != "session revocation lookup failed" {
		t.Fatalf("наружу ушёл текст хранилища: %q", msg)
	}
}
