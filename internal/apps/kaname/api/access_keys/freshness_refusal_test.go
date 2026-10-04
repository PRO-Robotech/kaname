// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// freshness_refusal_test.go — отказ несвежей сессии у глаголов ключа доступа
// (Ф7-04, Ф7-36) — ТОТ ЖЕ отказ, что у полосы второго фактора: `PERMISSION_DENIED`
// / 403, `reason = SESSION_NOT_FRESH`, текст `re-authentication required: present
// a credential again` (приёмка `second-factor-totp-and-recovery-codes.md`, §1.3 —
// Ф11-33 отдаёт код приёмке действия, Р8 его называет; kaname#523).
//
// Пара (HTTP, `code`) — контракт: клиент, ветвящийся по коду, на 400/9 пошёл бы
// «чинить форму или состояние» вместо того, чтобы предъявить удостоверение
// заново. Поэтому проба утверждает ПАРУ — gRPC-код и статус края, — и равенство
// побайтно у всех путей отказа: выдача испытания, приём результата, снятие,
// вызывающий без предъявления. Отказ свежести закрыт в обе стороны (fail-closed):
// момент предъявления не читается — испытание не выдаётся и ключ не снимается.

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestAccessKey_F7_04_F7_36_FreshnessRefusalIsThePermissionDeniedPair — четыре
// пути отказа свежести дают побайтно один статус, и он — пара 403/7 полосы
// второго фактора с тем же текстом, признаком и доменом.
func TestAccessKey_F7_04_F7_36_FreshnessRefusalIsThePermissionDeniedPair(t *testing.T) {
	t.Parallel()
	paths := []struct {
		name string
		call func(t *testing.T) error
	}{
		{"выдача испытания", func(t *testing.T) error {
			h := newHarness(t)
			h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
			uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
			require.NoError(t, err)
			_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
			return err
		}},
		{"вызывающий без предъявления", func(t *testing.T) error {
			h := newHarness(t)
			uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
			require.NoError(t, err)
			_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice})
			return err
		}},
		{"приём результата", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			ch := h.beginRegistration(alice)
			cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
			h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
			_, err := h.finishRegistration(access_keys.FinishRegistrationInput{UserID: alice, Actor: alice,
				CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att})
			return err
		}},
		{"снятие", func(t *testing.T) error {
			h := newHarness(t)
			k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
			h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
			h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
			_, err := h.revoke(alice, string(k.ID))
			return err
		}},
	}
	var first *status.Status
	for _, p := range paths {
		err := p.call(t)
		st := requireCode(t, err, codes.PermissionDenied)
		require.Equal(t, http.StatusForbidden, runtime.HTTPStatusFromCode(st.Code()), "%s: статус края", p.name)
		require.Equal(t, humansession.TextSessionNotFresh, st.Message(), "%s: текст — тот же, что у полосы второго фактора", p.name)
		require.Len(t, st.Details(), 1, "%s: подробность одна — признак", p.name)
		info, ok := st.Details()[0].(*errdetails.ErrorInfo)
		require.True(t, ok, "%s: подробность — ErrorInfo", p.name)
		require.Equal(t, humansession.ReasonSessionNotFresh, info.GetReason(), "%s: признак", p.name)
		require.Equal(t, refusaldomain.For(refusaldomain.ServiceIAM), info.GetDomain(), "%s: домен", p.name)
		if first == nil {
			first = st
			continue
		}
		require.True(t, proto.Equal(first.Proto(), st.Proto()), "%s: отказ свежести различим по телу:\n%v\n%v", p.name, first.Proto(), st.Proto())
	}
}

// TestAccessKey_FreshnessUnreadableIsClosed — момент предъявления не читается:
// испытание не выдаётся, ключ не снимается; отказ — недоступность, а не пропуск.
func TestAccessKey_FreshnessUnreadableIsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	challenges := len(h.store.challenges)
	h.fresh.err = errors.New("session store unreachable")

	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireCode(t, err, codes.Unavailable)
	require.Len(t, h.store.challenges, challenges, "испытание при нечитаемой свежести не выдаётся")

	_, err = h.revoke(alice, string(k.ID))
	requireCode(t, err, codes.Unavailable)
	require.Equal(t, 2, h.store.keyCount(alice), "ключ при нечитаемой свежести не снимается")
}
