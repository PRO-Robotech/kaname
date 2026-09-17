// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// refusal_bytes_test.go — §3.0/§7 инв. 4: отказы аутентификации на полосе
// утверждения неразличимы ПО ТЕЛУ — четырнадцать полос дают побайтово равный
// ответ (код, текст, подробности). Внесённое различие в один байт у любой
// полосы — красное с именем полосы; равные ответы — молчание. Различимый
// текст был бы оракулом существования и признанности ключа (Р6, Ф7-49).

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestAccessKey_AssertionRefusalBytesAreIdenticalAcrossFourteenLanes — каждая
// полоса производит отказ; все четырнадцать тел равны первому побайтово.
func TestAccessKey_AssertionRefusalBytesAreIdenticalAcrossFourteenLanes(t *testing.T) {
	lanes := []struct {
		id   string
		call func(t *testing.T) error
	}{
		{"Ф7-07 подделанная подпись", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{ForgeSignature: true})
			return err
		}},
		{"Ф7-08 подпись не тем ключом под названным идентификатором", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			other := webauthntest.New(t, webauthntest.AlgES256)
			other.SetCredentialID(a.CredentialID())
			_, err := h.assertWith(alice, other, webauthntest.AssertionOptions{})
			return err
		}},
		{"Ф7-09 неизвестное удостоверение", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{})
			return err
		}},
		{"Ф7-10 происхождение вне перечня", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{Origin: "https://evil.iam.example.test"})
			return err
		}},
		{"Ф7-11 происхождение решает перечень, а не заголовок", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{Origin: "https://console.iam.example.test:8443"})
			return err
		}},
		{"Ф7-12 чужое имя доверяющей стороны", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{RPID: "other.example.test"})
			return err
		}},
		{"Ф7-18 счётчик не вырос", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			six := uint32(6)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &six})
			require.NoError(t, err, "первое утверждение сдвигает счётчик до 6")
			_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &six})
			return err
		}},
		{"Ф7-20 ветвь б: проигравший конкуренции", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			k := h.mustRegister(alice, a)
			h.store.beforeAdvance = func() {
				h.store.mu.Lock()
				row := h.store.keys[k.ID]
				row.SignCount = 7 // сосед успел раньше
				h.store.keys[k.ID] = row
				h.store.mu.Unlock()
			}
			six := uint32(6)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &six})
			return err
		}},
		{"Ф7-49 бит присутствия снят", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{UserPresentUnset: true, UserVerified: true})
			return err
		}},
		{"Ф7-51 чужой ключ из своей сессии", func(t *testing.T) error {
			h := newHarness(t)
			kb := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(bob, kb)
			_, err := h.assertWith(alice, kb, webauthntest.AssertionOptions{})
			return err
		}},
		{"Ф7-52 испытание не выдавалось", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{Challenge: []byte("not issued by the service at all!")})
			return err
		}},
		{"Ф7-53 повтор утверждения", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			ch := h.beginAssertion(alice)
			as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
			_, err := h.finishAssertion(alice, as, nil)
			require.NoError(t, err)
			_, err = h.finishAssertion(alice, as, nil)
			return err
		}},
		{"Ф7-54 испытание просрочено", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			ch := h.beginAssertion(alice)
			as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
			h.now = h.now.Add(access_keys.ChallengeTTL + time.Second)
			_, err := h.finishAssertion(alice, as, nil)
			return err
		}},
		{"Ф7-55 испытание выдано в другой сессии", func(t *testing.T) error {
			h := newHarness(t)
			a := webauthntest.New(t, webauthntest.AlgES256)
			h.mustRegister(alice, a)
			chB := h.beginAssertion(bob)
			as := a.Assert(t, webauthntest.AssertionOptions{Challenge: chB.Challenge, Origin: origin, RPID: rpID})
			_, err := h.finishAssertion(alice, as, nil)
			return err
		}},
	}
	require.Len(t, lanes, 14, "полос четырнадцать (§8)")

	var first []byte
	for _, lane := range lanes {
		err := lane.call(t)
		require.Error(t, err, "%s: отказа не было", lane.id)
		st, ok := status.FromError(err)
		require.True(t, ok, "%s: не gRPC-статус: %v", lane.id, err)
		body, merr := proto.Marshal(st.Proto())
		require.NoError(t, merr)
		if first == nil {
			first = body
			continue
		}
		require.Equal(t, first, body, "%s: тело отказа отличается от первой полосы — оракул", lane.id)
	}
	t.Logf("перепись: полос %d · равных тел %d · байт в теле %d", len(lanes), len(lanes), len(first))
}
