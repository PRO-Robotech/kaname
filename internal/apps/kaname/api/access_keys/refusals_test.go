// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// refusals_test.go — тексты отказов глаголов ключа как КОНТРАКТ: каждый отказ,
// который видит вызывающий, называет следующий шаг — кто и что делает дальше
// (kaname#802). Тексты сверяются ЛИТЕРАЛОМ, а не константой: проба на константе
// зеленела бы при любой её правке, а клиент читает байты ответа.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// TestAccessKey_RegistrationRefusalsNameTheNextStep — шесть отказов приёма
// результата регистрации и отказ недоступности службы называют шаг: начать
// регистрацию заново (с чем именно) либо повторить позже. Каждый отказ
// производится настоящим вариантом использования; код и признак — прежние.
func TestAccessKey_RegistrationRefusalsNameTheNextStep(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code codes.Code
		text string
		call func(t *testing.T, h *harness) error
	}{
		{"происхождение вне перечня", codes.InvalidArgument,
			"credential origin is not in the declared list: begin registration again from a declared origin, or ask the operator to declare this origin",
			func(t *testing.T, h *harness) error {
				_, err := h.registerKey(alice, webauthntest.New(t, webauthntest.AlgES256),
					webauthntest.RegistrationOptions{Origin: "https://other.iam.example.test"})
				return err
			}},
		{"чужое имя доверяющей стороны", codes.InvalidArgument,
			"credential was created for another relying party: begin registration again and create the credential for the relying party named in the challenge",
			func(t *testing.T, h *harness) error {
				_, err := h.registerKey(alice, webauthntest.New(t, webauthntest.AlgES256),
					webauthntest.RegistrationOptions{RPID: "other.example.test"})
				return err
			}},
		{"присутствие не подтверждено", codes.InvalidArgument,
			"authenticator did not report user presence: begin registration again and confirm presence on the authenticator",
			func(t *testing.T, h *harness) error {
				_, err := h.registerKey(alice, webauthntest.New(t, webauthntest.AlgES256),
					webauthntest.RegistrationOptions{UserPresentUnset: true, UserVerified: true})
				return err
			}},
		{"алгоритм вне перечня", codes.InvalidArgument,
			"credential public key algorithm is not in the declared list: begin registration again with an algorithm named in the challenge",
			func(t *testing.T, h *harness) error {
				only, err := webauthnverify.ParseAlgorithms([]int64{-7})
				require.NoError(t, err)
				h.deps.Binding.Algorithms = only
				_, err = h.registerKey(alice, webauthntest.New(t, webauthntest.AlgRS256), webauthntest.RegistrationOptions{})
				return err
			}},
		{"удостоверение не обнаруживаемое", codes.InvalidArgument,
			"credential is not discoverable: begin registration again with a discoverable credential",
			func(t *testing.T, h *harness) error {
				no := false
				_, err := h.registerKeyRK(alice, webauthntest.New(t, webauthntest.AlgES256), webauthntest.RegistrationOptions{}, &no)
				return err
			}},
		{"результат негодной формы", codes.InvalidArgument,
			"Illegal argument credential.client_data_json: credential result is malformed: begin registration again",
			func(t *testing.T, h *harness) error {
				a := webauthntest.New(t, webauthntest.AlgES256)
				h.beginRegistration(alice)
				_, err := h.finishRegistration(access_keys.FinishRegistrationInput{UserID: alice, Actor: alice,
					CredentialID: a.CredentialID(), ClientDataJSON: []byte("{not json"), AttestationObject: []byte{0xa0}})
				return err
			}},
		{"служба недоступна", codes.Unavailable,
			"access key service temporarily unavailable: retry later",
			func(t *testing.T, h *harness) error {
				h.store.failWriter = true
				uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
				require.NoError(t, err)
				_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
				return err
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			st := requireCode(t, tc.call(t, h), tc.code)
			require.Equal(t, tc.text, st.Message(), "%s: текст отказа называет следующий шаг", tc.name)
		})
	}
}

// TestAccessKey_AssertionRefusalNamesTheStepOnEveryLane — единый отказ полосы
// утверждения называет шаг «начать утверждение заново» (kaname#757, приёмка
// `access-key-assertion-surfaces-declare-their-difference.md`, Р2): повтор
// погашенного испытания (AKS-06) и подделанная подпись (AKS-07) — побайтово
// один текст, код `INVALID_ARGUMENT`, подробностей нет. Близнецы: новое
// испытание принимает утверждение (AKS-06), испытание, над которым подпись
// отвергнута, живо (AKS-08) — шаг верен на обеих полосах.
func TestAccessKey_AssertionRefusalNamesTheStepOnEveryLane(t *testing.T) {
	t.Parallel()
	const text = "access key assertion is not accepted: begin the assertion again"
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, a)

	// AKS-06: принятое утверждение над испытанием, затем повтор того же.
	ch := h.beginAssertion(alice).Challenge
	as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch, Origin: origin, RPID: rpID})
	_, err := h.finishAssertion(alice, as, nil)
	require.NoError(t, err, "AKS-06: первое утверждение принято")
	_, err = h.finishAssertion(alice, as, nil)
	replay := requireCode(t, err, codes.InvalidArgument)
	require.Equal(t, text, replay.Message(), "AKS-06: отказ повтора называет шаг")
	require.Empty(t, replay.Details(), "AKS-06: единый отказ подробностей не несёт")
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err, "AKS-06 близнец: новое испытание принимает утверждение")

	// AKS-07 и AKS-08: подделанная подпись над живым испытанием c.
	c := h.beginAssertion(alice).Challenge
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{Challenge: c, ForgeSignature: true})
	forged := requireCode(t, err, codes.InvalidArgument)
	require.Equal(t, replay.Proto().String(), forged.Proto().String(), "AKS-07: тело побайтово равно телу повтора")
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{Challenge: c})
	require.NoError(t, err, "AKS-08: испытание после отказа REST живо")
}
