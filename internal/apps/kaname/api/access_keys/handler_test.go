// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// handler_test.go — ТРАНСПОРТ шести глаголов ключа доступа (Ф7, kacho#1273):
// разбор запроса → сценарий → форма ответа. Логики здесь нет — она у сценариев
// (usecase_test.go); здесь утверждается то, что видит вызывающий по контракту:
// вызывающий берётся из принципала, а не из тела; испытание отдаётся формой
// церемонии с шестью литералами (Ф7-40, Ф7-42); ответ утверждения называет
// вызывающего и ключ (Ф7-06); формат страницы судится до чтения; малформный
// идентификатор — синхронный отказ первым стейтментом (Ф7-47).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func (h *harness) handler() *access_keys.Handler {
	h.t.Helper()
	hd, err := access_keys.NewHandler(h.deps, h.ops)
	require.NoError(h.t, err)
	return hd
}

func asUser(id domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: string(id)})
}

// TestAccessKeyHandler_AnonymousIsRefusedOnEveryVerb — без принципала ни один
// глагол не отвечает по существу: и четыре глагола под правом, и два
// освобождённых (освобождение — от проверки права, не от аутентификации).
func TestAccessKeyHandler_AnonymousIsRefusedOnEveryVerb(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	ctx := context.Background()
	calls := map[string]func() error{
		"BeginRegistration": func() error {
			_, err := hd.BeginRegistration(ctx, &iamv1.BeginAccessKeyRegistrationRequest{UserId: string(alice)})
			return err
		},
		"FinishRegistration": func() error {
			_, err := hd.FinishRegistration(ctx, &iamv1.FinishAccessKeyRegistrationRequest{UserId: string(alice)})
			return err
		},
		"List": func() error { _, err := hd.List(ctx, &iamv1.ListAccessKeysRequest{UserId: string(alice)}); return err },
		"Revoke": func() error {
			_, err := hd.Revoke(ctx, &iamv1.RevokeAccessKeyRequest{UserId: string(alice), AccessKeyId: "ak-0000000000000000a"})
			return err
		},
		"BeginAssertion":  func() error { _, err := hd.BeginAssertion(ctx, &iamv1.BeginAccessKeyAssertionRequest{}); return err },
		"FinishAssertion": func() error { _, err := hd.FinishAssertion(ctx, &iamv1.FinishAccessKeyAssertionRequest{}); return err },
	}
	for name, call := range calls {
		err := call()
		st, ok := status.FromError(err)
		require.True(t, ok, "%s: ожидался gRPC-статус, получено %v", name, err)
		require.Contains(t, []codes.Code{codes.PermissionDenied, codes.Unauthenticated}, st.Code(), "%s: %v", name, err)
	}
}

// TestAccessKeyHandler_F7_40_ChallengeIsTheCeremonyForm — испытание регистрации
// отдаётся формой `PublicKeyCredentialCreationOptions`: шесть литералов
// контракта на месте, рукоятка — байты `id` человека, срок назван.
func TestAccessKeyHandler_F7_40_ChallengeIsTheCeremonyForm(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	ch, err := hd.BeginRegistration(asUser(alice), &iamv1.BeginAccessKeyRegistrationRequest{UserId: string(alice)})
	require.NoError(t, err)
	require.Len(t, ch.GetChallenge(), domain.AccessKeyChallengeBytes)
	require.Equal(t, rpID, ch.GetRp().GetId())
	require.Equal(t, access_keys.RPDisplayName, ch.GetRp().GetName())
	require.Equal(t, []byte(alice), ch.GetUser().GetId())
	require.NotEmpty(t, ch.GetUser().GetName())
	require.Equal(t, access_keys.UserVerificationRegistration, ch.GetAuthenticatorSelection().GetUserVerification())
	require.Equal(t, access_keys.ResidentKey, ch.GetAuthenticatorSelection().GetResidentKey())
	require.True(t, ch.GetAuthenticatorSelection().GetRequireResidentKey())
	require.Equal(t, access_keys.Attestation, ch.GetAttestation())
	require.True(t, ch.GetExtensions().GetCredProps())
	require.Len(t, ch.GetPubKeyCredParams(), 3)
	for _, p := range ch.GetPubKeyCredParams() {
		require.Equal(t, "public-key", p.GetType())
	}
	require.Equal(t, h.now.Add(access_keys.ChallengeTTL).Unix(), ch.GetExpiresAt().AsTime().Unix())
}

// TestAccessKeyHandler_F7_01_RegistrationRoundTripThroughTheTransport — полный
// круг транспортом: испытание → результат → операция → ключ в перечне под
// своим `id`, имя и описание доехали.
func TestAccessKeyHandler_F7_01_RegistrationRoundTripThroughTheTransport(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	ctx := asUser(alice)
	ch, err := hd.BeginRegistration(ctx, &iamv1.BeginAccessKeyRegistrationRequest{UserId: string(alice)})
	require.NoError(t, err)
	a := webauthntest.New(t, webauthntest.AlgES256)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.GetChallenge(), Origin: origin, RPID: rpID})
	op, err := hd.FinishRegistration(ctx, &iamv1.FinishAccessKeyRegistrationRequest{
		UserId: string(alice), Name: "laptop", Description: "рабочий",
		Credential: &iamv1.RegistrationCredential{Id: a.CredentialID(), ClientDataJson: cd, AttestationObject: att},
	})
	require.NoError(t, err)
	done := h.ops.await(t, op.GetId())
	require.Nil(t, done.Error)
	var resp iamv1.RegisterAccessKeyResponse
	require.NoError(t, done.Response.UnmarshalTo(&resp))
	require.Equal(t, "laptop", resp.GetAccessKey().GetName())
	require.Regexp(t, `^ak-[0-9a-hjkmnp-tv-z]{17}$`, resp.GetAccessKey().GetId())

	list, err := hd.List(ctx, &iamv1.ListAccessKeysRequest{UserId: string(alice), PageSize: 10})
	require.NoError(t, err)
	require.Len(t, list.GetAccessKeys(), 1)
	require.Equal(t, resp.GetAccessKey().GetId(), list.GetAccessKeys()[0].GetId())
	require.Equal(t, "рабочий", list.GetAccessKeys()[0].GetDescription())
}

// TestAccessKeyHandler_CredentialIsRequired — результат церемонии без
// удостоверения — отказ формы, называющий поле, до чтения хранилища.
func TestAccessKeyHandler_CredentialIsRequired(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	_, err := hd.FinishRegistration(asUser(alice), &iamv1.FinishAccessKeyRegistrationRequest{UserId: string(alice), Name: "laptop"})
	st := requireCode(t, err, codes.InvalidArgument)
	require.Contains(t, st.Message(), "credential")
	_, err = hd.FinishAssertion(asUser(alice), &iamv1.FinishAccessKeyAssertionRequest{})
	st = requireCode(t, err, codes.InvalidArgument)
	require.Contains(t, st.Message(), "credential")
}

// TestAccessKeyHandler_F7_47_RevokeJudgesTheIdFormFirst — малформный `id` —
// синхронный `InvalidArgument "invalid access key id '…'"`; годный —
// операция.
func TestAccessKeyHandler_F7_47_RevokeJudgesTheIdFormFirst(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	_, err := hd.Revoke(asUser(alice), &iamv1.RevokeAccessKeyRequest{UserId: string(alice), AccessKeyId: "not-an-id"})
	st := requireCode(t, err, codes.InvalidArgument)
	require.Contains(t, st.Message(), "invalid access key id 'not-an-id'")

	k := h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgRS256))
	op, err := hd.Revoke(asUser(alice), &iamv1.RevokeAccessKeyRequest{UserId: string(alice), AccessKeyId: string(k.ID)})
	require.NoError(t, err)
	done := h.ops.await(t, op.GetId())
	require.Nil(t, done.Error)
	var resp iamv1.RevokeAccessKeyResponse
	require.NoError(t, done.Response.UnmarshalTo(&resp))
	require.Equal(t, string(k.ID), resp.GetAccessKeyId())
}

// TestAccessKeyHandler_ListJudgesThePageFormBeforeReading — мусорный курсор и
// величина страницы вне `[0..1000]` — отказ формы, а не молчаливая обрезка.
func TestAccessKeyHandler_ListJudgesThePageFormBeforeReading(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	_, err := hd.List(asUser(alice), &iamv1.ListAccessKeysRequest{UserId: string(alice), PageSize: 1001})
	requireCode(t, err, codes.InvalidArgument)
	_, err = hd.List(asUser(alice), &iamv1.ListAccessKeysRequest{UserId: string(alice), PageToken: "not-a-cursor"})
	requireCode(t, err, codes.InvalidArgument)
	out, err := hd.List(asUser(alice), &iamv1.ListAccessKeysRequest{UserId: string(alice)})
	require.NoError(t, err)
	require.Empty(t, out.GetAccessKeys())
}

// TestAccessKeyHandler_F7_06_F7_42_AssertionNamesTheCaller — испытание
// предъявления называет требование проверки и удостоверения вызывающего;
// утверждение отвечает человеком, равным вызывающему, ключом и флагами.
func TestAccessKeyHandler_F7_06_F7_42_AssertionNamesTheCaller(t *testing.T) {
	h := newHarness(t)
	hd := h.handler()
	a := webauthntest.New(t, webauthntest.AlgES256)
	k := h.mustRegister(alice, a)

	ch, err := hd.BeginAssertion(asUser(alice), &iamv1.BeginAccessKeyAssertionRequest{})
	require.NoError(t, err)
	require.Equal(t, rpID, ch.GetRpId())
	require.Equal(t, access_keys.UserVerificationAssertion, ch.GetUserVerification())
	require.Len(t, ch.GetAllowCredentials(), 1)
	require.Equal(t, "public-key", ch.GetAllowCredentials()[0].GetType())
	require.Equal(t, a.CredentialID(), ch.GetAllowCredentials()[0].GetId())

	as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.GetChallenge(), Origin: origin, RPID: rpID, UserVerified: true})
	resp, err := hd.FinishAssertion(asUser(alice), &iamv1.FinishAccessKeyAssertionRequest{Credential: &iamv1.AssertionCredential{
		Id: as.CredentialID, ClientDataJson: as.ClientDataJSON, AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
	}})
	require.NoError(t, err)
	require.Equal(t, string(alice), resp.GetUserId())
	require.Equal(t, string(k.ID), resp.GetAccessKeyId())
	require.True(t, resp.GetFlags().GetUserPresent())
	require.True(t, resp.GetFlags().GetUserVerified())

	// Ф7-51: испытание из сессии Боба, ключ Алисы — единый отказ.
	chB, err := hd.BeginAssertion(asUser(bob), &iamv1.BeginAccessKeyAssertionRequest{})
	require.NoError(t, err)
	asB := a.Assert(t, webauthntest.AssertionOptions{Challenge: chB.GetChallenge(), Origin: origin, RPID: rpID})
	_, err = hd.FinishAssertion(asUser(bob), &iamv1.FinishAccessKeyAssertionRequest{Credential: &iamv1.AssertionCredential{
		Id: asB.CredentialID, ClientDataJson: asB.ClientDataJSON, AuthenticatorData: asB.AuthenticatorData, Signature: asB.Signature,
	}})
	requireUnifiedRefusal(t, err)
}
