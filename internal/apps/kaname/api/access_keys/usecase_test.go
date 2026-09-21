// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// usecase_test.go — глаголы ключа доступа через подставные порты (iam Ф7,
// PRO-Robotech/kacho#1273; приёмка `access-keys-are-ours.md`). Имена проб
// трассируются к меткам приёмки; каждое отрицание — рядом с положительным
// близнецом. Гонки, потолок оператором базы и откат переноса — интеграционные
// пробы адаптера, здесь их нет.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const (
	rpID      = "iam.example.test"
	origin    = "https://console.iam.example.test"
	freshness = 15 * time.Minute
	alice     = domain.UserID("usr00000000000000a01")
	bob       = domain.UserID("usr00000000000000b02")
)

type harness struct {
	t     *testing.T
	store *fakeStore
	fresh *fakeFreshness
	meth  *fakeMethods
	obs   *recordingObserver
	ops   *fakeOps
	now   time.Time
	deps  access_keys.Deps
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, store: newFakeStore(), fresh: &fakeFreshness{}, meth: &fakeMethods{password: map[domain.UserID]bool{}},
		obs: newObserver(), ops: newFakeOps(), now: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)}
	algs, err := webauthnverify.ParseAlgorithms([]int64{-7, -257, -8})
	require.NoError(t, err)
	h.deps = access_keys.Deps{
		Store: h.store, Freshness: h.fresh, Methods: h.meth,
		Binding:         webauthnverify.Binding{RPID: rpID, Origins: []string{origin}, Algorithms: algs},
		FreshnessWindow: freshness, Observer: h.obs, Now: func() time.Time { return h.now },
	}
	// Оба человека: с паролем, вошедшие только что.
	for _, id := range []domain.UserID{alice, bob} {
		h.store.addUser(id, domain.InviteStatusActive)
		h.meth.password[id] = true
		h.fresh.set(id, h.now)
	}
	return h
}

func (h *harness) ctx() context.Context { return context.Background() }

func (h *harness) beginRegistration(user domain.UserID) access_keys.BeginRegistrationOutput {
	h.t.Helper()
	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(h.t, err)
	out, err := uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: user, Actor: user})
	require.NoError(h.t, err)
	return out
}

func (h *harness) finishRegistration(in access_keys.FinishRegistrationInput) (*operations.Operation, error) {
	h.t.Helper()
	uc, err := access_keys.NewFinishRegistrationUseCase(h.deps, h.ops)
	require.NoError(h.t, err)
	return uc.Execute(h.ctx(), in)
}

// registerKey — Ф7-01 целиком: испытание → результат → операция → строка.
func (h *harness) registerKey(user domain.UserID, a *webauthntest.Authenticator, o webauthntest.RegistrationOptions) (*operations.Operation, error) {
	h.t.Helper()
	ch := h.beginRegistration(user)
	if o.Challenge == nil {
		o.Challenge = ch.Challenge
	}
	if o.Origin == "" {
		o.Origin = origin
	}
	if o.RPID == "" {
		o.RPID = rpID
	}
	cd, att := a.Register(h.t, o)
	op, err := h.finishRegistration(access_keys.FinishRegistrationInput{
		UserID: user, Actor: user, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att,
	})
	if err != nil {
		return nil, err
	}
	return h.ops.await(h.t, op.ID), nil
}

func (h *harness) mustRegister(user domain.UserID, a *webauthntest.Authenticator) domain.AccessKey {
	h.t.Helper()
	op, err := h.registerKey(user, a, webauthntest.RegistrationOptions{})
	require.NoError(h.t, err)
	require.Nil(h.t, op.Error, "операция заведения упала: %v", op.Error)
	k, ok, err := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.NoError(h.t, err)
	require.True(h.t, ok)
	return k
}

func (h *harness) beginAssertion(user domain.UserID) access_keys.BeginAssertionOutput {
	h.t.Helper()
	uc, err := access_keys.NewBeginAssertionUseCase(h.deps)
	require.NoError(h.t, err)
	out, err := uc.Execute(h.ctx(), access_keys.BeginAssertionInput{UserID: user})
	require.NoError(h.t, err)
	return out
}

func (h *harness) finishAssertion(user domain.UserID, as webauthntest.Assertion, handle []byte) (access_keys.FinishAssertionOutput, error) {
	h.t.Helper()
	uc, err := access_keys.NewFinishAssertionUseCase(h.deps)
	require.NoError(h.t, err)
	return uc.Execute(h.ctx(), access_keys.FinishAssertionInput{
		UserID: user, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: handle,
	})
}

// assertWith — Ф7-06 целиком: испытание из сессии user, утверждение ключом a.
func (h *harness) assertWith(user domain.UserID, a *webauthntest.Authenticator, o webauthntest.AssertionOptions) (access_keys.FinishAssertionOutput, error) {
	h.t.Helper()
	if o.Challenge == nil {
		o.Challenge = h.beginAssertion(user).Challenge
	}
	if o.Origin == "" {
		o.Origin = origin
	}
	if o.RPID == "" {
		o.RPID = rpID
	}
	return h.finishAssertion(user, a.Assert(h.t, o), nil)
}

func (h *harness) revoke(user domain.UserID, id string) (*operations.Operation, error) {
	h.t.Helper()
	uc, err := access_keys.NewRevokeUseCase(h.deps, h.ops)
	require.NoError(h.t, err)
	op, err := uc.Execute(h.ctx(), access_keys.RevokeInput{UserID: user, Actor: user, AccessKeyID: id})
	if err != nil {
		return nil, err
	}
	return h.ops.await(h.t, op.ID), nil
}

func (h *harness) list(user domain.UserID) []domain.AccessKey {
	h.t.Helper()
	uc, err := access_keys.NewListUseCase(h.deps)
	require.NoError(h.t, err)
	keys, _, err := uc.Execute(h.ctx(), access_keys.ListInput{UserID: user, PageSize: 50})
	require.NoError(h.t, err)
	return keys
}

func requireCode(t *testing.T, err error, code codes.Code) *status.Status {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидался gRPC-статус, получено %v", err)
	require.Equal(t, code, st.Code(), "код отказа: %v", err)
	return st
}

func requireReason(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	st := requireCode(t, err, code)
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			require.Equal(t, reason, info.GetReason())
			return
		}
	}
	t.Fatalf("признак %s не приклеен: %v", reason, err)
}

// requireFieldViolation — отказ формы фундамента: поле и правило стоят в
// `BadRequest.field_violations`, сообщение — общее «invalid argument».
func requireFieldViolation(t *testing.T, err error) (field, rule string) {
	t.Helper()
	st := requireCode(t, err, codes.InvalidArgument)
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			v := br.GetFieldViolations()[0]
			return v.GetField(), v.GetDescription()
		}
	}
	t.Fatalf("отказ формы без field_violations: %v", err)
	return "", ""
}

func requireUnifiedRefusal(t *testing.T, err error) {
	t.Helper()
	st := requireCode(t, err, codes.InvalidArgument)
	require.Equal(t, access_keys.TextAssertionNotAccepted, st.Message())
	require.Empty(t, st.Details(), "единый отказ подробностей не несёт")
}

// ─── §3.1 церемония регистрации ─────────────────────────────────────────────

// TestAccessKey_F7_01_CeremonyRegistersAKey — положительный близнец §3.1: ключ
// принят (последующее утверждение проходит, ключ в перечне под своим `id`),
// заведение — событием своего вида, ровно одним.
func TestAccessKey_F7_01_CeremonyRegistersAKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	key := h.mustRegister(alice, a)
	require.NoError(t, corevalidate.ResourceID("access key", "ak", string(key.ID)), "свой id проходит маршрутизатор (Ф7-47)")
	require.Equal(t, string(key.ID), string(key.Name), "пустое имя заменено умолчанием от id (Р10)")
	require.NotEqual(t, []byte(alice), key.UserHandle, "рукоятка — не платформенный id: отозвать его из аутентификатора нечем")
	require.Len(t, key.UserHandle, domain.CeremonyHandleBytes, "рукоятка — случайное значение длины нормы §14.6.1")

	out, err := h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err)
	require.Equal(t, alice, out.UserID)

	listed := h.list(alice)
	require.Len(t, listed, 1)
	require.Equal(t, key.ID, listed[0].ID)
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRegistered), 1)
	ev := h.store.auditOf(access_keys.AuditAccessKeyRegistered)[0]
	require.Equal(t, string(key.ID), ev.Payload["access_key_id"])
	require.Equal(t, string(alice), ev.Payload["user_id"])
	require.NotContains(t, ev.Payload, "email")
}

// TestAccessKey_F7_01_NameAndDescriptionAreKept — названное имя и описание
// доезжают до перечня.
func TestAccessKey_F7_01_NameAndDescriptionAreKept(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	ch := h.beginRegistration(alice)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	op, err := h.finishRegistration(access_keys.FinishRegistrationInput{
		UserID: alice, Actor: alice, Name: "moy-noutbuk", Description: "Мой ноутбук",
		CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att,
	})
	require.NoError(t, err)
	require.Nil(t, h.ops.await(t, op.ID).Error)
	listed := h.list(alice)
	require.Len(t, listed, 1)
	require.Equal(t, "moy-noutbuk", string(listed[0].Name))
	require.Equal(t, "Мой ноутбук", string(listed[0].Description))
}

// TestAccessKey_F7_40_RegistrationChallengeNamesSixContractValues — шесть
// величин контракта в выданном испытании, пара «попадает 6 · названо 6».
func TestAccessKey_F7_40_RegistrationChallengeNamesSixContractValues(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ch := h.beginRegistration(alice)
	require.Len(t, ch.Challenge, domain.AccessKeyChallengeBytes)
	require.Equal(t, rpID, ch.RPID)
	require.Equal(t, access_keys.RPDisplayName, ch.RPDisplayName)
	require.NotEmpty(t, ch.RPDisplayName)
	require.Equal(t, []int64{-7, -257, -8}, ch.Algorithms)
	require.Equal(t, access_keys.UserVerificationRegistration, ch.UserVerification)
	require.Equal(t, access_keys.ResidentKey, ch.ResidentKey)
	require.Equal(t, access_keys.Attestation, ch.Attestation)
	require.True(t, ch.CredProps, "запрос расширения свойств удостоверения (Ф7-41)")
	require.Equal(t, h.now.Add(access_keys.ChallengeTTL), ch.ExpiresAt)
	require.Len(t, []byte(ch.UserHandle), domain.CeremonyHandleBytes, "рукоятка церемонии — случайное значение длины нормы §14.6.1")
	require.NotEqual(t, []byte(alice), []byte(ch.UserHandle), "рукоятка церемонии — не платформенный id")
	named, total := access_keys.ContractValuesInRegistrationChallenge(ch)
	require.Equal(t, 6, total)
	require.Equal(t, 6, named)
}

// TestAccessKey_F7_02_ResultOverUnissuedChallengeIsRefused — испытание,
// которого служба не выдавала: отказ с именем состояния, ключ не заведён,
// события нет.
func TestAccessKey_F7_02_ResultOverUnissuedChallengeIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{Challenge: []byte("never issued by the service!!!!!")})
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonChallengeUnknown)
	require.Equal(t, 0, h.store.keyCount(alice))
	require.Empty(t, h.store.auditOf(access_keys.AuditAccessKeyRegistered))
}

// TestAccessKey_F7_03_ChallengeIsSingleUse — тот же результат второй раз:
// отказ «уже предъявлено», второго ключа нет, первый не изменён.
func TestAccessKey_F7_03_ChallengeIsSingleUse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	ch := h.beginRegistration(alice)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	in := access_keys.FinishRegistrationInput{UserID: alice, Actor: alice, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att}
	op, err := h.finishRegistration(in)
	require.NoError(t, err)
	require.Nil(t, h.ops.await(t, op.ID).Error)
	// Повтор — тот же результат; идентификатор удостоверения тоже тот же, но
	// однократность судится РАНЬШЕ уникальности, и отказ называет испытание.
	_, err = h.finishRegistration(in)
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonChallengeConsumed)
	require.Equal(t, 1, h.store.keyCount(alice))
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRegistered), 1)
}

// TestAccessKey_F7_34_ChallengeExpires — управляемые часы: за сроком — отказ
// со следующим шагом; то же испытание внутри срока проходит.
func TestAccessKey_F7_34_ChallengeExpires(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	ch := h.beginRegistration(alice)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	in := access_keys.FinishRegistrationInput{UserID: alice, Actor: alice, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att}
	issued := h.now
	h.now = issued.Add(access_keys.ChallengeTTL + time.Second)
	h.fresh.set(alice, h.now)
	_, err := h.finishRegistration(in)
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonChallengeExpired)
	require.Equal(t, 0, h.store.keyCount(alice))
	h.now = issued.Add(access_keys.ChallengeTTL - time.Second)
	op, err := h.finishRegistration(in)
	require.NoError(t, err, "положительный контроль: внутри срока проходит")
	require.Nil(t, h.ops.await(t, op.ID).Error)
}

// TestAccessKey_F7_04_RegistrationRequiresFreshness — момент последнего
// предъявления старше окна: отказ со следующим шагом; после предъявления —
// проходит.
func TestAccessKey_F7_04_RegistrationRequiresFreshness(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonSessionNotFresh)
	require.Contains(t, err.Error(), "present a credential again")
	require.Equal(t, 1, h.obs.refusal(access_keys.LaneRegistration, access_keys.RefusalSessionNotFresh))
	h.fresh.set(alice, h.now)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	require.NoError(t, err, "окно открывается предъявлением")
	// Свежесть судится и на приёме результата: результат, собранный в окне,
	// не принимается снаружи.
	a := webauthntest.New(t, webauthntest.AlgES256)
	ch := h.beginRegistration(alice)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
	_, err = h.finishRegistration(access_keys.FinishRegistrationInput{UserID: alice, Actor: alice, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att})
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonSessionNotFresh)
	// Живой сессии нет вовсе — предъявления не было.
	h.fresh = &fakeFreshness{}
	h.deps.Freshness = h.fresh
	uc2, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc2.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonSessionNotFresh)
}

// TestAccessKey_F7_05_DuplicateCredentialIDIsRefusedIdentically — тот же `K` у
// того же человека и у другого: отказы побайтово равны; третий — свой — проходит.
func TestAccessKey_F7_05_DuplicateCredentialIDIsRefusedIdentically(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, a)
	same := webauthntest.New(t, webauthntest.AlgES256)
	same.SetCredentialID(a.CredentialID())
	opA, err := h.registerKey(alice, same, webauthntest.RegistrationOptions{})
	require.NoError(t, err)
	require.NotNil(t, opA.Error, "ветвь а: тот же человек")
	other := webauthntest.New(t, webauthntest.AlgES256)
	other.SetCredentialID(a.CredentialID())
	opB, err := h.registerKey(bob, other, webauthntest.RegistrationOptions{})
	require.NoError(t, err)
	require.NotNil(t, opB.Error, "ветвь б: другой человек")
	require.Equal(t, opA.Error.GetCode(), opB.Error.GetCode())
	require.Equal(t, opA.Error.GetMessage(), opB.Error.GetMessage(), "тела двух отказов побайтово равны")
	require.Equal(t, 1, h.store.keyCount(alice))
	require.Equal(t, 0, h.store.keyCount(bob), "ни у кого не переназначен")
	third := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(bob, third)
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRegistered), 2, "отказы событий не породили")
}

// TestAccessKey_F7_35_AlgorithmOutsideTheListIsRefusedOnCeremony — алгоритм
// вне перечня: отказ; из перечня — принимается.
func TestAccessKey_F7_35_AlgorithmOutsideTheListIsRefusedOnCeremony(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	only, err := webauthnverify.ParseAlgorithms([]int64{-7})
	require.NoError(t, err)
	h.deps.Binding.Algorithms = only
	rsa := webauthntest.New(t, webauthntest.AlgRS256)
	_, err = h.registerKey(alice, rsa, webauthntest.RegistrationOptions{})
	requireReason(t, err, codes.InvalidArgument, access_keys.ReasonAlgorithmNotAllowed)
	require.Equal(t, 0, h.store.keyCount(alice))
	require.Equal(t, []int64{-7}, h.beginRegistration(alice).Algorithms, "испытание называло допустимые")
	ec := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, ec)
}

// TestAccessKey_F7_41_DiscoverabilityExtensionHasThreeSides — «не
// обнаруживаемое» — отказ; «обнаруживаемое» и «не сообщено» — принимаются.
func TestAccessKey_F7_41_DiscoverabilityExtensionHasThreeSides(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	no := false
	yes := true
	for _, tc := range []struct {
		name string
		rk   *bool
		ok   bool
	}{{"reported-not-discoverable", &no, false}, {"reported-discoverable", &yes, true}, {"not-reported", nil, true}} {
		a := webauthntest.New(t, webauthntest.AlgES256)
		ch := h.beginRegistration(alice)
		cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
		op, err := h.finishRegistration(access_keys.FinishRegistrationInput{
			UserID: alice, Actor: alice, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att, Discoverable: tc.rk,
		})
		if !tc.ok {
			requireReason(t, err, codes.InvalidArgument, access_keys.ReasonNotDiscoverable)
			continue
		}
		require.NoError(t, err, tc.name)
		require.Nil(t, h.ops.await(t, op.ID).Error, tc.name)
	}
	require.Equal(t, 2, h.store.keyCount(alice))
}

// TestAccessKey_F7_44_CeremonyOriginIsJudgedByTheList — происхождение результата
// вне перечня — отказ; из перечня — принимается; пустой перечень — никого.
func TestAccessKey_F7_44_CeremonyOriginIsJudgedByTheList(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{Origin: "https://other.iam.example.test"})
	requireReason(t, err, codes.InvalidArgument, access_keys.ReasonOriginNotAllowed)
	require.Equal(t, 0, h.store.keyCount(alice))
	h.mustRegister(alice, a)
	h.deps.Binding.Origins = []string{}
	b := webauthntest.New(t, webauthntest.AlgES256)
	_, err = h.registerKey(alice, b, webauthntest.RegistrationOptions{})
	requireReason(t, err, codes.InvalidArgument, access_keys.ReasonOriginNotAllowed)
}

// TestAccessKey_F7_45_CeremonyRPIDHashIsJudged — чужой хэш имени — отказ; свой —
// принимается.
func TestAccessKey_F7_45_CeremonyRPIDHashIsJudged(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{RPID: "other.example.test"})
	requireReason(t, err, codes.InvalidArgument, access_keys.ReasonRPIDMismatch)
	require.Equal(t, 0, h.store.keyCount(alice))
	h.mustRegister(alice, a)
}

// TestAccessKey_F7_48_CeremonyUserPresenceIsJudged — снятый бит присутствия —
// отказ; присутствие без проверки пользователя — принимается.
func TestAccessKey_F7_48_CeremonyUserPresenceIsJudged(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{UserPresentUnset: true, UserVerified: true})
	requireReason(t, err, codes.InvalidArgument, access_keys.ReasonUserNotPresent)
	require.Equal(t, 0, h.store.keyCount(alice))
	op, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{UserVerified: false})
	require.NoError(t, err)
	require.Nil(t, op.Error)
}

// TestAccessKey_F7_46_NameFormAndDescriptionLimit — три входа имени, каждый
// нарушает форму одним фактом; описание в 257 знаков; отказ формы синхронный и
// испытания не гасит — тот же результат с годными полями проходит.
func TestAccessKey_F7_46_NameFormAndDescriptionLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	ch := h.beginRegistration(alice)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	base := access_keys.FinishRegistrationInput{UserID: alice, Actor: alice, CredentialID: a.CredentialID(), ClientDataJSON: cd, AttestationObject: att}
	for _, bad := range []string{"Laptop", "my laptop", "ноутбук"} {
		in := base
		in.Name = bad
		_, err := h.finishRegistration(in)
		field, rule := requireFieldViolation(t, err)
		require.Equal(t, "name", field, "отказ называет поле: %q", bad)
		require.Contains(t, rule, "must match", "отказ называет правило формы: %q", bad)
	}
	in := base
	in.Description = strings.Repeat("я", 257)
	_, err := h.finishRegistration(in)
	field, rule := requireFieldViolation(t, err)
	require.Equal(t, "description", field)
	require.Contains(t, rule, "256")
	require.Equal(t, 0, h.store.keyCount(alice))
	in = base
	in.Name, in.Description = "moy-noutbuk", strings.Repeat("я", 256)
	op, err := h.finishRegistration(in)
	require.NoError(t, err, "испытание не погашено отказом формы; граница 256 включена")
	require.Nil(t, h.ops.await(t, op.ID).Error)
}

// TestAccessKey_F7_37_F7_38_CeilingIsJudgedByTheStore — потолок: ровно потолок
// проходит, сверх — отказ с величиной и следующим шагом; ноль — «не заводить».
func TestAccessKey_F7_37_F7_38_CeilingIsJudgedByTheStore(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	two := int64(2)
	h.store.ceiling = &two
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	op, err := h.registerKey(alice, webauthntest.New(t, webauthntest.AlgES256), webauthntest.RegistrationOptions{})
	require.NoError(t, err)
	require.NotNil(t, op.Error)
	require.Equal(t, int32(codes.ResourceExhausted), op.Error.GetCode())
	require.Contains(t, op.Error.GetMessage(), "limit of 2", "отказ называет действующую величину")
	require.Contains(t, op.Error.GetMessage(), "revoke an access key", "отказ называет следующий шаг")
	require.Equal(t, 2, h.store.keyCount(alice))
	require.Equal(t, 0, h.store.keyCount(bob), "потолок другого человека не расходуется")
	h.mustRegister(bob, webauthntest.New(t, webauthntest.AlgES256))
	zero := int64(0)
	h.store.ceiling = &zero
	op, err = h.registerKey(bob, webauthntest.New(t, webauthntest.AlgES256), webauthntest.RegistrationOptions{})
	require.NoError(t, err)
	require.NotNil(t, op.Error, "ноль — ключей не заводить")
	require.Contains(t, op.Error.GetMessage(), "limit of 0")
	require.Equal(t, 1, h.store.keyCount(bob), "уже принятые не удаляются")
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRegistered), 3, "отказы потолка событий не породили")
}

// TestAccessKey_F7_31_AttestationIsNotStored — результат с аттестацией
// принимается, содержимого аттестации в строке нет; открытый ключ — есть.
func TestAccessKey_F7_31_AttestationIsNotStored(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	op, err := h.registerKey(alice, a, webauthntest.RegistrationOptions{AttestationFormat: "packed"})
	require.NoError(t, err)
	require.Nil(t, op.Error)
	k, ok, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.True(t, ok)
	require.NotEmpty(t, k.PublicKey, "живой близнец")
}

// TestAccessKey_InactiveUserCannotRegister — ключ не заводится заблокированному:
// состояние решает владелец ключа.
func TestAccessKey_InactiveUserCannotRegister(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.addUser(alice, domain.InviteStatusBlocked)
	uc, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.NoError(t, err)
	_, err = uc.Execute(h.ctx(), access_keys.BeginRegistrationInput{UserID: alice, Actor: alice})
	requireCode(t, err, codes.FailedPrecondition)
}

// ─── §3.2, §3.3 утверждение и привязка ──────────────────────────────────────

// TestAccessKey_F7_06_AssertionPassesAndNamesTheCaller — положительный близнец
// §3.2: ответ называет человека, равного вызывающему; момент предъявления
// сдвинулся; флаги — в виде правила Ф11.
func TestAccessKey_F7_06_AssertionPassesAndNamesTheCaller(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	key := h.mustRegister(alice, a)
	require.Nil(t, key.LastUsedAt)
	h.now = h.now.Add(time.Minute)
	out, err := h.assertWith(alice, a, webauthntest.AssertionOptions{UserVerified: true})
	require.NoError(t, err)
	require.Equal(t, alice, out.UserID)
	require.Equal(t, key.ID, out.AccessKeyID)
	require.Equal(t, assurance.KeyAssertion(true, false), out.Presentation)
	after, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.NotNil(t, after.LastUsedAt)
	require.Equal(t, h.now, *after.LastUsedAt)
}

// TestAccessKey_F7_07_F7_09_ForgedAndUnknownAreOneRefusal — подделанная подпись
// и неизвестное удостоверение: один отказ побайтово; момент и счётчик не
// сдвинулись.
func TestAccessKey_F7_07_F7_09_ForgedAndUnknownAreOneRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	a.SetCounter(7)
	key := h.mustRegister(alice, a)
	_, errForged := h.assertWith(alice, a, webauthntest.AssertionOptions{ForgeSignature: true})
	requireUnifiedRefusal(t, errForged)
	stranger := webauthntest.New(t, webauthntest.AlgES256)
	_, errUnknown := h.assertWith(alice, stranger, webauthntest.AssertionOptions{})
	requireUnifiedRefusal(t, errUnknown)
	require.Equal(t, errForged.Error(), errUnknown.Error(), "побайтово равны")
	after, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.Nil(t, after.LastUsedAt)
	require.Equal(t, key.SignCount, after.SignCount)
	require.Equal(t, 1, h.obs.refusal(access_keys.LaneAssertion, access_keys.RefusalSignature))
	require.Equal(t, 1, h.obs.refusal(access_keys.LaneAssertion, access_keys.RefusalUnknownCredential))
}

// TestAccessKey_F7_08_KeyOfTheNamedRowIsVerified — подпись вторым ключом под
// идентификатором первого — единый отказ.
func TestAccessKey_F7_08_KeyOfTheNamedRowIsVerified(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := webauthntest.New(t, webauthntest.AlgES256)
	second := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, first)
	h.mustRegister(alice, second)
	ch := h.beginAssertion(alice)
	as := second.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	as.CredentialID = first.CredentialID()
	_, err := h.finishAssertion(alice, as, nil)
	requireUnifiedRefusal(t, err)
}

// TestAccessKey_F7_42_AssertionChallengeNamesUserVerification — испытание
// предъявления называет требование, равное объявленному, и свои удостоверения.
func TestAccessKey_F7_42_AssertionChallengeNamesUserVerification(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, a)
	ch := h.beginAssertion(alice)
	require.Equal(t, access_keys.UserVerificationAssertion, ch.UserVerification)
	require.Equal(t, rpID, ch.RPID)
	require.Equal(t, [][]byte{a.CredentialID()}, ch.AllowCredentials)
	require.Equal(t, h.now.Add(access_keys.ChallengeTTL), ch.ExpiresAt)
	out, err := h.assertWith(alice, a, webauthntest.AssertionOptions{UserVerified: false})
	require.NoError(t, err, "ключ без проверки пользователя проходит (Ф7-30)")
	require.False(t, out.Presentation.UserVerified())
}

// TestAccessKey_F7_49_AssertionUserPresenceIsJudged — снятый бит присутствия —
// единый отказ; с присутствием без проверки — проход; момент не сдвинулся.
func TestAccessKey_F7_49_AssertionUserPresenceIsJudged(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, a)
	_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{UserPresentUnset: true, UserVerified: true})
	requireUnifiedRefusal(t, err)
	after, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.Nil(t, after.LastUsedAt)
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err)
}

// TestAccessKey_F7_51_ForeignKeyFromOwnSessionIsRefused — ключ второго из
// сессии первого: единый отказ, ничьи моменты не сдвинулись; свой — проходит и
// называет первого.
func TestAccessKey_F7_51_ForeignKeyFromOwnSessionIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ka := webauthntest.New(t, webauthntest.AlgES256)
	kb := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, ka)
	h.mustRegister(bob, kb)
	_, err := h.assertWith(alice, kb, webauthntest.AssertionOptions{UserVerified: true})
	requireUnifiedRefusal(t, err)
	bobKey, _, _ := h.store.KeyByCredentialID(h.ctx(), kb.CredentialID())
	require.Nil(t, bobKey.LastUsedAt)
	out, err := h.assertWith(alice, ka, webauthntest.AssertionOptions{})
	require.NoError(t, err)
	require.Equal(t, alice, out.UserID)
	require.Equal(t, 1, h.obs.refusal(access_keys.LaneAssertion, access_keys.RefusalForeignKey))
}

// TestAccessKey_F7_52_F7_53_F7_54_F7_55_AssertionChallengeIsJudged — четыре
// состояния испытания на утверждении, все — единый отказ; положительные
// контроли внутри.
func TestAccessKey_F7_52_F7_53_F7_54_F7_55_AssertionChallengeIsJudged(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	a.SetCounter(3)
	h.mustRegister(alice, a)
	kb := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(bob, kb)

	// Ф7-52: не выдавалось.
	_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{Challenge: []byte("not issued by the service at all!")})
	requireUnifiedRefusal(t, err)
	before, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.Nil(t, before.LastUsedAt)

	// Ф7-53: повтор того же утверждения — отказ, момент и счётчик от первого,
	// сигнала клонирования нет.
	ch := h.beginAssertion(alice)
	as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	out, err := h.finishAssertion(alice, as, nil)
	require.NoError(t, err)
	require.Equal(t, alice, out.UserID)
	first, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	h.now = h.now.Add(time.Second)
	_, err = h.finishAssertion(alice, as, nil)
	requireUnifiedRefusal(t, err)
	again, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.Equal(t, first.SignCount, again.SignCount)
	require.Equal(t, *first.LastUsedAt, *again.LastUsedAt)
	require.Equal(t, 0, h.obs.signalCount(), "повтор — не клон (Р6 судит только над выданным)")
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err, "новое испытание и новое утверждение проходят")

	// Ф7-54: просрочено — управляемые часы; внутри срока проходит.
	ch = h.beginAssertion(alice)
	issued := h.now
	as = a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	h.now = issued.Add(access_keys.ChallengeTTL + time.Second)
	_, err = h.finishAssertion(alice, as, nil)
	requireUnifiedRefusal(t, err)
	h.now = issued.Add(access_keys.ChallengeTTL - time.Second)
	_, err = h.finishAssertion(alice, as, nil)
	require.NoError(t, err, "внутри срока — проходит")

	// Ф7-55: испытание выдано второму — из сессии первого не находится; второй
	// его же предъявляет и проходит.
	chB := h.beginAssertion(bob)
	asA := a.Assert(t, webauthntest.AssertionOptions{Challenge: chB.Challenge, Origin: origin, RPID: rpID})
	_, err = h.finishAssertion(alice, asA, nil)
	requireUnifiedRefusal(t, err)
	asB := kb.Assert(t, webauthntest.AssertionOptions{Challenge: chB.Challenge, Origin: origin, RPID: rpID})
	outB, err := h.finishAssertion(bob, asB, nil)
	require.NoError(t, err, "испытание не погашено попыткой из чужой сессии")
	require.Equal(t, bob, outB.UserID)
}

// TestAccessKey_F7_10_F7_11_F7_12_BindingIsJudgedOnAssertion — происхождение вне
// перечня и чужое имя доверяющей стороны — единый отказ; возврат объявления —
// проход.
func TestAccessKey_F7_10_F7_11_F7_12_BindingIsJudgedOnAssertion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, a)
	_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{Origin: "https://evil.iam.example.test"})
	requireUnifiedRefusal(t, err)
	h.deps.Binding.RPID = "other.example.test"
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	requireUnifiedRefusal(t, err)
	h.deps.Binding.RPID = rpID
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err, "при возврате объявления тот же ключ проходит")
}

// TestAccessKey_UserHandleIsVerifiedWhenPresented — присланная рукоятка
// сверяется со строкой; чужая — единый отказ; отсутствующая — не судится.
func TestAccessKey_UserHandleIsVerifiedWhenPresented(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	key := h.mustRegister(alice, a)
	// Чужая рукоятка — рукоятка ДРУГОГО человека, а не выдуманные байты: так
	// отрицание меряет сверку, а не длину.
	foreign := h.mustRegister(bob, webauthntest.New(t, webauthntest.AlgES256))
	require.NotEqual(t, key.UserHandle, foreign.UserHandle)
	ch := h.beginAssertion(alice)
	as := a.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: origin, RPID: rpID})
	_, err := h.finishAssertion(alice, as, foreign.UserHandle)
	requireUnifiedRefusal(t, err)
	_, err = h.finishAssertion(alice, as, key.UserHandle)
	require.NoError(t, err)
}

// ─── §3.5 счётчик ───────────────────────────────────────────────────────────

// TestAccessKey_F7_17_F7_18_F7_19_CounterDiscipline — больше — проходит и
// сохраняется; не больше — единый отказ и громкое состояние; ноль при нуле —
// проходит; ноль при положительном — отказ.
func TestAccessKey_F7_17_F7_18_F7_19_CounterDiscipline(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	a.SetCounter(5)
	h.mustRegister(alice, a)
	six := uint32(6)
	_, err := h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &six})
	require.NoError(t, err)
	k, _, _ := h.store.KeyByCredentialID(h.ctx(), a.CredentialID())
	require.Equal(t, uint32(6), k.SignCount, "Ф7-17: сохранённое стало сообщённым")
	same := uint32(6)
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &same})
	requireUnifiedRefusal(t, err)
	require.Equal(t, 1, h.obs.signalCount(), "Ф7-18: громкое состояние")
	zero := uint32(0)
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{SignCount: &zero})
	requireUnifiedRefusal(t, err)
	require.Equal(t, 2, h.obs.signalCount(), "Р6 строка 4: ноль при положительном")

	z := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, z)
	_, err = h.assertWith(alice, z, webauthntest.AssertionOptions{SignCount: &zero})
	require.NoError(t, err, "Ф7-19: ноль не судится")
	_, err = h.assertWith(alice, z, webauthntest.AssertionOptions{SignCount: &zero})
	require.NoError(t, err, "и второй ноль не судится")
	require.Equal(t, 2, h.obs.signalCount())
}

// ─── §3.4 несколько ключей ──────────────────────────────────────────────────

// TestAccessKey_F7_14_SeveralKeysCoexist — второй и третий ключи заводятся, первый
// не изменён и проходит.
func TestAccessKey_F7_14_SeveralKeysCoexist(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := webauthntest.New(t, webauthntest.AlgES256)
	k1 := h.mustRegister(alice, first)
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgRS256))
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgEdDSA))
	require.Len(t, h.list(alice), 3)
	still, _, _ := h.store.KeyByCredentialID(h.ctx(), first.CredentialID())
	require.Equal(t, k1, still)
	_, err := h.assertWith(alice, first, webauthntest.AssertionOptions{})
	require.NoError(t, err)
}

// ─── §3.7 снятие ────────────────────────────────────────────────────────────

// TestAccessKey_F7_25_RevokeRemovesOneKey — снятый перестаёт проходить, второй
// проходит; событие снятия ровно одно.
func TestAccessKey_F7_25_RevokeRemovesOneKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := webauthntest.New(t, webauthntest.AlgES256)
	second := webauthntest.New(t, webauthntest.AlgES256)
	k1 := h.mustRegister(alice, first)
	h.mustRegister(alice, second)
	op, err := h.revoke(alice, string(k1.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error)
	_, err = h.assertWith(alice, first, webauthntest.AssertionOptions{})
	requireUnifiedRefusal(t, err)
	_, err = h.assertWith(alice, second, webauthntest.AssertionOptions{})
	require.NoError(t, err)
	require.Len(t, h.store.auditOf(access_keys.AuditAccessKeyRevoked), 1)
	require.Equal(t, string(k1.ID), h.store.auditOf(access_keys.AuditAccessKeyRevoked)[0].Payload["access_key_id"])
}

// TestAccessKey_F7_26_LastSignInMethodIsNotRevoked — единственный способ —
// ключ: отказ со следующим шагом; с паролем — снимается.
func TestAccessKey_F7_26_LastSignInMethodIsNotRevoked(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.meth.password[alice] = false
	a := webauthntest.New(t, webauthntest.AlgES256)
	k := h.mustRegister(alice, a)
	_, err := h.revoke(alice, string(k.ID))
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonLastSignInMethod)
	require.Contains(t, err.Error(), "enrol another sign-in method")
	_, err = h.assertWith(alice, a, webauthntest.AssertionOptions{})
	require.NoError(t, err, "ключ не снят")
	require.Empty(t, h.store.auditOf(access_keys.AuditAccessKeyRevoked))
	h.meth.password[alice] = true
	op, err := h.revoke(alice, string(k.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error)
}

// TestAccessKey_F7_27_ForeignAndAbsentAreOneRefusal — чужой ключ и несуществующий
// годной формы: отказы побайтово равны, ключ второго на месте.
func TestAccessKey_F7_27_ForeignAndAbsentAreOneRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	kb := webauthntest.New(t, webauthntest.AlgES256)
	bobKey := h.mustRegister(bob, kb)
	_, errForeign := h.revoke(alice, string(bobKey.ID))
	requireCode(t, errForeign, codes.NotFound)
	_, errAbsent := h.revoke(alice, "ak-0000000000000000z")
	requireCode(t, errAbsent, codes.NotFound)
	require.Equal(t, strings.ReplaceAll(errForeign.Error(), string(bobKey.ID), "X"),
		strings.ReplaceAll(errAbsent.Error(), "ak-0000000000000000z", "X"), "форма отказов одна")
	_, errOther := h.revoke(alice, "usr00000000000000c03")
	requireCode(t, errOther, codes.NotFound)
	require.Equal(t, 1, h.store.keyCount(bob))
}

// TestAccessKey_F7_36_RevokeRequiresFreshness — окно свежести на снятии: отказ
// со следующим шагом, оба ключа на месте; после предъявления — снимается.
func TestAccessKey_F7_36_RevokeRequiresFreshness(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	first := webauthntest.New(t, webauthntest.AlgES256)
	second := webauthntest.New(t, webauthntest.AlgES256)
	k1 := h.mustRegister(alice, first)
	h.mustRegister(alice, second)
	h.fresh.set(alice, h.now.Add(-freshness-time.Minute))
	_, err := h.revoke(alice, string(k1.ID))
	requireReason(t, err, codes.FailedPrecondition, access_keys.ReasonSessionNotFresh)
	require.Equal(t, 2, h.store.keyCount(alice))
	h.fresh.set(alice, h.now)
	op, err := h.revoke(alice, string(k1.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error)
}

// TestAccessKey_F7_47_RevokeJudgesTheIdForm — пустой id — «обязательно»;
// строка без формы — `invalid access key id`; годная чужого типа — полоса
// отсутствия; свой — снимается.
func TestAccessKey_F7_47_RevokeJudgesTheIdForm(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := webauthntest.New(t, webauthntest.AlgES256)
	h.mustRegister(alice, webauthntest.New(t, webauthntest.AlgES256))
	k := h.mustRegister(alice, a)
	_, err := h.revoke(alice, "")
	st := requireCode(t, err, codes.InvalidArgument)
	require.Contains(t, st.Message(), "required")
	_, err = h.revoke(alice, "ключ-1")
	st = requireCode(t, err, codes.InvalidArgument)
	require.Equal(t, "invalid access key id 'ключ-1'", st.Message())
	_, err = h.revoke(alice, "usr00000000000000c03")
	requireCode(t, err, codes.NotFound)
	require.Equal(t, 2, h.store.keyCount(alice))
	op, err := h.revoke(alice, string(k.ID))
	require.NoError(t, err)
	require.Nil(t, op.Error)
}

// TestAccessKey_F7_33_RegistrationDoesNotWriteTheSession — глаголы ключа не
// пишут в сессию: у порта записи нет операции предъявления в сессии.
func TestAccessKey_F7_33_RegistrationDoesNotWriteTheSession(t *testing.T) {
	t.Parallel()
	var w access_keys.Writer
	_, presents := w.(interface {
		PresentInSession(context.Context, domain.HumanSessionID, []string, string, domain.BearerDigest, time.Time) error
	})
	require.False(t, presents, "порт записи ключа не пополняет множество предъявленного (Ф7-33)")
}

// TestAccessKey_DepsGuardTheContract — страж зависимостей: срок испытания не
// меньше окна свежести — отказ построения с обеими величинами.
func TestAccessKey_DepsGuardTheContract(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.FreshnessWindow = access_keys.ChallengeTTL
	_, err := access_keys.NewBeginRegistrationUseCase(h.deps)
	require.Error(t, err)
	require.Contains(t, err.Error(), access_keys.ChallengeTTL.String())
	h.deps.FreshnessWindow = freshness
	h.deps.Binding.Origins = nil
	_, err = access_keys.NewBeginRegistrationUseCase(h.deps)
	require.Error(t, err, "неназванный перечень происхождений — отказ построения")
}
