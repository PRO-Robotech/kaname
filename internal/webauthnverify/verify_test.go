// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify_test

// verify_test.go — проверяющий ключей доступа против подставного
// аутентификатора (iam Ф7, PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`).
//
// Имена проб трассируются к меткам приёмки. Каждое отрицание стоит рядом со
// своим положительным близнецом: подделка, снятая с проверяющего, красит
// отрицание, а не оба.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const (
	rpID   = "iam.example.test"
	origin = "https://console.iam.example.test"
)

var challenge = []byte("0123456789abcdef0123456789abcdef")

func binding(t *testing.T, algs ...int64) webauthnverify.Binding {
	t.Helper()
	if len(algs) == 0 {
		algs = []int64{webauthntest.AlgES256, webauthntest.AlgRS256, webauthntest.AlgEdDSA}
	}
	parsed, err := webauthnverify.ParseAlgorithms(algs)
	require.NoError(t, err)
	return webauthnverify.Binding{RPID: rpID, Origins: []string{origin}, Algorithms: parsed}
}

func register(t *testing.T, a *webauthntest.Authenticator, o webauthntest.RegistrationOptions) (webauthnverify.RegistrationResult, error) {
	t.Helper()
	if o.Challenge == nil {
		o.Challenge = challenge
	}
	if o.Origin == "" {
		o.Origin = origin
	}
	if o.RPID == "" {
		o.RPID = rpID
	}
	cd, att := a.Register(t, o)
	return webauthnverify.VerifyRegistration(webauthnverify.RegistrationInput{
		Challenge: challenge, Binding: binding(t), ClientDataJSON: cd, AttestationObject: att,
	})
}

// TestAccessKey_F7_01_RegistrationResultIsAccepted — положительный близнец
// §3.1 на уровне проверяющего: результат годной церемонии принимается по всем
// трём алгоритмам перечня, и принятое несёт материал строки.
func TestAccessKey_F7_01_RegistrationResultIsAccepted(t *testing.T) {
	t.Parallel()
	for _, alg := range []int64{webauthntest.AlgES256, webauthntest.AlgRS256, webauthntest.AlgEdDSA} {
		a := webauthntest.New(t, alg)
		res, err := register(t, a, webauthntest.RegistrationOptions{})
		require.NoError(t, err, "alg %d", alg)
		require.Equal(t, a.CredentialID(), res.CredentialID)
		require.Equal(t, webauthnverify.Algorithm(alg), res.Algorithm)
		require.Equal(t, a.COSEPublicKey(t), res.PublicKey, "открытый ключ строки — байты COSE как приняты")
		require.True(t, res.Flags.UserPresent)
	}
}

// TestAccessKey_F7_02_ResultOverAnotherChallengeIsRefused — испытание в
// клиентских данных не то, что выдавалось.
func TestAccessKey_F7_02_ResultOverAnotherChallengeIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := register(t, a, webauthntest.RegistrationOptions{Challenge: []byte("some other challenge value here!!")})
	requireRefusal(t, err, webauthnverify.ReasonChallengeMismatch)
}

// TestAccessKey_F7_44_OriginOutsideTheListIsRefused — происхождение решает
// ПЕРЕЧЕНЬ; положительный контроль — тот же результат с происхождением из
// перечня.
func TestAccessKey_F7_44_OriginOutsideTheListIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := register(t, a, webauthntest.RegistrationOptions{Origin: "https://evil.iam.example.test"})
	requireRefusal(t, err, webauthnverify.ReasonOriginNotAllowed)
	_, err = register(t, a, webauthntest.RegistrationOptions{Origin: origin})
	require.NoError(t, err, "положительный контроль: происхождение из перечня принимается")
}

// TestAccessKey_F7_44_EmptyOriginListRefusesEveryone — пустой перечень означает
// «никого» на полосе церемонии тоже (Ф7-13).
func TestAccessKey_F7_44_EmptyOriginListRefusesEveryone(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: challenge, Origin: origin, RPID: rpID})
	b := binding(t)
	b.Origins = nil
	_, err := webauthnverify.VerifyRegistration(webauthnverify.RegistrationInput{Challenge: challenge, Binding: b, ClientDataJSON: cd, AttestationObject: att})
	requireRefusal(t, err, webauthnverify.ReasonOriginNotAllowed)
}

// TestAccessKey_F7_45_ForeignRPIDHashIsRefused — хэш имени доверяющей стороны в
// данных аутентификатора не равен хэшу объявленного.
func TestAccessKey_F7_45_ForeignRPIDHashIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := register(t, a, webauthntest.RegistrationOptions{RPID: "other.example.test"})
	requireRefusal(t, err, webauthnverify.ReasonRPIDHashMismatch)
	_, err = register(t, a, webauthntest.RegistrationOptions{RPID: rpID})
	require.NoError(t, err, "положительный контроль: свой хэш принимается")
}

// TestAccessKey_F7_35_AlgorithmOutsideTheListIsRefused — алгоритм открытого
// ключа вне объявленного перечня; тот же результат при алгоритме из перечня
// принимается.
func TestAccessKey_F7_35_AlgorithmOutsideTheListIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgRS256)
	cd, att := a.Register(t, webauthntest.RegistrationOptions{Challenge: challenge, Origin: origin, RPID: rpID})
	only := binding(t, webauthntest.AlgES256)
	_, err := webauthnverify.VerifyRegistration(webauthnverify.RegistrationInput{Challenge: challenge, Binding: only, ClientDataJSON: cd, AttestationObject: att})
	requireRefusal(t, err, webauthnverify.ReasonAlgorithmNotAllowed)
	_, err = webauthnverify.VerifyRegistration(webauthnverify.RegistrationInput{Challenge: challenge, Binding: binding(t), ClientDataJSON: cd, AttestationObject: att})
	require.NoError(t, err, "положительный контроль: алгоритм из перечня")
}

// TestAccessKey_F7_35_AlgorithmClaimedOutsideTheDictionaryIsRefused — COSE-ключ
// называет алгоритм, которого проверяющий не знает: отказ, а не «прочее».
func TestAccessKey_F7_35_AlgorithmClaimedOutsideTheDictionaryIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	claimed := int64(-36) // ES512 — не в словаре проверяющего
	_, err := register(t, a, webauthntest.RegistrationOptions{ClaimedAlg: &claimed})
	requireRefusal(t, err, webauthnverify.ReasonAlgorithmNotAllowed)
}

// TestAccessKey_F7_48_UserPresentUnsetIsRefusedOnRegistration — бит присутствия
// снят; присутствие без проверки пользователя принимается, проверка без
// присутствия — отказ: продукт читает ДВА бита, а не один.
func TestAccessKey_F7_48_UserPresentUnsetIsRefusedOnRegistration(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := register(t, a, webauthntest.RegistrationOptions{UserPresentUnset: true})
	requireRefusal(t, err, webauthnverify.ReasonUserNotPresent)
	_, err = register(t, a, webauthntest.RegistrationOptions{UserPresentUnset: true, UserVerified: true})
	requireRefusal(t, err, webauthnverify.ReasonUserNotPresent)
	res, err := register(t, a, webauthntest.RegistrationOptions{UserVerified: false})
	require.NoError(t, err, "присутствие без проверки пользователя принимается (Р9)")
	require.False(t, res.Flags.UserVerified)
}

// TestAccessKey_F7_31_AttestationIsNotExpressed — результат с аттестацией
// принимается, а её содержимого в принятом нет: поля для него нет by
// construction (живой близнец: открытый ключ в принятом ЕСТЬ).
func TestAccessKey_F7_31_AttestationIsNotExpressed(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	res, err := register(t, a, webauthntest.RegistrationOptions{AttestationFormat: "packed"})
	require.NoError(t, err, "аттестация не требуется и не проверяется (Р4)")
	require.NotEmpty(t, res.PublicKey, "живой близнец: открытый ключ строка несёт")
	raw, err := json.Marshal(res)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	for k := range fields {
		require.NotContains(t, k, "ttest", "поле аттестации в принятом результате: %s", k)
	}
}

// TestAccessKey_ClientDataTypeMismatchIsRefused — результат церемонии с типом
// утверждения (и наоборот) не принимается: два типа — две процедуры.
func TestAccessKey_ClientDataTypeMismatchIsRefused(t *testing.T) {
	t.Parallel()
	a := webauthntest.New(t, webauthntest.AlgES256)
	_, err := register(t, a, webauthntest.RegistrationOptions{Type: "webauthn.get"})
	requireRefusal(t, err, webauthnverify.ReasonClientDataType)
}

// TestAccessKey_ParseClientData — испытание и происхождение читаются из
// клиентских данных до сверки; форма, которую нельзя разобрать, — отказ формы.
func TestAccessKey_ParseClientData(t *testing.T) {
	t.Parallel()
	cd, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin})
	require.NoError(t, err)
	parsed, err := webauthnverify.ParseClientData(cd)
	require.NoError(t, err)
	require.Equal(t, challenge, parsed.Challenge)
	require.Equal(t, origin, parsed.Origin)
	require.Equal(t, "webauthn.get", parsed.Type)
	_, err = webauthnverify.ParseClientData([]byte("{not json"))
	requireRefusal(t, err, webauthnverify.ReasonMalformed)
	_, err = webauthnverify.ParseClientData([]byte(`{"type":"webauthn.get","challenge":"***","origin":"x"}`))
	requireRefusal(t, err, webauthnverify.ReasonMalformed)
}

// ─── утверждение ────────────────────────────────────────────────────────────

func registered(t *testing.T, alg int64) (*webauthntest.Authenticator, webauthnverify.RegistrationResult) {
	t.Helper()
	a := webauthntest.New(t, alg)
	res, err := register(t, a, webauthntest.RegistrationOptions{})
	require.NoError(t, err)
	return a, res
}

func assert(t *testing.T, a *webauthntest.Authenticator, key webauthnverify.RegistrationResult, o webauthntest.AssertionOptions) (webauthnverify.AssertionResult, error) {
	t.Helper()
	if o.Challenge == nil {
		o.Challenge = challenge
	}
	if o.Origin == "" {
		o.Origin = origin
	}
	if o.RPID == "" {
		o.RPID = rpID
	}
	as := a.Assert(t, o)
	return webauthnverify.VerifyAssertion(webauthnverify.AssertionInput{
		Challenge: challenge, Binding: binding(t),
		ClientDataJSON: as.ClientDataJSON, AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
		PublicKey: key.PublicKey, Algorithm: key.Algorithm,
	})
}

// TestAccessKey_F7_06_GoodAssertionPasses — положительный близнец §3.2 по всем
// трём алгоритмам.
func TestAccessKey_F7_06_GoodAssertionPasses(t *testing.T) {
	t.Parallel()
	for _, alg := range []int64{webauthntest.AlgES256, webauthntest.AlgRS256, webauthntest.AlgEdDSA} {
		a, key := registered(t, alg)
		res, err := assert(t, a, key, webauthntest.AssertionOptions{})
		require.NoError(t, err, "alg %d", alg)
		require.True(t, res.Flags.UserPresent)
	}
}

// TestAccessKey_F7_07_ForgedSignatureIsRefused — подпись не сверяется с
// открытым ключом строки.
func TestAccessKey_F7_07_ForgedSignatureIsRefused(t *testing.T) {
	t.Parallel()
	for _, alg := range []int64{webauthntest.AlgES256, webauthntest.AlgRS256, webauthntest.AlgEdDSA} {
		a, key := registered(t, alg)
		_, err := assert(t, a, key, webauthntest.AssertionOptions{ForgeSignature: true})
		requireRefusal(t, err, webauthnverify.ReasonSignature)
	}
}

// TestAccessKey_F7_08_SignedByAnotherKeyOfTheSamePersonIsRefused — сверяется
// ключ НАЗВАННОЙ строки: подпись вторым ключом под открытым ключом первого.
func TestAccessKey_F7_08_SignedByAnotherKeyOfTheSamePersonIsRefused(t *testing.T) {
	t.Parallel()
	_, first := registered(t, webauthntest.AlgES256)
	second, _ := registered(t, webauthntest.AlgES256)
	_, err := assert(t, second, first, webauthntest.AssertionOptions{})
	requireRefusal(t, err, webauthnverify.ReasonSignature)
}

// TestAccessKey_F7_10_F7_11_OriginIsJudgedByTheListOnAssertion — происхождение
// вне перечня — отказ при любой годности подписи; из перечня — проход.
func TestAccessKey_F7_10_F7_11_OriginIsJudgedByTheListOnAssertion(t *testing.T) {
	t.Parallel()
	a, key := registered(t, webauthntest.AlgES256)
	_, err := assert(t, a, key, webauthntest.AssertionOptions{Origin: "https://evil.iam.example.test"})
	requireRefusal(t, err, webauthnverify.ReasonOriginNotAllowed)
	_, err = assert(t, a, key, webauthntest.AssertionOptions{Origin: origin})
	require.NoError(t, err)
}

// TestAccessKey_F7_12_RPIDBindingIsJudgedOnAssertion — имя доверяющей стороны
// иное — отказ; возврат к прежнему — проход (материал не испорчен).
func TestAccessKey_F7_12_RPIDBindingIsJudgedOnAssertion(t *testing.T) {
	t.Parallel()
	a, key := registered(t, webauthntest.AlgES256)
	as := a.Assert(t, webauthntest.AssertionOptions{Challenge: challenge, Origin: origin, RPID: rpID})
	b := binding(t)
	b.RPID = "other.example.test"
	in := webauthnverify.AssertionInput{Challenge: challenge, Binding: b, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, PublicKey: key.PublicKey, Algorithm: key.Algorithm}
	_, err := webauthnverify.VerifyAssertion(in)
	requireRefusal(t, err, webauthnverify.ReasonRPIDHashMismatch)
	in.Binding = binding(t)
	_, err = webauthnverify.VerifyAssertion(in)
	require.NoError(t, err, "положительный контроль возврата объявления")
}

// TestAccessKey_F7_49_UserPresentUnsetIsRefusedOnAssertion — снятый бит
// присутствия на утверждении; присутствие без проверки пользователя — проход.
func TestAccessKey_F7_49_UserPresentUnsetIsRefusedOnAssertion(t *testing.T) {
	t.Parallel()
	a, key := registered(t, webauthntest.AlgES256)
	_, err := assert(t, a, key, webauthntest.AssertionOptions{UserPresentUnset: true})
	requireRefusal(t, err, webauthnverify.ReasonUserNotPresent)
	_, err = assert(t, a, key, webauthntest.AssertionOptions{UserPresentUnset: true, UserVerified: true})
	requireRefusal(t, err, webauthnverify.ReasonUserNotPresent)
	res, err := assert(t, a, key, webauthntest.AssertionOptions{UserVerified: false})
	require.NoError(t, err)
	require.False(t, res.Flags.UserVerified)
}

// TestAccessKey_F7_28_F7_29_F7_30_FlagsReachTheRuleDistinguishably — оба флага
// различимы; нули — законный вход, а не ошибка чтения.
func TestAccessKey_F7_28_F7_29_F7_30_FlagsReachTheRuleDistinguishably(t *testing.T) {
	t.Parallel()
	a, key := registered(t, webauthntest.AlgES256)
	r1, err := assert(t, a, key, webauthntest.AssertionOptions{UserVerified: true})
	require.NoError(t, err)
	require.True(t, r1.Flags.UserVerified)
	require.False(t, r1.Flags.BackupEligible)
	r2, err := assert(t, a, key, webauthntest.AssertionOptions{UserVerified: true, BackupEligible: true, BackupState: true})
	require.NoError(t, err)
	require.True(t, r2.Flags.BackupEligible)
	require.True(t, r2.Flags.BackupState)
	require.NotEqual(t, r1.Flags, r2.Flags, "флаги доезжают различимо (Ф7-28 против Ф7-29)")
	r3, err := assert(t, a, key, webauthntest.AssertionOptions{})
	require.NoError(t, err, "флаги нулями — законное утверждение (Ф7-30)")
	require.Equal(t, webauthnverify.Flags{UserPresent: true}, r3.Flags)
	// «не прочитаны» — состояние ошибки: данные аутентификатора короче формы.
	_, err = webauthnverify.VerifyAssertion(webauthnverify.AssertionInput{
		Challenge: challenge, Binding: binding(t), ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
		AuthenticatorData: []byte{1, 2, 3}, Signature: []byte{1}, PublicKey: key.PublicKey, Algorithm: key.Algorithm,
	})
	requireRefusal(t, err, webauthnverify.ReasonMalformed)
}

// TestAccessKey_F7_17_F7_18_F7_19_CounterRuleIsOneSided — таблица Р6: ноль не
// судится, положительный обязан расти, ноль при положительном сохранённом —
// отказ; проигравший конкуренции здесь не решается (это оператор базы).
func TestAccessKey_F7_17_F7_18_F7_19_CounterRuleIsOneSided(t *testing.T) {
	t.Parallel()
	require.Equal(t, webauthnverify.CounterZeroUnjudged, webauthnverify.JudgeCounter(0, 0), "Ф7-19")
	require.Equal(t, webauthnverify.CounterAdvances, webauthnverify.JudgeCounter(5, 6), "Ф7-17")
	require.Equal(t, webauthnverify.CounterAdvances, webauthnverify.JudgeCounter(0, 1), "первый сдвиг с нуля")
	require.Equal(t, webauthnverify.CounterRegressed, webauthnverify.JudgeCounter(5, 5), "Ф7-18: не больше")
	require.Equal(t, webauthnverify.CounterRegressed, webauthnverify.JudgeCounter(5, 4), "Ф7-18: меньше")
	require.Equal(t, webauthnverify.CounterRegressed, webauthnverify.JudgeCounter(5, 0), "Р6 строка 4: ноль при положительном")
}

// TestAccessKey_AssertionSignCountIsReported — сообщённый счётчик читается из
// данных аутентификатора и отдаётся вызывающему для оператора сдвига.
func TestAccessKey_AssertionSignCountIsReported(t *testing.T) {
	t.Parallel()
	a, key := registered(t, webauthntest.AlgES256)
	n := uint32(41)
	res, err := assert(t, a, key, webauthntest.AssertionOptions{SignCount: &n})
	require.NoError(t, err)
	require.Equal(t, uint32(41), res.SignCount)
}

// TestAccessKey_RPIDHashIsSHA256OfTheName — контроль формы: хэш, который
// сверяет проверяющий, — SHA-256 имени.
func TestAccessKey_RPIDHashIsSHA256OfTheName(t *testing.T) {
	t.Parallel()
	h := sha256.Sum256([]byte(rpID))
	require.Equal(t, h[:], webauthntest.RPIDHash(rpID))
}

// TestAccessKey_ParseAlgorithms — словарь закрыт: неизвестный идентификатор —
// отказ с числом; пустой перечень — отказ.
func TestAccessKey_ParseAlgorithms(t *testing.T) {
	t.Parallel()
	_, err := webauthnverify.ParseAlgorithms([]int64{-7, -35})
	require.Error(t, err)
	require.Contains(t, err.Error(), "-35")
	_, err = webauthnverify.ParseAlgorithms(nil)
	require.Error(t, err)
	got, err := webauthnverify.ParseAlgorithms([]int64{-257, -7})
	require.NoError(t, err)
	require.Equal(t, []webauthnverify.Algorithm{webauthnverify.AlgRS256, webauthnverify.AlgES256}, got)
}

func requireRefusal(t *testing.T, err error, reason webauthnverify.Reason) {
	t.Helper()
	require.Error(t, err)
	var r *webauthnverify.Refusal
	require.True(t, errors.As(err, &r), "ожидался отказ проверяющего, получено %v", err)
	require.Equal(t, reason, r.Reason, "причина отказа: %v", err)
}
