// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verifier_test.go — проверяющий кода по времени (фаза Ф12, задача
// PRO-Robotech/kacho#1281; приёмка `second-factor-totp-and-recovery-codes.md`,
// Р2, Р5; Ф12-21, Ф12-22 в части проверяющего, Ф12-27, Ф12-35 «в», Ф12-39).
//
// КОДЫ ВЫЧИСЛЯЕТ ПРОБА — RFC 6238 из stdlib пробы, не из прод-кода (§8):
// иначе проба и продукт делили бы одну ошибку. Векторы RFC 6238 Приложения B
// (секрет `12345678901234567890`, SHA-1) закрепляют арифметику независимо от
// обоих.
//
// Каждое отрицание — рядом с положительным контролем.
package totpverify_test

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 в параметрах по умолчанию: SHA-1 — контракт приложений-аутентификаторов
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// probeCode — HOTP(секрет, шаг) шестью цифрами, посчитанный пробой.
func probeCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- шаг неотрицателен по построению пробы
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

func wrapper(t *testing.T, keys ...byte) *keywrap.Wrapper {
	t.Helper()
	var ring [][]byte
	for _, k := range keys {
		key := make([]byte, keywrap.KeySize)
		for i := range key {
			key[i] = k
		}
		ring = append(ring, key)
	}
	w, err := keywrap.New(ring...)
	require.NoError(t, err)
	return w
}

func newVerifier(t *testing.T, w *keywrap.Wrapper) *totpverify.Verifier {
	t.Helper()
	v, err := totpverify.New(w)
	require.NoError(t, err)
	return v
}

var probeBase = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

// TestRFC6238VectorsAgreeWithTheProbe — проба и продукт сходятся на векторах
// RFC 6238 (шесть младших цифр восьмизначных векторов Приложения B).
func TestRFC6238VectorsAgreeWithTheProbe(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		step := totpverify.StepAt(time.Unix(c.unix, 0).UTC())
		require.Equal(t, c.want, probeCode(secret, step), "вектор RFC для T=%d", c.unix)
	}
	require.EqualValues(t, 1, totpverify.StepAt(time.Unix(59, 0)))
	require.EqualValues(t, 37037036, totpverify.StepAt(time.Unix(1111111109, 0)))
}

// TestSecretIsTwentyBytesBase32AndNeverPrints — Р2, Р5: 20 байт, base32 без
// дополнения (32 знака), адрес otpauth по контракту; секрет не печатается.
func TestSecretIsTwentyBytesBase32AndNeverPrints(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	b32 := s.Base32()
	require.Len(t, b32, 32)
	require.NotContains(t, b32, "=")
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	require.NoError(t, err)
	require.Len(t, raw, totpverify.SecretBytes)
	require.Equal(t, 20, totpverify.SecretBytes)

	uri := totpverify.OtpauthURI("access.example.invalid", "person@example.invalid", s)
	require.Equal(t, "otpauth://totp/access.example.invalid:person@example.invalid?secret="+b32+
		"&issuer=access.example.invalid&algorithm=SHA1&digits=6&period=30", uri)

	for name, out := range map[string]string{
		"%v": fmt.Sprintf("%v", s), "%s": fmt.Sprintf("%s", s), "%+v": fmt.Sprintf("%+v", s), "%#v": fmt.Sprintf("%#v", s),
	} {
		require.NotContains(t, out, b32, "%s печатает секрет", name)
	}
	other, err := totpverify.NewSecret()
	require.NoError(t, err)
	require.NotEqual(t, b32, other.Base32(), "два секрета подряд различны")
}

// TestWrapHidesTheSecretAndUnwrapsWithAnyKeyOfTheRing — Ф12-39, Ф12-35 «в».
func TestWrapHidesTheSecretAndUnwrapsWithAnyKeyOfTheRing(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	v1 := newVerifier(t, wrapper(t, 1))
	stored, err := v1.Wrap(s)
	require.NoError(t, err)
	material := stored.Reveal()
	require.NotContains(t, material, s.Base32(), "материал не содержит секрет подстрокой")
	raw, err := base64.RawStdEncoding.DecodeString(material)
	require.NoError(t, err)
	require.NotContains(t, string(raw), s.Base32())

	// Перечень K2,K1 открывает записанное под K1; K2 без K1 — нет: не отказ
	// предъявителя, а недоступность.
	v21 := newVerifier(t, wrapper(t, 2, 1))
	step := totpverify.StepAt(probeBase)
	res := v21.Verify(stored, totpverify.NoAcceptedStep(), probeCode(secretBytes(t, s), step), probeBase)
	require.Equal(t, totpverify.OutcomeMatched, res.Outcome)
	require.Equal(t, step, res.Step)

	v2 := newVerifier(t, wrapper(t, 2))
	res = v2.Verify(stored, totpverify.NoAcceptedStep(), probeCode(secretBytes(t, s), step), probeBase)
	require.Equal(t, totpverify.OutcomeMaterialUnreadable, res.Outcome)

	// Положительный контроль: новое заведение под K2 оборачивает K2 и
	// открывается им.
	s2, err := totpverify.NewSecret()
	require.NoError(t, err)
	stored2, err := v2.Wrap(s2)
	require.NoError(t, err)
	res = v2.Verify(stored2, totpverify.NoAcceptedStep(), probeCode(secretBytes(t, s2), step), probeBase)
	require.Equal(t, totpverify.OutcomeMatched, res.Outcome)
}

func secretBytes(t *testing.T, s totpverify.Secret) []byte {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Base32())
	require.NoError(t, err)
	return raw
}

// TestWindowIsPlusMinusOneStep — Ф12-21: t−1, t, t+1 совпадают; t−2, t+2 —
// нет (обе стороны оси).
func TestWindowIsPlusMinusOneStep(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	v := newVerifier(t, wrapper(t, 1))
	stored, err := v.Wrap(s)
	require.NoError(t, err)
	raw := secretBytes(t, s)
	t0 := totpverify.StepAt(probeBase)
	for _, d := range []int64{-1, 0, 1} {
		res := v.Verify(stored, totpverify.NoAcceptedStep(), probeCode(raw, t0+d), probeBase)
		require.Equal(t, totpverify.OutcomeMatched, res.Outcome, "ступень t%+d в окне", d)
		require.Equal(t, t0+d, res.Step, "исход называет ступень предъявленного кода")
	}
	for _, d := range []int64{-2, 2} {
		res := v.Verify(stored, totpverify.NoAcceptedStep(), probeCode(raw, t0+d), probeBase)
		require.Equal(t, totpverify.OutcomeMismatched, res.Outcome, "ступень t%+d за окном", d)
	}
	res := v.Verify(stored, totpverify.NoAcceptedStep(), "000000", probeBase)
	if probeCode(raw, t0) != "000000" && probeCode(raw, t0-1) != "000000" && probeCode(raw, t0+1) != "000000" {
		require.Equal(t, totpverify.OutcomeMismatched, res.Outcome)
	}
}

// TestReplayIsJudgedAgainstTheLastAcceptedStep — Ф12-22: код шага не старше
// последнего принятого отвергается ПОВТОРОМ; исход снаружи один с «не подошёл»
// — различает только клетка.
func TestReplayIsJudgedAgainstTheLastAcceptedStep(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	v := newVerifier(t, wrapper(t, 1))
	stored, err := v.Wrap(s)
	require.NoError(t, err)
	raw := secretBytes(t, s)
	t0 := totpverify.StepAt(probeBase)

	last := totpverify.AcceptedStep(t0)
	res := v.Verify(stored, last, probeCode(raw, t0), probeBase)
	require.Equal(t, totpverify.OutcomeReplayed, res.Outcome, "тот же шаг — повтор")
	res = v.Verify(stored, last, probeCode(raw, t0-1), probeBase)
	require.Equal(t, totpverify.OutcomeReplayed, res.Outcome, "младший шаг — тоже повтор")
	res = v.Verify(stored, last, probeCode(raw, t0+1), probeBase)
	require.Equal(t, totpverify.OutcomeMatched, res.Outcome, "старший шаг в окне — проходит")
	require.Equal(t, t0+1, res.Step)
}

// TestMissingMaterialIsVerifiedAgainstADecoy — Р5, Ф12-33: личность без
// секрета проходит холостую сверку над неизменным холостым секретом; исход —
// «материала нет», не «не подошёл».
func TestMissingMaterialIsVerifiedAgainstADecoy(t *testing.T) {
	v := newVerifier(t, wrapper(t, 1))
	res := v.Verify(domain.LoginVerifier{}, totpverify.NoAcceptedStep(), "123456", probeBase)
	require.Equal(t, totpverify.OutcomeMaterialMissing, res.Outcome)
}

// TestCodeFormIsSixDigits — Н12: форма кода судится до сверки; правило
// объявлено рядом со способом.
func TestCodeFormIsSixDigits(t *testing.T) {
	for _, ok := range []string{"000000", "123456", "999999"} {
		require.True(t, totpverify.IsWellFormedCode(ok), ok)
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 456", "１２３４５６", "123456\n"} {
		require.False(t, totpverify.IsWellFormedCode(bad), "%q", bad)
	}
	// Проверяющий не доверяет форме на входе: малоформенный код — «не подошёл».
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	v := newVerifier(t, wrapper(t, 1))
	stored, err := v.Wrap(s)
	require.NoError(t, err)
	require.Equal(t, totpverify.OutcomeMismatched, v.Verify(stored, totpverify.NoAcceptedStep(), "abc", probeBase).Outcome)
}

// TestOutcomesAreAClosedVocabulary — клетки счётчика заводятся по словарю
// (Ф12-43): у каждого исхода имя, и перечень закрыт.
func TestOutcomesAreAClosedVocabulary(t *testing.T) {
	names := totpverify.OutcomeNames()
	require.ElementsMatch(t, []string{"matched", "mismatched", "replayed", "material-missing", "material-unreadable"}, names)
	require.Contains(t, strings.Join(names, ","), string(totpverify.OutcomeReplayed))
}

// TestNewRefusesAMissingWrapper — проверяющий без обёртки нечем открыть.
func TestNewRefusesAMissingWrapper(t *testing.T) {
	_, err := totpverify.New(nil)
	require.Error(t, err)
}
