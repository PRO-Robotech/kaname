// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lookup_set_test.go — НАБОР ЗАПАСНЫХ КОДОВ той же дисциплины, что пароль
// (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка Р6; Ф12-23, 24, 26, 27, 32,
// 39 в части проверяющего): чеканится тем же хешером по той же настройке «что
// писать», одна соль на набор, сверка — одно вычисление и сравнение с КАЖДЫМ
// элементом под той же ёмкостью, что пароль; потребление — по значению
// элемента, которое проверяющий вычислил из предъявленного.
package passwordverify_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func setHarness(t *testing.T) (*passwordverify.Hasher, *passwordverify.Verifier, *recordingObserver) {
	t.Helper()
	hasher, err := passwordverify.NewHasher(declaredArgon2id(65536, 3, 4))
	require.NoError(t, err)
	obs := newRecordingObserver()
	verifier, err := passwordverify.New(2, obs)
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy-of-the-probe")
	require.NoError(t, err)
	require.NoError(t, verifier.SetDecoy(decoy))
	return hasher, verifier, obs
}

// TestBackupCodes_TenOfTenCrockfordAndTheirForm — Р6: десять кодов по десять
// знаков алфавита без смешиваемых знаков; форма судится до сверки (Н12).
func TestBackupCodes_TenOfTenCrockfordAndTheirForm(t *testing.T) {
	codes, err := passwordverify.NewBackupCodes()
	require.NoError(t, err)
	require.Len(t, codes, passwordverify.BackupCodeCount)
	require.Equal(t, 10, passwordverify.BackupCodeCount)
	seen := map[string]bool{}
	for _, c := range codes {
		require.Len(t, c, passwordverify.BackupCodeLength)
		require.True(t, passwordverify.IsWellFormedBackupCode(c), c)
		for _, r := range c {
			require.Contains(t, "0123456789ABCDEFGHJKMNPQRSTVWXYZ", string(r), "знак вне алфавита Crockford: %q", c)
		}
		require.False(t, seen[c], "коды набора различны")
		seen[c] = true
	}
	for _, bad := range []string{"", "ABCDEFGH1", "ABCDEFGH123", "ABCDEFGHIJ", "ABCDEFGH1O", "ABCDEFGH1U", "ABCDEFGH1L", "ABCDE FGH1"} {
		require.False(t, passwordverify.IsWellFormedBackupCode(bad), "%q", bad)
	}
	// Строчные буквы — та же форма: приложение человека печатает как хочет.
	require.True(t, passwordverify.IsWellFormedBackupCode(strings.ToLower(codes[0])))
}

// TestHashSet_OneSaltDeclaredFormatNoCodeInMaterial — Р6, Ф12-39: формат и
// параметры настройки «что писать» в значении, соль одна на набор, по элементу
// на код, ни один код в материале не читается.
func TestHashSet_OneSaltDeclaredFormatNoCodeInMaterial(t *testing.T) {
	hasher, verifier, _ := setHarness(t)
	codes, err := passwordverify.NewBackupCodes()
	require.NoError(t, err)
	set, err := hasher.HashSet(codes)
	require.NoError(t, err)
	material := set.Reveal()
	require.True(t, strings.HasPrefix(material, "$argon2id$v=19$m=65536,t=3,p=4$"), material)
	for _, c := range codes {
		require.NotContains(t, material, c)
	}
	size, ok := verifier.SetSize(set)
	require.True(t, ok)
	require.Equal(t, 10, size)

	// Второй набор тех же кодов — другая соль, другой материал.
	again, err := hasher.HashSet(codes)
	require.NoError(t, err)
	require.NotEqual(t, material, again.Reveal())

	// Негодный вход отвергается до чеканки.
	_, err = hasher.HashSet(nil)
	require.Error(t, err)
	_, err = hasher.HashSet([]string{"short"})
	require.Error(t, err)
}

// TestSetMatch_EachCodeOnceOthersRemainAndElementIsConsumable — Ф12-23, 26:
// кандидат вычисляется до замка, сравнивается под замком с каждым элементом;
// совпавший элемент — то, что снимает адаптер; после снятия тот же код —
// «не совпал», прочие годны, остаток считается.
func TestSetMatch_EachCodeOnceOthersRemainAndElementIsConsumable(t *testing.T) {
	hasher, verifier, obs := setHarness(t)
	codes, err := passwordverify.NewBackupCodes()
	require.NoError(t, err)
	set, err := hasher.HashSet(codes)
	require.NoError(t, err)

	cand := verifier.SetCandidate(set, codes[2])
	require.True(t, cand.Ready())
	require.NotEmpty(t, cand.Element())
	require.NotContains(t, cand.Element(), ",", "элемент — без разделителя набора")
	match := verifier.MatchSet(set, cand)
	require.Equal(t, passwordverify.OutcomeMatched, match.Outcome)
	require.Equal(t, 10, match.Remaining, "остаток ДО потребления")
	require.Contains(t, set.Reveal(), ","+cand.Element()+",", "элемент стоит в наборе с обеими запятыми")

	// Снятие элемента — форма адаптера (`replace`), здесь повторена, чтобы
	// доказать однократность на проверяющем.
	consumed, err := domain.NewLoginVerifier(strings.Replace(set.Reveal(), ","+cand.Element()+",", ",", 1))
	require.NoError(t, err)
	size, ok := verifier.SetSize(consumed)
	require.True(t, ok)
	require.Equal(t, 9, size)
	again := verifier.MatchSet(consumed, verifier.SetCandidate(consumed, codes[2]))
	require.Equal(t, passwordverify.OutcomeMismatched, again.Outcome, "второй раз тот же — не совпал")
	require.Equal(t, 9, again.Remaining)
	other := verifier.MatchSet(consumed, verifier.SetCandidate(consumed, codes[7]))
	require.Equal(t, passwordverify.OutcomeMatched, other.Outcome, "прочие годны")

	// Строчные буквы предъявленного — тот же код.
	lower := verifier.MatchSet(consumed, verifier.SetCandidate(consumed, strings.ToLower(codes[5])))
	require.Equal(t, passwordverify.OutcomeMatched, lower.Outcome)

	// Чужой код — не совпал; кандидат от ДРУГОГО набора (другая соль) — не совпал.
	require.Equal(t, passwordverify.OutcomeMismatched, verifier.MatchSet(set, verifier.SetCandidate(set, "ZZZZZZZZZZ")).Outcome)
	foreign, err := hasher.HashSet(codes)
	require.NoError(t, err)
	require.Equal(t, passwordverify.OutcomeMismatched, verifier.MatchSet(foreign, verifier.SetCandidate(set, codes[0])).Outcome)

	// Исчерпанный набор: остаток ноль, ни один код не совпадает.
	empty, err := domain.NewLoginVerifier(set.Reveal()[:strings.LastIndex(set.Reveal(), "$")+2])
	require.NoError(t, err)
	size, ok = verifier.SetSize(empty)
	require.True(t, ok)
	require.Zero(t, size)
	require.Equal(t, passwordverify.OutcomeMismatched, verifier.MatchSet(empty, verifier.SetCandidate(empty, codes[0])).Outcome)

	// Исходы набора в клетки ПРОВЕРЯЮЩЕГО ПАРОЛЯ не идут — их считает полоса по
	// способу (Ф12-43).
	require.Zero(t, obs.count(passwordverify.OutcomeMatched))
	require.Zero(t, obs.count(passwordverify.OutcomeMismatched))
}

// TestSetCandidate_MissingMaterialAndCapacity — Р6, Ф12-32/33: личность без
// набора занимает ту же ёмкость и платит ту же цену (холостой материал);
// исчерпанная ёмкость — преходящий исход, не попытка.
func TestSetCandidate_MissingMaterialAndCapacity(t *testing.T) {
	hasher, verifier, _ := setHarness(t)
	cand := verifier.SetCandidate(domain.LoginVerifier{}, "ABCDEFGH12")
	require.False(t, cand.Ready())
	require.Equal(t, passwordverify.OutcomeMaterialMissing, cand.Refusal())
	require.Empty(t, cand.Element())

	codes, err := passwordverify.NewBackupCodes()
	require.NoError(t, err)
	set, err := hasher.HashSet(codes)
	require.NoError(t, err)
	// Ёмкость 2 занята двумя работами — третья не начинается.
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go verifier.WithCapacity(func() { started <- struct{}{}; <-release })
	}
	<-started
	<-started
	cand = verifier.SetCandidate(set, codes[0])
	require.False(t, cand.Ready())
	require.Equal(t, passwordverify.OutcomeCapacityExhausted, cand.Refusal())
	close(release)

	// Материал не набора (одиночный хеш пароля) — «тело не разбирается», а
	// не совпадение и не паника.
	single, err := hasher.Hash("a-password")
	require.NoError(t, err)
	cand = verifier.SetCandidate(single, codes[0])
	require.False(t, cand.Ready())
	require.Equal(t, passwordverify.OutcomeBodyNotParsable, cand.Refusal())
	_, ok := verifier.SetSize(single)
	require.False(t, ok)
	junk, err := domain.NewLoginVerifier("not-a-set")
	require.NoError(t, err)
	cand = verifier.SetCandidate(junk, codes[0])
	require.False(t, cand.Ready())
	require.Equal(t, passwordverify.OutcomeFormatNotInRegistry, cand.Refusal())
}

// TestSetMeetsDeclared_FloorAndCeilingOfTheRecord — Ф12-39, Б4 круга 1: набор
// ровно на полу записи законен; ниже пола и выше потолка — находка.
func TestSetMeetsDeclared_FloorAndCeilingOfTheRecord(t *testing.T) {
	hasher, verifier, _ := setHarness(t)
	codes, err := passwordverify.NewBackupCodes()
	require.NoError(t, err)
	set, err := hasher.HashSet(codes)
	require.NoError(t, err)
	res := verifier.InspectSet(set)
	require.Equal(t, domain.PasswordHashFormatArgon2id, res.Format)
	require.EqualValues(t, 65536, res.Params[domain.CostParamArgon2Memory])
	require.EqualValues(t, 3, res.Params[domain.CostParamArgon2Iterations])
	require.EqualValues(t, 4, res.Params[domain.CostParamArgon2Parallelism])
	require.Equal(t, passwordverify.OutcomeMismatched, res.Outcome, "разбор без сверки: «читается»")

	// Ниже пола записи — параметры вне области, «тело не разбирается».
	below := strings.Replace(set.Reveal(), "m=65536", fmt.Sprintf("m=%d", 8), 1)
	belowV, err := domain.NewLoginVerifier(below)
	require.NoError(t, err)
	require.Equal(t, passwordverify.OutcomeBodyNotParsable, verifier.InspectSet(belowV).Outcome)
	// Выше потолка — «параметры вне потолка», вычисление не начинается.
	above := strings.Replace(set.Reveal(), "t=3", "t=1000000", 1)
	aboveV, err := domain.NewLoginVerifier(above)
	require.NoError(t, err)
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, verifier.InspectSet(aboveV).Outcome)
}
