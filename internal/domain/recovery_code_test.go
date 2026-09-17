// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// recovery_code_test.go — код восстановления как ПРЕДЪЯВИТЕЛЬ (фаза Ф5, задача
// PRO-Robotech/kacho#1271; Р1): значение выходит ровно двумя путями — свёрткой
// в хранилище и формой для письма; общие пути вывода отдают заглушку либо
// отказ, как у носителя сессии и материала пароля.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecoveryCodeValue_LetterFormAndAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		v, err := NewRecoveryCodeValue()
		require.NoError(t, err)
		letter := v.Letter()
		require.Len(t, letter, RecoveryCodeLength+1, "две группы через дефис: %q", letter)
		require.Equal(t, byte('-'), letter[RecoveryCodeLength/2], "дефис посередине: %q", letter)
		for _, r := range strings.ReplaceAll(letter, "-", "") {
			require.True(t, strings.ContainsRune(recoveryCodeAlphabet, r), "знак %q вне алфавита", r)
		}
		require.False(t, seen[letter], "двести чеканок — двести разных кодов")
		seen[letter] = true
	}
}

func TestRecoveryCodeValue_PresentedFormIsNormalisedToTheSameDigest(t *testing.T) {
	v, err := NewRecoveryCodeValue()
	require.NoError(t, err)
	letter := v.Letter()

	forms := []string{
		letter,
		strings.ToLower(letter),
		strings.ReplaceAll(letter, "-", ""),
		" " + letter + " ",
		strings.ReplaceAll(letter, "-", " "),
	}
	for _, f := range forms {
		require.Equal(t, v.Digest(), PresentedRecoveryCode(f).Digest(), "форма %q обязана давать ту же свёртку", f)
	}
	// Знаки, исключённые из алфавита ради читаемости, при вводе приводятся к
	// своим двойникам (I, L → 1; O → 0): человек, прочитавший «O» как ноль,
	// не получает отказа за нашу же типографику.
	withLookalikes := strings.NewReplacer("1", "I", "0", "O").Replace(letter)
	require.Equal(t, v.Digest(), PresentedRecoveryCode(withLookalikes).Digest())

	other := "X"
	if strings.HasSuffix(letter, "X") {
		other = "Y"
	}
	require.NotEqual(t, v.Digest(), PresentedRecoveryCode(letter[:len(letter)-1]+other).Digest(),
		"положительный контроль нормализации: другой код — другая свёртка")
	require.True(t, PresentedRecoveryCode("").IsZero())
	require.True(t, PresentedRecoveryCode("  - ").IsZero(), "одни разделители — кода нет")
	require.False(t, PresentedRecoveryCode(letter).IsZero())
}

func TestRecoveryCodeValue_DigestIsNotThePresentation(t *testing.T) {
	v, err := NewRecoveryCodeValue()
	require.NoError(t, err)
	d := string(v.Digest())
	require.Len(t, d, 64, "свёртка — SHA-256 шестнадцатерично")
	require.NotEqual(t, v.Digest(), PresentedRecoveryCode(d).Digest(),
		"Ф5-07: свёртка, поданная как код, свёрткой кода не является")
}

func TestRecoveryCodeValue_DoesNotLeakThroughCommonOutputs(t *testing.T) {
	v, err := NewRecoveryCodeValue()
	require.NoError(t, err)
	letter := v.Letter()

	require.NotContains(t, v.String(), letter)
	require.NotContains(t, fmt.Sprint(v), letter)
	require.NotContains(t, fmt.Sprintf("%v %+v %#v %s", v, v, v, v), letter)
	require.NotContains(t, v.LogValue().String(), letter)
	_, jerr := json.Marshal(v)
	require.ErrorIs(t, jerr, ErrRecoveryCodeNotSerializable)
	_, terr := v.MarshalText()
	require.ErrorIs(t, terr, ErrRecoveryCodeNotSerializable)
	var wrapped struct{ Code RecoveryCodeValue }
	wrapped.Code = v
	_, werr := json.Marshal(wrapped)
	require.Error(t, werr, "и вложенным полем значение не сериализуется")
}

func TestRecoveryCode_Validate(t *testing.T) {
	v, err := NewRecoveryCodeValue()
	require.NoError(t, err)
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	good := RecoveryCode{ID: "rcv-1", UserID: "usr-1", Digest: v.Digest(), IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}
	require.NoError(t, good.Validate())

	cases := map[string]func(*RecoveryCode){
		"без id":               func(c *RecoveryCode) { c.ID = "" },
		"без личности":         func(c *RecoveryCode) { c.UserID = "" },
		"без свёртки":          func(c *RecoveryCode) { c.Digest = "" },
		"свёртка не той формы": func(c *RecoveryCode) { c.Digest = "abc" },
		"без момента выдачи":   func(c *RecoveryCode) { c.IssuedAt = time.Time{} },
		"срок не позже выдачи": func(c *RecoveryCode) { c.ExpiresAt = c.IssuedAt },
	}
	for name, mut := range cases {
		c := good
		mut(&c)
		require.Error(t, c.Validate(), name)
	}
}

func TestRecoveryCompletion_ExternalSubjectIsOptional(t *testing.T) {
	require.NoError(t, RecoveryCompletion{RecoveryJTI: "rcv-1", UserID: "usr-1"}.Validate(),
		"Р4: наш поток внешнего субъекта не называет")
	require.NoError(t, RecoveryCompletion{RecoveryJTI: "rcv-1", ExternalID: "ext-1", UserID: "usr-1"}.Validate())
	require.Error(t, RecoveryCompletion{RecoveryJTI: "rcv-1", ExternalID: ExternalSubject(strings.Repeat("x", 129)), UserID: "usr-1"}.Validate(),
		"заданный субъект по-прежнему ограничен длиной")
	require.Error(t, RecoveryCompletion{UserID: "usr-1"}.Validate(), "ключ потока обязателен")
}
