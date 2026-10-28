// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// account_id_form_test.go — распознаватель формы идентификатора аккаунта
// (задача kaname#1052, приёмка `account-id-may-be-supplied-at-create.md`, Р2,
// Р6а, Р10). Таблицы сценариев AID-05/AID-06 судят его через вход создания
// (`internal/apps/kaname/api/audit`); здесь — каждая ось формы и резерва
// парой «годный близнец — одно различие», без базы и без вызова use-case.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestJudgeAccountID_EachAxisIsAPairOfTwins(t *testing.T) {
	cases := []struct {
		axis        string
		value       string
		want        domain.AccountIDVerdict
		twin        string
		twinVerdict domain.AccountIDVerdict
	}{
		{"(а) короче трёх", "go", domain.AccountIDMalformed, "goj", domain.AccountIDAccepted},
		{"(а) длиннее тридцати", strings.Repeat("a", 31), domain.AccountIDMalformed, strings.Repeat("a", 30), domain.AccountIDAccepted},
		{"(б) заглавная", "Godjee", domain.AccountIDMalformed, "godjee", domain.AccountIDAccepted},
		{"(б) подчёркивание", "god_jee", domain.AccountIDMalformed, "god-jee", domain.AccountIDAccepted},
		{"(б) не ASCII", "godjeе", domain.AccountIDMalformed, "godjee", domain.AccountIDAccepted},
		{"(б) разделитель модели прав", "god:jee", domain.AccountIDMalformed, "god-jee", domain.AccountIDAccepted},
		{"(в) первая — цифра", "1godjee", domain.AccountIDMalformed, "g1odjee", domain.AccountIDAccepted},
		{"(в) последняя — дефис", "godjee-", domain.AccountIDMalformed, "godjee", domain.AccountIDAccepted},
		{"(г) двойной дефис", "god--jee", domain.AccountIDMalformed, "god-jee", domain.AccountIDAccepted},
		{"(д1) слитная форма другого вида", "prj7m3k9q2x5v8b4n6t1", domain.AccountIDReserved, "prj7m3k9q2x5v8b4n6tu", domain.AccountIDAccepted},
		{"(д1) префикс вне каталога", "xyz7m3k9q2x5v8b4n6t1", domain.AccountIDReserved, "xyz7m3k9q2x5v8b4n6tu", domain.AccountIDAccepted},
		{"(д2) дефисная форма аккаунта", "acc-7m3k9q2x5v8b4n6t1", domain.AccountIDReserved, "acc-7m3k9q2x5v8b4n6tu", domain.AccountIDAccepted},
		{"(д2) длинное начало", "abcdefghijkl-7m3k9q2x5v8b4n6t1", domain.AccountIDReserved, "abcdefghijkl-7m3k9q2x5v8b4n6tu", domain.AccountIDAccepted},
		{"(д3) посеянный литерал", "rol000000000sysviewer", domain.AccountIDReserved, "rol000000000sysviewe", domain.AccountIDAccepted},
		{"(д4) личное пространство", "personal-cloud-godjee", domain.AccountIDReserved, "personal-clouds-godjee", domain.AccountIDAccepted},
		{"(д4) после свёртки", "pers0nal-c1oud-godjee", domain.AccountIDReserved, "pers0nal-c1oudx-godjee", domain.AccountIDAccepted},
	}
	for _, c := range cases {
		t.Run(c.axis, func(t *testing.T) {
			require.Equal(t, c.want, domain.JudgeAccountID(c.value), "%q", c.value)
			require.Equal(t, c.twinVerdict, domain.JudgeAccountID(c.twin), "близнец %q", c.twin)
		})
	}
}

// Форма генератора — часть формы аккаунта: всё, что принималось прежде,
// принимается и теперь (Р2, совместимость).
func TestJudgeAccountID_GeneratorFormIsAccepted(t *testing.T) {
	for i := 0; i < 256; i++ {
		id := ids.NewID(domain.PrefixAccount)
		require.Equal(t, domain.AccountIDAccepted, domain.JudgeAccountID(id), "%q", id)
	}
	require.True(t, domain.IsAccountID("acc1a18042d81fb438d6"), "посеянный аккаунт")
	require.False(t, domain.IsAccountID(""), "пустая строка — не идентификатор")
}

func TestFoldLookAlike_FoldsExactlyTheThreeLookAlikes(t *testing.T) {
	require.Equal(t, "d1put11u", domain.FoldLookAlike("dlputi1u"))
	require.Equal(t, domain.FoldLookAlike("dlputi1u"), domain.FoldLookAlike("dlputilu"))
	require.Equal(t, "g0djee", domain.FoldLookAlike("godjee"))
	require.NotEqual(t, domain.FoldLookAlike("dlputi1u"), domain.FoldLookAlike("dlputimu"), "m не сворачивается")
	require.Equal(t, "OIL", domain.FoldLookAlike("OIL"), "заглавные вне формы и не сворачиваются")
}
