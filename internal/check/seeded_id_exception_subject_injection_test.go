// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// Доказательство способности гейта предмета УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются синтетические перечень и корпус: по одному
// снятому свойству на пробу, остальные оси целы — иначе красное приходило бы от
// соседнего требования.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// корпус инъекции: посеян ОДИН негодный по форме литерал (21 символ) — законный
// предмет записи перечня.
func synthExceptionCorpus() map[string]string {
	return map[string]string{
		"0001_initial.sql": synthGoodSeed +
			"INSERT INTO kaname.roles (id, name, permissions) " +
			"VALUES ('" + synthBadSeedID + "', 'kacho-system.viewer', '[]');\n",
	}
}

// TestExceptionSubjectGateIsSilentOnALawfulLedger — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestExceptionSubjectGateIsSilentOnALawfulLedger(t *testing.T) {
	findings, c := auditSeededIDExceptions(synthExceptionCorpus(), []string{synthBadSeedID})

	require.Empty(t, findings, "гейт краснеет на записи, у которой предмет ЕСТЬ")
	require.Equal(t, 1, c.withSubject)
	require.Equal(t, 2, c.seededValues, "объём осмотренного обязан быть сосчитан")
}

// TestExceptionSubjectGateIsSilentOnAnEmptyLedger — пустой перечень есть ЦЕЛЬ.
// Проверка не имеет права падать на достижении собственной цели.
func TestExceptionSubjectGateIsSilentOnAnEmptyLedger(t *testing.T) {
	findings, c := auditSeededIDExceptions(synthExceptionCorpus(), nil)

	require.Empty(t, findings, "пустой перечень подан поломкой — идеал превращён в отказ")
	require.Zero(t, c.pinned)
	require.NotZero(t, c.seededValues, "«ноль записей» обязано быть отличимо от «ноль прочитанного»")
}

// TestExceptionSubjectGateRedsWhenNothingSeedsTheLiteral — ось 1: предмет исчез.
func TestExceptionSubjectGateRedsWhenNothingSeedsTheLiteral(t *testing.T) {
	corpus := map[string]string{"0001_initial.sql": synthGoodSeed} // негодный посев снят

	findings, c := auditSeededIDExceptions(corpus, []string{synthBadSeedID})

	require.Len(t, findings, 1, "запись, которую больше не сеет ничто, оставила гейт зелёным")
	require.Contains(t, findings[0], "ЗАПИСИ НЕЧЕГО ПРОЩАТЬ")
	require.Contains(t, findings[0], synthBadSeedID)
	require.Zero(t, c.withSubject)
}

// TestExceptionSubjectGateRedsWhenTheFormAlreadyAcceptsIt — ось 2: прощать нечего.
// Литерал `rol000000000sysadmin` чеканен (20) — послабление на него лишнее.
func TestExceptionSubjectGateRedsWhenTheFormAlreadyAcceptsIt(t *testing.T) {
	findings, c := auditSeededIDExceptions(synthExceptionCorpus(), []string{"rol000000000sysadmin"})

	require.Len(t, findings, 1, "лишняя запись оставила гейт зелёным")
	require.Contains(t, findings[0], "ЗАПИСЬ ЛИШНЯЯ")
	require.Zero(t, c.withSubject)
}
