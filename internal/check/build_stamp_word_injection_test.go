// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Инъекция гейта «слово одно на оба модуля» — В ОБЕ СТОРОНЫ.
//
// Разбор вынесен в ConstStringValue именно затем, чтобы способность падать
// доказывалась ПОДАЧЕЙ ВХОДА, а не чтением: настоящее дерево и синтетический
// мир проходят одну функцию, поэтому доказанное на втором верно для первого.
//
// Оси:
//  1. РАСХОЖДЕНИЕ ЗНАЧЕНИЙ — разошлись слова, гейт обязан их различить.
//  2. ЗАКОННЫЙ БЛИЗНЕЦ — те же два объявления, слова совпадают: молчание.
//  3. ОТСУТСТВИЕ ОБЪЯВЛЕНИЯ — переехало или переименовано: это НЕ «совпало»,
//     а «сверять нечего», и состояния обязаны быть различимы.
//  4. ИСПОЛНЯЕМАЯ ЧАСТЬ — слово в комментарии и в чужой константе объявлением
//     не является; иначе гейт нашёл бы собственное объяснение.
//  5. НЕ-ЛИТЕРАЛ — значение, собранное выражением, разбором не сверить, и это
//     обязано быть ОШИБКОЙ, а не тихим «не нашли».
package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const wordSrcMatching = `package metrics

// BuildInfoUnstamped — то, что метка говорит, когда сборка её не проставила.
const BuildInfoUnstamped = "unstamped"
`

// wordSrcDiverged — ЗАКОННЫЙ БЛИЗНЕЦ предыдущего: дельта миров ОДИН факт —
// значение константы.
const wordSrcDiverged = `package metrics

// BuildInfoUnstamped — то, что метка говорит, когда сборка её не проставила.
const BuildInfoUnstamped = "not-stamped"
`

func TestBuildStampWordInjection_DivergedValueIsSeen(t *testing.T) {
	t.Parallel()
	v, found, err := check.ConstStringValue([]byte(wordSrcDiverged), "BuildInfoUnstamped")
	require.NoError(t, err)
	require.True(t, found)
	require.Equalf(t, "not-stamped", v, "разбор обязан вернуть РАСХОЖДЕНИЕ дословно: "+
		"вернув ожидаемое, он зеленел бы при разъехавшихся объявлениях")
}

func TestBuildStampWordInjection_MatchingValueIsSilent(t *testing.T) {
	t.Parallel()
	v, found, err := check.ConstStringValue([]byte(wordSrcMatching), "BuildInfoUnstamped")
	require.NoError(t, err)
	require.True(t, found)
	require.Equalf(t, "unstamped", v, "законный близнец обязан дать ровно то слово, что "+
		"объявлено, — и гейт на нём молчит")
}

func TestBuildStampWordInjection_MissingDeclarationIsNotAMatch(t *testing.T) {
	t.Parallel()
	renamed := `package metrics

const BuildInfoNotStamped = "unstamped"
`
	_, found, err := check.ConstStringValue([]byte(renamed), "BuildInfoUnstamped")
	require.NoError(t, err)
	require.Falsef(t, found, "константа переименована — сверять НЕЧЕГО. Схлопнув это в "+
		"«совпало», гейт молчал бы ровно тогда, когда предмет из-под него ушёл")
}

func TestBuildStampWordInjection_WordInProseIsNotADeclaration(t *testing.T) {
	t.Parallel()
	prose := `package metrics

// Непроставленный штамп называет себя словом "unstamped", а не BuildInfoUnstamped.
const Something = "other"
`
	_, found, err := check.ConstStringValue([]byte(prose), "BuildInfoUnstamped")
	require.NoError(t, err)
	require.Falsef(t, found, "слово стоит в комментарии, а объявления нет: гейт, читающий "+
		"сырой текст, нашёл бы СВОЁ СОБСТВЕННОЕ объяснение и объявил бы согласие")
}

func TestBuildStampWordInjection_ComputedValueIsAnErrorNotSilence(t *testing.T) {
	t.Parallel()
	computed := `package metrics

const prefix = "un"

const BuildInfoUnstamped = prefix + "stamped"
`
	_, _, err := check.ConstStringValue([]byte(computed), "BuildInfoUnstamped")
	require.Errorf(t, err, "значение, собранное выражением, разбором не сверить — и это "+
		"ОШИБКА, а не тихое «не нашли»: второе неотличимо от переименования")
}

func TestBuildStampWordInjection_UnparsableSourceIsAnError(t *testing.T) {
	t.Parallel()
	_, _, err := check.ConstStringValue([]byte("не Go вовсе"), "BuildInfoUnstamped")
	require.Errorf(t, err, "неразбираемый исходник обязан быть ошибкой: приняв его за "+
		"«объявления нет», гейт объявил бы предмет ушедшим при живом предмете")
}
