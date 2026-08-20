// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// verdictswitch_test.go — ГЕЙТ Г3: рубильник не вправе называть типом формы то,
// чего форма не умеет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ КОРМИТСЯ ИНЪЕКЦИЯ — производитель входа НАСТОЯЩИЙ, а не выдуманный
//
// «Неотвечаемый тип» здесь не синтетика: в модели прав есть типы, у которых нет
// НИ ОДНОГО отношения — они бывают только субъектами, и объектом решения не
// бывают никогда. Спросить о них форму нечем by construction. Перечень
// выводится из модели, а не выписывается: выписанный не сдвинулся бы от нового
// типа и молчал бы ровно про тот, ради которого его пришлось бы править.
//
// Инъекция идёт В ОБЕ СТОРОНЫ. Без положительного близнеца гейт ловил бы форму,
// а не существо: он краснел бы на любом непустом рубильнике, и первый же
// законный оператор отключил бы его как ложный.

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam/shadowverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// wiredStore — провязка, которую собирает композиционный корень: она обязана
// удовлетворять стражу сама по себе, иначе страж либо неверен, либо недостижим,
// а снаружи это выглядит одинаково.
func wiredStore(t *testing.T) (*authzcascade.Client, *authzcascade.Resolver) {
	t.Helper()
	transport := &clients.OpenFGAHTTPClient{Endpoint: "127.0.0.1:1", StoreID: "s"}
	facts := authzcascade.New(nil).WithBatch(authzcascade.BatchSourceFunc(openSnapshot))
	return authzcascade.Wrap(transport, facts).WithComparator(shadowverdict.New(nil, nil)), facts
}

// ПЕРЕПИСЬ печатает объём осмотренного: «ноль неотвечаемых» обязано быть
// отличимо от «ноль прочитанных типов».
func TestVerdictSwitchCensusPrintsWhatItLookedAt(t *testing.T) {
	census, err := surveyVerdictSwitch(verdictsource.New("iam_group", "iam_role"))
	require.NoError(t, err)

	require.Positive(t, census.TypesInModel,
		"перепись обязана назвать, сколько типов она осмотрела — иначе ноль находок неотличим от нуля прочитанного")
	require.Equal(t, []string{"iam_group", "iam_role"}, census.Declared)
	require.Equal(t, []string{"iam_group", "iam_role"}, census.Switched)
	require.Empty(t, census.Unanswerable)
}

// ИНЪЕКЦИЯ: тип, у которого форма вопроса не отвечает, — КРАСНОЕ с именем типа.
//
// Вход настоящий: `user` объявлен в модели и не несёт ни одного отношения.
func TestUnanswerableTypeInTheSwitchboardRefusesTheStart(t *testing.T) {
	store, facts := wiredStore(t)

	complaint := ownGateWiringComplaint(store, facts,
		verdictsource.New("iam_group", "user"), true)

	require.NotEmpty(t, complaint, "рубильник назвал тип, о котором форму спросить нечем — старт обязан отказать")
	require.Contains(t, complaint, "user", "отказ обязан НАЗВАТЬ тип: иначе стенд не поднять")
	require.Contains(t, complaint, "authz.verdict-form-types",
		"отказ обязан назвать ручку — рантайм-диагностика оператору, а не публичный артефакт")
}

// ЗАКОННЫЙ БЛИЗНЕЦ: отвечаемый тип в той же позиции — старт ПРОХОДИТ.
func TestAnswerableTypeInTheSwitchboardPassesTheStart(t *testing.T) {
	store, facts := wiredStore(t)

	require.Empty(t, ownGateWiringComplaint(store, facts, verdictsource.New("iam_group"), true),
		"законная позиция рубильника старт ронять не вправе — иначе гейт ловит форму, а не существо")
}

// Имя, которого в модели нет вовсе (опечатка оператора), — тоже отказ, и тоже
// с именем. Самая частая ошибка на этой ручке.
func TestUnknownTypeNameRefusesTheStart(t *testing.T) {
	store, facts := wiredStore(t)

	complaint := ownGateWiringComplaint(store, facts, verdictsource.New("iam_grup"), true)

	require.Contains(t, complaint, "iam_grup")
	require.Contains(t, strings.ToLower(complaint), "модел",
		"причина обязана быть названа: «нет такого типа в модели», а не просто «нельзя»")
}

// Имя в ЧУЖОМ СЛОВАРЕ — отказ. Словарей имени типа два, и рубильник, написанный
// в словаре каталога, не переключил бы ни одного вопроса, выглядя исполненным.
func TestCatalogDictionaryNameRefusesTheStart(t *testing.T) {
	store, facts := wiredStore(t)

	require.Contains(t,
		ownGateWiringComplaint(store, facts, verdictsource.New("iam.group"), true),
		"iam.group")
}

// РУБИЛЬНИК ПРИ ВЫКЛЮЧЕННОЙ СВЕРКЕ — отказ в старте.
//
// Иначе тип выглядел бы переключённым, а решения продолжали бы идти движком:
// без формы сравнителю нечем отвечать, и `Decides` честно отвечает «нет».
// Наблюдаемого признака у такого состояния нет — оно и есть «объявлено
// переключённым, но не переключено».
func TestSwitchboardWithShadowCompareOffRefusesTheStart(t *testing.T) {
	store, facts := wiredStore(t)

	complaint := ownGateWiringComplaint(store, facts, verdictsource.New("iam_group"), false)

	require.NotEmpty(t, complaint)
	require.Contains(t, complaint, "authz.shadow-compare")
}

// Пустой рубильник при выключенной сверке — законное состояние: не переключено
// ничего, платить за сверку не за что. Отрицание в паре с положительным.
func TestEmptySwitchboardWithShadowCompareOffPasses(t *testing.T) {
	store, facts := wiredStore(t)

	require.Empty(t, ownGateWiringComplaint(store, facts, verdictsource.Switchboard{}, false))
}

var _ = context.Background
