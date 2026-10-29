// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// list_subjects_page_size_test.go — сценарий LSP-10 приёмки
// `docs/engineering/acceptance/list-subjects-page-size-is-the-platform-one.md`
// (kaname#615): контракт ListSubjects называет правило платформы.
//
// Число умолчания судит соседняя проба
// (`TestPageSizeContractNamesTheDefaultTheServiceApplies`, без записи
// исключения). Здесь — две клаузы, у которых машинного держателя не было
// (условие ревью M4): поле `page_size` называет диапазон `[0..1000]` и отказ
// INVALID_ARGUMENT вне него; комментарий глагола называет тот же диапазон, а
// не прежний «Hard cap: page size ≤ 1000».

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	lspRange      = "[0..1000]"
	lspOldVerbCap = "Hard cap: page size ≤ 1000"
)

// lspFieldKey и lspVerbKeys — узлы заглушек, несущие текст поля и глагола.
var (
	lspFieldKey = "ListSubjectsRequest.PageSize"
	lspVerbKeys = []string{"AuthorizeServiceClient.ListSubjects", "AuthorizeServiceServer.ListSubjects"}
)

// listSubjectsRangeFindings — находки по тексту поля и глагола; пусто = обе
// клаузы LSP-10 выполнены.
func listSubjectsRangeFindings(texts stubTexts) []string {
	var found []string
	field := oneLine(texts[lspFieldKey])
	if !strings.Contains(field, lspRange) {
		found = append(found, lspFieldKey+": диапазон "+lspRange+" не назван")
	}
	if !strings.Contains(field, "INVALID_ARGUMENT") && !strings.Contains(field, "InvalidArgument") {
		found = append(found, lspFieldKey+": отказ INVALID_ARGUMENT вне диапазона не назван")
	}
	for _, k := range lspVerbKeys {
		verb := oneLine(texts[k])
		if strings.Contains(verb, lspOldVerbCap) {
			found = append(found, k+": называет прежний предел «"+lspOldVerbCap+"»")
		}
		if !strings.Contains(verb, lspRange) {
			found = append(found, k+": диапазон "+lspRange+" не назван")
		}
	}
	return found
}

// TestLSP10_ListSubjectsContractNamesThePlatformRange — LSP-10 на дереве.
func TestLSP10_ListSubjectsContractNamesThePlatformRange(t *testing.T) {
	texts := readStubTexts(t)
	// ПРЕДПОСЫЛКА: узлы прочитаны и несут прозу — иначе «не назван» значил бы
	// «не нашли узел», а не «контракт молчит».
	requireTexts(t, texts, append([]string{lspFieldKey}, lspVerbKeys...)...)
	found := listSubjectsRangeFindings(texts)
	require.Emptyf(t, found, "LSP-10: контракт ListSubjects не называет правило платформы:\n  %s\n"+
		"Правится комментарий в proto/kaname/cloud/iam/v1/authorize_service.proto, заглушки — регенерацией.",
		strings.Join(found, "\n  "))
}

// TestLSP10_RangePredicateInjection — предикат краснеет на каждом дефекте
// одним фактом и молчит на исправном тексте.
func TestLSP10_RangePredicateInjection(t *testing.T) {
	const (
		goodField = "Page size; 0 selects the platform default (50); allowed [0..1000], INVALID_ARGUMENT otherwise."
		goodVerb  = "ListSubjects — who holds `action`. Page size [0..1000] (INVALID_ARGUMENT otherwise)."
	)
	world := func(field, verb string) stubTexts {
		return stubTexts{
			lspFieldKey:                           field,
			"AuthorizeServiceClient.ListSubjects": verb,
			"AuthorizeServiceServer.ListSubjects": verb,
		}
	}
	require.Empty(t, listSubjectsRangeFindings(world(goodField, goodVerb)), "исправный текст — молчание")
	for _, tc := range []struct{ name, field, verb string }{
		{"поле без диапазона", strings.Replace(goodField, " allowed [0..1000],", "", 1), goodVerb},
		{"поле без отказа", strings.Replace(goodField, ", INVALID_ARGUMENT otherwise", "", 1), goodVerb},
		{"глагол с прежним пределом", goodField, goodVerb + " Hard cap: page size ≤ 1000 (InvalidArgument otherwise)."},
		{"глагол без диапазона", goodField, strings.Replace(goodVerb, " [0..1000]", "", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEqual(t, goodField+goodVerb, tc.field+tc.verb, "инъекция ничего не изменила")
			require.NotEmpty(t, listSubjectsRangeFindings(world(tc.field, tc.verb)))
		})
	}
}
