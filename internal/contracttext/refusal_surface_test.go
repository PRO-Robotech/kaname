// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// refusal_surface_test.go — текст отказа аутентификации, названный в контракте,
// назван ВМЕСТЕ с поверхностью, которая его отвечает (kaname#718).
//
// # Предмет
//
// Служба на негодное удостоверение отвечает `presentedcred.RefusalMessage`
// («credential is not accepted»). Край платформы — свой отказ со своим телом.
// Описание удаления личности ссылалось на текст службы как на ответ, хотя
// человек ходит через край: читатель ждал бы тела, которого не получит.
//
// # Что судится
//
// Каждый текст контракта, цитирующий отказ службы, называет его ответом ЭТОЙ
// службы и называет край, который отвечает иначе. Текст отказа берётся из кода,
// а не выписывается: смена текста в коде без контракта красит пробу.
//
// # Граница
//
// Тело ответа края проба не цитирует и не судит: его держит документация края
// (два места об одном предмете были бы вторым дефектом того же класса).

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

var (
	namesThisService = regexp.MustCompile(`(?i)\bthis service('s)?\b`)
	namesTheEdge     = regexp.MustCompile(`(?i)\bedge\b`)
)

// refusalSurfaceFindings — находки и число судимых текстов.
func refusalSurfaceFindings(texts stubTexts, refusal string) (found []string, judged int) {
	keys := make([]string, 0, len(texts))
	for k, v := range texts {
		if strings.Contains(oneLine(v), refusal) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		judged++
		text := oneLine(texts[k])
		if !namesThisService.MatchString(text) {
			found = append(found, k+": отказ «"+refusal+"» не назван ответом этой службы")
		}
		if !namesTheEdge.MatchString(text) {
			found = append(found, k+": не сказано, что край отвечает своим отказом")
		}
	}
	return found, judged
}

// TestRefusalTextIsNamedWithTheSurfaceThatAnswersIt — гейт на дереве.
func TestRefusalTextIsNamedWithTheSurfaceThatAnswersIt(t *testing.T) {
	texts := readStubTexts(t)
	found, judged := refusalSurfaceFindings(texts, presentedcred.RefusalMessage)
	t.Logf("осмотрено текстов с отказом службы: %d", judged)
	// ПРЕДПОСЫЛКА: удаление личности называет отказ — без этого текста судить
	// нечего, и молчание было бы неотличимо от исправности.
	require.Greater(t, judged, 0, "ни один текст контракта не цитирует %q — предпосылка сломана",
		presentedcred.RefusalMessage)
	require.Emptyf(t, found, "контракт цитирует отказ без его поверхности:\n  %s",
		strings.Join(found, "\n  "))
}

// TestRefusalSurfacePredicateInjection — дефектный текст краснит, исправный молчит.
func TestRefusalSurfacePredicateInjection(t *testing.T) {
	const refusal = "credential is not accepted"
	for _, tc := range []struct {
		name, text string
		red        bool
	}{
		{"без поверхности", `refused on presentation (UNAUTHENTICATED "credential is not accepted").`, true},
		{"без края", `this service answers UNAUTHENTICATED "credential is not accepted".`, true},
		{"обе поверхности", `this service answers UNAUTHENTICATED "credential is not accepted"; through the platform edge the edge answers with its own refusal.`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, judged := refusalSurfaceFindings(stubTexts{"X.Y": tc.text}, refusal)
			require.Equal(t, 1, judged)
			require.Equal(t, tc.red, len(found) > 0, "%v", found)
		})
	}
}
