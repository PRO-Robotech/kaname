// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// cutoff_readers_test.go — контракт сессии человека называет ВСЕХ читателей
// отсечки, а не одного края (kaname#749).
//
// # Предмет
//
// Комментарий `InternalHumanSessionService` объявлял край единственным
// читателем отсечки. Служба же читает её сама: выдача церемонии отвечает
// `login_required` на сессию, аутентифицированную не позже отсечки
// (`domain.ErrCeremonySubjectCutOff`, предикат `sessionCutOffBySubjectSQL`),
// и тот же предикат стоит в перечне сессий. Читатель контракта, ищущий, где
// действует отсечка, не нашёл бы точку авторизации службы.
//
// # Что судится
//
// Шапка службы не утверждает единственного читателя и называет читателя на
// стороне службы — церемонию с её исходом `login_required`. Факт кода держит
// ссылка на признак `domain.ErrCeremonySubjectCutOff`: снят признак — проба не
// собирается, и утверждение о втором читателе пересматривается вместе с ним.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const textHumanSession = "InternalHumanSessionServiceClient"

var (
	claimsSingleReader = regexp.MustCompile(`(?i)\b(one|single|only|sole)\s+reader\b`)
	namesCeremonyRead  = regexp.MustCompile(`(?i)\bceremony\b[^.]{0,200}\blogin_required\b|\blogin_required\b[^.]{0,200}\bceremony\b`)
)

// cutoffReaderFindings — находки; пусто = шапка называет читателей верно.
func cutoffReaderFindings(text string) []string {
	text = oneLine(text)
	var found []string
	if m := claimsSingleReader.FindString(text); m != "" {
		found = append(found, "утверждён единственный читатель отсечки: «"+m+"»")
	}
	if !namesCeremonyRead.MatchString(text) {
		found = append(found, "не назван читатель отсечки на стороне службы — церемония и её login_required")
	}
	return found
}

// TestHumanSessionContractNamesEveryCutoffReader — гейт на дереве.
func TestHumanSessionContractNamesEveryCutoffReader(t *testing.T) {
	// ПРЕДПОСЫЛКА: служба читает отсечку на выдаче церемонии.
	require.Error(t, domain.ErrCeremonySubjectCutOff)

	texts := readStubTexts(t)
	requireTexts(t, texts, textHumanSession)
	found := cutoffReaderFindings(texts[textHumanSession])
	require.Emptyf(t, found, "шапка InternalHumanSessionService о читателях отсечки:\n  %s\n"+
		"Правится proto/kaname/cloud/iam/v1/human_session_service.proto.",
		strings.Join(found, "\n  "))
}

// TestCutoffReaderPredicateInjection — дефектный текст краснит, исправный молчит.
func TestCutoffReaderPredicateInjection(t *testing.T) {
	require.NotEmpty(t, cutoffReaderFindings("One reader of the cutoff, and it is on the edge."))
	require.NotEmpty(t, cutoffReaderFindings("The edge compares the cutoff."))
	require.Empty(t, cutoffReaderFindings("The cutoff has two readers: the edge, and this service's ceremony, "+
		"which answers login_required on a session older than the cutoff."))
}
