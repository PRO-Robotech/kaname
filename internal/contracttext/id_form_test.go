// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// id_form_test.go — контракт показывает идентификатор службы в той форме,
// которую служба выдаёт и принимает: префикс и хвост БЕЗ дефиса (kaname#797).
//
// # Предмет
//
// Идентификатор службы — префикс и 17 знаков crockford-base32, 20 знаков в
// сумме (`domain.ShortIDLen`), без разделителя. Пример `usr-...` в тексте
// контракта ведёт интегратора к строке, которую `ValidateResourceID` отвергает
// `INVALID_ARGUMENT`.
//
// # Что судится
//
// Все тексты порождённых заглушек службы: ни один не показывает префикс
// службы с дефисом. Перечень префиксов — константы домена, а не выписка.
// Входной контракт операции (`proto/corelib/operation`) судится не здесь: его
// дом — дерево платформы, здесь лежит копия под ведомостью `proto/inputs.yaml`.

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ownIDPrefixes — префиксы идентификаторов, которые служба чеканит.
var ownIDPrefixes = []string{
	domain.PrefixAccount, domain.PrefixProject, domain.PrefixUser,
	domain.PrefixServiceAccount, domain.PrefixGroup, domain.PrefixRole,
	domain.PrefixAccessBinding, domain.PrefixOperationIAM,
	domain.PrefixClusterAdminGrant, domain.PrefixSAOAuthClient,
	domain.PrefixUserOAuthClient, domain.PrefixAuditEvent,
	domain.HumanSessionIDPrefix,
}

// hyphenIDForm — префикс службы, за которым дефис и начало хвоста
// (`usr-...`, `usr-<17>`, `usr-0abc`).
func hyphenIDForm(prefixes []string) *regexp.Regexp {
	quoted := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		quoted = append(quoted, regexp.QuoteMeta(p))
	}
	return regexp.MustCompile(`\b(` + strings.Join(quoted, "|") + `)-[.<0-9a-z]`)
}

// idFormFindings — находки по всем текстам.
func idFormFindings(texts stubTexts, re *regexp.Regexp) []string {
	keys := make([]string, 0, len(texts))
	for k := range texts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var found []string
	for _, k := range keys {
		if m := re.FindString(texts[k]); m != "" {
			found = append(found, k+": идентификатор с дефисом «"+m+"»")
		}
	}
	return found
}

// TestContractShowsServiceIDsInTheMintedForm — гейт на дереве.
func TestContractShowsServiceIDsInTheMintedForm(t *testing.T) {
	require.Equal(t, 20, domain.ShortIDLen, "форма идентификатора сменилась — пересмотреть пробу")
	texts := readStubTexts(t)
	t.Logf("осмотрено текстов контракта: %d", len(texts))
	found := idFormFindings(texts, hyphenIDForm(ownIDPrefixes))
	require.Emptyf(t, found, "контракт показывает идентификатор не в форме службы:\n  %s",
		strings.Join(found, "\n  "))
}

// TestIDFormPredicateInjection — дефектный текст краснит, исправный молчит.
func TestIDFormPredicateInjection(t *testing.T) {
	re := hyphenIDForm(ownIDPrefixes)
	require.NotEmpty(t, idFormFindings(stubTexts{"X": "kaname internal id (`usr-...` или `sva-...`)."}, re))
	require.NotEmpty(t, idFormFindings(stubTexts{"X": "for example acc-0abc"}, re))
	require.Empty(t, idFormFindings(stubTexts{"X": "kaname internal id (`usr<17>` или `sva<17>`)."}, re))
	require.Empty(t, idFormFindings(stubTexts{"X": "a user-facing name, personal-cloud-x"}, re))
}
