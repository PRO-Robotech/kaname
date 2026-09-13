// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_parity_claim_injection_test.go — доказательство того, что ось
// утверждения о совпадении копий СПОСОБНА упасть, и того, что она молчит на
// законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годный Makefile собран один раз; каждая проба меняет в нём РОВНО ОДИН факт —
// одну строку блока либо одну строку объявления цели. Контроль («держатель
// назван и объявлен — находок ноль») стоит первым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОВТОРНАЯ ИНЪЕКЦИЯ ПОСЛЕ ПЕРЕУСТРОЙСТВА — НЕ ФОРМАЛЬНОСТЬ
//
// Первая редакция оси запрещала имя цели края в блоке БЕЗУСЛОВНО и покраснела на
// исправленной прозе, чей разбор эту самую ошибку объясняет. Распознаватель
// переустроен, и перепись после переустройства СОШЛАСЬ — 42 блока, один с
// утверждением, — но совпадение переписи ничего не говорит о способности падать.
// Поэтому дефект подаётся входом ЗАНОВО, в том виде, в каком он стоял в дереве.
package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// parityGoodMakefile — годный вход: блок утверждает совпадение копий и называет
// держателя этого дерева; цель объявлена ниже.
const parityGoodMakefile = `IAM_CATALOG_EMBED := internal/apps/kaname/seed/embedded/permission_catalog.json
# Копия каталога у службы ОБЯЗАНА побайтово совпадать с копией края — это один
# источник истины, и держит это ` + "`check-permission-catalog`" + `, объявленная ниже.
.PHONY: check-permission-catalog
check-permission-catalog:
	@cmp -s "$(EDGE)" "$(IAM_CATALOG_EMBED)"
`

// requireParityFinding — находка с названной подстрокой есть, и перепись непуста.
func requireParityFinding(t *testing.T, makefile, want string) {
	t.Helper()
	census, findings := scanCatalogParityClaims(makefile)
	require.NotZero(t, census.claimingBlocks, "инъекция беспредметна: блоков с утверждением не распознано")

	var rendered []string
	for _, f := range findings {
		rendered = append(rendered, "Makefile:"+itoaCheck(f.firstLine)+" "+f.reason)
	}
	joined := strings.Join(rendered, "\n")
	require.Containsf(t, joined, want,
		"ось НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// itoaCheck — местное преобразование, чтобы проба не тянула форматирование ради числа.
func itoaCheck(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestCatalogParityClaimInjection_ControlIsSilent — КОНТРОЛЬ: держатель назван и
// объявлен, находок ноль. Без него всякое красное ниже могло бы прийти от соседа.
func TestCatalogParityClaimInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := scanCatalogParityClaims(parityGoodMakefile)
	require.Equal(t, 1, census.claimingBlocks, "утверждение распознано ровно одно")
	require.Empty(t, findings, "на верном входе находок быть не должно")
}

// TestCatalogParityClaimInjection_EdgeTargetSubstituted — ДЕФЕКТ, СТОЯВШИЙ В
// ДЕРЕВЕ: держателем названа цель другого дерева, своей не названо.
func TestCatalogParityClaimInjection_EdgeTargetSubstituted(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(parityGoodMakefile,
		"держит это `check-permission-catalog`, объявленная ниже.",
		"гейт `make -C <дерево>/gateway permission-catalog-check` роняет сборку при расхождении.", 1)
	require.NotEqual(t, parityGoodMakefile, broken, "инъекция не внесена: вход не изменился")

	requireParityFinding(t, broken, "названа цель другого дерева permission-catalog-check")
}

// TestCatalogParityClaimInjection_NoHolderNamed — ДЕФЕКТ второй: утверждение
// есть, держателя нет вовсе. Оно читается как исполняемое, а проверять нечем.
func TestCatalogParityClaimInjection_NoHolderNamed(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(parityGoodMakefile,
		"держит это `check-permission-catalog`, объявленная ниже.",
		"это один источник истины.", 1)
	require.NotEqual(t, parityGoodMakefile, broken, "инъекция не внесена: вход не изменился")

	requireParityFinding(t, broken, "держатель не назван вовсе")
}

// TestCatalogParityClaimInjection_HolderNamedButNotDeclared — ДЕФЕКТ третий:
// держатель назван и в этом файле НЕ объявлен. Названный и несуществующий
// держатель — то же обещание, что и подменённый.
func TestCatalogParityClaimInjection_HolderNamedButNotDeclared(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(parityGoodMakefile,
		"check-permission-catalog:\n\t@cmp", "check-permission-catalogue:\n\t@cmp", 1)
	require.NotEqual(t, parityGoodMakefile, broken, "инъекция не внесена: вход не изменился")

	requireParityFinding(t, broken, "НЕ объявлен")
}

// TestCatalogParityClaimInjection_BlockWithoutTheClaimIsNotJudged — ЗАКОННЫЙ
// БЛИЗНЕЦ: блок без утверждения называет цель края и осью не судится. Ось
// УСЛОВНА: снимут утверждение — снимется и требование к нему, само.
func TestCatalogParityClaimInjection_BlockWithoutTheClaimIsNotJudged(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(parityGoodMakefile,
		"# Копия каталога у службы ОБЯЗАНА побайтово совпадать с копией края — это один\n"+
			"# источник истины, и держит это `check-permission-catalog`, объявленная ниже.\n",
		"# Каталог края регенерируется целью `permission-catalog-check` в дереве платформы.\n", 1)
	require.NotEqual(t, parityGoodMakefile, twin, "близнец не подан: вход не изменился")

	census, findings := scanCatalogParityClaims(twin)
	require.Zero(t, census.claimingBlocks, "утверждения в этом входе нет")
	require.Empty(t, findings, "блок без утверждения осью не судится")
}

// TestCatalogParityClaimInjection_BothNamedIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ второй, и
// ровно он опроверг первую редакцию оси: свой держатель назван, а цель края
// упомянута в разборе прежней ошибки. Это ФОРМА ИСПРАВЛЕННОЙ ПРОЗЫ, и красное на
// ней означало бы проверку, краснеющую на собственном объяснении.
func TestCatalogParityClaimInjection_BothNamedIsSilent(t *testing.T) {
	t.Parallel()
	twin := strings.Replace(parityGoodMakefile,
		"объявленная ниже.",
		"объявленная ниже.\n# Здесь назывался гейт края `permission-catalog-check` — он сверяет другое.", 1)
	require.NotEqual(t, parityGoodMakefile, twin, "близнец не подан: вход не изменился")

	census, findings := scanCatalogParityClaims(twin)
	require.Equal(t, 1, census.claimingBlocks, "утверждение распознано")
	require.Empty(t, findings, "упоминание соседнего дерева рядом с названным своим подменой не является")
}

// TestCatalogParityClaimInjection_NoCommentBlocksIsVoidNotGreen — ПУСТОЙ ОБХОД:
// комментариев нет вовсе. Главный тест на такой переписи падает своим стражем.
func TestCatalogParityClaimInjection_NoCommentBlocksIsVoidNotGreen(t *testing.T) {
	t.Parallel()
	census, findings := scanCatalogParityClaims("check-permission-catalog:\n\t@true\n")
	require.Empty(t, findings)
	require.Zero(t, census.blocksSeen, "блоков комментария нет")
	require.Zero(t, census.claimingBlocks,
		"утверждений нет — на этой переписи главный тест обязан падать стражем, а не зеленеть")
}
