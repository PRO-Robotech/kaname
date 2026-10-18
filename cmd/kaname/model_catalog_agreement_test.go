// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// model_catalog_agreement_test.go — текст и отбор шага «модель против каталога»
// (kaname#865, Д10, текст Д7) над входом, собранным здесь: исход применителя
// каталога и отчёт композиции. Последовательность старта над живой базой —
// `module_revision_boot_integration_test.go` (865-09, 865-24, 865-34, 865-35).

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

const (
	agrDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	agrDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	agrTail    = " собраны в модель процесса из этого документа — модель доступа не может быть собрана из документа, который каталог отверг"
)

func agrSkip(module string, outcome modulecatalog.RevisionOutcome, declared, previous *modulecatalog.Edition) modulecatalog.RevisionSkip {
	return modulecatalog.RevisionSkip{Module: module, RevisionReport: modulecatalog.RevisionReport{
		Outcome: outcome, Declared: declared, Previous: previous,
	}}
}

func agrQuiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestModelCatalogAgreement_NamesEveryRejectedModuleWithOutOfCanonTypes —
// строка на каждый не применённый модуль с типами вне канона, в порядке
// доставки; модуль без таких типов пуск не останавливает.
func TestModelCatalogAgreement_NamesEveryRejectedModuleWithOutOfCanonTypes(t *testing.T) {
	rep := modelcompose.Report{
		Composed: []string{"alpha_b", "alpha_Z", "zeta_x"},
		ComposedBy: map[string][]string{
			// Порядок байтов имени: заглавная раньше строчной.
			"zeta":  {"zeta_x"},
			"alpha": {"alpha_Z", "alpha_b"},
		},
	}
	notApplied := []modulecatalog.RevisionSkip{
		agrSkip("zeta", modulecatalog.RevisionStale,
			&modulecatalog.Edition{Revision: 3, Digest: agrDigestA}, &modulecatalog.Edition{Revision: 5, Digest: agrDigestB}),
		agrSkip("iam", modulecatalog.RevisionConflict,
			&modulecatalog.Edition{Revision: 2, Digest: agrDigestA}, &modulecatalog.Edition{Revision: 2, Digest: agrDigestB}),
		agrSkip("alpha", modulecatalog.RevisionStale,
			nil, &modulecatalog.Edition{Revision: 7, Digest: agrDigestB}),
	}
	err := assertModelAgreesWithCatalog(agrQuiet(), notApplied, rep)
	require.Error(t, err)
	require.Equal(t, strings.Join([]string{
		"модель доступа: модуль zeta каталог не применил — доставлена редакция 3 (отпечаток " + agrDigestA +
			"), применена 5 (отпечаток " + agrDigestB + "); его типы вне канона zeta_x" + agrTail,
		"модель доступа: модуль alpha каталог не применил — доставлена редакция не объявлена, применена 7 (отпечаток " +
			agrDigestB + "); его типы вне канона alpha_Z, alpha_b" + agrTail,
	}, "\n"), err.Error())
}

// TestModelCatalogAgreement_SilentTwins — близнецы: не применённых нет; не
// применённый модуль без типов вне канона; типы вне канона у применённого.
func TestModelCatalogAgreement_SilentTwins(t *testing.T) {
	rep := modelcompose.Report{
		Composed:   []string{"probemod_box", "probemod_item"},
		ComposedBy: map[string][]string{"probemod": {"probemod_box", "probemod_item"}},
	}
	require.NoError(t, assertModelAgreesWithCatalog(agrQuiet(), nil, rep), "не применённых нет")
	require.NoError(t, assertModelAgreesWithCatalog(agrQuiet(), []modulecatalog.RevisionSkip{
		agrSkip("iam", modulecatalog.RevisionStale,
			&modulecatalog.Edition{Revision: 1, Digest: agrDigestA}, &modulecatalog.Edition{Revision: 3, Digest: agrDigestB}),
	}, rep), "пропущенный iam типов вне канона не несёт, probemod применён")

	// Контроль близнеца: тот же вход с пропущенным probemod — отказ.
	require.Error(t, assertModelAgreesWithCatalog(agrQuiet(), []modulecatalog.RevisionSkip{
		agrSkip("probemod", modulecatalog.RevisionStale,
			&modulecatalog.Edition{Revision: 1, Digest: agrDigestA}, &modulecatalog.Edition{Revision: 3, Digest: agrDigestB}),
	}, rep))
}
