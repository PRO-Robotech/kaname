// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/stretchr/testify/require"
)

const catalogPublicationDeclaration = `apiVersion: iam/v1
module: erp
revision: 1
resources:
  - name: contract
    objectType: erp_contract
    parents: [project]
    producer: authored
    verbs:
      - get
      - {name: sign, class: update}
`

func TestParseCatalogPublicationDocumentAcceptsTypesAndActionsWithoutGrants(t *testing.T) {
	for _, module := range []string{"erp", "erp-tools"} {
		t.Run(module, func(t *testing.T) {
			document := strings.Replace(catalogPublicationDeclaration, "module: erp", "module: "+module, 1)
			document = strings.Replace(document, "erp_contract", strings.ReplaceAll(module, "-", "_")+"_contract", 1)
			m, err := modulecatalog.ParseCatalogPublicationDocument(module, []byte(document), len(document))
			require.NoError(t, err)
			require.Equal(t, module, m.Module)
			require.False(t, m.RolesDeclared())
			require.Nil(t, m.Seed)
			require.Equal(t, int64(1), modulecatalog.DeclaredEdition(m).Revision)
		})
	}
}

func TestParseCatalogPublicationDocumentRefusesWrongScopeAndNonCatalogInput(t *testing.T) {
	for _, test := range []struct {
		name, module, document string
	}{
		{"foreign-module", "other", catalogPublicationDeclaration},
		{"invalid-module", "ERP", catalogPublicationDeclaration},
		{"reserved-iam", "iam", strings.Replace(catalogPublicationDeclaration, "module: erp", "module: iam", 1)},
		{"missing-revision", "erp", strings.Replace(catalogPublicationDeclaration, "revision: 1\n", "", 1)},
		{"empty-resources", "erp", "apiVersion: iam/v1\nmodule: erp\nrevision: 1\nresources: []\n"},
		{"declared-empty-roles", "erp", catalogPublicationDeclaration + "roles: []\n"},
		{"declared-seed", "erp", catalogPublicationDeclaration + "seed: {}\n"},
		{"deprecated-verbs", "erp", catalogPublicationDeclaration + "deprecatedVerbs:\n  read: {class: get, since: \"2026-08-23\", reason: прежний глагол, removeWhen: выдач нет}\n"},
		{"foreign-type", "erp", strings.Replace(catalogPublicationDeclaration, "erp_contract", "other_contract", 1)},
		{"foreign-parent", "erp", strings.Replace(catalogPublicationDeclaration, "[project]", "[other_contract]", 1)},
		{"undeclared-own-parent", "erp", strings.Replace(catalogPublicationDeclaration, "[project]", "[erp_missing]", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := modulecatalog.ParseCatalogPublicationDocument(test.module, []byte(test.document), 65536)
			require.Error(t, err)
			require.Nil(t, m)
		})
	}
}

func TestParseCatalogPublicationDocumentBoundsInput(t *testing.T) {
	for _, test := range []struct {
		document []byte
		limit    int
	}{
		{nil, 65536},
		{[]byte(catalogPublicationDeclaration), 0},
		{[]byte(catalogPublicationDeclaration), -1},
		{[]byte(catalogPublicationDeclaration), len(catalogPublicationDeclaration) - 1},
	} {
		m, err := modulecatalog.ParseCatalogPublicationDocument("erp", test.document, test.limit)
		require.Error(t, err)
		require.Nil(t, m)
	}
}
