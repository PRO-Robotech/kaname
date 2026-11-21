// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

func TestIAMManifestDeclaresOnlyExplicitGrantAuthoringAxes(t *testing.T) {
	body, e := os.ReadFile("../../../../manifest.yaml")
	require.NoError(t, e)
	m, e := manifest.Load(body)
	require.NoError(t, e)
	rows, e := modulecatalog.RowsOf(m)
	require.NoError(t, e)
	for _, axis := range [][2]string{{"role", "bind"}, {"accessBinding", "create"}} {
		n := 0
		for _, v := range rows.Verbs {
			if v.Resource == axis[0] && v.Verb == axis[1] {
				n++
				require.False(t, v.PerObject)
				require.False(t, v.IsContainer())
			}
		}
		require.Equal(t, 1, n)
	}
	for i := range m.Resources {
		if m.Resources[i].Name == "role" {
			m.Resources[i].GrantVerbs = append(m.Resources[i].GrantVerbs, "create")
		}
	}
	_, e = modulecatalog.RowsOf(m)
	require.Error(t, e)
}
