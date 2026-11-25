// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelAuthoringRowIsNativeToIAM(t *testing.T) {
	declaration, err := modulecatalog.RowsOf(&manifest.Manifest{Module: "iam"})
	require.NoError(t, err)
	resource := catalog.ResourceRow{Module: "iam", Resource: "accessLabel", ObjectType: grantcapability.AccessLabelObjectType}
	verb := catalog.VerbRow{Module: "iam", Resource: "accessLabel", Verb: "apply"}
	require.Equal(t, []catalog.ResourceRow{resource}, declaration.Resources)
	require.Equal(t, []catalog.VerbRow{verb}, declaration.Verbs)
	require.Empty(t, declaration.TierOnlyVerbs)
	_, object := authzmap.ObjectType("iam", "accessLabel")
	require.False(t, object)
	for _, row := range seed.LiteralRows().Resources {
		if row.Module == resource.Module && row.Resource == resource.Resource {
			require.Equal(t, resource, row)
			return
		}
	}
	t.Fatal("авторская координата отсутствует в ожидаемом каталоге")
}

func TestManifestCannotDeclareAccessLabelAsObject(t *testing.T) {
	for _, candidate := range []*manifest.Manifest{
		{Module: "iam", Resources: []manifest.Resource{{Name: "accessLabel", ObjectType: "iam_public_label"}}},
		{Module: "foreign", Resources: []manifest.Resource{{Name: "object", ObjectType: grantcapability.AccessLabelObjectType}}},
	} {
		_, err := modulecatalog.RowsOf(candidate)
		require.ErrorContains(t, err, "зарезервированная координата")
	}
}
