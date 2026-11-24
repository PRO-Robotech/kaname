// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/stretchr/testify/require"
)

func TestReconstructPublishedModelChecksPartAndRestoresAdmissionTerms(t *testing.T) {
	raw, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	raw, err = publicreadfixture.WithRevision(raw, 1)
	require.NoError(t, err)
	doc, err := manifest.Load(raw)
	require.NoError(t, err)
	require.Equal(t, "probemod", doc.Module)
	edition := modulecatalog.DeclaredEdition(doc)
	require.NotNil(t, edition)
	part := modulecatalog.LatestPart{
		PublishedPart: modulecatalog.PublishedPart{Module: doc.Module, Edition: *edition, Document: raw},
	}

	text, terms, err := modulecatalog.ReconstructPublishedModel([]modulecatalog.LatestPart{part})
	require.NoError(t, err)
	require.NotEmpty(t, terms)
	rows, err := modulecatalog.RowsOf(doc)
	require.NoError(t, err)
	halves := catalog.Halves{Live: catalog.Rows{Modules: []string{doc.Module}, Resources: rows.Resources, Verbs: rows.Verbs}}
	_, err = granteffect.NewBundle(t.Context(), text, halves, granteffect.ProjectorVersion)
	require.ErrorIs(t, err, granteffect.ErrInvalidBundle)
	withTerms, err := granteffect.NewBundle(t.Context(), text, halves, granteffect.ProjectorVersion, terms...)
	require.NoError(t, err)
	require.Equal(t, text, withTerms.ModelSource())

	_, _, err = modulecatalog.ReconstructPublishedModel([]modulecatalog.LatestPart{part, part})
	require.Error(t, err)
	bad := part
	bad.Edition.Digest = "sha256:" + strings.Repeat("0", 64)
	_, _, err = modulecatalog.ReconstructPublishedModel([]modulecatalog.LatestPart{bad})
	require.Error(t, err)

	part.Withdrawn = true
	text, terms, err = modulecatalog.ReconstructPublishedModel([]modulecatalog.LatestPart{part})
	require.NoError(t, err)
	require.Equal(t, authzmodel.DSL, text)
	require.Empty(t, terms)
}
