// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/stretchr/testify/require"
)

func TestCatalogPublicationRequiresCurrentPlanAndRepeatsWithoutWriting(t *testing.T) {
	const module = "erp"
	const maxBytes = 65536
	ctx := verbCtx()
	document := []byte(catalogPublicationDeclaration)
	emptyCatalog, err := catalog.CanonicalJSON(catalog.Halves{})
	require.NoError(t, err)
	w := &publicationWriter{head: modulecatalog.PublishedModel{
		Revision: 1, CatalogID: fmt.Sprintf("%x", sha256.Sum256(emptyCatalog)),
	}}
	plan, err := modulecatalog.PlanCatalogPublication(ctx, w, module, document, maxBytes)
	require.NoError(t, err)
	require.Equal(t, modulecatalog.RevisionFirst, plan.Revision.Outcome)
	require.Empty(t, w.calls)

	_, err = modulecatalog.ApplyCatalogPublication(ctx, w, module, document, maxBytes, "stale")
	require.ErrorIs(t, err, modulecatalog.ErrStateMoved)
	require.Empty(t, w.calls)

	first, err := modulecatalog.ApplyCatalogPublication(ctx, w, module, document, maxBytes, plan.StateToken)
	require.NoError(t, err)
	require.Equal(t, plan.Model, first)
	require.Equal(t, int64(2), first.Revision)
	require.Len(t, w.audited, 1)
	require.Equal(t, 1, w.reprojections)
	require.Equal(t, "usr-probe865", w.audited[0].Actor)
	require.Equal(t, plan.StateToken, w.audited[0].ExpectedState)
	payload := w.audited[0].Payload()
	require.Equal(t, plan.Revision.Declared.Revision, payload["part_revision"])
	require.Equal(t, plan.Revision.Declared.Digest, payload["part_digest"])
	require.Equal(t, first.Revision, payload["model_revision"])
	require.Equal(t, first.Digest, payload["model_digest"])
	initialVerbs := len(w.live.Verbs)

	more := strings.Replace(catalogPublicationDeclaration, "revision: 1", "revision: 2", 1)
	more += "      - {name: approve, class: update}\n"
	secondPlan, err := modulecatalog.PlanCatalogPublication(ctx, w, module, []byte(more), maxBytes)
	require.NoError(t, err)
	require.Equal(t, plan.Revision.Declared, secondPlan.Revision.Previous)
	second, err := modulecatalog.ApplyCatalogPublication(ctx, w, module, []byte(more), maxBytes, secondPlan.StateToken)
	require.NoError(t, err)
	require.Equal(t, int64(3), second.Revision)
	require.Len(t, w.live.Verbs, initialVerbs+1)
	require.Contains(t, w.live.Verbs, catalog.VerbRow{Module: module, Resource: "contract", Verb: "approve", PerObject: true})
	require.Len(t, w.audited, 2)
	require.Equal(t, 2, w.reprojections)

	before := len(w.calls)
	repeated, err := modulecatalog.ApplyCatalogPublication(ctx, w, module, []byte(more), maxBytes, secondPlan.StateToken)
	require.NoError(t, err)
	require.Equal(t, second, repeated)
	require.Len(t, w.calls, before)
	require.Equal(t, 2, w.partsWritten)
	require.Equal(t, 2, w.reprojections)

	w.live.Verbs = w.live.Verbs[:len(w.live.Verbs)-1]
	_, err = modulecatalog.ApplyCatalogPublication(ctx, w, module, []byte(more), maxBytes, secondPlan.StateToken)
	require.ErrorIs(t, err, modulecatalog.ErrStateMoved)
	require.Len(t, w.calls, before)
}

func TestCatalogPublicationExtendsArchivedManifestWithoutAppliedEdition(t *testing.T) {
	const module = "erp"
	const maxBytes = 65536
	ctx := verbCtx()
	document := []byte(strings.Replace(catalogPublicationDeclaration, "revision: 1\n", "", 1))
	old, err := modulecatalog.NewBaselinePublishedPart(module, document)
	require.NoError(t, err)
	require.Equal(t, int64(1), old.Edition.Revision)
	require.Equal(t, document, old.Document)
	declared, err := old.DeclaredEdition()
	require.NoError(t, err)
	require.Nil(t, declared)

	oldManifest, err := manifest.Load(document)
	require.NoError(t, err)
	rows, err := modulecatalog.RowsOf(oldManifest)
	require.NoError(t, err)
	live := catalog.Rows{Modules: []string{module}, Resources: rows.Resources, Verbs: rows.Verbs}
	canonical, err := catalog.CanonicalJSON(catalog.Halves{Live: live})
	require.NoError(t, err)
	part := modulecatalog.LatestPart{PublishedPart: old}
	text, _, err := modulecatalog.ReconstructPublishedModel([]modulecatalog.LatestPart{part})
	require.NoError(t, err)
	w := &publicationWriter{live: live, part: &part, head: modulecatalog.PublishedModel{
		Revision: 1, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))),
		CatalogID: fmt.Sprintf("%x", sha256.Sum256(canonical)), Text: text,
	}}

	more := strings.Replace(catalogPublicationDeclaration, "revision: 1", "revision: 2", 1)
	more += "      - {name: approve, class: update}\n"
	plan, err := modulecatalog.PlanCatalogPublication(ctx, w, module, []byte(more), maxBytes)
	require.NoError(t, err)
	require.Equal(t, &old.Edition, plan.Revision.Previous)
	applied, err := modulecatalog.ApplyCatalogPublication(ctx, w, module, []byte(more), maxBytes, plan.StateToken)
	require.NoError(t, err)
	require.Equal(t, plan.Model, applied)
	require.Equal(t, int64(2), applied.Revision)
	require.Equal(t, int64(2), w.applied[module].Revision)
	require.Len(t, w.live.Verbs, len(rows.Verbs)+1)
}

type publicationWriter struct {
	recordingWriter
	live          catalog.Rows
	head          modulecatalog.PublishedModel
	part          *modulecatalog.LatestPart
	partsWritten  int
	reprojections int
}

func (w *publicationWriter) RunInCatalogPublicationTx(ctx context.Context, fn func(context.Context, modulecatalog.CatalogPublicationWriter) error) error {
	return fn(ctx, w)
}

func (w *publicationWriter) ReadCatalog(context.Context) (modulecatalog.CatalogState, error) {
	return modulecatalog.NewCatalogState(w.live, catalog.Rows{}), nil
}

func (w *publicationWriter) ReadModule(context.Context, string) (catalog.Rows, error) {
	return w.live, nil
}

func (w *publicationWriter) UpsertModule(_ context.Context, module string) (bool, error) {
	if len(w.live.Modules) != 0 {
		return false, nil
	}
	w.live.Modules = []string{module}
	return true, nil
}

func (w *publicationWriter) UpsertResource(_ context.Context, row catalog.ResourceRow) (bool, error) {
	if len(w.live.Resources) != 0 {
		return false, nil
	}
	w.live.Resources = []catalog.ResourceRow{row}
	return true, nil
}

func (w *publicationWriter) UpsertVerb(_ context.Context, row catalog.VerbRow) (bool, error) {
	for _, existing := range w.live.Verbs {
		if existing.Verb == row.Verb {
			return false, nil
		}
	}
	w.live.Verbs = append(w.live.Verbs, row)
	return true, nil
}

func (w *publicationWriter) LatestPublishedModel(context.Context) (modulecatalog.PublishedModel, error) {
	return w.head, nil
}

func (w *publicationWriter) LatestPublishedParts(context.Context) ([]modulecatalog.LatestPart, error) {
	if w.part == nil {
		return nil, nil
	}
	return []modulecatalog.LatestPart{*w.part}, nil
}

func (w *publicationWriter) ReprojectCatalogExtension(context.Context, string, catalog.Halves, catalog.Halves) error {
	w.reprojections++
	return nil
}

func (w *publicationWriter) AppendPublishedPart(_ context.Context, part modulecatalog.PublishedPart) error {
	w.part = &modulecatalog.LatestPart{PublishedPart: part}
	w.partsWritten++
	return nil
}

func (w *publicationWriter) AppendPublishedModel(_ context.Context, model modulecatalog.PublishedModel) (modulecatalog.PublishedModel, error) {
	model.Revision = w.head.Revision + 1
	w.head = model
	return w.head, nil
}
