// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type generationObservationRow struct {
	roots [][]string
}

func (r generationObservationRow) Scan(dest ...any) error {
	fingerprint := strings.Repeat("a", 64)
	*dest[0].(**string) = &fingerprint
	*dest[1].(*[][]string) = r.roots
	*dest[2].(*[][]string) = [][]string{{"project", "project-output"}}
	*dest[3].(*int) = len(r.roots) + 1
	*dest[4].(*int) = 1
	return nil
}

type generationObservationTx struct {
	pgx.Tx
	row generationObservationRow
}

func (tx generationObservationTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return tx.row
}

// Дублёр воспроизводит форму SQL-наблюдения после установленной SA-миграции.
// Он проверяет Go-границу, не подменяет приёмку настоящего SQL generation.
func TestCaptureResourceGenerationAdmitsInstalledServiceAccountRoot(t *testing.T) {
	parents := parentCaptureFixture(t)
	parents.tx = generationObservationTx{row: generationObservationRow{roots: [][]string{
		{"iam.account", "account-root"},
		{"iam.project", "project-root"},
		{"iam.serviceAccount", "service-account-root"},
	}}}
	got, err := captureResourceGeneration(context.Background(), parents, "project", "project-output")
	require.NoError(t, err)
	require.NotNil(t, got.fingerprint)
	require.Equal(t, strings.Repeat("a", 64), *got.fingerprint)
	require.Equal(t, []string{"project:project-output"}, got.outputRefs)
	require.Empty(t, got.externalRoots)
}

func TestResourceGenerationCapturePreservesExactRetiredRoot(t *testing.T) {
	parents := parentCaptureFixture(t)
	parents.tx = generationObservationTx{row: generationObservationRow{roots: [][]string{
		{"vpc.oldNetwork", "network/opaque%2F"},
		{"vpc.network", "network/opaque%2F"},
	}}}
	got, err := captureResourceGeneration(context.Background(), parents, "project", "project-output")
	require.NoError(t, err)
	require.Equal(t, []domain.ResourceRef{
		{Type: "vpc.oldNetwork", ID: "network/opaque%2F"},
		{Type: "vpc.network", ID: "network/opaque%2F"},
	}, got.externalRoots)
	require.Equal(t, []string{"project:project-output"}, got.outputRefs)
}

func TestCaptureResourceGenerationStillRejectsUnsupportedRoot(t *testing.T) {
	for _, root := range [][]string{
		{"example..resources", "external-root"},
		{"example.resources", "external#root"},
		{".resources", "external-root"},
		{"example.", "external-root"},
		{"iam.service_account", "service-account-root"},
		{"iam.serviceAccount", ""},
		{"iam.serviceAccount", "root#member"},
		{"iam.serviceAccount"},
		{"iam.serviceAccount", "service-account-root", "extra"},
	} {
		t.Run(strings.Join(root, "/"), func(t *testing.T) {
			parents := parentCaptureFixture(t)
			parents.tx = generationObservationTx{row: generationObservationRow{roots: [][]string{root}}}
			got, err := captureResourceGeneration(context.Background(), parents, "project", "project-output")
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			require.Nil(t, got.fingerprint)
			require.Nil(t, got.outputRefs)
		})
	}
}
