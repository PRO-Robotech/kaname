// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelAuthoringCatalogSeedsOnlyApply(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	verifyAccessLabelAuthoringCatalog(t, r)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id)
		VALUES('iam_grant_access_label','test-authoring-only')`)
	requireAccessDefinitionSQLState(t, err, "23514")
}

func TestAccessLabelAuthoringCatalogUpgradeClosesOldIdentity(t *testing.T) {
	raw, err := migrations.FS.ReadFile("20261124020000_access_label_authoring_catalog.sql")
	require.NoError(t, err)
	up, down, found := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, found)
	for _, profile := range []string{"active", "full"} {
		t.Run(profile, func(t *testing.T) {
			r, owner := writerProtocolRigBeforePreparation(t)
			apply := func(sql string) {
				t.Helper()
				tx, err := r.admin.Begin(r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, tx)
				_, err = tx.Exec(r.ctx, sql)
				require.NoError(t, err)
				require.NoError(t, tx.Commit(r.ctx))
			}
			apply(down)
			r.bundle = semanticBundleDB(t, r.ctx, r.admin)
			activate := func() {
				t.Helper()
				if profile == "full" {
					_, _ = fullContractActivate(t, r)
				} else {
					require.NoError(t, owner.StageAuthorityBundle(r.ctx, r.bundle))
					require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
				}
			}
			activate()
			apply(up)
			var phase string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase))
			require.Equal(t, "transition", phase)
			verifyAccessLabelAuthoringCatalog(t, r)

			// Прямой откат на закрытой редакции не получает writer admission.
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			_, err = tx.Exec(r.ctx, down)
			requireAccessDefinitionSQLState(t, err, "P1036")
			require.NoError(t, tx.Rollback(r.ctx))
			verifyAccessLabelAuthoringCatalog(t, r)

			// Подготовка актуального bundle открывает штатный каталог для Down.
			r.bundle = semanticBundleDB(t, r.ctx, r.admin)
			activate()
			apply(down)
			var absent bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT phase, NOT EXISTS (
			 SELECT 1 FROM kaname.catalog_resource WHERE module='iam' AND resource='accessLabel')
			 FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase, &absent))
			require.True(t, absent)
			require.Equal(t, "transition", phase)
		})
	}
}

func verifyAccessLabelAuthoringCatalog(t *testing.T, r protocolRig) {
	t.Helper()
	rows, err := kanamepg.NewCatalogRepo(r.admin).ReadLiveCatalog(r.ctx)
	require.NoError(t, err)
	project := func(rows catalog.Rows) ([]catalog.ResourceRow, []catalog.VerbRow) {
		var resources []catalog.ResourceRow
		var verbs []catalog.VerbRow
		for _, row := range rows.Resources {
			if row.Module == "iam" && row.Resource == "accessLabel" {
				resources = append(resources, row)
			}
		}
		for _, row := range rows.Verbs {
			if row.Module == "iam" && row.Resource == "accessLabel" {
				verbs = append(verbs, row)
			}
		}
		return resources, verbs
	}
	wantResources, wantVerbs := project(seed.LiteralRows())
	gotResources, gotVerbs := project(rows)
	require.Len(t, wantResources, 1)
	require.Len(t, wantVerbs, 1)
	require.Len(t, gotResources, 1)
	require.Len(t, gotVerbs, 1)
	require.True(t, gotResources[0].SameForm(wantResources[0]))
	require.Equal(t, wantVerbs[0], gotVerbs[0])
}
